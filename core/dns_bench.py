# core/dns_bench.py
"""
Замер DNS-резолверов с роутера и автовыбор лучшего (приём Tachyon,
``tachyon dns_benchmark`` / ``dns_autotune``).

## Зачем

Правило «домен → DNS» (``core/dns_routing``) превращается в
``server=/домен/IP`` для dnsmasq, то есть в обычный DNS по UDP на порт
53. Какой из пресетов отвечает быстрее и, главное, отвечает честно, с
роутера заранее не видно: у части провайдеров UDP/53 к Google или
Cloudflare перехвачен, и «правильный» сервер отдаёт ту же заглушку.
Здесь каждый пресет замеряется (UDP, а для справки ещё DoH и DoT), и
лучший по UDP можно выбрать как сервер ``auto`` для правил.

## Как

* Для каждого сервера — :data:`ROUNDS` проходов по :data:`DOMAINS`;
  задержка — медиана удачных ответов. Серверы опрашиваются параллельно.
* Подмена: UDP-ответ для :data:`SPOOF_PROBE` (заблокированный в РФ
  домен) сравнивается с ответом DoH мимо провайдера. Внутренние адреса
  или NXDOMAIN там, где DoH знает публичные, — сервер перехвачен.
* Лучший — из честных серверов, ответивших хотя бы на 2/3 запросов, с
  наименьшей медианой (:func:`pick_best`). Текущий DNS роутера
  замеряется для сравнения, но не выбирается.
* Выбор хранится в ``dns_routing.auto_server``; правила с сервером
  ``auto`` пересобираются, если лучший сменился. Если такие правила
  есть, замер повторяется раз в ``dns_routing.auto_bench_hours``.
"""

from __future__ import annotations

import base64
import copy
import random
import socket
import ssl
import struct
import threading
import time
import urllib.request

from core.log_buffer import log

SOURCE = "dns_routing"
DOMAINS = ("ya.ru", "google.com", "cloudflare.com")
ROUNDS = 2
TIMEOUT = 2.5
SPOOF_PROBE = "rutracker.org"
MIN_OK_SHARE = 2 / 3
TICK_SEC = 600
RETRY_SEC = 6 * 3600
DEADLINE_PAD = 5
SYSTEM_ID = "system"

_run_lock = threading.Lock()
_last = {}
_stop = threading.Event()
_thread = None
_tried_at = 0.0


# ─────────────────────────── формат DNS ──────────────────────────────

def build_query(name: str, qid: int) -> bytes:
    """Запрос A-записи в формате DNS (RFC 1035)."""
    labels = name.strip(".").encode("idna").split(b".")
    if not labels or any(not 0 < len(x) < 64 for x in labels):
        raise ValueError("неверное имя: %r" % name)
    q = b"".join(bytes([len(x)]) + x for x in labels) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q \
        + struct.pack(">HH", 1, 1)


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise ValueError("обрезанное имя")
        n = data[off]
        if n & 0xC0 == 0xC0:          # указатель сжатия: 2 байта и конец
            return off + 2
        if n == 0:
            return off + 1
        off += 1 + n


def parse_response(data: bytes, qid: int):
    """Ответ → ``(rcode, [IPv4])``; ValueError — не тот или битый ответ."""
    if len(data) < 12:
        raise ValueError("короткий ответ")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("чужой ответ")
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            raise ValueError("обрезанная запись")
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return flags & 0x000F, ips


# ─────────────────────────── протоколы ───────────────────────────────

def udp_query(ip: str, name: str, timeout: float = TIMEOUT):
    """→ ``(мс, rcode, ips)``; исключение — нет ответа."""
    qid = random.randint(0, 0xFFFF)
    q = build_query(name, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.sendto(q, (ip, 53))
        deadline = t0 + timeout
        while True:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            data, addr = s.recvfrom(4096)
            try:
                rcode, ips = parse_response(data, qid)
            except ValueError:
                continue            # опоздавший ответ прошлого запроса
            return (time.monotonic() - t0) * 1000, rcode, ips


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("соединение закрыто")
        buf += chunk
    return buf


def dot_query(spec: str, name: str, timeout: float = TIMEOUT):
    """DNS-over-TLS (``host:port``) → ``(мс, rcode, ips)``; с рукопожатием."""
    host, _, port = spec.rpartition(":")
    qid = random.randint(0, 0xFFFF)
    q = build_query(name, qid)
    ctx = ssl.create_default_context()
    t0 = time.monotonic()
    with socket.create_connection((host, int(port)), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(struct.pack(">H", len(q)) + q)
            n = struct.unpack(">H", _recv_exact(s, 2))[0]
            rcode, ips = parse_response(_recv_exact(s, n), qid)
    return (time.monotonic() - t0) * 1000, rcode, ips


def doh_query(url: str, name: str, timeout: float = TIMEOUT):
    """DNS-over-HTTPS (RFC 8484, GET) → ``(мс, rcode, ips)``."""
    q = build_query(name, 0)            # для DoH id = 0 (RFC 8484 §4.1)
    b64 = base64.urlsafe_b64encode(q).rstrip(b"=").decode()
    req = urllib.request.Request(
        "%s%sdns=%s" % (url, "&" if "?" in url else "?", b64),
        headers={"Accept": "application/dns-message",
                 "User-Agent": "zapret-gui/dns-bench"})
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(65536)
    rcode, ips = parse_response(data, 0)
    return (time.monotonic() - t0) * 1000, rcode, ips


# ─────────────────────────── замер ───────────────────────────────────

def _median(xs):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def _measure(fn, target: str) -> dict:
    times, errors, total = [], [], 0
    for _ in range(ROUNDS):
        for d in DOMAINS:
            total += 1
            try:
                ms, rcode, ips = fn(target, d)
            except Exception as e:                  # noqa: BLE001 — граница
                errors.append(type(e).__name__ if not str(e) else str(e))
                continue
            if rcode == 0 and ips:
                times.append(ms)
            else:
                errors.append("rcode %d" % rcode)
    med = _median(times)
    return {"ok": len(times), "total": total,
            "ms": round(med, 1) if med is not None else None,
            "error": errors[-1] if errors and not times else ""}


def _spoofed(ip: str, reference: list):
    """True — UDP-ответ подменён; None — сравнить не с чем."""
    if not reference:
        return None
    from core.block_detector import all_non_public
    try:
        _, rcode, ips = udp_query(ip, SPOOF_PROBE)
    except Exception:                               # noqa: BLE001 — граница
        return None
    if rcode == 3 or not ips or all_non_public(ips):
        return True
    # Заглушка провайдера бывает и на публичном адресе; у пробного домена
    # адреса постоянные, так что ни одного общего с DoH — подмена.
    return not set(ips) & set(reference)


def system_nameserver(servers=None) -> str:
    """Первый IPv4 ``nameserver`` из resolv.conf ("" — нет)."""
    if servers is None:
        from core.diagnostics import _get_dns_servers
        servers = _get_dns_servers()
    for ip in servers:
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except (OSError, ValueError):
            continue
        return ip
    return ""


def candidates() -> list:
    from core.dns_routing import DNS_SERVERS, SERVER_TITLES
    out = []
    sysns = system_nameserver()
    if sysns:
        out.append({"id": SYSTEM_ID, "name": "DNS роутера сейчас",
                    "ip": sysns, "doh": "", "dot": ""})
    for sid, s in DNS_SERVERS.items():
        out.append({"id": sid, "name": SERVER_TITLES.get(sid, sid),
                    "ip": s.get("ip", ""), "doh": s.get("doh", ""),
                    "dot": s.get("dot", "")})
    return out


def _bench_one(c: dict, reference: list) -> dict:
    row = dict(c)
    row["udp"] = _measure(udp_query, c["ip"]) if c["ip"] else None
    row["doh"] = _measure(doh_query, c["doh"]) if c["doh"] else None
    row["dot"] = _measure(dot_query, c["dot"]) if c["dot"] else None
    row["spoofed"] = (_spoofed(c["ip"], reference)
                      if c["ip"] and row["udp"] and row["udp"]["ok"]
                      else None)
    return row


def pick_best(rows: list) -> str:
    """Чистая функция: id лучшего сервера для ``server=`` dnsmasq.

    Берутся только серверы, честность которых проверена
    (``spoofed is False``): быстрый, но перехваченный провайдером сервер
    отдавал бы правилам «auto» те же заглушки.
    """
    best, best_ms = "", None
    for r in rows:
        u = r.get("udp") or {}
        if r.get("id") == SYSTEM_ID or r.get("spoofed") is not False:
            continue
        if not u.get("total") or u.get("ms") is None \
                or u["ok"] < u["total"] * MIN_OK_SHARE:
            continue
        if best_ms is None or u["ms"] < best_ms:
            best, best_ms = r["id"], u["ms"]
    return best


def _reference(cands: list) -> list:
    """Честные адреса :data:`SPOOF_PROBE`: DoH мимо провайдера. Если
    Cloudflare и Google по DoH закрыты — DoH остальных пресетов."""
    from core.block_detector import all_non_public, doh_resolve
    try:
        ips = doh_resolve(SPOOF_PROBE)
    except Exception:                               # noqa: BLE001 — граница
        ips = []
    for c in cands:
        if ips:
            break
        if not c.get("doh"):
            continue
        try:
            _, rcode, got = doh_query(c["doh"], SPOOF_PROBE)
        except Exception:                           # noqa: BLE001 — граница
            continue
        if rcode == 0 and got and not all_non_public(got):
            ips = got
    return ips


def _release_after(threads) -> None:
    """Отпустить замок, когда допрашиваются последние серверы: новый
    замер поверх недоделанного исказил бы задержки обоих."""
    for t in threads:
        t.join()
    _run_lock.release()


def benchmark() -> dict:
    """Замерить все серверы. Один замер за раз."""
    if not _run_lock.acquire(blocking=False):
        return {"ok": False, "error": "замер уже идёт"}
    handed_over = False
    try:
        cands = candidates()
        reference = _reference(cands)
        rows = [None] * len(cands)

        def work(i, c):
            try:
                rows[i] = _bench_one(c, reference)
            except Exception as e:                  # noqa: BLE001 — граница
                rows[i] = dict(c, udp=None, doh=None, dot=None,
                               spoofed=None, error=str(e))

        threads = [threading.Thread(target=work, args=(i, c), daemon=True)
                   for i, c in enumerate(cands)]
        for t in threads:
            t.start()
        # Худший случай одного сервера: все запросы по таймауту.
        deadline = time.monotonic() + TIMEOUT * len(DOMAINS) * ROUNDS * 3 \
            + DEADLINE_PAD
        for t in threads:
            t.join(max(0.0, deadline - time.monotonic()))
        rows = [r or dict(c, udp=None, doh=None, dot=None, spoofed=None,
                          error="не успел")
                for r, c in zip(rows, cands)]
        alive = [t for t in threads if t.is_alive()]
        if alive:
            threading.Thread(target=_release_after, args=(alive,),
                             daemon=True).start()
            handed_over = True
        best = pick_best(rows)
        result = {"ok": True, "ts": int(time.time()), "rows": rows,
                  "best": best, "spoof_checked": bool(reference),
                  "probe": SPOOF_PROBE}
        if not best and not reference:
            result["hint"] = ("подмену проверить не с чем (DoH недоступен), "
                              "поэтому сервер не выбран")
        elif not best:
            result["hint"] = ("ни один публичный DNS не отвечает честно по "
                              "UDP: правила «домен → DNS» здесь не помогут, "
                              "пускайте сайты через туннель")
        _last.clear()
        _last.update(result)
        return result
    finally:
        if not handed_over:
            _run_lock.release()


def last() -> dict:
    return copy.deepcopy(_last) if _last else {"ok": True, "rows": [],
                                                "ts": 0}


def has_result() -> bool:
    return bool(_last.get("rows"))


# ─────────────────────────── автовыбор ───────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def uses_auto() -> bool:
    from core.dns_routing import AUTO
    return any(r.get("dns") == AUTO and r.get("enabled", True)
               for r in _cfg().get("dns_routing", "rules", default=[]) or [])


def autoselect(fresh: bool = True) -> dict:
    """Замерить (или взять последний замер) и сделать лучший сервером
    ``auto``. Правила с ``auto`` пересобираются, если выбор сменился."""
    res = benchmark() if fresh or not has_result() else last()
    if not res.get("ok"):
        return res
    best = res.get("best") or ""
    cm = _cfg()
    prev = cm.get("dns_routing", "auto_server", default="") or ""
    prev_at = cm.get("dns_routing", "auto_server_at", default=0) or 0
    if not best:
        return {"ok": False, "best": "", "previous": prev,
                "error": res.get("hint") or "подходящего сервера нет"}
    cm.set("dns_routing", "auto_server", best)
    cm.set("dns_routing", "auto_server_at", int(time.time()))
    if not cm.save():
        # Диск полон или только для чтения: выбор живёт до перезапуска,
        # а сказать «выбран» значило бы соврать.
        cm.set("dns_routing", "auto_server", prev)
        cm.set("dns_routing", "auto_server_at", prev_at)
        return {"ok": False, "best": best, "previous": prev,
                "error": "не удалось сохранить настройки (место на диске?)"}
    out = {"ok": True, "best": best, "previous": prev,
           "changed": best != prev, "applied": None}
    if best != prev:
        log.info("DNS: лучший сервер по замеру — %s (был %s)"
                 % (best, prev or "не выбран"), source=SOURCE)
        if uses_auto():
            from core.dns_routing import get_dns_routing_manager
            out["applied"] = get_dns_routing_manager().apply()
    return out


def tick(now: float = None) -> dict:
    global _tried_at
    now = time.time() if now is None else now
    cm = _cfg()
    hours = int(cm.get("dns_routing", "auto_bench_hours", default=24) or 0)
    if hours <= 0 or not uses_auto():
        return {"action": "off"}
    at = int(cm.get("dns_routing", "auto_server_at", default=0) or 0)
    if now - at < hours * 3600:
        return {"action": "fresh"}
    if now - _tried_at < RETRY_SEC:
        # Неудачный замер (сервер не выбран) не двигает auto_server_at;
        # без паузы он повторялся бы каждые 10 минут.
        return {"action": "retry_later"}
    from core import reachability
    if reachability.wan_down():
        return {"action": "wan_down"}
    _tried_at = now
    return dict(autoselect(), action="bench")


def _loop() -> None:
    while not _stop.wait(TICK_SEC):
        try:
            tick()
        except Exception as e:                      # noqa: BLE001 — граница
            log.warning("замер DNS: %s" % e, source=SOURCE)


def start() -> None:
    """Фоновый перезамер для правил ``auto`` (из загрузки приложения)."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="dns-bench", daemon=True)
    _thread.start()
