# core/smart_detect.py
"""
Smart Detect: автодобавление в список только подтверждённых блокировок.

## Зачем

Детектор блокировок (``core/block_detector``) видит домен из живого DNS,
пробует его и при «внятном способе обхода» дописывал в список сразу. Два
изъяна (приём Tachyon, ``docs/SMART_DETECT.md``):

* один провал — ещё не блокировка: сервер перезагружался, Wi-Fi моргнул,
  у провайдера минутная авария. Список, питающий маршруты, зарастал;
* в список шло точное имя хоста, а заблокированный сервис приходит
  десятком поддоменов, и список догонял их неделями.

## Как теперь

1. Провал пробы ставит домен в очередь (:func:`submit`), а не в список.
2. Не раньше чем через ``smart_recheck_sec`` (по умолчанию 120 с) —
   повторная прямая проба. Открылось — это был сбой, домен уходит в
   «отклонённые» на ``smart_cooldown_h`` часов.
3. Снова не открылось — проба **через метод маршрута**, который этот
   список кормит (``awg:awg0`` → сокет привязан к интерфейсу туннеля).
   Не открылось и там — туннель не поможет, в список не добавляем.
   Для ``nfqws2``/``direct`` (или если список не ведёт ни в один
   маршрут) хватает двух прямых провалов.
4. В список идёт регистрируемый домен по PSL (``core/registrable``):
   ``api.example.co.uk`` → ``example.co.uk``.
5. Каждое добавление записано (``<config_dir>/smart-detect.json``) и
   отменяется: :func:`undo` убирает запись из списка, :func:`exclude`
   ещё и вносит домен в белый список детектора. В Telegram у
   уведомления — кнопки «Отменить» и «Исключить» (``core/notify_bot``).

Пока у провайдера нет интернета (``core/reachability``), очередь стоит:
иначе каждый домен в ней «подтвердился» бы.

## Второй источник: зависшие соединения mihomo / sing-box

DNS-лог видит имя, но не видит, что соединение «отправило и ничего не
получило». Clash API наших mihomo и sing-box (``/connections``) видит:
соединение через ``DIRECT``, отправлено > 0, получено 0, висит
дольше :data:`STALL_SEC` — кандидат. Включается
``block_detector.smart_clash``; дальше тот же путь, что у DNS.
"""

from __future__ import annotations

import json
import os
import threading
import time

from core.log_buffer import log

SOURCE = "block_detector"
DEFAULT_RECHECK = 120
DEFAULT_COOLDOWN_H = 24
# Сколько ждём возможности проверить через туннель (тот лежит), прежде
# чем бросить домен.
MAX_PENDING_SEC = 3600
MAX_PENDING = 200
MAX_PER_TICK = 10
MAX_ADDED = 200
PROXY_TIMEOUT = 8
STALL_SEC = 15

_lock = threading.RLock()


# ─────────────────────────── настройки и хранение ────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def settings() -> dict:
    cfg = _cfg()

    def _int(key, default):
        try:
            return int(cfg.get("block_detector", key, default=default))
        except (TypeError, ValueError):
            return default
    return {
        "confirm": bool(cfg.get("block_detector", "smart_confirm",
                                default=True)),
        "recheck_sec": max(30, _int("smart_recheck_sec", DEFAULT_RECHECK)),
        "registrable": bool(cfg.get("block_detector", "smart_registrable",
                                    default=True)),
        "clash": bool(cfg.get("block_detector", "smart_clash",
                              default=False)),
        "cooldown_h": max(1, _int("smart_cooldown_h", DEFAULT_COOLDOWN_H)),
    }


def _path() -> str:
    return os.path.join(_cfg().config_dir, "smart-detect.json")


def _read() -> dict:
    try:
        with open(_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    from core.safe_io import atomic_write_json
    data["added"] = (data.get("added") or [])[-MAX_ADDED:]
    atomic_write_json(_path(), data)


# ─────────────────────────── чистые функции ─────────────────────────

def list_entry(domain: str, use_registrable: bool = True) -> str:
    """Что писать в список: регистрируемый домен или само имя."""
    if use_registrable:
        from core.registrable import registrable
        reg = registrable(domain)
        if reg:
            return reg
    return (domain or "").strip(".").lower()


def via_iface(method: str) -> str:
    """Метод маршрута → интерфейс туннеля для пробы через него ("" — нечем).

    Туннельные методы адресуют интерфейс (``awg:awg0``, ``singbox:tun0``,
    ``warp:wg1``); проба привязывает сокет к нему (SO_BINDTODEVICE), как
    скачивания через ``awg:<iface>`` (``core/download_transport``).
    """
    from core.unified.model import parse_method
    try:
        kind, target = parse_method(method or "")
    except ValueError:
        return ""
    if kind in ("direct", "nfqws2") or not target:
        return ""
    return target


def stalled_hosts(connections, now: float, stall_sec: float = STALL_SEC):
    """Чистая функция: хосты соединений Clash API, которые ушли напрямую,
    что-то отправили и ничего не получили дольше ``stall_sec``."""
    out = []
    for c in connections or []:
        if not isinstance(c, dict):
            continue
        meta = c.get("metadata") or {}
        host = str(meta.get("host") or "").strip().lower().strip(".")
        # mihomo пишет «DIRECT», sing-box — тег исходящего («direct»).
        chains = [str(x).lower() for x in (c.get("chains") or [])]
        if not host or "direct" not in chains:
            continue
        try:
            up, down = int(c.get("upload") or 0), int(c.get("download") or 0)
        except (TypeError, ValueError):
            continue
        if up <= 0 or down > 0:
            continue
        started = _parse_ts(c.get("start"))
        if started is None or now - started < stall_sec:
            continue
        if host not in out:
            out.append(host)
    return out


def _parse_ts(value):
    """RFC 3339 с наносекундами (как пишет Go) → epoch или None."""
    if not value:
        return None
    from datetime import datetime
    import re
    s = str(value).strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


# ─────────────────────────── очередь ─────────────────────────────────

def submit(domain: str, list_id: str, code: str = "", source: str = "dns",
           now: float = None) -> str:
    """Поставить провалившийся домен в очередь подтверждения.

    Возвращает ``queued`` / ``pending`` (уже в очереди) / ``cooldown``.
    """
    now = time.time() if now is None else now
    domain = (domain or "").strip(".").lower()
    st = settings()
    with _lock:
        data = _read()
        rejected = data.get("rejected") or {}
        if domain in rejected and \
                now - float(rejected[domain]) < st["cooldown_h"] * 3600:
            return "cooldown"
        pending = data.get("pending") or {}
        if domain in pending:
            return "pending"
        if len(pending) >= MAX_PENDING:
            oldest = min(pending, key=lambda d: pending[d].get("first", 0))
            pending.pop(oldest, None)
        pending[domain] = {"first": now, "list_id": list_id, "code": code,
                           "source": source}
        data["pending"] = pending
        _write(data)
    log.info("smart detect: %s в очереди подтверждения (%s)"
             % (domain, code or source), source=SOURCE)
    return "queued"


def _target_method(list_id: str) -> str:
    """Метод маршрута, который кормит этот список ("" — ни один)."""
    try:
        from core.unified import failover, storage
        for route in storage.load_routes():
            if route.enabled and list_id in (route.destination.list_ids
                                             or []):
                return failover.current_method(route.id) or route.method
    except Exception:                               # noqa: BLE001 — граница
        pass
    return ""


def _probe_direct(domain: str) -> bool:
    from core.testers.probe import probe_domain
    try:
        return bool(probe_domain(domain, timeout=5).ok)
    except Exception:                               # noqa: BLE001
        return False


def _iface_up(iface: str) -> bool:
    return os.path.isdir("/sys/class/net/%s" % iface)


def _addresses(domain: str, code: str) -> list:
    """Адреса для пробы через туннель. DNS-блокировку (NXDOMAIN, 0.0.0.0
    от провайдера) обходим DoH: резолвер роутера тут и есть отравленный."""
    from core.block_detector import doh_resolve
    if code not in ("dns_block", "dns_hijack"):
        try:
            import socket
            ips = [ai[4][0] for ai in socket.getaddrinfo(
                domain, 443, 0, socket.SOCK_STREAM)]
            if ips:
                return ips
        except (OSError, UnicodeError):
            pass
    return doh_resolve(domain)


def _probe_via(domain: str, iface: str, code: str = ""):
    """Открывается ли сайт через туннель: True/False, None — туннеля нет.

    TLS с SNI домена до его адреса через сокет, привязанный к интерфейсу
    туннеля, и HEAD: любой ответ сервера — сервер достигнут, судить о
    странице не наше дело.
    """
    import socket
    import ssl
    from core.download_transport import _connect_bound
    if not _iface_up(iface):
        return None
    ips = _addresses(domain, code)
    if not ips:
        return False
    ctx = ssl.create_default_context()
    for ip in ips[:2]:
        try:
            raw = _connect_bound(ip, 443, PROXY_TIMEOUT, iface)
        except OSError:
            continue
        try:
            with ctx.wrap_socket(raw, server_hostname=domain) as tls:
                tls.sendall(("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: "
                             "Mozilla/5.0\r\nConnection: close\r\n\r\n"
                             % domain).encode("ascii", "ignore"))
                if tls.recv(16):
                    return True
        except (OSError, ssl.SSLError, socket.timeout):
            continue
        finally:
            try:
                raw.close()
            except OSError:
                pass
    return False


def _wan_down() -> bool:
    from core import reachability
    return reachability.wan_down()


def _reject(domain: str, reason: str, now: float) -> None:
    with _lock:
        data = _read()
        (data.get("pending") or {}).pop(domain, None)
        rejected = data.get("rejected") or {}
        rejected[domain] = now
        # Старые отказы не копим.
        cut = now - settings()["cooldown_h"] * 3600
        data["rejected"] = {d: t for d, t in rejected.items() if t >= cut}
        _write(data)
    log.info("smart detect: %s не добавлен — %s" % (domain, reason),
             source=SOURCE)


def _whitelist() -> set:
    raw = _cfg().get("block_detector", "whitelist", default=[]) or []
    return {str(d).strip().lower().strip(".") for d in raw if str(d).strip()}


def _whitelisted(domain: str) -> bool:
    """Домен или его родитель в белом списке детектора."""
    wl = _whitelist()
    d = domain
    while d:
        if d in wl:
            return True
        d = d.split(".", 1)[1] if "." in d else ""
    return False


def _covers_whitelisted(entry: str) -> bool:
    """Есть ли в белом списке поддомен ``entry``."""
    return any(w.endswith("." + entry) for w in _whitelist())


def known(domain: str, now: float = None) -> bool:
    """Домен уже в работе: в очереди, отклонён недавно или добавлен."""
    now = time.time() if now is None else now
    domain = (domain or "").strip(".").lower()
    data = _read()
    if domain in (data.get("pending") or {}):
        return True
    ts = (data.get("rejected") or {}).get(domain)
    if ts is not None and now - float(ts) < \
            settings()["cooldown_h"] * 3600:
        return True
    return any(r.get("domain") == domain and not r.get("undone")
               for r in data.get("added") or [])


def process(now: float = None) -> list:
    """Разобрать очередь: кого пора перепроверить. Возвращает итоги.

    За раз — не больше :data:`MAX_PER_TICK` старейших: каждое
    подтверждение — до двух проб с таймаутами, а идёт это в такте
    детектора.
    """
    now = time.time() if now is None else now
    st = settings()
    with _lock:
        pending = dict(_read().get("pending") or {})
    due = sorted((d for d, p in pending.items()
                  if now - float(p.get("first", now)) >= st["recheck_sec"]),
                 key=lambda d: pending[d].get("first", 0))[:MAX_PER_TICK]
    if not due:
        return []
    if _wan_down():
        return [{"domain": d, "result": "wan_down"} for d in due]
    out = []
    for domain in due:
        item = pending[domain]
        out.append({"domain": domain,
                    "result": _confirm(domain, item, st, now)})
    return out


def _confirm(domain: str, item: dict, st: dict, now: float) -> str:
    list_id = item.get("list_id") or ""
    method = _target_method(list_id)
    iface = via_iface(method)
    if iface and not _iface_up(iface):
        # Туннель лежит — нечем подтвердить; прямую пробу не тратим.
        if now - float(item.get("first", now)) > MAX_PENDING_SEC:
            _reject(domain, "туннель %s так и не поднялся" % method, now)
            return "expired"
        return "waiting_tunnel"
    if _probe_direct(domain):
        _reject(domain, "повторная проба напрямую прошла", now)
        return "recovered"
    if iface:
        via = _probe_via(domain, iface, item.get("code") or "")
        if via is None:
            return "waiting_tunnel"
        if not via:
            _reject(domain, "через %s тоже не открывается" % method, now)
            return "tunnel_fails"
    if _whitelisted(domain):
        _reject(domain, "в исключениях", now)
        return "excluded"
    entry = list_entry(domain, st["registrable"])
    if entry != domain and (_whitelisted(entry)
                            or _covers_whitelisted(entry)):
        # Регистрируемый домен накрыл бы исключённый поддомен — добавляем
        # только само имя.
        entry = domain
    return _add(domain, entry, list_id, method, now)


def _add(domain: str, entry: str, list_id: str, method: str,
         now: float) -> str:
    from core import named_lists
    res = named_lists.add_entries(list_id, [entry])
    with _lock:
        data = _read()
        (data.get("pending") or {}).pop(domain, None)
        if res.get("ok") and res.get("added"):
            rec = {"id": "%d-%s" % (int(now), entry), "ts": now,
                   "domain": domain, "entry": entry, "list_id": list_id,
                   "method": method}
            data.setdefault("added", []).append(rec)
        else:
            rec = None
        _write(data)
    if rec is None:
        return "already" if res.get("ok") else "list_error"
    log.info("smart detect: %s → %s в списке %s (подтверждено%s)"
             % (domain, entry, list_id,
                " через %s" % method if method else " повторной пробой"),
             source=SOURCE)
    try:
        from core import notify
        notify.event(
            "smart_detect",
            "➕ %s добавлен в список обхода%s: напрямую не открывается%s"
            % (entry, "" if entry == domain else " (из %s)" % domain,
               ", через %s — да" % method if method else ""),
            buttons=[{"text": "Отменить", "action": "smart_undo",
                      "arg": rec["id"]},
                     {"text": "Исключить", "action": "smart_exclude",
                      "arg": rec["id"]}])
    except Exception:                               # noqa: BLE001
        pass
    return "added"


# ─────────────────────────── отмена ──────────────────────────────────

def _find(rec_id: str):
    for rec in _read().get("added") or []:
        if rec.get("id") == rec_id:
            return rec
    return None


def undo(rec_id: str) -> dict:
    """Убрать автодобавленную запись из списка."""
    from core import named_lists
    rec = _find(rec_id)
    if not rec:
        return {"ok": False, "error": "такого добавления нет"}
    if rec.get("undone"):
        return {"ok": True, "already": True, "entry": rec["entry"]}
    entry = rec["entry"]

    def _fn(item):
        domains = list(item.get("domains") or [])
        if entry not in domains:
            return None
        return {"domains": [d for d in domains if d != entry]}
    res = named_lists.mutate(rec["list_id"], _fn)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error") or "список не найден"}
    with _lock:
        data = _read()
        for r in data.get("added") or []:
            if r.get("id") == rec_id:
                r["undone"] = time.time()
        _write(data)
    log.info("smart detect: %s убран из списка %s"
             % (entry, rec["list_id"]), source=SOURCE)
    return {"ok": True, "entry": entry, "list_id": rec["list_id"]}


def exclude(rec_id: str) -> dict:
    """Отменить и больше не добавлять: домен — в белый список детектора."""
    res = undo(rec_id)
    if not res.get("ok"):
        return res
    entry = res["entry"]
    cfg = _cfg()
    wl = list(cfg.get("block_detector", "whitelist", default=[]) or [])
    if entry not in wl:
        wl.append(entry)
        cfg.set("block_detector", "whitelist", wl)
        cfg.save()
    return dict(res, excluded=True)


def status() -> dict:
    data = _read()
    pending = data.get("pending") or {}
    return {"settings": settings(),
            "pending": [dict(v, domain=k) for k, v in sorted(
                pending.items(), key=lambda kv: kv[1].get("first", 0))],
            "added": list(reversed(data.get("added") or []))[:50],
            "rejected": len(data.get("rejected") or {})}


# ─────────────────────────── Clash API ───────────────────────────────

def _endpoints() -> list:
    """Clash API запущенных mihomo и sing-box: [{host, port, secret}].

    Каждый конфиг — сам по себе: битый или удалённый между листингом и
    чтением не должен прятать соседние.
    """
    from core.mihomo_proxies import external_controller_endpoint
    eps = []
    try:
        from core.clash_yaml import parse_yaml
        from core.mihomo_manager import get_mihomo_manager
        mgr = get_mihomo_manager()
        for c in mgr.list_configs() or []:
            try:
                if not mgr.is_running(c["name"]):
                    continue
                resp = mgr.get_config(c["name"])
                cfg = parse_yaml(resp.get("text") or "") \
                    if resp.get("ok") else {}
                ep = external_controller_endpoint(cfg or {})
                if ep:
                    eps.append(ep)
            except Exception:                       # noqa: BLE001
                continue
    except Exception:                               # noqa: BLE001 — граница
        pass
    try:
        from core.singbox_manager import get_singbox_manager
        mgr = get_singbox_manager()
        for c in mgr.list_configs() or []:
            try:
                if not mgr.is_running(c["name"]):
                    continue
                with open(c["path"], encoding="utf-8") as f:
                    cfg = json.load(f)
                api = (cfg.get("experimental") or {}).get("clash_api") or {}
                ep = external_controller_endpoint({
                    "external-controller": api.get("external_controller"),
                    "secret": api.get("secret")})
                if ep:
                    eps.append(ep)
            except Exception:                       # noqa: BLE001
                continue
    except Exception:                               # noqa: BLE001 — граница
        pass
    return eps


def clash_candidates(now: float = None) -> list:
    """Хосты зависших прямых соединений со всех Clash API."""
    if not settings()["clash"]:
        return []
    from core.mihomo_proxies import _request
    now = time.time() if now is None else now
    out = []
    for ep in _endpoints():
        code, body = _request(ep, "/connections")
        if code != 200 or not body:
            continue
        try:
            conns = (json.loads(body) or {}).get("connections") or []
        except (ValueError, AttributeError):
            continue
        for h in stalled_hosts(conns, now):
            # Уже в очереди, отклонён или добавлен — пробовать заново
            # каждый такт, пока соединение висит, незачем.
            if h not in out and not known(h, now):
                out.append(h)
    return out
