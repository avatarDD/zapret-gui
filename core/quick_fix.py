# core/quick_fix.py
"""
Быстрый ремонт: системные поломки, которые выглядят как «обход не работает».

## Зачем

Часть жалоб «ничего не открывается, подбор стратегий показывает 0%» —
вовсе не DPI. У роутера без часов реального времени после перезагрузки
дата 1970 года или дата сборки прошивки: любой TLS падает на проверке
сертификата («ещё не действителен»), и сканер честно решает, что
ни одна стратегия не работает. Или упал dnsmasq, и роутер не резолвит
ничего. Здесь такие поломки проверяются отдельно и чинятся кнопкой
(приём Tachyon, ``diagnostics/repairs.uc``: ``fix_system_time``,
``fix_dnsmasq``, ``fix_gateway``…).

## Проверки

* ``clock`` — расхождение часов с заголовком ``Date`` HTTP-ответов
  (обычный HTTP: проверка по TLS сама упала бы на неверных часах).
  Без сети — хотя бы «год раньше сборки GUI» (заведомо неверно).
  Ремонт — ``ntpd -q`` / ``ntpdate``, при их отсутствии — время из того
  же заголовка ``Date`` через ``date -u -s``.
* ``dns`` — резолвит ли системный резолвер роутера (тот же путь, что у
  клиентов LAN), когда публичные резолверы отвечают напрямую по IP
  (UDP/53 к 1.1.1.1 и 8.8.8.8 — без имён и без TLS: DoH по имени сам
  упал бы вместе с DNS роутера, а по TLS — на неверных часах). Ремонт —
  перезапуск (или запуск) dnsmasq тем же кодом, что у DNS-маршрутизации
  (``DnsmasqIntegration``); Keenetic со штатным DNS не трогаем.
* ``default_route`` и ``resolv_conf`` — только диагноз: чинить маршрут
  по умолчанию или ``resolv.conf`` вслепую опаснее, чем подсказать.

Оценка — чистые функции (``evaluate_*``), сеть и команды — отдельно,
их подменяют тесты.
"""

from __future__ import annotations

import email.utils
import os
import random
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


# Обычный HTTP: TLS на неверных часах упал бы раньше, чем мы прочли
# заголовок. Адреса проверки доступности ОС — живут годами и отвечают
# коротко.
CLOCK_URLS = (
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://detectportal.firefox.com/success.txt",
)
NTP_SERVERS = ("pool.ntp.org", "time.google.com", "time.cloudflare.com")
# Год, раньше которого часы заведомо врут: GUI с такими датами не
# собирался. Нижняя граница без сети.
MIN_SANE_YEAR = 2025
# Порог расхождения: больше минуты — уже заметно (подписи, TOTP),
# больше пяти — ломаются TLS-проверки с запасом на сдвиг сертификатов.
CLOCK_WARN_SEC = 60
CLOCK_ERROR_SEC = 300

DNS_PROBE_DOMAINS = ("ya.ru", "google.com")
DNS_TIMEOUT = 4.0
# Публичные резолверы по адресу: «интернет есть» без DNS роутера и TLS.
PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8")

CACHE_TTL = 120

_cache = {"ts": 0.0, "report": None}
_lock = threading.Lock()


# ─────────────────────────── чистые оценки ───────────────────────────

def parse_http_date(value: str):
    """Заголовок ``Date`` → unix-время (или None)."""
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def evaluate_clock(local_now: float, remote_now=None) -> dict:
    """Оценить часы: ``remote_now`` — время по сети (None — сети нет).

    Возвращает находку ``{id, status, title, detail, hint, offset_sec,
    fix}``; ``status`` — ok / warning / error / unknown.
    """
    year = time.gmtime(local_now).tm_year
    base = {"id": "clock", "offset_sec": None, "fix": None,
            "local_time": _fmt(local_now)}
    if remote_now is None:
        if year < MIN_SANE_YEAR:
            return dict(base, status="error",
                        title="Часы роутера в прошлом (%d год)" % year,
                        detail="Сеть для сверки недоступна, но %d год "
                               "заведомо неверен" % year,
                        hint="Все TLS-проверки и подбор стратегий упадут "
                             "на сертификатах «ещё не действителен». "
                             "Синхронизируйте время.",
                        fix="clock_sync")
        return dict(base, status="unknown",
                    title="Часы не сверены",
                    detail="Ни один адрес проверки времени не ответил",
                    hint="Проверка повторится, когда появится сеть.")
    offset = remote_now - local_now
    base["offset_sec"] = round(offset, 1)
    base["remote_time"] = _fmt(remote_now)
    magnitude = abs(offset)
    if magnitude >= CLOCK_ERROR_SEC or year < MIN_SANE_YEAR:
        return dict(base, status="error",
                    title="Часы роутера врут на %s" % _human(magnitude),
                    detail="На роутере %s, в сети %s (UTC)"
                           % (_fmt(local_now), _fmt(remote_now)),
                    hint="С такими часами TLS-проверки падают на "
                         "сертификатах, и подбор стратегий показывает 0%. "
                         "Синхронизируйте время.",
                    fix="clock_sync")
    if magnitude >= CLOCK_WARN_SEC:
        return dict(base, status="warning",
                    title="Часы роутера расходятся на %s" % _human(magnitude),
                    detail="На роутере %s, в сети %s (UTC)"
                           % (_fmt(local_now), _fmt(remote_now)),
                    hint="Обходу пока не мешает, но NTP, похоже, не "
                         "работает. Синхронизируйте время.",
                    fix="clock_sync")
    return dict(base, status="ok", title="Часы в порядке",
                detail="Расхождение %.0f с" % magnitude, hint="")


def evaluate_dns(system: dict, doh_ok) -> dict:
    """Оценить системный резолвер.

    ``system`` — {домен: bool} результатов резолва системой;
    ``doh_ok`` — отвечают ли публичные резолверы напрямую по адресу
    (None — не проверяли).
    """
    base = {"id": "dns", "fix": None, "results": dict(system)}
    if not system:
        return dict(base, status="unknown", title="DNS не проверялся",
                    detail="", hint="")
    failed = sorted(d for d, ok in system.items() if not ok)
    if not failed:
        return dict(base, status="ok", title="DNS роутера отвечает",
                    detail="", hint="")
    if len(failed) < len(system):
        return dict(base, status="warning",
                    title="DNS роутера отвечает не на всё",
                    detail="Не резолвятся: %s" % ", ".join(failed),
                    hint="Один домен — скорее блокировка по DNS, чем "
                         "поломка: проверьте его в «Куда пойдёт сайт».")
    if doh_ok is False:
        return dict(base, status="error",
                    title="Нет интернета или DNS вообще",
                    detail="Не отвечают ни DNS роутера, ни публичные "
                           "резолверы по адресу",
                    hint="Похоже на пропавший интернет у провайдера, "
                         "а не на поломку DNS: проверьте WAN.")
    return dict(base, status="error",
                title="DNS роутера не отвечает",
                detail="Не резолвятся: %s, а публичные резолверы по "
                       "адресу отвечают" % ", ".join(failed),
                hint="Сайты не открываются ни у кого в сети. Обычно "
                     "помогает перезапуск dnsmasq.",
                fix="dns_restart")


def evaluate_default_route(route_lines: list) -> dict:
    """Есть ли маршрут по умолчанию (строки ``/proc/net/route``)."""
    base = {"id": "default_route", "fix": None}
    if not route_lines:
        return dict(base, status="unknown", title="Таблица маршрутов недоступна",
                    detail="", hint="")
    for line in route_lines[1:]:
        cols = line.split()
        if len(cols) >= 2 and cols[1] == "00000000":
            return dict(base, status="ok",
                        title="Маршрут по умолчанию есть",
                        detail="через %s" % cols[0], hint="")
    return dict(base, status="error",
                title="Нет маршрута по умолчанию",
                detail="В основной таблице нет default-маршрута",
                hint="Роутер не знает, куда слать трафик в интернет: "
                     "проверьте подключение к провайдеру (WAN).")


def evaluate_resolv_conf(text) -> dict:
    """Есть ли в ``/etc/resolv.conf`` хоть один ``nameserver``."""
    base = {"id": "resolv_conf", "fix": None}
    if text is None:
        return dict(base, status="warning", title="Нет /etc/resolv.conf",
                    detail="Файл не читается",
                    hint="Программы на роутере (и сам GUI) не знают, у "
                         "кого спрашивать DNS.")
    servers = [ln.split()[1] for ln in text.splitlines()
               if ln.strip().startswith("nameserver") and len(ln.split()) > 1]
    if not servers:
        return dict(base, status="warning",
                    title="В /etc/resolv.conf нет DNS-серверов",
                    detail="Нет ни одной строки nameserver",
                    hint="Программы на роутере не смогут резолвить имена. "
                         "Обычно файл пишет прошивка — перезапустите WAN.")
    return dict(base, status="ok", title="resolv.conf в порядке",
                detail=", ".join(servers[:4]), hint="")


def _fmt(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
    except (OverflowError, OSError, ValueError):
        return "?"


def _human(sec: float) -> str:
    sec = abs(sec)
    if sec < 120:
        return "%d с" % sec
    if sec < 7200:
        return "%d мин" % (sec // 60)
    if sec < 172800:
        return "%d ч" % (sec // 3600)
    if sec < 86400 * 730:
        return "%d дн." % (sec // 86400)
    return "%d лет" % (sec // (86400 * 365))


# ───────────────────────────── сеть и I/O ────────────────────────────

def network_time(timeout: float = 5.0):
    """Время по заголовку ``Date`` первого ответившего адреса (или None).

    Прямой запрос без прокси окружения: на роутере ``HTTPS_PROXY`` бывает
    выставлен на туннель, который сам может лежать. Задержку ответа
    делим пополам — заголовок пишется в середине обмена.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in CLOCK_URLS:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": "zapret-gui/clock"})
        started = time.time()
        try:
            with opener.open(req, timeout=timeout) as resp:
                header = resp.headers.get("Date", "")
        except urllib.error.HTTPError as e:
            header = e.headers.get("Date", "") if e.headers else ""
        except (OSError, ValueError):
            continue
        remote = parse_http_date(header)
        if remote is None:
            continue
        rtt = time.time() - started
        return remote + rtt / 2.0
    return None


def _resolve(domain: str, timeout: float) -> bool:
    """Резолв системным резолвером с таймаутом (getaddrinfo его не знает)."""
    box = {}

    def _run():
        try:
            box["ok"] = bool(socket.getaddrinfo(domain, 443,
                                                proto=socket.IPPROTO_TCP))
        except (OSError, UnicodeError):
            box["ok"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    return bool(box.get("ok"))


def build_dns_query(domain: str, qid: int) -> bytes:
    """Минимальный DNS-запрос A (RD=1) — чтобы спросить резолвер по IP."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in domain.strip(".").split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def dns_reply_ok(data: bytes, qid: int) -> bool:
    """Ответ на наш запрос, без ошибки и хотя бы с одной записью."""
    if len(data) < 12:
        return False
    rid, flags, _qd, ancount = struct.unpack("!HHHH", data[:8])
    return rid == qid and bool(flags & 0x8000) and (flags & 0x000F) == 0 \
        and ancount > 0


def _public_dns_alive(timeout: float = 2.0) -> bool:
    """Отвечает ли хоть один публичный резолвер напрямую (UDP/53 по IP)."""
    for server in PUBLIC_RESOLVERS:
        qid = random.randint(1, 0xFFFF)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(build_dns_query(DNS_PROBE_DOMAINS[0], qid),
                        (server, 53))
            data, _addr = sock.recvfrom(2048)
            if dns_reply_ok(data, qid):
                return True
        except OSError:
            continue
        finally:
            sock.close()
    return False


def _read(path: str):
    try:
        with open(path, "r") as f:
            return f.read(65536)
    except (OSError, UnicodeDecodeError):
        return None


def _route_lines() -> list:
    text = _read("/proc/net/route")
    return text.splitlines() if text else []


def check(network: bool = True, fresh: bool = False) -> dict:
    """Все проверки. ``network=False`` — только локальные (без пакетов):
    часы по нижней границе года, маршрут и resolv.conf.

    Сетевой отчёт кешируется на ``CACHE_TTL`` секунд: его зовут и
    диагностика, и сканер перед стартом.
    """
    if network and not fresh:
        with _lock:
            if _cache["report"] and time.time() - _cache["ts"] < CACHE_TTL:
                return _cache["report"]
    now = time.time()
    findings = []
    remote = network_time() if network else None
    findings.append(evaluate_clock(now, remote))
    if network:
        system = {d: _resolve(d, DNS_TIMEOUT) for d in DNS_PROBE_DOMAINS}
        doh = None if all(system.values()) else _public_dns_alive()
        findings.append(evaluate_dns(system, doh))
    findings.append(evaluate_default_route(_route_lines()))
    findings.append(evaluate_resolv_conf(_read("/etc/resolv.conf")))
    report = {"ok": True, "network": network, "checked_at": now,
              "findings": findings,
              "problems": sum(1 for f in findings
                              if f["status"] in ("warning", "error")),
              "fixes": [f["fix"] for f in findings if f.get("fix")]}
    if network:
        with _lock:
            _cache.update(ts=time.time(), report=report)
    return report


def clock_problem(network: bool = True):
    """Находка о часах, если с ними беда (для сканера), иначе None.

    Только часы: одна HTTP-проба, без DNS-части полной проверки — её
    зовут на старте сканера, и ждать там DNS незачем. Свежий полный отчёт
    (кеш) используется, если он есть.
    """
    try:
        with _lock:
            cached = _cache["report"] if (
                _cache["report"]
                and time.time() - _cache["ts"] < CACHE_TTL) else None
        if cached:
            found = [f for f in cached.get("findings") or []
                     if f.get("id") == "clock"]
            finding = found[0] if found else None
        else:
            finding = evaluate_clock(
                time.time(), network_time() if network else None)
    except Exception:                           # noqa: BLE001 — граница
        return None
    if finding and finding.get("status") == "error":
        return finding
    return None


def invalidate() -> None:
    with _lock:
        _cache.update(ts=0.0, report=None)


# ───────────────────────────── ремонт ────────────────────────────────

FIXES = ("clock_sync", "dns_restart")


def _run(argv, timeout=20) -> tuple:
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, str(e)


def _busybox_ntpd():
    """Путь к ntpd из BusyBox или None.

    Флаги ``-q -n -p`` — BusyBox: у ntpd из ntp.org ``-p`` — pid-файл, и
    вызов ушёл бы мимо. Чужой ntpd пропускаем (там есть ntpdate).
    """
    path = shutil.which("ntpd")
    if not path:
        return None
    try:
        if os.path.basename(os.path.realpath(path)).startswith("busybox"):
            return path
    except OSError:
        return None
    rc, out = _run([path, "--help"], timeout=5)
    return path if "busybox" in out.lower() else None


def sync_clock() -> dict:
    """Синхронизировать часы: NTP, а без него — по заголовку ``Date``.

    NTP ограничен по времени: BusyBox ``ntpd -q`` не выходит сам, если
    UDP/123 закрыт, а HTTP-запасной путь работает почти всегда.
    """
    tried = []
    started = time.monotonic()
    before = time.time()

    def _shift():
        # Сдвиг часов = сколько прибавилось на стенных часах сверх
        # реально прошедшего времени (попытки тоже идут во время ремонта).
        return (time.time() - before) - (time.monotonic() - started)

    ntpd = _busybox_ntpd()
    if ntpd:
        argv = [ntpd, "-q", "-n"]
        for server in NTP_SERVERS:
            argv += ["-p", server]
        rc, out = _run(argv, timeout=12)
        tried.append("ntpd: %s" % ("ok" if rc == 0 else
                                   (out.strip()[:120] or rc)))
        if rc == 0:
            return _clock_done("ntpd", "", _shift(), tried)
    ntpdate = shutil.which("ntpdate")
    if ntpdate:
        rc, out = _run([ntpdate, "-u", "-t", "3"] + list(NTP_SERVERS),
                       timeout=15)
        tried.append("ntpdate: %s" % ("ok" if rc == 0 else
                                      (out.strip()[:120] or rc)))
        if rc == 0:
            return _clock_done("ntpdate", "", _shift(), tried)
    remote = network_time()
    if remote is None:
        return {"ok": False, "error": "Ни NTP, ни HTTP-сверка времени не "
                                      "ответили — нет сети?",
                "tried": tried}
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(remote))
    rc, out = _run(["date", "-u", "-s", stamp], timeout=10)
    tried.append("date -u -s: %s" % ("ok" if rc == 0 else
                                     (out.strip()[:120] or rc)))
    if rc != 0:
        return {"ok": False, "error": "Не удалось установить время: %s"
                                      % out.strip()[:200], "tried": tried}
    return _clock_done("http-date", stamp, _shift(), tried)


def _clock_done(method: str, source: str, shift: float, tried: list) -> dict:
    invalidate()
    log.info("быстрый ремонт: часы синхронизированы (%s%s), сдвиг %.0f с"
             % (method, " " + source if source else "", shift),
             source="diagnostics")
    return {"ok": True, "method": method, "source": source,
            "shift_sec": round(shift, 1), "tried": tried}


def restart_dns() -> dict:
    """Перезапустить dnsmasq, а упавший — запустить.

    Тем же кодом, что у DNS-маршрутизации (``DnsmasqIntegration``):
    systemd-юнит или init-скрипт, успех — только по живому pid (init-
    скрипты врут кодом возврата). ``restart()`` намеренно не поднимает
    остановленный dnsmasq — здесь упавший как раз и надо поднять.
    """
    try:
        from core.system_info import platform_kind
        keenetic = platform_kind() == "keenetic"
    except Exception:                           # noqa: BLE001
        keenetic = False
    from core.routing.dnsmasq_integration import DnsmasqIntegration
    dn = DnsmasqIntegration()
    if dn.get_pid() > 0:
        res = dn.restart()
    elif dn._has_dnsmasq_service():
        res = dn._step_start_unit("dnsmasq")
        res["ok"] = bool(res.get("ok")) and dn.get_pid() > 0
    elif dn._find_init_script():
        res = dn._step_start_init_script()
    else:
        res = {"ok": False,
               "error": ("dnsmasq не установлен. DNS на Keenetic — штатный: "
                         "перезапустите интернет-подключение в "
                         "веб-интерфейсе роутера." if keenetic else
                         "dnsmasq не найден (ни юнита systemd, ни "
                         "init-скрипта).")}
    invalidate()
    if res.get("ok"):
        log.info("быстрый ремонт: dnsmasq %s" % (
            "перезапущен" if res.get("how") else "запущен"),
            source="diagnostics")
        return {"ok": True, "how": res.get("how", ""),
                "degraded": bool(res.get("degraded")),
                "warning": res.get("error", "") if res.get("degraded") else ""}
    return {"ok": False, "error": res.get("error") or "dnsmasq не поднялся"}


_fix_lock = threading.Lock()


def apply_fix(fix_id: str) -> dict:
    """Выполнить ремонт по коду из ``FIXES`` (не два сразу: второй клик
    по кнопке, пока первый ждёт NTP, получит отказ, а не второй ntpd)."""
    if fix_id not in FIXES:
        return {"ok": False, "error": "Неизвестный ремонт: %s" % fix_id,
                "known": list(FIXES)}
    if not _fix_lock.acquire(blocking=False):
        return {"ok": False, "error": "Ремонт уже выполняется — дождитесь "
                                      "его окончания", "busy": True}
    try:
        return sync_clock() if fix_id == "clock_sync" else restart_dns()
    finally:
        _fix_lock.release()
