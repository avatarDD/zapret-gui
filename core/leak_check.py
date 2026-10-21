# core/leak_check.py
"""
Проверка утечек IP и DNS (приём Tachyon, ``docs/DNS_LEAK_CHECK.md``).

## Зачем

«Туннель поднят» ещё не значит «трафик идёт через него»: интерфейс
может быть жив, а маршрут — мимо, и сайт видит домашний IP. А DNS
роутера может уходить провайдеру, который подменяет ответы для
заблокированных сайтов. Обе вещи из GUI не видны.

## Как

* **Внешний IP.** Напрямую и через каждый доступный транспорт
  (``core/download_transport``: AWG-интерфейс, прокси sing-box/mihomo).
  Туннель с тем же IP, что и напрямую, — трафик идёт мимо.
* **DNS.** Сервис bash.ws: выдаёт метку, роутер резолвит
  ``<n>.<метка>.bash.ws`` своим резолвером (тем же путём, что клиенты
  LAN через dnsmasq), а bash.ws отвечает, какие серверы к нему пришли
  (IP, страна, провайдер). Резолвер из сети провайдера — ответы может
  подменять он.
* **Без ложного «всё хорошо».** Если какая-то часть не удалась, итог —
  «проверка неполная», а не «утечек нет» (из того же разбора Tachyon).

Запросы уходят на bash.ws и api.ipify.org: поэтому только по кнопке.
"""

from __future__ import annotations

import copy
import json
import socket
import threading
import time

from core.log_buffer import log

LEAK_SERVICE = "https://bash.ws"
IP_SERVICES = ("https://api.ipify.org?format=json",
               "https://ifconfig.me/ip")
NAMES = 6
TIMEOUT = 8
USER_AGENT = "zapret-gui/leak-check"

_run_lock = threading.Lock()
_last = {}


# ─────────────────────────── сеть ────────────────────────────────────

def _get(url: str, transport: str = "") -> str:
    from core.download_transport import urlopen_via
    with urlopen_via(url, transport=transport, timeout=TIMEOUT,
                     headers={"User-Agent": USER_AGENT}) as r:
        return r.read(65536).decode("utf-8", "replace")


def parse_ip(text: str) -> str:
    """Чистая функция: ответ сервиса IP → адрес ("" — не адрес)."""
    t = (text or "").strip()
    if t.startswith("{"):
        try:
            t = str(json.loads(t).get("ip") or "")
        except (ValueError, AttributeError):
            return ""
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(af, t)
            return t
        except (OSError, ValueError):
            continue
    return ""


def external_ip(transport: str = "") -> dict:
    err = ""
    for url in IP_SERVICES:
        try:
            ip = parse_ip(_get(url, transport))
        except Exception as e:                      # noqa: BLE001 — граница
            err = str(e) or type(e).__name__
            continue
        if ip:
            return {"ok": True, "ip": ip}
        err = "сервис ответил не адресом"
    return {"ok": False, "ip": "", "error": err}


def _resolve(name: str) -> None:
    try:
        socket.getaddrinfo(name, 80, socket.AF_INET)
    except OSError:
        pass                    # bash.ws отвечает NXDOMAIN — так и задумано


def parse_dns_report(items) -> dict:
    """Чистая функция: ответ bash.ws → ``{"ip": {...}, "dns": [...]}``."""
    out = {"ip": None, "dns": []}
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        entry = {"ip": str(it.get("ip") or ""),
                 "country": str(it.get("country_name")
                                or it.get("country") or ""),
                 "asn": str(it.get("asn") or "")}
        if it.get("type") == "ip":
            out["ip"] = entry
        elif it.get("type") == "dns" and entry["ip"]:
            out["dns"].append(entry)
    return out


def dns_leak() -> dict:
    """Какие резолверы видит мир, когда роутер резолвит имя."""
    try:
        ident = _get(LEAK_SERVICE + "/id").strip()
    except Exception as e:                          # noqa: BLE001 — граница
        return {"ok": False, "error": "bash.ws недоступен: %s" % e}
    if not ident.isdigit():
        return {"ok": False, "error": "bash.ws ответил непонятно"}
    threads = [threading.Thread(target=_resolve, daemon=True,
                                args=("%d.%s.bash.ws" % (i, ident),))
               for i in range(1, NAMES + 1)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + TIMEOUT
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    try:
        raw = _get("%s/dnsleak/test/%s?json" % (LEAK_SERVICE, ident))
        report = parse_dns_report(json.loads(raw))
    except Exception as e:                          # noqa: BLE001 — граница
        return {"ok": False, "error": "итог bash.ws не получен: %s" % e}
    if not report["dns"]:
        return dict(report, ok=False,
                    error="ни один запрос не дошёл до bash.ws — DNS роутера "
                          "не резолвит внешние имена или режет их")
    return dict(report, ok=True)


def _tunnels() -> list:
    from core.download_transport import list_transports
    try:
        items = list_transports().get("transports") or []
    except Exception:                               # noqa: BLE001 — граница
        return []
    return [t for t in items if t.get("kind") != "direct" and t.get("id")]


# ─────────────────────────── вывод ───────────────────────────────────

def evaluate(direct: dict, tunnels: list, dns: dict) -> dict:
    """Чистая функция: замеры → находки и итог.

    ``level``: ``ok`` — всё проверено и чисто; ``warn`` — есть что
    проверить (тот же IP через туннель, DNS у провайдера); ``incomplete`` — проверено не всё, «утечек нет» сказать
    нельзя.
    """
    findings, incomplete = [], False
    if direct.get("ok"):
        findings.append({"id": "ip_direct", "status": "ok",
                         "title": "Внешний IP напрямую",
                         "detail": direct["ip"]})
    else:
        incomplete = True
        findings.append({"id": "ip_direct", "status": "unknown",
                         "title": "Внешний IP напрямую не узнать",
                         "detail": direct.get("error", "")})
    for t in tunnels:
        title = "Через %s" % (t.get("label") or t.get("id"))
        if t.get("ok") and not direct.get("ok"):
            incomplete = True
            findings.append({"id": "ip_tunnel", "status": "unknown",
                             "title": title, "transport": t.get("id"),
                             "detail": "IP %s — сравнить не с чем: прямой "
                                       "IP не узнать" % t["ip"]})
        elif not t.get("ok"):
            incomplete = True
            findings.append({"id": "ip_tunnel", "status": "unknown",
                             "title": title, "transport": t.get("id"),
                             "detail": "не ответил: %s" % t.get("error", "")})
        elif direct.get("ok") and t["ip"] == direct["ip"]:
            # Не обязательно утечка: весь интернет роутера может и так
            # идти через этот туннель, а правила sing-box/mihomo — слать
            # проверочный сайт напрямую. Решает человек.
            findings.append({
                "id": "ip_tunnel", "status": "warning", "title": title,
                "transport": t.get("id"),
                "detail": "тот же IP, что напрямую (%s)" % t["ip"],
                "hint": "либо трафик идёт мимо туннеля (маршрут, правила "
                        "sing-box/mihomo), либо весь интернет роутера и так "
                        "идёт через него"})
        else:
            findings.append({"id": "ip_tunnel", "status": "ok",
                             "title": title, "transport": t.get("id"),
                             "detail": "IP %s — отличается от прямого"
                                       % t["ip"]})
    if not dns.get("ok"):
        incomplete = True
        findings.append({"id": "dns", "status": "unknown",
                         "title": "DNS роутера не проверен",
                         "detail": dns.get("error", "")})
    else:
        home = (dns.get("ip") or {}).get("asn") or ""
        isp = [d for d in dns["dns"] if home and d["asn"] == home]
        detail = ", ".join("%s (%s%s)" % (d["ip"], d["country"],
                                          ", " + d["asn"] if d["asn"] else "")
                           for d in dns["dns"][:6])
        if isp:
            findings.append({
                "id": "dns", "status": "warning",
                "title": "DNS роутера уходит провайдеру", "detail": detail,
                "hint": "провайдер видит, какие сайты открываются, и может "
                        "подменять ответы для заблокированных: задайте им "
                        "«DNS для отдельных доменов» или пустите DNS через "
                        "туннель"})
        else:
            findings.append({"id": "dns", "status": "ok",
                             "title": "DNS роутера идёт не через провайдера",
                             "detail": detail})
    if any(f["status"] == "warning" for f in findings):
        level = "warn"
    elif incomplete:
        level = "incomplete"
    else:
        level = "ok"
    line = {"ok": "Утечек не найдено",
            "warn": "Есть что проверить",
            "incomplete": "Проверка неполная — «утечек нет» сказать "
                          "нельзя"}[level]
    return {"level": level, "line": line, "findings": findings,
            "complete": not incomplete}


def run() -> dict:
    """Полная проверка; одна за раз."""
    if not _run_lock.acquire(blocking=False):
        return {"ok": False, "error": "проверка уже идёт"}
    try:
        tunnels = _tunnels()
        results = {}

        def work(key, transport):
            results[key] = external_ip(transport)

        jobs = [("direct", "")] + [(t["id"], t["id"]) for t in tunnels]
        threads = [threading.Thread(target=work, args=j, daemon=True)
                   for j in jobs]
        for th in threads:
            th.start()
        dns = dns_leak()
        deadline = time.monotonic() + TIMEOUT * len(IP_SERVICES) + 2
        for th in threads:
            th.join(max(0.0, deadline - time.monotonic()))
        direct = results.get("direct") or {"ok": False, "error": "не успел"}
        tun = [dict(t, **(results.get(t["id"])
                          or {"ok": False, "ip": "", "error": "не успел"}))
               for t in tunnels]
        out = evaluate(direct, tun, dns)
        out.update(ok=True, ts=int(time.time()), dns_servers=dns.get("dns")
                   or [], isp=dns.get("ip"))
        log.info("проверка утечек: %s" % out["line"], source="diagnostics")
        _last.clear()
        _last.update(copy.deepcopy(out))
        return out
    finally:
        _run_lock.release()


def last() -> dict:
    return copy.deepcopy(_last) if _last else {"ok": True, "ts": 0,
                                                "findings": []}
