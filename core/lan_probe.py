# core/lan_probe.py
"""
Проба «как клиент LAN» через сетевое пространство имён (приём Tachyon,
``diagnostics/service_check.uc``, режим netns).

## Зачем

Пробы GUI идут с самого роутера: их трафик рождается в OUTPUT, а не
приходит с LAN в FORWARD. Это другой путь: правила по устройствам, NAT,
перехват DNS для клиентов, политика Keenetic, transparent-режим
sing-box/mihomo — всё это на пробу с роутера не действует. «С роутера
открывается, а с телефона нет» отсюда и не было видно.

## Как

Временное пространство имён ``zgui_probe`` с veth-парой: один конец
включается в мост LAN (``br-lan``), другой с адресом из подсети LAN
живёт внутри. Шлюз и DNS — сам роутер, как у любого клиента. Внутри
запускается этот же файл как скрипт (:func:`child_probe`: DNS, TCP,
TLS-рукопожатие с SNI) по тем же сайтам, что и с роутера; результаты
сравниваются. После пробы пространство и veth удаляются в любом случае.

Только Linux/OpenWrt с ``ip netns`` и veth. На Keenetic мост LAN
принадлежит NDMS, и вставлять в него свой порт нельзя, поэтому там
режим недоступен (:func:`availability` объясняет почему).

Адрес клиента — последний свободный в подсети LAN (обычно ``.254``, вне
пула DHCP); занятый по таблице соседей пропускается. Можно задать свой —
тогда проба пройдёт по правилам, написанным для этого адреса (но не
берите адрес включённого устройства: будет конфликт).
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

NS = "zgui_probe"
VETH_HOST = "zgp0"
VETH_NS = "zgp1"
BRIDGES = ("br-lan", "br0", "br-home")
DEFAULT_HOSTS = ("google.com", "youtube.com", "instagram.com",
                 "discord.com", "ya.ru")
TIMEOUT = 5
MAX_HOSTS = 10

_busy = threading.Lock()


# ─────────────────────────── проба (и внутри netns) ──────────────────

def probe_host(host: str, timeout: float = TIMEOUT) -> dict:
    """DNS → TCP:443 → TLS с SNI. Только stdlib: идёт и внутри netns."""
    out = {"host": host, "ok": False, "ip": "", "stage": "", "ms": None,
           "error": ""}
    t0 = time.monotonic()
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET,
                                socket.SOCK_STREAM)[0][4][0]
        out["ip"] = ip
    except OSError as e:
        out.update(stage="dns", error=str(e) or type(e).__name__)
        return out
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
    except OSError as e:
        out.update(stage="tcp", error=str(e) or type(e).__name__)
        return out
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(timeout)
            s.do_handshake()
    except (OSError, ssl.SSLError) as e:
        out.update(stage="tls", error=str(e) or type(e).__name__)
        return out
    finally:
        raw.close()
    out.update(ok=True, stage="ok",
               ms=round((time.monotonic() - t0) * 1000, 1))
    return out


def child_probe(hosts, timeout: float = TIMEOUT) -> list:
    """Все сайты параллельно; не уложившийся (getaddrinfo таймаута не
    знает) — ``stage: timeout``."""
    out = [None] * len(hosts)

    def work(i, h):
        out[i] = probe_host(h, timeout)

    threads = [threading.Thread(target=work, args=(i, h), daemon=True)
               for i, h in enumerate(hosts)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout * 3 + 2
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return [r or {"host": h, "ok": False, "ip": "", "stage": "timeout",
                  "ms": None, "error": "не уложился в %d с" % (timeout * 3)}
            for r, h in zip(out, hosts)]


# ─────────────────────────── чистые помощники ────────────────────────

def pick_address(router_cidr: str, taken=()) -> str:
    """Свободный адрес клиента: с конца подсети, мимо роутера и соседей."""
    iface = ipaddress.ip_interface(router_cidr)
    net = iface.network
    if net.num_addresses < 4:
        return ""
    taken = {str(t) for t in taken} | {str(iface.ip)}
    cand = net.broadcast_address - 1
    for _ in range(32):
        if cand <= net.network_address:
            break
        if str(cand) not in taken:
            return "%s/%d" % (cand, net.prefixlen)
        cand -= 1
    return ""


def compare(router_rows: list, lan_rows: list) -> list:
    """Чистая функция: строки «с роутера» и «как клиент» → вердикты."""
    lan = {r["host"]: r for r in lan_rows}
    out = []
    for r in router_rows:
        c = lan.get(r["host"]) or {"ok": False, "stage": "",
                                   "error": "нет результата"}
        if r["ok"] and c["ok"]:
            verdict = "both"
        elif r["ok"]:
            verdict = "lan_fails"
        elif c["ok"]:
            verdict = "router_fails"
        else:
            verdict = "both_fail"
        out.append({"host": r["host"], "router": r, "lan": c,
                    "verdict": verdict})
    return out


def _valid_host(h: str) -> bool:
    h = (h or "").strip().lower()
    return bool(h) and len(h) < 254 and all(
        c.isalnum() or c in "-." for c in h) and "." in h


# ─────────────────────────── окружение ───────────────────────────────

def _run(args, timeout=10, input_text=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, input=input_text)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _bridge(name: str = "") -> str:
    for b in ([name] if name else list(BRIDGES)):
        if b and os.path.isdir("/sys/class/net/%s/bridge" % b):
            return b
    return ""


def _router_cidr(bridge: str) -> str:
    rc, out, _ = _run(["ip", "-4", "-o", "addr", "show", "dev", bridge])
    for ln in out.splitlines():
        parts = ln.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1]
    return ""


def availability(bridge: str = "") -> dict:
    """Можно ли здесь пробовать как клиент LAN, и если нет — почему."""
    try:
        from core.firewall_persistence import is_keenetic
        if is_keenetic():
            return {"ok": False, "reason": "на Keenetic мост LAN "
                    "принадлежит прошивке: вставить в него свой порт нельзя"}
    except Exception:                               # noqa: BLE001 — граница
        pass
    if not sys.platform.startswith("linux") or not shutil.which("ip"):
        return {"ok": False, "reason": "нужен Linux с командой ip"}
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return {"ok": False, "reason": "нужны права root"}
    if _run(["ip", "netns", "list"])[0] != 0:
        return {"ok": False, "reason": "ядро или ip без поддержки netns"}
    br = _bridge(bridge)
    if not br:
        return {"ok": False, "reason": "мост LAN не найден (искал %s)"
                % ", ".join([bridge] if bridge else BRIDGES)}
    cidr = _router_cidr(br)
    if not cidr:
        return {"ok": False, "reason": "у моста %s нет IPv4-адреса" % br}
    return {"ok": True, "bridge": br, "router": cidr}


def _cleanup() -> None:
    _run(["ip", "netns", "del", NS])
    _run(["ip", "link", "del", VETH_HOST])
    shutil.rmtree("/etc/netns/%s" % NS, ignore_errors=True)


def _setup(bridge: str, addr: str, gateway: str) -> str:
    """Поднять netns; "" — готово, иначе текст ошибки."""
    steps = [
        ["ip", "netns", "add", NS],
        ["ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name",
         VETH_NS],
        ["ip", "link", "set", VETH_NS, "netns", NS],
        ["ip", "link", "set", VETH_HOST, "master", bridge],
        ["ip", "link", "set", VETH_HOST, "up"],
        ["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", NS, "ip", "addr", "add", addr, "dev",
         VETH_NS],
        ["ip", "netns", "exec", NS, "ip", "link", "set", VETH_NS, "up"],
        ["ip", "netns", "exec", NS, "ip", "route", "add", "default", "via",
         gateway],
    ]
    for cmd in steps:
        rc, _, err = _run(cmd)
        if rc != 0:
            return "%s: %s" % (" ".join(cmd[:5]), err.strip() or rc)
    # ip netns exec подменяет /etc/resolv.conf на этот файл: DNS — роутер,
    # как у клиента по DHCP.
    try:
        os.makedirs("/etc/netns/%s" % NS, exist_ok=True)
        with open("/etc/netns/%s/resolv.conf" % NS, "w") as f:
            f.write("nameserver %s\n" % gateway)
    except OSError as e:
        return "resolv.conf для netns: %s" % e
    # Порт моста переходит в forwarding не сразу (STP): ждём шлюз.
    for _ in range(10):
        if _run(["ip", "netns", "exec", NS, "ping", "-c", "1", "-W", "1",
                 gateway], timeout=3)[0] == 0:
            return ""
        time.sleep(0.5)
    return "шлюз %s не отвечает из netns" % gateway


def run(hosts=None, address: str = "", bridge: str = "") -> dict:
    """Пробы с роутера и как клиент LAN; netns убирается всегда."""
    hosts = [h.strip().lower() for h in (hosts or DEFAULT_HOSTS)
             if _valid_host(h)][:MAX_HOSTS]
    if not hosts:
        return {"ok": False, "error": "нет сайтов для проверки"}
    av = availability(bridge)
    if not av["ok"]:
        return {"ok": False, "error": av["reason"], "available": False}
    router_ip = av["router"].split("/")[0]
    if address:
        try:
            iface = ipaddress.ip_interface(address if "/" in address else
                                           "%s/%s" % (address,
                                                      av["router"].split(
                                                          "/")[1]))
        except ValueError:
            return {"ok": False, "error": "адрес клиента — IPv4"}
        lan = ipaddress.ip_interface(av["router"])
        if iface.network != lan.network:
            return {"ok": False, "error": "адрес не из подсети LAN %s"
                    % av["router"]}
        if iface.ip in (lan.ip, lan.network.network_address,
                        lan.network.broadcast_address):
            return {"ok": False, "error": "это адрес роутера или сети, "
                                          "а не клиента"}
        addr = str(iface)
    else:
        from core.device_schedule import read_neighbors
        addr = pick_address(av["router"], [ip for ip, _ in read_neighbors()])
        if not addr:
            return {"ok": False, "error": "в подсети LAN нет свободного "
                                          "адреса для пробы"}
    if not _busy.acquire(blocking=False):
        # Имена netns и veth постоянные: вторая проба снесла бы первой
        # её пространство посреди замера.
        return {"ok": False, "error": "проба уже идёт"}
    try:
        return _run_locked(hosts, av, addr, router_ip)
    finally:
        _busy.release()


def _run_locked(hosts, av, addr, router_ip) -> dict:
    router_rows = child_probe(hosts)
    _cleanup()
    try:
        err = _setup(av["bridge"], addr, router_ip)
        if err:
            return {"ok": False, "error": err}
        # -I: без каталога скрипта в sys.path — соседние модули core/
        # не должны подменять stdlib.
        rc, out, err = _run(["ip", "netns", "exec", NS, sys.executable,
                             "-I", os.path.abspath(__file__), "--child"]
                            + hosts,
                            timeout=TIMEOUT * 3 + 15)
        try:
            lan_rows = json.loads(out)
        except ValueError:
            return {"ok": False, "error": "проба в netns не ответила: %s"
                    % (err.strip()[-300:] or "rc=%d" % rc)}
    finally:
        _cleanup()
    rows = compare(router_rows, lan_rows)
    lan_fails = [r["host"] for r in rows if r["verdict"] == "lan_fails"]
    if lan_fails:
        hint = ("с роутера открывается, а у клиента LAN нет: %s — смотрите "
                "правила для клиентов (перехват FORWARD, правила по "
                "устройствам, transparent-режим, DNS клиентов)"
                % ", ".join(lan_fails))
    elif any(r["verdict"] == "router_fails" for r in rows):
        hint = ("у клиента открывается, а с роутера нет: пробы GUI с "
                "роутера тут не показатель")
    else:
        hint = "клиент LAN видит сайты так же, как роутер"
    return {"ok": True, "bridge": av["bridge"], "address": addr,
            "rows": rows, "lan_fails": lan_fails, "hint": hint}


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--child":
    print(json.dumps(child_probe(sys.argv[2:])))
