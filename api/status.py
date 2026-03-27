# api/status.py
"""
GET /api/status — общий статус системы, nfqws и firewall.
GET /api/ping  — health check.
GET /api/interfaces — список интерфейсов + авто-определение ролей.
POST /api/interfaces/select — сохранить выбранные интерфейсы.
"""

import os
import re
import subprocess
import time
from bottle import response


def _run_cmd(args, timeout=5):
    """Запустить команду, вернуть (returncode, stdout)."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return -1, ""


def _is_private_ip(addr):
    """Проверить, является ли IPv4-адрес приватным (RFC 1918)."""
    try:
        parts = addr.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10
                or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168))
    except (ValueError, IndexError):
        return False


def _detect_interface_roles(interfaces, addr_map):
    """
    Авто-определение ролей WAN/WAN6/LAN по маршрутам и адресам.

    Аналог логики zapret2:
      WAN  — интерфейс с IPv4 default route (/proc/net/route)
      WAN6 — интерфейс с IPv6 default route; fallback на WAN
      LAN  — bridge (br-*) или приватная подсеть, отличная от WAN
    """
    detected = {"wan": "", "wan6": "", "lan": ""}
    iface_names = {i["name"] for i in interfaces}

    # --- WAN (IPv4): default route ---
    # Способ 1: /proc/net/route (как в zapret2 init.d скриптах)
    wan_ifaces = set()
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split("\t")
                # Dest==00000000, Mask==00000000 → default route
                if (len(parts) >= 8
                        and parts[1] == "00000000"
                        and parts[7] == "00000000"
                        and parts[0] in iface_names):
                    wan_ifaces.add(parts[0])
    except (IOError, OSError):
        pass

    # Способ 2 (fallback): ip route show default
    if not wan_ifaces:
        rc, out = _run_cmd(["ip", "route", "show", "default"])
        if rc == 0 and out:
            for line in out.split("\n"):
                m = re.search(r"dev\s+(\S+)", line)
                if m and m.group(1) in iface_names:
                    wan_ifaces.add(m.group(1))

    if wan_ifaces:
        detected["wan"] = " ".join(sorted(wan_ifaces))

    # --- WAN6 (IPv6): default route ---
    wan6_ifaces = set()
    rc, out = _run_cmd(["ip", "-6", "route", "show", "default"])
    if rc == 0 and out:
        for line in out.split("\n"):
            m = re.search(r"dev\s+(\S+)", line)
            if m and m.group(1) in iface_names:
                wan6_ifaces.add(m.group(1))

    if wan6_ifaces:
        detected["wan6"] = " ".join(sorted(wan6_ifaces))
    elif detected["wan"]:
        # Как в zapret2: IFACE_WAN6 = IFACE_WAN если не задан
        detected["wan6"] = detected["wan"]

    # --- LAN: bridge или приватная подсеть, не WAN ---
    all_wan = wan_ifaces | wan6_ifaces
    lan_candidates = []

    for iface in interfaces:
        name = iface["name"]
        if name in all_wan:
            continue
        # Bridge → первый приоритет
        if name.startswith("br"):
            lan_candidates.insert(0, name)
            continue
        # Приватный IPv4 → второй приоритет
        for a in addr_map.get(name, []):
            if a["family"] == "ipv4" and _is_private_ip(a["address"]):
                lan_candidates.append(name)
                break

    if lan_candidates:
        detected["lan"] = lan_candidates[0]

    return detected


def register(app):

    @app.route("/api/status")
    def api_status():
        """Общий статус системы: nfqws, firewall, стратегия, система."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager
        from core.system_info import get_system_info
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.autostart_manager import get_autostart_manager
        from core.zapret_installer import get_zapret_installer

        cfg = get_config_manager()
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        am = get_autostart_manager()
        inst = get_zapret_installer()

        zapret_version = inst.get_installed_version()

        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
            "strategy": {
                "id": cfg.get("strategy", "current_id"),
                "name": cfg.get("strategy", "current_name") or "Не выбрана",
            },
            "autostart": am.get_status(),
            "system": get_system_info(),
            "zapret": {
                "installed": zapret_version["installed"],
                "version": zapret_version["version"],
            },
            "gui_version": "0.13.1",
            "timestamp": time.time(),
        }

    @app.route("/api/ping")
    def api_ping():
        """Health check."""
        response.content_type = "application/json; charset=utf-8"
        return {"ok": True, "timestamp": time.time()}

    @app.route("/api/interfaces")
    def api_interfaces():
        """
        Список сетевых интерфейсов + авто-определение WAN/WAN6/LAN.

        Возвращает:
          interfaces — массив интерфейсов [{name, state, addresses}]
          selected   — привязанные интерфейсы из конфига
          detected   — авто-определённые роли {wan, wan6, lan}
        """
        response.content_type = "application/json; charset=utf-8"

        interfaces = []
        seen = set()

        # Способ 1: ip link show
        rc, out = _run_cmd(["ip", "-o", "link", "show"])
        if rc == 0 and out:
            for line in out.split("\n"):
                match = re.match(r"\d+:\s+(\S+?)(@\S+)?:", line)
                if match:
                    name = match.group(1)
                    if name != "lo" and name not in seen:
                        seen.add(name)
                        state = "unknown"
                        upper = line.upper()
                        if "UP" in upper and "LOWER_UP" in upper:
                            state = "up"
                        elif "DOWN" in upper:
                            state = "down"
                        interfaces.append({"name": name, "state": state})

        # Способ 2 (fallback): /sys/class/net/
        if not interfaces:
            try:
                net_dir = "/sys/class/net"
                if os.path.isdir(net_dir):
                    for name in sorted(os.listdir(net_dir)):
                        if name == "lo" or name in seen:
                            continue
                        seen.add(name)
                        state = "unknown"
                        op = os.path.join(net_dir, name, "operstate")
                        if os.path.isfile(op):
                            try:
                                with open(op, "r") as f:
                                    s = f.read().strip()
                                    state = s if s else "unknown"
                            except (IOError, OSError):
                                pass
                        interfaces.append({"name": name, "state": state})
            except (IOError, OSError):
                pass

        # Собираем IP-адреса
        addr_map = {}
        rc, out = _run_cmd(["ip", "-o", "addr", "show"])
        if rc == 0 and out:
            for line in out.split("\n"):
                match = re.match(
                    r"\d+:\s+(\S+)\s+(inet6?)\s+([\da-fA-F.:]+)/(\d+)",
                    line.strip()
                )
                if match:
                    iname = match.group(1)
                    family = "ipv4" if match.group(2) == "inet" else "ipv6"
                    addr = match.group(3)
                    if iname not in addr_map:
                        addr_map[iname] = []
                    addr_map[iname].append({
                        "family": family,
                        "address": addr,
                    })

        for iface in interfaces:
            iface["addresses"] = addr_map.get(iface["name"], [])

        # Авто-определение ролей WAN/WAN6/LAN
        detected = _detect_interface_roles(interfaces, addr_map)

        # Текущие выбранные из конфига
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        selected = cfg.get("interfaces", "bind_to", default=[])
        if isinstance(selected, str):
            selected = [s.strip() for s in selected.split(",") if s.strip()]

        return {
            "ok": True,
            "interfaces": interfaces,
            "selected": selected,
            "detected": detected,
        }

    @app.route("/api/interfaces/select", method="POST")
    def api_interfaces_select():
        """Сохранить выбранные интерфейсы для nfqws2."""
        response.content_type = "application/json; charset=utf-8"

        from bottle import request
        from core.config_manager import get_config_manager
        from core.log_buffer import log

        cfg = get_config_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        selected = body.get("interfaces", [])
        if not isinstance(selected, list):
            response.status = 400
            return {"ok": False, "error": "interfaces должен быть массивом"}

        cfg.set("interfaces", "bind_to", selected)
        cfg.save()

        if selected:
            log.info("Интерфейсы для nfqws2: %s" % ", ".join(selected),
                     source="settings")
        else:
            log.info("Интерфейсы для nfqws2: все (по умолчанию)",
                     source="settings")

        return {
            "ok": True,
            "selected": selected,
            "message": "Интерфейсы обновлены" + (
                " (%s)" % ", ".join(selected) if selected
                else " (все интерфейсы)"
            ),
        }
