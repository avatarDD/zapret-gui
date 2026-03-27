# api/status.py
"""
GET /api/status — общий статус системы, nfqws и firewall.
GET /api/ping  — health check.
"""

import time
from bottle import response


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

        # Получаем информацию о версии zapret2
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
            "gui_version": "0.13.0",
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
        Список сетевых интерфейсов системы.

        Возвращает имена всех не-lo интерфейсов для выбора в настройках.
        """
        response.content_type = "application/json; charset=utf-8"

        import os
        import re
        import subprocess

        interfaces = []
        seen = set()

        try:
            # Способ 1: ip link show
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    # "2: eth0: <BROADCAST,...> ..."
                    match = re.match(r"\d+:\s+(\S+?)(@\S+)?:", line)
                    if match:
                        name = match.group(1)
                        if name != "lo" and name not in seen:
                            seen.add(name)
                            # Определяем статус
                            state = "unknown"
                            if "UP" in line.upper() and "LOWER_UP" in line.upper():
                                state = "up"
                            elif "DOWN" in line.upper():
                                state = "down"

                            interfaces.append({
                                "name": name,
                                "state": state,
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

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
                        operstate_path = os.path.join(net_dir, name, "operstate")
                        if os.path.isfile(operstate_path):
                            try:
                                with open(operstate_path, "r") as f:
                                    s = f.read().strip()
                                    state = s if s else "unknown"
                            except (IOError, OSError):
                                pass
                        interfaces.append({
                            "name": name,
                            "state": state,
                        })
            except (IOError, OSError):
                pass

        # Добавляем IP-адреса к интерфейсам
        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                addr_map = {}
                for line in result.stdout.strip().split("\n"):
                    match = re.match(
                        r"\d+:\s+(\S+)\s+(inet6?)\s+([\da-fA-F.:]+)/(\d+)",
                        line.strip()
                    )
                    if match:
                        iface_name = match.group(1)
                        family = "ipv4" if match.group(2) == "inet" else "ipv6"
                        addr = match.group(3)
                        if iface_name not in addr_map:
                            addr_map[iface_name] = []
                        addr_map[iface_name].append({
                            "family": family,
                            "address": addr,
                        })

                for iface in interfaces:
                    iface["addresses"] = addr_map.get(iface["name"], [])
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Получаем текущие выбранные интерфейсы из конфига
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        selected = cfg.get("interfaces", "bind_to", default=[])
        if isinstance(selected, str):
            selected = [s.strip() for s in selected.split(",") if s.strip()]

        return {
            "ok": True,
            "interfaces": interfaces,
            "selected": selected,
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

        # Сохраняем в конфиг
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



