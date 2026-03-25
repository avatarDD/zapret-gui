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
            "gui_version": "0.9.2",
            "timestamp": time.time(),
        }

    @app.route("/api/ping")
    def api_ping():
        """Health check."""
        response.content_type = "application/json; charset=utf-8"
        return {"ok": True, "timestamp": time.time()}
