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

        cfg = get_config_manager()
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()

        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
            "strategy": {
                "id": cfg.get("strategy", "current_id"),
                "name": cfg.get("strategy", "current_name") or "Не выбрана",
            },
            "autostart": {
                "enabled": cfg.get("autostart", "enabled", default=False),
            },
            "system": get_system_info(),
            "gui_version": "0.2.0",
            "timestamp": time.time(),
        }

    @app.route("/api/ping")
    def api_ping():
        """Health check."""
        response.content_type = "application/json; charset=utf-8"
        return {"ok": True, "timestamp": time.time()}

