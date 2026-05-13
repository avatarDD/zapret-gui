# api/devices.py
"""
REST API для обнаружения устройств LAN.

Маршруты:
  GET /api/devices            — текущий список устройств
                                  (DHCP-leases + ARP, merged)
  GET /api/devices/sources    — диагностика источников
"""

from bottle import response


def register(app):

    @app.route("/api/devices")
    def devices_list():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.devices_discovery import list_devices, sources_status
            return {"ok": True,
                    "devices": list_devices(),
                    "sources": sources_status()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/devices/sources")
    def devices_sources():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.devices_discovery import sources_status
            return {"ok": True, "sources": sources_status()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
