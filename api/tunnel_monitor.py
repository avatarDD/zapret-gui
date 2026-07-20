# api/tunnel_monitor.py
"""
API-модуль Live мониторинга туннелей.

Эндпоинты:
  GET  /api/monitor/status   — статус монитора
  GET  /api/monitor/metrics  — метрики всех интерфейсов
  POST /api/monitor/start    — запустить сбор
  POST /api/monitor/stop     — остановить сбор
"""

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты tunnel_monitor."""

    @app.route("/api/monitor/status", method="GET")
    def monitor_status():
        from core.tunnel_monitor import get_tunnel_monitor
        return get_tunnel_monitor().get_status()

    @app.route("/api/monitor/metrics", method="GET")
    def monitor_metrics():
        from core.tunnel_monitor import get_tunnel_monitor
        return {"ok": True, "metrics": get_tunnel_monitor().get_metrics()}

    @app.route("/api/monitor/start", method="POST")
    def monitor_start():
        from core.tunnel_monitor import get_tunnel_monitor
        get_tunnel_monitor().start()
        return {"ok": True}

    @app.route("/api/monitor/stop", method="POST")
    def monitor_stop():
        from core.tunnel_monitor import get_tunnel_monitor
        get_tunnel_monitor().stop()
        return {"ok": True}
