# api/warp_in_warp.py
"""
API-модуль WARP-in-WARP (MASQUE-based).

Эндпоинты:
  GET  /api/warp-in-warp/status  — статус
  GET  /api/warp-in-warp/detect  — доступность компонентов
  POST /api/warp-in-warp/up      — запуск
  POST /api/warp-in-warp/down    — остановка
"""

import json

from bottle import request


def register(app):
    """Зарегистрировать API-маршруты warp_in_warp."""

    @app.route("/api/warp-in-warp/status", method="GET")
    def wiw_status():
        from core.warp_in_warp import get_warp_in_warp_manager
        return get_warp_in_warp_manager().get_status()

    @app.route("/api/warp-in-warp/detect", method="GET")
    def wiw_detect():
        from core.warp_in_warp import get_warp_in_warp_manager
        return get_warp_in_warp_manager().detect()

    @app.route("/api/warp-in-warp/up", method="POST")
    def wiw_up():
        from core.warp_in_warp import get_warp_in_warp_manager
        data = json.loads(request.body.read()) if request.body else {}
        return get_warp_in_warp_manager().start(
            mode=data.get("mode", "masque_masque"),
            outer_sni=data.get("outer_sni", ""),
            inner_sni=data.get("inner_sni", ""),
            outer_config=data.get("outer_config", ""),
            inner_config=data.get("inner_config", ""),
            awg_conf=data.get("awg_conf", ""),
        )

    @app.route("/api/warp-in-warp/down", method="POST")
    def wiw_down():
        from core.warp_in_warp import get_warp_in_warp_manager
        return get_warp_in_warp_manager().stop()
