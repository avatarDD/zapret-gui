# api/tunnel_optimizer.py
"""
API-модуль оптимизатора латентности туннелей.

Эндпоинты:
  GET  /api/optimizer/status    — текущие TCP-настройки
  POST /api/optimizer/optimize  — применить оптимизации к интерфейсу
  POST /api/optimizer/optimize-all — оптимизировать все активные туннели
"""


from bottle import request


def register(app):
    """Зарегистрировать API-маршруты tunnel_optimizer."""

    @app.route("/api/optimizer/status", method="GET")
    def optimizer_status():
        from core.tunnel_optimizer import get_optimization_status
        return get_optimization_status()

    @app.route("/api/optimizer/optimize", method="POST")
    def optimizer_optimize():
        from core.tunnel_optimizer import optimize_iface, MTU_PROFILES
        data = request.json or {}
        iface = data.get("iface", "")
        profile = data.get("profile", "balanced")
        if not iface:
            return {"ok": False, "error": "Не указан iface"}
        if profile not in MTU_PROFILES:
            return {"ok": False, "error": "Неизвестный профиль: %s" % profile}
        return optimize_iface(iface, profile)

    @app.route("/api/optimizer/optimize-all", method="POST")
    def optimizer_optimize_all():
        from core.tunnel_optimizer import optimize_all_tunnels, MTU_PROFILES
        data = request.json or {}
        profile = data.get("profile", "balanced")
        if profile not in MTU_PROFILES:
            return {"ok": False, "error": "Неизвестный профиль: %s" % profile}
        return optimize_all_tunnels(profile)
