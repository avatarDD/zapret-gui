# api/tunnel_optimizer.py
"""
API-модуль оптимизатора латентности туннелей.

Эндпоинты:
  GET  /api/optimizer/status    — текущие TCP-настройки
  POST /api/optimizer/optimize  — применить оптимизации к интерфейсу
  POST /api/optimizer/optimize-all — оптимизировать все активные туннели
"""

import json

from bottle import request


def register(app):
    """Зарегистрировать API-маршруты tunnel_optimizer."""

    @app.route("/api/optimizer/status", method="GET")
    def optimizer_status():
        from core.tunnel_optimizer import get_optimization_status
        return get_optimization_status()

    @app.route("/api/optimizer/optimize", method="POST")
    def optimizer_optimize():
        from core.tunnel_optimizer import optimize_iface
        data = json.loads(request.body.read()) if request.body else {}
        iface = data.get("iface", "")
        profile = data.get("profile", "balanced")
        if not iface:
            return {"ok": False, "error": "Не указан iface"}
        return optimize_iface(iface, profile)

    @app.route("/api/optimizer/optimize-all", method="POST")
    def optimizer_optimize_all():
        from core.tunnel_optimizer import optimize_all_tunnels
        data = json.loads(request.body.read()) if request.body else {}
        profile = data.get("profile", "balanced")
        return optimize_all_tunnels(profile)
