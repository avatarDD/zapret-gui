# api/tunnel_optimizer.py
"""
API-модуль оптимизатора латентности туннелей.

Эндпоинты:
  GET  /api/optimizer/status    — текущие TCP-настройки
  POST /api/optimizer/optimize  — применить оптимизации к интерфейсу
  POST /api/optimizer/optimize-all — оптимизировать все активные туннели
  POST /api/optimizer/probe-pmtu — dataplane PMTU probe
  POST /api/optimizer/restore    — полный откат sysctl/MTU/qdisc/MSS
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
        kind = data.get("transport_kind", "")
        if kind not in ("", "warp", "awg", "singbox", "mihomo"):
            return {"ok": False, "error": "Неизвестный transport_kind: %s" % kind}
        return optimize_iface(iface, profile, transport_kind=kind)

    @app.route("/api/optimizer/optimize-all", method="POST")
    def optimizer_optimize_all():
        from core.tunnel_optimizer import optimize_all_tunnels, MTU_PROFILES
        data = request.json or {}
        profile = data.get("profile", "balanced")
        if profile not in MTU_PROFILES:
            return {"ok": False, "error": "Неизвестный профиль: %s" % profile}
        return optimize_all_tunnels(profile)

    @app.route("/api/optimizer/probe-pmtu", method="POST")
    def optimizer_probe_pmtu():
        from core.tunnel_optimizer import probe_pmtu
        data = request.json or {}
        return probe_pmtu(
            data.get("iface", ""),
            data.get("host", "1.1.1.1"),
            data.get("minimum", 1280),
            data.get("maximum", 1500),
        )

    @app.route("/api/optimizer/restore", method="POST")
    def optimizer_restore():
        from core.tunnel_optimizer import restore_system_defaults
        return restore_system_defaults(only_if_idle=False)
