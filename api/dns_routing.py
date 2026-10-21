# api/dns_routing.py
"""
API-модуль Per-domain DNS routing.

Эндпоинты:
  GET  /api/dns-routing/rules      — список правил
  POST /api/dns-routing/rules      — добавить правило
  DELETE /api/dns-routing/rules/<domain> — удалить правило
  POST /api/dns-routing/apply      — применить правила (dnsmasq)
  GET  /api/dns-routing/servers    — доступные DNS-серверы
  GET  /api/dns-routing/bench      — последний замер серверов
  POST /api/dns-routing/bench      — замерить серверы (core/dns_bench)
  POST /api/dns-routing/autoselect — замерить и сделать лучший «auto»
"""


from bottle import request


def register(app):
    """Зарегистрировать API-маршруты dns_routing."""

    @app.route("/api/dns-routing/rules", method="GET")
    def dns_rules():
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        return {"ok": True, "rules": mgr.get_rules()}

    @app.route("/api/dns-routing/rules", method="POST")
    def dns_add_rule():
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        data = request.json or {}
        domain = (data.get("domain") or "").strip()
        dns_server = (data.get("dns") or "").strip()
        description = (data.get("description") or "").strip()
        if not domain or not dns_server:
            return {"ok": False, "error": "domain и dns обязательны"}
        return mgr.add_rule(domain, dns_server, description)

    @app.route("/api/dns-routing/rules/batch", method="POST")
    def dns_add_rules_batch():
        """MR-82: Batch-добавление правил одним сохранением конфига."""
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        data = request.json or {}
        items = data.get("rules") or []
        if not isinstance(items, list):
            return {"ok": False, "error": "rules должен быть массивом"}
        return mgr.add_rules_batch(items)

    @app.route("/api/dns-routing/rules/<domain>", method="DELETE")
    def dns_remove_rule(domain):
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        return mgr.remove_rule(domain)

    @app.route("/api/dns-routing/apply", method="POST")
    def dns_apply():
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        return mgr.apply()

    @app.route("/api/dns-routing/servers", method="GET")
    def dns_servers():
        from core.dns_routing import get_dns_routing_manager
        mgr = get_dns_routing_manager()
        return {"ok": True, "servers": mgr.get_available_servers()}

    @app.route("/api/dns-routing/bench", method="GET")
    def dns_bench_last():
        from core import dns_bench
        return dns_bench.last()

    @app.route("/api/dns-routing/bench", method="POST")
    def dns_bench_run():
        from core import dns_bench
        return dns_bench.benchmark()

    @app.route("/api/dns-routing/autoselect", method="POST")
    def dns_autoselect():
        from core import dns_bench
        try:
            fresh = bool((request.json or {}).get("fresh", True))
        except Exception:
            fresh = True
        return dns_bench.autoselect(fresh=fresh)
