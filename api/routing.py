# api/routing.py
"""
REST API для selective routing.

Маршруты:
  GET    /api/routing/rules               — список всех правил
  POST   /api/routing/rules               — создать правило
                                              (поле type: cidr|domain|device)
  GET    /api/routing/rules/<id>          — одно правило
  PUT    /api/routing/rules/<id>          — обновить правило
  DELETE /api/routing/rules/<id>          — удалить правило
  POST   /api/routing/apply               — переприменить все правила

  GET    /api/routing/dnsmasq/status      — есть ли dnsmasq, версия,
                                              путь к конфигу, поддержка
                                              nftset, и т.п.
"""

from bottle import request, response


def register(app):

    @app.route("/api/routing/dnsmasq/status")
    def routing_dnsmasq_status():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            from core.routing import ipset_backend, nftset_backend
            dn_mod = DnsmasqIntegration()
            dn = dn_mod.status()
            backends = {
                "ipset":  ipset_backend.available(),
                "nftset": nftset_backend.available(),
            }
            preferred = ("nftset" if (dn.get("supports_nftset") and
                                      backends["nftset"])
                         else ("ipset" if backends["ipset"] else ""))
            return {"ok": True, "dnsmasq": dn,
                    "backends": backends,
                    "preferred_backend": preferred,
                    "auto_setup_applied": dn_mod.is_applied()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/dnsmasq/setup/plan")
    def routing_dnsmasq_setup_plan():
        """Что СДЕЛАЕТ кнопка «Настроить dnsmasq» — без побочек."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            return {"ok": True, "plan": DnsmasqIntegration().plan_auto_setup()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/dnsmasq/setup", method="POST")
    def routing_dnsmasq_setup():
        """Применить auto-setup dnsmasq (disable stub-listener и т.д.)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            return DnsmasqIntegration().auto_setup()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/dnsmasq/revert", method="POST")
    def routing_dnsmasq_revert():
        """Откатить auto-setup dnsmasq, вернуть systemd-resolved на :53."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            return DnsmasqIntegration().revert()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/rules")
    def routing_list():
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager
        try:
            iface_filter = (request.params.get("iface") or "").strip()
            rules = get_routing_manager().list_rules_dict()
            if iface_filter:
                rules = [r for r in rules
                         if r.get("target_iface") == iface_filter]
            return {"ok": True, "rules": rules}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/rules", method="POST")
    def routing_create():
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager, rule_from_dict

        try:
            body = request.json or {}
        except Exception:
            body = {}

        if not isinstance(body, dict) or not body.get("type"):
            response.status = 400
            return {"ok": False,
                    "error": "Тело должно содержать поле 'type'"}

        # Не даём клиенту навязать id — генерируем сами
        body.pop("id", None)

        try:
            rule = rule_from_dict(body)
        except (ValueError, TypeError) as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

        try:
            return get_routing_manager().add_rule(rule)
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/rules/<rid>")
    def routing_get(rid):
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager
        rule = get_routing_manager().get_rule(rid)
        if rule is None:
            response.status = 404
            return {"ok": False, "error": "Правило не найдено"}
        return {"ok": True, "rule": rule.to_dict()}

    @app.route("/api/routing/rules/<rid>", method="PUT")
    def routing_update(rid):
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager, rule_from_dict

        existing = get_routing_manager().get_rule(rid)
        if existing is None:
            response.status = 404
            return {"ok": False, "error": "Правило не найдено"}

        try:
            body = request.json or {}
        except Exception:
            body = {}
        body["id"] = rid
        # Тип меняем тоже из body, если передан, иначе берём существующий
        if not body.get("type"):
            body["type"] = existing.type_name

        try:
            rule = rule_from_dict(body)
        except (ValueError, TypeError) as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

        try:
            return get_routing_manager().update_rule(rule)
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/rules/<rid>", method="DELETE")
    def routing_delete(rid):
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager
        result = get_routing_manager().remove_rule(rid)
        if not result.get("ok"):
            response.status = 404 if "не найдено" in result.get("error", "") else 500
        return result

    @app.route("/api/routing/apply", method="POST")
    def routing_apply():
        response.content_type = "application/json; charset=utf-8"
        from core.routing import get_routing_manager
        try:
            return get_routing_manager().reapply_all()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
