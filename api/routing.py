# api/routing.py
"""
REST API для selective routing.

Маршруты:
  GET    /api/routing/rules               — список всех правил
  POST   /api/routing/rules               — создать правило
                                              (поле type: cidr|domain|device|dscp)
  GET    /api/routing/rules/<id>          — одно правило
  PUT    /api/routing/rules/<id>          — обновить правило
  DELETE /api/routing/rules/<id>          — удалить правило
  POST   /api/routing/apply               — переприменить все правила

  GET    /api/routing/dnsmasq/status      — есть ли dnsmasq, версия,
                                              путь к конфигу, поддержка
                                              nftset, и т.п.

  GET    /api/routing/ndms/status         — доступен ли Keenetic RCI,
                                              версия прошивки, активный backend
  GET    /api/routing/interfaces          — все доступные target-интерфейсы
                                              (наши AWG + нативные NDMS WG)

  GET    /api/routing/aliases             — что есть в кэше geosite:/geoip:
                                              + список рекомендованных алиасов
  POST   /api/routing/aliases/refresh     — обновить ВСЕ закэшированные
                                              алиасы (force-fetch с источника)
  POST   /api/routing/aliases/preview     — развернуть массив строк
                                              (body: {"items": [...]}) —
                                              для UI-предпросмотра

  GET    /api/routing/doh                 — настройки DoH-резолвера
  POST   /api/routing/doh                 — обновить настройки
                                              (body: {enabled, providers, timeout})
  POST   /api/routing/doh/test            — пинговать DoH-провайдер
                                              (body: {provider, domain})
"""

from bottle import request, response


def register(app):

    @app.route("/api/routing/ndms/status")
    def routing_ndms_status():
        """
        Доступен ли Keenetic NDMS-backend.

        Если ok=True и available=True — на странице Routing можно
        показывать «активен нативный Keenetic-backend, dnsmasq не
        требуется». На не-Keenetic-платформах всегда available=False
        без сетевого probe.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.ndms import is_ndms_available, get_rci_client
            avail = is_ndms_available()
            client = get_rci_client()
            return {
                "ok":        True,
                "available": avail,
                "version":   client.version() if avail else "",
                "backend":   "ndms" if avail else "",
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/ndms/refresh", method="POST")
    def routing_ndms_refresh():
        """Принудительный re-probe RCI (сбрасывает кэш доступности)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.ndms import is_ndms_available
            from core.ndms.wg_discovery import invalidate_cache
            invalidate_cache()
            avail = is_ndms_available(force=True)
            return {"ok": True, "available": avail}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/interfaces")
    def routing_interfaces():
        """
        Все доступные target-интерфейсы для routing-правил:
          - наши amneziawg-go (`awg0`, `opkgtun0`, ...)
          - нативные Keenetic WG (`Wireguard0..N`) — только если
            мы на Keenetic'е и RCI доступен;
          - sing-box TUN-инbound'ы (`tun0`, `singbox-tun`, ...) —
            читаем из активных sing-box-конфигов.

        Формат:
          {"ok": true,
           "interfaces": [
             {"name": "awg0", "source": "awg",  "type": "amneziawg-go", ...},
             {"name": "Wireguard0", "source": "ndms", "type": "wireguard"},
             {"name": "tun0", "source": "singbox", "type": "singbox-tun"},
             ...]}
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.awg_manager import AwgManager
            mgr = AwgManager()
            result = []
            seen = set()

            for iface in mgr.list_interfaces():
                nm = iface.get("name", "")
                if not nm or nm in seen:
                    continue
                seen.add(nm)
                entry = {
                    "name":   nm,
                    "active": iface.get("active", False),
                    "source": iface.get("source", "awg"),
                    "type":   "amneziawg-go",
                }
                if iface.get("native"):
                    entry["type"]   = "wireguard"
                    entry["source"] = "ndms"
                    entry["description"] = iface.get("description", "")
                    entry["state"]   = iface.get("state", "")
                    entry["address"] = iface.get("address", "")
                result.append(entry)

            # sing-box: для каждого активного конфига с tun-inbound'ом
            # отдаём interface_name из его секции interface (default
            # `tun0`). На уровне ядра он реально есть → ip rule на него
            # сработает.
            try:
                from core.singbox_manager import get_singbox_manager
                from core.singbox_config import parse_conf as _sb_parse
                sb_mgr = get_singbox_manager()
                for cfg in sb_mgr.list_configs():
                    name = cfg.get("name", "")
                    if not cfg.get("running") or not name:
                        continue
                    full = sb_mgr.get_config(name)
                    if not full.get("ok") or not full.get("parsed"):
                        continue
                    for ib in (full["parsed"].get("inbounds") or []):
                        if not isinstance(ib, dict):
                            continue
                        if ib.get("type") != "tun":
                            continue
                        ifname = (ib.get("interface_name")
                                  or "tun0")
                        if ifname in seen:
                            continue
                        seen.add(ifname)
                        result.append({
                            "name":        ifname,
                            "active":      True,
                            "source":      "singbox",
                            "type":        "singbox-tun",
                            "description": "sing-box (%s)" % name,
                        })
            except Exception as e:
                # sing-box ещё не интегрирован / упал — это норма
                # для большинства установок. Не валим весь endpoint.
                from core.log_buffer import log
                log.warning("routing/interfaces: sing-box не добавлен: %s"
                            % e, source="routing")

            return {"ok": True, "interfaces": result}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── geosite:/geoip: aliases (HydraRoute Neo compat) ──────

    @app.route("/api/routing/aliases")
    def routing_aliases_list():
        """
        Состояние кэша алиасов + список рекомендованных имён.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing import alias_resolver
            return {
                "ok":          True,
                "cached":      alias_resolver.list_cached(),
                "suggestions": alias_resolver.list_suggestions(),
                "ttl_hours":   alias_resolver.TTL_HOURS,
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/aliases/refresh", method="POST")
    def routing_aliases_refresh():
        """Force-refetch всех закэшированных алиасов."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing import alias_resolver
            return {"ok": True, "result": alias_resolver.refresh_all_cached()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/aliases/preview", method="POST")
    def routing_aliases_preview():
        """
        Разрешить массив строк (`{"items": ["youtube.com",
        "geosite:netflix", "geoip:ru"]}`) в реальный список — для
        UI-предпросмотра перед сохранением правила.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        items = body.get("items")
        if not isinstance(items, list):
            response.status = 400
            return {"ok": False, "error": "items должен быть массивом"}
        try:
            from core.routing import alias_resolver
            return {"ok": True,
                    "result": alias_resolver.expand_domains(items)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── DoH-резолвер (для pre-population на не-Keenetic) ──────

    @app.route("/api/routing/doh")
    def routing_doh_get():
        """Текущие настройки DoH + известные провайдеры."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing import doh_resolver
            return {
                "ok":       True,
                "settings": doh_resolver._get_settings(),
                "known":    dict(doh_resolver.KNOWN_PROVIDERS),
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/doh", method="POST")
    def routing_doh_set():
        """
        body: {"enabled": bool, "providers": [URL,...], "timeout": float}.
        Любое поле опционально (None оставляет существующее).
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        try:
            from core.routing import doh_resolver
            new_settings = doh_resolver.set_settings(
                enabled=body.get("enabled"),
                providers=body.get("providers"),
                timeout=body.get("timeout"),
            )
            return {"ok": True, "settings": new_settings}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/doh/test", method="POST")
    def routing_doh_test():
        """
        Прозвонить конкретный DoH-провайдер. Body:
          {"provider": "https://...", "domain": "example.com"}.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        provider = (body.get("provider") or "").strip()
        domain   = (body.get("domain")   or "example.com").strip()
        if not provider:
            response.status = 400
            return {"ok": False, "error": "provider обязателен"}
        try:
            from core.routing import doh_resolver
            ips = doh_resolver._query_json(
                provider, domain, "A", doh_resolver.DEFAULT_TIMEOUT)
            return {"ok": True, "ips": ips, "provider": provider,
                    "domain": domain}
        except Exception as e:
            return {"ok": False, "error": str(e),
                    "provider": provider, "domain": domain}

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
            # Прицепляем plan, чтобы UI мог показать кнопку «применить
            # обновления конфига», если у нас есть отложенные шаги
            # (например ретроактивное добавление user=root после
            # апгрейда версии).
            try:
                plan = dn_mod.plan_auto_setup()
            except Exception:
                plan = {"applicable": False, "steps": []}
            return {"ok": True, "dnsmasq": dn,
                    "backends": backends,
                    "preferred_backend": preferred,
                    "auto_setup_applied": dn_mod.is_applied(),
                    "auto_setup_plan": plan}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/dns-intercept")
    def routing_dns_intercept_status():
        """Статус перехвата DNS (:53 → наш прокси) для доменных правил."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing.dns_intercept import get_dns_intercept
            return {"ok": True, "status": get_dns_intercept().status()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/dns-intercept", method="POST")
    def routing_dns_intercept_set():
        """body: {"enabled": bool} — включить/выключить перехват DNS."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        try:
            from core.routing import dns_intercept
            res = dns_intercept.set_enabled(bool(body.get("enabled")))
            res["status"] = dns_intercept.get_dns_intercept().status()
            return res
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/routing/doctor")
    def routing_doctor():
        """Пошаговая диагностика цепочки маршрутизации (core/routing/doctor):
        по каждому правилу — где именно рвётся «правило есть, трафик мимо»."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.routing import doctor
            report = doctor.diagnose()
            report["text"] = doctor.render_text(report)
            return report
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
