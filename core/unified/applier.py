# core/unified/applier.py
"""
Применение маршрутов единого слоя поверх существующих движков.

Идея: UnifiedRoute — источник истины; «под капотом» он раскладывается
в УЖЕ существующие механизмы, которые протестированы и умеют
deferred-apply / masquerade / ndms / nft:

  • tunnel-метод (awg:/singbox:/mihomo:<iface>) →
      производные routing-правила DomainRoutingRule + CidrRoutingRule
      с детерминированными id (`uni-<route>-dom` / `-cidr`),
      target_iface = iface метода. Управляются через RoutingManager,
      поэтому переживают up/down интерфейса и переприменяются.

  • nfqws2 →
      домены назначения материализуются в управляемый hostlist
      `unified_<route>` (HostlistManager). nfqws2 должен быть запущен
      со стратегией, включающей этот hostlist.

  • direct →
      производные артефакты снимаются (трафик идёт штатно).

Смена активного метода = idempotent re-apply: артефакты неактуальных
методов удаляются, актуального — создаются/обновляются.

geosite/geoip в назначении движок ipset-routing не разворачивает
(это концепции sing-box/mihomo) — они игнорируются на этом уровне и
помечаются в результате как `skipped_selectors`.
"""

from core.log_buffer import log
from core.unified.model import UnifiedRoute, parse_method


def _dom_rule_id(route_id: str) -> str:
    return "uni-%s-dom" % route_id


def _cidr_rule_id(route_id: str) -> str:
    return "uni-%s-cidr" % route_id


def _hostlist_name(route_id: str) -> str:
    return ("unified_%s" % route_id).replace("-", "_")[:31]


def active_method(route: UnifiedRoute) -> str:
    """
    Текущий активный метод маршрута. По умолчанию — primary; если
    включён failover и монитор выбрал другой — берётся из состояния
    (core.unified.failover). Здесь — мягкая зависимость.
    """
    try:
        from core.unified import failover
        chosen = failover.current_method(route.id)
        if chosen:
            return chosen
    except Exception:
        pass
    return route.method


# ─────────────────────── apply / remove ──────────────────────────────

def apply_route(route: UnifiedRoute, method: str = None) -> dict:
    """Применить маршрут с заданным (или активным) методом."""
    if not isinstance(route, UnifiedRoute):
        return {"ok": False, "error": "Не UnifiedRoute"}
    method = method or active_method(route)
    try:
        kind, target = parse_method(method)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    resolved = route.destination.resolve()
    domains = resolved["domains"]
    cidrs = resolved["cidrs"]
    skipped = []
    if resolved.get("geosite") or resolved.get("geoip"):
        skipped.append("geosite/geoip (нужен sing-box/mihomo route)")

    if kind in ("awg", "singbox", "mihomo"):
        res = _apply_tunnel(route, target, domains, cidrs)
        res["method"] = method
        res["skipped_selectors"] = skipped
        return res
    if kind == "nfqws2":
        res = _apply_nfqws(route, domains)
        res["method"] = method
        res["skipped_selectors"] = skipped
        return res
    # direct — снимаем все производные артефакты, трафик идёт штатно.
    _remove_routing_rules(route.id)
    _remove_hostlist(route.id)
    log.info("unified: маршрут %s = direct (артефакты сняты)" % route.id,
             source="unified")
    return {"ok": True, "method": "direct", "skipped_selectors": skipped}


def remove_route(route: UnifiedRoute) -> dict:
    """Снять все производные артефакты маршрута."""
    rid = route.id if isinstance(route, UnifiedRoute) else str(route)
    _remove_routing_rules(rid)
    _remove_hostlist(rid)
    log.info("unified: маршрут %s снят" % rid, source="unified")
    return {"ok": True, "id": rid}


# ─────────────────────── tunnel method ───────────────────────────────

def _apply_tunnel(route, iface, domains, cidrs) -> dict:
    from core.routing import get_routing_manager
    from core.routing.rules import DomainRoutingRule, CidrRoutingRule
    mgr = get_routing_manager()
    results = []

    # domain-rule
    if domains:
        rule = DomainRoutingRule(
            target_iface=iface, domains=domains,
            rule_id=_dom_rule_id(route.id),
            description="unified:%s" % route.name)
        results.append(_upsert(mgr, rule))
    else:
        _remove_one(mgr, _dom_rule_id(route.id))

    # cidr-rule
    if cidrs:
        rule = CidrRoutingRule(
            target_iface=iface, cidrs=cidrs,
            rule_id=_cidr_rule_id(route.id),
            description="unified:%s" % route.name)
        results.append(_upsert(mgr, rule))
    else:
        _remove_one(mgr, _cidr_rule_id(route.id))

    # nfqws2-hostlist этого маршрута больше не нужен.
    _remove_hostlist(route.id)

    ok = all(r.get("ok", False) or r.get("deferred") for r in results) \
        if results else True
    return {"ok": ok, "iface": iface, "applied": results}


def _upsert(mgr, rule) -> dict:
    """Обновить правило, если уже есть, иначе добавить."""
    from core.routing import storage
    existing = storage.get_rule(rule.id)
    if existing is not None:
        return mgr.update_rule(rule)
    return mgr.add_rule(rule)


def _remove_one(mgr, rule_id):
    from core.routing import storage
    if storage.get_rule(rule_id) is not None:
        mgr.remove_rule(rule_id)


def _remove_routing_rules(route_id):
    from core.routing import get_routing_manager
    mgr = get_routing_manager()
    for rid in (_dom_rule_id(route_id), _cidr_rule_id(route_id)):
        _remove_one(mgr, rid)


# ─────────────────────── nfqws2 method ───────────────────────────────

def _apply_nfqws(route, domains) -> dict:
    # Снимаем возможные tunnel-артефакты этого маршрута.
    _remove_routing_rules(route.id)
    if not domains:
        _remove_hostlist(route.id)
        return {"ok": True, "note": "нет доменов для nfqws2-hostlist"}
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        name = _hostlist_name(route.id)
        res = hm.save_hostlist(name, domains)
        ok = bool(res.get("ok", True)) if isinstance(res, dict) else True
        return {"ok": ok, "hostlist": name, "domains": len(domains),
                "note": "nfqws2 должен использовать hostlist '%s'" % name}
    except Exception as e:
        return {"ok": False, "error": "hostlist: %s" % e}


def _remove_hostlist(route_id):
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        name = _hostlist_name(route_id)
        # Удаляем только если существует (best-effort).
        try:
            if name in (hm.list_names() or []):
                hm.delete_hostlist(name)
        except Exception:
            pass
    except Exception:
        pass


# ─────────────────────── bulk ────────────────────────────────────────

def apply_all() -> dict:
    """Применить все enabled-маршруты единого слоя."""
    from core.unified import storage
    results = []
    for route in storage.load_routes():
        if not route.enabled:
            remove_route(route)
            continue
        results.append({"id": route.id, "result": apply_route(route)})
    return {"ok": True, "applied": results}
