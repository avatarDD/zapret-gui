# core/unified/applier.py
"""
Применение маршрутов единого слоя поверх существующих движков.

Идея: UnifiedRoute — источник истины; «под капотом» он раскладывается
в УЖЕ существующие механизмы, которые протестированы и умеют
deferred-apply / masquerade / ndms / nft:

  • tunnel-метод (awg:/singbox:/mihomo:<iface>) →
      производные routing-правила DomainRoutingRule + CidrRoutingRule
      + DeviceRoutingRule (по одному на устройство) + DscpRoutingRule
      с детерминированными id (`uni-<route>-dom` / `-cidr` /
      `-dev-<hash(ip)>` / `-dscp`), target_iface = iface метода.
      Управляются через RoutingManager, поэтому переживают up/down
      интерфейса и переприменяются.

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

import hashlib

from core.log_buffer import log
from core.unified.model import UnifiedRoute, parse_method


def _dom_rule_id(route_id: str) -> str:
    return "uni-%s-dom" % route_id


def _cidr_rule_id(route_id: str) -> str:
    return "uni-%s-cidr" % route_id


def _dscp_rule_id(route_id: str) -> str:
    return "uni-%s-dscp" % route_id


def _dev_rule_prefix(route_id: str) -> str:
    return "uni-%s-dev-" % route_id


def _dev_rule_id(route_id: str, ip: str) -> str:
    """Детерминированный id device-правила: один на устройство (по ip)."""
    h = hashlib.sha1(ip.encode("utf-8", "replace")).hexdigest()[:8]
    return _dev_rule_prefix(route_id) + h


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
    has_geo = bool(resolved.get("geosite") or resolved.get("geoip"))
    has_src = bool(route.devices) or route.dscp is not None
    skipped = []

    if kind in ("awg", "singbox", "mihomo"):
        # sing-box умеет geosite/geoip нативно (geo_engine → route-правила
        # движка с его geo-базой). Для AWG (и mihomo — у него нет YAML-
        # эмиттера geo) заворачиваем geo через dnsmasq + ipset/nftset:
        # geosite → домены, geoip → CIDR в interval-set — тот же путь, что
        # у обычных доменов (domain_rule._expand_rule/_add_static_cidrs).
        geo_native = (kind == "singbox")
        tun_domains = list(domains)
        if not geo_native and has_geo:
            tun_domains += ["geosite:%s" % g
                            for g in (resolved.get("geosite") or [])]
            tun_domains += ["geoip:%s" % g
                            for g in (resolved.get("geoip") or [])]
        res = _apply_tunnel(route, target, tun_domains, cidrs)
        if geo_native:
            geo = _apply_geo(route, method)
            if geo.get("skipped"):
                skipped.append(geo.get("reason", "geosite/geoip пропущены"))
        else:
            # снять возможный прежний sing-box-инжект и не вводить в
            # заблуждение «skipped» — geo уже в domain-rule выше.
            _remove_geo(route)
            geo = ({"ok": True, "via": "domain-set"} if has_geo
                   else {"ok": True, "noop": True})
        res["method"] = method
        res["geo"] = geo
        res["skipped_selectors"] = skipped
        return res
    if kind == "nfqws2":
        res = _apply_nfqws(route, domains)
        if has_geo:
            skipped.append("geosite/geoip игнорируются для метода nfqws2")
        if has_src:
            skipped.append("устройства/DSCP применимы только к туннельным "
                           "методам — для nfqws2 пропущены")
        _remove_geo(route)
        res["method"] = method
        res["skipped_selectors"] = skipped
        return res
    # direct — снимаем все производные артефакты, трафик идёт штатно.
    _remove_routing_rules(route.id)
    _remove_hostlist(route.id)
    _remove_geo(route)
    _rebuild_nfqws_aggregate()
    if has_geo:
        skipped.append("geosite/geoip игнорируются для метода direct")
    if has_src:
        skipped.append("устройства/DSCP применимы только к туннельным "
                       "методам — для direct пропущены")
    log.info("unified: маршрут %s = direct (артефакты сняты)" % route.id,
             source="unified")
    return {"ok": True, "method": "direct", "skipped_selectors": skipped}


def remove_route(route: UnifiedRoute) -> dict:
    """Снять все производные артефакты маршрута."""
    rid = route.id if isinstance(route, UnifiedRoute) else str(route)
    _remove_routing_rules(rid)
    _remove_hostlist(rid)
    if isinstance(route, UnifiedRoute):
        _remove_geo(route)
    _rebuild_nfqws_aggregate()
    log.info("unified: маршрут %s снят" % rid, source="unified")
    return {"ok": True, "id": rid}


def _apply_geo(route, method) -> dict:
    try:
        from core.unified import geo_engine
        return geo_engine.apply_geo(route, method)
    except Exception as e:
        log.warning("unified geo apply %s: %s" % (route.id, e),
                    source="unified")
        return {"ok": False, "error": str(e)}


def _remove_geo(route):
    try:
        from core.unified import geo_engine
        geo_engine.remove_geo(route)
    except Exception:
        pass


def _rebuild_nfqws_aggregate():
    """Пересобрать агрегатный nfqws2-hostlist (после ухода маршрута с nfqws2)."""
    try:
        from core.unified import nfqws_hostlist
        nfqws_hostlist.rebuild()
    except Exception:
        pass


# ─────────────────────── tunnel method ───────────────────────────────

def _apply_tunnel(route, iface, domains, cidrs) -> dict:
    from core.routing import get_routing_manager
    from core.routing.rules import (DomainRoutingRule, CidrRoutingRule,
                                    DeviceRoutingRule, DscpRoutingRule)
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

    # device-rules: по одному на устройство; снятые из маршрута
    # устройства убираем (id у каждого детерминирован по ip).
    wanted_dev_ids = set()
    for dev in (route.devices or []):
        rid = _dev_rule_id(route.id, dev["ip"])
        wanted_dev_ids.add(rid)
        rule = DeviceRoutingRule(
            target_iface=iface, source_ip=dev["ip"],
            mac=dev.get("mac", ""), hostname=dev.get("hostname", ""),
            rule_id=rid,
            description="unified:%s" % route.name)
        results.append(_upsert(mgr, rule))
    for stale in _derived_device_ids(route.id):
        if stale not in wanted_dev_ids:
            _remove_one(mgr, stale)

    # dscp-rule
    if route.dscp is not None:
        rule = DscpRoutingRule(
            target_iface=iface, dscp=route.dscp,
            proxy_self=route.dscp_self,
            rule_id=_dscp_rule_id(route.id),
            description="unified:%s" % route.name)
        results.append(_upsert(mgr, rule))
    else:
        _remove_one(mgr, _dscp_rule_id(route.id))

    # nfqws2-hostlist этого маршрута больше не нужен.
    _remove_hostlist(route.id)
    _rebuild_nfqws_aggregate()

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


def _derived_device_ids(route_id) -> list:
    """id всех device-правил, производных от маршрута (по префиксу)."""
    from core.routing import storage
    prefix = _dev_rule_prefix(route_id)
    out = []
    for rule in storage.load_rules():
        if rule.type_name == "device" and rule.id.startswith(prefix):
            out.append(rule.id)
    return out


def _remove_routing_rules(route_id):
    from core.routing import get_routing_manager
    mgr = get_routing_manager()
    for rid in (_dom_rule_id(route_id), _cidr_rule_id(route_id),
                _dscp_rule_id(route_id)):
        _remove_one(mgr, rid)
    for rid in _derived_device_ids(route_id):
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
    except Exception as e:
        return {"ok": False, "error": "hostlist: %s" % e}
    # Пересобираем агрегат и (если фича включена) перезапускаем nfqws2,
    # чтобы домены реально подхватились запущенной стратегией.
    agg = None
    try:
        from core.unified import nfqws_hostlist
        agg = nfqws_hostlist.rebuild()
    except Exception as e:
        log.warning("unified nfqws aggregate: %s" % e, source="unified")
    return {"ok": ok, "hostlist": name, "domains": len(domains),
            "aggregate": agg,
            "note": ("включите nfqws.unified_hostlist, чтобы стратегия "
                     "применялась к этим доменам автоматически")}


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
