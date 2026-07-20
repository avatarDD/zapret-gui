# core/unified/migration.py
"""
Миграция legacy-правил selective routing (core/routing, хранилище
`routing.rules`) в единый слой маршрутизации (core/unified).

До слияния разделов было ДВА независимых хранилища правил:
  • unified_routes (единый слой, «что → через что»);
  • routing.rules (низкоуровневые AWG-правила: cidr/domain/device/dscp).

Производные правила единого слоя живут в том же routing.rules с
префиксом id `uni-` — они НЕ мигрируются (ими уже владеет unified).
Любое другое («legacy») правило заворачивается в UnifiedRoute 1:1:

  cidr   → destination.cidrs
  domain → destination.domains
  device → devices=[{ip,mac,hostname}]
  dscp   → dscp / dscp_self

Метод — `awg:<iface>` (покрывает и нативные NDMS-интерфейсы: бэкенд
routing сам выбирает NDMS по имени iface), либо `singbox:<iface>`,
если iface принадлежит tun-инбаунду sing-box-конфига.

id мигрированного маршрута детерминирован (`mig-<legacy_id>`), поэтому
повторный запуск после сбоя на полпути не плодит дубликатов: маршрут
перезаписывается, а не клонируется.

Порядок на каждое правило (минимизирует окно потери трафика и
исключает потерю данных):
  1) собрать и провалидировать UnifiedRoute (ValueError → правило
     остаётся как было, в отчёт пишется ошибка);
  2) записать маршрут в unified-storage (без изменений в ядре);
  3) снять legacy-правило через RoutingManager (откат ip rule/ipset
     старого id + удаление из routing.rules);
  4) применить маршрут (создаст производные uni-* правила).

Запускается на boot GUI (app.py) и вручную через
POST /api/unified/migrate.
"""

from core.log_buffer import log
from core.unified.model import UnifiedRoute, Destination


def legacy_rules() -> list:
    """Legacy-правила (dict) из routing.rules — всё, что не `uni-*`."""
    from core.routing import get_routing_manager
    out = []
    for d in get_routing_manager().list_rules_dict():
        rid = d.get("id") or ""
        if not rid.startswith("uni-"):
            out.append(d)
    return out


def _singbox_tun_ifaces() -> set:
    """Имена tun-интерфейсов из sing-box-конфигов (best-effort)."""
    names = set()
    try:
        from core.singbox_manager import get_singbox_manager
        mgr = get_singbox_manager()
        for cfg in mgr.list_configs():
            name = cfg.get("name", "")
            if not name:
                continue
            full = mgr.get_config(name)
            parsed = full.get("parsed") if isinstance(full, dict) else None
            for ib in ((parsed or {}).get("inbounds") or []):
                if isinstance(ib, dict) and ib.get("type") == "tun":
                    names.add(ib.get("interface_name") or "tun0")
    except Exception:
        pass
    return names


def _warp_ifaces() -> set:
    """Имена TUN-интерфейсов usque (WARP/MASQUE)."""
    names = set()
    try:
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        for cfg in mgr.list_configs():
            iface = cfg.get("iface", "")
            if iface:
                names.add(iface)
    except Exception:
        pass
    return names


def method_for_iface(iface: str, singbox_ifaces=None) -> str:
    """
    Подобрать method-токен для целевого интерфейса legacy-правила.
    sing-box-tun → singbox:<iface>; usque (WARP) → warp:<iface>;
    всё остальное (наши AWG, нативные NDMS WG и пр.) → awg:<iface>.
    """
    sb = (singbox_ifaces if singbox_ifaces is not None
          else _singbox_tun_ifaces())
    if iface in sb:
        return "singbox:%s" % iface
    if iface in _warp_ifaces():
        return "warp:%s" % iface
    return "awg:%s" % iface


def _route_from_legacy(d: dict, singbox_ifaces) -> UnifiedRoute:
    """Собрать UnifiedRoute из legacy-правила. ValueError при битом."""
    rtype = (d.get("type") or "").strip().lower()
    iface = (d.get("target_iface") or "").strip()
    if not iface:
        raise ValueError("у правила %s нет target_iface" % d.get("id"))

    destination = Destination()
    devices = []
    dscp = None
    dscp_self = False

    if rtype == "cidr":
        destination = Destination(cidrs=d.get("cidrs") or [])
    elif rtype == "domain":
        destination = Destination(domains=d.get("domains") or [])
    elif rtype == "device":
        ip = (d.get("source_ip") or "").strip()
        if not ip:
            raise ValueError("device-правило %s без source_ip" % d.get("id"))
        devices = [{"ip": ip, "mac": d.get("mac") or "",
                    "hostname": d.get("hostname") or ""}]
    elif rtype == "dscp":
        dscp = d.get("dscp")
        dscp_self = bool(d.get("proxy_self", False))
    else:
        raise ValueError("неизвестный тип legacy-правила: %s" % rtype)

    name = (d.get("description") or "").strip()
    if not name:
        hint = ""
        if rtype == "device" and devices:
            hint = devices[0].get("hostname") or devices[0]["ip"]
        elif rtype == "dscp":
            hint = "DSCP %s" % dscp
        name = ("%s → %s" % (hint, iface)) if hint \
            else ("%s → %s" % (rtype, iface))

    return UnifiedRoute(
        route_id="mig-%s" % (d.get("id") or ""),
        name=name,
        destination=destination,
        devices=devices,
        dscp=dscp,
        dscp_self=dscp_self,
        method=method_for_iface(iface, singbox_ifaces),
        enabled=bool(d.get("enabled", True)),
        priority=int(d.get("priority") or 0),
        created_at=int(d.get("created_at") or 0),
    )


def migrate(apply: bool = True) -> dict:
    """
    Перенести все legacy-правила в единый слой.

    Возвращает {"ok", "migrated": [ {legacy_id, route_id}, ...],
    "errors": [str, ...]}. ok=True, если ни одной ошибки (в т.ч. когда
    мигрировать нечего — идемпотентный no-op).
    """
    from core.routing import get_routing_manager
    from core.unified import storage, applier

    legacy = legacy_rules()
    if not legacy:
        return {"ok": True, "migrated": [], "errors": []}

    singbox_ifaces = _singbox_tun_ifaces()
    rmgr = get_routing_manager()
    migrated, errors = [], []

    for d in legacy:
        legacy_id = d.get("id") or "?"
        try:
            route = _route_from_legacy(d, singbox_ifaces)
        except (ValueError, TypeError) as e:
            errors.append("%s: %s" % (legacy_id, e))
            continue
        # 1) Персистим маршрут (id детерминирован — повтор перезапишет).
        storage.add_route(route)
        # 2) Снимаем legacy-артефакты и убираем правило из routing.rules.
        try:
            rmgr.remove_rule(legacy_id)
        except Exception as e:
            log.warning("unified migrate: снятие legacy %s: %s"
                        % (legacy_id, e), source="unified")
        # 3) Применяем маршрут (создаст производные uni-* правила).
        if apply and route.enabled:
            try:
                applier.apply_route(route)
            except Exception as e:
                log.warning("unified migrate: apply %s: %s"
                            % (route.id, e), source="unified")
        migrated.append({"legacy_id": legacy_id, "route_id": route.id,
                         "name": route.name, "method": route.method})
        log.info("unified migrate: %s → маршрут %s (%s)"
                 % (legacy_id, route.id, route.method), source="unified")

    try:
        from core.unified import monitor
        monitor.autostart_if_needed()
    except Exception:
        pass

    return {"ok": not errors, "migrated": migrated, "errors": errors}


def migrate_on_boot():
    """
    Авто-миграция при старте GUI: тихий no-op, когда legacy-правил нет.
    Любые исключения гасятся — boot не должен падать из-за миграции.
    """
    try:
        if not legacy_rules():
            return
        res = migrate(apply=True)
        log.info("unified migrate (boot): перенесено %d, ошибок %d"
                 % (len(res.get("migrated") or []),
                    len(res.get("errors") or [])),
                 source="unified")
        for err in (res.get("errors") or []):
            log.warning("unified migrate (boot): %s" % err, source="unified")
    except Exception as e:
        log.warning("unified migrate (boot) упал: %s" % e, source="unified")
