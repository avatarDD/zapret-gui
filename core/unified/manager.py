# core/unified/manager.py
"""
Тонкая оркестрация единого слоя: CRUD маршрутов (storage) + применение
(applier). Используется API. Держим API-слой тонким и тестируемым.
"""

from core.log_buffer import log
from core.unified import storage, applier
from core.unified.model import UnifiedRoute


def list_routes() -> list:
    return [r.to_dict() for r in storage.load_routes()]


def get_route(route_id: str):
    r = storage.get_route(route_id)
    return r.to_dict() if r else None


def save_route(data: dict, *, apply: bool = True) -> dict:
    """Создать/обновить маршрут из dict. Валидирует модель, сохраняет,
    (опц.) применяет."""
    try:
        route = UnifiedRoute.from_dict(data or {})
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not route.has_selectors():
        return {"ok": False, "error": "Назначение пустое — укажите домены/"
                                      "CIDR/список/geosite, устройства "
                                      "или DSCP"}
    existing = storage.get_route(route.id)
    if existing is not None:
        storage.update_route(route)
    else:
        storage.add_route(route)
    applied = None
    if apply and route.enabled:
        applied = applier.apply_route(route)
    elif not route.enabled:
        applier.remove_route(route)
    _sync_monitor()
    log.info("unified: сохранён маршрут %s (%s → %s)"
             % (route.id, route.name, route.method), source="unified")
    return {"ok": True, "route": route.to_dict(), "applied": applied}


def _sync_monitor():
    """Поднять/остановить фоновый мониторинг по факту наличия маршрутов
    с включённым мониторингом/автопереключением."""
    try:
        from core.unified import monitor
        monitor.autostart_if_needed()
    except Exception:
        pass


def delete_route(route_id: str) -> dict:
    route = storage.get_route(route_id)
    if route is None:
        return {"ok": False, "error": "Маршрут не найден"}
    applier.remove_route(route)
    storage.remove_route(route_id)
    try:
        from core.unified import failover, monitor
        failover.reset(route_id)
        monitor.clear(route_id)
    except Exception:
        pass
    _sync_monitor()
    return {"ok": True, "id": route_id}


def apply_route_by_id(route_id: str) -> dict:
    route = storage.get_route(route_id)
    if route is None:
        return {"ok": False, "error": "Маршрут не найден"}
    return applier.apply_route(route)


def apply_all() -> dict:
    res = applier.apply_all()
    _sync_monitor()
    return res


def status() -> dict:
    """Сводка для UI: маршруты + успешность + активный метод + подсказки."""
    from core.unified import monitor, failover, scanner_hint
    routes = storage.load_routes()
    mon = monitor.stats()
    out = []
    for r in routes:
        rid = r.id
        active = failover.current_method(rid) or r.method
        suggestion = {}
        try:
            suggestion = scanner_hint.suggest_for_route(r)
        except Exception:
            suggestion = {}
        out.append({
            "id": rid, "name": r.name, "enabled": r.enabled,
            "method": r.method, "active_method": active,
            "fallbacks": r.fallbacks,
            "monitor_enabled": r.monitor_enabled,
            "failover_enabled": r.failover_enabled,
            "monitor": mon.get(rid, {}),
            "suggest_scan": suggestion.get("suggest", False),
            "suggest_reason": suggestion.get("reason", ""),
        })
    return {"ok": True, "routes": out,
            "monitor_running": monitor.get_monitor().running()}
