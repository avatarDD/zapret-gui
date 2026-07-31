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


def reapply_all() -> dict:
    """
    Полное переприменение маршрутизации + сброс «левых» артефактов.

    Ручное «привести систему в соответствие с тем, что показано в GUI»:

      1. sweep — снимаем `ip rule`/set'ы/таблицы, за которыми не стоит
         ни одного правила (см. core/routing/sweeper). Первым шагом,
         чтобы протухший перехват не мешал свежим правилам;
      2. unified apply_all — каждый маршрут раскладывается заново
         (update_rule = снять старое + применить новое), домены при
         этом резолвятся заново;
      3. reapply низкоуровневых правил, НЕ производных от единого слоя
         (legacy без `uni-`-префикса) — их apply_all не трогает;
      4. будим рефрешер IP, чтобы не ждать его 10-минутного такта.

    Типичный случай: у туннеля поменяли AllowedIPs (или он переподнялся
    с другим набором подсетей) — правила остались прежними, но набор
    IP/таблица в ядре успели протухнуть.
    """
    out = {"ok": True}

    try:
        from core.routing import sweeper
        out["sweep"] = sweeper.sweep()
    except Exception as e:
        out["sweep"] = {"ok": False, "error": str(e)}
        log.warning("unified reapply: sweep: %s" % e, source="unified")

    out["applied"] = applier.apply_all()

    try:
        out["legacy"] = _reapply_legacy()
    except Exception as e:
        out["legacy"] = {"ok": False, "error": str(e)}
        log.warning("unified reapply: legacy: %s" % e, source="unified")

    try:
        from core.routing import domain_refresh
        domain_refresh.ensure_started()
        domain_refresh.kick()
    except Exception:
        pass

    _sync_monitor()
    out["ok"] = all(
        (out.get(k) or {}).get("ok", True)
        for k in ("sweep", "applied", "legacy")
    )
    log.info("unified: маршрутизация переприменена (сброшено левых: %d)"
             % (out.get("sweep", {}).get("total") or 0), source="unified")
    return out


def _reapply_legacy() -> dict:
    """Снять и применить заново низкоуровневые правила вне единого слоя.

    Производные единого слоя (`uni-…`) пропускаем: их только что
    переприменил applier.apply_all(), повтор стоил бы второго резолва
    всех доменов.
    """
    from core.routing import get_routing_manager
    mgr = get_routing_manager()
    done, errors = [], []
    for rule in mgr.list_rules():
        if rule.id.startswith("uni-"):
            continue
        try:
            mgr.remove_applied_rule(rule.id)
            if rule.enabled:
                res = mgr.apply_rule(rule.id)
                done.append({"id": rule.id, "result": res})
        except Exception as e:
            errors.append("%s: %s" % (rule.id, e))
    return {"ok": not errors, "applied": done, "errors": errors}


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
