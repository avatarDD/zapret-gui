# core/unified/storage.py
"""
Хранилище маршрутов единого слоя в settings.json (секция
"unified_routes": [ <UnifiedRoute.to_dict()>, ... ]).

Паттерн повторяет core/routing/storage.py.
"""

import threading

from core.config_manager import get_config_manager
from core.unified.model import UnifiedRoute


_lock = threading.Lock()


def _all_raw() -> list:
    cm = get_config_manager()
    v = cm.get("unified_routes")
    return list(v) if isinstance(v, list) else []


def _save(items: list):
    cm = get_config_manager()
    cm.set("unified_routes", list(items))
    cm.save()


def load_routes() -> list:
    out = []
    for raw in _all_raw():
        try:
            out.append(UnifiedRoute.from_dict(raw))
        except (ValueError, TypeError):
            continue
    return out


def get_route(route_id: str):
    for raw in _all_raw():
        if raw.get("id") == route_id:
            try:
                return UnifiedRoute.from_dict(raw)
            except (ValueError, TypeError):
                return None
    return None


def add_route(route: UnifiedRoute):
    with _lock:
        items = [r for r in _all_raw() if r.get("id") != route.id]
        items.append(route.to_dict())
        _save(items)


def update_route(route: UnifiedRoute):
    add_route(route)


def remove_route(route_id: str) -> bool:
    with _lock:
        items = _all_raw()
        new = [r for r in items if r.get("id") != route_id]
        if len(new) == len(items):
            return False
        _save(new)
        return True
