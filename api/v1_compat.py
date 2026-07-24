# api/v1_compat.py
"""
MR-56: Backward-compatible /api/v1/ versioning layer.

После того как все /api/<path> маршруты зарегистрированы в `app`,
вызов `register_v1_aliases(app)` добавляет идентичные маршруты
под префиксом /api/v1/<path>.

Это означает:
  GET  /api/updates         — работает (старый путь, без изменений)
  GET  /api/v1/updates      — то же самое (новый v1-путь)
  POST /api/updates/check   — работает
  POST /api/v1/updates/check — то же самое

Клиентский код (JS/curl) может работать со старыми путями бесконечно;
новый код — использовать /api/v1/ как стабильный контракт.
"""

import functools


def register_v1_aliases(app):
    """
    Добавить /api/v1/<path> aliases для всех маршрутов /api/<path>.

    Вызывается ПОСЛЕ register_routes(app), чтобы все маршруты
    уже были зарегистрированы в Bottle-роутере.

    Bottle хранит маршруты в app.router.rules (Bottle < 0.13)
    или через app.routes (Bottle >= 0.13).  Мы обходим app.routes,
    которые Bottle накапливает в app.routes как список Route-объектов.
    """
    _V1_PREFIX = "/api/v1"
    _API_PREFIX = "/api"

    # Собираем маршруты, которые нужно зеркалировать, ДО итерации,
    # чтобы не изменять список во время обхода.
    to_alias = []
    for route in list(app.routes):
        path = route.rule  # type: str
        if not path.startswith(_API_PREFIX + "/"):
            continue
        # Не добавляем alias на уже существующие /api/v1/ маршруты
        if path.startswith(_V1_PREFIX + "/"):
            continue
        v1_path = _V1_PREFIX + path[len(_API_PREFIX):]
        to_alias.append((v1_path, route.method, route.callback))

    for v1_path, method, callback in to_alias:
        # Избегаем дублирования, если alias уже есть
        existing = {r.rule for r in app.routes}
        if v1_path not in existing:
            app.route(v1_path, method=method)(callback)
