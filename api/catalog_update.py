# api/catalog_update.py
"""
API обновления каталогов стратегий nfqws2.

Эндпоинты:
  GET  /api/catalog/check    — статус локальных каталогов и наличие обновлений
  POST /api/catalog/update   — скачать и применить последнюю версию каталогов
  GET  /api/catalog/progress — прогресс текущей операции обновления
"""

import threading

from bottle import request, response


# Сколько секунд ждём результата обновления в синхронном запросе,
# прежде чем вернуть in_progress.
_UPDATE_THREAD_TIMEOUT = 5


def register(app):

    @app.route("/api/catalog/check")
    def api_catalog_check():
        """Локальный статус каталогов + последний коммит в источнике."""
        response.content_type = "application/json; charset=utf-8"

        from core.catalog_updater import get_catalog_updater

        updater = get_catalog_updater()
        force = request.params.get("force", "").lower() in ("1", "true")
        return {"ok": True, **updater.get_comparison(force_refresh=force)}

    @app.post("/api/catalog/update")
    def api_catalog_update():
        """Скачать и установить актуальные каталоги winws2."""
        response.content_type = "application/json; charset=utf-8"

        from core.catalog_updater import get_catalog_updater

        updater = get_catalog_updater()
        op = updater.get_operation_status()
        if op["in_progress"]:
            return {
                "ok": True,
                "message": "Обновление уже выполняется.",
                "in_progress": True,
            }

        result_holder = {"result": None}

        def task():
            result_holder["result"] = updater.update()

        t = threading.Thread(
            target=task, daemon=True, name="catalog-update"
        )
        t.start()
        t.join(timeout=_UPDATE_THREAD_TIMEOUT)

        if t.is_alive():
            return {
                "ok": True,
                "message": "Обновление запущено. Следите за прогрессом.",
                "in_progress": True,
            }

        result = result_holder["result"]
        if result:
            if not result.get("ok"):
                response.status = 500
            return result

        response.status = 500
        return {"ok": False, "message": "Внутренняя ошибка обновления"}

    @app.route("/api/catalog/progress")
    def api_catalog_progress():
        """Прогресс текущей операции обновления каталогов."""
        response.content_type = "application/json; charset=utf-8"

        from core.catalog_updater import get_catalog_updater
        return {"ok": True, **get_catalog_updater().get_operation_status()}
