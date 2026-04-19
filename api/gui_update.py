# api/gui_update.py
"""
API обновления zapret-gui.

Эндпоинты:
  GET  /api/gui/version     — текущая версия GUI
  GET  /api/gui/check       — проверить наличие обновлений GUI
  POST /api/gui/update      — обновить GUI до последней версии
  GET  /api/gui/progress    — прогресс обновления
"""

import threading
from bottle import request, response


# Краткий таймаут: ловим быстрые ошибки, затем возвращаем in_progress
_UPDATE_THREAD_TIMEOUT = 5


def register(app):

    @app.route("/api/gui/version")
    def api_gui_version():
        """Текущая установленная версия GUI."""
        response.content_type = "application/json; charset=utf-8"

        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()
        return {"ok": True, **updater.get_installed_version()}

    @app.route("/api/gui/check")
    def api_gui_check():
        """Проверить наличие обновлений GUI."""
        response.content_type = "application/json; charset=utf-8"

        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()

        force = request.params.get("force", "").lower() in ("1", "true")
        if force:
            updater.get_latest_version(force_refresh=True)

        comparison = updater.get_version_comparison()
        return {"ok": True, **comparison}

    @app.post("/api/gui/update")
    def api_gui_update():
        """Обновить GUI до последней версии."""
        response.content_type = "application/json; charset=utf-8"

        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()

        # Проверяем, не идёт ли уже обновление
        op = updater.get_operation_status()
        if op["in_progress"]:
            return {
                "ok": True,
                "message": "Обновление уже выполняется.",
                "in_progress": True,
            }

        try:
            body = request.json or {}
        except Exception:
            body = {}

        branch = body.get("branch", "main")

        # Запускаем в фоновом потоке
        result_holder = {"result": None}

        def update_task():
            result_holder["result"] = updater.update(branch=branch)

        t = threading.Thread(
            target=update_task, daemon=True, name="gui-update"
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

    @app.route("/api/gui/progress")
    def api_gui_progress():
        """Прогресс текущей операции обновления GUI."""
        response.content_type = "application/json; charset=utf-8"

        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()
        return {"ok": True, **updater.get_operation_status()}
