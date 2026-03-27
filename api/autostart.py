# api/autostart.py
"""
API автозапуска.

Эндпоинты:
  GET  /api/autostart           — статус автозапуска
  POST /api/autostart/enable    — включить
  POST /api/autostart/disable   — выключить
  POST /api/autostart/regenerate — пересоздать скрипт
  GET  /api/autostart/script    — содержимое скрипта
  GET  /api/autostart/preview   — превью генерируемого скрипта
"""

from bottle import request, response


def register(app):

    @app.route("/api/autostart")
    def api_autostart_status():
        """Статус автозапуска."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        status = am.get_status()

        return {"ok": True, **status}

    @app.post("/api/autostart/enable")
    def api_autostart_enable():
        """Включить автозапуск."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        result = am.enable()

        if not result["ok"]:
            response.status = 400

        return result

    @app.post("/api/autostart/disable")
    def api_autostart_disable():
        """Выключить автозапуск."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        result = am.disable()

        return result

    @app.post("/api/autostart/regenerate")
    def api_autostart_regenerate():
        """Пересоздать скрипт автозапуска."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        result = am.regenerate()

        if not result["ok"]:
            response.status = 400

        return result

    @app.route("/api/autostart/script")
    def api_autostart_script():
        """Получить содержимое установленного скрипта."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        content = am.get_script_content()

        return {
            "ok": True,
            "script": content,
            "exists": bool(content),
        }

    @app.route("/api/autostart/preview")
    def api_autostart_preview():
        """Превью генерируемого скрипта (без установки)."""
        response.content_type = "application/json; charset=utf-8"

        from core.autostart_manager import get_autostart_manager

        am = get_autostart_manager()
        preview = am.get_script_preview()

        return {
            "ok": True,
            "script": preview,
        }



