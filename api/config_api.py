# api/config_api.py
"""
API для конфигурации.

GET    /api/config          — получить текущую конфигурацию
PUT    /api/config          — обновить конфигурацию
POST   /api/config/reset    — сбросить к дефолтам
POST   /api/config/export   — экспортировать как JSON
POST   /api/config/import   — импортировать из JSON
"""

from bottle import request, response


def register(app):

    @app.route("/api/config")
    def api_config_get():
        """Получить текущую конфигурацию."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        data = cfg.get_all()

        # Скрываем пароль в выводе
        if "gui" in data and data["gui"].get("auth_password"):
            data["gui"]["auth_password"] = "***"

        return {"ok": True, "config": data}

    @app.put("/api/config")
    def api_config_update():
        """Обновить секцию конфигурации."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager
        from core.log_buffer import log

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body or not isinstance(body, dict):
            response.status = 400
            return {"ok": False, "error": "Ожидается JSON-объект"}

        cfg = get_config_manager()

        # Обновляем каждую переданную секцию
        updated = []
        for section, data in body.items():
            if isinstance(data, dict):
                if cfg.update_section(section, data):
                    updated.append(section)
                else:
                    log.warning(f"Неизвестная секция: {section}", source="config")

        if updated:
            cfg.save()
            log.info(f"Конфигурация обновлена: {', '.join(updated)}",
                     source="config")

        return {"ok": True, "updated": updated}

    @app.post("/api/config/reset")
    def api_config_reset():
        """Сбросить к настройкам по умолчанию."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager
        from core.log_buffer import log

        cfg = get_config_manager()
        data = cfg.reset()

        log.warning("Конфигурация сброшена к дефолтам", source="config")

        return {"ok": True, "config": data}

    @app.post("/api/config/export")
    def api_config_export():
        """Экспортировать конфигурацию."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        return {"ok": True, "json": cfg.export_json()}

    @app.post("/api/config/import")
    def api_config_import():
        """Импортировать конфигурацию."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body or "json" not in body:
            response.status = 400
            return {"ok": False, "error": "Поле 'json' обязательно"}

        cfg = get_config_manager()
        json_data = body["json"]

        # Если передали строку — парсим, если объект — сериализуем обратно
        import json as json_mod
        if isinstance(json_data, dict):
            json_str = json_mod.dumps(json_data)
        elif isinstance(json_data, str):
            json_str = json_data
        else:
            response.status = 400
            return {"ok": False, "error": "Поле 'json' — строка или объект"}

        if cfg.import_json(json_str):
            return {"ok": True}
        else:
            response.status = 400
            return {"ok": False, "error": "Ошибка импорта конфигурации"}

