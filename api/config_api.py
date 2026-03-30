from bottle import request, response
def register(app):
    @app.route("/api/config")
    def api_config_get():
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        data = cfg.get_all()
        if "gui" in data and data["gui"].get("auth_password"):
            data["gui"]["auth_password"] = "***"
        return {"ok": True, "config": data}
    @app.put("/api/config")
    def api_config_update():
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
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        from core.log_buffer import log
        cfg = get_config_manager()
        data = cfg.reset()
        log.warning("Конфигурация сброшена к дефолтам", source="config")
        return {"ok": True, "config": data}
    @app.post("/api/config/export")
    def api_config_export():
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return {"ok": True, "json": cfg.export_json()}
    @app.post("/api/config/import")
    def api_config_import():
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
