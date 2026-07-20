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

        # Настройки персистентного лога применяем «вживую» — без рестарта GUI.
        if "logging" in updated:
            try:
                from core.log_buffer import reconfigure_persistent_from_config
                reconfigure_persistent_from_config()
            except Exception:
                pass

        # Настройки tunnel_optimizer применяем «вживую»:
        if "tunnel_optimizer" in updated:
            try:
                opt_cfg = body.get("tunnel_optimizer") or {}
                if not opt_cfg.get("enabled"):
                    from core.tunnel_optimizer import restore_system_defaults
                    restore_system_defaults()
            except Exception:
                pass

        # Если поменяли host/port в gui — переписываем systemd unit,
        # чтобы он не подсовывал свои --host/--port из времени установки.
        # Без этого изменение порта в UI не применяется к реальному
        # сервису (старый порт сохранён в ExecStart unit-файла).
        info = {}
        gui_section = body.get("gui") if isinstance(body, dict) else None
        if isinstance(gui_section, dict) and (
            "host" in gui_section or "port" in gui_section
        ):
            try:
                from core.autostart_manager import (
                    regenerate_systemd_unit_if_needed,
                )
                result = regenerate_systemd_unit_if_needed()
                if result.get("changed"):
                    info["systemd_unit_updated"] = True
                    info["restart_required"] = True
                    info["restart_hint"] = (
                        "Для применения нового порта/хоста перезапустите "
                        "сервис: systemctl restart zapret-gui"
                    )
            except Exception as e:
                log.warning(
                    f"Не удалось обновить systemd unit: {e}",
                    source="config",
                )

        return {"ok": True, "updated": updated, **info}

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
        import copy, json as _json

        cfg = get_config_manager()
        include_secrets = request.query.get("include_secrets", "false").lower() == "true"

        if include_secrets:
            return {"ok": True, "json": cfg.export_json()}

        # MR-60: маскируем чувствительные данные в экспорте
        # POST /api/config/export раньше возвращал auth_password + AWG private keys plaintext
        data = cfg.get_all()
        if "gui" in data and data["gui"].get("auth_password"):
            data["gui"]["auth_password"] = "***"
        # Маскируем приватные ключи AWG-конфигов
        for section_key in ("awg", "usque", "tgproxy"):
            sec = data.get(section_key, {})
            for field in ("private_key", "secret", "tunnel_secret"):
                if sec.get(field):
                    sec[field] = "***"
        return {"ok": True, "json": _json.dumps(data, indent=2, ensure_ascii=False)}

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
