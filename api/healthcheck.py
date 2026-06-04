# api/healthcheck.py
"""
API healthcheck-демона (фоновый watchdog для autocircular).

  GET    /api/healthcheck/status   — состояние демона + история проверок
  POST   /api/healthcheck/run      — прогон сразу (для кнопки в GUI)
  POST   /api/healthcheck/enable   — включить и запустить
  POST   /api/healthcheck/disable  — выключить и остановить
"""

from bottle import request, response


def register(app):

    @app.route("/api/healthcheck/status")
    def api_healthcheck_status():
        """Текущее состояние демона + история последних прогонов."""
        response.content_type = "application/json; charset=utf-8"
        from core.healthcheck import get_healthcheck
        return {"ok": True, "status": get_healthcheck().get_status()}

    @app.post("/api/healthcheck/run")
    def api_healthcheck_run():
        """Принудительная проверка прямо сейчас (НЕблокирующая).

        Запускает проверку в фоне и сразу возвращает {started, busy}.
        Каждый сервис проверяется до 8с — синхронно ждать ~30с в HTTP
        нельзя. GUI после этого опрашивает /status и показывает спиннер,
        пока last_check_at не обновится. Работает даже когда демон
        остановлен — это разовая проверка из GUI.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.healthcheck import get_healthcheck
        result = get_healthcheck().run_now(blocking=False)
        return {"ok": True, "result": result}

    # Поля конфигурации healthcheck, принимаемые из body (валидируются мягко).
    _CFG_KEYS = (
        "interval_min", "consecutive_failures", "auto_reset", "services",
        "custom_domains", "control_domain", "outage_guard", "history_size",
    )

    def _apply_cfg_body(cfg, body):
        for k in _CFG_KEYS:
            if k in body:
                cfg.set("healthcheck", k, body[k])

    @app.post("/api/healthcheck/config")
    def api_healthcheck_config():
        """Сохранить настройки healthcheck БЕЗ изменения enabled.

        Позволяет редактировать список сайтов/контрольный домен/пороги, даже
        когда демон выключен. Если демон запущен — перечитывает конфиг.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        from core.healthcheck import get_healthcheck
        from core.log_buffer import log

        try:
            body = request.json or {}
        except Exception:
            body = {}
        cfg = get_config_manager()
        _apply_cfg_body(cfg, body)
        cfg.save()
        log.info("Healthcheck: настройки обновлены", source="healthcheck")
        hc = get_healthcheck()
        # Перечитать только если включён/работает (reload — no-op если выключен).
        if hc.is_running():
            hc.reload()
        return {"ok": True, "status": hc.get_status()}

    @app.post("/api/healthcheck/enable")
    def api_healthcheck_enable():
        """Включить healthcheck (cfg.healthcheck.enabled = true) и запустить."""
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        from core.healthcheck import get_healthcheck
        from core.log_buffer import log

        cfg = get_config_manager()
        cfg.set("healthcheck", "enabled", True)
        # Применяем настройки из body, если переданы (interval/services/...)
        try:
            body = request.json or {}
        except Exception:
            body = {}
        _apply_cfg_body(cfg, body)
        cfg.save()
        log.info("Healthcheck: включён через API", source="healthcheck")
        result = get_healthcheck().reload()
        return {"ok": True, "result": result}

    @app.post("/api/healthcheck/disable")
    def api_healthcheck_disable():
        """Выключить и остановить демон."""
        response.content_type = "application/json; charset=utf-8"
        from core.config_manager import get_config_manager
        from core.healthcheck import get_healthcheck
        from core.log_buffer import log

        cfg = get_config_manager()
        cfg.set("healthcheck", "enabled", False)
        cfg.save()
        get_healthcheck().stop()
        log.info("Healthcheck: выключен через API", source="healthcheck")
        return {"ok": True}
