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
        """Принудительная проверка прямо сейчас.

        Возвращает результат проверки текущего тика. Работает даже когда
        демон остановлен — это разовая проверка из GUI.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.healthcheck import get_healthcheck
        result = get_healthcheck().run_now()
        return {"ok": True, "result": result}

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
        for k in ("interval_min", "consecutive_failures",
                  "auto_reset", "services", "history_size"):
            if k in body:
                cfg.set("healthcheck", k, body[k])
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
