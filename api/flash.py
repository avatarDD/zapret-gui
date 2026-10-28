# api/flash.py
"""
API раздела «Память (flash)»: износ носителя, объём записи и рычаги
снижения записи (core/flash_wear.py, core/flash_saver.py).

Эндпоинты:
  GET  /api/flash/status?fresh=1  — носители, износ, запись за сутки/месяц,
                                    «кто пишет», настройки, профили,
                                    действующее состояние, подсказки
  PUT  /api/flash/settings        — сохранить настройки и применить
                                    (body: {engine_logs_ram, noatime, …})
  POST /api/flash/action          — действие из подсказки (body: {name})
  POST /api/flash/stats/reset     — обнулить накопленную статистику записи
"""

from bottle import request, response


def register(app):

    @app.route("/api/flash/status")
    def api_flash_status():
        response.content_type = "application/json; charset=utf-8"
        from core import flash_saver
        from core.flash_wear import get_flash_stats
        out = get_flash_stats().report(fresh=request.query.get("fresh") == "1")
        out["settings"] = flash_saver.get_settings()
        out["presets"] = flash_saver.PRESETS
        out["state"] = flash_saver.state()
        out["hints"] = flash_saver.hints()
        return out

    @app.route("/api/flash/settings", method="PUT")
    def api_flash_settings():
        response.content_type = "application/json; charset=utf-8"
        from core import flash_saver
        res = flash_saver.save_settings(request.json or {})
        if not res.get("ok") and "settings" not in res:
            response.status = 400
        return res

    @app.route("/api/flash/action", method="POST")
    def api_flash_action():
        response.content_type = "application/json; charset=utf-8"
        from core import flash_saver
        name = str((request.json or {}).get("name") or "")
        res = flash_saver.action(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/flash/stats/reset", method="POST")
    def api_flash_stats_reset():
        response.content_type = "application/json; charset=utf-8"
        from core.flash_wear import get_flash_stats
        get_flash_stats().reset()
        return {"ok": True}
