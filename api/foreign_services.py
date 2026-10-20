# api/foreign_services.py
"""
API сторонних экземпляров туннельных движков (core/foreign_services).

Эндпоинты:
  GET  /api/foreign/status            — скрипты, процессы, конфликты имён
  GET  /api/foreign/summary           — короткая сводка (дашборд)
  POST /api/foreign/script/disable    — {path}: stop + отключить автозапуск
  POST /api/foreign/script/enable     — {path, start?}: вернуть как было
  POST /api/foreign/process/stop      — {pid}: остановить чужой процесс
  POST /api/foreign/adopt             — {engine, pid}: передать под GUI
  POST /api/foreign/exclusive         — {enabled}: режим «только GUI»

Всё, что меняет систему, — только POST по действию пользователя: сам GUI
чужие сервисы не трогает.
"""

from bottle import request


def _body() -> dict:
    try:
        return request.json or {}
    except Exception:
        return {}


def register(app):
    """Зарегистрировать маршруты /api/foreign/*."""

    @app.route("/api/foreign/status", method="GET")
    def foreign_status():
        from core.foreign_services import scan
        return scan()

    @app.route("/api/foreign/summary", method="GET")
    def foreign_summary():
        from core.foreign_services import summary
        return summary()

    @app.route("/api/foreign/script/disable", method="POST")
    def foreign_script_disable():
        from core.foreign_services import disable_script, get_guard
        path = str(_body().get("path") or "")
        res = disable_script(path)
        if res.get("ok"):
            get_guard().reconfigure()
        return res

    @app.route("/api/foreign/script/enable", method="POST")
    def foreign_script_enable():
        from core.foreign_services import enable_script, get_guard
        body = _body()
        res = enable_script(str(body.get("path") or ""),
                            start=bool(body.get("start", False)))
        get_guard().reconfigure()
        return res

    @app.route("/api/foreign/process/stop", method="POST")
    def foreign_process_stop():
        from core.foreign_services import stop_process
        return stop_process(_body().get("pid"))

    @app.route("/api/foreign/adopt", method="POST")
    def foreign_adopt():
        from core.foreign_services import adopt, get_guard
        body = _body()
        res = adopt(str(body.get("engine") or ""), body.get("pid"))
        get_guard().reconfigure()
        return res

    @app.route("/api/foreign/exclusive", method="POST")
    def foreign_exclusive():
        from core.foreign_services import set_exclusive
        return set_exclusive(bool(_body().get("enabled", False)))
