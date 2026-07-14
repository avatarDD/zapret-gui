# api/update_checker.py
"""
API-модуль Unified Update Checker.

Эндпоинты:
  GET  /api/updates         — кешированные результаты
  POST /api/updates/check   — проверить все бинарники
  GET  /api/updates/status  — статус фонового процесса
  POST /api/updates/start   — запустить фоновую проверку
  POST /api/updates/stop    — остановить
"""

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты update_checker."""

    @app.route("/api/updates", method="GET")
    def updates_cached():
        from core.update_checker import get_cached_results
        return get_cached_results()

    @app.route("/api/updates/check", method="POST")
    def updates_check():
        from core.update_checker import check_all
        return check_all()

    @app.route("/api/updates/status", method="GET")
    def updates_status():
        from core.update_checker import get_update_checker
        return get_update_checker().get_status()

    @app.route("/api/updates/start", method="POST")
    def updates_start():
        from core.update_checker import get_update_checker
        get_update_checker()._start()
        return {"ok": True}

    @app.route("/api/updates/stop", method="POST")
    def updates_stop():
        from core.update_checker import get_update_checker
        get_update_checker()._stop()
        return {"ok": True}
