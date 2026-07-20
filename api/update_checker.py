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
        # MR-58: in-flight guard — предотвращаем параллельные вызовы check_all()
        # которые спавнят 18+ curl-процессов и исчерпывают GitHub 60-req/h rate-limit
        from core.update_checker import get_update_checker, get_cached_results
        checker = get_update_checker()
        status = checker.get_status()
        if status.get("running"):
            # Уже идёт проверка — возвращаем 202 + URL для polling
            from bottle import response as _resp
            _resp.status = 202
            return {
                "ok": True,
                "status": "in_progress",
                "message": "Проверка уже выполняется",
                "poll_url": "/api/updates",
            }
        # Делегируем фоновому демону (не блокируем worker)
        checker._start()
        return {
            "ok": True,
            "status": "started",
            "message": "Проверка запущена в фоне",
            "poll_url": "/api/updates",
        }

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
