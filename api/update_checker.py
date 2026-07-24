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
        # MR-58: in-flight guard внутри check_now() — параллельные check_all()
        # спавнят 18+ curl и исчерпывают GitHub rate-limit 60 req/h.
        # Запускаем немедленную разовую проверку в фоне (не блокируем worker,
        # не ждём 60s-инициализации демона). Фронт поллит /api/updates/status
        # (поле checking) и по завершении читает /api/updates.
        from core.update_checker import get_update_checker
        checker = get_update_checker()
        started = checker.check_now()
        return {
            "ok": True,
            "status": "started" if started else "in_progress",
            "message": ("Проверка запущена" if started
                        else "Проверка уже выполняется"),
            "poll_url": "/api/updates",
            "status_url": "/api/updates/status",
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
