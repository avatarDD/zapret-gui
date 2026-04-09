# api/scan.py
"""
API подбора стратегий (Strategy Scanner).

Эндпоинты:
  POST /api/scan/start          — начать подбор стратегий
  GET  /api/scan/status         — прогресс подбора
  POST /api/scan/stop           — остановить подбор
  GET  /api/scan/results        — результаты подбора
  POST /api/scan/apply/<idx>    — применить найденную стратегию по индексу
"""

from bottle import request, response


def register(app):

    @app.post("/api/scan/start")
    def api_scan_start():
        """
        Начать подбор стратегий.

        Body (JSON):
            {
                "target": "youtube.com",                    (обязательно)
                "protocol": "tcp" | "udp",                  (опционально, default: tcp)
                "mode": "quick" | "standard" | "full",      (опционально, default: quick)
                "resume": true | false                       (опционально, default: false)
            }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # Парсим тело запроса
        try:
            body = request.json or {}
        except Exception:
            body = {}

        target = (body.get("target") or "").strip()
        if not target:
            response.status = 400
            return {
                "ok": False,
                "error": "Поле 'target' обязательно (домен для проверки)",
            }

        # Базовая валидация домена
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]+$', target):
            response.status = 400
            return {
                "ok": False,
                "error": "Невалидный домен: %s" % target,
            }

        protocol = body.get("protocol", "tcp")
        if protocol not in ("tcp", "udp"):
            response.status = 400
            return {
                "ok": False,
                "error": "Неверный протокол: %s. "
                         "Допустимые: tcp, udp" % protocol,
            }

        mode = body.get("mode", "quick")
        if mode not in ("quick", "standard", "full"):
            response.status = 400
            return {
                "ok": False,
                "error": "Неверный режим: %s. "
                         "Допустимые: quick, standard, full" % mode,
            }

        # Resume: загрузить индекс из сохранённого состояния
        resume = bool(body.get("resume", False))
        start_index = 0
        if resume:
            start_index = scanner.get_resume_index()

        # Запускаем
        started = scanner.start(
            target=target,
            protocol=protocol,
            mode=mode,
            start_index=start_index,
        )

        if not started:
            response.status = 409
            return {
                "ok": False,
                "error": "Подбор стратегий уже выполняется",
            }

        result = {
            "ok": True,
            "status": "started",
            "target": target,
            "protocol": protocol,
            "mode": mode,
        }
        if resume and start_index > 0:
            result["resumed_from"] = start_index

        return result

    @app.route("/api/scan/status")
    def api_scan_status():
        """Текущий статус и прогресс подбора."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()
        status = scanner.get_status()

        return {"ok": True, **status}

    @app.route("/api/scan/results")
    def api_scan_results():
        """Результаты подбора стратегий."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # Работающие стратегии
        working = scanner.get_working_strategies()

        # Полный отчёт если есть
        report = scanner.get_results()
        report_dict = report.to_dict() if report else None

        return {
            "ok": True,
            "working": working,
            "working_count": len(working),
            "report": report_dict,
        }

    @app.post("/api/scan/stop")
    def api_scan_stop():
        """Остановить текущий подбор."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner

        scanner = get_strategy_scanner()

        # FIX: было scanner.cancel() — такого метода нет,
        # правильный метод: stop()
        stopped = scanner.stop()

        if not stopped:
            return {
                "ok": True,
                "message": "Подбор не выполняется",
            }

        return {
            "ok": True,
            "message": "Остановка запрошена",
        }

    @app.post("/api/scan/apply/<idx:int>")
    def api_scan_apply(idx):
        """
        Применить найденную стратегию по индексу.

        Создаёт user-стратегию в JSON и перезапускает nfqws2.
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_scanner import get_strategy_scanner
        from core.log_buffer import log

        scanner = get_strategy_scanner()

        applied = scanner.apply_strategy(idx)

        if not applied:
            response.status = 400
            return {
                "ok": False,
                "error": "Не удалось применить стратегию с индексом %d. "
                         "Проверьте, что индекс корректен." % idx,
            }

        log.success(
            "Стратегия из подбора #%d применена" % idx,
            source="scan-api",
        )

        return {
            "ok": True,
            "message": "Стратегия применена",
        }
