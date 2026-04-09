# api/blockcheck.py
"""
API тестирования доступности (BlockCheck).

Эндпоинты:
  POST /api/blockcheck/start    — запустить тестирование
  GET  /api/blockcheck/status   — текущий статус и прогресс
  GET  /api/blockcheck/results  — результаты последнего теста
  POST /api/blockcheck/stop     — остановить тестирование
  GET  /api/blockcheck/domains  — получить список доменов по умолчанию
  POST /api/blockcheck/domains  — сохранить список доменов
"""

from bottle import request, response


def register(app):

    @app.post("/api/blockcheck/start")
    def api_blockcheck_start():
        """
        Запустить тестирование доступности.

        Body (JSON):
            {
                "mode": "quick" | "full" | "dpi_only",   (опционально, default: quick)
                "extra_domains": ["example.com", ...]     (опционально)
                "domains": ["youtube.com", ...]           (опционально — заменяет базовый список)
            }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()

        # Парсим тело запроса
        try:
            body = request.json or {}
        except Exception:
            body = {}

        mode = body.get("mode", "quick")
        if mode not in ("quick", "full", "dpi_only"):
            response.status = 400
            return {
                "ok": False,
                "error": "Неверный режим: %s. "
                         "Допустимые: quick, full, dpi_only" % mode,
            }

        extra_domains = body.get("extra_domains")
        if extra_domains is not None:
            if not isinstance(extra_domains, list):
                response.status = 400
                return {
                    "ok": False,
                    "error": "extra_domains должен быть списком строк",
                }
            extra_domains = [str(d).strip() for d in extra_domains if d]

        # Поддержка полной замены списка доменов
        domains_override = body.get("domains")
        if domains_override is not None:
            if not isinstance(domains_override, list):
                response.status = 400
                return {
                    "ok": False,
                    "error": "domains должен быть списком строк",
                }
            domains_override = [str(d).strip() for d in domains_override if str(d).strip()]

        # Запускаем
        started = runner.start(
            mode=mode,
            extra_domains=extra_domains or None,
            domains_override=domains_override or None,
        )

        if not started:
            response.status = 409
            return {
                "ok": False,
                "error": "Тестирование уже выполняется",
            }

        return {
            "ok": True,
            "status": "started",
            "mode": mode,
        }

    @app.route("/api/blockcheck/status")
    def api_blockcheck_status():
        """Текущий статус и прогресс тестирования."""
        response.content_type = "application/json; charset=utf-8"

        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()
        status = runner.get_status()

        return {"ok": True, **status}

    @app.route("/api/blockcheck/results")
    def api_blockcheck_results():
        """Результаты последнего тестирования."""
        response.content_type = "application/json; charset=utf-8"

        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()
        results = runner.get_results_dict()

        if results is None:
            return {
                "ok": True,
                "results": None,
                "message": "Нет результатов. Запустите тестирование.",
            }

        return {
            "ok": True,
            "results": results,
        }

    @app.post("/api/blockcheck/stop")
    def api_blockcheck_stop():
        """Остановить текущее тестирование."""
        response.content_type = "application/json; charset=utf-8"

        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()
        cancelled = runner.cancel()

        if not cancelled:
            return {
                "ok": True,
                "message": "Тестирование не выполняется",
            }

        return {
            "ok": True,
            "status": "cancelling",
        }

    @app.route("/api/blockcheck/domains")
    def api_blockcheck_domains_get():
        """Получить список доменов для тестирования."""
        response.content_type = "application/json; charset=utf-8"

        from core.blockcheck import load_domains

        domains, source = load_domains()

        return {
            "ok": True,
            "domains": domains,
            "source": source,
        }

    @app.post("/api/blockcheck/domains")
    def api_blockcheck_domains_save():
        """Сохранить список доменов в data/domains.txt.

        Body (JSON):
            {
                "domains": ["youtube.com", "discord.com", ...]
            }
        """
        response.content_type = "application/json; charset=utf-8"

        import os

        try:
            body = request.json or {}
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        domains = body.get("domains")
        if not isinstance(domains, list):
            response.status = 400
            return {"ok": False, "error": "domains должен быть списком строк"}

        # Нормализация и фильтрация
        clean = []
        for d in domains:
            d = str(d).strip()
            if d and not d.startswith("#"):
                clean.append(d)

        if not clean:
            response.status = 400
            return {"ok": False, "error": "Список доменов пуст"}

        # Сохраняем в data/domains.txt
        from core.blockcheck import _get_app_dir
        data_dir = os.path.join(_get_app_dir(), "data")
        os.makedirs(data_dir, exist_ok=True)
        domains_file = os.path.join(data_dir, "domains.txt")

        try:
            content = "# BlockCheck domain list\n# One domain per line\n\n"
            content += "\n".join(clean) + "\n"
            with open(domains_file, "w", encoding="utf-8") as f:
                f.write(content)
        except (OSError, IOError) as e:
            response.status = 500
            return {"ok": False, "error": "Ошибка записи: %s" % str(e)}

        from core.log_buffer import log
        log.info(
            f"Сохранено {len(clean)} доменов в domains.txt",
            source="blockcheck",
        )

        return {
            "ok": True,
            "count": len(clean),
        }
