# api/blockcheck2.py
"""
API запуска штатного blockcheck zapret2 (blockcheck2.sh) с телеметрией.

Эндпоинты:
  GET  /api/blockcheck2/script   — найден ли скрипт, путь
  POST /api/blockcheck2/start    — запустить (с параметрами и без)
  GET  /api/blockcheck2/status   — статус выполнения + highlights
  GET  /api/blockcheck2/output   — инкрементальный вывод (?offset=N)
  POST /api/blockcheck2/stop     — остановить

Это запуск ОРИГИНАЛЬНОГО скрипта bol-van как подпроцесса (не наша
Python-реализация из /api/blockcheck/*). Вывод стримится в лог-буфер
(source=blockcheck2) и в кольцевой буфер строк для инкрементального polling.
"""

from bottle import request, response


def register(app):

    @app.route("/api/blockcheck2/script")
    def api_blockcheck2_script():
        """Информация о найденном blockcheck-скрипте."""
        response.content_type = "application/json; charset=utf-8"
        from core.blockcheck2 import get_blockcheck2_runner
        script = get_blockcheck2_runner().find_script()
        return {"ok": True, "found": script is not None, "script": script}

    @app.post("/api/blockcheck2/start")
    def api_blockcheck2_start():
        """Запустить blockcheck.

        Body (JSON), все поля опциональны:
            {
              "domains":   ["rutracker.org", ...] | "a.com b.com",
              "scanlevel": "quick" | "standard" | "force",
              "params":    {"IPVS": "4", "ENABLE_HTTP": "0", "REPEATS": "2"},
              "extra_args": ["--foo"]            // позиционные аргументы скрипта
            }
        Без тела — запуск с дефолтами скрипта (но BATCH=1, неинтерактивно).
        """
        response.content_type = "application/json; charset=utf-8"

        try:
            body = request.json or {}
        except Exception:
            body = {}

        domains = body.get("domains")
        if domains is not None and not isinstance(domains, (list, str)):
            response.status = 400
            return {"ok": False, "error": "domains: список строк или строка"}

        params = body.get("params")
        if params is not None and not isinstance(params, dict):
            response.status = 400
            return {"ok": False, "error": "params должен быть объектом"}

        extra_args = body.get("extra_args")
        if extra_args is not None and not isinstance(extra_args, list):
            response.status = 400
            return {"ok": False, "error": "extra_args должен быть списком"}

        scanlevel = body.get("scanlevel")

        from core.blockcheck2 import get_blockcheck2_runner
        result = get_blockcheck2_runner().start(
            domains=domains,
            params=params,
            extra_args=extra_args,
            scanlevel=scanlevel,
        )
        if not result.get("ok"):
            # 409 если уже запущен, иначе 400.
            response.status = 409 if "уже" in result.get("error", "") else 400
        return result

    @app.route("/api/blockcheck2/status")
    def api_blockcheck2_status():
        """Статус выполнения blockcheck."""
        response.content_type = "application/json; charset=utf-8"
        from core.blockcheck2 import get_blockcheck2_runner
        return {"ok": True, **get_blockcheck2_runner().get_status()}

    @app.route("/api/blockcheck2/output")
    def api_blockcheck2_output():
        """Инкрементальный вывод телеметрии. Параметр ?offset=N."""
        response.content_type = "application/json; charset=utf-8"
        try:
            offset = int(request.query.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        from core.blockcheck2 import get_blockcheck2_runner
        return {"ok": True, **get_blockcheck2_runner().get_output(offset)}

    @app.post("/api/blockcheck2/stop")
    def api_blockcheck2_stop():
        """Остановить выполняющийся blockcheck."""
        response.content_type = "application/json; charset=utf-8"
        from core.blockcheck2 import get_blockcheck2_runner
        stopped = get_blockcheck2_runner().stop()
        if not stopped:
            return {"ok": True, "message": "blockcheck не выполняется"}
        return {"ok": True, "status": "stopping"}
