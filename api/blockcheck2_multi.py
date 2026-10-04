# api/blockcheck2_multi.py
"""
API мульти-доменного blockcheck2 (вкладка «Подбор стратегий →
Несколько доменов»), см. core/blockcheck2_multi.

Эндпоинты:
  POST /api/blockcheck2m/start    — запустить проверку списка доменов
  GET  /api/blockcheck2m/status   — состояние по доменам + находки
  GET  /api/blockcheck2m/output   — вывод копии (?domain=…&offset=N)
  POST /api/blockcheck2m/stop     — остановить все копии
  POST /api/blockcheck2m/combine  — собрать стратегию из находок через --new
"""

from bottle import request, response


def _json_body() -> dict:
    try:
        return request.json or {}
    except Exception:
        return {}


def register(app):

    @app.post("/api/blockcheck2m/start")
    def api_bc2m_start():
        """Body: {domains, params, scanlevel, concurrency, stop_after,
        pause_bypass, group_shared_ips}."""
        response.content_type = "application/json; charset=utf-8"
        body = _json_body()
        params = body.get("params")
        if params is not None and not isinstance(params, dict):
            response.status = 400
            return {"ok": False, "error": "params должен быть объектом"}
        from core.blockcheck2_multi import (DEFAULT_CONCURRENCY,
                                            get_multi_runner)
        r = get_multi_runner().start(
            domains=body.get("domains"),
            params=params,
            scanlevel=body.get("scanlevel"),
            concurrency=body.get("concurrency", DEFAULT_CONCURRENCY),
            stop_after=body.get("stop_after", 3),
            pause_bypass=bool(body.get("pause_bypass", True)),
            group_shared_ips=bool(body.get("group_shared_ips", True)),
        )
        if not r.get("ok"):
            response.status = 409 if "уже" in r.get("error", "") else 400
        return r

    @app.route("/api/blockcheck2m/status")
    def api_bc2m_status():
        response.content_type = "application/json; charset=utf-8"
        from core.blockcheck2_multi import get_multi_runner
        return {"ok": True, **get_multi_runner().get_status()}

    @app.route("/api/blockcheck2m/output")
    def api_bc2m_output():
        response.content_type = "application/json; charset=utf-8"
        try:
            offset = int(request.query.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
        from core.blockcheck2_multi import get_multi_runner
        return {"ok": True, **get_multi_runner().get_output(
            request.query.get("domain", ""), offset)}

    @app.post("/api/blockcheck2m/stop")
    def api_bc2m_stop():
        response.content_type = "application/json; charset=utf-8"
        from core.blockcheck2_multi import get_multi_runner
        if not get_multi_runner().stop():
            return {"ok": True, "message": "проверка не выполняется"}
        return {"ok": True, "status": "stopping"}

    @app.post("/api/blockcheck2m/combine")
    def api_bc2m_combine():
        """Body: {mode, choices, include_partial, limit, families, domains}.

        Находки — из текущего/последнего прогона. ``domains`` — ограничить
        сборку этими доменами (по умолчанию все проверенные).
        """
        response.content_type = "application/json; charset=utf-8"
        body = _json_body()
        choices = body.get("choices")
        if choices is not None and not isinstance(choices, dict):
            response.status = 400
            return {"ok": False, "error": "choices должен быть объектом"}
        from core.blockcheck2_multi import get_multi_runner, split_domains
        from core.strategy_combine import combine
        found = get_multi_runner().found()
        if body.get("domains"):
            want = set(split_domains(body.get("domains")))
            found = [f for f in found if f.get("domain") in want]
        r = combine(found, mode=body.get("mode") or "grouped",
                    choices=choices,
                    include_partial=bool(body.get("include_partial")),
                    limit=body.get("limit") or 20,
                    families=body.get("families") or None)
        if not r.get("ok"):
            response.status = 400
        return r
