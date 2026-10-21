# api/engine_wrapper.py
"""
Общая обвязка AmneziaWG, sing-box и mihomo — одинаковые роуты для трёх
движков (core/engine_common.py):

  GET    /api/<engine>/go-memory                 — лимит памяти Go
  POST   /api/<engine>/go-memory                 — body: {enabled?, gogc?, memlimit_mb?}
  GET    /api/<engine>/configs/<name>/diagnostics — снимок для баг-репорта
        (у AWG — свой, давний роут в api/awg.py; здесь sing-box и mihomo)

И то, чего у AWG не было, а у sing-box/mihomo было:

  GET    /api/awg/debug                          — режим отладки (LOG_LEVEL=verbose)
  POST   /api/awg/debug                          — body: {enabled}
  GET    /api/awg/configs/<name>/log?lines=N     — хвост лога демона
  POST   /api/awg/configs/<name>/test            — проверка связи через туннель

<engine> — awg | singbox | mihomo.
"""

from bottle import request, response


ENGINES = ("awg", "singbox", "mihomo")


def _json_body() -> dict:
    try:
        body = request.json or {}
    except Exception:
        body = {}
    return body if isinstance(body, dict) else {}


def _manager(engine: str):
    if engine == "awg":
        from core.awg_manager import get_awg_manager
        return get_awg_manager()
    if engine == "singbox":
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager()
    from core.mihomo_manager import get_mihomo_manager
    return get_mihomo_manager()


def register(app):

    def _go_memory_get(engine):
        def handler():
            response.content_type = "application/json; charset=utf-8"
            from core import engine_common
            return dict(ok=True, **engine_common.go_memory_get(engine))
        return handler

    def _go_memory_set(engine):
        def handler():
            """Поля: enabled, gogc, memlimit_mb (0 = не задавать).
            Применяется при следующем запуске инстанса."""
            response.content_type = "application/json; charset=utf-8"
            from core import engine_common
            body = _json_body()
            try:
                new = engine_common.go_memory_set(
                    engine, enabled=body.get("enabled"),
                    gogc=body.get("gogc"),
                    memlimit_mb=body.get("memlimit_mb"))
            except engine_common.SettingsError as e:
                response.status = 400
                return {"ok": False, "error": str(e)}
            what = "туннеля" if engine == "awg" else "инстанса"
            return dict(ok=True, note="Применится при следующем запуске %s"
                        % what, **new)
        return handler

    for engine in ENGINES:
        app.route("/api/%s/go-memory" % engine, method="GET",
                  callback=_go_memory_get(engine))
        app.route("/api/%s/go-memory" % engine, method="POST",
                  callback=_go_memory_set(engine))

    def _diagnostics(engine):
        def handler(name):
            response.content_type = "application/json; charset=utf-8"
            try:
                result = _manager(engine).diagnostics(name)
            except Exception as e:
                response.status = 500
                return {"ok": False, "error": str(e)}
            if not result.get("ok"):
                response.status = 404
            return result
        return handler

    for engine in ("singbox", "mihomo"):
        app.route("/api/%s/configs/<name>/diagnostics" % engine,
                  method="GET", callback=_diagnostics(engine))

    # ─────── AWG: отладка, лог демона, проверка связи ───────

    @app.route("/api/awg/debug")
    def awg_debug_get():
        response.content_type = "application/json; charset=utf-8"
        return _manager("awg").get_debug()

    @app.route("/api/awg/debug", method="POST")
    def awg_debug_set():
        response.content_type = "application/json; charset=utf-8"
        result = _manager("awg").set_debug(bool(_json_body().get("enabled")))
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/log")
    def awg_config_log(name):
        response.content_type = "application/json; charset=utf-8"
        result = _manager("awg").read_log(
            name, request.query.get("lines") or 200)
        if not result.get("ok"):
            response.status = 400
        return result

    @app.route("/api/awg/configs/<name>/test", method="POST")
    def awg_config_test(name):
        """body: {host?, port?, timeout?} — по умолчанию цель пробы сторожа."""
        response.content_type = "application/json; charset=utf-8"
        body = _json_body()
        try:
            timeout = float(body.get("timeout") or 4.0)
        except (TypeError, ValueError):
            timeout = 4.0
        timeout = max(1.0, min(15.0, timeout))
        return _manager("awg").probe(name, host=str(body.get("host") or ""),
                                     port=body.get("port") or 0,
                                     timeout=timeout)
