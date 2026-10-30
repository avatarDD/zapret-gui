# api/geneva.py
"""
API движка geneva_c и выбора движка обхода.

Эндпоинты geneva:
  GET  /api/geneva/status         — всё для страницы одним ответом:
                                     бинарник, движок, подбор
  POST /api/geneva/install        — поставить geneva из релиза avatarDD/geneva_c
  GET  /api/geneva/config         — настройки движка
  PUT  /api/geneva/config         — обновить настройки
  POST /api/geneva/start | stop | restart
  POST /api/geneva/pause | resume — пауза: пакеты идут без изменений
  POST /api/geneva/strategy       — сделать стратегию рабочей {strategy, source}
  POST /api/geneva/check          — разобрать стратегию {strategy}
  GET  /api/geneva/library        — готовые стратегии Geneva
  GET  /api/geneva/db             — лучшие из базы оценок (?target=&limit=)
  POST /api/geneva/search/start   — подбор {host, probe, ...} или {resume: true}
  POST /api/geneva/search/stop    — остановить (checkpoint сохранится)
  GET  /api/geneva/search/status  — прогресс подбора
  POST /api/geneva/search/forget  — забыть сохранённый поиск
  POST /api/geneva/eval           — проверить список стратегий {strategies, host}
  GET  /api/geneva/log            — хвост лога (?which=run|job&lines=)

Выбор движка:
  GET  /api/bypass/engine         — оба движка и какой активен
  POST /api/bypass/engine         — переключить {engine: nfqws2|geneva, start}
"""

from bottle import request, response


def _body() -> dict:
    """Тело запроса. Кривой JSON не должен превращаться в HTTP 500."""
    try:
        data = request.json
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _reply(res: dict, fail_status: int = 400) -> dict:
    if not res.get("ok"):
        response.status = 409 if res.get("error_code") in (
            "busy", "engine_nfqws2", "engine_geneva") else fail_status
    return res


def _mgr():
    from core.geneva_manager import get_geneva_manager
    return get_geneva_manager()


def register(app):
    """Зарегистрировать маршруты geneva и выбора движка."""

    @app.route("/api/geneva/status", method="GET")
    def geneva_status():
        from core.bypass_engine import get_active
        from core.update_checker import geneva_release_info
        mgr = _mgr()
        det = mgr.detect()
        # Что поставит «Установить/Обновить»: закреплённый релиз.
        det["release"] = geneva_release_info(det.get("version", ""))
        return {"ok": True, "active_engine": get_active(),
                "detect": det, "engine": mgr.status(),
                "search": mgr.search_status()}

    @app.route("/api/geneva/install", method="POST")
    def geneva_install():
        from core.ext_binary_installer import install_binary_by_name
        res = install_binary_by_name("geneva")
        if res.get("ok"):
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            cfg.set("geneva", "installed_tag", res.get("tag", ""))
            cfg.save()
            res["detect"] = _mgr().detect()
        return _reply(res, 502)

    @app.route("/api/geneva/config", method="GET")
    def geneva_config_get():
        from core.config_manager import get_config_manager
        from core.geneva_manager import SEARCH_DEFAULTS, run_settings
        out = run_settings()
        saved = get_config_manager().get("geneva", "search", default={})
        search = dict(SEARCH_DEFAULTS)
        search.update(saved or {})
        out.update({"ok": True, "search": search})
        return out

    @app.route("/api/geneva/config", method="PUT")
    def geneva_config_put():
        from core.config_manager import get_config_manager
        from core.geneva_manager import validate_settings
        try:
            clean = validate_settings(_body())
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        cfg = get_config_manager()
        for key, value in clean.items():
            cfg.set("geneva", key, value)
        cfg.save()
        mgr = _mgr()
        # Порты, протокол и прочее — аргументы процесса: живой движок их
        # подхватит только перезапуском. Говорим об этом, а не молчим.
        restart_needed = mgr.is_running() and any(
            k in clean for k in ("ports", "proto", "iface", "firewall",
                                 "first", "log_level"))
        return {"ok": True, "saved": sorted(clean),
                "restart_needed": restart_needed}

    @app.route("/api/geneva/start", method="POST")
    def geneva_start():
        return _reply(_mgr().start())

    @app.route("/api/geneva/stop", method="POST")
    def geneva_stop():
        return _reply(_mgr().stop())

    @app.route("/api/geneva/restart", method="POST")
    def geneva_restart():
        return _reply(_mgr().restart())

    @app.route("/api/geneva/pause", method="POST")
    def geneva_pause():
        return _reply(_mgr().control("pause"))

    @app.route("/api/geneva/resume", method="POST")
    def geneva_resume():
        return _reply(_mgr().control("resume"))

    @app.route("/api/geneva/strategy", method="POST")
    def geneva_strategy():
        body = _body()
        return _reply(_mgr().set_strategy(
            body.get("strategy") or "", source=body.get("source") or
            "manual", apply=body.get("apply", True) is not False))

    @app.route("/api/geneva/check", method="POST")
    def geneva_check():
        return _reply(_mgr().check_strategy(_body().get("strategy") or ""))

    @app.route("/api/geneva/library", method="GET")
    def geneva_library():
        refresh = str(request.query.get("refresh") or "") in ("1", "true")
        return _reply(_mgr().library(refresh=refresh), 503)

    @app.route("/api/geneva/db", method="GET")
    def geneva_db():
        try:
            limit = int(request.query.get("limit") or 10)
        except (TypeError, ValueError):
            limit = 10
        return _reply(_mgr().db_top(target=request.query.get("target") or "",
                                    limit=limit), 503)

    @app.route("/api/geneva/search/start", method="POST")
    def geneva_search_start():
        body = _body()
        resume = bool(body.pop("resume", False))
        try:
            more = int(body.pop("more_generations", 0) or 0)
        except (TypeError, ValueError):
            more = 0
        return _reply(_mgr().start_search(body, resume=resume,
                                          more_generations=max(0, more)))

    @app.route("/api/geneva/search/stop", method="POST")
    def geneva_search_stop():
        return _reply(_mgr().stop_search())

    @app.route("/api/geneva/search/status", method="GET")
    def geneva_search_status():
        out = _mgr().search_status()
        out["ok"] = True
        return out

    @app.route("/api/geneva/search/forget", method="POST")
    def geneva_search_forget():
        return _reply(_mgr().forget_search())

    @app.route("/api/geneva/eval", method="POST")
    def geneva_eval():
        body = _body()
        strategies = body.pop("strategies", None) or []
        if not isinstance(strategies, list):
            response.status = 400
            return {"ok": False, "error": "strategies — список строк"}
        return _reply(_mgr().start_eval([str(s) for s in strategies], body))

    @app.route("/api/geneva/log", method="GET")
    def geneva_log():
        try:
            lines = int(request.query.get("lines") or 200)
        except (TypeError, ValueError):
            lines = 200
        which = "job" if request.query.get("which") == "job" else "run"
        return _mgr().read_log(lines=lines, which=which)

    @app.route("/api/bypass/engine", method="GET")
    def bypass_engine_get():
        from core.bypass_engine import overview
        return overview()

    @app.route("/api/bypass/engine", method="POST")
    def bypass_engine_set():
        from core.bypass_engine import switch
        body = _body()
        return _reply(switch(body.get("engine") or "",
                             start=body.get("start", True) is not False))
