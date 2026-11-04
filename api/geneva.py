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
  GET  /api/geneva/found          — рабочие стратегии этой сети: сервисы
                                     «Авто» с обходом + удачный подбор
                                     + импортированные
  GET  /api/geneva/found/export   — они же файлом для обмена (JSON)
  POST /api/geneva/found/import   — принять файл {data} (JSON экспорта
                                     или текст «стратегия на строку»)
  POST /api/geneva/found/forget   — убрать импортированную {strategy}
  POST /api/geneva/search/start   — подбор {host, probe, ...} или {resume: true}
  POST /api/geneva/search/stop    — остановить (checkpoint сохранится)
  GET  /api/geneva/search/status  — прогресс подбора
  POST /api/geneva/search/forget  — забыть сохранённый поиск
  POST /api/geneva/eval           — проверить список стратегий {strategies, host}
  GET  /api/geneva/log            — хвост лога (?which=run|job&lines=)

Режим «Авто» (core/geneva_auto_manager):
  GET  /api/geneva/auto           — состояние (?all=1 — все сервисы)
  POST /api/geneva/auto/enable    — включить {confirm}; без confirm при
                                     нужном переключении движка — 409
                                     error_code need_confirm
  POST /api/geneva/auto/disable   — выключить
  POST /api/geneva/auto/reset     — забыть сервис {key}
  GET  /api/geneva/nat-offload    — ускорение NAT роутера (OpenWrt, Keenetic)
  POST /api/geneva/nat-offload    — включить/выключить {enabled, confirm}

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
            "busy", "engine_nfqws2", "engine_geneva", "geneva_auto",
            "need_confirm") else fail_status
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
            mgr = _mgr()
            res["detect"] = mgr.detect()
            # Работающий процесс — ещё старый бинарник (файл заменён
            # через rename): новая версия заработает после перезапуска.
            res["restart_needed"] = mgr.is_running()
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

    @app.route("/api/geneva/found", method="GET")
    def geneva_found():
        from core.geneva_auto_manager import get_geneva_auto_manager
        return get_geneva_auto_manager().found()

    @app.route("/api/geneva/found/export", method="GET")
    def geneva_found_export():
        import json as _json
        from core.geneva_auto_manager import get_geneva_auto_manager
        doc = get_geneva_auto_manager().export_found()
        response.content_type = "application/json; charset=utf-8"
        response.set_header("Content-Disposition",
                            'attachment; filename="geneva-strategies.json"')
        return _json.dumps(doc, ensure_ascii=False, indent=1)

    @app.route("/api/geneva/found/import", method="POST")
    def geneva_found_import():
        from core.geneva_auto_manager import get_geneva_auto_manager
        body = _body()
        data = body.get("data") if body else None
        if data is None:
            try:
                data = request.body.read(512 * 1024 + 1).decode(
                    "utf-8", "replace")
            except Exception:                       # noqa: BLE001
                data = ""
        return _reply(get_geneva_auto_manager().import_strategies(data))

    @app.route("/api/geneva/found/forget", method="POST")
    def geneva_found_forget():
        from core.geneva_auto_manager import get_geneva_auto_manager
        return _reply(get_geneva_auto_manager().remove_imported(
            _body().get("strategy") or ""), 404)

    @app.route("/api/geneva/auto", method="GET")
    def geneva_auto_status():
        from core.geneva_auto_manager import get_geneva_auto_manager
        show_all = str(request.query.get("all") or "") in ("1", "true")
        out = get_geneva_auto_manager().status(all_services=show_all)
        out["ok"] = True
        return out

    @app.route("/api/geneva/auto/enable", method="POST")
    def geneva_auto_enable():
        from core.geneva_auto_manager import get_geneva_auto_manager
        confirm = _body().get("confirm") is True
        return _reply(get_geneva_auto_manager().enable(confirm=confirm))

    @app.route("/api/geneva/auto/disable", method="POST")
    def geneva_auto_disable():
        from core.geneva_auto_manager import get_geneva_auto_manager
        return _reply(get_geneva_auto_manager().disable("с веб-страницы"))

    @app.route("/api/geneva/auto/reset", method="POST")
    def geneva_auto_reset():
        from core.geneva_auto_manager import get_geneva_auto_manager
        key = str(_body().get("key") or "").strip()
        if not key:
            response.status = 400
            return {"ok": False, "error": "не указан сервис (key)"}
        return _reply(get_geneva_auto_manager().reset(key), 404)

    @app.route("/api/geneva/nat-offload", method="GET")
    def geneva_nat_offload_get():
        from core.nat_offload import get_nat_offload
        return dict(get_nat_offload().status(), ok=True)

    @app.route("/api/geneva/nat-offload", method="POST")
    def geneva_nat_offload_set():
        from core.nat_offload import get_nat_offload
        body = _body()
        if body.get("confirm") is not True:
            # меняется конфигурация роутера: только с подтверждением
            response.status = 409
            return {"ok": False, "error_code": "need_confirm",
                    "error": "нужно подтверждение (confirm: true)"}
        if not isinstance(body.get("enabled"), bool):
            response.status = 400
            return {"ok": False, "error": "enabled: true или false"}
        res = get_nat_offload().set(body["enabled"])
        if not res.get("ok"):
            response.status = 400 if res.get("error_code") == \
                "unsupported" else 500
        else:
            try:
                from core.geneva_auto_manager import get_geneva_auto_manager
                get_geneva_auto_manager().recheck_offload()
            except Exception:                       # noqa: BLE001
                pass
        return res

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
