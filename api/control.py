from bottle import request, response
def register(app):
    @app.post("/api/start")
    def api_start():
        response.content_type = "application/json; charset=utf-8"
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.config_manager import get_config_manager
        from core.log_buffer import log
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        cfg = get_config_manager()
        strategy_args = []
        try:
            body = request.json
            if body and "strategy_args" in body:
                args = body["strategy_args"]
                if isinstance(args, list):
                    strategy_args = [str(a) for a in args]
                elif isinstance(args, str):
                    strategy_args = args.split()
        except Exception:
            pass
        apply_fw = cfg.get("firewall", "apply_on_start", default=True)
        fw_ok = True
        if apply_fw:
            fw_ok = fw.apply_rules()
            if not fw_ok:
                log.warning(
                    "Правила firewall не применены, "
                    "но пробуем запустить nfqws2",
                    source="control"
                )
        nfqws_ok = mgr.start(strategy_args if strategy_args else None)
        if not nfqws_ok:
            if apply_fw and fw_ok:
                fw.remove_rules()
            response.status = 500
            return {
                "ok": False,
                "error": "Не удалось запустить nfqws2",
                "nfqws": mgr.get_status(),
                "firewall": fw.get_status(),
            }
        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
        }
    @app.post("/api/stop")
    def api_stop():
        response.content_type = "application/json; charset=utf-8"
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        nfqws_ok = mgr.stop()
        fw_ok = fw.remove_rules()
        if not nfqws_ok:
            response.status = 500
            return {
                "ok": False,
                "error": "Не удалось полностью остановить nfqws2",
                "nfqws": mgr.get_status(),
                "firewall": fw.get_status(),
            }
        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
        }
    @app.post("/api/restart")
    def api_restart():
        response.content_type = "application/json; charset=utf-8"
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.config_manager import get_config_manager
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        cfg = get_config_manager()
        strategy_args = None
        try:
            body = request.json
            if body and "strategy_args" in body:
                args = body["strategy_args"]
                if isinstance(args, list):
                    strategy_args = [str(a) for a in args]
        except Exception:
            pass
        nfqws_ok = mgr.restart(strategy_args)
        apply_fw = cfg.get("firewall", "apply_on_start", default=True)
        if apply_fw:
            fw.remove_rules()
            fw.apply_rules()
        if not nfqws_ok:
            response.status = 500
            return {
                "ok": False,
                "error": "Ошибка перезапуска nfqws2",
                "nfqws": mgr.get_status(),
                "firewall": fw.get_status(),
            }
        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
        }
