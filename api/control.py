# api/control.py
"""
API управления nfqws2.

POST /api/start     — запустить nfqws2 + применить FW правила
POST /api/stop      — остановить nfqws2 + снять FW правила
POST /api/restart   — перезапустить nfqws2
"""

from bottle import request, response


def register(app):

    @app.post("/api/start")
    def api_start():
        """
        Запустить nfqws2 с опциональными аргументами стратегии.

        Body (JSON, опционально):
            { "strategy_args": ["--filter-tcp=443", ...] }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.config_manager import get_config_manager
        from core.log_buffer import log

        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        cfg = get_config_manager()

        # Парсим аргументы из body (если есть)
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

        # 1. Применяем правила firewall
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

        # 2. Запускаем nfqws2
        nfqws_ok = mgr.start(strategy_args if strategy_args else None)

        if not nfqws_ok:
            # Если не удалось запустить — снимаем FW правила
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
        """Остановить nfqws2 и снять правила firewall."""
        response.content_type = "application/json; charset=utf-8"

        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        mgr = get_nfqws_manager()
        fw = get_firewall_manager()

        # 1. Останавливаем nfqws2
        nfqws_ok = mgr.stop()

        # 2. Снимаем правила firewall (даже если stop не удался)
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
        """
        Перезапустить nfqws2.

        Body (JSON, опционально):
            { "strategy_args": ["--filter-tcp=443", ...] }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.config_manager import get_config_manager

        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        cfg = get_config_manager()

        # Парсим аргументы
        strategy_args = None
        try:
            body = request.json
            if body and "strategy_args" in body:
                args = body["strategy_args"]
                if isinstance(args, list):
                    strategy_args = [str(a) for a in args]
        except Exception:
            pass

        # 1. Перезапускаем nfqws2
        nfqws_ok = mgr.restart(strategy_args)

        # 2. Переприменяем FW правила
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



