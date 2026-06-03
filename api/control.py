# api/control.py
"""
API управления nfqws2.

POST /api/start     — запустить nfqws2 + применить FW правила
POST /api/stop      — остановить nfqws2 + снять FW правила
POST /api/restart   — перезапустить nfqws2
"""

from bottle import request, response


def _active_strategy_args():
    """Пересобрать аргументы nfqws2 из активной стратегии (strategy.current_id).

    Возвращает свежий список аргументов или None, если активной стратегии нет
    либо собрать не удалось. Нужно, чтобы кнопки «Старт»/«Перезапуск» в GUI
    применяли ТЕКУЩУЮ (в т.ч. только что отредактированную) стратегию, а не
    закэшированные в nfqws_manager аргументы прошлого запуска. Без этого после
    правки активной стратегии перезапуск применял старую версию, и приходилось
    вручную переключаться на другую стратегию и обратно.
    """
    from core.config_manager import get_config_manager
    from core.log_buffer import log

    cfg = get_config_manager()
    current_id = cfg.get("strategy", "current_id", default=None)
    if not current_id:
        return None
    try:
        from core.strategy_builder import get_strategy_manager
        sm = get_strategy_manager()
        strategy = sm.get_strategy(current_id)
        if not strategy:
            return None
        args = sm.build_nfqws_args(strategy)
        if args:
            log.info(
                "Пересобраны аргументы активной стратегии «%s»"
                % strategy.get("name", current_id),
                source="control",
            )
            return args
    except Exception as e:
        log.warning(
            "Не удалось пересобрать аргументы активной стратегии: %s" % e,
            source="control",
        )
    return None


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

        # Явных аргументов нет — стартуем АКТИВНУЮ стратегию (пересобрав её
        # из конфига), а не «голый» nfqws2 без десинка. Так кнопка «Старт»
        # поднимает ту же стратегию, что была выбрана, со свежими правками.
        if not strategy_args:
            rebuilt = _active_strategy_args()
            if rebuilt:
                strategy_args = rebuilt

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

        # Если явных аргументов нет — ПЕРЕСОБИРАЕМ их из активной стратегии,
        # а не переиспользуем mgr._last_args. Иначе после правки активной
        # стратегии (редактирование+сохранение) перезапуск кнопкой «nfqws2»
        # применял СТАРЫЕ закэшированные аргументы, и приходилось вручную
        # переключаться на другую стратегию и обратно. Пересборка из
        # strategy.current_id подхватывает свежесохранённую стратегию.
        if strategy_args is None:
            strategy_args = _active_strategy_args()

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
