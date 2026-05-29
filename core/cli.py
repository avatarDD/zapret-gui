# core/cli.py
"""
CLI-обёртка над менеджерами zapret-gui.

Заимствовано из XKeen, где основной интерфейс — команда `xkeen` в
SSH-терминале. У нас GUI-first, но иногда нужно быстро дёрнуть из
консоли (по SSH, из скрипта, из cron) без браузера:

    zapret-gui status
    zapret-gui nfqws {start|stop|restart|status}
    zapret-gui strategy list
    zapret-gui strategy apply <id>
    zapret-gui singbox list
    zapret-gui singbox {up|down|restart} <name>

Тонкий слой: только парсинг + вызов синглтон-менеджеров + печать.
Никакого Bottle — инициализируем только ядро (init_config) и работаем
напрямую с core/*. Возвращаемый код = exit-code процесса.

Вызывается из app.py main(), когда первый аргумент — известная
подкоманда (а не --host/--port и т.п. для web-сервера).
"""

import argparse
import sys


# Подкоманды верхнего уровня, по которым app.py решает «это CLI, не web».
COMMANDS = ("status", "nfqws", "strategy", "singbox")


def _p(msg=""):
    print(msg)


def _ok(label, result):
    """Печать результата dict {ok, error?} в человекочитаемом виде."""
    if isinstance(result, dict):
        if result.get("ok", True):
            _p("✓ %s" % label)
            return 0
        _p("✗ %s: %s" % (label, result.get("error") or "ошибка"))
        return 1
    # bool
    if result:
        _p("✓ %s" % label)
        return 0
    _p("✗ %s" % label)
    return 1


# ─────────────────────── status ──────────────────────────────────────

def _cmd_status(_args) -> int:
    _p("=== zapret-gui ===")
    # nfqws
    try:
        from core.nfqws_manager import get_nfqws_manager
        st = get_nfqws_manager().get_status()
        running = st.get("running")
        _p("nfqws2:   %s%s" % (
            "запущен" if running else "остановлен",
            " (pid %s)" % st.get("pid") if running and st.get("pid") else ""))
    except Exception as e:
        _p("nfqws2:   ? (%s)" % e)
    # current strategy
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        sid = cfg.get("strategy", "current_id", default=None)
        sname = cfg.get("strategy", "current_name", default=None)
        if sid or sname:
            _p("стратегия: %s%s" % (sname or "?",
                                    " [%s]" % sid if sid else ""))
        else:
            _p("стратегия: не выбрана")
    except Exception:
        pass
    # sing-box
    try:
        from core.singbox_manager import get_singbox_manager
        cfgs = get_singbox_manager().list_configs()
        if cfgs:
            up = [c["name"] for c in cfgs if c.get("running")]
            _p("sing-box: %d конфигов, запущено: %s"
               % (len(cfgs), ", ".join(up) if up else "—"))
    except Exception:
        pass
    return 0


# ─────────────────────── nfqws ───────────────────────────────────────

def _cmd_nfqws(args) -> int:
    from core.nfqws_manager import get_nfqws_manager
    mgr = get_nfqws_manager()
    action = args.action
    if action == "status":
        st = mgr.get_status()
        _p("nfqws2: %s" % ("запущен" if st.get("running")
                           else "остановлен"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        return _ok("nfqws start", mgr.start())
    if action == "stop":
        return _ok("nfqws stop", mgr.stop())
    if action == "restart":
        return _ok("nfqws restart", mgr.restart())
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── strategy ────────────────────────────────────

def _cmd_strategy(args) -> int:
    from core.strategy_builder import get_strategy_manager
    sm = get_strategy_manager()
    if args.action == "list":
        for s in sm.get_strategies():
            _p("  %-24s %s" % (s.get("id", "?"),
                               s.get("name", "")))
        return 0
    if args.action == "apply":
        if not args.id:
            _p("Укажите id стратегии: zapret-gui strategy apply <id>")
            return 2
        strategy = sm.get_strategy(args.id)
        if not strategy:
            _p("✗ Стратегия не найдена: %s" % args.id)
            return 1
        nfqws_args = sm.build_nfqws_args(strategy)
        if not nfqws_args:
            _p("✗ Нет включённых профилей в стратегии")
            return 1
        from core.nfqws_manager import get_nfqws_manager
        from core.config_manager import get_config_manager
        mgr = get_nfqws_manager()
        ok = mgr.restart(nfqws_args) if mgr.is_running() \
            else mgr.start(nfqws_args)
        if ok:
            try:
                cfg = get_config_manager()
                cfg.set("strategy", "current_id", strategy.get("id"))
                cfg.set("strategy", "current_name", strategy.get("name"))
                cfg.save()
            except Exception:
                pass
        return _ok("strategy apply %s" % args.id, ok)
    _p("Неизвестное действие: %s" % args.action)
    return 2


# ─────────────────────── singbox ─────────────────────────────────────

def _cmd_singbox(args) -> int:
    from core.singbox_manager import get_singbox_manager
    mgr = get_singbox_manager()
    if args.action == "list":
        cfgs = mgr.list_configs()
        if not cfgs:
            _p("sing-box: конфигов нет")
            return 0
        for c in cfgs:
            _p("  %-24s %s" % (c["name"],
                               "запущен" if c.get("running")
                               else "остановлен"))
        return 0
    if not args.name:
        _p("Укажите имя конфига: zapret-gui singbox %s <name>" % args.action)
        return 2
    if args.action == "up":
        return _ok("singbox up %s" % args.name, mgr.up(args.name))
    if args.action == "down":
        return _ok("singbox down %s" % args.name, mgr.down(args.name))
    if args.action == "restart":
        return _ok("singbox restart %s" % args.name, mgr.restart(args.name))
    _p("Неизвестное действие: %s" % args.action)
    return 2


# ─────────────────────── entry ───────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zapret-gui",
        description="CLI-управление zapret-gui (nfqws2 / sing-box / стратегии)")
    p.add_argument("--config", default=None,
                   help="Путь к директории конфигурации")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Общий статус")

    pn = sub.add_parser("nfqws", help="Управление nfqws2")
    pn.add_argument("action", choices=["start", "stop", "restart", "status"])

    ps = sub.add_parser("strategy", help="Стратегии nfqws2")
    ps.add_argument("action", choices=["list", "apply"])
    ps.add_argument("id", nargs="?", help="ID стратегии (для apply)")

    pb = sub.add_parser("singbox", help="Управление sing-box")
    pb.add_argument("action", choices=["list", "up", "down", "restart"])
    pb.add_argument("name", nargs="?", help="Имя конфига")

    return p


_DISPATCH = {
    "status":   _cmd_status,
    "nfqws":    _cmd_nfqws,
    "strategy": _cmd_strategy,
    "singbox":  _cmd_singbox,
}


def run(argv) -> int:
    """Точка входа CLI. argv — список без имени программы."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Инициализируем только ядро (без web-сервера).
    try:
        from core.config_manager import init_config
        init_config(args.config)
    except Exception as e:
        _p("Ошибка инициализации конфига: %s" % e)
        return 2

    handler = _DISPATCH.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except Exception as e:
        _p("Ошибка: %s" % e)
        return 2


def main():
    sys.exit(run(sys.argv[1:]))
