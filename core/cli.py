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
COMMANDS = ("status", "nfqws", "strategy", "singbox", "mihomo",
            "usque", "tgproxy", "opera", "monitor", "updates", "dns-routing")


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
    # mihomo
    try:
        from core.mihomo_manager import get_mihomo_manager
        cfgs = get_mihomo_manager().list_configs()
        if cfgs:
            up = [c["name"] for c in cfgs if c.get("running")]
            _p("mihomo:   %d конфигов, запущено: %s"
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


def _cmd_mihomo(args) -> int:
    from core.mihomo_manager import get_mihomo_manager
    mgr = get_mihomo_manager()
    if args.action == "list":
        cfgs = mgr.list_configs()
        if not cfgs:
            _p("mihomo: конфигов нет")
            return 0
        for c in cfgs:
            _p("  %-24s %s" % (c["name"],
                               "запущен" if c.get("running")
                               else "остановлен"))
        return 0
    if not args.name:
        _p("Укажите имя конфига: zapret-gui mihomo %s <name>" % args.action)
        return 2
    if args.action == "up":
        return _ok("mihomo up %s" % args.name, mgr.up(args.name))
    if args.action == "down":
        return _ok("mihomo down %s" % args.name, mgr.down(args.name))
    if args.action == "restart":
        return _ok("mihomo restart %s" % args.name, mgr.restart(args.name))
    _p("Неизвестное действие: %s" % args.action)
    return 2


# ─────────────────────── usque (WARP/MASQUE) ────────────────────────

def _cmd_usque(args) -> int:
    from core.usque_manager import get_usque_manager
    mgr = get_usque_manager()
    action = args.action
    if action == "status":
        env = mgr.detect()
        if env.get("installed"):
            _p("usque: установлен (%s, %s)" % (env.get("version", "?"), env.get("arch", "?")))
        else:
            _p("usque: не установлен")
        configs = mgr.list_configs()
        active = [c for c in configs if c.get("active")]
        _p("конфигов: %d, активных: %s" % (len(configs), ", ".join(c["iface"] for c in active) if active else "—"))
        return 0
    if action == "start":
        if not args.iface:
            _p("Укажите интерфейс: zapret-gui usque start <iface>")
            return 2
        configs = mgr.list_configs()
        target = next((c for c in configs if c["iface"] == args.iface), None)
        if not target:
            _p("✗ Интерфейс не найден: %s" % args.iface)
            return 1
        return _ok("usque start %s" % args.iface,
                    mgr.start(args.iface, target["path"]))
    if action == "stop":
        if not args.iface:
            _p("Укажите интерфейс: zapret-gui usque stop <iface>")
            return 2
        return _ok("usque stop %s" % args.iface, mgr.stop(args.iface))
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── tgproxy (Telegram) ──────────────────────────

def _cmd_tgproxy(args) -> int:
    from core.tgproxy_manager import get_tgwsproxy_manager
    mgr = get_tgwsproxy_manager()
    action = args.action
    if action == "status":
        st = mgr.get_status()
        _p("telegram: %s" % ("запущен (%s)" % st.get("engine", "?")
                            if st.get("running") else "остановлен"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        return _ok("telegram start", mgr.start())
    if action == "stop":
        return _ok("telegram stop", mgr.stop())
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── opera proxy ─────────────────────────────────

def _cmd_opera(args) -> int:
    from core.opera_proxy_manager import get_opera_proxy_manager
    mgr = get_opera_proxy_manager()
    action = args.action
    if action == "status":
        st = mgr.status()
        _p("opera: %s" % ("запущен" if st.get("running") else "остановлен"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        return _ok("opera start", mgr.start())
    if action == "stop":
        return _ok("opera stop", mgr.stop())
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── monitor (live metrics) ──────────────────────

def _cmd_monitor(_args) -> int:
    from core.tunnel_monitor import get_tunnel_monitor
    monitor = get_tunnel_monitor()
    metrics = monitor.get_metrics()
    if not metrics:
        _p("Нет активных туннелей")
        return 0
    _p("%-20s %12s %12s %12s %12s" % ("Интерфейс", "RX", "TX", "RX/s", "TX/s"))
    _p("-" * 70)
    for m in metrics:
        rx = _fmt_bytes(m.get("rx_bytes", 0))
        tx = _fmt_bytes(m.get("tx_bytes", 0))
        rx_s = _fmt_speed(m.get("rx_speed", 0))
        tx_s = _fmt_speed(m.get("tx_speed", 0))
        _p("%-20s %12s %12s %12s %12s" % (m["iface"], rx, tx, rx_s, tx_s))
    return 0


def _fmt_bytes(b):
    if b < 1024: return "%d B" % b
    if b < 1024*1024: return "%.1f KB" % (b/1024)
    if b < 1024*1024*1024: return "%.1f MB" % (b/(1024*1024))
    return "%.2f GB" % (b/(1024*1024*1024))


def _fmt_speed(bps):
    if bps < 1024: return "%d B/s" % bps
    if bps < 1024*1024: return "%.1f KB/s" % (bps/1024)
    return "%.1f MB/s" % (bps/(1024*1024))


# ─────────────────────── updates ─────────────────────────────────────

def _cmd_updates(_args) -> int:
    from core.update_checker import check_all
    _p("Проверка обновлений...")
    result = check_all()
    results = result.get("results", [])
    updates = [r for r in results if r.get("has_update")]
    _p("")
    _p("%-20s %-15s %-15s %s" % ("Компонент", "Установлена", "Последняя", "Статус"))
    _p("-" * 70)
    for r in results:
        status = "← обновление" if r.get("has_update") else "OK"
        _p("%-20s %-15s %-15s %s" % (
            r.get("display_name", r.get("name", "?")),
            r.get("current", "-") or "-",
            r.get("latest", "-") or "-",
            status))
    _p("")
    _p("Найдено обновлений: %d" % len(updates))
    return 0 if not updates else 1


# ─────────────────────── dns-routing ─────────────────────────────────

def _cmd_dns_routing(args) -> int:
    from core.dns_routing import get_dns_routing_manager
    mgr = get_dns_routing_manager()
    action = args.action
    if action == "list":
        rules = mgr.get_rules()
        if not rules:
            _p("Нет DNS-правил")
            return 0
        _p("%-30s %-20s %s" % ("Домен", "DNS", "Описание"))
        _p("-" * 70)
        for r in rules:
            _p("%-30s %-20s %s" % (r.get("domain", "?"),
                                   r.get("dns", "?"),
                                   r.get("description", "")))
        return 0
    if action == "apply":
        result = mgr.apply()
        return _ok("dns-routing apply: %d правил" % result.get("applied", 0), result)
    _p("Неизвестное действие: %s" % action)
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

    pm = sub.add_parser("mihomo", help="Управление mihomo (Clash.Meta)")
    pm.add_argument("action", choices=["list", "up", "down", "restart"])
    pm.add_argument("name", nargs="?", help="Имя конфига")

    pu = sub.add_parser("usque", help="Управление WARP/MASQUE (usque)")
    pu.add_argument("action", choices=["status", "start", "stop"])
    pu.add_argument("iface", nargs="?", help="Интерфейс (opkgtun0)")

    pt = sub.add_parser("tgproxy", help="Управление Telegram MTProto Proxy")
    pt.add_argument("action", choices=["status", "start", "stop"])

    po = sub.add_parser("opera", help="Управление Opera Proxy")
    po.add_argument("action", choices=["status", "start", "stop"])

    sub.add_parser("monitor", help="Live метрики туннелей")
    sub.add_parser("updates", help="Проверка обновлений")

    pdr = sub.add_parser("dns-routing", help="Per-domain DNS routing")
    pdr.add_argument("action", choices=["list", "apply"])

    return p


_DISPATCH = {
    "status":      _cmd_status,
    "nfqws":       _cmd_nfqws,
    "strategy":    _cmd_strategy,
    "singbox":     _cmd_singbox,
    "mihomo":      _cmd_mihomo,
    "usque":       _cmd_usque,
    "tgproxy":     _cmd_tgproxy,
    "opera":       _cmd_opera,
    "monitor":     _cmd_monitor,
    "updates":     _cmd_updates,
    "dns-routing": _cmd_dns_routing,
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
