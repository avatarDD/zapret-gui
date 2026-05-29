# core/teardown.py
"""
Корректное снятие всех runtime-артефактов zapret-gui перед удалением.

Вызывается из uninstall.sh и пакетных prerm-скриптов ДО удаления файлов
приложения. Делает best-effort очистку (каждый шаг изолирован try/except),
чтобы частичная поломка одного шага не мешала остальным:

  1. остановка nfqws2 (живой путь под управлением GUI);
  2. снятие firewall-правил (iptables-цепочки nfqws_post/pre/nat + nft-таблица);
  3. снятие ndm/hotplug-хуков персистентности + reapply-скрипта;
  4. отключение автозапуска (init.d/S99zapret) — если он установлен.

Запуск:  PYTHONPATH=<app_dir> python3 -m core.teardown
Печатает краткий отчёт в stdout. Код возврата всегда 0 (удаление не должно
падать из-за остаточной очистки).
"""

import os
import sys


def _log(msg):
    sys.stdout.write("  [teardown] %s\n" % msg)
    sys.stdout.flush()


def _stop_nfqws():
    try:
        from core.nfqws_manager import get_nfqws_manager
        mgr = get_nfqws_manager()
        if mgr.is_running():
            mgr.stop()
            _log("nfqws2 остановлен")
    except Exception as e:  # noqa: BLE001
        _log("не удалось остановить nfqws2: %s" % e)


def _remove_firewall():
    try:
        from core.firewall import get_firewall_manager
        get_firewall_manager().remove_rules()
        _log("firewall-правила сняты")
    except Exception as e:  # noqa: BLE001
        _log("не удалось снять firewall-правила: %s" % e)


def _remove_persistence():
    try:
        from core import firewall_persistence as fp
        res = fp.remove_hooks()
        if res.get("removed"):
            _log("хуки персистентности удалены: %s" % ", ".join(res["removed"]))
        # reapply-скрипт + runtime-conf
        for path in (fp.REAPPLY_SCRIPT, fp.FW_RUN_CONF):
            try:
                if os.path.exists(path):
                    os.remove(path)
                    _log("удалён %s" % path)
            except OSError:
                pass
    except Exception as e:  # noqa: BLE001
        _log("не удалось снять персистентность: %s" % e)


def _disable_autostart():
    try:
        from core.autostart_manager import get_autostart_manager, SCRIPT_PATH
        if os.path.isfile(SCRIPT_PATH):
            get_autostart_manager().disable()
            _log("автозапуск nfqws2 отключён")
    except Exception as e:  # noqa: BLE001
        _log("не удалось отключить автозапуск: %s" % e)


def _remove_transparent():
    """Снять firewall прозрачного проксирования sing-box (iptables+nft+ip rule)."""
    try:
        from core import singbox_transparent as tp
        tp.remove()
        _log("transparent-proxy firewall снят")
    except Exception as e:  # noqa: BLE001
        _log("не удалось снять transparent-proxy: %s" % e)


def _stop_engines():
    """Остановить запущенные инстансы sing-box и mihomo (иначе осиротеют)."""
    for mod, getter, label in (
        ("core.singbox_manager", "get_singbox_manager", "sing-box"),
        ("core.mihomo_manager", "get_mihomo_manager", "mihomo"),
    ):
        try:
            import importlib
            mgr = getattr(importlib.import_module(mod), getter)()
            stopped = 0
            for cfg in mgr.list_configs():
                if cfg.get("running"):
                    mgr.down(cfg["name"])
                    stopped += 1
            if stopped:
                _log("%s: остановлено инстансов: %d" % (label, stopped))
        except Exception as e:  # noqa: BLE001
            _log("не удалось остановить %s: %s" % (label, e))


def run():
    """Выполнить полную очистку. Всегда возвращает 0."""
    _log("очистка runtime-артефактов zapret-gui...")
    _disable_autostart()   # снимает S99zapret + хуки (на Entware/OpenWrt)
    _stop_nfqws()
    _remove_firewall()
    _remove_persistence()  # на случай, если хуки ставил живой путь, а не автозапуск
    _stop_engines()        # sing-box / mihomo инстансы
    _remove_transparent()  # transparent-proxy firewall (iptables/nft/ip rule)
    _log("очистка завершена")
    return 0


if __name__ == "__main__":
    sys.exit(run())
