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


def _remove_dnsmasq_integration():
    try:
        from core.routing.dnsmasq_integration import DnsmasqIntegration, INCLUDE_MARKER
        dns = DnsmasqIntegration()
        
        # 1. Откатываем авто-настройку resolv.conf и resolved
        revert_res = dns.revert_if_applied()
        if not revert_res.get("skipped"):
            _log("dnsmasq: авто-настройка resolved/resolv.conf успешно откачена")
            
        # 2. Удаляем managed файл
        main_conf = dns.find_main_config()
        if main_conf:
            managed_path = dns.managed_file_path(main_conf)
            if os.path.isfile(managed_path):
                os.remove(managed_path)
                _log("dnsmasq: managed-файл удалён: %s" % managed_path)
                
            # 3. Чистим dnsmasq.conf от include'ов (awg-routing И dns-routing).
            #    dns_routing.apply() дописывает свой маркер
            #    "# zapret-gui dns-routing managed include" + conf-file=; без
            #    его снятия оставшийся conf-file= указывает на удалённый файл
            #    и dnsmasq падает при reload → DNS ломается после удаления.
            DNS_ROUTING_MARKER = "# zapret-gui dns-routing managed include"
            if os.path.isfile(main_conf):
                with open(main_conf, "r") as f:
                    lines = f.readlines()
                new_lines = []
                skip = False
                for line in lines:
                    if INCLUDE_MARKER in line or DNS_ROUTING_MARKER in line:
                        skip = True
                        continue
                    if skip and line.strip().startswith("conf-file="):
                        skip = False
                        continue
                    new_lines.append(line)
                with open(main_conf, "w") as f:
                    f.writelines(new_lines)
                _log("dnsmasq: include удалён из %s" % main_conf)

            # Удаляем сам managed-файл dns-routing (<base>/lists/dns-routing.conf).
            # base вычисляем так же, как dns_routing.apply().
            try:
                from core.config_manager import get_config_manager
                base = get_config_manager().get("zapret", "base_path",
                                                default="/opt/zapret2")
                dns_routing_conf = os.path.join(base, "lists", "dns-routing.conf")
                if os.path.isfile(dns_routing_conf):
                    os.remove(dns_routing_conf)
                    _log("dnsmasq: dns-routing.conf удалён")
            except Exception:
                pass
                
                # Перезапускаем или перезагружаем dnsmasq
                dns.reload()
    except Exception as e:
        _log("не удалось очистить dnsmasq-интеграцию: %s" % e)


def _flush_dnsmasq_backend():
    """Сбросить dnsmasq backend правила (DnsmasqBackend), если модуль доступен."""
    try:
        try:
            from core.routing.dnsmasq_backend import DnsmasqBackend
            DnsmasqBackend().flush_rules()
            _log("dnsmasq backend: правила сброшены")
        except ImportError:
            pass
    except Exception as e:
        _log("не удалось сбросить dnsmasq backend: %s" % e)


def _flush_ndms_backend():
    """Очистить NDMS routing backend, если доступен."""
    try:
        try:
            from core.routing.ndms_backend import NdmsBackend
            NdmsBackend().flush_all()
            _log("NDMS backend: правила сброшены")
            return
        except ImportError:
            pass
        # Fallback: удаляем наши объекты через NDMS-команды
        try:
            from core.ndms import is_ndms_available
            if is_ndms_available():
                from core.ndms.commands import get_ndms_commands, is_owned_name
                cmd = get_ndms_commands()
                routes = cmd.show_dns_proxy_routes()
                cleared = 0
                for route in routes:
                    group = route.get("group", "")
                    iface = route.get("interface", "")
                    if group and is_owned_name(group):
                        cmd.delete_dns_proxy_route(group, iface)
                        cmd.delete_fqdn_group(group)
                        cleared += 1
                if cleared:
                    _log("NDMS: удалено %d dns-proxy route-групп" % cleared)
        except Exception:
            pass
    except Exception as e:
        _log("не удалось очистить NDMS backend: %s" % e)


def _remove_routing_rules():
    try:
        from core.routing.manager import get_routing_manager
        mgr = get_routing_manager()

        # Per-interface cleanup: удаляем правила для каждого интерфейса
        from core.routing import storage
        all_rules = storage.load_rules()
        seen_ifaces = set()
        for rule in all_rules:
            iface = getattr(rule, "target_iface", None)
            if iface and iface not in seen_ifaces:
                seen_ifaces.add(iface)
                try:
                    mgr.remove_all_for_iface(iface)
                except Exception:
                    pass

        # Финальный total cleanup (включая правила, оставшиеся вне storage)
        res = mgr.remove_all()
        removed = res.get("removed") or []
        if removed:
            _log("правила маршрутизации сняты: %s" % ", ".join(removed))
    except Exception as e:
        _log("не удалось снять правила маршрутизации: %s" % e)


def _reset_block_detector():
    """Сбросить DPI-детектор блокировок (stop + clear internal state)."""
    try:
        from core.block_detector import get_block_detector
        bd = get_block_detector()
        if hasattr(bd, "reset"):
            bd.reset()
            _log("block-detector: сброшен")
        else:
            bd.stop()
            _log("block-detector: остановлен")
    except Exception as e:
        _log("не удалось сбросить block-detector: %s" % e)


def _flush_ipset_nftset():
    """MR-12: Очистить ipset/nftset множества созданные routing."""
    import subprocess
    # iptables ipset chains (AWG_ROUTING_PRE, AWG_ROUTING_OUT, AWG_ROUTING_NAT)
    for ipt in ("iptables", "ip6tables"):
        for table, chain in (("mangle", "AWG_ROUTING_PRE"), ("mangle", "AWG_ROUTING_OUT"),
                              ("nat", "AWG_ROUTING_NAT")):
            try:
                subprocess.run([ipt, "-t", table, "-F", chain],
                               capture_output=True, timeout=5)
                subprocess.run([ipt, "-t", table, "-X", chain],
                               capture_output=True, timeout=5)
            except Exception:
                pass
    # nft awg_routing table
    try:
        subprocess.run(["nft", "delete", "table", "inet", "awg_routing"],
                       capture_output=True, timeout=5)
        _log("nft: таблица awg_routing удалена")
    except Exception:
        pass
    # ipset sets
    try:
        result = subprocess.run(["ipset", "list", "-n"], capture_output=True,
                                text=True, timeout=5)
        for name in (result.stdout or "").splitlines():
            name = name.strip()
            if name.startswith("awgr_") or name.startswith("zapret_"):
                subprocess.run(["ipset", "destroy", name],
                               capture_output=True, timeout=5)
        _log("ipset: множества awgr_*/zapret_* уничтожены")
    except Exception:
        pass
    # nft sets in awg_routing (если таблица не удалась выше)
    try:
        result = subprocess.run(
            ["nft", "-j", "list", "tables"], capture_output=True,
            text=True, timeout=5)
        import json
        data = json.loads(result.stdout or "{}")
        for t in data.get("nftables", []):
            tbl = t.get("table", {})
            if tbl.get("name") == "awg_routing":
                subprocess.run(["nft", "delete", "table", "inet", "awg_routing"],
                               capture_output=True, timeout=5)
    except Exception:
        pass


def run():
    """Выполнить полную очистку. Всегда возвращает 0."""
    _log("очистка runtime-артефактов zapret-gui...")
    _disable_autostart()   # снимает S99zapret + хуки (на Entware/OpenWrt)
    _stop_nfqws()
    _remove_firewall()
    _remove_persistence()  # на случай, если хуки ставил живой путь, а не автозапуск
    _stop_engines()        # sing-box / mihomo инстансы
    _remove_transparent()  # transparent-proxy firewall (iptables/nft/ip rule)
    _flush_dnsmasq_backend()  # DnsmasqBackend.flush_rules() если доступен
    _flush_ndms_backend()     # NdmsBackend.flush_all() если доступен
    _flush_ipset_nftset()     # MR-12: ipset/nftset множества + iptables chains
    _remove_routing_rules()   # правила маршрутизации (ip rule, ip route, ndms)
    _remove_dnsmasq_integration() # dnsmasq include и auto-setup revert
    _reset_block_detector()   # сброс DPI-детектора
    _log("очистка завершена")
    return 0


if __name__ == "__main__":
    sys.exit(run())
