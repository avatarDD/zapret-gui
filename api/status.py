# api/status.py
"""
GET /api/status — общий статус системы, nfqws и firewall.
GET /api/ping  — health check.
GET /api/interfaces — список интерфейсов + авто-определение ролей.
GET /api/network/environment — профиль окружения (роутер / ПК с 1 NIC).
"""

import json
import os
import re
import subprocess
import time
from bottle import request, response


def _run_cmd(args, timeout=5):
    """Запустить команду, вернуть (returncode, stdout)."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return -1, ""


_RIVALS_TTL = 10.0
_rivals_cache = {"ts": 0.0, "value": []}


def _cached_rivals():
    """Другие обходчики DPI для дашборда, с кешем на _RIVALS_TTL секунд.

    Ошибку не кешируем: разовый сбой чтения /proc не должен на весь срок
    кеша прятать конфликт — отдаём прошлое значение и пробуем снова.
    """
    now = time.monotonic()
    if _rivals_cache["ts"] and now - _rivals_cache["ts"] < _RIVALS_TTL:
        return _rivals_cache["value"]
    try:
        from core.diagnostics import check_rival_bypassers
        value = check_rival_bypassers()["rivals"]
    except Exception:
        return _rivals_cache["value"]
    _rivals_cache.update(ts=now, value=value)
    return value


_FOREIGN_TTL = 30.0
_foreign_cache = {"ts": 0.0, "value": {}}


def _cached_foreign():
    """Сводка о сторонних экземплярах туннелей (core/foreign_services).

    Скан /proc и init.d — не для каждого опроса дашборда (раз в 3 с),
    поэтому с кешем; ошибку не кешируем.
    """
    now = time.monotonic()
    if _foreign_cache["ts"] and now - _foreign_cache["ts"] < _FOREIGN_TTL:
        return _foreign_cache["value"]
    try:
        from core.foreign_services import summary
        value = summary()
    except Exception:
        return _foreign_cache["value"]
    _foreign_cache.update(ts=now, value=value)
    return value


def _is_private_ip(addr):
    """Проверить, является ли IPv4-адрес приватным (RFC 1918)."""
    try:
        parts = addr.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10
                or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168))
    except (ValueError, IndexError):
        return False


def _openwrt_networks():
    """
    Логические сети OpenWrt (wan, wan6, lan, …) по устройствам.

    В LuCI пользователь видит «wan»/«lan», а в списке ядра — eth1,
    pppoe-wan, br-lan; без сопоставления непонятно, какой из них
    внешний. Источник — `ubus call network.interface dump`
    (l3_device и device: у PPPoE это pppoe-wan и eth1), fallback —
    `uci -q show network`. Возвращает {устройство: [сети]}; вне OpenWrt
    или при ошибке — {}.
    """
    result = {}

    def add(dev, net):
        dev = (dev or "").strip()
        if not dev or not net or net == "loopback":
            return
        nets = result.setdefault(dev, [])
        if net not in nets:
            nets.append(net)

    rc, out = _run_cmd(["ubus", "call", "network.interface", "dump"])
    if rc == 0 and out:
        try:
            data = json.loads(out)
        except ValueError:
            data = {}
        for item in data.get("interface") or []:
            if not isinstance(item, dict):
                continue
            net = item.get("interface") or ""
            add(item.get("l3_device"), net)
            add(item.get("device"), net)
        if result:
            return result

    rc, out = _run_cmd(["uci", "-q", "show", "network"])
    if rc == 0 and out:
        for line in out.split("\n"):
            m = re.match(
                r"network\.([\w-]+)\.(device|ifname)='?([^']*)'?$",
                line.strip())
            if not m:
                continue
            for dev in m.group(3).split():
                add(dev, m.group(1))
    return result


def _default_route_ifaces(iface_names):
    """
    Интерфейсы с маршрутом по умолчанию: (IPv4-набор, IPv6-набор).
    Ровно по нему zapret2 определяет IFACE_WAN/IFACE_WAN6.
    """
    # --- IPv4 ---
    # Способ 1: /proc/net/route (как в zapret2 init.d скриптах)
    v4 = set()
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split("\t")
                # Dest==00000000, Mask==00000000 → default route
                if (len(parts) >= 8
                        and parts[1] == "00000000"
                        and parts[7] == "00000000"
                        and parts[0] in iface_names):
                    v4.add(parts[0])
    except (IOError, OSError):
        pass

    # Способ 2 (fallback): ip route show default
    if not v4:
        rc, out = _run_cmd(["ip", "route", "show", "default"])
        if rc == 0 and out:
            for line in out.split("\n"):
                m = re.search(r"dev\s+(\S+)", line)
                if m and m.group(1) in iface_names:
                    v4.add(m.group(1))

    # --- IPv6 ---
    v6 = set()
    rc, out = _run_cmd(["ip", "-6", "route", "show", "default"])
    if rc == 0 and out:
        for line in out.split("\n"):
            m = re.search(r"dev\s+(\S+)", line)
            if m and m.group(1) in iface_names:
                v6.add(m.group(1))
    return v4, v6


def _annotate_external(interfaces, routes, networks):
    """
    Пометить внешние интерфейсы, чтобы в настройках было видно, какой
    из них WAN. Каждому интерфейсу добавляется:

      networks      — логические сети OpenWrt (["wan"], ["lan"], …);
      default_route — семейства маршрута по умолчанию (["ipv4", "ipv6"]);
      external      — внешний. Если OpenWrt знает сети wan*, решают
                      они: маршрут по умолчанию через VPN (wg0, tun0)
                      не делает туннель внешним интерфейсом. Иначе —
                      есть маршрут по умолчанию.
    """
    v4, v6 = routes

    def is_wan(nets):
        return any(n.lower().startswith("wan") for n in nets)

    by_network = any(is_wan(n) for n in networks.values())
    for iface in interfaces:
        name = iface["name"]
        nets = list(networks.get(name, []))
        dr = []
        if name in v4:
            dr.append("ipv4")
        if name in v6:
            dr.append("ipv6")
        iface["networks"] = nets
        iface["default_route"] = dr
        iface["external"] = is_wan(nets) if by_network else bool(dr)


def _detect_interface_roles(interfaces, addr_map, routes=None):
    """
    Авто-определение ролей WAN/WAN6/LAN по маршрутам и адресам.

    Аналог логики zapret2:
      WAN  — интерфейс с IPv4 default route (/proc/net/route)
      WAN6 — интерфейс с IPv6 default route; fallback на WAN
      LAN  — bridge (br-*) или приватная подсеть, отличная от WAN
    """
    detected = {"wan": "", "wan6": "", "lan": ""}
    if routes is None:
        routes = _default_route_ifaces({i["name"] for i in interfaces})
    wan_ifaces, wan6_ifaces = routes

    if wan_ifaces:
        detected["wan"] = " ".join(sorted(wan_ifaces))

    if wan6_ifaces:
        detected["wan6"] = " ".join(sorted(wan6_ifaces))
    elif detected["wan"]:
        # Как в zapret2: IFACE_WAN6 = IFACE_WAN если не задан
        detected["wan6"] = detected["wan"]

    # --- LAN: bridge или приватная подсеть, не WAN ---
    all_wan = wan_ifaces | wan6_ifaces
    lan_candidates = []

    for iface in interfaces:
        name = iface["name"]
        if name in all_wan:
            continue
        # Bridge → первый приоритет
        if name.startswith("br"):
            lan_candidates.insert(0, name)
            continue
        # Приватный IPv4 → второй приоритет
        for a in addr_map.get(name, []):
            if a["family"] == "ipv4" and _is_private_ip(a["address"]):
                lan_candidates.append(name)
                break

    if lan_candidates:
        detected["lan"] = lan_candidates[0]

    return detected


def dashboard_status() -> dict:
    """Объединенный статус для Dashboard: nfqws, system, warp, opera, tgproxy, block_detector, healthcheck, logs."""

    from core.config_manager import get_config_manager
    from core.system_info import get_system_info
    from core.nfqws_manager import get_nfqws_manager
    from core.firewall import get_firewall_manager
    from core.autostart_manager import get_autostart_manager
    from core.zapret_installer import get_zapret_installer
    from core.version import GUI_VERSION

    cfg = get_config_manager()
    mgr = get_nfqws_manager()
    fw = get_firewall_manager()
    am = get_autostart_manager()
    inst = get_zapret_installer()
    zapret_version = inst.get_installed_version()

    status_data = {
        "nfqws": mgr.get_status(),
        "firewall": fw.get_status(),
        "strategy": {
            "id": cfg.get("strategy", "current_id"),
            "name": cfg.get("strategy", "current_name") or "Не выбрана",
        },
        "autostart": am.get_status(),
        "system": get_system_info(),
        "zapret": {
            "installed": zapret_version["installed"],
            "version": zapret_version["version"],
        },
        "gui_version": GUI_VERSION,
        "timestamp": time.time(),
    }

    # 2. Статус WARP/MASQUE (usque)
    warp_configs = []
    try:
        from core.usque_manager import get_usque_manager
        warp_configs = get_usque_manager().list_configs()
    except Exception:
        pass

    # 3. Статус Opera Proxy
    opera_status = {}
    try:
        from core.opera_proxy_manager import get_opera_proxy_manager
        opera_status = get_opera_proxy_manager().status()
    except Exception:
        pass

    # 4. Статус Telegram Proxy
    tg_status = {}
    try:
        from core.tgproxy_manager import get_active_engine_status
        tg_status = get_active_engine_status()
    except Exception:
        pass

    # 4b. Основные VPN-движки: AmneziaWG, sing-box, mihomo.
    # Их не было в дашборде вообще — при поднятом AWG-туннеле раздел
    # «VPN / Туннели» оставался пустым, хотя это главные движки.
    # Отдаём компактно: сколько профилей и сколько из них активно.
    def _engine_summary(loader, active_key):
        try:
            configs = loader() or []
        except Exception:
            return {"available": False, "total": 0, "active": 0,
                    "names": []}
        active = [c for c in configs
                  if isinstance(c, dict) and c.get(active_key)]
        return {
            "available": True,
            "total": len(configs),
            "active": len(active),
            "names": [c.get("iface") or c.get("name") or ""
                      for c in active][:3],
        }

    awg_status = _engine_summary(
        lambda: __import__("core.awg_manager", fromlist=["x"])
        .get_awg_manager().list_configs(), "active")
    singbox_status = _engine_summary(
        lambda: __import__("core.singbox_manager", fromlist=["x"])
        .get_singbox_manager().list_configs(), "running")
    mihomo_status = _engine_summary(
        lambda: __import__("core.mihomo_manager", fromlist=["x"])
        .get_mihomo_manager().list_configs(), "running")

    # 5. Статус Block Detector
    bd_status = {}
    try:
        from core.block_detector import get_block_detector
        bd_status = get_block_detector().get_status()
    except Exception:
        pass

    # 6. Статус Healthcheck
    hc_status = {}
    try:
        from core.healthcheck import get_healthcheck
        hc_status = get_healthcheck().get_status()
    except Exception:
        pass

    # 6b. Другие обходчики DPI (youtubeUnblock, b4, byedpi, …): вдвоём
    # с nfqws2 они мешают друг другу, и это первое, что надо видеть
    # на главной, а не только в «Диагностике». Обход /proc — раз в
    # 30 секунд, а не на каждый опрос дашборда.
    rivals = _cached_rivals()

    # 7. Последние логи (15 записей)
    logs_data = []
    try:
        from core.log_buffer import get_log_buffer
        logs_data = get_log_buffer().get_last(15)
    except Exception:
        pass

    result = {
        "ok": True,
        "status": status_data,
        "warp": warp_configs,
        "opera": opera_status,
        "tgproxy": tg_status,
        "awg": awg_status,
        "singbox": singbox_status,
        "mihomo": mihomo_status,
        "block_detector": bd_status,
        "healthcheck": hc_status,
        "rivals": rivals,
        "foreign": _cached_foreign(),
        "logs": logs_data,
    }
    # «Кратко»: одна строка «всё ли работает» и итог каждого блока.
    try:
        from core.dashboard_brief import brief
        result["brief"] = brief(result)
    except Exception:
        pass
    return result


def register(app):

    @app.route("/api/dashboard/status")
    def api_dashboard_status():
        """Объединенный статус для Dashboard (см. dashboard_status)."""
        response.content_type = "application/json; charset=utf-8"
        return dashboard_status()

    @app.route("/api/status")
    def api_status():
        """Общий статус системы: nfqws, firewall, стратегия, система."""
        response.content_type = "application/json; charset=utf-8"

        from core.config_manager import get_config_manager
        from core.system_info import get_system_info
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.autostart_manager import get_autostart_manager
        from core.zapret_installer import get_zapret_installer
        from core.version import GUI_VERSION

        cfg = get_config_manager()
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()
        am = get_autostart_manager()
        inst = get_zapret_installer()

        zapret_version = inst.get_installed_version()

        return {
            "ok": True,
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
            "strategy": {
                "id": cfg.get("strategy", "current_id"),
                "name": cfg.get("strategy", "current_name") or "Не выбрана",
            },
            "autostart": am.get_status(),
            "system": get_system_info(),
            "zapret": {
                "installed": zapret_version["installed"],
                "version": zapret_version["version"],
            },
            "gui_version": GUI_VERSION,
            "timestamp": time.time(),
        }

    @app.route("/api/ping")
    def api_ping():
        """Health check."""
        response.content_type = "application/json; charset=utf-8"
        return {"ok": True, "timestamp": time.time()}

    @app.route("/api/network/environment")
    def api_network_environment():
        """
        Профиль сетевого окружения: роутер с LAN (Keenetic/OpenWrt или
        generic Linux с LAN-мостом) либо обычный ПК / VPS с одной
        сетевой картой (локальный режим). ?refresh=1 — пересканировать.
        """
        response.content_type = "application/json; charset=utf-8"
        from core import network_env
        force = request.query.get("refresh") in ("1", "true", "yes")
        return network_env.detect(force=force)

    @app.route("/api/install/transports")
    def api_install_transports():
        """
        Доступные транспорты скачивания (через что качать релизы):
        напрямую + активные AWG-интерфейсы + запущенные sing-box/mihomo
        конфиги с локальным mixed/http-портом. Общий для всех
        разделов установки.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.download_transport import list_transports
            return list_transports()
        except Exception as e:
            return {"ok": False, "error": str(e),
                    "transports": [{"id": "direct", "kind": "direct",
                                    "label": "Напрямую"}]}

    @app.route("/api/interfaces")
    def api_interfaces():
        """
        Список сетевых интерфейсов + авто-определение WAN/WAN6/LAN.

        Возвращает:
          interfaces — [{name, state, addresses, networks,
                         default_route, external}]
          detected   — авто-определённые роли {wan, wan6, lan}
        """
        response.content_type = "application/json; charset=utf-8"

        interfaces = []
        seen = set()

        # Способ 1: ip link show
        rc, out = _run_cmd(["ip", "-o", "link", "show"])
        if rc == 0 and out:
            for line in out.split("\n"):
                match = re.match(r"\d+:\s+(\S+?)(@\S+)?:", line)
                if match:
                    name = match.group(1)
                    if name != "lo" and name not in seen:
                        seen.add(name)
                        state = "unknown"
                        upper = line.upper()
                        if "UP" in upper and "LOWER_UP" in upper:
                            state = "up"
                        elif "DOWN" in upper:
                            state = "down"
                        interfaces.append({"name": name, "state": state})

        # Способ 2 (fallback): /sys/class/net/
        if not interfaces:
            try:
                net_dir = "/sys/class/net"
                if os.path.isdir(net_dir):
                    for name in sorted(os.listdir(net_dir)):
                        if name == "lo" or name in seen:
                            continue
                        seen.add(name)
                        state = "unknown"
                        op = os.path.join(net_dir, name, "operstate")
                        if os.path.isfile(op):
                            try:
                                with open(op, "r") as f:
                                    s = f.read().strip()
                                    state = s if s else "unknown"
                            except (IOError, OSError):
                                pass
                        interfaces.append({"name": name, "state": state})
            except (IOError, OSError):
                pass

        # Собираем IP-адреса
        addr_map = {}
        rc, out = _run_cmd(["ip", "-o", "addr", "show"])
        if rc == 0 and out:
            for line in out.split("\n"):
                match = re.match(
                    r"\d+:\s+(\S+)\s+(inet6?)\s+([\da-fA-F.:]+)/(\d+)",
                    line.strip()
                )
                if match:
                    iname = match.group(1)
                    family = "ipv4" if match.group(2) == "inet" else "ipv6"
                    addr = match.group(3)
                    if iname not in addr_map:
                        addr_map[iname] = []
                    addr_map[iname].append({
                        "family": family,
                        "address": addr,
                    })

        for iface in interfaces:
            iface["addresses"] = addr_map.get(iface["name"], [])

        # Авто-определение ролей и пометка внешних интерфейсов
        routes = _default_route_ifaces({i["name"] for i in interfaces})
        detected = _detect_interface_roles(interfaces, addr_map, routes)
        _annotate_external(interfaces, routes, _openwrt_networks())

        return {
            "ok": True,
            "interfaces": interfaces,
            "detected": detected,
        }
