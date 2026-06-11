# core/network_env.py
"""
Детект сетевого окружения: роутер (есть LAN, форвардим клиентов) или
обычный ПК / VPS с одной сетевой картой.

Зачем: почти вся логика GUI исторически писалась под роутер (Keenetic /
OpenWrt) — прозрачное проксирование заворачивает PREROUTING-форвард
LAN-клиентов, маршрутизация предлагает выбор устройств сети и т.д. На
обычном Linux-ПК с единственной сетевухой ролей WAN/LAN нет:

  • заворачивать нужно OUTPUT — исходящий трафик самой машины
    (scope='self' в core/singbox_transparent*), а PREROUTING-redirect
    без -i-фильтра опасен: на машине с публичным IP (VPS) он перехватит
    ВХОДЯЩИЕ соединения — обрыв SSH;
  • выбор LAN-устройств в правилах маршрутизации не имеет смысла.

Профиль:
  'router' — Keenetic / OpenWrt / Entware ЛИБО generic Linux с LAN-мостом,
             в котором есть физический интерфейс (рукодельный роутер);
  'pc'     — остальной generic Linux (десктоп, ноутбук, VPS). Мосты без
             физических членов (docker0/virbr0/lxdbr0 из veth) профиль
             НЕ меняют — это контейнеры на ПК, а не LAN.

Авто-детект переопределяется настройкой network.profile
(auto | router | pc) в settings.json — на случай экзотики.

Все обращения к sysfs/procfs вынесены в маленькие обёртки (_listdir /
_isdir / _exists / _route_lines) — тесты подменяют их и проверяют чистую
логику без рута (tests/test_network_env.py).
"""

import os
import threading

SYS_NET = "/sys/class/net"
SYS_VIRTUAL = "/sys/devices/virtual/net"

PROFILES = ("auto", "router", "pc")

_lock = threading.Lock()
_cache = None


# ─────────────────────── обёртки I/O (для тестов) ─────────────────────

def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _isdir(path):
    return os.path.isdir(path)


def _exists(path):
    return os.path.exists(path)


def _route_lines():
    """Строки /proc/net/route (включая заголовок) либо []."""
    try:
        with open("/proc/net/route", "r") as f:
            return f.readlines()
    except (IOError, OSError):
        return []


# ─────────────────────── элементы детекта ────────────────────────────

def _platform_kind() -> str:
    """
    'keenetic' | 'openwrt' | 'entware' | 'linux' — лёгкий файловый детект
    (та же логика, что core/system_info._get_platform; тяжёлый
    awg_detector здесь ни к чему).
    """
    if _exists("/tmp/ndnproxy_acl"):
        return "keenetic"
    if _exists("/etc/openwrt_release"):
        return "openwrt"
    if _exists("/opt/etc/entware_release"):
        return "entware"
    return "linux"


def list_interfaces() -> dict:
    """
    Разложить интерфейсы по типам.

      physical — есть симлинк device (PCI/USB/SoC): ethernet, wifi, wwan;
      bridges  — мосты (есть каталог bridge);
      virtual  — остальная виртуалка: tun/tap, wg/awg, veth, vlan, ppp…;
      wireless — подмножество physical с каталогом wireless.
    """
    physical, bridges, virtual, wireless = [], [], [], []
    for name in _listdir(SYS_NET):
        if name == "lo":
            continue
        base = os.path.join(SYS_NET, name)
        # Мост проверяем раньше virtual: мосты тоже лежат в virtual/net.
        if _isdir(os.path.join(base, "bridge")):
            bridges.append(name)
            continue
        if _isdir(os.path.join(SYS_VIRTUAL, name)):
            virtual.append(name)
            continue
        if _exists(os.path.join(base, "device")):
            physical.append(name)
            if _isdir(os.path.join(base, "wireless")):
                wireless.append(name)
        else:
            virtual.append(name)
    return {"physical": physical, "bridges": bridges,
            "virtual": virtual, "wireless": wireless}


def _bridge_has_physical(bridge: str, physical: list) -> bool:
    """
    Есть ли в мосту физический member (по brif) — признак LAN-моста
    роутера. docker0/virbr0 на ПК состоят из veth — физики там нет.
    """
    members = _listdir(os.path.join(SYS_NET, bridge, "brif"))
    return any(m in physical for m in members)


def _default_iface() -> str:
    """Интерфейс IPv4 default route (как core/firewall, по /proc/net/route)."""
    for line in _route_lines()[1:]:
        parts = line.strip().split("\t")
        if (len(parts) >= 8
                and parts[1] == "00000000"
                and parts[7] == "00000000"):
            return parts[0]
    return ""


def _profile_override() -> str:
    """network.profile из settings.json ('auto' при отсутствии/мусоре)."""
    try:
        from core.config_manager import get_config_manager
        v = get_config_manager().get("network", "profile", default="auto")
        v = str(v or "auto").strip().lower()
    except Exception:
        v = "auto"
    return v if v in PROFILES else "auto"


# ─────────────────────── публичный API ────────────────────────────────

def detect(force: bool = False) -> dict:
    """
    Полный отчёт об окружении.

      profile        — итоговый 'router' | 'pc' (с учётом override);
      profile_auto   — что сказал авто-детект;
      profile_source — 'auto' | 'override';
      single_nic     — ровно одна физическая сетевая карта;
      physical/bridges/lan_bridges/virtual/wireless — раскладка;
      default_iface  — интерфейс default route ('' если нет).

    Скан железа кэшируется (статус-эндпоинты поллятся каждые 5с), а
    override из settings.json читается всегда свежим — смена
    network.profile в Настройках действует без перезапуска GUI.
    """
    global _cache
    with _lock:
        if _cache is None or force:
            ifaces = list_interfaces()
            platform = _platform_kind()
            physical = ifaces["physical"]
            lan_bridges = [b for b in ifaces["bridges"]
                           if _bridge_has_physical(b, physical)]
            if platform in ("keenetic", "openwrt", "entware"):
                auto = "router"
            elif lan_bridges:
                auto = "router"
            else:
                auto = "pc"
            _cache = {
                "ok": True,
                "profile_auto": auto,
                "platform": platform,
                "single_nic": len(physical) == 1,
                "physical": physical,
                "bridges": ifaces["bridges"],
                "lan_bridges": lan_bridges,
                "virtual": ifaces["virtual"],
                "wireless": ifaces["wireless"],
                "default_iface": _default_iface(),
            }
        report = dict(_cache)
    override = _profile_override()
    auto = report["profile_auto"]
    report["profile"] = auto if override == "auto" else override
    report["profile_source"] = "auto" if override == "auto" else "override"
    return report


def is_pc_profile() -> bool:
    """True, если работаем как ПК/VPS (локальный режим, не роутер)."""
    try:
        return detect().get("profile") == "pc"
    except Exception:
        return False


def reset_cache() -> None:
    """Сбросить кэш детекта (после смены network.profile / интерфейсов)."""
    global _cache
    with _lock:
        _cache = None
