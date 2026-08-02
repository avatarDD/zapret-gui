# core/system_info.py
"""
Сбор информации о системе роутера.

Версия ядра, архитектура, RAM, uptime, IP-адреса.

Здесь же живёт лёгкий детект платформы (`platform_kind`) — единственный
источник правды для тех мест, где нельзя платить за тяжёлые пробы:
эта функция вызывается на каждый опрос дашборда, поэтому она смотрит
ТОЛЬКО файлы и PATH, без запуска ndmc/ndmq (их сессии на
/var/run/ndm.core.socket забивают системный лог роутера).

Для задач, где точность важнее цены (выбор бинарников, путей, init-
скриптов), есть полноценный детектор — core/awg_detector.AwgDetector:
он при необходимости дёргает `ndmc` и кэширует результат на процесс.
Маркеры Keenetic здесь подобраны так, чтобы совпадать с ним.
"""

import os
import platform
import re
import shutil
import subprocess


def get_system_info() -> dict:
    """Собрать основную информацию о системе."""
    info = {
        "hostname": _read_file("/etc/hostname", platform.node()),
        "kernel": platform.release(),
        "arch": _get_arch(),
        "arch_uname": platform.machine(),
        "platform": _get_platform(),
        "uptime": _get_uptime(),
        "uptime_human": _format_uptime(_get_uptime()),
        "ram": _get_ram_info(),
        "load_avg": _get_load_average(),
        "wan_ip": _get_wan_ip(),
    }
    return info


def _get_arch() -> str:
    """Архитектура, по которой РЕАЛЬНО выбираются сборки бинарников.

    `platform.machine()` — это `uname -m`, а он на MIPS отдаёт просто
    "mips" и для little-, и для big-endian. Из-за этого «Диагностика»
    показывала `mips` на роутере, где все остальные страницы (установка
    sing-box, usque, AWG) правильно определяют `mipsel`, — и выглядело
    это как противоречие в самом GUI.

    Источник истины здесь тот же, что у установщиков: endianness берётся
    у работающего интерпретатора, а не у `uname`. Сырое значение
    остаётся рядом в поле `arch_uname`.
    """
    try:
        from core.ext_binary_installer import detect_arch
        arch = (detect_arch() or "").strip()
        if arch:
            return arch
    except Exception:
        pass
    return platform.machine()


def _read_file(path: str, default: str = "") -> str:
    """Прочитать файл, вернуть default при ошибке."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (IOError, OSError):
        return default


def _is_keenetic() -> bool:
    """Keenetic — по любому из дешёвых маркеров (без запуска ndmc).

    Раньше признаком служил один `/tmp/ndnproxy_acl`, но этот файл
    создаёт ndnproxy — компонент DNS-прокси KeenOS. У кого DNS отдан
    dnsmasq/AdGuard (типовой случай для zapret-gui), файла нет, и роутер
    определялся как «OpenWrt» (у KeenOS есть /etc/openwrt_release) либо
    как «Entware».
    """
    if os.path.exists("/tmp/ndnproxy_acl"):
        return True
    # Каталог хуков NDMS — им же пользуется firewall_persistence.is_keenetic.
    if os.path.isdir("/opt/etc/ndm"):
        return True
    # Наличие CLI NDMS в PATH. Именно which, а не запуск: каждый вызов
    # ndmc открывает сессию на ndm.core.socket и пишет в лог роутера.
    if shutil.which("ndmc") or shutil.which("ndmq"):
        return True
    if "keenetic" in _read_file("/proc/version").lower():
        return True
    # KeenOS на OpenWrt-основе: файл есть, но это не «просто OpenWrt».
    return "keenetic" in _read_file("/etc/openwrt_release").lower()


def platform_kind() -> str:
    """'keenetic' | 'openwrt' | 'entware' | 'linux' — лёгкий детект.

    Keenetic проверяем раньше OpenWrt: у KeenOS бывает и
    /etc/openwrt_release, и Entware, поэтому обратный порядок давал
    неверную платформу.
    """
    if _is_keenetic():
        return "keenetic"
    if os.path.exists("/etc/openwrt_release") or \
            os.path.exists("/etc/openwrt_version"):
        return "openwrt"
    if os.path.exists("/opt/etc/entware_release") or \
            os.path.exists("/opt/bin/opkg"):
        return "entware"
    return "linux"


def _keenos_version() -> str:
    """Версия KeenOS из /proc/version, если она там есть (без ndmc)."""
    m = re.search(r"Keenetic[^\d]*(\d+\.\d+\.\d+)",
                  _read_file("/proc/version"), re.I)
    if m:
        return m.group(1)
    m = re.search(r'DISTRIB_DESCRIPTION="[^"]*Keenetic[^"]*?(\d+\.\d+\.\d+)',
                  _read_file("/etc/openwrt_release"), re.I)
    return m.group(1) if m else ""


def _openwrt_version() -> str:
    """DISTRIB_RELEASE из /etc/openwrt_release."""
    m = re.search(r"DISTRIB_RELEASE=['\"]?([^'\"\n]+)",
                  _read_file("/etc/openwrt_release"))
    return m.group(1).strip() if m else ""


def _get_platform() -> str:
    """Человекочитаемая платформа для карточки «Системная информация»."""
    kind = platform_kind()
    entware = os.path.exists("/opt/etc/entware_release") or \
        os.path.exists("/opt/bin/opkg")

    if kind == "keenetic":
        ver = _keenos_version()
        label = f"Keenetic {ver} (NDMS)" if ver else "Keenetic (NDMS)"
    elif kind == "openwrt":
        ver = _openwrt_version()
        label = f"OpenWrt {ver}" if ver else "OpenWrt"
    elif kind == "entware":
        release = _read_file("/opt/etc/entware_release").split("\n")[0]
        return f"Entware ({release})" if release else "Entware"
    else:
        return "Linux"

    # Entware на Keenetic/OpenWrt — норма, и знать о нём полезно: именно
    # там лежат наши бинарники и init-скрипты.
    return f"{label} + Entware" if entware else label


def _get_uptime() -> int:
    """Получить uptime в секундах."""
    try:
        data = _read_file("/proc/uptime")
        return int(float(data.split()[0]))
    except (ValueError, IndexError):
        return 0


def _format_uptime(seconds: int) -> str:
    """Форматировать uptime в человекочитаемый вид: Xмес Xд Xч Xм Xс."""
    if seconds <= 0:
        return "—"

    months = seconds // (30 * 86400)     # ~30 дней в месяце
    remainder = seconds % (30 * 86400)
    days = remainder // 86400
    remainder = remainder % 86400
    hours = remainder // 3600
    remainder = remainder % 3600
    minutes = remainder // 60
    secs = remainder % 60

    parts = []
    if months > 0:
        parts.append("%dмес" % months)
    if days > 0:
        parts.append("%dд" % days)
    if hours > 0:
        parts.append("%dч" % hours)
    if minutes > 0:
        parts.append("%dм" % minutes)
    # Секунды показываем всегда, если нет более крупных единиц,
    # либо если uptime менее часа (для точности)
    if secs > 0 and (not parts or hours == 0):
        parts.append("%dс" % secs)

    # Fallback если всё нулевое (не должно случиться при seconds > 0)
    if not parts:
        parts.append("0с")

    return " ".join(parts)


def _get_ram_info() -> dict:
    """Получить информацию о RAM из /proc/meminfo."""
    info = {"total_mb": 0, "free_mb": 0, "available_mb": 0, "used_percent": 0}
    try:
        meminfo = _read_file("/proc/meminfo")
        data = {}
        for line in meminfo.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                # Значение в kB
                data[key.strip()] = int(val.strip().split()[0])

        total = data.get("MemTotal", 0)
        available = data.get("MemAvailable", data.get("MemFree", 0))

        info["total_mb"] = round(total / 1024)
        info["available_mb"] = round(available / 1024)
        info["free_mb"] = round(data.get("MemFree", 0) / 1024)
        if total > 0:
            info["used_percent"] = round((1 - available / total) * 100)
    except (ValueError, KeyError):
        pass
    return info


def _get_load_average() -> str:
    """Получить load average."""
    try:
        data = _read_file("/proc/loadavg")
        parts = data.split()
        return f"{parts[0]} {parts[1]} {parts[2]}"
    except (IndexError, IOError):
        return "—"


def _get_wan_ip() -> str:
    """
    Локальный адрес, с которого уходит трафик в интернет.

    Это `src` из `ip route get 8.8.8.8`, то есть адрес НАШЕГО исходящего
    интерфейса, а не публичный IP: за NAT/CGNAT он будет серым. В UI
    подписан соответственно.

    Возвращает пустую строку, когда определить не удалось (нет `ip`, нет
    маршрута). Раньше здесь возвращался символ «—» — оформление в данных,
    из-за чего его нельзя было отличить от реального значения.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if "src" in parts:
                idx = parts.index("src")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""
