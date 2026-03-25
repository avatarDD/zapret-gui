# core/system_info.py
"""
Сбор информации о системе роутера.

Версия ядра, архитектура, RAM, uptime, IP-адреса.
"""

import os
import platform
import subprocess


def get_system_info() -> dict:
    """Собрать основную информацию о системе."""
    info = {
        "hostname": _read_file("/etc/hostname", platform.node()),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": _get_platform(),
        "uptime": _get_uptime(),
        "uptime_human": _format_uptime(_get_uptime()),
        "ram": _get_ram_info(),
        "load_avg": _get_load_average(),
        "wan_ip": _get_wan_ip(),
    }
    return info


def _read_file(path: str, default: str = "") -> str:
    """Прочитать файл, вернуть default при ошибке."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (IOError, OSError):
        return default


def _get_platform() -> str:
    """Определить платформу (Keenetic, OpenWrt, generic Linux)."""
    if os.path.exists("/tmp/ndnproxy_acl"):
        return "Keenetic (NDMS)"
    if os.path.exists("/etc/openwrt_release"):
        return "OpenWrt"
    if os.path.exists("/opt/etc/entware_release"):
        release = _read_file("/opt/etc/entware_release")
        return f"Entware ({release.split(chr(10))[0]})" if release else "Entware"
    return "Linux"


def _get_uptime() -> int:
    """Получить uptime в секундах."""
    try:
        data = _read_file("/proc/uptime")
        return int(float(data.split()[0]))
    except (ValueError, IndexError):
        return 0


def _format_uptime(seconds: int) -> str:
    """Форматировать uptime в человекочитаемый вид."""
    if seconds <= 0:
        return "—"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    parts = []
    if days > 0:
        parts.append(f"{days}д")
    if hours > 0:
        parts.append(f"{hours}ч")
    parts.append(f"{minutes}м")
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
    """Попробовать определить WAN IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for part in result.stdout.split():
                if part == "src":
                    idx = result.stdout.split().index("src")
                    return result.stdout.split()[idx + 1]
    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError):
        pass
    return "—"


