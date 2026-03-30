import os
import platform
import subprocess
def get_system_info() -> dict:
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
    if os.path.exists("/tmp/ndnproxy_acl"):
        return "Keenetic (NDMS)"
    if os.path.exists("/etc/openwrt_release"):
        return "OpenWrt"
    if os.path.exists("/opt/etc/entware_release"):
        release = _read_file("/opt/etc/entware_release")
        return f"Entware ({release.split(chr(10))[0]})" if release else "Entware"
    return "Linux"
def _get_uptime() -> int:
    try:
        data = _read_file("/proc/uptime")
        return int(float(data.split()[0]))
    except (ValueError, IndexError):
        return 0
def _format_uptime(seconds: int) -> str:
    if seconds <= 0:
        return "—"
    months = seconds // (30 * 86400)
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
    if secs > 0 and (not parts or hours == 0):
        parts.append("%dс" % secs)
    if not parts:
        parts.append("0с")
    return " ".join(parts)
def _get_ram_info() -> dict:
    info = {"total_mb": 0, "free_mb": 0, "available_mb": 0, "used_percent": 0}
    try:
        meminfo = _read_file("/proc/meminfo")
        data = {}
        for line in meminfo.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
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
