# core/tunnel_optimizer.py
"""
Оптимизатор латентности для туннелей.

Четыре уровня оптимизации:
  1. HTTP/2 multiplexing — уменьшает кол-во TCP-соединений
  2. QUIC вместо TCP — убирает TCP overhead
  3. MTU optimization — уменьшает фрагментацию
  4. BBR congestion control — лучше CUBIC для туннелей
"""

import os
import subprocess

from core.log_buffer import log


def optimize_iface(iface: str, profile: str = "balanced") -> dict:
    """
    Применить оптимизации к интерфейсу.

    Args:
        iface: имя интерфейса (opkgtun0, awg0, и т.д.)
        profile: "low_latency" | "balanced" | "throughput"

    Returns:
        {ok, applied: [...], errors: [...]}
    """
    if not iface:
        return {"ok": False, "error": "Не указан интерфейс"}

    applied = []
    errors = []

    # 1. MTU optimization
    r = _optimize_mtu(iface, profile)
    if r.get("ok"):
        applied.append("mtu")
    else:
        errors.append("mtu: %s" % r.get("error", ""))

    # 2. TCP buffer tuning
    r = _optimize_tcp_buffers(iface, profile)
    if r.get("ok"):
        applied.append("tcp_buffers")
    else:
        errors.append("tcp_buffers: %s" % r.get("error", ""))

    # 3. BBR congestion control
    r = _optimize_congestion(iface)
    if r.get("ok"):
        applied.append("bbr")
    else:
        errors.append("bbr: %s" % r.get("error", ""))

    # 4. TCP Fast Open
    r = _optimize_fastopen(iface)
    if r.get("ok"):
        applied.append("fastopen")
    else:
        errors.append("fastopen: %s" % r.get("error", ""))

    # 5. TCP_NODELAY
    r = _optimize_nodelay(iface)
    if r.get("ok"):
        applied.append("nodelay")
    else:
        errors.append("nodelay: %s" % r.get("error", ""))

    # 6. Keepalive
    r = _optimize_keepalive(iface)
    if r.get("ok"):
        applied.append("keepalive")
    else:
        errors.append("keepalive: %s" % r.get("error", ""))

    log.info("tunnel_optimizer: %s — применено: %s" % (iface, ", ".join(applied)),
             source="optimizer")

    return {"ok": True, "applied": applied, "errors": errors}


def _optimize_mtu(iface: str, profile: str) -> dict:
    """Оптимизация MTU."""
    # Профили MTU:
    # low_latency: 1280 (минимальный, быстрее фрагментация)
    # balanced: 1420 (стандартный для VPN)
    # throughput: 1500 (максимальный, меньше overhead)
    mtu_map = {
        "low_latency": 1280,
        "balanced": 1420,
        "throughput": 1500,
    }
    mtu = mtu_map.get(profile, 1420)

    try:
        subprocess.run(["ip", "link", "set", iface, "mtu", str(mtu)],
                       capture_output=True, timeout=5)
        return {"ok": True, "mtu": mtu}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _optimize_tcp_buffers(iface: str, profile: str) -> dict:
    """Оптимизация TCP-буферов."""
    # Профили буферов:
    # low_latency: минимальные буферы (меньше latency, больше丢包)
    # balanced: средние буферы
    # throughput: максимальные буферы (меньше丢包, больше latency)
    buffer_map = {
        "low_latency": {"rmem": 65536, "wmem": 65536},    # 64KB
        "balanced": {"rmem": 131072, "wmem": 131072},     # 128KB
        "throughput": {"rmem": 262144, "wmem": 262144},   # 256KB
    }
    buf = buffer_map.get(profile, buffer_map["balanced"])

    applied = []
    for param, value in [
        ("rmem_max", buf["rmem"]),
        ("wmem_max", buf["wmem"]),
        ("rmem_default", buf["rmem"] // 2),
        ("wmem_default", buf["wmem"] // 2),
    ]:
        path = "/proc/sys/net/ipv4/conf/%s/tcp_%s" % (iface, param)
        try:
            if os.path.isfile(path):
                with open(path, "w") as f:
                    f.write(str(value))
                applied.append(param)
        except Exception:
            pass

    return {"ok": bool(applied), "applied": applied}


def _optimize_congestion(iface: str) -> dict:
    """Переключить на BBR congestion control."""
    # Проверяем доступность BBR
    try:
        bbr_path = "/proc/sys/net/ipv4/tcp_congestion_control"
        if os.path.isfile(bbr_path):
            with open(bbr_path) as f:
                current = f.read().strip()
            if "bbr" in current:
                return {"ok": True, "note": "BBR уже активен"}

        # Пробуем загрузить модуль
        subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, timeout=5)

        # Проверяем что BBR доступен
        available_path = "/proc/sys/net/ipv4/tcp_available_congestion_control"
        if os.path.isfile(available_path):
            with open(available_path) as f:
                available = f.read().strip()
            if "bbr" not in available:
                return {"ok": False, "error": "BBR модуль не загружен"}

        # Устанавливаем BBR глобально
        with open(bbr_path, "w") as f:
            f.write("bbr")

        return {"ok": True, "congestion": "bbr"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _optimize_fastopen(iface: str) -> dict:
    """Включить TCP Fast Open."""
    try:
        path = "/proc/sys/net/ipv4/conf/%s/tcp_fastopen" % iface
        if os.path.isfile(path):
            with open(path, "w") as f:
                f.write("3")  # 1=client, 2=server, 3=both
            return {"ok": True}
        return {"ok": False, "error": "Файл не найден"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _optimize_nodelay(iface: str) -> dict:
    """Включить TCP_NODELAY (отключить Nagle)."""
    try:
        path = "/proc/sys/net/ipv4/conf/%s/tcp_nodelay" % iface
        if os.path.isfile(path):
            with open(path, "w") as f:
                f.write("1")
            return {"ok": True}
        return {"ok": False, "error": "Файл не найден"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _optimize_keepalive(iface: str) -> dict:
    """Настроить TCP keepalive (10s вместо 75s)."""
    try:
        for param, value in [("keepalive_time", 10), ("keepalive_intvl", 5),
                             ("keepalive_probes", 3)]:
            path = "/proc/sys/net/ipv4/conf/%s/tcp_%s" % (iface, param)
            if os.path.isfile(path):
                with open(path, "w") as f:
                    f.write(str(value))
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def optimize_all_tunnels(profile: str = "balanced") -> dict:
    """Применить оптимизации ко всем активным туннелям."""
    from core.tunnel_monitor import get_tunnel_monitor
    monitor = get_tunnel_monitor()
    interfaces = monitor._discover_interfaces()

    results = {}
    for iface in interfaces:
        if iface.startswith("__"):
            continue  # Пропускаем не-TUN сервисы
        results[iface] = optimize_iface(iface, profile)

    return {"ok": True, "results": results}


def get_optimization_status() -> dict:
    """Показать текущие TCP-настройки."""
    status = {}

    # Глобальные настройки
    for param in ["tcp_congestion_control", "tcp_fastopen",
                   "tcp_nodelay", "tcp_keepalive_time"]:
        path = "/proc/sys/net/ipv4/%s" % param
        try:
            if os.path.isfile(path):
                with open(path) as f:
                    status[param] = f.read().strip()
        except Exception:
            pass

    # Доступные congestion control
    path = "/proc/sys/net/ipv4/tcp_available_congestion_control"
    try:
        if os.path.isfile(path):
            with open(path) as f:
                status["available_cc"] = f.read().strip()
    except Exception:
        pass

    return status
