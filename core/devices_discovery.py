# core/devices_discovery.py
"""
Обнаружение устройств в локальной сети для per-device routing.

Источники данных (в порядке приоритета):
  1. DHCP-leases dnsmasq:
       /tmp/dhcp.leases           — Keenetic / OpenWrt / Entware
       /var/lib/misc/dnsmasq.leases
       /tmp/dnsmasq.leases
       /opt/var/lib/misc/dnsmasq.leases
  2. ARP-таблица: /proc/net/arp как fallback / дополнение

Возвращает дедуплицированный список устройств:
    {
        "ip":         "192.168.1.42",
        "mac":        "aa:bb:cc:dd:ee:ff",   # lowercase
        "hostname":   "Galaxy-S21",
        "source":     "leases" | "arp" | "leases+arp",
        "expires_at": 1731234567 | 0,        # 0 если бессрочный/из ARP
        "iface":      "br0" | ""             # только из ARP, опционально
    }

Никаких внешних команд, кроме чтения /proc и текстовых файлов —
функция должна быть быстрой и устойчивой на любой платформе.
"""

import os
import re


# Кандидатные пути для dnsmasq leases.
_LEASE_PATHS = (
    "/tmp/dhcp.leases",
    "/var/lib/misc/dnsmasq.leases",
    "/tmp/dnsmasq.leases",
    "/opt/var/lib/misc/dnsmasq.leases",
    "/var/dhcp.leases",
)

# IPv4 в /proc/net/arp.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_RE  = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


# ───────────────────────── helpers ──────────────────────────────────

def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    m = mac.strip().lower()
    if not _MAC_RE.match(m):
        return ""
    return m


def _is_valid_ip(ip: str) -> bool:
    if not ip or not _IPV4_RE.match(ip):
        return False
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False


def _read_file(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except (OSError, IOError):
        return ""


# ───────────────────────── DHCP leases ──────────────────────────────

def _parse_lease_line(line: str) -> dict:
    """
    Формат dnsmasq lease:
        <expiry> <mac> <ip> <hostname|*> <client_id|*>

    На некоторых платформах могут быть лишние поля — берём первые 4.
    """
    parts = line.split()
    if len(parts) < 4:
        return {}
    try:
        expires_at = int(parts[0])
    except ValueError:
        expires_at = 0
    mac = _normalize_mac(parts[1])
    ip  = parts[2].strip()
    hostname = parts[3].strip()
    if hostname == "*":
        hostname = ""
    if not mac or not _is_valid_ip(ip):
        return {}
    return {
        "ip":         ip,
        "mac":        mac,
        "hostname":   hostname,
        "source":     "leases",
        "expires_at": expires_at,
        "iface":      "",
    }


def _read_leases() -> list:
    out = []
    seen_ips = set()
    for path in _LEASE_PATHS:
        if not os.path.exists(path):
            continue
        text = _read_file(path)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            d = _parse_lease_line(line)
            if not d:
                continue
            if d["ip"] in seen_ips:
                continue
            seen_ips.add(d["ip"])
            out.append(d)
    return out


# ───────────────────────── ARP ──────────────────────────────────────

def _read_arp() -> list:
    """
    /proc/net/arp:
        IP address       HW type     Flags       HW address            Mask     Device
        192.168.1.42     0x1         0x2         aa:bb:cc:dd:ee:ff     *        br0
    """
    out = []
    text = _read_file("/proc/net/arp")
    if not text:
        return out
    lines = text.splitlines()
    if len(lines) <= 1:
        return out
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip    = parts[0].strip()
        flags = parts[2].strip()
        mac   = _normalize_mac(parts[3])
        iface = parts[5].strip()
        # Флаги 0x0 = incomplete, пропускаем.
        if flags == "0x0":
            continue
        # MAC из нулей — невалидная запись.
        if not mac or mac == "00:00:00:00:00:00":
            continue
        if not _is_valid_ip(ip):
            continue
        out.append({
            "ip":         ip,
            "mac":        mac,
            "hostname":   "",
            "source":     "arp",
            "expires_at": 0,
            "iface":      iface,
        })
    return out


# ───────────────────────── public API ───────────────────────────────

def list_devices() -> list:
    """
    Вернуть список всех видимых устройств LAN, сгруппированных по IP.
    Записи из leases приоритетнее (hostname, expiry); из ARP добавляем
    те, которых нет в leases.
    """
    leases = _read_leases()
    arp    = _read_arp()

    by_ip = {}
    for d in leases:
        by_ip[d["ip"]] = dict(d)

    for d in arp:
        if d["ip"] in by_ip:
            cur = by_ip[d["ip"]]
            # Дополним iface, если из leases он был пуст.
            if not cur.get("iface"):
                cur["iface"] = d.get("iface", "")
            # Запомним, что устройство в данный момент онлайн (ARP видел).
            cur["source"] = "leases+arp"
            # MAC из leases считаем авторитетнее, но если был пуст —
            # подменим из ARP.
            if not cur.get("mac"):
                cur["mac"] = d["mac"]
        else:
            by_ip[d["ip"]] = dict(d)

    out = list(by_ip.values())
    # Стабильная сортировка по IPv4 (числовая).
    def _ip_key(rec):
        try:
            return tuple(int(p) for p in rec["ip"].split("."))
        except ValueError:
            return (999, 999, 999, 999)
    out.sort(key=_ip_key)
    return out


def get_device_by_ip(ip: str) -> dict:
    """Найти одно устройство по IP. Вернёт {} если нет."""
    if not _is_valid_ip(ip):
        return {}
    for d in list_devices():
        if d["ip"] == ip:
            return d
    return {}


def sources_status() -> dict:
    """Диагностика доступности источников (для UI)."""
    leases_paths = [p for p in _LEASE_PATHS if os.path.exists(p)]
    arp_ok = os.path.exists("/proc/net/arp")
    return {
        "leases_paths": leases_paths,
        "arp_available": arp_ok,
    }
