# core/devices_discovery.py
"""
Обнаружение устройств в локальной сети для per-device routing.

Источники данных (в порядке приоритета):
  1. Keenetic NDM: `ndmc -c "show ip hotspot"` / `ndmq -p ...` — даёт
     самые полные имена хостов (name из веб-админки, hostname от клиента)
  2. DHCP-leases dnsmasq:
       /tmp/dhcp.leases           — Keenetic / OpenWrt / Entware
       /var/lib/misc/dnsmasq.leases
       /tmp/dnsmasq.leases
       /opt/var/lib/misc/dnsmasq.leases
  3. ARP-таблица: /proc/net/arp как fallback / дополнение

Возвращает дедуплицированный список устройств:
    {
        "ip":         "192.168.1.42",
        "mac":        "aa:bb:cc:dd:ee:ff",   # lowercase
        "hostname":   "Galaxy-S21",
        "source":     "leases" | "arp" | "ndm" | комбинации через '+',
        "expires_at": 1731234567 | 0,        # 0 если бессрочный/из ARP
        "iface":      "br0" | ""             # только из ARP, опционально
    }

ndmc/ndmq вызываются только если бинарники найдены — на не-Keenetic
системах функция работает как раньше (быстрая, без внешних команд).
"""

import json
import os
import re
import subprocess
import time


def _run(args, timeout=5):
    """Тонкая обёртка subprocess.run — глушит FileNotFoundError и т.п."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


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


# ───────────────────────── Keenetic NDM ─────────────────────────────

def _cmd_out(args, timeout=4):
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


def _parse_ndm_hosts_json(text: str) -> list:
    """
    Парсер JSON-вывода `ndmq -p "show ip hotspot"`.

    Ожидается структура { "host": [ {mac, ip, name, hostname, ...}, ... ] }
    или сразу массив, или одиночный объект под ключом "host".
    Toleranт к шумным заголовкам ndmq.
    """
    text = text.strip()
    if not text:
        return []
    # Иногда ndmq добавляет шапку до JSON
    start = text.find("{")
    if start < 0:
        start = text.find("[")
    if start < 0:
        return []
    try:
        data = json.loads(text[start:])
    except (ValueError, TypeError):
        return []

    if isinstance(data, dict):
        hosts = data.get("host")
        if hosts is None:
            return []
        if isinstance(hosts, dict):
            hosts = [hosts]
    elif isinstance(data, list):
        hosts = data
    else:
        return []

    out = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        mac = _normalize_mac(h.get("mac") or "")
        ip  = (h.get("ip") or "").strip()
        if not mac and not _is_valid_ip(ip):
            continue
        # Предпочитаем "name" (заданное в админке), затем "hostname".
        name = (h.get("name") or h.get("hostname") or "").strip()
        out.append({
            "ip":         ip if _is_valid_ip(ip) else "",
            "mac":        mac,
            "hostname":   name,
            "source":     "ndm",
            "expires_at": 0,
            "iface":      "",
        })
    return out


def _parse_ndm_hosts_yaml(text: str) -> list:
    """
    Парсер текстового YAML-подобного вывода `ndmc -c "show ip hotspot"`.

    Записи разделены строками вида `host:` или `host, name = ...`.
    Внутри блока ищем `mac:`, `ip:`, `name:`, `hostname:` независимо
    от отступов — поскольку ndmc форматирует столбцом разной ширины.
    """
    if not text:
        return []
    out = []
    cur = None

    def _flush():
        if not cur:
            return
        mac = _normalize_mac(cur.get("mac", ""))
        ip  = (cur.get("ip") or "").strip()
        if not mac and not _is_valid_ip(ip):
            return
        name = (cur.get("name") or cur.get("hostname") or "").strip()
        out.append({
            "ip":         ip if _is_valid_ip(ip) else "",
            "mac":        mac,
            "hostname":   name,
            "source":     "ndm",
            "expires_at": 0,
            "iface":      "",
        })

    key_re = re.compile(r"^\s*([A-Za-z][\w\-]*)\s*:\s*(.*?)\s*$")
    host_marker_re = re.compile(r"^\s*host\s*(?::|,)", re.IGNORECASE)

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if host_marker_re.match(line):
            _flush()
            cur = {}
            # Иногда поля идут на той же строке: "host, name = \"X\", mac = ..."
            inline = re.findall(r"(\w+)\s*=\s*\"?([^,\"]+)\"?", line)
            for k, v in inline:
                cur[k.lower()] = v.strip()
            continue
        if cur is None:
            continue
        m = key_re.match(line)
        if not m:
            continue
        k = m.group(1).lower()
        v = m.group(2).strip()
        # Поля могут встретиться несколько раз — берём первое непустое.
        if k in ("mac", "ip", "name", "hostname") and v and k not in cur:
            cur[k] = v
    _flush()
    return out


def _read_ndm_hosts() -> list:
    """
    Лучшие усилия по чтению списка хостов через NDM.
    Возвращает [] на не-Keenetic системах (когда ndmc/ndmq нет).
    """
    # Сначала пробуем JSON (легче и однозначнее парсится).
    for cmd in (
        ["ndmq", "-p", "show ip hotspot"],
        ["ndmq", "-p", "show ip dhcp bindings"],
    ):
        out = _cmd_out(cmd)
        hosts = _parse_ndm_hosts_json(out) if out else []
        if hosts:
            return hosts

    # Затем YAML-подобный вывод ndmc.
    for cmd in (
        ["ndmc", "-c", "show ip hotspot"],
        ["ndmc", "-c", "show ip dhcp bindings"],
    ):
        out = _cmd_out(cmd)
        hosts = _parse_ndm_hosts_yaml(out) if out else []
        if hosts:
            return hosts
    return []


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

    Приоритет hostname: NDM (Keenetic) → DHCP-leases → ARP.
    NDM-данные мерджатся как по IP, так и по MAC, поскольку в JSON-выводе
    ndmq IP может быть пустым (хост зарегистрирован, но не в сети сейчас).
    """
    ndm    = _read_ndm_hosts()
    leases = _read_leases()
    arp    = _read_arp()

    by_ip = {}
    # 1) leases — основа: IP + hostname + expiry.
    for d in leases:
        by_ip[d["ip"]] = dict(d)

    # 2) ARP — добавляет онлайн-статус и недостающие IP.
    for d in arp:
        if d["ip"] in by_ip:
            cur = by_ip[d["ip"]]
            if not cur.get("iface"):
                cur["iface"] = d.get("iface", "")
            cur["source"] = "leases+arp"
            if not cur.get("mac"):
                cur["mac"] = d["mac"]
        else:
            by_ip[d["ip"]] = dict(d)

    # 3) NDM — обогащаем hostname. Сверка идёт по IP, при пустом IP —
    #    по MAC (бывает у Keenetic для статических резерваций).
    by_mac = {rec.get("mac"): rec for rec in by_ip.values() if rec.get("mac")}
    for d in ndm:
        target = None
        if d["ip"] and d["ip"] in by_ip:
            target = by_ip[d["ip"]]
        elif d["mac"] and d["mac"] in by_mac:
            target = by_mac[d["mac"]]
        if target is not None:
            # NDM считаем авторитетным источником имени.
            if d["hostname"]:
                target["hostname"] = d["hostname"]
            cur_src = target.get("source", "")
            if "ndm" not in cur_src:
                target["source"] = (cur_src + "+ndm").lstrip("+")
        else:
            # Новый хост, не виден ни в leases, ни в ARP. Добавим, если
            # у него есть IP — иначе строка без IP мало полезна для UI.
            if d["ip"]:
                by_ip[d["ip"]] = dict(d)
                if d["mac"]:
                    by_mac[d["mac"]] = by_ip[d["ip"]]

    # 4) Реверс-DNS / mDNS — заполняет hostname, если он всё ещё пуст.
    #    На Debian-клиенте (без своего DHCP-сервера) leases и NDM —
    #    пустые, и без этого шага колонка «Имя» в UI всегда оставалась
    #    бы пустой. avahi-resolve запрашивается только если он есть в
    #    PATH; socket.gethostbyaddr — фолбэк через стандартный резолвер
    #    (PTR-запись или /etc/hosts).
    for rec in by_ip.values():
        if rec.get("hostname"):
            continue
        name = _reverse_lookup(rec.get("ip", ""))
        if name:
            rec["hostname"] = name
            cur_src = rec.get("source", "")
            if "rdns" not in cur_src:
                rec["source"] = (cur_src + "+rdns").lstrip("+")

    out = list(by_ip.values())
    # Стабильная сортировка по IPv4 (числовая).
    def _ip_key(rec):
        try:
            return tuple(int(p) for p in rec["ip"].split("."))
        except ValueError:
            return (999, 999, 999, 999)
    out.sort(key=_ip_key)
    return out


# Кэш реверс-DNS на ~30 секунд: list_devices() зовут часто, а PTR-запрос
# из тайм-ауте может встать в секунды. Ключ — IP, значение — (hostname, ts).
_RDNS_CACHE = {}
_RDNS_TTL   = 30.0


def _reverse_lookup(ip: str) -> str:
    """
    Попробовать узнать hostname для IP без админских прав и без сторонних
    зависимостей. Возвращает «короткое» имя (до первой точки), потому что
    UI ждёт что-то вроде «Galaxy-S21», а не FQDN с .local/.localdomain.
    Пустая строка = ничего не нашли.
    """
    if not ip:
        return ""
    now = time.time()
    cached = _RDNS_CACHE.get(ip)
    if cached and (now - cached[1]) < _RDNS_TTL:
        return cached[0]

    name = ""
    # 1) avahi-resolve — лучший вариант для домашнего LAN: ловим mDNS
    #    имена вроде "telefon.local". Стоит почти на всех Debian/Ubuntu.
    rc, out, _e = _run(["avahi-resolve", "-4", "-a", ip], timeout=2)
    if rc == 0 and out:
        # Формат: "<ip>\t<name>"
        parts = out.strip().split(None, 1)
        if len(parts) == 2 and parts[1]:
            name = parts[1].strip()

    # 2) Системный реверс-резолвер (/etc/hosts, PTR-запись).
    if not name:
        try:
            import socket as _s
            hostname, _aliases, _addrs = _s.gethostbyaddr(ip)
            if hostname:
                name = hostname
        except (OSError, _s.herror, _s.gaierror):
            pass

    # Подрезаем хвост .local / .localdomain / .lan — у пользователя в UI
    # должно остаться человекочитаемое имя устройства.
    if name:
        short = name.split(".", 1)[0]
        if short:
            name = short

    _RDNS_CACHE[ip] = (name, now)
    return name


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
    ndm_ok = bool(_read_ndm_hosts())
    return {
        "leases_paths": leases_paths,
        "arp_available": arp_ok,
        "ndm_available": ndm_ok,
    }
