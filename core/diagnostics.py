# core/diagnostics.py
"""
Модуль диагностики сети и системы.

Проверка доступности сервисов, DNS, firewall, конфликтов.
Все проверки через subprocess с таймаутами.
Кэширование результатов на 30 секунд.

Использование:
    from core.diagnostics import (
        ping_host, check_http, check_dns,
        check_service, check_all_services,
        check_nfqws_conflicts, get_firewall_status,
        get_system_diagnostics, get_available_services,
    )
"""

import os
import re
import shutil
import socket
import subprocess
import threading
import time

from core.log_buffer import log


# ─────────────────────── Предустановленные сервисы ───────────────────────

SERVICES = {
    "youtube": {
        "name": "YouTube",
        "icon": "▶",
        "hosts": ["youtube.com", "www.youtube.com", "i.ytimg.com"],
        "urls": ["https://www.youtube.com"],
    },
    "discord": {
        "name": "Discord",
        "icon": "💬",
        "hosts": ["discord.com", "cdn.discordapp.com", "gateway.discord.gg"],
        "urls": ["https://discord.com"],
    },
    "telegram": {
        "name": "Telegram",
        "icon": "✈",
        "hosts": ["t.me", "web.telegram.org", "core.telegram.org"],
        "urls": ["https://t.me"],
    },
    "instagram": {
        "name": "Instagram",
        "icon": "📷",
        "hosts": ["instagram.com", "i.instagram.com"],
        "urls": ["https://www.instagram.com"],
    },
    "twitter": {
        "name": "X / Twitter",
        "icon": "𝕏",
        "hosts": ["x.com", "twitter.com"],
        "urls": ["https://x.com"],
    },
    "chatgpt": {
        "name": "ChatGPT",
        "icon": "🤖",
        "hosts": ["chatgpt.com", "chat.openai.com"],
        "urls": ["https://chatgpt.com"],
    },
    "claude": {
        "name": "Claude",
        "icon": "🧠",
        "hosts": ["claude.ai"],
        "urls": ["https://claude.ai"],
    },
}


# ─────────────────────── Кэш результатов ───────────────────────

_cache = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 30  # секунд


def _cache_get(key):
    """Получить из кэша, если не протух."""
    with _cache_lock:
        entry = _cache.get(key)
        if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
            return entry["data"]
    return None


def _cache_set(key, data):
    """Положить в кэш."""
    with _cache_lock:
        _cache[key] = {"data": data, "ts": time.time()}


# ─────────────────────── Утилиты subprocess ───────────────────────

def _run(cmd, timeout=10):
    """
    Запустить subprocess с таймаутом.

    Returns:
        (returncode, stdout, stderr) или (None, '', error_message) при ошибке.
    """
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except FileNotFoundError:
        return None, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return None, "", str(e)


def _find_binary(names):
    """Найти первый доступный бинарник из списка имён."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


# ─────────────────────── Ping ───────────────────────

def ping_host(host, count=3, timeout=3):
    """
    Ping хоста через subprocess.

    Returns:
        dict: { host, alive, rtt_min, rtt_avg, rtt_max, packet_loss, raw_output }
    """
    cache_key = f"ping:{host}:{count}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        "host": host,
        "alive": False,
        "rtt_min": None,
        "rtt_avg": None,
        "rtt_max": None,
        "packet_loss": 100,
        "raw_output": "",
    }

    ping_bin = _find_binary(["ping"])
    if not ping_bin:
        result["raw_output"] = "ping не найден"
        return result

    cmd = [ping_bin, "-c", str(count), "-W", str(timeout), host]
    rc, stdout, stderr = _run(cmd, timeout=count * timeout + 5)

    result["raw_output"] = stdout or stderr or ""

    if rc == 0:
        result["alive"] = True

    # Парсим packet loss
    loss_match = re.search(r"(\d+)% packet loss", stdout or "")
    if loss_match:
        result["packet_loss"] = int(loss_match.group(1))
        if result["packet_loss"] < 100:
            result["alive"] = True

    # Парсим RTT: rtt min/avg/max/mdev = 1.234/5.678/9.012/1.234 ms
    # или: round-trip min/avg/max = 1.234/5.678/9.012 ms
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/\w+)?\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)",
        stdout or ""
    )
    if rtt_match:
        result["rtt_min"] = float(rtt_match.group(1))
        result["rtt_avg"] = float(rtt_match.group(2))
        result["rtt_max"] = float(rtt_match.group(3))

    _cache_set(cache_key, result)
    return result


# ─────────────────────── HTTP Check ───────────────────────

def check_http(url, timeout=5):
    """
    HTTP(S) проверка через curl → wget → urllib fallback.

    Returns:
        dict: { url, status_code, ok, response_time, error, tls_version, redirect_url }
    """
    cache_key = f"http:{url}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        "url": url,
        "status_code": 0,
        "ok": False,
        "response_time": None,
        "error": None,
        "tls_version": None,
        "redirect_url": None,
    }

    # Попытка 1: curl
    curl_bin = _find_binary(["curl"])
    if curl_bin:
        t0 = time.time()
        cmd = [
            curl_bin,
            "-sS",                      # silent но показать ошибки
            "-o", "/dev/null",           # не выводить тело
            "-w", "%{http_code}|%{ssl_version}|%{redirect_url}|%{time_total}",
            "-L",                        # следовать редиректам
            "--max-time", str(timeout),
            "--connect-timeout", str(timeout),
            "-k",                        # игнорировать SSL ошибки
            url,
        ]
        rc, stdout, stderr = _run(cmd, timeout=timeout + 5)

        if rc == 0 and stdout:
            parts = stdout.strip().split("|")
            if len(parts) >= 4:
                try:
                    result["status_code"] = int(parts[0])
                except ValueError:
                    pass
                result["tls_version"] = parts[1] if parts[1] else None
                result["redirect_url"] = parts[2] if parts[2] else None
                try:
                    result["response_time"] = round(float(parts[3]) * 1000)
                except ValueError:
                    result["response_time"] = round((time.time() - t0) * 1000)
                result["ok"] = 200 <= result["status_code"] < 400
                _cache_set(cache_key, result)
                return result
        elif stderr:
            result["error"] = stderr.strip()[:200]

    # Попытка 2: wget
    wget_bin = _find_binary(["wget"])
    if wget_bin and not result["ok"]:
        t0 = time.time()
        cmd = [
            wget_bin,
            "-q",                        # quiet
            "--spider",                  # не скачивать
            "--timeout", str(timeout),
            "--no-check-certificate",
            "-S",                        # показать заголовки
            url,
        ]
        rc, stdout, stderr = _run(cmd, timeout=timeout + 5)
        elapsed = round((time.time() - t0) * 1000)

        # wget пишет заголовки в stderr
        output = stderr or stdout or ""
        status_match = re.search(r"HTTP/\S+\s+(\d+)", output)
        if status_match:
            result["status_code"] = int(status_match.group(1))
            result["ok"] = 200 <= result["status_code"] < 400
            result["response_time"] = elapsed
            result["error"] = None
            _cache_set(cache_key, result)
            return result
        elif rc is not None and rc == 0:
            result["ok"] = True
            result["status_code"] = 200
            result["response_time"] = elapsed

    # Попытка 3: Python urllib (базовый fallback)
    if not result["ok"]:
        try:
            import urllib.request
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            t0 = time.time()
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "zapret-gui/0.7")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                result["status_code"] = resp.status
                result["ok"] = 200 <= resp.status < 400
                result["response_time"] = round((time.time() - t0) * 1000)
                result["error"] = None
        except Exception as e:
            result["error"] = str(e)[:200]
            result["response_time"] = round((time.time() - t0) * 1000) if 't0' in dir() else None

    _cache_set(cache_key, result)
    return result


# ─────────────────────── DNS Check ───────────────────────

def check_dns(domain, dns_server=None, timeout=3):
    """
    Проверка DNS-резолва.
    Пробуем: nslookup → dig → socket.getaddrinfo fallback.

    Returns:
        dict: { domain, resolved_ips, dns_server, ok, response_time, error }
    """
    cache_key = f"dns:{domain}:{dns_server or 'default'}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        "domain": domain,
        "resolved_ips": [],
        "dns_server": dns_server or "system",
        "ok": False,
        "response_time": None,
        "error": None,
    }

    # Попытка 1: nslookup
    nslookup_bin = _find_binary(["nslookup"])
    if nslookup_bin:
        cmd = [nslookup_bin, domain]
        if dns_server:
            cmd.append(dns_server)
        t0 = time.time()
        rc, stdout, stderr = _run(cmd, timeout=timeout + 2)
        result["response_time"] = round((time.time() - t0) * 1000)

        if rc == 0 and stdout:
            ips = _parse_nslookup(stdout, domain)
            if ips:
                result["resolved_ips"] = ips
                result["ok"] = True
                _cache_set(cache_key, result)
                return result

    # Попытка 2: dig
    dig_bin = _find_binary(["dig"])
    if dig_bin and not result["ok"]:
        cmd = [dig_bin, "+short", "+time=" + str(timeout), domain]
        if dns_server:
            cmd.insert(1, "@" + dns_server)
        t0 = time.time()
        rc, stdout, stderr = _run(cmd, timeout=timeout + 2)
        result["response_time"] = round((time.time() - t0) * 1000)

        if rc == 0 and stdout:
            ips = [
                line.strip() for line in stdout.strip().split("\n")
                if re.match(r"^[\d.:a-fA-F]+$", line.strip())
            ]
            if ips:
                result["resolved_ips"] = ips
                result["ok"] = True
                _cache_set(cache_key, result)
                return result

    # Попытка 3: Python socket (fallback, без выбора DNS-сервера)
    if not result["ok"]:
        try:
            t0 = time.time()
            addrs = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            result["response_time"] = round((time.time() - t0) * 1000)
            ips = list(set(addr[4][0] for addr in addrs))
            if ips:
                result["resolved_ips"] = ips[:10]
                result["ok"] = True
                if dns_server:
                    result["dns_server"] = "system (fallback)"
        except socket.gaierror as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)[:200]

    _cache_set(cache_key, result)
    return result


def _parse_nslookup(output, domain):
    """Извлечь IP-адреса из вывода nslookup."""
    ips = []
    # Пропускаем секцию сервера (до "Name:" или "Non-authoritative answer:")
    in_answer = False
    for line in output.split("\n"):
        line = line.strip()
        if "Non-authoritative answer" in line or ("Name:" in line and domain in line):
            in_answer = True
            continue
        if in_answer and line.startswith("Address:"):
            addr = line.split(":", 1)[1].strip()
            # Убираем порт (nslookup на некоторых системах: "Address: 1.2.3.4#53")
            addr = addr.split("#")[0].strip()
            if re.match(r"^[\d.:a-fA-F]+$", addr):
                ips.append(addr)
    return ips


# ─────────────────────── Проверка сервиса ───────────────────────

def check_service(service_name):
    """
    Комплексная проверка сервиса (ping + DNS + HTTP).

    Returns:
        dict: { name, display_name, status, ping, dns, http, checks }
    """
    svc = SERVICES.get(service_name)
    if not svc:
        return {"name": service_name, "error": "Неизвестный сервис"}

    cache_key = f"service:{service_name}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        "name": service_name,
        "display_name": svc["name"],
        "icon": svc.get("icon", ""),
        "status": "checking",
        "ping": None,
        "dns": [],
        "http": [],
        "summary": {
            "ping_ok": False,
            "dns_ok": False,
            "http_ok": False,
        },
    }

    # 1. Ping первого хоста
    if svc["hosts"]:
        ping_result = ping_host(svc["hosts"][0], count=2, timeout=3)
        result["ping"] = ping_result
        result["summary"]["ping_ok"] = ping_result["alive"]

    # 2. DNS для всех хостов
    for host in svc["hosts"]:
        dns_result = check_dns(host, timeout=3)
        result["dns"].append(dns_result)
    result["summary"]["dns_ok"] = any(d["ok"] for d in result["dns"])

    # 3. HTTP для всех URL
    for url in svc.get("urls", []):
        http_result = check_http(url, timeout=5)
        result["http"].append(http_result)
    result["summary"]["http_ok"] = any(h["ok"] for h in result["http"])

    # Общий статус
    if result["summary"]["http_ok"]:
        result["status"] = "ok"
    elif result["summary"]["dns_ok"] and result["summary"]["ping_ok"]:
        result["status"] = "partial"
    elif result["summary"]["ping_ok"]:
        result["status"] = "degraded"
    else:
        result["status"] = "down"

    _cache_set(cache_key, result)
    log.info(f"Диагностика {svc['name']}: {result['status']}", source="diagnostics")
    return result


def check_all_services():
    """
    Проверить все сервисы.

    Returns:
        dict: { services: {name: result, ...}, total, ok, down, partial, timestamp }
    """
    results = {}
    for name in SERVICES:
        results[name] = check_service(name)

    total = len(results)
    ok = sum(1 for r in results.values() if r.get("status") == "ok")
    down = sum(1 for r in results.values() if r.get("status") == "down")

    log.info(f"Полная диагностика: {ok}/{total} сервисов доступны", source="diagnostics")

    return {
        "services": results,
        "total": total,
        "ok": ok,
        "down": down,
        "partial": total - ok - down,
        "timestamp": time.time(),
    }


# ─────────────────────── Конфликты nfqws/tpws ───────────────────────

def check_nfqws_conflicts():
    """
    Проверка конфликтующих процессов nfqws/tpws.

    Returns:
        dict: { conflicts: [{pid, name, cmdline}...], has_conflicts }
    """
    cache_key = "conflicts"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    conflicts = []

    # Ищем процессы nfqws/tpws через /proc
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            pid = int(pid_dir)
            try:
                cmdline_path = f"/proc/{pid}/cmdline"
                with open(cmdline_path, "r") as f:
                    cmdline = f.read().replace("\x00", " ").strip()

                if not cmdline:
                    continue

                # Проверяем имя процесса
                exe_name = os.path.basename(cmdline.split()[0]) if cmdline.split() else ""

                if exe_name in ("nfqws", "nfqws2", "tpws", "tpws2"):
                    # Проверяем — не наш ли это процесс (от нашего GUI)
                    from core.nfqws_manager import get_nfqws_manager
                    mgr = get_nfqws_manager()
                    our_pid = mgr.get_status().get("pid")

                    if pid != our_pid:
                        conflicts.append({
                            "pid": pid,
                            "name": exe_name,
                            "cmdline": cmdline[:500],
                        })
            except (IOError, OSError, PermissionError):
                continue
    except (IOError, OSError):
        pass

    # Альтернатива: через ps (если /proc недоступен для полного обхода)
    if not conflicts:
        ps_bin = _find_binary(["ps"])
        if ps_bin:
            rc, stdout, _ = _run([ps_bin, "w"], timeout=5)
            if rc == 0 and stdout:
                from core.nfqws_manager import get_nfqws_manager
                mgr = get_nfqws_manager()
                our_pid = mgr.get_status().get("pid")

                for line in stdout.strip().split("\n")[1:]:
                    parts = line.split(None, 4)
                    if len(parts) < 5:
                        continue
                    try:
                        pid = int(parts[0])
                    except ValueError:
                        continue
                    cmdline = parts[4] if len(parts) > 4 else ""
                    exe_name = os.path.basename(cmdline.split()[0]) if cmdline.split() else ""

                    if exe_name in ("nfqws", "nfqws2", "tpws", "tpws2") and pid != our_pid:
                        conflicts.append({
                            "pid": pid,
                            "name": exe_name,
                            "cmdline": cmdline[:500],
                        })

    result = {
        "conflicts": conflicts,
        "has_conflicts": len(conflicts) > 0,
    }

    _cache_set(cache_key, result)
    return result


# ─────────────────────── Статус Firewall ───────────────────────

def get_firewall_status():
    """
    Подробный статус firewall (iptables/nft rules, NFQUEUE).

    Returns:
        dict: { type, rules, nfqueue_available, nfqueue_count, raw_output }
    """
    cache_key = "firewall_status"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result = {
        "type": None,
        "rules": [],
        "nfqueue_available": False,
        "nfqueue_count": 0,
        "raw_output": "",
    }

    # Определяем тип firewall
    from core.firewall import get_firewall_manager
    fw = get_firewall_manager()
    fw_type = fw.detect_fw_type()
    result["type"] = fw_type

    # Получаем правила
    if fw_type == "iptables":
        result.update(_get_iptables_status())
    elif fw_type == "nftables":
        result.update(_get_nftables_status())

    # Проверяем NFQUEUE
    result["nfqueue_available"] = _check_nfqueue_available()

    _cache_set(cache_key, result)
    return result


def _get_iptables_status():
    """Получить правила iptables с пометкой zapret."""
    info = {"rules": [], "raw_output": ""}

    ipt_bin = _find_binary(["iptables"])
    if not ipt_bin:
        return info

    # Получаем все правила в mangle и nat таблицах
    for table in ("mangle", "nat", "filter"):
        rc, stdout, _ = _run([ipt_bin, "-t", table, "-L", "-n", "-v", "--line-numbers"], timeout=5)
        if rc == 0 and stdout:
            info["raw_output"] += f"\n=== {table} ===\n{stdout}"

            # Ищем правила с пометкой zapret
            for line in stdout.split("\n"):
                if "zapret" in line.lower() or "NFQUEUE" in line:
                    info["rules"].append({
                        "table": table,
                        "rule": line.strip(),
                        "type": "nfqueue" if "NFQUEUE" in line else "other",
                    })

    return info


def _get_nftables_status():
    """Получить правила nftables с пометкой zapret."""
    info = {"rules": [], "raw_output": ""}

    nft_bin = _find_binary(["nft"])
    if not nft_bin:
        return info

    rc, stdout, _ = _run([nft_bin, "list", "ruleset"], timeout=5)
    if rc == 0 and stdout:
        info["raw_output"] = stdout

        # Ищем правила zapret
        current_table = ""
        current_chain = ""
        for line in stdout.split("\n"):
            stripped = line.strip()
            if stripped.startswith("table"):
                current_table = stripped
            elif stripped.startswith("chain"):
                current_chain = stripped.split("{")[0].strip() if "{" in stripped else stripped
            elif "queue" in stripped.lower() or "zapret" in stripped.lower():
                info["rules"].append({
                    "table": current_table,
                    "chain": current_chain,
                    "rule": stripped,
                    "type": "nfqueue" if "queue" in stripped.lower() else "other",
                })

    return info


def _check_nfqueue_available():
    """Проверить, доступен ли модуль NFQUEUE."""
    # Способ 1: /proc/net/netfilter/nfnetlink_queue
    if os.path.exists("/proc/net/netfilter/nfnetlink_queue"):
        return True

    # Способ 2: модуль загружен
    try:
        modules = ""
        with open("/proc/modules", "r") as f:
            modules = f.read()
        if "nfnetlink_queue" in modules or "xt_NFQUEUE" in modules:
            return True
    except (IOError, OSError):
        pass

    # Способ 3: пробуем modprobe
    modprobe_bin = _find_binary(["modprobe"])
    if modprobe_bin:
        rc, _, _ = _run([modprobe_bin, "-n", "xt_NFQUEUE"], timeout=3)
        if rc == 0:
            return True

    return False


# ─────────────────────── Системная диагностика ───────────────────────

def get_system_diagnostics():
    """
    Расширенная системная информация для диагностики.
    Дополняет core/system_info.py.

    Returns:
        dict с system_info + dns_servers, default_gateway, interfaces,
              nfqws_binary_exists, nfqws_version
    """
    cache_key = "system_diagnostics"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    from core.system_info import get_system_info
    from core.config_manager import get_config_manager

    info = get_system_info()
    cfg = get_config_manager()

    # DNS-серверы из resolv.conf
    info["dns_servers"] = _get_dns_servers()

    # Default gateway
    info["default_gateway"] = _get_default_gateway()

    # Сетевые интерфейсы
    info["network_interfaces"] = _get_network_interfaces()

    # Проверка бинарника nfqws2
    nfqws_binary = cfg.get("zapret", "nfqws_binary", default="/opt/zapret2/nfq2/nfqws2")
    info["nfqws_binary_path"] = nfqws_binary
    info["nfqws_binary_exists"] = os.path.isfile(nfqws_binary)

    # Версия nfqws2
    info["nfqws_version"] = _get_nfqws_version(nfqws_binary)

    # Entware
    info["entware_installed"] = os.path.exists("/opt/bin/opkg")

    # Python
    import sys
    info["python_version"] = sys.version.split()[0]

    _cache_set(cache_key, info)
    return info


def _get_dns_servers():
    """Прочитать DNS-серверы из /etc/resolv.conf."""
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except (IOError, OSError):
        pass
    return servers


def _get_default_gateway():
    """Определить default gateway."""
    try:
        rc, stdout, _ = _run(["ip", "route", "show", "default"], timeout=3)
        if rc == 0 and stdout:
            # "default via 192.168.1.1 dev eth0"
            match = re.search(r"via\s+([\d.]+)", stdout)
            if match:
                return match.group(1)
    except Exception:
        pass

    # Fallback: /proc/net/route
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split("\t")
                if len(parts) >= 3 and parts[1] == "00000000":
                    # Gateway в hex, little-endian
                    gw_hex = parts[2]
                    gw_bytes = bytes.fromhex(gw_hex)
                    gw = f"{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}"
                    return gw
    except (IOError, OSError, ValueError):
        pass

    return None


def _get_network_interfaces():
    """Получить список сетевых интерфейсов с IP-адресами."""
    interfaces = []
    try:
        rc, stdout, _ = _run(["ip", "-o", "addr", "show"], timeout=3)
        if rc == 0 and stdout:
            seen = set()
            for line in stdout.strip().split("\n"):
                # "2: eth0    inet 192.168.1.1/24 brd ..."
                match = re.match(
                    r"\d+:\s+(\S+)\s+(inet6?)\s+([\da-fA-F.:]+)/(\d+)",
                    line.strip()
                )
                if match:
                    iface = match.group(1)
                    family = match.group(2)
                    addr = match.group(3)
                    prefix = match.group(4)

                    if iface == "lo":
                        continue

                    key = f"{iface}:{addr}"
                    if key not in seen:
                        seen.add(key)
                        interfaces.append({
                            "name": iface,
                            "family": "ipv4" if family == "inet" else "ipv6",
                            "address": addr,
                            "prefix": int(prefix),
                        })
    except Exception:
        pass

    return interfaces


def _get_nfqws_version(binary_path):
    """Попробовать получить версию nfqws2."""
    if not os.path.isfile(binary_path):
        return None

    # nfqws2 обычно выводит версию при --help или при ошибке
    rc, stdout, stderr = _run([binary_path, "--help"], timeout=3)
    output = (stdout or "") + (stderr or "")

    # Ищем версию в выводе
    ver_match = re.search(r"(?:version|v)\s*([\d.]+)", output, re.IGNORECASE)
    if ver_match:
        return ver_match.group(1)

    # Если --help не даёт версию, пробуем --version
    rc, stdout, stderr = _run([binary_path, "--version"], timeout=3)
    output = (stdout or "") + (stderr or "")
    ver_match = re.search(r"(?:version|v)\s*([\d.]+)", output, re.IGNORECASE)
    if ver_match:
        return ver_match.group(1)

    return "unknown"


# ─────────────────────── Публичные утилиты ───────────────────────

def get_available_services():
    """Список доступных сервисов для проверки."""
    return {
        name: {
            "name": svc["name"],
            "icon": svc.get("icon", ""),
            "hosts": svc["hosts"],
            "urls": svc.get("urls", []),
        }
        for name, svc in SERVICES.items()
    }


def clear_cache():
    """Очистить кэш диагностики."""
    with _cache_lock:
        _cache.clear()

