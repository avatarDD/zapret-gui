# core/block_detector.py
"""
Block Detector: DNS-мониторинг + автообнаружение блокировок.

Мониторит DNS-запросы клиентов, пронирует новые домены,
автодобавляет заблокированные в named lists.

Реализация по мотивам z2k-detect:
  - DNS source: AF_PACKET / dnsmasq log / adguard log
  - 4-stage probing: DNS → TCP:443 → TLS → HTTP read 32KB
  - Block classification: dns_block, tcp_refused, tls_rst, http_cutoff, etc.
  - Auto-add to named list (опционально)
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
import threading
import time
from collections import deque
from typing import Any

from core.log_buffer import log


# Коды блокировок (по мотивам z2k-detect)
BLOCK_CODES = {
    "ok": "Доступен",
    "dns_block": "DNS-блокировка",
    "dns_hijack": "DNS-хайджак",
    "tcp_refused": "TCP отклонён",
    "tcp_timeout": "TCP таймаут",
    "tls_rst": "TLS RST",
    "tls_garbage": "TLS мусор",
    "tls_timeout": "TLS таймаут",
    "http_cutoff": "HTTP обрезан",
    "http_timeout": "HTTP таймаут",
    "throttled": "Замедлен",
    "unknown": "Неизвестная ошибка",
}


class BlockDetector:
    """Singleton: мониторинг DNS + пронирование доменов."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._monitored = {}  # domain -> {first_seen, last_checked, block_code}
        self._whitelist = set()
        self._ssl_context = None
        # MR-62: per-IP rate-limit
        self._request_counts: dict[str, list[float]] = {}
        self._req_counter = 0

    def start(self) -> None:
        """Запустить фоновый мониторинг."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("block_detector", "enabled", default=False):
            return

        self._whitelist = set(cfg.get("block_detector", "whitelist", default=[]))

        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="block-detector", daemon=True)
            t.start()
            self._thread = t
            log.info("block-detector: запущен", source="block_detector")

    def stop(self) -> None:
        """Остановить мониторинг."""
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("block-detector: остановлен", source="block_detector")

    def _run_loop(self):
        from core.config_manager import get_config_manager
        while not self._stop_evt.is_set():
            try:
                cfg = get_config_manager()
                interval = cfg.get("block_detector", "interval_sec", default=300)
                self._tick()
            except Exception as e:
                log.warning("block-detector tick: %s" % e,
                            source="block_detector")
            # MR-30: использовать настраиваемый interval вместо хардкода 60s
            self._stop_evt.wait(interval)

    def _tick(self):
        """Основной цикл: собрать DNS + пронировать."""
        # Собираем домены из DNS-источника
        new_domains = self._collect_dns_queries()
        with self._lock:
            for d in new_domains:
                if d not in self._monitored and d not in self._whitelist:
                    self._monitored[d] = {
                        "first_seen": int(time.time()),
                        "last_checked": 0,
                        "block_code": "unknown",
                    }

            # MR-18: Ограничиваем размер self._monitored до 1000 доменов (FIFO)
            MAX_MONITORED = 2000
            if len(self._monitored) > MAX_MONITORED:
                sorted_keys = sorted(self._monitored.keys(), key=lambda k: self._monitored[k]["first_seen"])
                for k in sorted_keys[:len(self._monitored) - MAX_MONITORED]:
                    self._monitored.pop(k, None)

        # Пронируем домены которые давно не проверялись
        now = int(time.time())
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        timeout = cfg.get("block_detector", "probe_timeout", default=5)

        with self._lock:
            monitored_snapshot = list(self._monitored.items())

        to_probe = []
        for domain, info in monitored_snapshot:
            if (now - info["last_checked"]) >= 3600:  # раз в час
                to_probe.append(domain)

        # MR-97: Параллельный опрос через ThreadPoolExecutor
        if to_probe:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            max_workers = min(5, len(to_probe))
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="block-detector-probe") as executor:
                future_to_domain = {
                    executor.submit(self._probe, domain, timeout): domain
                    for domain in to_probe
                }
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = "unknown"

                    with self._lock:
                        if domain in self._monitored:
                            self._monitored[domain]["last_checked"] = int(time.time())
                            self._monitored[domain]["block_code"] = result

                    if result != "ok":
                        log.info("block-detector: %s → %s (%s)" % (
                            domain, result, BLOCK_CODES.get(result, result)),
                            source="block_detector")
                        self._maybe_auto_add(domain, result)

    def _collect_dns_queries(self) -> list:
        """Собрать уникальные домены из DNS-источника."""
        domains = []
        source = self._get_dns_source()

        if source == "dnsmasq_log":
            domains = self._from_dnsmasq_log()
        elif source == "adguard_log":
            domains = self._from_adguard_log()
        else:
            # AF_PACKET — заглушка (требует root + raw sockets)
            domains = self._from_af_packet()

        return domains

    def _get_dns_source(self) -> str:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        src = cfg.get("block_detector", "dns_source", default="auto")
        if src != "auto":
            return src
        # Автоопределение: проверяем что доступно
        if os.path.isfile("/var/log/dnsmasq.log"):
            return "dnsmasq_log"
        if os.path.isdir("/opt/etc/AdGuardHome"):
            return "adguard_log"
        return "af_packet"

    def _from_dnsmasq_log(self) -> list:
        """Читать домены из dnsmasq лога."""
        domains = []
        try:
            log_path = "/var/log/dnsmasq.log"
            if not os.path.isfile(log_path):
                return []
            # MR-48: после seek в середину файла пропускаем первую половинчатую строку
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 10240))
                if f.tell() > 0:
                    f.readline()  # пропустить possibly-truncated first line
                data = f.read().decode("utf-8", errors="replace")
            # Парсим: "reply <domain> is <ip>"
            for line in data.splitlines():
                m = re.search(r"reply\s+(\S+)\s+is\s+", line)
                if m:
                    domains.append(m.group(1).lower())
        except Exception:
            pass
        return list(set(domains))[-50:]  # последние 50 уникальных

    def _from_adguard_log(self) -> list:
        """Читать домены из AdGuard Home лога."""
        # AdGuard хранит логи в JSON lines формате
        domains = []
        try:
            log_path = "/opt/etc/AdGuardHome/data/querylog.json"
            if not os.path.isfile(log_path):
                return []
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 10240))
                data = f.read().decode("utf-8", errors="replace")
            import json
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    domain = entry.get("domain", "")
                    if domain:
                        domains.append(domain.lower())
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return list(set(domains))[-50:]

    def _from_af_packet(self) -> list:
        """AF_PACKET DNS-сниффинг для случаев, когда dnsmasq/adguard-log недоступны."""
        try:
            import select
            import struct

            ETH_P_ALL = 0x0003
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.setblocking(False)
        except Exception as e:
            log.warning("block-detector: AF_PACKET недоступен: %s" % e,
                        source="block_detector")
            return []

        def _read_dns_name(buf: bytes, offset: int) -> tuple[str, int]:
            labels = []
            jumped = False
            seen = set()
            start = offset
            while offset < len(buf):
                ln = buf[offset]
                if ln == 0:
                    offset += 1
                    break
                if ln & 0xC0 == 0xC0:
                    if offset + 1 >= len(buf):
                        break
                    ptr = ((ln & 0x3F) << 8) | buf[offset + 1]
                    if ptr in seen:
                        break
                    seen.add(ptr)
                    if not jumped:
                        start = offset + 2
                        jumped = True
                    offset = ptr
                    continue
                offset += 1
                label = buf[offset:offset + ln]
                try:
                    labels.append(label.decode("idna", errors="ignore"))
                except Exception:
                    labels.append(label.decode("utf-8", errors="ignore"))
                offset += ln
            return ".".join([p for p in labels if p]), (start if jumped else offset)

        domains = []
        deadline = time.time() + 1.0
        try:
            while time.time() < deadline and len(domains) < 50:
                ready, _, _ = select.select([sock], [], [], 0.2)
                if not ready:
                    continue
                packet = sock.recv(65535)
                if len(packet) < 42:
                    continue

                eth_type = struct.unpack("!H", packet[12:14])[0]
                if eth_type != 0x0800:
                    continue

                ip_start = 14
                version_ihl = packet[ip_start]
                if (version_ihl >> 4) != 4:
                    continue
                ihl = (version_ihl & 0x0F) * 4
                if len(packet) < ip_start + ihl + 8:
                    continue
                proto = packet[ip_start + 9]
                if proto != 17:
                    continue

                udp_start = ip_start + ihl
                src_port, dst_port, udp_len = struct.unpack("!HHH", packet[udp_start:udp_start + 6])
                if src_port != 53 and dst_port != 53:
                    continue

                dns = packet[udp_start + 8:]
                if len(dns) < 12:
                    continue
                flags = struct.unpack("!H", dns[2:4])[0]
                qr = (flags >> 15) & 1
                # Нам интересны и запросы, и ответы: у провайдера может быть
                # виден только ответ в перехвате, а имя домена всё равно нужно.
                offset = 12
                qdcount = struct.unpack("!H", dns[4:6])[0]
                for _ in range(qdcount):
                    name, offset = _read_dns_name(dns, offset)
                    if not name:
                        break
                    if offset + 4 > len(dns):
                        break
                    offset += 4
                    name = name.lower().strip(".")
                    if name and "." in name and name not in domains:
                        domains.append(name)
                if qr == 1 and domains:
                    continue
        except Exception as e:
            log.warning("block-detector: AF_PACKET sniff error: %s" % e,
                        source="block_detector")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return domains[-50:]

    # ─────── probing ───────

    def _probe(self, domain: str, timeout: int = 5) -> str:
        """4-stage probing: DNS → TCP:443 → TLS → HTTP."""
        # Stage 1: DNS resolve
        try:
            ip = socket.getaddrinfo(domain, 443, socket.AF_INET,
                                    socket.SOCK_STREAM)[0][4][0]
        except socket.gaierror:
            return "dns_block"
        except Exception:
            return "dns_block"

        # Stage 2: TCP connect
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
        except ConnectionRefusedError:
            return "tcp_refused"
        except (socket.timeout, OSError):
            return "tcp_timeout"

        # Stage 3 & 4: TLS handshake + HTTP — socket закрываем в finally (MR-29)
        tls = None
        try:
            if self._ssl_context is None:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self._ssl_context = ctx
            tls = self._ssl_context.wrap_socket(sock, server_hostname=domain)
            # Stage 4: HTTP read
            tls.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % domain.encode())
            data = tls.recv(4096)
            if len(data) < 100:
                return "http_cutoff"
            if b"200" in data or b"301" in data or b"302" in data:
                return "ok"
            # MR-46: любой другой ответ (403 geo-block, 451 legal, 521) → http_cutoff
            return "http_cutoff"
        except (ssl.SSLError, OSError) as e:
            err = str(e).lower()
            if "rst" in err or "reset" in err:
                return "tls_rst"
            if "timeout" in err:
                return "tls_timeout"
            return "tls_garbage"
        except Exception:
            return "unknown"
        finally:
            # MR-29: гарантируем закрытие сокета на всех путях выхода
            try:
                if tls:
                    tls.close()
                else:
                    sock.close()
            except Exception:
                pass

    # ─────── auto-add ───────

    def _maybe_auto_add(self, domain: str, block_code: str):
        """Автодобавление в named list если настроено."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if not cfg.get("block_detector", "auto_add_enabled", default=False):
            return
        list_id = cfg.get("block_detector", "auto_add_list_id", default="")
        if not list_id:
            return

        try:
            from core import named_lists
            item = named_lists.get(list_id)
            if not item:
                return
            domains = list(item.get("domains") or [])
            if domain not in domains:
                domains.append(domain)
                named_lists.update_fields(list_id, {"domains": domains})
                log.info("block-detector: автодобавлен %s в %s" % (domain, list_id),
                         source="block_detector")
        except Exception as e:
            log.warning("block-detector auto_add: %s" % e,
                        source="block_detector")

    # ─────── public API ───────

    def get_status(self) -> dict:
        """Статус детектора."""
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
            monitored_count = len(self._monitored)
            blocked_count = sum(1 for v in self._monitored.values()
                                 if v["block_code"] != "ok")
        return {
            "running": running,
            "monitored_count": monitored_count,
            "blocked_count": blocked_count,
        }

    def get_results(self) -> list[dict[str, Any]]:
        """Результаты проверок."""
        with self._lock:
            items = list(self._monitored.items())
        out = []
        for domain, info in sorted(items,
                                    key=lambda x: x[1]["last_checked"],
                                    reverse=True):
            out.append({
                "domain": domain,
                "block_code": info["block_code"],
                "block_desc": BLOCK_CODES.get(info["block_code"], "Неизвестно"),
                "first_seen": info["first_seen"],
                "last_checked": info["last_checked"],
            })
        return out[:200]

    def _is_rate_limited(self, client_ip: str) -> bool:
        """MR-62: проверить per-IP rate-limit (10 запросов/60с)."""
        if not client_ip or client_ip in ("127.0.0.1", "::1", "localhost"):
            return False
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            self._req_counter += 1
            counts = self._request_counts.setdefault(client_ip, [])
            counts[:] = [t for t in counts if t > cutoff]
            if len(counts) >= 10:
                return True
            counts.append(now)
            if self._req_counter % 10 == 0:
                for ip in list(self._request_counts.keys()):
                    self._request_counts[ip] = [t for t in self._request_counts[ip] if t > cutoff]
                    if not self._request_counts[ip]:
                        del self._request_counts[ip]
        return False

    def probe_now(self, domain: str, client_ip: str = "") -> dict[str, Any]:
        """Пронировать домен прямо сейчас."""
        # MR-62: per-IP rate-limit
        if self._is_rate_limited(client_ip):
            return {
                "domain": domain,
                "block_code": "throttled",
                "block_desc": "Too Many Requests",
            }
        # MR-98: запускаем пробу в ThreadPoolExecutor с жестким таймаутом 2.5с
        # чтобы гарантированно не блокировать Bottle-воркер API надолго
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._probe, domain, 2)
            try:
                result = future.result(timeout=2.5)
            except Exception:
                result = "tcp_timeout"

        return {
            "domain": domain,
            "block_code": result,
            "block_desc": BLOCK_CODES.get(result, "Неизвестно"),
        }


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_block_detector() -> BlockDetector:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = BlockDetector()
    return _instance
