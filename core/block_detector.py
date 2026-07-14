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

import os
import re
import socket
import ssl
import subprocess
import threading
import time
from collections import deque

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

    def start(self):
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

    def stop(self):
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
            self._stop_evt.wait(60)  # базовый интервал 60s

    def _tick(self):
        """Основной цикл: собрать DNS + пронировать."""
        # Собираем домены из DNS-источника
        new_domains = self._collect_dns_queries()
        for d in new_domains:
            if d not in self._monitored and d not in self._whitelist:
                self._monitored[d] = {
                    "first_seen": int(time.time()),
                    "last_checked": 0,
                    "block_code": "unknown",
                }

        # Пронируем домены которые давно не проверялись
        now = int(time.time())
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        timeout = cfg.get("block_detector", "probe_timeout", default=5)

        for domain, info in list(self._monitored.items()):
            if (now - info["last_checked"]) < 3600:  # раз в час
                continue
            result = self._probe(domain, timeout)
            info["last_checked"] = now
            info["block_code"] = result

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
            # Читаем последние 10KB
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 10240))
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
        """AF_PACKET DNS-сниффинг (заглушка — требует root)."""
        # Полная реализация требует scapy/netfilter_queue
        # Пока возвращаем пустой список
        return []

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

        # Stage 3: TLS handshake
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(sock, server_hostname=domain)
            # Stage 4: HTTP read
            tls.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % domain.encode())
            data = tls.recv(4096)
            tls.close()
            if len(data) < 100:
                return "http_cutoff"
            if b"200" in data or b"301" in data or b"302" in data:
                return "ok"
            return "ok"  # есть ответ — считаем доступным
        except ssl.SSLCertVerificationError:
            return "tls_rst"
        except (ssl.SSLError, OSError) as e:
            err = str(e).lower()
            if "rst" in err or "reset" in err:
                return "tls_rst"
            if "timeout" in err:
                return "tls_timeout"
            return "tls_garbage"
        except Exception:
            return "unknown"

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
        return {
            "running": running,
            "monitored_count": len(self._monitored),
            "blocked_count": sum(1 for v in self._monitored.values()
                                 if v["block_code"] != "ok"),
        }

    def get_results(self) -> list:
        """Результаты проверок."""
        out = []
        for domain, info in sorted(self._monitored.items(),
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

    def probe_now(self, domain: str) -> dict:
        """Пронировать домен прямо сейчас."""
        result = self._probe(domain, timeout=5)
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
