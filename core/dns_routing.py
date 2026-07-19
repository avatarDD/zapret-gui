# core/dns_routing.py
"""
Per-domain DNS routing: кастомный DNS для конкретных хостов.

Позволяет направлять DNS-запросы для определённых доменов
на конкретные DoH/DoT серверы, минуя ISP DNS.

Использование:
  - ISP подменяет DNS для youtube.com → ложный IP → DPI блокирует
  - Per-domain DNS: youtube.com → Cloudflare DoH → правильный IP

Реализация через:
  1. dnsmasq server= directives (на роутере)
  2. Hosts-файл (статические записи)
  3. sing-box/mihomo DNS rules (через unified routing)
"""

import os
import re
import socket
import time
import threading
import urllib.parse

from core.log_buffer import log


# Дефолтные DNS-провайдеры
DNS_SERVERS = {
    "cloudflare": {"doh": "https://1.1.1.1/dns-query", "dot": "1.1.1.1:853", "ip": "1.1.1.1"},
    "google": {"doh": "https://dns.google/dns-query", "dot": "8.8.8.8:853", "ip": "8.8.8.8"},
    "adguard": {"doh": "https://dns.adguard.com/dns-query", "dot": "94.140.14.14:853", "ip": "94.140.14.14"},
    "quad9": {"doh": "https://dns.quad9.net/dns-query", "dot": "9.9.9.9:853", "ip": "9.9.9.9"},
    "yandex": {"doh": "https://dns.yandex.net/dns-query", "dot": "77.88.8.8:853", "ip": "77.88.8.8"},
    "comss": {"doh": "https://dns.comss.one/dns-query", "ip": "9.9.9.10"},
    "geohide": {"doh": "https://dns.geohide.ru:444/dns-query", "dot": "dns.geohide.ru:853", "ip": "45.155.204.190"},
}

# MR-83: кеш DNS-резолва чтобы не блокировать apply() на каждом вызове
_dns_cache = {}  # {hostname: (ip, timestamp)}
_dns_cache_lock = threading.Lock()
_DNS_CACHE_TTL = 300  # 5 минут


class DnsRoutingManager:
    """Управление per-domain DNS маршрутизацией."""

    def __init__(self):
        self._lock = threading.Lock()

    def get_rules(self) -> list:
        """Получить текущие DNS-правила из конфига."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return cfg.get("dns_routing", "rules", default=[])

    def add_rule(self, domain: str, dns_server: str, description: str = "") -> dict:
        """Добавить DNS-правило: домен → DNS-сервер."""
        from core.config_manager import get_config_manager
        cm = get_config_manager()

        # MR-61: строгая валидация domain против dnsmasq directive injection
        # domain="x.com\naddn-hosts=/etc/passwd" → инъекция произвольной dnsmasq-директивы
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}[a-zA-Z0-9]$', domain) or \
                any(c in domain for c in ('/\n\r\t #')):
            return {"ok": False, "error": "Недопустимый домен: только буквы, цифры, . - _"}

        rules = cm.get("dns_routing", "rules", default=[])

        # Дедуп по домену
        for r in rules:
            if r.get("domain") == domain:
                return {"ok": False, "error": "Правило для %s уже существует" % domain}

        # Валидация DNS-сервера
        if dns_server not in DNS_SERVERS:
            # Пробуем как IP/URL
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", dns_server) and \
               not dns_server.startswith("https://"):
                return {"ok": False, "error": "Неизвестный DNS: %s" % dns_server}

        rules.append({
            "domain": domain,
            "dns": dns_server,
            "description": description,
            "enabled": True,
        })

        cm.set("dns_routing", "rules", rules)
        cm.save()

        log.info("dns_routing: правило добавлено %s → %s" % (domain, dns_server),
                 source="dns_routing")
        return {"ok": True}

    def add_rules_batch(self, items: list) -> dict:
        """Добавить несколько DNS-правил одним сохранением конфига.

        MR-82: вместо N вызовов add_rule() (каждый делает cm.save()),
        валидируем и записываем всё за один fs-flush.

        Args:
            items: list of {"domain": str, "dns": str, "description": str?}

        Returns:
            {"ok": bool, "added": int, "skipped": int, "errors": [str]}
        """
        from core.config_manager import get_config_manager
        cm = get_config_manager()

        _DOMAIN_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}[a-zA-Z0-9]$')
        _INVALID_CHARS = set('/\n\r\t #')

        with self._lock:
            rules = cm.get("dns_routing", "rules", default=[])
            existing_domains = {r.get("domain") for r in rules}

            added = 0
            skipped = 0
            errors = []

            for item in (items or []):
                domain = (item.get("domain") or "").strip()
                dns_server = (item.get("dns") or "").strip()
                description = (item.get("description") or "").strip()

                if not domain or not dns_server:
                    errors.append("domain и dns обязательны")
                    continue

                # Валидация домена
                if not _DOMAIN_RE.match(domain) or any(c in domain for c in _INVALID_CHARS):
                    errors.append("Недопустимый домен: %s" % domain)
                    continue

                # Дедуп
                if domain in existing_domains:
                    skipped += 1
                    continue

                # Валидация DNS-сервера
                if dns_server not in DNS_SERVERS:
                    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", dns_server) and \
                       not dns_server.startswith("https://"):
                        errors.append("Неизвестный DNS: %s" % dns_server)
                        continue

                rules.append({
                    "domain": domain,
                    "dns": dns_server,
                    "description": description,
                    "enabled": True,
                })
                existing_domains.add(domain)
                added += 1

            if added > 0:
                cm.set("dns_routing", "rules", rules)
                cm.save()  # единственный flush на весь батч

        log.info("dns_routing: batch added=%d skipped=%d errors=%d" % (
                 added, skipped, len(errors)), source="dns_routing")
        return {"ok": True, "added": added, "skipped": skipped, "errors": errors}

    def remove_rule(self, domain: str) -> dict:
        """Удалить DNS-правило."""
        from core.config_manager import get_config_manager
        cm = get_config_manager()

        rules = cm.get("dns_routing", "rules", default=[])
        new_rules = [r for r in rules if r.get("domain") != domain]

        if len(new_rules) == len(rules):
            return {"ok": False, "error": "Правило не найдено"}

        cm.set("dns_routing", "rules", new_rules)
        cm.save()
        return {"ok": True}

    def apply(self) -> dict:
        """Применить DNS-правила через dnsmasq."""
        rules = self.get_rules()
        if not rules:
            return {"ok": True, "applied": 0}

        # Группируем по DNS-серверу
        by_server = {}
        for r in rules:
            if not r.get("enabled", True):
                continue
            server = r.get("dns", "")
            domain = r.get("domain", "")
            if server and domain:
                by_server.setdefault(server, []).append(domain)

        # Генерируем dnsmasq server= directives
        lines = []
        for server, domains in by_server.items():
            dns_ip = self._resolve_server(server)
            if not dns_ip:
                continue
            for domain in domains:
                lines.append("server=/%s/%s" % (domain, dns_ip))

        # Записываем в файл
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            base = cfg.get("zapret", "base_path", default="/opt/zapret2")
            dns_file = os.path.join(base, "lists", "dns-routing.conf")
            os.makedirs(os.path.dirname(dns_file), exist_ok=True)
            with open(dns_file, "w") as f:
                f.write("# Auto-generated by zapret-gui dns_routing\n")
                for line in lines:
                    f.write(line + "\n")

            # Подключаем к dnsmasq
            from core.routing.dnsmasq_integration import DnsmasqIntegration
            dnsmasq = DnsmasqIntegration()
            main_conf = dnsmasq.find_main_config()
            if main_conf:
                marker = "# zapret-gui dns-routing managed include"
                has_include = False
                if os.path.isfile(main_conf):
                    with open(main_conf, "r") as f:
                        text = f.read()
                    if marker in text:
                        has_include = True
                    else:
                        for line in text.splitlines():
                            if line.strip().startswith("conf-file=") and dns_file in line:
                                has_include = True
                                break

                if not has_include:
                    with open(main_conf, "a") as f:
                        f.write("\n%s\nconf-file=%s\n" % (marker, dns_file))
                    log.info("dns_routing: conf-file добавлен в %s" % main_conf, source="dns_routing")

                dnsmasq.reload()

            log.info("dns_routing: применено %d правил → %s" % (len(lines), dns_file),
                     source="dns_routing")
            return {"ok": True, "applied": len(lines), "file": dns_file}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _resolve_server(self, server: str) -> str:
        """Разрешить имя DNS-сервера в IP (с кешем MR-83)."""
        if server in DNS_SERVERS:
            return DNS_SERVERS[server]["ip"]
        # Если это уже IP
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
            return server

        # Сначала ищем по известным DoH-провайдерам
        for provider in DNS_SERVERS.values():
            if provider.get("doh") == server:
                return provider["ip"]

        # Если это DoH URL — извлекаем hostname
        if server.startswith("https://"):
            host = urllib.parse.urlparse(server).hostname
            if host:
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                    return host
                # MR-83: проверяем кеш перед резолвом
                now = time.monotonic()
                with _dns_cache_lock:
                    cached = _dns_cache.get(host)
                    if cached and (now - cached[1]) < _DNS_CACHE_TTL:
                        return cached[0]
                try:
                    ip = self._resolve_with_timeout(host, timeout=2.0)
                    if ip:
                        with _dns_cache_lock:
                            _dns_cache[host] = (ip, now)
                        return ip
                except Exception:
                    pass
                # MR-83: при ошибке — вернуть устаревший кеш (better than nothing)
                with _dns_cache_lock:
                    cached = _dns_cache.get(host)
                    if cached:
                        return cached[0]
        return ""

    def _resolve_with_timeout(self, host: str, timeout: float = 2.0) -> str:
        res = []
        def _run():
            try:
                res.append(socket.gethostbyname(host))
            except Exception:
                pass

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout)
        if res:
            return res[0]
        return ""

    def get_available_servers(self) -> list:
        """Список доступных DNS-серверов."""
        return [{"id": k, "name": v.get("doh", k), "ip": v.get("ip", "")}
                for k, v in DNS_SERVERS.items()]


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_dns_routing_manager() -> DnsRoutingManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = DnsRoutingManager()
    return _instance
