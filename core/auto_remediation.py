# core/auto_remediation.py
"""
Auto-Remediation: автоматический выбор метода обхода по результатам DPI-классификации.

После BlockCheck определяет тип блокировки для каждого домена и:
  - "zapret"   → запускает strategy scanner для nfqws2
  - "tunnel"   → создаёт unified route через WARP/AWG/sing-box
  - "dns"      → настраивает DoH/DoT или добавляет в hosts
  - "none"     → не требуется обход

Интегрирует BlockCheck → Unified Routing в один автоматический пайплайн.
"""

import threading
import time

from core.log_buffer import log


# Маппинг DPI-классификации → действие.
# MR-73: Дефолты можно переопределить через config auto_remediation.actions
# (см. _get_remediation_actions() которая merge'ит пользовательские overrides).
REMEDIATION_ACTIONS = {
    "none":         "skip",
    "dns_fake":     "dns_fix",
    "http_inject":  "zapret_scan",
    "isp_page":     "zapret_scan",
    "tls_dpi":      "zapret_scan",
    "tls_mitm":     "zapret_scan",
    "clienthello_dpi": "zapret_scan",
    "tcp_reset":    "zapret_scan",
    "tcp_16_20":    "zapret_scan",
    "stun_block":   "zapret_scan",
    "quic_block":   "zapret_scan",
    "throttled":    "zapret_scan",
    "timeout_drop": "zapret_scan",
    "ip_block":     "tunnel",
    "full_block":   "tunnel",
    "unknown":      "zapret_scan",  # по умолчанию пробуем zapret
}


def _get_remediation_actions() -> dict:
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    user_actions = cfg.get("auto_remediation", "actions", default={})
    if not isinstance(user_actions, dict):
        user_actions = {}
    full_actions = dict(REMEDIATION_ACTIONS)
    full_actions.update(user_actions)
    return full_actions


class AutoRemediation:
    """Автоматическое восстановление доступа по DPI-классификации."""

    def __init__(self):
        self._lock = threading.Lock()
        self._results = []  # {domain, dpi_type, action, status, details}
        self._remediation_history = {}  # domain -> timestamp
        self._in_flight = False  # guard against concurrent runs

    def run(self, blockcheck_report=None, *, auto_apply=False,
            dry_run=False) -> dict:
        """
        Запустить auto-remediation по результатам BlockCheck.

        Args:
            blockcheck_report: BlockcheckReport из blockcheck.py
            auto_apply: автоматически применять remediation (иначе только рекомендации)
            dry_run: если True — возвращает planned_actions без применения (preview)

        Returns:
            {ok, results: [{domain, dpi_type, action, remediation, applied, details}]}
            При dry_run=True ключ dry_run=True и applied всегда False.
        """
        if not blockcheck_report:
            return {"ok": False, "error": "Нет отчёта BlockCheck"}

        # In-flight guard: предотвращаем параллельные вызовы (ISSUE-010).
        # dry_run запросы не блокируются и не выставляют флаг.
        if not dry_run:
            with self._lock:
                if self._in_flight:
                    return {
                        "ok": False,
                        "error": "Remediation уже выполняется",
                        "in_flight": True,
                    }
                self._in_flight = True

        try:
            return self._do_run(blockcheck_report,
                                auto_apply=auto_apply,
                                dry_run=dry_run)
        finally:
            if not dry_run:
                with self._lock:
                    self._in_flight = False

    def _do_run(self, blockcheck_report, *, auto_apply=False,
                dry_run=False) -> dict:
        """Внутренний метод выполнения remediation (вызывается из run())."""
        results = []

        # Собираем результаты по доменам
        targets = getattr(blockcheck_report, 'targets', [])
        if not targets:
            return {"ok": False, "error": "Нет целей в отчёте"}

        actions = _get_remediation_actions()
        for target in targets:
            domain = getattr(target, 'domain', '')
            dpi_type = getattr(target, 'dpi_classification', 'unknown')
            action = actions.get(dpi_type, 'zapret_scan')

            result = {
                "domain": domain,
                "dpi_type": dpi_type,
                "action": action,
                "applied": False,
                "details": "",
                "dry_run": dry_run,
            }

            # Проверка кулдауна на повторный запуск (15 минут)
            now = time.time()
            last_run = self._remediation_history.get(domain, 0)
            if auto_apply and not dry_run and action != "skip" and (now - last_run < 900):
                result["details"] = "Пропуск: исправление уже выполнялось недавно"
                results.append(result)
                continue

            if action == "skip":
                result["details"] = "Обход не требуется"
            elif action == "dns_fix":
                result["details"] = "Рекомендация: DoH/DoT или hosts"
                if auto_apply and not dry_run:
                    result["applied"], result["details"] = self._apply_dns_fix(domain)
                    if result["applied"]:
                        self._remediation_history[domain] = now
            elif action == "zapret_scan":
                result["details"] = "Рекомендация: strategy scan для nfqws2"
                if auto_apply and not dry_run:
                    # Проверяем, не запущен ли уже сканер
                    from core.strategy_scanner import get_strategy_scanner
                    scanner = get_strategy_scanner()
                    if getattr(scanner, '_status', '') == 'running':
                        result["details"] = "Пропуск: сканер стратегий уже занят"
                    else:
                        result["applied"], result["details"] = \
                            self._apply_zapret(domain, dpi_type)
                        if result["applied"]:
                            self._remediation_history[domain] = now
            elif action == "tunnel":
                result["details"] = "Рекомендация: tunnel (WARP/AWG/sing-box)"
                if auto_apply and not dry_run:
                    result["applied"], result["details"] = \
                        self._apply_tunnel(domain)
                    if result["applied"]:
                        self._remediation_history[domain] = now

            results.append(result)

        if not dry_run:
            with self._lock:
                self._results = results

        return {
            "ok": True,
            "results": results,
            "auto_applied": auto_apply and not dry_run,
            "dry_run": dry_run,
        }

    def _apply_dns_fix(self, domain: str) -> tuple[bool, str]:
        """Добавить домен в hosts с реальным IP, полученным через DoH."""
        try:
            from core.hosts_manager import get_hosts_manager
            hm = get_hosts_manager()

            # Пробуем получить IP через DoH
            import urllib.request
            import json
            urls = [
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                f"https://dns.google/dns-query?name={domain}&type=A"
            ]
            correct_ip = None
            for url in urls:
                try:
                    req = urllib.request.Request(
                        url, headers={"Accept": "application/dns-json"}
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as response:
                        data = json.loads(response.read().decode())
                        for ans in data.get("Answer", []):
                            if ans.get("type") == 1:  # A record
                                correct_ip = ans.get("data")
                                break
                    if correct_ip:
                        break
                except Exception:
                    pass

            if not correct_ip:
                msg = "DNS IP не найден через DoH для %s (manual action required)" % domain
                log.warning("auto-remediation: %s" % msg, source="auto_remediation")
                return False, msg

            log.info("auto-remediation: DNS fix для %s -> %s" % (domain, correct_ip),
                     source="auto_remediation")
            ok = hm.add_entry(correct_ip, domain)
            if ok:
                return True, "Добавлен в hosts: %s -> %s" % (domain, correct_ip)
            else:
                return False, "Не удалось добавить запись в hosts для %s" % domain
        except Exception as e:
            return False, "Ошибка: %s" % str(e)

    def _apply_zapret(self, domain: str, dpi_type: str) -> tuple:
        """Запустить strategy scan для nfqws2."""
        try:
            from core.strategy_scanner import get_strategy_scanner
            scanner = get_strategy_scanner()

            # Определяем протокол по DPI-типу
            protocol = "tcp"
            if dpi_type in ("quic_block", "stun_block"):
                protocol = "udp"

            # Определяем режим: quick для простых типов, standard для сложных
            mode = "quick"
            if dpi_type in ("clienthello_dpi", "tls_mitm", "full_block"):
                mode = "standard"

            log.info("auto-remediation: strategy scan для %s (dpi=%s, proto=%s, mode=%s)"
                     % (domain, dpi_type, protocol, mode),
                     source="auto_remediation")

            # Запускаем скан с DPI-фильтрацией (неблокирующе)
            ok = scanner.start(target=domain, protocol=protocol, mode=mode,
                              dpi_type=dpi_type)
            if ok:
                return True, "Strategy scan запущен (DPI: %s)" % dpi_type
            else:
                return False, "Не удалось запустить сканирование (возможно, сканер уже занят)"

        except Exception as e:
            return False, "Ошибка: %s" % str(e)

    def _apply_tunnel(self, domain: str) -> tuple:
        """Создать unified route через туннель и проверить доступность."""
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            # Определяем лучший доступный туннель
            tunnel_method = self._find_best_tunnel()
            if not tunnel_method:
                return False, "Нет доступных туннелей (настройте WARP/AWG/sing-box)"

            # Создаём unified route
            from core.unified.storage import load_routes, add_route
            from core.unified.model import UnifiedRoute, Destination

            route = UnifiedRoute(
                name="Auto: %s → %s" % (domain, tunnel_method),
                destination=Destination(domains=[domain]),
                method=tunnel_method,
                enabled=True,
            )

            add_route(route)

            # Применяем
            from core.unified import applier
            result = applier.apply_route(route)
            if not result.get("ok"):
                return False, "Не удалось применить route: %s" % result.get("error", "Неизвестная ошибка")

            log.info("auto-remediation: tunnel route создан для %s → %s"
                     % (domain, tunnel_method), source="auto_remediation")

            # MR-33: выполняем block_detector._probe(domain) после применения роута
            from core.block_detector import get_block_detector
            bd = get_block_detector()
            probe_res = bd._probe(domain)

            if probe_res == "ok":
                return True, "Route создан и проверен: %s → %s. Статус: ok" % (domain, tunnel_method)
            else:
                return False, "Route создан, но проверка туннеля не удалась. Статус: %s" % probe_res

        except Exception as e:
            return False, "Ошибка: %s" % str(e)

    def _find_best_tunnel(self) -> str:
        """Найти лучший доступный туннель по приоритету из конфига."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        priority = cfg.get("auto_remediation", "tunnel_priority",
                           default=["warp", "awg", "singbox", "mihomo"])

        for name in priority:
            target = self._detect_tunnel(name)
            if target:
                return "%s:%s" % (name, target)

        return ""

    def _detect_tunnel(self, name: str) -> str:
        """Обнаружить активный интерфейс/прокси для типа туннеля."""
        try:
            if name == "warp":
                from core.usque_manager import get_usque_manager
                mgr = get_usque_manager()
                for c in mgr.list_configs():
                    if c.get("active"):
                        return c.get("iface", "")
            elif name == "awg":
                from core.awg_manager import get_awg_manager
                mgr = get_awg_manager()
                for c in mgr.list_configs():
                    if c.get("active"):
                        return c.get("iface", "awg0")
            elif name == "singbox":
                from core.singbox_manager import get_singbox_manager
                mgr = get_singbox_manager()
                for c in mgr.list_configs():
                    if c.get("running"):
                        return c.get("tun_iface", "tun0")
            elif name == "mihomo":
                from core.mihomo_manager import get_mihomo_manager
                mgr = get_mihomo_manager()
                for c in mgr.list_configs():
                    if c.get("running"):
                        return c.get("tun_iface", "meta")
            # opera-proxy — локальный HTTP/SOCKS-прокси, а не прозрачный
            # CIDR-метод unified-слоя (METHOD_KINDS без "opera"). Как цель
            # авто-ремедиации не годится: UnifiedRoute(method="opera:...")
            # бросил бы ValueError. Приложения используют его через явную
            # HTTP-proxy настройку, не через policy-routing.
        except Exception:
            pass
        return ""

    def get_results(self) -> list:
        with self._lock:
            return list(self._results)


# ─────── singleton ───────

_instance = None
_instance_lock = threading.Lock()


def get_auto_remediation() -> AutoRemediation:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AutoRemediation()
    return _instance
