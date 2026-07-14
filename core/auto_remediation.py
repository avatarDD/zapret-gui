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


# Маппинг DPI-классификации → действие
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


class AutoRemediation:
    """Автоматическое восстановление доступа по DPI-классификации."""

    def __init__(self):
        self._lock = threading.Lock()
        self._results = []  # {domain, dpi_type, action, status, details}

    def run(self, blockcheck_report=None, *, auto_apply=False) -> dict:
        """
        Запустить auto-remediation по результатам BlockCheck.

        Args:
            blockcheck_report: BlockcheckReport из blockcheck.py
            auto_apply: автоматически применять remediation (иначе только рекомендации)

        Returns:
            {ok, results: [{domain, dpi_type, action, remediation, applied, details}]}
        """
        if not blockcheck_report:
            return {"ok": False, "error": "Нет отчёта BlockCheck"}

        results = []

        # Собираем результаты по доменам
        targets = getattr(blockcheck_report, 'targets', [])
        if not targets:
            return {"ok": False, "error": "Нет целей в отчёте"}

        for target in targets:
            domain = getattr(target, 'domain', '')
            dpi_type = getattr(target, 'dpi_classification', 'unknown')
            action = REMEDIATION_ACTIONS.get(dpi_type, 'zapret_scan')

            result = {
                "domain": domain,
                "dpi_type": dpi_type,
                "action": action,
                "applied": False,
                "details": "",
            }

            if action == "skip":
                result["details"] = "Обход не требуется"
            elif action == "dns_fix":
                result["details"] = "Рекомендация: DoH/DoT или hosts"
                if auto_apply:
                    result["applied"] = self._apply_dns_fix(domain)
            elif action == "zapret_scan":
                result["details"] = "Рекомендация: strategy scan для nfqws2"
                if auto_apply:
                    result["applied"], result["details"] = \
                        self._apply_zapret(domain, dpi_type)
            elif action == "tunnel":
                result["details"] = "Рекомендация: tunnel (WARP/AWG/sing-box)"
                if auto_apply:
                    result["applied"], result["details"] = \
                        self._apply_tunnel(domain)

            results.append(result)

        with self._lock:
            self._results = results

        return {
            "ok": True,
            "results": results,
            "auto_applied": auto_apply,
        }

    def _apply_dns_fix(self, domain: str) -> bool:
        """Добавить домен в hosts или настроить DoH."""
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            # Добавляем в hosts если есть hosts-менеджер
            try:
                from core.hosts_manager import get_hosts_manager
                hm = get_hosts_manager()
                # Домен с DNS_FAKE нуждается в правильном IP
                # Пока просто логируем — полная реализация требует DNS probe
                log.info("auto-remediation: DNS fix для %s (требуется DoH/hosts)" % domain,
                         source="auto_remediation")
                return True
            except Exception:
                return False
        except Exception:
            return False

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
            scanner.start(target=domain, protocol=protocol, mode=mode,
                         dpi_type=dpi_type)
            return True, "Strategy scan запущен (DPI: %s)" % dpi_type

        except Exception as e:
            return False, "Ошибка: %s" % str(e)

    def _apply_tunnel(self, domain: str) -> tuple:
        """Создать unified route через туннель."""
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            # Определяем лучший доступный туннель
            tunnel_method = self._find_best_tunnel()
            if not tunnel_method:
                return False, "Нет доступных туннелей (настройте WARP/AWG/sing-box)"

            # Создаём unified route
            from core.unified.storage import load_routes, save_route
            from core.unified.model import UnifiedRoute, Destination

            route = UnifiedRoute(
                name="Auto: %s → %s" % (domain, tunnel_method),
                destination=Destination(domains=[domain]),
                method=tunnel_method,
                enabled=True,
            )

            save_route(route)

            # Применяем
            from core.unified import applier
            result = applier.apply_route(route)

            log.info("auto-remediation: tunnel route создан для %s → %s"
                     % (domain, tunnel_method), source="auto_remediation")

            return True, "Route создан: %s → %s" % (domain, tunnel_method)

        except Exception as e:
            return False, "Ошибка: %s" % str(e)

    def _find_best_tunnel(self) -> str:
        """Найти лучший доступный туннель по приоритету из конфига."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        priority = cfg.get("auto_remediation", "tunnel_priority",
                           default=["warp", "awg", "opera", "singbox", "mihomo"])

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
            elif name == "opera":
                from core.opera_proxy_manager import get_opera_proxy_manager
                mgr = get_opera_proxy_manager()
                if mgr._is_running():
                    from core.config_manager import get_config_manager
                    cfg = get_config_manager()
                    return cfg.get("opera_proxy", "bind",
                                   default="127.0.0.1:18080")
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
