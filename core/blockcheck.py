# core/blockcheck.py
"""
BlockCheck-оркестратор — запуск всех сетевых тестеров и сборка отчёта.

Управляет последовательностью тестов (DNS, TLS, ISP, TCP 16-20KB, STUN, Ping),
собирает результаты в BlockcheckReport, классифицирует DPI.

Запускается в фоновом потоке, статус доступен для polling из REST API.

Использование:
    from core.blockcheck import get_blockcheck_runner

    runner = get_blockcheck_runner()
    runner.start(mode="quick", extra_domains=["youtube.com"])
    status = runner.get_status()   # {"status": "running", "progress": ...}
    report = runner.get_results()  # BlockcheckReport | None
"""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from core.log_buffer import log
from core.config_manager import get_config_manager
from core.models import (
    BlockcheckReport,
    DPIClassification,
    SingleTestResult,
    TargetResult,
    TestStatus,
    TestType,
)


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

class RunMode:
    """Режимы запуска blockcheck."""
    QUICK = "quick"         # TLS 1.3 + DNS + Ping (быстрый)
    FULL = "full"           # Все тесты
    DPI_ONLY = "dpi_only"   # TLS + ISP + TCP + DNS (без ping, без STUN)


# ---------------------------------------------------------------------------
# Runner status
# ---------------------------------------------------------------------------

class RunnerStatus:
    """Статусы runner-а."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Default targets
# ---------------------------------------------------------------------------

# Домены по умолчанию, если data/domains.txt отсутствует
_DEFAULT_DOMAINS: list[str] = [
    "youtube.com",
    "www.youtube.com",
    "i.ytimg.com",
    "discord.com",
    "cdn.discordapp.com",
    "gateway.discord.gg",
    "telegram.org",
    "web.telegram.org",
    "www.google.com",
    "www.cloudflare.com",
    "rutracker.org",
    "www.linkedin.com",
    "www.instagram.com",
    "www.facebook.com",
    "x.com",
    "www.spotify.com",
]

# Цели для STUN/UDP тестов
_DEFAULT_STUN_TARGETS: list[dict[str, Any]] = [
    {"name": "Google STUN", "host": "stun.l.google.com", "port": 19302},
    {"name": "Cloudflare STUN", "host": "stun.cloudflare.com", "port": 3478},
    {"name": "Twilio STUN", "host": "global.stun.twilio.com", "port": 3478},
    {"name": "Telegram STUN", "host": "stun.telegram.org", "port": 3478},
]

# Цели для Ping
_DEFAULT_PING_TARGETS: list[str] = [
    "1.1.1.1",
    "8.8.8.8",
]


# ---------------------------------------------------------------------------
# Domain loading
# ---------------------------------------------------------------------------

def _get_app_dir() -> str:
    """Путь к корню приложения zapret-gui."""
    # core/blockcheck.py → core/ → zapret-gui/
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_domains(data_dir: str | None = None) -> tuple[list[str], str]:
    """Загрузить домены из data/domains.txt.

    Returns:
        (domains, source_info)
    """
    if data_dir is None:
        data_dir = os.path.join(_get_app_dir(), "data")

    domains_file = os.path.join(data_dir, "domains.txt")

    if os.path.isfile(domains_file):
        try:
            with open(domains_file, "r", encoding="utf-8") as f:
                domains = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)
            if domains:
                return domains, f"file:{domains_file}"
        except (OSError, IOError) as e:
            log.warning(f"Не удалось загрузить domains.txt: {e}",
                        source="blockcheck")

    return list(_DEFAULT_DOMAINS), "fallback:defaults"


def _normalize_domain(raw: str) -> str:
    """Извлечь домен из URL или строки."""
    raw = raw.strip()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.rstrip("/").split("/")[0].split("?")[0].split("#")[0]
    if ":" in raw:
        raw = raw.rsplit(":", 1)[0]
    return raw.lower().strip()


def _build_domain_list(
    extra_domains: list[str] | None = None,
) -> list[str]:
    """Построить полный список доменов для тестирования."""
    domains, source = load_domains()
    log.debug(f"Domains source: {source} ({len(domains)} шт.)",
              source="blockcheck")

    # Добавляем пользовательские домены
    seen = set(d.lower() for d in domains)
    if extra_domains:
        for raw in extra_domains:
            d = _normalize_domain(raw)
            if d and d not in seen:
                domains.append(d)
                seen.add(d)

    return domains


# ---------------------------------------------------------------------------
# BlockcheckRunner
# ---------------------------------------------------------------------------

class BlockcheckRunner:
    """
    Оркестратор всех blockcheck-тестов.

    Запускается в фоновом потоке. Статус и результаты доступны
    для polling из REST API через get_status() и get_results().
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._status = RunnerStatus.IDLE
        self._progress = 0
        self._progress_total = 0
        self._progress_message = ""
        self._current_phase = ""
        self._report: Optional[BlockcheckReport] = None
        self._thread: Optional[threading.Thread] = None
        self._cancelled = threading.Event()
        self._started_at = 0.0
        self._error = ""
        self._callback: Optional[Callable] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        mode: str = RunMode.QUICK,
        extra_domains: list[str] | None = None,
        callback: Callable | None = None,
        timeout: int | None = None,
    ) -> bool:
        """Запустить blockcheck в фоновом потоке.

        Args:
            mode: RunMode.QUICK / FULL / DPI_ONLY
            extra_domains: Дополнительные домены для тестирования.
            callback: Callable(event_type: str, data: dict) для уведомлений.
            timeout: Таймаут для тестов (в секундах), None = из конфига.

        Returns:
            True если запущен, False если уже выполняется.
        """
        with self._lock:
            if self._status == RunnerStatus.RUNNING:
                return False

            self._status = RunnerStatus.RUNNING
            self._progress = 0
            self._progress_total = 0
            self._progress_message = ""
            self._current_phase = ""
            self._report = None
            self._cancelled.clear()
            self._error = ""
            self._started_at = time.time()
            self._callback = callback

        cfg = get_config_manager()
        max_workers = cfg.get("blockcheck", "max_workers", default=2)
        if timeout is None:
            timeout = cfg.get("blockcheck", "probe_timeout", default=10)

        thread = threading.Thread(
            target=self._run,
            args=(mode, extra_domains, timeout, max_workers),
            daemon=True,
            name="blockcheck-runner",
        )
        self._thread = thread
        thread.start()

        log.info(f"BlockCheck запущен: mode={mode}", source="blockcheck")
        return True

    def cancel(self) -> bool:
        """Отменить текущее выполнение."""
        if self._status != RunnerStatus.RUNNING:
            return False
        self._cancelled.set()
        log.info("BlockCheck: запрошена отмена", source="blockcheck")
        return True

    def get_status(self) -> dict[str, Any]:
        """Получить текущий статус для REST API polling."""
        with self._lock:
            result = {
                "status": self._status,
                "progress": self._progress,
                "total": self._progress_total,
                "message": self._progress_message,
                "phase": self._current_phase,
                "started_at": self._started_at,
                "error": self._error,
            }
            if self._status == RunnerStatus.COMPLETED and self._report:
                result["elapsed_seconds"] = round(
                    self._report.finished_at - self._report.started_at, 2
                )
            elif self._status == RunnerStatus.RUNNING:
                result["elapsed_seconds"] = round(
                    time.time() - self._started_at, 2
                )
            return result

    def get_results(self) -> Optional[BlockcheckReport]:
        """Получить результаты последнего blockcheck."""
        return self._report

    def get_results_dict(self) -> Optional[dict[str, Any]]:
        """Получить результаты в dict-формате для JSON."""
        report = self._report
        if report is None:
            return None
        return report.to_dict()

    @property
    def is_running(self) -> bool:
        return self._status == RunnerStatus.RUNNING

    # ------------------------------------------------------------------
    # Internal: progress helpers
    # ------------------------------------------------------------------

    def _set_phase(self, phase: str) -> None:
        with self._lock:
            self._current_phase = phase
        log.info(f"BlockCheck: {phase}", source="blockcheck")
        self._emit("phase_change", {"phase": phase})

    def _set_progress(self, current: int, total: int, message: str = "") -> None:
        with self._lock:
            self._progress = current
            self._progress_total = total
            self._progress_message = message
        self._emit("progress", {
            "current": current, "total": total, "message": message,
        })

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Уведомить callback, если задан."""
        cb = self._callback
        if cb:
            try:
                cb(event_type, data)
            except Exception:
                pass

    @property
    def _is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    # ------------------------------------------------------------------
    # Internal: main run
    # ------------------------------------------------------------------

    def _run(
        self,
        mode: str,
        extra_domains: list[str] | None,
        timeout: int,
        max_workers: int,
    ) -> None:
        """Основной метод — запускается в отдельном потоке."""
        report = BlockcheckReport(
            mode=mode,
            started_at=time.time(),
        )

        try:
            domains = _build_domain_list(extra_domains)
            phase_count = self._count_phases(mode)
            current_phase = 0

            # --- Фаза 1: DNS ---
            if mode in (RunMode.FULL, RunMode.DPI_ONLY) and not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: DNS проверка"
                )
                self._run_dns_phase(domains, report)

            # --- Фаза 2: TLS ---
            if not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: TLS тесты"
                )
                self._run_tls_phase(
                    domains, report, mode, timeout, max_workers,
                )

            # --- Фаза 3: ISP-детекция ---
            if mode in (RunMode.FULL, RunMode.DPI_ONLY) and not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: ISP детекция"
                )
                self._run_isp_phase(report, max_workers)

            # --- Фаза 4: TCP 16-20KB ---
            if mode in (RunMode.FULL, RunMode.DPI_ONLY) and not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: TCP 16-20KB"
                )
                self._run_tcp_phase(report, max_workers)

            # --- Фаза 5: STUN/UDP ---
            if mode == RunMode.FULL and not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: STUN/UDP"
                )
                self._run_stun_phase(report, max_workers)

            # --- Фаза 6: Ping ---
            if mode in (RunMode.FULL, RunMode.QUICK) and not self._is_cancelled:
                current_phase += 1
                self._set_phase(
                    f"Фаза {current_phase}/{phase_count}: Ping"
                )
                self._run_ping_phase(domains, report)

            # --- Классификация DPI ---
            if not self._is_cancelled:
                self._set_phase("Классификация DPI...")
                self._run_classification(report)

            # --- Формирование итогов ---
            report.finished_at = time.time()
            report.dpi_classification = self._aggregate_dpi(report)
            report.dpi_detail = self._build_dpi_summary(report)

            with self._lock:
                self._report = report
                if self._is_cancelled:
                    self._status = RunnerStatus.CANCELLED
                else:
                    self._status = RunnerStatus.COMPLETED
                self._current_phase = "Готово"

            elapsed = round(report.finished_at - report.started_at, 1)
            log.success(
                f"BlockCheck завершён за {elapsed}с: {report.dpi_classification}",
                source="blockcheck",
            )
            self._emit("complete", {"report": report.to_dict()})

        except Exception as e:
            report.finished_at = time.time()
            report.error = str(e)[:200]
            with self._lock:
                self._report = report
                self._status = RunnerStatus.ERROR
                self._error = str(e)[:200]
            log.error(f"BlockCheck ошибка: {e}", source="blockcheck")
            self._emit("error", {"error": str(e)[:200]})

    # ------------------------------------------------------------------
    # Phase: DNS
    # ------------------------------------------------------------------

    def _run_dns_phase(
        self,
        domains: list[str],
        report: BlockcheckReport,
    ) -> None:
        """DNS-проверка через существующий core.diagnostics.check_dns()."""
        from core.diagnostics import check_dns

        total = len(domains)
        for idx, domain in enumerate(domains):
            if self._is_cancelled:
                break

            self._set_progress(idx + 1, total, f"DNS: {domain}")

            try:
                dns_result = check_dns(domain)
            except Exception as e:
                dns_result = {
                    "domain": domain, "ok": False,
                    "resolved_ips": [], "error": str(e),
                }

            ok = dns_result.get("ok", False)
            resolved_ips = dns_result.get("resolved_ips", [])
            error_str = dns_result.get("error", "") or ""
            response_time = dns_result.get("response_time")

            # Создаём SingleTestResult
            if ok and resolved_ips:
                status = TestStatus.SUCCESS.value
                details = f"Resolved: {', '.join(str(ip) for ip in resolved_ips[:3])}"
                error_code = ""
            elif error_str:
                status = TestStatus.FAILED.value
                details = str(error_str)[:100]
                error_code = "DNS_ERR"
            else:
                status = TestStatus.FAILED.value
                details = "DNS resolution failed"
                error_code = "DNS_ERR"

            latency = float(response_time) if response_time else 0.0

            test_result = SingleTestResult(
                target=domain,
                test_type=TestType.DNS.value,
                status=status,
                latency_ms=latency,
                error=error_code,
                details=details,
                raw_data={
                    "resolved_ips": resolved_ips,
                    "dns_server": dns_result.get("dns_server", ""),
                },
            )

            # Добавляем к существующему TargetResult или создаём новый
            target_result = self._get_or_create_target(report, domain)
            target_result.results.append(test_result)

            log.debug(
                f"DNS {domain}: {status} — {details}",
                source="blockcheck",
            )
            self._emit("test_result", {"result": test_result.to_dict()})

    # ------------------------------------------------------------------
    # Phase: TLS
    # ------------------------------------------------------------------

    def _run_tls_phase(
        self,
        domains: list[str],
        report: BlockcheckReport,
        mode: str,
        timeout: int,
        max_workers: int,
    ) -> None:
        """TLS-тесты: HTTP, TLS 1.2, TLS 1.3 для каждого домена."""
        from core.testers.tls_tester import test_tls

        # В QUICK-режиме — только TLS 1.3 (быстрее)
        if mode == RunMode.QUICK:
            tls_versions = [("1.3", TestType.TLS_13)]
        else:
            tls_versions = [
                (None, TestType.HTTP),
                ("1.2", TestType.TLS_12),
                ("1.3", TestType.TLS_13),
            ]

        # Строим задачи
        jobs: list[tuple[str, str | None, TestType]] = []
        for domain in domains:
            for tls_ver, _test_type in tls_versions:
                jobs.append((domain, tls_ver, _test_type))

        total = len(jobs)
        completed = 0

        def _test_one(domain: str, tls_version: str | None) -> SingleTestResult:
            return test_tls(
                host=domain,
                timeout=timeout,
                tls_version=tls_version,
            )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for domain, tls_ver, test_type in jobs:
                if self._is_cancelled:
                    break
                future = pool.submit(_test_one, domain, tls_ver)
                futures[future] = (domain, tls_ver, test_type)

            for future in as_completed(futures):
                if self._is_cancelled:
                    break

                domain, tls_ver, test_type = futures[future]
                completed += 1

                try:
                    result = future.result()
                except Exception as e:
                    result = SingleTestResult(
                        target=domain,
                        test_type=test_type.value,
                        status=TestStatus.ERROR.value,
                        error="EXCEPTION",
                        details=str(e)[:100],
                    )

                label = {None: "HTTP", "1.2": "TLS1.2", "1.3": "TLS1.3"}[tls_ver]
                self._set_progress(
                    completed, total, f"{label}: {domain}",
                )

                target_result = self._get_or_create_target(report, domain)
                target_result.results.append(result)

                log.debug(
                    f"{label} {domain}: {result.status} — {result.details}",
                    source="blockcheck",
                )
                self._emit("test_result", {"result": result.to_dict()})

    # ------------------------------------------------------------------
    # Phase: ISP detection
    # ------------------------------------------------------------------

    def _run_isp_phase(
        self,
        report: BlockcheckReport,
        max_workers: int,
    ) -> None:
        """ISP-заглушки и HTTP injection для каждого домена."""
        from core.testers.isp_detector import detect_isp_page, check_http_injection

        # Работаем только с уже добавленными доменами
        targets = list(report.targets)
        if not targets:
            return

        total = len(targets)
        completed = 0

        def _isp_one(domain: str) -> list[SingleTestResult]:
            results = []

            # HTTP injection (порт 80)
            try:
                http_r = check_http_injection(domain)
                results.append(http_r)
            except Exception as e:
                results.append(SingleTestResult(
                    target=domain,
                    test_type=TestType.HTTP_INJECT.value,
                    status=TestStatus.ERROR.value,
                    error="EXCEPTION",
                    details=str(e)[:100],
                ))

            # ISP page via HTTPS
            try:
                isp_r = detect_isp_page(domain)
                results.append(isp_r)
            except Exception as e:
                results.append(SingleTestResult(
                    target=domain,
                    test_type=TestType.ISP_DETECT.value,
                    status=TestStatus.ERROR.value,
                    error="EXCEPTION",
                    details=str(e)[:100],
                ))

            return results

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for tr in targets:
                if self._is_cancelled:
                    break
                future = pool.submit(_isp_one, tr.domain)
                futures[future] = tr

            for future in as_completed(futures):
                if self._is_cancelled:
                    break

                tr = futures[future]
                completed += 1
                self._set_progress(completed, total, f"ISP: {tr.domain}")

                try:
                    results = future.result()
                except Exception as e:
                    results = [SingleTestResult(
                        target=tr.domain,
                        test_type=TestType.ISP_DETECT.value,
                        status=TestStatus.ERROR.value,
                        error="EXCEPTION",
                        details=str(e)[:100],
                    )]

                for r in results:
                    tr.results.append(r)
                    self._emit("test_result", {"result": r.to_dict()})

                log.debug(
                    f"ISP {tr.domain}: "
                    + ", ".join(f"{r.test_type}={r.status}" for r in results),
                    source="blockcheck",
                )

    # ------------------------------------------------------------------
    # Phase: TCP 16-20KB
    # ------------------------------------------------------------------

    def _run_tcp_phase(
        self,
        report: BlockcheckReport,
        max_workers: int,
    ) -> None:
        """TCP 16-20KB block detection."""
        from core.testers.tcp_test import (
            check_tcp_16_20,
            load_tcp_targets,
            select_tcp_targets,
        )

        # Загружаем TCP-цели
        all_targets = load_tcp_targets()
        if not all_targets:
            log.warning(
                "Нет TCP-целей для 16-20KB теста", source="blockcheck",
            )
            return

        selected = select_tcp_targets(
            targets=all_targets,
            check_health=True,
        )
        if not selected:
            log.warning(
                "Нет доступных TCP-целей после health-check",
                source="blockcheck",
            )
            return

        log.info(
            f"TCP 16-20KB: выбрано {len(selected)} целей",
            source="blockcheck",
        )

        total = len(selected)
        completed = 0
        tcp_results: list[SingleTestResult] = []

        def _tcp_one(tcp_target: dict) -> SingleTestResult:
            url = tcp_target.get("url", "")
            r = check_tcp_16_20(url)
            r.raw_data.setdefault("target_id", tcp_target.get("id", ""))
            r.raw_data.setdefault("provider", tcp_target.get("provider", ""))
            return r

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for t in selected:
                if self._is_cancelled:
                    break
                future = pool.submit(_tcp_one, t)
                futures[future] = t

            for future in as_completed(futures):
                if self._is_cancelled:
                    break

                t = futures[future]
                completed += 1
                name = t.get("name", t.get("id", "?"))
                self._set_progress(completed, total, f"TCP: {name}")

                try:
                    result = future.result()
                except Exception as e:
                    result = SingleTestResult(
                        target=t.get("url", ""),
                        test_type=TestType.TCP_16_20.value,
                        status=TestStatus.ERROR.value,
                        error="EXCEPTION",
                        details=str(e)[:100],
                    )

                tcp_results.append(result)
                self._emit("test_result", {"result": result.to_dict()})
                log.debug(
                    f"TCP {name}: {result.status} — {result.details}",
                    source="blockcheck",
                )

        # Агрегируем TCP-результаты в один TargetResult
        if tcp_results:
            tcp_target_result = TargetResult(domain="TCP 16-20KB")
            tcp_target_result.results = tcp_results
            report.targets.append(tcp_target_result)

    # ------------------------------------------------------------------
    # Phase: STUN/UDP
    # ------------------------------------------------------------------

    def _run_stun_phase(
        self,
        report: BlockcheckReport,
        max_workers: int,
    ) -> None:
        """STUN/UDP тесты."""
        from core.testers.stun_tester import test_stun
        from core.testers.config import STUN_TIMEOUT

        stun_targets = _DEFAULT_STUN_TARGETS
        total = len(stun_targets)
        completed = 0

        def _stun_one(target: dict) -> SingleTestResult:
            return test_stun(
                host=target["host"],
                port=target.get("port", 3478),
                timeout=STUN_TIMEOUT,
            )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for t in stun_targets:
                if self._is_cancelled:
                    break
                future = pool.submit(_stun_one, t)
                futures[future] = t

            for future in as_completed(futures):
                if self._is_cancelled:
                    break

                t = futures[future]
                completed += 1
                self._set_progress(
                    completed, total, f"STUN: {t['name']}",
                )

                try:
                    result = future.result()
                except Exception as e:
                    result = SingleTestResult(
                        target=f"{t['host']}:{t.get('port', 3478)}",
                        test_type=TestType.STUN.value,
                        status=TestStatus.ERROR.value,
                        error="EXCEPTION",
                        details=str(e)[:100],
                    )

                # STUN — отдельный TargetResult для каждого сервера
                stun_tr = TargetResult(domain=t["name"])
                stun_tr.results.append(result)
                report.targets.append(stun_tr)

                self._emit("test_result", {"result": result.to_dict()})
                log.debug(
                    f"STUN {t['name']}: {result.status} — {result.details}",
                    source="blockcheck",
                )

    # ------------------------------------------------------------------
    # Phase: Ping
    # ------------------------------------------------------------------

    def _run_ping_phase(
        self,
        domains: list[str],
        report: BlockcheckReport,
    ) -> None:
        """Ping через существующий core.diagnostics.ping_host()."""
        from core.diagnostics import ping_host

        # Пингуем и IP-цели, и домены из отчёта
        ping_targets: list[tuple[str, str]] = []  # (label, host)

        # IP-адреса
        for ip in _DEFAULT_PING_TARGETS:
            ping_targets.append((f"Ping {ip}", ip))

        # Домены из отчёта (не все — только первые N для экономии)
        for domain in domains[:8]:
            ping_targets.append((domain, domain))

        total = len(ping_targets)

        for idx, (label, host) in enumerate(ping_targets):
            if self._is_cancelled:
                break

            self._set_progress(idx + 1, total, f"Ping: {host}")

            try:
                ping_result = ping_host(host, count=2, timeout=3)
            except Exception as e:
                ping_result = {"host": host, "alive": False, "error": str(e)}

            alive = ping_result.get("alive", False)
            rtt_avg = ping_result.get("rtt_avg")
            latency = round(rtt_avg, 2) if rtt_avg else 0.0

            test_result = SingleTestResult(
                target=host,
                test_type=TestType.PING.value,
                status=(TestStatus.SUCCESS.value if alive
                        else TestStatus.FAILED.value),
                latency_ms=latency,
                error="" if alive else "PING_FAIL",
                details=(f"RTT avg: {rtt_avg:.1f}ms" if rtt_avg
                         else "Ping failed"),
                raw_data=ping_result,
            )

            # Для IP-целей — отдельный TargetResult
            # Для доменов — добавляем к существующему
            is_ip_target = host in _DEFAULT_PING_TARGETS
            if is_ip_target:
                ping_tr = TargetResult(domain=label)
                ping_tr.results.append(test_result)
                report.targets.append(ping_tr)
            else:
                target_result = self._get_or_create_target(report, host)
                target_result.results.append(test_result)

            self._emit("test_result", {"result": test_result.to_dict()})

    # ------------------------------------------------------------------
    # DPI Classification
    # ------------------------------------------------------------------

    def _run_classification(self, report: BlockcheckReport) -> None:
        """Классификация DPI для каждого TargetResult."""
        from core.testers.dpi_classifier import DPIClassifier

        for tr in report.targets:
            # Пропускаем служебные target-ы (TCP, Ping IP)
            if tr.domain in ("TCP 16-20KB",) or tr.domain.startswith("Ping "):
                continue

            classification, detail = DPIClassifier.classify(tr)
            tr.dpi_classification = classification.value
            tr.dpi_detail = detail

            if classification != DPIClassification.NONE:
                log.info(
                    f"DPI {tr.domain}: {classification.value} — {detail}",
                    source="blockcheck",
                )

    @staticmethod
    def _aggregate_dpi(report: BlockcheckReport) -> str:
        """Определить общую DPI-классификацию отчёта."""
        classifications = []
        for tr in report.targets:
            if (tr.dpi_classification
                    and tr.dpi_classification != DPIClassification.NONE.value):
                classifications.append(tr.dpi_classification)

        if not classifications:
            return DPIClassification.NONE.value

        # Приоритет: TLS_DPI > ISP_PAGE > FULL_BLOCK > остальные
        priority = [
            DPIClassification.TLS_DPI.value,
            DPIClassification.TLS_MITM.value,
            DPIClassification.ISP_PAGE.value,
            DPIClassification.HTTP_INJECT.value,
            DPIClassification.FULL_BLOCK.value,
            DPIClassification.TCP_RESET.value,
            DPIClassification.TCP_16_20.value,
            DPIClassification.STUN_BLOCK.value,
            DPIClassification.DNS_FAKE.value,
        ]
        for p in priority:
            if p in classifications:
                return p

        return classifications[0] if classifications else DPIClassification.NONE.value

    @staticmethod
    def _build_dpi_summary(report: BlockcheckReport) -> str:
        """Построить текстовое описание DPI."""
        dpi_targets = [
            tr for tr in report.targets
            if (tr.dpi_classification
                and tr.dpi_classification != DPIClassification.NONE.value)
        ]
        if not dpi_targets:
            return "DPI не обнаружен"

        types = set(tr.dpi_classification for tr in dpi_targets)
        domains = [tr.domain for tr in dpi_targets[:5]]
        return (
            f"Обнаружен DPI: {', '.join(types)} "
            f"на {len(dpi_targets)} целях "
            f"({', '.join(domains)}{'...' if len(dpi_targets) > 5 else ''})"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_or_create_target(
        report: BlockcheckReport, domain: str,
    ) -> TargetResult:
        """Найти или создать TargetResult для домена."""
        for tr in report.targets:
            if tr.domain == domain:
                return tr
        tr = TargetResult(domain=domain)
        report.targets.append(tr)
        return tr

    @staticmethod
    def _count_phases(mode: str) -> int:
        """Количество фаз для данного режима."""
        if mode == RunMode.QUICK:
            return 2    # TLS + Ping
        if mode == RunMode.DPI_ONLY:
            return 4    # DNS + TLS + ISP + TCP
        return 6        # DNS + TLS + ISP + TCP + STUN + Ping

    def _build_summary_stats(self, report: BlockcheckReport) -> dict[str, Any]:
        """Построить статистику по отчёту."""
        stats: dict[str, int] = {
            "http_ok": 0, "http_fail": 0,
            "tls12_ok": 0, "tls12_fail": 0,
            "tls13_ok": 0, "tls13_fail": 0,
            "stun_ok": 0, "stun_fail": 0,
            "ping_ok": 0, "ping_fail": 0,
            "dns_ok": 0, "dns_fail": 0,
            "isp_ok": 0, "isp_inject": 0,
            "tcp_ok": 0, "tcp_block": 0,
            "dpi_count": 0,
        }

        for tr in report.targets:
            for t in tr.results:
                ok = (t.status == TestStatus.SUCCESS.value)
                tt = t.test_type

                if tt == TestType.HTTP.value:
                    stats["http_ok" if ok else "http_fail"] += 1
                elif tt == TestType.TLS_12.value:
                    stats["tls12_ok" if ok else "tls12_fail"] += 1
                elif tt == TestType.TLS_13.value:
                    stats["tls13_ok" if ok else "tls13_fail"] += 1
                elif tt == TestType.STUN.value:
                    stats["stun_ok" if ok else "stun_fail"] += 1
                elif tt == TestType.PING.value:
                    stats["ping_ok" if ok else "ping_fail"] += 1
                elif tt == TestType.DNS.value:
                    stats["dns_ok" if ok else "dns_fail"] += 1
                elif tt in (TestType.ISP_DETECT.value,
                            TestType.HTTP_INJECT.value):
                    stats["isp_ok" if ok else "isp_inject"] += 1
                elif tt == TestType.TCP_16_20.value:
                    stats["tcp_ok" if ok else "tcp_block"] += 1

        stats["dpi_count"] = sum(
            1 for tr in report.targets
            if (tr.dpi_classification
                and tr.dpi_classification != DPIClassification.NONE.value)
        )

        return stats


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[BlockcheckRunner] = None
_instance_lock = threading.Lock()


def get_blockcheck_runner() -> BlockcheckRunner:
    """Получить singleton-экземпляр BlockcheckRunner."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = BlockcheckRunner()
    return _instance
