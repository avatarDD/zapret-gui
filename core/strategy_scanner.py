# core/strategy_scanner.py
"""
Strategy Scanner — автоматический перебор стратегий обхода DPI.

Для каждой стратегии из INI-каталога:
  1. Применяет iptables/nftables через FirewallManager
  2. Запускает nfqws2 через NFQWSManager
  3. Ждёт стабилизации
  4. Тестирует доступность (TLS / STUN)
  5. Останавливает nfqws2
  6. Снимает правила firewall
  7. Записывает результат

Безопасность: try/finally на КАЖДОМ шаге, mutex, восстановление
состояния после завершения/ошибки/отмены.

Использование:
    from core.strategy_scanner import get_strategy_scanner

    scanner = get_strategy_scanner()
    scanner.start(target='youtube.com', protocol='tcp', mode='quick')

    status = scanner.get_status()
    # {"status": "running", "progress": 5, "total": 30, ...}

    report = scanner.get_results()
    # StrategyScanReport
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Optional

from core.log_buffer import log
from core.models import (
    CatalogEntry,
    SingleTestResult,
    StrategyProbeResult,
    StrategyScanReport,
    TestStatus,
)


# ═══════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════

# Таймауты (увеличены для роутера)
STABILIZATION_DELAY = 2.0       # Ожидание после запуска nfqws2
PROBE_TIMEOUT = 10              # Таймаут проверки TLS/STUN
STUN_PROBE_TIMEOUT = 5          # Таймаут STUN-пробы
KILL_TIMEOUT = 4                # Ожидание остановки nfqws2
INTER_STRATEGY_DELAY = 0.5     # Пауза между стратегиями

# Resume state
RESUME_FILE = "/tmp/zapret-gui-scan-resume.json"

# Scan status
STATUS_IDLE = "idle"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"
STATUS_CANCELLED = "cancelled"


# ═══════════════════════════════════════════════════════════
#  StrategyScanner
# ═══════════════════════════════════════════════════════════

class StrategyScanner:
    """
    Автоматический перебор стратегий обхода DPI.

    Использует существующие менеджеры:
    - NFQWSManager для запуска/остановки nfqws2
    - FirewallManager для применения/снятия правил iptables/nftables
    - CatalogManager для получения стратегий из INI-каталогов
    - TLS/STUN тестеры для проверки доступности

    Singleton: get_strategy_scanner()
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._status = STATUS_IDLE
        self._cancelled = False
        self._thread: Optional[threading.Thread] = None

        # Progress tracking
        self._progress = 0
        self._total = 0
        self._current_strategy_name = ""
        self._phase = ""

        # Results
        self._results: list[StrategyProbeResult] = []
        self._report: Optional[StrategyScanReport] = None

        # Parameters of current/last scan
        self._target = ""
        self._protocol = "tcp"
        self._mode = "quick"
        self._start_index = 0

        # Saved state (for restoring nfqws after scan)
        self._saved_nfqws_running = False
        self._saved_nfqws_args: list[str] = []
        self._saved_firewall_applied = False

        # Callback
        self._callback: Optional[Callable] = None

        # Error message
        self._error = ""

    # ─────────────────── Public API ───────────────────

    def start(
        self,
        target: str = "youtube.com",
        protocol: str = "tcp",
        mode: str = "quick",
        start_index: int = 0,
        callback: Optional[Callable] = None,
    ) -> bool:
        """
        Запустить сканирование стратегий в фоновом потоке.

        Args:
            target:      Домен для проверки (напр. 'youtube.com').
            protocol:    'tcp' или 'udp'.
            mode:        'quick' (~30), 'standard' (~80), 'full' (все).
            start_index: Индекс для resume (0 = начало).
            callback:    Опциональный callable(event_type, data).

        Returns:
            True если сканирование запущено.
        """
        with self._lock:
            if self._status == STATUS_RUNNING:
                log.warning(
                    "Сканирование уже запущено",
                    source="scanner",
                )
                return False

            # Reset state
            self._cancelled = False
            self._status = STATUS_RUNNING
            self._progress = 0
            self._total = 0
            self._current_strategy_name = ""
            self._phase = "Подготовка"
            self._results = []
            self._report = None
            self._error = ""

            self._target = target.strip() or "youtube.com"
            self._protocol = protocol.strip().lower() or "tcp"
            self._mode = mode.strip().lower() or "quick"
            self._start_index = max(0, int(start_index))
            self._callback = callback

        log.info(
            "Запуск сканирования: target=%s, protocol=%s, mode=%s"
            % (self._target, self._protocol, self._mode),
            source="scanner",
        )

        self._thread = threading.Thread(
            target=self._run_scan,
            daemon=True,
            name="strategy-scanner",
        )
        self._thread.start()
        return True

    def stop(self) -> bool:
        """
        Остановить текущее сканирование.

        Returns:
            True если команда принята.
        """
        with self._lock:
            if self._status != STATUS_RUNNING:
                return False
            self._cancelled = True

        log.info("Запрос на остановку сканирования", source="scanner")
        return True

    def get_status(self) -> dict[str, Any]:
        """
        Текущий статус для API polling.

        Returns:
            dict с полями: status, progress, total, phase,
            current_strategy, target, protocol, mode, error,
            working_count, failed_count.
        """
        with self._lock:
            working = [r for r in self._results if r.success]
            failed = [r for r in self._results if not r.success]

            return {
                "status": self._status,
                "progress": self._progress,
                "total": self._total,
                "phase": self._phase,
                "current_strategy": self._current_strategy_name,
                "target": self._target,
                "protocol": self._protocol,
                "mode": self._mode,
                "error": self._error,
                "working_count": len(working),
                "failed_count": len(failed),
            }

    def get_results(self) -> Optional[StrategyScanReport]:
        """Получить результаты последнего сканирования."""
        return self._report

    def get_working_strategies(self) -> list[dict[str, Any]]:
        """Получить список работающих стратегий."""
        return [r.to_dict() for r in self._results if r.success]

    def get_resume_index(self) -> int:
        """Получить индекс для resume из сохранённого состояния."""
        return self._load_resume_state()

    def apply_strategy(self, index: int) -> bool:
        """
        Применить найденную стратегию по индексу в результатах.

        Создаёт user-стратегию в JSON-формате и применяет.

        Args:
            index: Индекс в списке working_strategies.

        Returns:
            True если стратегия применена.
        """
        working = [r for r in self._results if r.success]
        if index < 0 or index >= len(working):
            log.error(
                "Неверный индекс стратегии: %d (доступно: %d)"
                % (index, len(working)),
                source="scanner",
            )
            return False

        probe_result = working[index]
        return self._apply_probe_result(probe_result)

    def apply_strategy_by_id(self, strategy_id: str) -> bool:
        """
        Применить найденную стратегию по strategy_id.

        Args:
            strategy_id: ID стратегии из каталога.

        Returns:
            True если стратегия применена.
        """
        for r in self._results:
            if r.success and r.strategy_id == strategy_id:
                return self._apply_probe_result(r)

        log.error(
            "Стратегия не найдена или не рабочая: %s" % strategy_id,
            source="scanner",
        )
        return False

    # ─────────────────── Main scan loop ───────────────────

    def _run_scan(self) -> None:
        """Главный цикл сканирования (выполняется в фоновом потоке)."""
        started_at = time.time()

        try:
            # 1. Сохраняем текущее состояние nfqws/firewall
            self._save_current_state()

            # 2. Загружаем стратегии из каталога
            strategies = self._select_strategies()
            if not strategies:
                self._set_error("Нет доступных стратегий для сканирования")
                return

            with self._lock:
                self._total = len(strategies)

            log.info(
                "Загружено %d стратегий (%s/%s)"
                % (len(strategies), self._protocol, self._mode),
                source="scanner",
            )

            # 3. Останавливаем текущий nfqws2 если запущен
            self._stop_current_nfqws()

            # 4. Baseline тест (без обхода)
            self._set_phase("Baseline-тест")
            baseline_accessible = self._run_baseline_test()

            if baseline_accessible:
                log.warning(
                    "Ресурс %s ДОСТУПЕН без обхода — результаты "
                    "могут быть ложноположительными" % self._target,
                    source="scanner",
                )

            # 5. Перебор стратегий
            self._set_phase("Сканирование стратегий")

            for idx, entry in enumerate(strategies):
                if self._cancelled:
                    break

                actual_idx = self._start_index + idx
                with self._lock:
                    self._progress = idx + 1
                    self._current_strategy_name = entry.name

                self._emit_callback(
                    "strategy_start",
                    {
                        "index": actual_idx,
                        "total": self._total,
                        "name": entry.name,
                    },
                )

                log.info(
                    "[%d/%d] Тестирование: %s"
                    % (idx + 1, self._total, entry.name),
                    source="scanner",
                )

                # Пробуем одну стратегию
                result = self._probe_one_strategy(entry, actual_idx)

                with self._lock:
                    self._results.append(result)

                self._emit_callback("strategy_result", result.to_dict())

                if result.success:
                    log.success(
                        "  УСПЕХ: %s (%.0f ms)" % (entry.name, result.latency_ms),
                        source="scanner",
                    )
                else:
                    log.debug(
                        "  НЕУДАЧА: %s — %s" % (entry.name, result.error),
                        source="scanner",
                    )

                # Сохраняем resume-state
                self._save_resume_state(actual_idx + 1)

                # Пауза между стратегиями
                if not self._cancelled and idx < len(strategies) - 1:
                    time.sleep(INTER_STRATEGY_DELAY)

            # 6. Формируем отчёт
            finished_at = time.time()
            self._build_report(
                started_at, finished_at, baseline_accessible,
            )

            with self._lock:
                if self._cancelled:
                    self._status = STATUS_CANCELLED
                    self._phase = "Отменено"
                else:
                    self._status = STATUS_COMPLETED
                    self._phase = "Завершено"

            working_count = len([r for r in self._results if r.success])
            total_tested = len(self._results)
            elapsed = finished_at - started_at

            if self._cancelled:
                log.warning(
                    "Сканирование отменено. Протестировано: %d/%d, "
                    "рабочих: %d (%.1f сек)"
                    % (total_tested, self._total, working_count, elapsed),
                    source="scanner",
                )
            else:
                log.success(
                    "Сканирование завершено. Протестировано: %d/%d, "
                    "рабочих: %d (%.1f сек)"
                    % (total_tested, self._total, working_count, elapsed),
                    source="scanner",
                )

            self._emit_callback(
                "complete",
                self._report.to_dict() if self._report else {},
            )

        except Exception as e:
            log.error(
                "Критическая ошибка сканирования: %s" % e,
                source="scanner",
            )
            self._set_error(str(e))

        finally:
            # КРИТИЧЕСКИ ВАЖНО: гарантируем cleanup
            self._ensure_cleanup()

            # Восстанавливаем предыдущее состояние nfqws
            self._restore_previous_state()

            # Удаляем resume file при успешном завершении
            if not self._cancelled:
                self._remove_resume_state()

    # ─────────────────── Strategy selection ───────────────────

    def _select_strategies(self) -> list[CatalogEntry]:
        """
        Выбрать стратегии из каталога по режиму и протоколу.

        Returns:
            Список CatalogEntry для тестирования.
        """
        from core.catalog_loader import get_catalog_manager

        cm = get_catalog_manager()
        protocol = self._protocol

        if self._mode == "quick":
            entries = cm.get_quick_set(protocol=protocol)
        elif self._mode == "standard":
            entries = cm.get_standard_set(protocol=protocol)
        else:  # full
            entries = cm.get_full_set(protocol=protocol)

        # Применяем start_index для resume
        if self._start_index > 0 and self._start_index < len(entries):
            entries = entries[self._start_index:]
            log.info(
                "Resume: начинаем с индекса %d" % self._start_index,
                source="scanner",
            )

        return entries

    # ─────────────────── Probe one strategy ───────────────────

    def _probe_one_strategy(
        self,
        entry: CatalogEntry,
        index: int,
    ) -> StrategyProbeResult:
        """
        Тестирование одной стратегии: firewall → nfqws2 → probe → cleanup.

        Каждый шаг обёрнут в try/finally для гарантированного cleanup.

        Args:
            entry: Запись каталога стратегий.
            index: Глобальный индекс стратегии.

        Returns:
            StrategyProbeResult.
        """
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        nfqws = get_nfqws_manager()
        fw = get_firewall_manager()

        start_time = time.time()
        nfqws_started = False
        fw_applied = False

        try:
            # 1. Собираем аргументы из CatalogEntry
            args = self._build_strategy_args(entry)

            if not args:
                return StrategyProbeResult(
                    strategy_id=entry.section_id,
                    strategy_name=entry.name,
                    target=self._target,
                    success=False,
                    latency_ms=0.0,
                    error="NO_ARGS",
                    protocol=self._protocol,
                )

            log.debug(
                "  args: %s" % " ".join(args[:5]),
                source="scanner",
            )

            # 2. Применяем правила firewall
            if not fw.apply_rules():
                return StrategyProbeResult(
                    strategy_id=entry.section_id,
                    strategy_name=entry.name,
                    target=self._target,
                    success=False,
                    latency_ms=0.0,
                    error="FW_FAIL",
                    protocol=self._protocol,
                    raw_data={"detail": "Не удалось применить firewall"},
                )

            fw_applied = True

            # 3. Запускаем nfqws2
            if not nfqws.start(args):
                return StrategyProbeResult(
                    strategy_id=entry.section_id,
                    strategy_name=entry.name,
                    target=self._target,
                    success=False,
                    latency_ms=0.0,
                    error="NFQWS_FAIL",
                    protocol=self._protocol,
                    raw_data={"detail": "Не удалось запустить nfqws2"},
                )

            nfqws_started = True

            # 4. Ждём стабилизации
            stabilization = self._get_stabilization_delay()
            time.sleep(stabilization)

            # 5. Проверяем что nfqws2 ещё жив
            if not nfqws.is_running():
                exit_code = nfqws.get_exit_code()
                return StrategyProbeResult(
                    strategy_id=entry.section_id,
                    strategy_name=entry.name,
                    target=self._target,
                    success=False,
                    latency_ms=0.0,
                    error="NFQWS_CRASHED",
                    protocol=self._protocol,
                    raw_data={
                        "detail": "nfqws2 завершился (exit=%s)"
                        % str(exit_code),
                    },
                )

            # 6. Проба доступности
            if self._protocol == "udp":
                probe_result = self._probe_stun()
            else:
                probe_result = self._probe_tls()

            elapsed_ms = (time.time() - start_time) * 1000

            # 7. Формируем результат
            success = probe_result.status == TestStatus.SUCCESS.value

            return StrategyProbeResult(
                strategy_id=entry.section_id,
                strategy_name=entry.name,
                target=self._target,
                success=success,
                latency_ms=round(probe_result.latency_ms, 2),
                error="" if success else (probe_result.error or probe_result.details),
                http_code=probe_result.raw_data.get("status_code", 0)
                    if success else 0,
                protocol=self._protocol,
                raw_data={
                    "test_type": probe_result.test_type,
                    "details": probe_result.details,
                    "args_preview": " ".join(args[:3]) + "..."
                        if len(args) > 3 else " ".join(args),
                },
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            log.error(
                "Ошибка пробы стратегии %s: %s" % (entry.name, e),
                source="scanner",
            )
            return StrategyProbeResult(
                strategy_id=entry.section_id,
                strategy_name=entry.name,
                target=self._target,
                success=False,
                latency_ms=round(elapsed_ms, 2),
                error="EXCEPTION",
                protocol=self._protocol,
                raw_data={"detail": str(e)[:200]},
            )

        finally:
            # КРИТИЧНО: гарантируем cleanup после каждой стратегии
            try:
                if nfqws_started:
                    nfqws.stop()
            except Exception as e:
                log.warning(
                    "Ошибка остановки nfqws2: %s" % e,
                    source="scanner",
                )

            try:
                if fw_applied:
                    fw.remove_rules()
            except Exception as e:
                log.warning(
                    "Ошибка снятия firewall: %s" % e,
                    source="scanner",
                )

    # ─────────────────── Args builder ───────────────────

    def _build_strategy_args(self, entry: CatalogEntry) -> list[str]:
        """
        Собрать аргументы nfqws2 из записи каталога.

        Включает:
        - Аргументы стратегии из CatalogEntry.args
        - Резолвинг путей (@lua/, lists/)
        - Фильтры по протоколу (--filter-tcp/--filter-udp)

        Базовые аргументы (--user, --fwmark, --qnum, --lua-init)
        добавляются автоматически NFQWSManager._build_base_args().

        Returns:
            list[str] аргументов для NFQWSManager.start().
        """
        from core.catalog_loader import CatalogManager
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        lua_path = cfg.get("zapret", "lua_path", default="/opt/zapret2/lua")
        lists_path = cfg.get("zapret", "lists_path",
                             default="/opt/zapret2/lists")

        # Получаем аргументы из записи каталога
        raw_args = CatalogManager.build_nfqws_args_from_entry(entry)

        if not raw_args:
            return []

        # Резолвим пути (@lua/ → /opt/zapret2/lua/, lists/ → ...)
        resolved = CatalogManager.resolve_paths_in_args(
            raw_args,
            lua_path=lua_path,
            lists_path=lists_path,
        )

        # Добавляем фильтры протокола если их нет в аргументах стратегии
        has_filter = any(
            a.startswith("--filter-tcp") or a.startswith("--filter-udp")
            for a in resolved
        )

        if not has_filter:
            if self._protocol == "udp":
                resolved = ["--filter-udp=443"] + resolved
            else:
                resolved = ["--filter-tcp=443"] + resolved

        # Добавляем hostlist если его нет
        has_hostlist = any(
            a.startswith("--hostlist=") or a.startswith("--hostlist-exclude=")
            for a in resolved
        )

        if not has_hostlist:
            hostlist_path = os.path.join(lists_path, "other.txt")
            if os.path.isfile(hostlist_path):
                # Вставляем после --filter-*
                insert_pos = 0
                for i, a in enumerate(resolved):
                    if a.startswith("--filter-"):
                        insert_pos = i + 1
                resolved.insert(insert_pos, "--hostlist=%s" % hostlist_path)

        return resolved

    # ─────────────────── Probe tests ───────────────────

    def _probe_tls(self) -> SingleTestResult:
        """Проверить доступность по TLS/HTTPS."""
        from core.testers.tls_tester import test_tls

        return test_tls(
            host=self._target,
            port=443,
            timeout=PROBE_TIMEOUT,
        )

    def _probe_stun(self) -> SingleTestResult:
        """Проверить доступность по STUN/UDP."""
        from core.testers.stun_tester import test_stun

        # Парсим target (может быть host:port)
        host = self._target
        port = 19302

        if ":" in self._target and not self._target.startswith("["):
            parts = self._target.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    port = int(parts[1])
                    host = parts[0]
                except ValueError:
                    pass

        return test_stun(
            host=host,
            port=port,
            timeout=STUN_PROBE_TIMEOUT,
        )

    # ─────────────────── Baseline test ───────────────────

    def _run_baseline_test(self) -> bool:
        """
        Baseline-тест: проверить ресурс БЕЗ обхода.

        Returns:
            True если ресурс уже доступен (не заблокирован).
        """
        log.info(
            "Baseline-тест: %s (%s)" % (self._target, self._protocol),
            source="scanner",
        )

        self._emit_callback("phase", {"phase": "Baseline-тест"})

        if self._protocol == "udp":
            result = self._probe_stun()
        else:
            result = self._probe_tls()

        is_accessible = result.status == TestStatus.SUCCESS.value

        if is_accessible:
            log.warning(
                "Baseline: %s доступен без обхода (%.0f ms)"
                % (self._target, result.latency_ms),
                source="scanner",
            )
        else:
            log.info(
                "Baseline: %s заблокирован — %s"
                % (self._target, result.error or result.details),
                source="scanner",
            )

        return is_accessible

    # ─────────────────── State save/restore ───────────────────

    def _save_current_state(self) -> None:
        """
        Сохранить текущее состояние nfqws2 и firewall
        для восстановления после сканирования.
        """
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        nfqws = get_nfqws_manager()
        fw = get_firewall_manager()

        self._saved_nfqws_running = nfqws.is_running()
        self._saved_nfqws_args = nfqws.get_last_args()
        self._saved_firewall_applied = fw.is_applied()

        if self._saved_nfqws_running:
            log.info(
                "Сохранено состояние: nfqws2 запущен (PID %s)"
                % nfqws.get_pid(),
                source="scanner",
            )

    def _stop_current_nfqws(self) -> None:
        """Остановить текущий nfqws2 перед сканированием."""
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        nfqws = get_nfqws_manager()
        fw = get_firewall_manager()

        if nfqws.is_running():
            log.info(
                "Останавливаем текущий nfqws2 для сканирования",
                source="scanner",
            )
            nfqws.stop()

        if fw.is_applied():
            fw.remove_rules()

        time.sleep(0.5)

    def _restore_previous_state(self) -> None:
        """
        Восстановить предыдущее состояние nfqws2 и firewall
        после завершения сканирования.
        """
        if not self._saved_nfqws_running:
            return

        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        log.info(
            "Восстанавливаем предыдущее состояние nfqws2",
            source="scanner",
        )

        try:
            fw = get_firewall_manager()
            nfqws = get_nfqws_manager()

            if self._saved_firewall_applied:
                fw.apply_rules()

            if self._saved_nfqws_args:
                nfqws.start(self._saved_nfqws_args)
            else:
                nfqws.start()

            log.success(
                "Предыдущее состояние восстановлено",
                source="scanner",
            )

        except Exception as e:
            log.error(
                "Ошибка восстановления состояния: %s" % e,
                source="scanner",
            )

    def _ensure_cleanup(self) -> None:
        """
        Гарантированная очистка: остановка nfqws2 и снятие firewall.

        Вызывается в finally блоке главного цикла.
        """
        try:
            from core.nfqws_manager import get_nfqws_manager
            nfqws = get_nfqws_manager()
            if nfqws.is_running():
                nfqws.stop()
        except Exception as e:
            log.warning(
                "Cleanup: ошибка остановки nfqws2: %s" % e,
                source="scanner",
            )

        try:
            from core.firewall import get_firewall_manager
            fw = get_firewall_manager()
            fw.remove_rules()
        except Exception as e:
            log.warning(
                "Cleanup: ошибка снятия firewall: %s" % e,
                source="scanner",
            )

    # ─────────────────── Resume state ───────────────────

    def _save_resume_state(self, next_index: int) -> None:
        """Сохранить позицию для resume в /tmp/."""
        state = {
            "target": self._target,
            "protocol": self._protocol,
            "mode": self._mode,
            "next_index": next_index,
            "timestamp": time.time(),
            "working_count": len(
                [r for r in self._results if r.success]
            ),
        }

        try:
            with open(RESUME_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
        except (IOError, OSError):
            pass  # /tmp/ может быть недоступен — не критично

    def _load_resume_state(self) -> int:
        """
        Загрузить позицию resume.

        Returns:
            Индекс следующей стратегии (0 если нет данных).
        """
        try:
            if not os.path.exists(RESUME_FILE):
                return 0
            with open(RESUME_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            return int(state.get("next_index", 0))
        except (IOError, OSError, json.JSONDecodeError, ValueError):
            return 0

    def _remove_resume_state(self) -> None:
        """Удалить файл resume state."""
        try:
            if os.path.exists(RESUME_FILE):
                os.remove(RESUME_FILE)
        except OSError:
            pass

    # ─────────────────── Report builder ───────────────────

    def _build_report(
        self,
        started_at: float,
        finished_at: float,
        baseline_accessible: bool,
    ) -> None:
        """Сформировать итоговый отчёт."""
        working = [r for r in self._results if r.success]

        # Лучшая стратегия = минимальная latency
        best: Optional[StrategyProbeResult] = None
        if working:
            best = min(working, key=lambda r: r.latency_ms)

        self._report = StrategyScanReport(
            target=self._target,
            protocol=self._protocol,
            mode=self._mode,
            results=list(self._results),
            best_strategy=best,
            total_tested=len(self._results),
            total_available=self._total + self._start_index,
            started_at=started_at,
            finished_at=finished_at,
            cancelled=self._cancelled,
            baseline_accessible=baseline_accessible,
        )

    # ─────────────────── Apply strategy ───────────────────

    def _apply_probe_result(self, probe_result: StrategyProbeResult) -> bool:
        """
        Применить стратегию из результата пробы.

        Создаёт user-стратегию в JSON-формате через StrategyManager
        и применяет её (start nfqws2 + apply firewall).

        Args:
            probe_result: Результат успешной пробы.

        Returns:
            True если стратегия применена.
        """
        from core.catalog_loader import get_catalog_manager
        from core.strategy_builder import get_strategy_manager
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        # Находим оригинальную запись каталога
        cm = get_catalog_manager()
        entry = cm.get_entry_by_id(
            probe_result.strategy_id,
            protocol=probe_result.protocol,
        )

        if entry is None:
            log.error(
                "Запись каталога не найдена: %s" % probe_result.strategy_id,
                source="scanner",
            )
            return False

        # Собираем аргументы
        args = self._build_strategy_args(entry)
        if not args:
            log.error(
                "Не удалось собрать аргументы для: %s"
                % probe_result.strategy_name,
                source="scanner",
            )
            return False

        # Создаём user-стратегию в JSON-формате
        sm = get_strategy_manager()
        strategy_data = {
            "id": "scan_%s" % entry.section_id,
            "name": "[Scan] %s" % entry.name,
            "description": "Найдена сканером: %s (%s, %.0f ms)"
                % (entry.name, entry.source_file, probe_result.latency_ms),
            "type": "combined",
            "version": 1,
            "profiles": [
                {
                    "id": "main",
                    "name": entry.name,
                    "enabled": True,
                    "args": " ".join(args),
                }
            ],
        }

        saved = sm.save_user_strategy(strategy_data)
        if not saved:
            log.error(
                "Не удалось сохранить стратегию: %s" % entry.name,
                source="scanner",
            )
            return False

        # Применяем: firewall + nfqws2
        try:
            fw = get_firewall_manager()
            nfqws = get_nfqws_manager()

            # Останавливаем текущий nfqws если запущен
            if nfqws.is_running():
                nfqws.stop()
                time.sleep(0.3)

            # Применяем firewall
            if not fw.apply_rules():
                log.error("Не удалось применить firewall", source="scanner")
                return False

            # Запускаем nfqws2 с новой стратегией
            if not nfqws.start(args):
                log.error("Не удалось запустить nfqws2", source="scanner")
                fw.remove_rules()
                return False

            # Обновляем конфиг
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            cfg.set("strategy", "current_id", saved["id"])
            cfg.set("strategy", "current_name", saved["name"])
            cfg.save()

            log.success(
                "Стратегия применена: %s" % entry.name,
                source="scanner",
            )
            return True

        except Exception as e:
            log.error(
                "Ошибка применения стратегии: %s" % e,
                source="scanner",
            )
            return False

    # ─────────────────── Helpers ───────────────────

    def _set_phase(self, phase: str) -> None:
        """Установить текущую фазу."""
        with self._lock:
            self._phase = phase
        self._emit_callback("phase", {"phase": phase})

    def _set_error(self, error: str) -> None:
        """Установить ошибку и статус ERROR."""
        with self._lock:
            self._status = STATUS_ERROR
            self._error = error
            self._phase = "Ошибка"
        log.error("Scanner error: %s" % error, source="scanner")

    def _emit_callback(self, event_type: str, data: Any) -> None:
        """Вызвать callback если установлен."""
        if self._callback:
            try:
                self._callback(event_type, data)
            except Exception:
                pass  # Callback не должен прерывать сканирование

    def _get_stabilization_delay(self) -> float:
        """Получить время стабилизации из конфига."""
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            delay = cfg.get("scan", "stabilization_delay", default=None)
            if delay is not None:
                return float(delay)
        except (ValueError, TypeError):
            pass
        return STABILIZATION_DELAY


# ═══════════════════════════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════════════════════════

_scanner: Optional[StrategyScanner] = None
_scanner_lock = threading.Lock()


def get_strategy_scanner() -> StrategyScanner:
    """Получить глобальный экземпляр StrategyScanner."""
    global _scanner
    if _scanner is None:
        with _scanner_lock:
            if _scanner is None:
                _scanner = StrategyScanner()
    return _scanner
