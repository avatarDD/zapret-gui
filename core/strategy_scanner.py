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

# Таймауты (значения по умолчанию; могут быть переопределены в конфиге).
# Раньше PROBE_TIMEOUT был 10с — это и было главной причиной «медленно»:
# каждая неудачная стратегия съедала весь TLS-таймаут.
STABILIZATION_DELAY = 1.0       # Ожидание после запуска nfqws2
PROBE_TIMEOUT = 6               # Таймаут TLS handshake
BODY_PROBE_TIMEOUT = 8          # Таймаут body-загрузки (>=64 KB)
STUN_PROBE_TIMEOUT = 4          # Таймаут STUN-пробы (UDP)
KILL_TIMEOUT = 4                # Ожидание остановки nfqws2
INTER_STRATEGY_DELAY = 0.3      # Пауза между стратегиями
BODY_PROBE_MIN_BYTES = 65_536   # Минимум для прохождения 16-20 KB барьера

# Сколько раз повторить запуск nfqws2, если он мгновенно упал/крашнулся
# (гонка с conntrack/NFQUEUE bind или флапающий fwmark).
NFQWS_CRASH_RETRIES = 2
NFQWS_CRASH_BACKOFF = 1.0       # пауза между попытками

# Tmp hostlist для приёмов (basic/advanced/direct), обогащённый доменами
# цели. nfqws2 матчит SNI/Host строго по записям; без них десинк
# не применяется к трафику цели и проба всегда падает.
TMP_HOSTLIST_PATH = "/tmp/zapret-gui-scan-target.txt"

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
        # Профиль цели (см. core/scan_targets.py)
        self._scan_profile = None  # type: ignore[var-annotated]
        # Путь временного hostlist'а для приёмов (создаётся в _run_scan)
        self._tmp_hostlist: Optional[str] = None

        # Saved state (for restoring nfqws after scan)
        self._saved_nfqws_running = False
        self._saved_nfqws_args: list[str] = []
        self._saved_firewall_applied = False

        # Baseline-aware фильтрация: { "ipv4": True/False, "ipv6": True/False }.
        # True = ресурс уже доступен без обхода → стратегии «успехи» по этому AF
        # не зачитываются как фикс блока (см. _deep_probe).
        self._baseline_by_af: dict[str, bool] = {}
        self._baseline_open: bool = False

        # Callback
        self._callback: Optional[Callable] = None

        # Error message
        self._error = ""

        # Timing
        self._started_at: float = 0.0

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
            self._started_at = time.time()

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
            working_count, failed_count, success_rate, elapsed_seconds.
        """
        with self._lock:
            working = [r for r in self._results if r.success]
            failed = [r for r in self._results if not r.success]
            total_done = len(self._results)

            # Процент успешности
            success_rate = round(
                len(working) / total_done * 100, 1
            ) if total_done > 0 else 0.0

            # Elapsed
            elapsed = 0.0
            if self._started_at > 0:
                if self._status == STATUS_RUNNING:
                    elapsed = round(time.time() - self._started_at, 1)
                elif self._report:
                    elapsed = round(
                        self._report.finished_at - self._report.started_at, 1
                    )

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
                "success_rate": success_rate,
                "elapsed_seconds": elapsed,
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

            # 1a. Готовим профиль цели + tmp hostlist для приёмов
            from core.scan_targets import detect_target
            self._scan_profile = detect_target(self._target)
            self._ensure_tmp_hostlist()
            log.info(
                "Профиль цели: %s, тестовых хостов: %d, hostlist в %s"
                % (self._scan_profile.key,
                   len(self._scan_profile.test_hosts) + 1,
                   self._tmp_hostlist or "—"),
                source="scanner",
            )

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

                # --- Подробный лог параметров стратегии ---
                args_list = entry.get_args_list()
                args_display = " ".join(args_list)
                log.info(
                    "[%d/%d] Тестирование: %s (каталог: %s, уровень: %s)"
                    % (idx + 1, self._total, entry.name,
                       entry.source_file, entry.level),
                    source="scanner",
                )
                log.debug(
                    "  Параметры стратегии: %s" % args_display,
                    source="scanner",
                )
                if entry.blobs:
                    log.debug(
                        "  Блобы: %s" % ", ".join(entry.blobs),
                        source="scanner",
                    )

                # Пробуем одну стратегию
                probe_start = time.time()
                result = self._probe_one_strategy(entry, actual_idx)
                probe_elapsed = time.time() - probe_start

                with self._lock:
                    self._results.append(result)

                self._emit_callback("strategy_result", result.to_dict())

                # --- Подробный лог результата ---
                working_count = len(
                    [r for r in self._results if r.success]
                )
                failed_count = len(
                    [r for r in self._results if not r.success]
                )
                total_done = working_count + failed_count
                success_rate = round(
                    working_count / total_done * 100, 1
                ) if total_done > 0 else 0.0

                if result.success:
                    log.success(
                        "  ✓ УСПЕХ: %s — %.0f ms (latency), "
                        "проба %.1f с | Итого: %d/%d рабочих (%.1f%%)"
                        % (entry.name, result.latency_ms, probe_elapsed,
                           working_count, total_done, success_rate),
                        source="scanner",
                    )
                else:
                    log.info(
                        "  ✗ НЕУДАЧА: %s — %s (%.1f с) | "
                        "Итого: %d/%d рабочих (%.1f%%)"
                        % (entry.name,
                           result.error or "unknown",
                           probe_elapsed,
                           working_count, total_done, success_rate),
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
            final_rate = round(
                working_count / total_tested * 100, 1
            ) if total_tested > 0 else 0.0

            if self._cancelled:
                log.warning(
                    "Сканирование отменено. Протестировано: %d/%d, "
                    "рабочих: %d (%.1f%%), время: %.1f сек"
                    % (total_tested, self._total, working_count,
                       final_rate, elapsed),
                    source="scanner",
                )
            else:
                log.success(
                    "═══ Сканирование завершено ═══\n"
                    "  Протестировано: %d/%d стратегий\n"
                    "  Рабочих: %d (%.1f%%)\n"
                    "  Лучшая: %s (%.0f ms)\n"
                    "  Время: %.1f сек"
                    % (total_tested, self._total, working_count,
                       final_rate,
                       (self._report.best_strategy.strategy_name
                        if self._report and self._report.best_strategy
                        else "—"),
                       (self._report.best_strategy.latency_ms
                        if self._report and self._report.best_strategy
                        else 0),
                       elapsed),
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

            # Удаляем временный hostlist
            self._remove_tmp_hostlist()

            # Восстанавливаем предыдущее состояние nfqws
            self._restore_previous_state()

            # Удаляем resume file при успешном завершении
            if not self._cancelled:
                self._remove_resume_state()

    # ─────────────────── Strategy selection ───────────────────

    def _select_strategies(self) -> list[CatalogEntry]:
        """
        Выбрать стратегии из каталога по режиму и протоколу.

        Порядок: сначала full-presets (level=builtin) — у них собственные
        --filter-*/--hostlist=, шанс успеха высокий; затем «приёмы»
        (basic/advanced/direct), которые сканер обогащает шаблоном цели.

        Returns:
            Список CatalogEntry для тестирования.
        """
        from core.catalog_loader import get_catalog_manager

        cm = get_catalog_manager()
        protocol = self._protocol

        # quick/standard/full — отбираем кандидатов из каталога
        if self._mode == "quick":
            entries = cm.get_quick_set(protocol=protocol)
        elif self._mode == "standard":
            entries = cm.get_standard_set(protocol=protocol)
        else:  # full
            entries = cm.get_full_set(protocol=protocol)

        # quick может оказаться без builtin (label=recommended нет у
        # пресетов). Подставляем топ-N builtin в начало, общий размер
        # quick остаётся ~30.
        if self._mode == "quick":
            builtin_full = [
                e for e in cm.get_catalog_entries(
                    protocol=protocol, level="builtin")
                if _is_full_preset_entry(e)
            ]
            top_builtin = builtin_full[:10]
            existing_ids = {e.section_id for e in top_builtin}
            tail = [e for e in entries if e.section_id not in existing_ids]
            # Суммарно ~30: до 10 builtin + добор приёмами
            entries = top_builtin + tail[: max(20, 30 - len(top_builtin))]

        # standard — добавим побольше builtin (до 20 шт.)
        elif self._mode == "standard":
            builtin_full = [
                e for e in cm.get_catalog_entries(
                    protocol=protocol, level="builtin")
                if _is_full_preset_entry(e)
            ]
            top_builtin = builtin_full[:20]
            existing_ids = {e.section_id for e in top_builtin}
            tail = [e for e in entries if e.section_id not in existing_ids]
            entries = top_builtin + tail

        # Сортировка: full presets вперёд, recommended вторыми
        def _sort_key(e: CatalogEntry) -> tuple:
            full = _is_full_preset_entry(e)
            recommended = (e.label == "recommended")
            # 0 — самый приоритетный
            return (
                0 if full else (1 if recommended else 2),
                # внутри группы — стабильный порядок
                e.source_file,
                e.section_id,
            )

        entries.sort(key=_sort_key)

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
                    raw_data={
                        "detail": "Нет аргументов после сборки",
                        "source_file": entry.source_file,
                        "level": entry.level,
                    },
                )

            # Полная строка аргументов для лога и UI
            args_full = " ".join(args)

            log.debug(
                "  Аргументы nfqws2: %s" % args_full,
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
                    raw_data={
                        "detail": "Не удалось применить firewall",
                        "args_preview": args_full,
                        "source_file": entry.source_file,
                        "level": entry.level,
                    },
                )

            fw_applied = True

            # 3. Запускаем nfqws2 с crash-retry (гонка с conntrack/NFQUEUE bind
            #    бывает на холодном старте; ретрай через короткую паузу решает).
            stabilization = self._get_stabilization_delay()
            launch_attempts = 0
            launch_error: str | None = None
            launch_detail: str = ""

            for attempt in range(1 + NFQWS_CRASH_RETRIES):
                launch_attempts += 1

                if not nfqws.start(args):
                    launch_error = "NFQWS_FAIL"
                    launch_detail = "Не удалось запустить nfqws2"
                    nfqws_started = False
                else:
                    nfqws_started = True
                    # Ждём стабилизации и проверяем что не упал.
                    time.sleep(stabilization)
                    if nfqws.is_running():
                        launch_error = None
                        launch_detail = ""
                        break
                    exit_code = nfqws.get_exit_code()
                    launch_error = "NFQWS_CRASHED"
                    launch_detail = "nfqws2 завершился (exit=%s)" % str(exit_code)
                    nfqws_started = False

                # Не последняя попытка — короткая пауза перед ретраем
                if attempt < NFQWS_CRASH_RETRIES:
                    log.warning(
                        "nfqws2 упал на старте (%s, попытка %d/%d), повтор..."
                        % (launch_error, launch_attempts,
                           1 + NFQWS_CRASH_RETRIES),
                        source="scanner",
                    )
                    time.sleep(NFQWS_CRASH_BACKOFF)

            if launch_error is not None:
                return StrategyProbeResult(
                    strategy_id=entry.section_id,
                    strategy_name=entry.name,
                    target=self._target,
                    success=False,
                    latency_ms=0.0,
                    error=launch_error,
                    protocol=self._protocol,
                    raw_data={
                        "detail": "%s после %d попыток"
                        % (launch_detail, launch_attempts),
                        "launch_attempts": launch_attempts,
                        "args_preview": args_full,
                        "source_file": entry.source_file,
                        "level": entry.level,
                    },
                )

            # 6. Проба доступности — глубокая, с детектом 16-20 KB
            probe = self._deep_probe()

            elapsed_ms = (time.time() - start_time) * 1000

            # 7. Формируем результат
            return StrategyProbeResult(
                strategy_id=entry.section_id,
                strategy_name=entry.name,
                target=self._target,
                success=probe["success"],
                latency_ms=round(probe["latency_ms"], 2),
                error=probe["error"],
                http_code=probe["http_code"],
                protocol=self._protocol,
                throughput_kbps=probe["kbps"],
                body_passed=probe["body_passed"],
                success_rate=probe["success_rate"],
                score=probe["score"],
                raw_data={
                    "test_type": probe["test_type"],
                    "details": probe["details"],
                    "args_preview": args_full,
                    "source_file": entry.source_file,
                    "level": entry.level,
                    "label": entry.label,
                    "probe_elapsed_ms": round(elapsed_ms, 1),
                    "probe_per_host": probe["per_host"],
                    "is_full_preset": _is_full_preset_args(
                        entry.get_args_list()
                    ),
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
                raw_data={
                    "detail": str(e)[:200],
                    "source_file": entry.source_file,
                    "level": entry.level,
                },
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

        Различает два типа стратегий:

        ▸ Full preset (catalogs/builtin/* и подобные с собственными
          --filter-*/--hostlist=/--new): берём args как-есть, только
          резолвим пути @lua/, @bin/, lists/.

        ▸ Trick (catalogs/basic|advanced|direct: один-два
          --lua-desync=...): оборачиваем в шаблон цели — добавляем
          --filter-tcp/udp + порт, --filter-l7=, --payload= и --hostlist=
          с временным файлом, в котором перечислены домены цели.

        Базовые аргументы (--user, --fwmark, --qnum, --lua-init) добавляет
        NFQWSManager._build_base_args().
        """
        from core.catalog_loader import CatalogManager
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        lua_path = cfg.get("zapret", "lua_path", default="/opt/zapret2/lua")
        lists_path = cfg.get("zapret", "lists_path",
                             default="/opt/zapret2/lists")
        bin_path = cfg.get("zapret", "bin_path",
                           default="/opt/zapret2/bin")
        ipset_path = cfg.get("zapret", "ipset_path",
                             default="/opt/zapret2/ipset")

        raw_args = CatalogManager.build_nfqws_args_from_entry(entry)
        if not raw_args:
            return []

        is_full = _is_full_preset_args(raw_args)

        if is_full:
            # Полный пресет — ничего не дописываем, только резолвим пути.
            return CatalogManager.resolve_paths_in_args(
                raw_args,
                lua_path=lua_path,
                lists_path=lists_path,
                bin_path=bin_path,
                ipset_path=ipset_path,
            )

        # Trick: разворачиваем под цель
        return self._wrap_trick_args(
            raw_args,
            lua_path=lua_path,
            lists_path=lists_path,
            bin_path=bin_path,
            ipset_path=ipset_path,
        )

    def _wrap_trick_args(
        self,
        raw_args: list[str],
        *,
        lua_path: str,
        lists_path: str,
        bin_path: str,
        ipset_path: str,
    ) -> list[str]:
        """Обернуть «приём» в шаблон под self._scan_profile."""
        from core.catalog_loader import CatalogManager
        from core.scan_targets import detect_target

        profile = self._scan_profile or detect_target(self._target)

        # --filter-* + порты + l7 + payload
        if self._protocol == "udp":
            filter_arg = "--filter-udp=%s" % profile.udp_ports
            l7_arg = ("--filter-l7=%s" % profile.udp_l7) if profile.udp_l7 else ""
            payload_arg = (
                "--payload=%s" % profile.udp_payload
            ) if profile.udp_payload else ""
        else:
            filter_arg = "--filter-tcp=%s" % profile.tcp_ports
            l7_arg = ("--filter-l7=%s" % profile.tcp_l7) if profile.tcp_l7 else ""
            payload_arg = (
                "--payload=%s" % profile.tcp_payload
            ) if profile.tcp_payload else ""

        # Hostlist: tmp-файл (создан в _ensure_tmp_hostlist) с доменами цели.
        # Если по какой-то причине файла нет — пропускаем --hostlist и
        # nfqws2 будет десинхронизировать весь трафик по фильтру.
        hostlist_arg = ""
        if self._tmp_hostlist and os.path.isfile(self._tmp_hostlist):
            hostlist_arg = "--hostlist=%s" % self._tmp_hostlist

        wrapped: list[str] = []
        if filter_arg:
            wrapped.append(filter_arg)
        if l7_arg:
            wrapped.append(l7_arg)
        if hostlist_arg:
            wrapped.append(hostlist_arg)
        if payload_arg:
            wrapped.append(payload_arg)
        wrapped.extend(raw_args)

        # Резолвим пути в самих raw_args (могут содержать @lua/, @bin/, lists/)
        return CatalogManager.resolve_paths_in_args(
            wrapped,
            lua_path=lua_path,
            lists_path=lists_path,
            bin_path=bin_path,
            ipset_path=ipset_path,
        )

    # ─────────────────── Probe tests ───────────────────

    def _deep_probe(self) -> dict[str, Any]:
        """Глубокая проба: TLS gate + body-загрузка по нескольким хостам.

        Возвращает словарь с ключами:
            success, latency_ms, error, http_code,
            kbps, body_passed, success_rate, score,
            test_type, details, per_host (list[dict]).

        Алгоритм:
          1) Для каждого test_host (1 в quick, 2 в standard, все в full):
             a) TLS handshake (быстрый gate; если падает — суб-неудача).
             b) Body-загрузка ≥64 КБ — отсеиваем «псевдо-успехи»,
                когда DPI пускает первые 16-20 КБ и обрывает.
          2) Композитный score = success_rate × min(kbps, 2048) /
             max(latency_ms, 50).
        """
        from core.testers.tls_tester import test_tls
        from core.testers.body_tester import probe_body
        from core.scan_targets import detect_target

        profile = self._scan_profile or detect_target(self._target)

        # UDP: ничего лучше STUN сейчас не умеем.
        if self._protocol == "udp":
            stun = self._probe_stun()
            ok = stun.status == TestStatus.SUCCESS.value
            kbps = 0.0
            return {
                "success": ok,
                "latency_ms": stun.latency_ms,
                "error": "" if ok else (stun.error or stun.details),
                "http_code": 0,
                "kbps": kbps,
                "body_passed": False,
                "success_rate": 1.0 if ok else 0.0,
                "score": (1.0 / max(stun.latency_ms, 50.0)) * 1000.0
                         if ok else 0.0,
                "test_type": stun.test_type,
                "details": stun.details,
                "per_host": [{
                    "host": self._target,
                    "tls_ok": ok,
                    "body_ok": False,
                    "kbps": kbps,
                    "latency_ms": stun.latency_ms,
                    "details": stun.details,
                }],
            }

        # TCP: TLS + body
        hosts = self._select_test_hosts(profile)

        # Какие AF имеет смысл проверять у стратегии:
        #  - если baseline дал per-AF map — пробуем те, что были заблокированы
        #    (на доступных нет смысла — стратегия их «не починит»);
        #  - если карта пустая (нет резолва или UDP) — только ipv4 как и раньше.
        if self._baseline_by_af:
            blocked_afs = [af for af, ok in self._baseline_by_af.items()
                           if not ok]
            if not blocked_afs:
                # Все AF уже открыты на baseline — стратегия не может «починить»,
                # но всё равно прогоним один проход (чтобы не пустые результаты).
                probe_afs = ["ipv4"] if "ipv4" in self._baseline_by_af else \
                            list(self._baseline_by_af.keys())[:1]
            else:
                probe_afs = blocked_afs
        else:
            probe_afs = ["ipv4"]

        per_host: list[dict[str, Any]] = []
        sum_latency = 0.0
        sum_kbps = 0.0
        kbps_count = 0
        body_ok_count = 0
        tls_ok_count = 0
        any_http_code = 0
        # Собираем гранулярные коды ошибок — для верхнеуровневой агрегации
        sub_errors: list[str] = []

        for host in hosts:
            # Один host_entry — но с per-AF подсекциями
            host_entry: dict[str, Any] = {
                "host": host,
                "tls_ok": False,
                "body_ok": False,
                "kbps": 0.0,
                "latency_ms": 0.0,
                "details": "",
                "af_results": {},  # per-AF: {ipv4: {...}, ipv6: {...}}
            }

            best_body_kbps = 0.0
            best_body_latency = 0.0
            host_tls_ok_any = False
            host_body_ok_any = False

            for af in probe_afs:
                tls_res = test_tls(
                    host=host, port=443, timeout=PROBE_TIMEOUT,
                    ip_family=af,
                )
                # SKIPPED — этот AF не резолвится; не считаем за ошибку
                if tls_res.status == TestStatus.SKIPPED.value:
                    continue

                tls_ok = tls_res.status == TestStatus.SUCCESS.value
                af_entry: dict[str, Any] = {
                    "tls_ok": tls_ok,
                    "tls_error": tls_res.error or "",
                    "tls_details": tls_res.details,
                    "tls_latency_ms": tls_res.latency_ms,
                    "connected_ip": tls_res.raw_data.get("connected_ip", ""),
                    "body_ok": False,
                    "body_error": "",
                    "body_details": "",
                    "kbps": 0.0,
                    "bytes": 0,
                    "status_code": 0,
                    "dpi_marker": "",
                }

                if not tls_ok:
                    if tls_res.error:
                        sub_errors.append(tls_res.error)
                    host_entry["af_results"][af] = af_entry
                    continue

                host_tls_ok_any = True

                # Шаг 2: body-загрузка
                url = (profile.get_probe_url()
                       if host == profile.primary_host
                       else "https://%s/" % host)
                body = probe_body(
                    url=url,
                    min_bytes=BODY_PROBE_MIN_BYTES,
                    timeout=BODY_PROBE_TIMEOUT,
                )
                body_ok = body.status == TestStatus.SUCCESS.value
                af_entry["body_ok"] = body_ok
                af_entry["body_error"] = body.error or ""
                af_entry["body_details"] = body.details
                af_entry["kbps"] = body.raw_data.get("kbps", 0.0) or 0.0
                af_entry["bytes"] = body.raw_data.get("bytes_received", 0)
                af_entry["status_code"] = body.raw_data.get("status_code", 0)
                af_entry["dpi_marker"] = body.raw_data.get("dpi_marker", "")

                if body_ok:
                    host_body_ok_any = True
                    body_ok_count += 1
                    sum_kbps += af_entry["kbps"]
                    kbps_count += 1
                    sum_latency += body.latency_ms
                    any_http_code = af_entry["status_code"] or any_http_code
                    if af_entry["kbps"] > best_body_kbps:
                        best_body_kbps = af_entry["kbps"]
                        best_body_latency = body.latency_ms
                else:
                    if body.error:
                        sub_errors.append(body.error)

                host_entry["af_results"][af] = af_entry

            # Сворачиваем host-уровень из per-AF
            host_entry["tls_ok"] = host_tls_ok_any
            host_entry["body_ok"] = host_body_ok_any
            if host_tls_ok_any:
                tls_ok_count += 1
            host_entry["kbps"] = best_body_kbps
            host_entry["latency_ms"] = best_body_latency or (
                next(
                    (a["tls_latency_ms"] for a in host_entry["af_results"].values()
                     if a.get("tls_ok")),
                    0.0,
                )
            )
            # Краткая сводка для совместимости со старыми потребителями
            first_af = next(iter(host_entry["af_results"].values()), {})
            host_entry["details"] = (
                first_af.get("body_details") or first_af.get("tls_details") or ""
            )
            host_entry["dpi_marker"] = next(
                (a.get("dpi_marker", "") for a in host_entry["af_results"].values()
                 if a.get("dpi_marker")),
                "",
            )
            host_entry["status_code"] = next(
                (a.get("status_code", 0) for a in host_entry["af_results"].values()
                 if a.get("status_code")),
                0,
            )
            per_host.append(host_entry)

        total_subprobes = max(len(hosts), 1)
        # success_rate: 0.4 за TLS-only, 0.6 добавка за body
        weighted = (tls_ok_count * 0.4 + body_ok_count * 0.6) / total_subprobes
        success_rate = round(weighted, 3)

        # Стратегия "успешна" если хотя бы на одном хосте прошла body-проба
        # на ранее заблокированном AF. TLS-only без body — псевдо-успех.
        success = body_ok_count > 0

        # Baseline-aware: если все AF и так открыты — обнуляем кредит,
        # стратегия ничего не починила.
        baseline_open_all = bool(self._baseline_by_af) and \
            all(self._baseline_by_af.values())
        if success and baseline_open_all:
            success = False

        avg_kbps = (sum_kbps / kbps_count) if kbps_count > 0 else 0.0
        avg_latency = (sum_latency / total_subprobes) if per_host else 0.0

        if success:
            score = success_rate * (min(avg_kbps, 2048.0) /
                                    max(avg_latency, 50.0)) * 1000.0
        else:
            score = success_rate * 1.0

        # Гранулярная агрегация ошибки. Приоритет (от наиболее информативного):
        #  ISP_PAGE > TCP_16_20 > TLS_RESET/TCP_RESET > TLS_EOF_EARLY >
        #  TLS_TIMEOUT/TIMEOUT > TLS_HANDSHAKE/TLS_ALERT > SHORT_BODY >
        #  TLS_FAIL/BODY_FAIL (generic).
        if success:
            err = ""
        elif baseline_open_all:
            err = "BASELINE_OPEN"
        else:
            err = self._pick_best_error(sub_errors, tls_ok_count, body_ok_count)

        af_summary = ",".join(probe_afs) if probe_afs else "auto"
        details = "AF=%s, TLS %d/%d, body %d/%d, %.1f KB/s" % (
            af_summary,
            tls_ok_count, total_subprobes,
            body_ok_count, total_subprobes,
            avg_kbps,
        )

        return {
            "success": success,
            "latency_ms": avg_latency,
            "error": err,
            "http_code": any_http_code,
            "kbps": round(avg_kbps, 1),
            "body_passed": body_ok_count > 0,
            "success_rate": success_rate,
            "score": round(score, 2),
            "test_type": "tls+body",
            "details": details,
            "per_host": per_host,
            "probe_afs": probe_afs,
            "baseline_by_af": dict(self._baseline_by_af),
        }

    @staticmethod
    def _pick_best_error(
        errors: list[str],
        tls_ok_count: int,
        body_ok_count: int,
    ) -> str:
        """Выбрать наиболее информативный код ошибки из подпроб.

        Приоритеты подобраны так, чтобы пользователь видел ПЕРВОПРИЧИНУ:
        ISP-заглушка > 16-20KB block > классический DPI (RST/EOF) >
        timeout > generic.
        """
        if not errors:
            # Нет конкретных ошибок, но успех нулевой — fallback
            return "TLS_FAIL" if tls_ok_count == 0 else "BODY_FAIL"

        # Список приоритетов: чем выше — тем информативнее
        priority = [
            "ISP_PAGE",          # body — провайдерская заглушка
            "HTTP_INJECT",       # HTTP инъекция
            "TLS_MITM_SELF",     # MITM с самоподписанным
            "TLS_MITM_UNKNOWN_CA",
            "TCP_16_20",         # классический российский DPI
            "TLS_RESET",         # TCP RST в handshake
            "TCP_RESET",
            "TLS_EOF_EARLY",     # EOF до данных
            "TLS_EOF_DATA",
            "READ_RESET",        # RST в потоке
            "READ_BROKEN",
            "TLS_SNI_REJECT",
            "TLS_HANDSHAKE",
            "TLS_ALERT_INTERNAL",
            "TLS_ALERT",
            "TLS_CERT_ERR",
            "TLS_VERSION",
            "TCP_REFUSED",
            "HOST_UNREACH",
            "NET_UNREACH",
            "TLS_TIMEOUT",
            "TCP_TIMEOUT",
            "READ_TIMEOUT",
            "TIMEOUT",
            "SHORT_BODY",
            "RST",
            "TCP_ABORT",
            "CONNECT_ERR",
            "TLS_ERR",
            "READ_ERR",
            "BAD_URL",
            "DNS_ERR",
            "RESOLVE_ERR",
        ]
        present = set(errors)
        for code in priority:
            if code in present:
                return code
        # Не из списка — отдадим первое уникальное (возможно, кастомный код)
        return errors[0]

    def _select_test_hosts(self, profile) -> list[str]:
        """Сколько хостов проверять: 1 (quick) / 2 (standard) / все (full)."""
        all_hosts = [profile.primary_host] + [
            h for h in profile.test_hosts if h != profile.primary_host
        ]
        if self._mode == "quick":
            return all_hosts[:1]
        if self._mode == "standard":
            return all_hosts[:2]
        return all_hosts[:4]

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
        Baseline-тест: проверить ресурс БЕЗ обхода (per-AF для TCP).

        Заполняет self._baseline_by_af: {"ipv4": bool, "ipv6": bool}
        — True означает «ресурс уже доступен без обхода» для этого AF.
        Если AF не резолвится / отсутствует, ключ просто не появится.

        Returns:
            True если ресурс уже доступен хотя бы по одному AF.
        """
        log.info(
            "Baseline-тест: %s (%s)" % (self._target, self._protocol),
            source="scanner",
        )

        self._emit_callback("phase", {"phase": "Baseline-тест"})

        # UDP: per-AF не делаем (STUN сам резолвит как умеет)
        if self._protocol == "udp":
            result = self._probe_stun()
            is_accessible = result.status == TestStatus.SUCCESS.value
            self._baseline_by_af = {"ipv4": is_accessible}
            self._baseline_open = is_accessible
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

        # TCP: пробуем IPv4 и IPv6 раздельно
        from core.testers.tls_tester import test_tls

        # Системные ошибки сети (нет маршрута/DNS) — стратегия DPI это не лечит,
        # такой AF исключаем из карты, как и SKIPPED.
        UNAVAILABLE_ERRS = {
            "NET_UNREACH", "HOST_UNREACH", "DNS_ERR", "RESOLVE_ERR",
        }

        per_af: dict[str, bool] = {}
        for af in ("ipv4", "ipv6"):
            try:
                res = test_tls(
                    host=self._target, port=443,
                    timeout=PROBE_TIMEOUT, ip_family=af,
                )
            except Exception as e:
                log.debug(
                    "Baseline %s: исключение %s" % (af, e),
                    source="scanner",
                )
                continue
            # SKIPPED = нет адресов этого семейства, пропускаем (не кладём в map)
            if res.status == TestStatus.SKIPPED.value:
                continue
            # Сетевая недоступность (нет IPv6-маршрута и т.п.) — не DPI,
            # стратегия не сможет это починить. Исключаем AF из карты,
            # чтобы пробы стратегий не гонялись по неработающему семейству.
            if res.error in UNAVAILABLE_ERRS:
                log.info(
                    "Baseline %s: недоступно (%s, %.0f ms) — "
                    "AF исключён из сканирования стратегий" % (
                        af, res.error, res.latency_ms,
                    ),
                    source="scanner",
                )
                continue
            per_af[af] = (res.status == TestStatus.SUCCESS.value)
            log.info(
                "Baseline %s: %s (%s, %.0f ms)" % (
                    af,
                    "доступен" if per_af[af] else "заблокирован",
                    res.error or res.details or "ok",
                    res.latency_ms,
                ),
                source="scanner",
            )

        # Если ни одного AF не резолвилось — fallback на старое поведение
        if not per_af:
            log.warning(
                "Baseline: ни IPv4, ни IPv6 не резолвятся для %s"
                % self._target,
                source="scanner",
            )
            self._baseline_by_af = {}
            self._baseline_open = False
            return False

        self._baseline_by_af = per_af
        is_accessible = any(per_af.values())
        self._baseline_open = is_accessible

        if all(per_af.values()):
            log.warning(
                "Baseline: %s доступен без обхода по всем AF — "
                "результаты сканирования будут ложноположительными"
                % self._target,
                source="scanner",
            )
        elif is_accessible:
            blocked = [af for af, ok in per_af.items() if not ok]
            log.info(
                "Baseline: %s частично заблокирован (только: %s)"
                % (self._target, ", ".join(blocked) or "—"),
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

        # Лучшая = максимальный score (success_rate × kbps/latency).
        # Это надёжнее, чем просто latency: latency низкий бывает у
        # «псевдо-успехов», у которых body обрывается на 16-20 KB.
        best: Optional[StrategyProbeResult] = None
        if working:
            best = max(working, key=lambda r: r.score)

        # Сортируем self._results по score (для UI)
        self._results.sort(key=lambda r: r.score, reverse=True)

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

        # Если в args есть ссылка на TMP_HOSTLIST_PATH (это означает,
        # что стратегия была trick-обёрткой), переписываем её в постоянный
        # hostlist в lists_path — иначе после удаления tmp файл пропадёт.
        args = self._materialize_tmp_hostlist(args, probe_result)

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

    def _materialize_tmp_hostlist(
        self,
        args: list[str],
        probe_result: StrategyProbeResult,
    ) -> list[str]:
        """Заменить ссылку на TMP_HOSTLIST_PATH на постоянный файл.

        При сканировании trick'ам подсовывается /tmp/...target.txt, который
        удаляется в finally. Чтобы применённая стратегия пережила перезапуск
        nfqws2, копируем содержимое в lists_path/zapret-gui-target-<key>.txt
        и переписываем --hostlist=… на этот путь.
        """
        if not any(a.endswith(TMP_HOSTLIST_PATH) for a in args):
            return args

        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        lists_path = cfg.get("zapret", "lists_path",
                             default="/opt/zapret2/lists")

        from core.scan_targets import detect_target
        profile = self._scan_profile or detect_target(probe_result.target)
        permanent = os.path.join(
            lists_path, "zapret-gui-target-%s.txt" % profile.key,
        )

        try:
            os.makedirs(lists_path, exist_ok=True)
            with open(permanent, "w", encoding="utf-8") as f:
                for d in profile.all_hostlist_domains():
                    f.write(d.strip() + "\n")
        except OSError as e:
            log.warning(
                "Не удалось записать постоянный hostlist (%s): %s"
                % (permanent, e),
                source="scanner",
            )
            return args

        return [
            ("--hostlist=%s" % permanent) if a == ("--hostlist=%s" % TMP_HOSTLIST_PATH)
            else a
            for a in args
        ]

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

    # ─────────────────── tmp hostlist ───────────────────

    def _ensure_tmp_hostlist(self) -> None:
        """
        Создать временный hostlist для приёмов basic/advanced/direct.

        nfqws2 матчит SNI/Host строго по записям файла; чтобы trick'и
        реально применялись к трафику цели, нужны корректные домены.
        """
        if self._scan_profile is None:
            self._tmp_hostlist = None
            return

        domains = self._scan_profile.all_hostlist_domains()
        if not domains:
            self._tmp_hostlist = None
            return

        try:
            with open(TMP_HOSTLIST_PATH, "w", encoding="utf-8") as f:
                for d in domains:
                    f.write(d.strip() + "\n")
            self._tmp_hostlist = TMP_HOSTLIST_PATH
        except OSError as e:
            log.warning(
                "Не удалось создать временный hostlist: %s" % e,
                source="scanner",
            )
            self._tmp_hostlist = None

    def _remove_tmp_hostlist(self) -> None:
        """Удалить временный hostlist."""
        if self._tmp_hostlist:
            try:
                if os.path.exists(self._tmp_hostlist):
                    os.remove(self._tmp_hostlist)
            except OSError:
                pass
        self._tmp_hostlist = None


# ═══════════════════════════════════════════════════════════
#  Helpers (module-level)
# ═══════════════════════════════════════════════════════════

def _is_full_preset_args(args: list[str]) -> bool:
    """Эвристика: «полный пресет» — содержит --filter-* или --new или
    собственные --hostlist/--blob/--ipset. У «приёма» в args обычно один
    или два --lua-desync= и больше ничего.
    """
    if not args:
        return False
    for a in args:
        if a == "--new":
            return True
        if a.startswith("--filter-tcp") or a.startswith("--filter-udp"):
            return True
        if a.startswith("--hostlist=") or a.startswith("--hostlist-domains="):
            return True
        if a.startswith("--ipset=") or a.startswith("--ipset-exclude="):
            return True
        if a.startswith("--blob="):
            return True
    return False


def _is_full_preset_entry(entry: CatalogEntry) -> bool:
    """То же, но для CatalogEntry."""
    return _is_full_preset_args(entry.get_args_list())


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
