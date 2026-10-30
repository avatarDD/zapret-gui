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
QUIC_PROBE_TIMEOUT = 4          # Таймаут QUIC-пробы (Initial с SNI)
KILL_TIMEOUT = 4                # Ожидание остановки nfqws2
INTER_STRATEGY_DELAY = 0.3      # Пауза между стратегиями
BODY_PROBE_MIN_BYTES = 65_536   # Минимум для прохождения 16-20 KB барьера

# Сколько раз повторить запуск nfqws2, если он мгновенно упал/крашнулся
# (гонка с conntrack/NFQUEUE bind или флапающий fwmark).
NFQWS_CRASH_RETRIES = 2
NFQWS_CRASH_BACKOFF = 1.0       # пауза между попытками

# Остановка после N рабочих: потолок, чтобы «найти 1000» не выглядело
# как режим.
MAX_STOP_AFTER = 50
# Сколько найденных стратегий хранит resume-файл (лучшие по score).
RESUME_KEEP_WORKING = 20

# Перепроверка лучших: сколько лучших и сколько раз ещё (по умолчанию;
# переопределяются scan.confirm_top / scan.confirm_repeats).
CONFIRM_TOP = 3
CONFIRM_REPEATS = 2

# Сколько стратегий из памяти подбора ставим в начало.
MEMORY_FIRST_MAX = 10

# Этапы прогона — для прогресса в UI.
STAGE_PREPARE = "prepare"
STAGE_BASELINE = "baseline"
STAGE_SCAN = "scan"
STAGE_CONFIRM = "confirm"
STAGE_DONE = "done"

# Scan status
STATUS_IDLE = "idle"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"
STATUS_CANCELLED = "cancelled"


# ═══════════════════════════════════════════════════════════
#  Композитный score — одна формула на сканер и эксперименты
# ═══════════════════════════════════════════════════════════

# Потолки формулы. Вынесены сюда, а не оставлены магическими числами
# внутри `_deep_probe`: по ним видно, почему гигабитный канал не даёт
# гигабитного score, а латентность ниже 50 мс не улучшает результат.
SCORE_KBPS_CAP = 2048.0         # выше этого скорость в score не растёт
SCORE_LATENCY_FLOOR_MS = 50.0   # ниже этого латентность в score не падает


def udp_probe_kind(profile) -> str:
    """Чем проверять UDP-цель: ``quic`` или ``stun``.

    STUN к ``youtube.com:19302`` для QUIC-профиля ничего не говорит — там
    нет STUN-сервера, и такой подбор давал 0% на всём. QUIC-цели
    проверяются настоящим Initial с SNI (``core/testers/quic_initial``).
    """
    l7 = str(getattr(profile, "udp_l7", "") or "").lower()
    return "quic" if "quic" in l7.split(",") else "stun"


def credit_success(success: bool, baseline_open: bool) -> bool:
    """Засчитывать ли успех стратегии с поправкой на baseline.

    Цель, открытая и БЕЗ обхода, никакой стратегии кредита не даёт:
    «сработало» там означает «чинить было нечего». Правило одно на
    сканер и на движок экспериментов — разойдись они, эксперимент
    объявлял бы победителя там, где сканер честно пишет
    ``BASELINE_OPEN``.
    """
    return bool(success and not baseline_open)


def compose_score(success: bool, success_rate: float, kbps: float,
                  latency_ms: float) -> float:
    """Композитный score стратегии: успешность × скорость / латентность.

    Единственное место, где живёт формула ранжирования. Её зовут и
    сканер (`_deep_probe`), и движок экспериментов
    (`core/strategy_experiment.py`): разойдись они — «лучший вариант»
    эксперимента перестал бы совпадать с «лучшей стратегией» в UI, и
    пользователь видел бы два разных победителя на одних и тех же
    измерениях.

    Неуспешная стратегия получает голый `success_rate`: он всё ещё
    отличает «TLS прошёл, тело не докачалось» от «ничего не прошло», но
    скорость и латентность у неудачи ничего не значат.
    """
    rate = max(0.0, float(success_rate or 0.0))
    if not success:
        return round(rate, 2)
    speed = min(max(0.0, float(kbps or 0.0)), SCORE_KBPS_CAP)
    latency = max(float(latency_ms or 0.0), SCORE_LATENCY_FLOOR_MS)
    return round(rate * (speed / latency) * 1000.0, 2)


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
        self._dpi_type = ""
        # Сколько раз правила перехвата пришлось ставить заново посреди
        # прогона (их сбрасывал системный firewall) — видно в статусе.
        self._rules_reapplied = 0
        # Остановка после N рабочих и перепроверка лучших.
        self._stop_after = 0
        self._confirm = True
        self._stopped_early = False
        # Этап прогона (для человеческого прогресса в UI).
        self._stage = ""
        self._confirm_progress = 0
        self._confirm_total = 0
        # id стратегий, поднятых в начало памятью подбора.
        self._memory_ids: list[str] = []
        # Находки пробы обрыва 16 КБ, поставленные первыми (для resume).
        self._freeze: list[dict] = []
        # Стратегии сообщества, поставленные первыми, и что о базе сказать.
        self._community: list[dict] = []
        self._community_info: dict = {}
        self._community_req = None
        # Записи каталога прогона по id — для перепроверки.
        self._entries_by_id: dict[str, CatalogEntry] = {}
        # Профиль цели (см. core/scan_targets.py)
        self._scan_profile = None  # type: ignore[var-annotated]
        # Путь временного hostlist'а для приёмов (создаётся в _run_scan)
        self._tmp_hostlist: Optional[str] = None

        # Песочница (core/nfqws_sandbox.py): кандидаты — во втором nfqws2,
        # обход сети не трогается. Решается на старте прогона
        # (_decide_isolation); причина — в isolation_note статуса.
        self._isolated = False
        self._isolation_note = ""
        # Параллельный подбор (core/scan_parallel.py): дорожек в пачке
        # (0 — по одной), почему выключен, что просили при старте.
        self._parallel = 0
        self._parallel_note = ""
        self._parallel_req = None
        self._sandbox = None
        self._sandbox_mark = 0
        # Метка проб baseline: при работающем движке сети замер «без
        # обхода» идёт мимо очереди (core/probe_mark.py).
        self._baseline_mark = 0

        # Saved state (for restoring nfqws after scan)
        # Снимок целиком — из core/nfqws_session; три поля рядом
        # оставлены как есть: по ним читается «а надо ли вообще
        # восстанавливать».
        self._session_snapshot: dict[str, Any] = {}
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
        dpi_type: str = "",
        callback: Optional[Callable] = None,
        stop_after: int = 0,
        confirm: bool = True,
        require_isolation: bool = False,
        custom: Optional[list] = None,
        parallel: Optional[bool] = None,
        community: Optional[bool] = None,
    ) -> bool:
        """
        Запустить сканирование стратегий в фоновом потоке.

        Args:
            target:      Домен для проверки (напр. 'youtube.com').
            protocol:    'tcp' или 'udp'.
            mode:        'quick' (~30), 'standard' (~80), 'full' (все).
            start_index: Индекс для resume (0 = начало).
            dpi_type:    Тип DPI-блокировки (из BlockCheck). Фильтрует
                         релевантные стратегии.
            callback:    Опциональный callable(event_type, data).
            stop_after:  Остановить перебор, когда найдено столько рабочих
                         стратегий (0 — перебрать всё).
            confirm:     Перепроверить лучшие находки несколько раз
                         (медиана вместо одного замера).
            require_isolation: Только в песочнице: если она недоступна,
                         прогон завершается ошибкой, а не гасит обход
                         сети (автоподбор, core/autopick.py).
            custom:      «Своя стратегия»: кандидаты из
                         ``custom_candidates.check()`` вместо каталога;
                         режим прогона — ``custom``.
            parallel:    Проверять пачками в одной песочнице
                         (core/scan_parallel.py); None — по настройке
                         ``scan.parallel``.
            community:   Стратегии сообщества своего провайдера первыми
                         (core/community_strategies.py); None — по
                         настройке ``scan.community``.

        Returns:
            True если сканирование запущено.
        """
        # Разбор входа — ДО статуса RUNNING: исключение здесь иначе
        # оставило бы сканер «запущенным» без потока, а движок — занятым
        # для всех (nfqws_control.busy() смотрит на этот статус).
        target = str(target or "").strip() or "youtube.com"
        protocol = str(protocol or "").strip().lower() or "tcp"
        mode = str(mode or "").strip().lower() or "quick"
        start_index = max(0, int(start_index or 0))
        dpi_type = str(dpi_type or "").strip().lower()
        stop_after = max(0, min(int(stop_after or 0), MAX_STOP_AFTER))
        confirm = bool(confirm)
        custom = [dict(c) for c in (custom or [])]
        if custom:
            mode = "custom"

        # Пока ждёт подтверждения «Применить с проверкой», движок — её:
        # подбор занял бы его, и откат по сроку не смог бы перезапустить
        # nfqws2 (core/safe_apply.py).
        self.refusal = "Подбор стратегий уже выполняется"
        try:
            from core import safe_apply
            if safe_apply.active():
                self.refusal = ("идёт «Применить с проверкой» — сначала "
                                "подтвердите или откатите стратегию")
                log.warning("Подбор не запущен: %s" % self.refusal,
                            source="scanner")
                return False
        except Exception:                       # noqa: BLE001 — граница
            pass

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

            self._target = target
            self._protocol = protocol
            self._mode = mode
            self._start_index = start_index
            self._dpi_type = dpi_type
            self._callback = callback
            self._stop_after = stop_after
            self._confirm = confirm
            self._require_isolation = bool(require_isolation)
            self._custom = custom
            self._parallel_req = parallel
            self._community_req = community
            self._community, self._community_info = [], {}
            self._parallel, self._parallel_note = 0, ""
            self._stopped_early = False
            self._rules_reapplied = 0
            self._stage = STAGE_PREPARE
            self._confirm_progress = 0
            self._confirm_total = 0
            self._memory_ids = []
            self._entries_by_id = {}

        # Продолжение прерванного прогона: API отдал start_index только
        # для того же списка (get_resume_index), значит и найденное тогда
        # относится к этому прогону.
        if start_index > 0 and not custom:
            restored = self._restore_working()
            if restored:
                log.info("Resume: возвращено найденных ранее стратегий — %d"
                         % restored, source="scanner")

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
                # Ресурс доступен без обхода → стратегии помечаются неуспешными
                # (нечего «чинить»), success_rate будет 0%. Это ожидаемо, а не
                # ошибка: подбор нужно запускать на ЗАБЛОКИРОВАННОМ ресурсе.
                "baseline_open": self._baseline_open,
                "baseline_by_af": dict(self._baseline_by_af),
                # Для человеческого прогресса: этап, перепроверка,
                # чем проверяется цель, остановка после N рабочих.
                "stage": self._stage,
                "probe_kind": self._probe_kind_name(),
                "stop_after": self._stop_after,
                "stopped_early": self._stopped_early,
                "confirm": self._confirm,
                "confirm_progress": self._confirm_progress,
                "confirm_total": self._confirm_total,
                "confirmed_count": len([r for r in working if r.confirmed]),
                "memory_first": len(self._memory_ids),
                "rules_reapplied": self._rules_reapplied,
                # Прерванный прогон на диске (переживает перезагрузку):
                # по нему страница показывает «Продолжить», даже когда
                # сканер в памяти «idle».
                "saved_resume": (self.saved_resume_info()
                                 if self._status != STATUS_RUNNING else {}),
                # Песочница: кандидаты во втором nfqws2, обход сети цел.
                "isolated": self._isolated,
                "isolation_note": self._isolation_note,
                # Параллельно: сколько дорожек (0 — по одной) и почему нет.
                "parallel": self._parallel,
                "parallel_note": self._parallel_note,
                # База сообщества: AS, сколько записей, ошибка.
                "community": dict(self._community_info),
                "community_first": len(self._community),
                # Семейство цели (tls/http/quic/voice) — для «Поделиться».
                "family": self._family_name(),
            }

    def _family_name(self) -> str:
        if self._scan_profile is None:
            return ""
        try:
            from core.scan_targets import traffic_family
            return traffic_family(self._scan_profile, self._protocol)
        except Exception:                       # noqa: BLE001
            return ""

    def _probe_kind_name(self) -> str:
        """Чем проверяется цель: ``tls+body`` / ``quic`` / ``stun``."""
        if self._protocol != "udp":
            return "tls+body"
        if self._scan_profile is None:
            return "quic"
        return udp_probe_kind(self._scan_profile)

    def get_results(self) -> Optional[StrategyScanReport]:
        """Получить результаты последнего сканирования."""
        return self._report

    def refine_base(self, lighter: bool = False) -> Optional[dict]:
        """База для «уточнения» (core/strategy_refine.py) из этого прогона.

        ``lighter`` — лучшая рабочая (искать вариант полегче), иначе —
        продвинувшаяся дальше всех неудачная (наибольший ``score``).
        """
        with self._lock:
            if self._status == STATUS_RUNNING:
                return None
            results = list(self._results)
            entries = dict(self._entries_by_id)
            target, protocol = self._target, self._protocol
        pool = [r for r in results if r.success] if lighter \
            else [r for r in results if not r.success and r.score > 0]
        if not pool:
            return None
        best = max(pool, key=lambda r: (r.confirmed, r.score))
        entry = entries.get(best.strategy_id) or \
            self._catalog_entry(best.strategy_id)
        if entry is None:
            return None
        return {"strategy_id": best.strategy_id, "name": best.strategy_name,
                "args": entry.get_args_list(), "score": best.score,
                "target": target, "protocol": protocol}

    def get_working_strategies(self) -> list[dict[str, Any]]:
        """Получить список работающих стратегий."""
        with self._lock:
            return [r.to_dict() for r in self._results if r.success]

    def get_resume_index(self, target=None, protocol=None, mode=None,
                         dpi_type=None) -> int:
        """Индекс для resume из сохранённого состояния.

        Индекс имеет смысл только в том же списке стратегий, а список
        задают цель, протокол, режим и тип DPI. Сохранённая позиция
        ЧУЖОГО прогона (отменили youtube/tcp/standard на 50-й, а
        продолжить просят discord/udp/quick) — это 0, а не «начать с
        50-й стратегии другого списка». ``None`` — параметр не сверять.
        """
        state = self._load_resume_state()
        if not state:
            return 0
        want = {"target": target, "protocol": protocol, "mode": mode,
                "dpi_type": dpi_type}
        for key, value in want.items():
            if value is None:
                continue
            saved = str(state.get(key) or "").strip().lower()
            if saved != str(value or "").strip().lower():
                log.info(
                    "Resume не применён: сохранён прогон %s=%s, а просят %s"
                    % (key, saved or "—", value or "—"),
                    source="scanner")
                return 0
        try:
            return max(0, int(state.get("next_index", 0)))
        except (TypeError, ValueError):
            return 0

    def apply_strategy(self, index: int) -> bool:
        """
        Применить найденную стратегию по индексу в результатах.

        Создаёт user-стратегию в JSON-формате и применяет.

        Args:
            index: Индекс в списке working_strategies.

        Returns:
            True если стратегия применена.
        """
        with self._lock:
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
        probe_result = None
        with self._lock:
            for r in self._results:
                if r.success and r.strategy_id == strategy_id:
                    probe_result = r
                    break

        if probe_result:
            return self._apply_probe_result(probe_result)

        log.error(
            "Стратегия не найдена или не рабочая: %s" % strategy_id,
            source="scanner",
        )
        return False

    # ─────────────────── Main scan loop ───────────────────

    def _run_scan(self) -> None:
        """Главный цикл сканирования под общим мьютексом на движок.

        Сканер поднимает и роняет nfqws2 сам, поэтому весь прогон идёт
        под захватом ``core/nfqws_session``: пока он держится, ни
        применение стратегии, ни сравнение проб в движок не полезут.
        Занято — скан не начинается вовсе (``timeout=0``): иначе
        ``finally`` внутри цикла «восстановил бы как было» чужое
        состояние.
        """
        from core.nfqws_session import (OWNER_SCANNER, SessionBusy,
                                        get_nfqws_session)

        try:
            with get_nfqws_session().acquire(
                    owner=OWNER_SCANNER, timeout=0,
                    reason="подбор стратегий для %s" % self._target):
                self._run_scan_locked()
        except SessionBusy as busy:
            self._set_error("движок занят: %s" % busy)

    def _run_scan_locked(self) -> None:
        """Тело сканирования; мьютекс на движок уже наш."""
        started_at = time.time()
        # Решение о песочнице — этого прогона, а не прошлого: до него
        # (ранний выход) уборка идёт старым путём.
        self._isolated, self._isolation_note = False, ""

        try:
            # 0. Проверка предпосылок: без lua-скриптов / NFQUEUE сканировать
            #    бессмысленно — все стратегии дадут 0%. Не прерываем (на роутере
            #    проверки могут быть неточны), но громко предупреждаем в лог.
            self._check_prerequisites()

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

            # 3. Песочница или остановка движка сети. В песочнице обход
            #    сети работает весь подбор; без неё — гасим, как раньше.
            self._decide_isolation()
            if not self._isolated:
                if getattr(self, "_require_isolation", False):
                    self._set_error("подбор только в песочнице, а она "
                                    "недоступна: %s" % self._isolation_note)
                    return
                self._stop_current_nfqws()
            self._decide_parallel(len(strategies))

            # 4. Baseline тест (без обхода). При работающем движке сети
            #    пробы идут с меткой мимо очереди.
            self._set_stage(STAGE_BASELINE)
            self._set_phase("Проверка без обхода (baseline)")
            from core import probe_mark
            with probe_mark.marking(self._baseline_mark):
                baseline_accessible = self._run_baseline_test()

            if baseline_accessible:
                log.warning(
                    "Ресурс %s ДОСТУПЕН без обхода — результаты "
                    "могут быть ложноположительными" % self._target,
                    source="scanner",
                )

            # 5. Правила перехвата — один раз на весь прогон
            self._set_phase("Подготовка перехвата")
            if not self._start_scan_rules():
                self._set_error(
                    "Не удалось применить правила firewall: без них "
                    "стратегии проверить нельзя. Подробности — в журнале "
                    "(источник firewall).")
                return

            # 6. Перебор стратегий
            self._set_stage(STAGE_SCAN)
            self._set_phase("Перебор стратегий")

            batch: dict = {}
            batch_end = 0
            for idx, entry in enumerate(strategies):
                if self._cancelled:
                    break

                actual_idx = self._start_index + idx
                # Параллельно: пачка начиная с этой стратегии — разом;
                # дальше цикл берёт готовые итоги по одному.
                if self._parallel and idx >= batch_end:
                    batch, batch_end = self._probe_batch(strategies, idx)
                with self._lock:
                    self._progress = idx + 1
                    self._current_strategy_name = entry.name
                    self._entries_by_id[entry.section_id] = entry

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
                from_batch = idx in batch
                if from_batch:
                    result = batch.pop(idx)
                else:
                    result = self._probe_one_strategy(entry, actual_idx)
                probe_elapsed = time.time() - probe_start
                result.from_memory = entry.section_id in self._memory_ids

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

                # MR-85: Сохраняем resume-state с throttle (каждые 5 стратегий или каждые 10s)
                save_idx = actual_idx + 1
                if not hasattr(self, '_last_save_time'):
                    self._last_save_time = 0
                    self._save_counter = 0
                self._save_counter += 1
                now = time.time()
                # Последняя стратегия ЭТОГО прогона: idx нумерует срез
                # `strategies` (при resume он уже обрезан по _start_index),
                # поэтому сравнивать надо с len(strategies), а не с
                # self._total/actual_idx — иначе при resume условие
                # срабатывало бы на каждой итерации (issue #266).
                if (self._save_counter % 5 == 0
                        or (now - self._last_save_time) >= 10
                        or idx >= len(strategies) - 1):
                    self._save_resume_state(save_idx)
                    self._last_save_time = now

                # Остановка после N рабочих: пользователю нужна рабочая
                # стратегия, а не перебор всего каталога.
                if self._stop_after and working_count >= self._stop_after:
                    with self._lock:
                        self._stopped_early = True
                    # Позиция — точно на месте остановки: «Искать дальше»
                    # продолжит отсюда, а не с последнего троттлинга.
                    self._save_resume_state(actual_idx + 1)
                    log.info(
                        "Найдено рабочих стратегий: %d — перебор "
                        "остановлен (stop_after=%d)"
                        % (working_count, self._stop_after),
                        source="scanner",
                    )
                    break

                # Пауза между стратегиями
                if (not self._cancelled and not from_batch
                        and idx < len(strategies) - 1):
                    time.sleep(INTER_STRATEGY_DELAY)

            # 7. Перепроверка лучших: один замер — это совпадение,
            #    три подряд — знание.
            if self._confirm and not self._cancelled:
                self._confirm_best()

            # 8. Память подбора: что сработало на этой цели в этой сети.
            self._remember_findings()

            # 9. Формируем отчёт
            self._set_stage(STAGE_DONE)
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

            # Resume-файл нужен после отмены и после остановки «после N
            # рабочих» («Искать дальше»); после полного прохода — нет.
            if not self._cancelled and not self._stopped_early:
                self._remove_resume_state()

    def _check_prerequisites(self) -> None:
        """Предупредить о блокерах окружения (lua/blob/NFQUEUE) перед сканом."""
        try:
            from core.diagnostics import check_strategy_prerequisites
            pre = check_strategy_prerequisites()
        except Exception as e:
            log.debug("Проверка предпосылок недоступна: %s" % e,
                      source="scanner")
            return

        for issue in pre.get("issues", []):
            msg = "Предпосылка [%s]: %s — %s" % (
                issue.get("severity", "?"),
                issue.get("title", ""),
                issue.get("hint", ""),
            )
            if issue.get("severity") == "error":
                log.error(msg, source="scanner")
            else:
                log.warning(msg, source="scanner")

        if not pre.get("ok", True):
            log.error(
                "Окружение НЕ готово к стратегиям — вероятен 0%% на всём. "
                "Откройте Диагностику (prerequisites) и устраните ошибки.",
                source="scanner",
            )

        # Часы по сети (core/quick_fix, кеш на пару минут): год в
        # предпосылках ловит только «1970», а сдвиг на дни ломает TLS
        # точно так же.
        try:
            from core.quick_fix import clock_problem
            clock = None if any(i.get("id") == "clock_wrong"
                                for i in pre.get("issues", [])) \
                else clock_problem(network=True)
        except Exception:
            clock = None
        if clock:
            log.error("%s: %s. %s" % (clock.get("title", ""),
                                      clock.get("detail", ""),
                                      clock.get("hint", "")),
                      source="scanner")

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
        # «Своя стратегия»: только вставленное, без каталога и памяти.
        if getattr(self, "_custom", None):
            from core.custom_candidates import entries as custom_entries
            self._memory_ids = []
            return custom_entries(self._custom, self._protocol)[
                self._start_index:]

        from core.catalog_loader import get_catalog_manager

        from core.scan_targets import detect_target, traffic_family

        cm = get_catalog_manager()
        protocol = self._protocol
        # Приёмы — под трафик цели: HTTP-приёмы для TLS-цели и голос
        # Discord для QUIC — пустые пробы.
        family = traffic_family(
            self._scan_profile or detect_target(self._target), protocol)

        # quick/standard/full — отбираем кандидатов из каталога
        if self._mode == "quick":
            entries = cm.get_quick_set(protocol=protocol, family=family)
        elif self._mode == "standard":
            entries = cm.get_standard_set(protocol=protocol, family=family)
        else:  # full
            entries = cm.get_full_set(protocol=protocol, family=family)

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

        # Генерированные стратегии «на лету» (standard/full): расширяем
        # покрытие без хранения файлов. Дедуп против уже отобранных по args.
        from core.config_manager import get_config_manager
        if (self._mode in ("standard", "full")
                and get_config_manager().get("scan", "use_generated", default=True)):
            try:
                from core.strategy_generator import generate, _norm_args
                have_args = {_norm_args(e.get_args_list()) for e in entries}
                gen = generate(protocol=protocol, level=self._mode)
                added = 0
                for ge in gen:
                    if _norm_args(ge.get_args_list()) not in have_args:
                        entries.append(ge)
                        have_args.add(_norm_args(ge.get_args_list()))
                        added += 1
                if added:
                    log.info("Добавлено сгенерированных стратегий: %d" % added,
                             source="scanner")
            except Exception as e:
                log.warning("Генератор стратегий недоступен: %s" % e,
                            source="scanner")

        # DPI-type фильтрация: оставляем только релевантные стратегии
        if self._dpi_type:
            before_count = len(entries)
            entries = self._filter_by_dpi(entries, self._dpi_type)
            log.info(
                "DPI-фильтрация (%s): %d → %d стратегий"
                % (self._dpi_type, before_count, len(entries)),
                source="scanner",
            )

        # Сортировка: full presets вперёд, recommended вторыми, внутри
        # группы — от простых стратегий к сложным (blockcheckw rank).
        from core.strategy_generator import complexity_key

        def _sort_key(e: CatalogEntry) -> tuple:
            full = _is_full_preset_entry(e)
            recommended = (e.label == "recommended")
            # 0 — самый приоритетный
            return (
                0 if full else (1 if recommended else 2),
                complexity_key(e.get_args_list()),
                # внутри группы — стабильный порядок
                e.source_file,
                e.section_id,
            )

        entries.sort(key=_sort_key)

        # То, что уже срабатывало на этой цели в этой сети, — первым:
        # пользователю важна рабочая стратегия, и шанс у этих выше.
        # Каждый ставит своё в самое начало, поэтому порядок вызовов
        # обратный итоговому: память подбора, находки пробы обрыва,
        # сообщество.
        entries = self._community_first(entries, family)
        entries = self._freeze_first(entries, family)
        entries = self._memory_first(entries)

        # Применяем start_index для resume
        if self._start_index > 0 and self._start_index < len(entries):
            entries = entries[self._start_index:]
            log.info(
                "Resume: начинаем с индекса %d" % self._start_index,
                source="scanner",
            )

        return entries

    def _memory_first(self, entries: list) -> list:
        """Поставить в начало стратегии, которые помнит память подбора.

        Порядок сохраняется в resume-файле (``memory_ids``): «продолжить»
        обязано идти по тому же списку, даже если память с тех пор
        пополнил эксперимент. Стратегию из памяти, не попавшую в набор
        режима (quick — ~30 штук), берём из каталога целиком.
        """
        ids = self._remembered_ids()
        if not ids:
            self._memory_ids = []
            return entries
        by_id = {e.section_id: e for e in entries}
        front = []
        for sid in ids:
            entry = by_id.get(sid) or self._catalog_entry(sid)
            if entry is not None and entry not in front:
                front.append(entry)
        taken = {e.section_id for e in front}
        self._memory_ids = [e.section_id for e in front]
        if front:
            log.info(
                "Память подбора: первыми проверим %d стратегий, которые "
                "уже срабатывали на %s в этой сети"
                % (len(front), self._target), source="scanner")
        return front + [e for e in entries if e.section_id not in taken]

    def _freeze_first(self, entries: list, family: str) -> list:
        """Находки пробы «обрыв на 16 КБ» (core/freeze_probe) — первыми.

        Только для TLS: приёмы пробы — на ClientHello. Для resume берётся
        сохранённый список, а не свежий файл: «продолжить» обязано идти по
        тому же порядку.
        """
        self._freeze = []
        if self._protocol != "tcp" or family != "tls":
            return entries
        try:
            if self._start_index > 0:
                saved = self._load_resume_state().get("freeze")
                found = saved if isinstance(saved, list) else []
            else:
                from core import freeze_probe
                found = freeze_probe.candidates(freeze_probe.load())
                found = found[:freeze_probe.SCAN_FIRST_MAX]
            from core.custom_candidates import entries as custom_entries
            front = custom_entries(found, self._protocol)
        except Exception as e:                  # noqa: BLE001 — граница
            log.debug("Находки пробы обрыва недоступны: %s" % e,
                      source="scanner")
            return entries
        if not front:
            return entries
        self._freeze = found
        log.info("Проба обрыва 16 КБ: первыми проверим %d её находок"
                 % len(front), source="scanner")
        # Те же шаги из каталога второй раз не пробуем.
        have = {tuple(e.get_args_list()) for e in front}
        return front + [e for e in entries
                        if tuple(e.get_args_list()) not in have]

    def _community_first(self, entries: list, family: str) -> list:
        """Стратегии сообщества своего провайдера (core/community_strategies)
        — первыми, если пользователь включил базу.

        TLS и HTTP: база других не знает. Сеть (RIPEstat, GitHub) — только
        здесь, в потоке сканера. Для resume — сохранённый список.
        """
        self._community, self._community_info = [], {}
        req = getattr(self, "_community_req", None)
        if req is None:
            try:
                from core.config_manager import get_config_manager
                req = bool(get_config_manager().get("scan", "community",
                                                    default=False))
            except Exception:                   # noqa: BLE001 — граница
                req = False
        resuming = self._start_index > 0
        # Resume — по сохранённому списку, даже если галку сняли: иначе
        # позиция продолжения съехала бы на длину этого списка.
        if (not req and not resuming) or self._protocol != "tcp" \
                or family not in ("tls", "http"):
            return entries
        try:
            if resuming:
                saved = self._load_resume_state().get("community")
                found = saved if isinstance(saved, list) else []
                from core import community_strategies
                info = {"asn": community_strategies.provider().get("asn")}
            else:
                from core import community_strategies
                self._set_phase("Стратегии сообщества для вашего провайдера")
                found, info = community_strategies.scan_candidates(
                    self._target, family)
            from core.custom_candidates import entries as custom_entries
            front = custom_entries(found, self._protocol)
        except Exception as e:                  # noqa: BLE001 — граница
            log.warning("База сообщества недоступна: %s" % e,
                        source="scanner")
            self._community_info = {"error": str(e)[:200]}
            return entries
        self._community_info = info
        if info.get("error"):
            log.info("Сообщество: %s" % info["error"], source="scanner")
        if not front:
            return entries
        self._community = found
        log.info("Сообщество: первыми проверим %d стратегий абонентов "
                 "AS%s" % (len(front), info.get("asn", "?")),
                 source="scanner")
        have = {tuple(e.get_args_list()) for e in front}
        return front + [e for e in entries
                        if tuple(e.get_args_list()) not in have]

    def _remembered_ids(self) -> list:
        """id стратегий из памяти: для resume — сохранённые, иначе свежие."""
        if self._start_index > 0:
            saved = self._load_resume_state().get("memory_ids")
            return [str(x) for x in saved] if isinstance(saved, list) else []
        try:
            from core import strategy_memory
            found = strategy_memory.lookup(targets=[self._target], limit=50)
        except Exception as e:                  # noqa: BLE001 — граница
            log.debug("Память подбора недоступна: %s" % e, source="scanner")
            return []
        ids = []
        for item in found.get("items") or []:
            sid = str(item.get("strategy_id") or "")
            # «Своя стратегия» в каталоге не живёт — по id её не поднять.
            if sid.startswith("custom_"):
                continue
            if (sid and sid not in ids and not item.get("stale")
                    and item.get("wins", 0) > item.get("losses", 0)):
                ids.append(sid)
            if len(ids) >= MEMORY_FIRST_MAX:
                break
        # Затем — что открывало соседей по регистрируемому домену в этой
        # сети (семейство, приём d2k): поддомен CDN той же коробкой
        # обычно обходится тем же приёмом. Своя история цели — первой.
        own = len(ids)
        for item in (found.get("family") or {}).get(
                str(self._target).strip().lower(), []):
            if len(ids) >= MEMORY_FIRST_MAX:
                break
            sid = str(item.get("strategy_id") or "")
            if sid and sid not in ids and not sid.startswith("custom_"):
                ids.append(sid)
        if len(ids) > own:
            log.info("Память подбора: %d стратегий от соседей по домену "
                     "%s" % (len(ids) - own,
                             (found["family"][self._target.strip().lower()]
                              [0]["family"])), source="scanner")
        return ids

    def _catalog_entry(self, strategy_id: str):
        try:
            from core.catalog_loader import get_catalog_manager
            return get_catalog_manager().get_entry_by_id(
                strategy_id, protocol=self._protocol)
        except Exception:                       # noqa: BLE001 — граница
            return None

    def _filter_by_dpi(self, entries: list, dpi_type: str) -> list:
        """
        Отфильтровать стратегии по типу DPI-блокировки.

        Оставляет только те стратегии, которые релевантны для
        конкретного типа блокировки. Ускоряет скан в 5-10 раз.
        """
        if not dpi_type:
            return entries

        # Маппинг DPI-типа → ключевые слова в аргументах стратегии
        # Если стратегия содержит хотя бы одно ключевое слово — она релевантна
        DPI_FILTERS = {
            # TLS DPI — нужен fake + split/disorder для TLS ClientHello
            "tls_dpi": {
                "must_have": ["filter-l7=tls", "tls_client_hello"],
                "good": ["fake", "split", "disorder", "fakedsplit",
                         "multisplit", "multidisorder", "seqovl"],
                "bad": ["filter-l7=quic", "quic_initial"],
            },
            # ClientHello DPI — нужен multisplit по позициям (размер-based)
            "clienthello_dpi": {
                "must_have": ["filter-l7=tls", "tls_client_hello"],
                "good": ["multisplit", "pos=", "seqovl", "split"],
                "bad": ["filter-l7=quic"],
            },
            # TCP Reset — нужен desync с fooling (tcp_md5, badsum, ttl)
            "tcp_reset": {
                "must_have": ["filter-l7=tls"],
                "good": ["fake", "fool=", "tcp_md5", "badsum", "ip_ttl",
                         "autottl", "tcp_ack"],
                "bad": [],
            },
            # QUIC blocked — нужны QUIC-стратегии
            "quic_block": {
                "must_have": ["filter-l7=quic", "quic_initial"],
                "good": ["udplen", "fake", "quic"],
                "bad": ["filter-l7=tls"],
            },
            # HTTP inject — нужны HTTP-стратегии
            "http_inject": {
                "must_have": ["filter-l7=http", "http_req"],
                "good": ["http_methodeol", "domcase", "hostcase", "split"],
                "bad": ["filter-l7=tls"],
            },
            # ISP page — HTTP + TLS
            "isp_page": {
                "must_have": [],
                "good": ["fake", "split", "disorder"],
                "bad": [],
            },
            # TLS MITM — сложный, пробуем всё
            "tls_mitm": {
                "must_have": [],
                "good": ["fake", "split", "disorder", "fool"],
                "bad": [],
            },
            # TCP 16-20KB — split с seqovl
            "tcp_16_20": {
                "must_have": ["filter-l7=tls"],
                "good": ["split", "seqovl", "multisplit"],
                "bad": [],
            },
            # STUN block — UDP
            "stun_block": {
                "must_have": ["filter-udp"],
                "good": ["fake", "udplen"],
                "bad": [],
            },
            # Throttled — split + fake
            "throttled": {
                "must_have": [],
                "good": ["fake", "split", "disorder"],
                "bad": [],
            },
            # DNS fake — не нужен nfqws2, нужен DoH
            "dns_fake": {
                "must_have": [],
                "good": [],
                "bad": [],
                "skip": True,  # Пропускаем — nfqws2 не поможет
            },
            # IP block — нужен туннель
            "ip_block": {
                "must_have": [],
                "good": [],
                "bad": [],
                "skip": True,
            },
            # Full block — нужен туннель
            "full_block": {
                "must_have": [],
                "good": [],
                "bad": [],
                "skip": True,
            },
        }

        f = DPI_FILTERS.get(dpi_type)
        if not f:
            return entries  # Неизвестный тип — не фильтруем

        if f.get("skip"):
            return []  # nfqws2 не поможет

        must_have = set(f.get("must_have", []))
        good = set(f.get("good", []))
        bad = set(f.get("bad", []))

        filtered = []
        for e in entries:
            args_str = e.args.lower()
            args_list = [a.lower() for a in e.get_args_list()]

            # Проверяем must_have — если есть ограничение, стратегия
            # должна содержать хотя бы одно ключевое слово
            if must_have and not any(kw in args_str for kw in must_have):
                # MR-11: разрешаем "trick"-стратегии (basic/direct/builtin, или чистый сплит/disorder/oob без desync)
                is_trick = e.level in ("basic", "direct", "builtin") or (
                    any(kw in args_str for kw in ("split", "disorder", "oob")) and "desync" not in args_str
                )
                if not is_trick:
                    continue

            # Проверяем bad — исключаем нерелевантные
            if bad and any(kw in args_str for kw in bad):
                continue

            filtered.append(e)

        return filtered

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
        from core import probe_mark
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager

        # В песочнице кандидат поднимается во втором nfqws2, а пробы
        # метятся так, чтобы firewall увёл в его очередь только их.
        nfqws = self._sandbox if self._isolated else get_nfqws_manager()
        mark = self._sandbox_mark if self._isolated else 0
        fw = get_firewall_manager()

        start_time = time.time()
        nfqws_started = False

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

            # 2. Правила firewall стоят на весь прогон (_start_scan_rules);
            #    здесь — только дешёвая проверка, что их не снёс
            #    системный firewall (Keenetic NDMS, fw4 reload).
            if not self._ensure_scan_rules(fw):
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
            with probe_mark.marking(mark):
                probe = self._deep_probe()

            elapsed_ms = (time.time() - start_time) * 1000

            # 7. Формируем результат
            return self._probe_result(entry, probe, args_full, elapsed_ms)

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            log.error(
                "Ошибка пробы стратегии %s: %s" % (entry.name, e),
                source="scanner",
            )
            return self._exception_result(entry, e, elapsed_ms)

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

    def _exception_result(self, entry, e, elapsed_ms: float):
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

    def _probe_result(self, entry, probe: dict, args_full: str,
                      elapsed_ms: float):
        """Итог глубокой пробы → StrategyProbeResult."""
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

    # ─────────────────── Параллельный подбор ───────────────────

    def _decide_parallel(self, count: int) -> None:
        """Пачками или по одной — и почему (в статус и журнал)."""
        from core import scan_parallel
        self._parallel, self._parallel_note = 0, ""
        self._batch_fails = 0
        req = getattr(self, "_parallel_req", None)
        try:
            from core.config_manager import get_config_manager
            value = get_config_manager().get("scan", "parallel",
                                             default="off")
        except Exception:                       # noqa: BLE001 — граница
            value = "off"
        # Галка формы главнее; включена — потолок дорожек всё равно из
        # настройки, если там число.
        if req is False:
            value = "off"
        elif req and not scan_parallel.enabled(value):
            value = "auto"
        if not scan_parallel.enabled(value):
            return
        if not self._isolated or self._sandbox is None:
            note = "нужна песочница: %s" % (self._isolation_note or "нет")
        elif count < scan_parallel.PAR_MIN:
            note = "кандидатов меньше %d" % scan_parallel.PAR_MIN
        elif not self._sandbox.supports_option("filter-mark"):
            note = "nfqws2 старше 1.0.5: нет --filter-mark"
        else:
            note = ""
        if note:
            self._parallel_note = note
            log.info("Параллельный подбор выключен: %s" % note,
                     source="scanner")
            return
        self._parallel = scan_parallel.limit(value)
        log.info("Параллельный подбор: до %d стратегий разом (по памяти "
                 "— перед каждой пачкой)" % self._parallel, source="scanner")

    @staticmethod
    def _meminfo() -> str:
        try:
            with open("/proc/meminfo", "r") as f:
                return f.read()
        except OSError:
            return ""

    def _probe_batch(self, strategies: list, idx: int) -> tuple:
        """Пачка с ``idx`` разом: ({индекс: результат}, конец пачки).

        Не вошедшие в пачку (и вся пачка, которую nfqws2 не принял) в
        словаре отсутствуют — цикл проверит их по одной, а новую пачку
        начнёт только за концом этой. Находка пачки сразу
        перепроверяется в одиночку; две пачки подряд не поднялись —
        дальше по одной до конца прогона.
        """
        from core import scan_parallel
        slots = min(self._parallel,
                    scan_parallel.slots_for_memory(self._meminfo()))
        chunk = strategies[idx:idx + slots]
        end = idx + max(1, len(chunk))
        if slots < 2 or len(chunk) < 2:
            return {}, idx + 1
        args_lists = []
        for entry in chunk:
            try:
                args_lists.append(self._build_strategy_args(entry))
            except Exception:                   # noqa: BLE001 — по одной
                args_lists.append([])
        argv, packed, _alone = scan_parallel.combine(args_lists)
        if len(packed) < 2:
            return {}, end
        entries = [chunk[i] for i in packed]
        self._set_phase("Перебор стратегий: %d разом" % len(entries))
        results = self._run_batch(entries, argv,
                                  [" ".join(args_lists[i]) for i in packed])
        if results is None:
            self._batch_fails = getattr(self, "_batch_fails", 0) + 1
            log.info("Пачка не поднялась — эти %d по одной" % len(entries),
                     source="scanner")
            if self._batch_fails >= 2:
                self._parallel = 0
                self._parallel_note = ("nfqws2 дважды не принял пачку — "
                                       "дальше по одной")
                log.warning("Параллельный подбор выключен: %s"
                            % self._parallel_note, source="scanner")
            return {}, end
        self._batch_fails = 0
        # Перепроверять по одной — не больше, чем нужно до stop_after:
        # остальные находки пачки цикл проверит сам, если дойдёт.
        with self._lock:
            have = len([r for r in self._results if r.success])
        need = (self._stop_after - have) if self._stop_after else len(packed)
        out = {}
        for i, result in zip(packed, results):
            if result.success and (self._cancelled or need <= 0):
                # Неперепроверенная находка в итог не идёт.
                continue
            if result.success:
                need -= 1
                with self._lock:
                    self._current_strategy_name = chunk[i].name
                solo = self._probe_one_strategy(
                    chunk[i], self._start_index + idx + i)
                if solo.raw_data is None:
                    solo.raw_data = {}
                solo.raw_data["parallel"] = (
                    "найдена в пачке, перепроверена по одной")
                result = solo
            out[idx + i] = result
        return out, end

    def _run_batch(self, entries: list, argv: list, previews: list):
        """Один nfqws2 песочницы на пачку, пробы — параллельно."""
        from core import probe_mark, scan_parallel
        from core.firewall import get_firewall_manager

        nfqws = self._sandbox
        if nfqws is None or not self._ensure_scan_rules(
                get_firewall_manager()):
            return None
        if not nfqws.start(argv):
            return None
        try:
            time.sleep(self._get_stabilization_delay())
            if not nfqws.is_running():
                return None
            probes = [None] * len(entries)
            took = [0.0] * len(entries)

            def work(k):
                t0 = time.time()
                try:
                    with probe_mark.marking(self._sandbox_mark,
                                            ports=scan_parallel.slot_ports(k)):
                        probes[k] = self._deep_probe()
                except Exception as e:          # noqa: BLE001 — в итог
                    probes[k] = e
                took[k] = (time.time() - t0) * 1000

            threads = [threading.Thread(target=work, args=(k,), daemon=True,
                                        name="scan-slot-%d" % k)
                       for k in range(len(entries))]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            try:
                nfqws.stop()
            except Exception as e:              # noqa: BLE001
                log.warning("Ошибка остановки nfqws2: %s" % e,
                            source="scanner")
        # Время — своей дорожки, а не всей пачки.
        out = []
        for entry, probe, preview, ms in zip(entries, probes, previews,
                                             took):
            if isinstance(probe, dict):
                out.append(self._probe_result(entry, probe, preview, ms))
            else:
                out.append(self._exception_result(entry, probe, ms))
        return out

    # ─────────────────── Правила на весь прогон ───────────────────

    def _start_scan_rules(self) -> bool:
        """Поставить правила перехвата один раз — на весь прогон.

        Раньше правила ставились и снимались на КАЖДУЮ стратегию: на
        роутере это десятки вызовов iptables/nft на пробу. Они стоят с
        `--queue-bypass`/`bypass`: пока nfqws2 между стратегиями
        перезапускается, пакеты идут мимо очереди, а не в пустоту.
        Снимает их `_ensure_cleanup` в конце прогона.
        """
        from core.firewall import get_firewall_manager

        if self._apply_scan_rules(get_firewall_manager()):
            with self._lock:
                self._rules_reapplied = 0
            return True
        return False

    def _apply_scan_rules(self, fw) -> bool:
        """Основные правила — или только правила песочницы."""
        if self._isolated:
            from core import scan_parallel
            return fw.apply_sandbox_rules(
                self._sandbox_queue(), self._sandbox_mark,
                slots=scan_parallel.PAR_MAX if self._parallel else 0)
        return fw.apply_rules()

    def _sandbox_queue(self) -> int:
        from core import nfqws_sandbox
        return nfqws_sandbox.queue_num()

    def _ensure_scan_rules(self, fw) -> bool:
        """Правила на месте? Нет — поставить снова (и посчитать это)."""
        try:
            if (fw.sandbox_rules_applied() if self._isolated
                    else fw.is_applied()):
                return True
        except Exception as e:                  # noqa: BLE001 — граница
            log.debug("Проверка правил не удалась: %s" % e,
                      source="scanner")
        log.warning("Правила перехвата пропали посреди подбора (их "
                    "сбросил системный firewall?) — ставим заново",
                    source="scanner")
        if not self._apply_scan_rules(fw):
            return False
        with self._lock:
            self._rules_reapplied += 1
        return True

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
                           default="/opt/zapret2/files/fake")
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

        # Регистрация именованных blob'ов (tls_google и т.п.): без декларации
        # --blob=NAME:@bin/file.bin nfqws2 шлёт ПУСТОЙ fake и проба ложно
        # падает. Подмешиваем недостающие декларации в начало (как в
        # strategy_builder.build_nfqws_args для ручного применения).
        try:
            from core.blob_registry import build_blob_declarations
            blob_decls = build_blob_declarations(wrapped)
            if blob_decls:
                wrapped = blob_decls + wrapped
        except Exception:
            pass

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

        # UDP: QUIC-профилю — настоящий QUIC Initial с SNI (его DPI и
        # режет), остальным (Discord voice, STUN) — STUN.
        if self._protocol == "udp" and udp_probe_kind(profile) == "quic":
            return self._quic_probe(profile)
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
                # У STUN нет ни тела, ни скорости — в формулу уходит
                # единичная «скорость», и score вырождается в
                # 1000 / латентность, как и было до вынесения формулы.
                "score": compose_score(ok, 1.0, 1.0, stun.latency_ms)
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

        probe_afs = self._probe_afs()

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
                url = profile.get_probe_url(host)
                # Тело — по ТОМУ ЖЕ семейству адресов, что и TLS: иначе
                # при открытом IPv4 и заблокированном IPv6 «успех по
                # IPv6» скачивался бы по IPv4 (http.client откатывается
                # на другое семейство сам).
                body = probe_body(
                    url=url,
                    min_bytes=BODY_PROBE_MIN_BYTES,
                    timeout=BODY_PROBE_TIMEOUT,
                    ip_family=af,
                )
                if body.status == TestStatus.SKIPPED.value:
                    # У хоста пробного URL нет адресов этого семейства —
                    # качаем с хоста, на котором TLS по нему уже прошёл.
                    body = probe_body(
                        url="https://%s/" % host,
                        min_bytes=BODY_PROBE_MIN_BYTES,
                        timeout=BODY_PROBE_TIMEOUT,
                        ip_family=af,
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
        success = credit_success(success, baseline_open_all)

        avg_kbps = (sum_kbps / kbps_count) if kbps_count > 0 else 0.0
        avg_latency = (sum_latency / total_subprobes) if per_host else 0.0

        score = compose_score(success, success_rate, avg_kbps, avg_latency)

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

    def _probe_afs(self) -> list:
        """Какие AF имеет смысл проверять у стратегии.

        Если baseline дал per-AF карту — те, что были заблокированы (на
        открытых стратегия ничего «не починит»). Все открыты — один
        проход, чтобы результат не был пустым. Карты нет — только ipv4.
        """
        if not self._baseline_by_af:
            return ["ipv4"]
        blocked = [af for af, ok in self._baseline_by_af.items() if not ok]
        if blocked:
            return blocked
        return (["ipv4"] if "ipv4" in self._baseline_by_af
                else list(self._baseline_by_af.keys())[:1])

    def _quic_probe(self, profile) -> dict[str, Any]:
        """QUIC-проба стратегии: Initial с SNI по хостам цели и AF.

        Та же форма ответа, что у TLS+body-пробы, чтобы отчёт, score и
        UI не различали протоколы. Скорости у QUIC-пробы нет — в формулу
        уходит единичная, как у STUN.
        """
        from core.testers.quic_tester import test_quic_handshake

        hosts = self._select_test_hosts(profile)
        probe_afs = self._probe_afs()
        per_host: list[dict[str, Any]] = []
        ok_count, sum_latency, sub_errors = 0, 0.0, []

        for host in hosts:
            entry = {"host": host, "tls_ok": False, "body_ok": False,
                     "quic_ok": False, "kbps": 0.0, "latency_ms": 0.0,
                     "details": "", "af_results": {}}
            for af in probe_afs:
                res = test_quic_handshake(host, port=443,
                                          timeout=QUIC_PROBE_TIMEOUT,
                                          ip_family=af)
                if res.status == TestStatus.SKIPPED.value:
                    continue
                ok = res.status == TestStatus.SUCCESS.value
                entry["af_results"][af] = {
                    "quic_ok": ok, "quic_error": res.error or "",
                    "quic_details": res.details,
                    "latency_ms": res.latency_ms,
                    "connected_ip": res.raw_data.get("connected_ip", ""),
                }
                if ok and not entry["quic_ok"]:
                    entry["quic_ok"] = True
                    entry["latency_ms"] = res.latency_ms
                elif not ok and res.error:
                    sub_errors.append(res.error)
                entry["details"] = entry["details"] or res.details
            if entry["quic_ok"]:
                ok_count += 1
                sum_latency += entry["latency_ms"]
            per_host.append(entry)

        total = max(len(hosts), 1)
        success_rate = round(ok_count / total, 3)
        baseline_open_all = bool(self._baseline_by_af) and \
            all(self._baseline_by_af.values())
        success = credit_success(ok_count > 0, baseline_open_all)
        latency = (sum_latency / ok_count) if ok_count else 0.0
        if success:
            err = ""
        elif baseline_open_all:
            err = "BASELINE_OPEN"
        else:
            err = self._pick_best_error(sub_errors, 0, 0) if sub_errors \
                else "QUIC_TIMEOUT"
        return {
            "success": success,
            "latency_ms": latency,
            "error": err,
            "http_code": 0,
            "kbps": 0.0,
            "body_passed": False,
            "success_rate": success_rate,
            "score": compose_score(success, success_rate, 1.0, latency)
                     if success else round(success_rate, 2),
            "test_type": "quic",
            "details": "AF=%s, QUIC %d/%d" % (",".join(probe_afs),
                                              ok_count, total),
            "per_host": per_host,
            "probe_afs": probe_afs,
            "baseline_by_af": dict(self._baseline_by_af),
        }

    # ─────────────────── Перепроверка лучших ───────────────────

    def _confirm_settings(self) -> tuple:
        """``(сколько лучших, сколько раз ещё)`` — из конфига или дефолт."""
        top, repeats = CONFIRM_TOP, CONFIRM_REPEATS
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            top = int(cfg.get("scan", "confirm_top", default=top))
            repeats = int(cfg.get("scan", "confirm_repeats",
                                  default=repeats))
        except (TypeError, ValueError):
            pass
        return max(0, min(top, 10)), max(0, min(repeats, 5))

    def _confirm_best(self) -> None:
        """Перепроверить лучшие находки ещё несколько раз.

        Один удачный замер — это и настоящая стратегия, и случайность
        (DPI пропустил одно соединение, CDN отдал кэш). Лучшие K
        проверяются ещё R раз; скорость и задержка берутся медианой,
        score умножается на долю пройденных проверок, а стратегия, не
        прошедшая большинства, успех теряет (``UNSTABLE``).
        """
        top, repeats = self._confirm_settings()
        if not top or not repeats:
            return
        with self._lock:
            candidates = sorted((r for r in self._results if r.success),
                                key=lambda r: r.score, reverse=True)[:top]
            self._confirm_total = len(candidates) * repeats
            self._confirm_progress = 0
        if not candidates:
            return

        self._set_stage(STAGE_CONFIRM)
        log.info("Перепроверка лучших: %d стратегий × %d"
                 % (len(candidates), repeats), source="scanner")
        for n, result in enumerate(candidates, 1):
            entry = self._entries_by_id.get(result.strategy_id)
            if entry is None:
                continue
            samples = [result]
            for _ in range(repeats):
                if self._cancelled:
                    break
                self._set_phase("Перепроверка лучших: %d из %d"
                                % (n, len(candidates)))
                with self._lock:
                    self._current_strategy_name = result.strategy_name
                samples.append(self._probe_one_strategy(entry, 0))
                with self._lock:
                    self._confirm_progress += 1
                time.sleep(INTER_STRATEGY_DELAY)
            self._merge_checks(result, samples)

    def _merge_checks(self, result: StrategyProbeResult,
                      samples: list) -> None:
        """Свести повторные замеры в один результат (медиана)."""
        checks = len(samples)
        good = [x for x in samples if x.success]
        passes = len(good)
        with self._lock:
            result.checks = checks
            result.passes = passes
            result.confirmed = checks > 1 and passes == checks
            result.raw_data["checks"] = [
                {"success": x.success, "latency_ms": round(x.latency_ms, 1),
                 "kbps": round(x.throughput_kbps, 1), "error": x.error}
                for x in samples]
            if passes * 2 <= checks:
                # Большинство проверок провалено: первый успех был
                # случайностью, а не стратегией.
                result.success = False
                result.error = "UNSTABLE"
                result.score = round(result.success_rate * passes / checks,
                                     2)
                return
            result.latency_ms = _median([x.latency_ms for x in good])
            result.throughput_kbps = _median([x.throughput_kbps
                                              for x in good])
            result.success_rate = _median([x.success_rate for x in good])
            speed = (result.throughput_kbps
                     if self._probe_kind_name() == "tls+body" else 1.0)
            result.score = round(
                compose_score(True, result.success_rate, speed,
                              result.latency_ms) * passes / checks, 2)

    # ─────────────────── Память подбора ───────────────────

    def _remember_findings(self) -> None:
        """Записать находки прогона в память подбора (core/strategy_memory).

        Удачи — всегда. Провалы — только у тех, кого выдвинула сама
        память, и у не прошедших перепроверку: память должна узнать, что
        стратегия перестала работать, но не копить сотни «не сработало»
        по всему каталогу (у неё потолок записей). Цель, открытая без
        обхода, в память не пишется: вклада стратегии там нет.
        """
        if self._baseline_by_af and all(self._baseline_by_af.values()):
            return
        with self._lock:
            results = list(self._results)
        observations = []
        for r in results:
            if not (r.success or r.from_memory or r.error == "UNSTABLE"):
                continue
            args = str(r.raw_data.get("args_preview") or "").split()
            if not args:
                continue
            observations.append({
                "target": self._target, "args": args, "ok": bool(r.success),
                "strategy_id": r.strategy_id, "label": r.strategy_name,
                "score": r.score, "success_rate": r.success_rate,
                "latency_ms": r.latency_ms,
            })
        if not observations:
            return
        try:
            from core import strategy_memory
            strategy_memory.remember(observations, source="scanner")
        except Exception as e:                  # noqa: BLE001 — граница
            log.debug("Память подбора не записана: %s" % e,
                      source="scanner")

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
            "FAKE_LEAK",         # HTTP 400 — сервер получил fake, стратегия не сработала
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
            "QUIC_REFUSED",
            "QUIC_TIMEOUT",
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
        # «Своя стратегия» — как standard: кандидатов мало, но человек
        # ждёт ответа быстрее полного прогона.
        if self._mode in ("standard", "custom"):
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

        from core.scan_targets import detect_target
        profile = self._scan_profile or detect_target(self._target)
        if self._protocol == "udp" and udp_probe_kind(profile) == "quic":
            return self._quic_baseline()

        # UDP-STUN: per-AF не делаем (STUN сам резолвит как умеет)
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
            ok = res.status == TestStatus.SUCCESS.value
            if ok:
                # Критерий — тот же, что у пробы стратегии (TLS + тело
                # ≥64 КБ): TLS-тестер читает ≤2 КБ, и при обрыве на
                # 16-20 КБ baseline видел бы «открыт», а каждая
                # стратегия получала бы BASELINE_OPEN — подбор под самый
                # частый тип блокировки не находил бы ничего.
                body = self._baseline_body(af)
                if body is not None and \
                        body.status != TestStatus.SUCCESS.value:
                    ok = False
                    res = body
            per_af[af] = ok
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

    def _quic_baseline(self) -> bool:
        """Baseline QUIC-цели: Initial с SNI без обхода, по IPv4 и IPv6.

        Критерий — тот же, что у пробы стратегии (``_quic_probe``).
        Нет адресов AF, «порт закрыт» (ICMP) или сетевая ошибка — AF
        из карты исключается: DPI-стратегия это не лечит.
        """
        from core.testers.quic_tester import test_quic_handshake

        per_af: dict[str, bool] = {}
        for af in ("ipv4", "ipv6"):
            try:
                res = test_quic_handshake(self._target, port=443,
                                          timeout=QUIC_PROBE_TIMEOUT,
                                          ip_family=af)
            except Exception as e:              # noqa: BLE001 — граница
                log.debug("Baseline QUIC %s: исключение %s" % (af, e),
                          source="scanner")
                continue
            if res.status == TestStatus.SKIPPED.value or \
                    res.error in ("QUIC_REFUSED", "QUIC_ERR"):
                continue
            per_af[af] = res.status == TestStatus.SUCCESS.value
            log.info("Baseline QUIC %s: %s (%s)" % (
                af, "доступен" if per_af[af] else "заблокирован",
                res.details), source="scanner")

        self._baseline_by_af = per_af
        self._baseline_open = any(per_af.values())
        if per_af and all(per_af.values()):
            log.warning(
                "Baseline: QUIC к %s работает без обхода — подбирать "
                "UDP-стратегию незачем" % self._target, source="scanner")
        return self._baseline_open

    def _baseline_body(self, af: str):
        """Body-проба цели без обхода по одному AF (или ``None``).

        URL — тот же, что у пробы стратегии для основного хоста
        (``_deep_probe``). ``None`` — проверить нечем (у цели нет адресов
        этого AF ни по пробному URL, ни по ней самой): тогда baseline
        остаётся на результате TLS.
        """
        from core.scan_targets import detect_target
        from core.testers.body_tester import probe_body

        profile = self._scan_profile or detect_target(self._target)
        urls = [profile.get_probe_url(), "https://%s/" % self._target]
        for url in dict.fromkeys(urls):
            body = probe_body(url=url, min_bytes=BODY_PROBE_MIN_BYTES,
                              timeout=BODY_PROBE_TIMEOUT, ip_family=af)
            if body.status != TestStatus.SKIPPED.value:
                return body
        return None

    # ─────────────────── State save/restore ───────────────────

    def _save_current_state(self) -> None:
        """
        Сохранить текущее состояние nfqws2 и firewall
        для восстановления после сканирования.

        Снимок снимает ``core/nfqws_session`` — тот же, которым
        пользуется движок экспериментов: два своих механизма отката
        независимо «вернули бы как было», и победил бы закончивший
        вторым.
        """
        from core.nfqws_session import get_nfqws_session

        snapshot = get_nfqws_session().snapshot(source="scanner")

        self._session_snapshot = snapshot
        self._saved_nfqws_running = snapshot["nfqws_running"]
        self._saved_nfqws_args = snapshot["nfqws_args"]
        self._saved_firewall_applied = snapshot["firewall_applied"]

    def _decide_isolation(self) -> None:
        """Песочница или старый путь — и почему (в статус и журнал).

        Песочница — когда она доступна (``nfqws_sandbox.available``) и
        baseline можно снять, не гася движок сети: движок не работает
        (замер и так прямой) или метка проб мимо очереди действует.
        """
        from core import nfqws_sandbox, probe_mark
        from core.nfqws_manager import get_nfqws_manager

        self._isolated, self._sandbox, self._sandbox_mark = False, None, 0
        self._baseline_mark = 0
        try:
            avail = nfqws_sandbox.available()
            if avail["ok"] and get_nfqws_manager().is_running():
                mode = probe_mark.baseline_mode()
                if mode["marked"]:
                    self._baseline_mark = mode["mark"]
                else:
                    avail = {"ok": False,
                             "reason": "baseline без остановки движка "
                                       "сети невозможен: %s"
                                       % mode["reason"]}
        except Exception as e:                  # noqa: BLE001 — граница
            avail = {"ok": False, "reason": "%s: %s"
                                            % (type(e).__name__, e)}

        if avail["ok"]:
            self._sandbox = nfqws_sandbox.NFQWSSandbox(
                nfqws_sandbox.queue_num())
            self._sandbox_mark = nfqws_sandbox.mark()
            self._isolated = True
            log.info("Подбор в песочнице: %s" % avail["reason"],
                     source="scanner")
        else:
            self._baseline_mark = 0
            log.info("Подбор без песочницы (%s): обход сети на время "
                     "подбора остановлен" % avail["reason"],
                     source="scanner")
        self._isolation_note = avail["reason"]

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

        Возвращает состояние ``core/nfqws_session.restore()`` — там же,
        где оно снималось. Условие «движок до скана НЕ работал — не
        трогаем» остаётся здесь: в этом случае состояние «как было» уже
        обеспечил ``_ensure_cleanup``.
        """
        if not self._saved_nfqws_running or self._isolated:
            # В песочнице движок сети не трогали — возвращать нечего.
            return

        from core.nfqws_session import get_nfqws_session

        get_nfqws_session().restore(
            getattr(self, "_session_snapshot", None) or {
                "nfqws_running": self._saved_nfqws_running,
                "nfqws_args": self._saved_nfqws_args,
                "firewall_applied": self._saved_firewall_applied,
            },
            source="scanner",
        )

    def _ensure_cleanup(self) -> None:
        """
        Гарантированная очистка: остановка nfqws2 и снятие firewall.

        Вызывается в finally блоке главного цикла. В песочнице — только
        её процесс и её правила: обход сети остаётся как был.
        """
        if self._isolated:
            try:
                if self._sandbox is not None:
                    self._sandbox.stop()
            except Exception as e:              # noqa: BLE001
                log.warning("Cleanup: песочница не остановилась: %s" % e,
                            source="scanner")
            try:
                from core.firewall import get_firewall_manager
                get_firewall_manager().remove_sandbox_rules()
            except Exception as e:              # noqa: BLE001
                log.warning("Cleanup: правила песочницы не сняты: %s" % e,
                            source="scanner")
            return
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

    def _resume_file_path(self) -> str:
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            custom = cfg.get("scan", "resume_file_path", default=None)
            if custom:
                return custom
        except Exception:
            pass
        # Рядом с settings.json, а не в /tmp: «Продолжить» должно пережить
        # перезагрузку роутера и перезапуск GUI — ради этого файл и
        # пишется. Пишется он не чаще раза в 5 стратегий или 10 с.
        try:
            from core.platform_dirs import config_dir
            return os.path.join(config_dir(), "state", "scan",
                                "resume.json")
        except Exception:
            import tempfile
            return os.path.join(tempfile.gettempdir(),
                                "zapret-gui-scan-resume.json")

    def _tmp_hostlist_path(self) -> str:
        try:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            custom = cfg.get("scan", "tmp_hostlist_path", default=None)
            if custom:
                return custom
        except Exception:
            pass
        import tempfile
        return os.path.join(tempfile.gettempdir(), "zapret-gui-scan-target.txt")

    def _save_resume_state(self, next_index: int) -> None:
        """Сохранить позицию для resume."""
        # Свой текст не продолжить (его нет в каталоге), а файл один:
        # не затираем позицию прерванного прогона по каталогу. Так же и
        # фоновый автоподбор (он один ходит с require_isolation): его
        # прогон не должен стирать «Продолжить» пользователя.
        if self._mode == "custom" or getattr(self, "_require_isolation",
                                             False):
            return
        resume_file = self._resume_file_path()
        with self._lock:
            state = {
                "target": self._target,
                "protocol": self._protocol,
                "mode": self._mode,
                "dpi_type": self._dpi_type,
                "memory_ids": list(self._memory_ids),
                "freeze": list(getattr(self, "_freeze", []) or []),
                "community": list(getattr(self, "_community", []) or []),
                "next_index": next_index,
                "timestamp": time.time(),
                "working_count": len(
                    [r for r in self._results if r.success]
                ),
                # Найденное до остановки: после «Продолжить» оно снова в
                # результатах, а не только числом «нашли 3».
                "working": [
                    r.to_dict() for r in sorted(
                        (r for r in self._results if r.success),
                        key=lambda r: -float(r.score or 0))
                ][:RESUME_KEEP_WORKING],
            }

        try:
            os.makedirs(os.path.dirname(resume_file), exist_ok=True)
            tmp = resume_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, resume_file)
        except (IOError, OSError):
            pass  # каталог может быть недоступен — не критично

    def saved_resume_info(self) -> dict:
        """Сохранённый прерванный подбор — для кнопки «Продолжить».

        Нужен после перезапуска GUI или роутера: статус сканера в памяти
        тогда ``idle``, и по нему одному продолжать было бы нечего.
        """
        state = self._load_resume_state()
        try:
            next_index = int(state.get("next_index", 0))
        except (TypeError, ValueError):
            next_index = 0
        if not state or next_index <= 0:
            return {}
        return {
            "target": state.get("target", ""),
            "protocol": state.get("protocol", ""),
            "mode": state.get("mode", ""),
            "dpi_type": state.get("dpi_type", ""),
            "next_index": next_index,
            "working_count": int(state.get("working_count") or 0),
            "timestamp": state.get("timestamp"),
        }

    def _restore_working(self) -> int:
        """Вернуть в результаты найденное прерванным прогоном."""
        restored = []
        for item in self._load_resume_state().get("working") or []:
            if not isinstance(item, dict) or not item.get("success"):
                continue
            try:
                fields = {k: item[k] for k in (
                    "strategy_id", "strategy_name", "target", "success",
                    "latency_ms", "error", "http_code", "timestamp",
                    "protocol", "throughput_kbps", "body_passed",
                    "success_rate", "score", "checks", "passes",
                    "confirmed", "from_memory", "raw_data") if k in item}
                restored.append(StrategyProbeResult(**fields))
            except (TypeError, ValueError):
                continue
        with self._lock:
            self._results.extend(restored)
        return len(restored)

    def _load_resume_state(self) -> dict:
        """
        Загрузить сохранённое состояние resume.

        Returns:
            Словарь ``{target, protocol, mode, dpi_type, next_index, …}``
            (пустой, если данных нет или файл битый).
        """
        resume_file = self._resume_file_path()
        try:
            if not os.path.exists(resume_file):
                return {}
            with open(resume_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except (IOError, OSError, ValueError):
            return {}
        return state if isinstance(state, dict) else {}

    def _remove_resume_state(self) -> None:
        """Удалить файл resume state."""
        resume_file = self._resume_file_path()
        try:
            if os.path.exists(resume_file):
                os.remove(resume_file)
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
        with self._lock:
            working = [r for r in self._results if r.success]

            # Лучшая = подтверждённая перепроверкой, среди них — с
            # максимальным score (success_rate × kbps/latency). Score
            # надёжнее latency: низкая задержка бывает у «псевдо-успехов»,
            # у которых тело обрывается на 16-20 KB.
            best: Optional[StrategyProbeResult] = None
            if working:
                best = max(working, key=lambda r: (r.confirmed, r.score))

            # Для UI: рабочие вперёд, среди них подтверждённые, затем score.
            self._results.sort(
                key=lambda r: (r.success, r.confirmed, r.score),
                reverse=True)

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
                probe_kind=self._probe_kind_name(),
                stop_after=self._stop_after,
                stopped_early=self._stopped_early,
                confirmed_count=len([r for r in working if r.confirmed]),
                memory_first=len(self._memory_ids),
                rules_reapplied=self._rules_reapplied,
            )

    # ─────────────────── Apply strategy ───────────────────

    def _save_probe_result(self, probe_result: StrategyProbeResult):
        """
        Сохранить находку пользовательской стратегией (JSON) через
        StrategyManager. Возвращает сохранённую стратегию или ``None``.
        """
        from core.catalog_loader import get_catalog_manager
        from core.strategy_builder import get_strategy_manager

        # Находим оригинальную запись каталога
        cm = get_catalog_manager()
        entry = cm.get_entry_by_id(
            probe_result.strategy_id,
            protocol=probe_result.protocol,
        )
        if entry is None:
            # «Своя стратегия» — не из каталога: запись этого прогона.
            with self._lock:
                entry = self._entries_by_id.get(probe_result.strategy_id)

        if entry is None:
            log.error(
                "Запись каталога не найдена: %s" % probe_result.strategy_id,
                source="scanner",
            )
            return None

        # Собираем аргументы
        args = self._build_strategy_args(entry)
        if not args:
            log.error(
                "Не удалось собрать аргументы для: %s"
                % probe_result.strategy_name,
                source="scanner",
            )
            return None

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
            return None
        return saved

    def save_working_by_id(self, strategy_id: str):
        """Сохранить находку своей стратегией, НЕ применяя её.

        Для автоподбора (core/autopick.py): применять он будет через
        «Применить с проверкой», а не напрямую.

        Returns:
            dict сохранённой стратегии (``id``, ``name``…) или ``None``.
        """
        with self._lock:
            probe_result = next((r for r in self._results
                                 if r.success and r.strategy_id == strategy_id),
                                None)
        if probe_result is None:
            return None
        return self._save_probe_result(probe_result)

    def _apply_probe_result(self, probe_result: StrategyProbeResult) -> bool:
        """
        Применить стратегию из результата пробы: сохранить своей
        (:meth:`_save_probe_result`) и применить.
        """
        saved = self._save_probe_result(probe_result)
        if not saved:
            return False
        entry_name = probe_result.strategy_name

        # Применяем тем же путём, что кнопка «Применить» и MCP
        # (`nfqws_control.apply_strategy`): общий мьютекс на движок (не
        # поверх идущего скана или эксперимента), откат правил при
        # неудачном старте, запись в конфиг и пересборка автозапуска —
        # иначе после перезагрузки роутера поднялась бы прежняя
        # стратегия.
        from core import nfqws_control
        result = nfqws_control.apply_strategy(saved["id"], source="scanner")
        if not result.get("ok"):
            log.error(
                "Не удалось применить стратегию %s: %s"
                % (entry_name, result.get("error") or "?"),
                source="scanner",
            )
            return False

        log.success(
            "Стратегия применена: %s" % entry_name,
            source="scanner",
        )
        return True

    def _materialize_tmp_hostlist(
        self,
        args: list[str],
        probe_result: StrategyProbeResult,
    ) -> list[str]:
        """Заменить ссылку на TMP_HOSTLIST_PATH на постоянный файл.

        При сканировании trick'ам подсовывается временный target.txt, который
        удаляется в finally. Чтобы применённая стратегия пережила перезапуск
        nfqws2, копируем содержимое в lists_path/zapret-gui-target-<key>.txt
        и переписываем --hostlist=… на этот путь.
        """
        tmp_hostlist = self._tmp_hostlist_path()
        if not any(a.endswith(tmp_hostlist) for a in args):
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
            ("--hostlist=%s" % permanent) if a == ("--hostlist=%s" % tmp_hostlist)
            else a
            for a in args
        ]

    # ─────────────────── Helpers ───────────────────

    def _set_stage(self, stage: str) -> None:
        """Этап прогона (prepare/baseline/scan/confirm/done)."""
        with self._lock:
            self._stage = stage

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

        tmp_hostlist = self._tmp_hostlist_path()
        try:
            with open(tmp_hostlist, "w", encoding="utf-8") as f:
                for d in domains:
                    f.write(d.strip() + "\n")
            self._tmp_hostlist = tmp_hostlist
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

def _median(values) -> float:
    """Медиана без ``statistics`` (его может не быть в python3-light)."""
    items = sorted(float(v or 0.0) for v in values)
    if not items:
        return 0.0
    mid = len(items) // 2
    if len(items) % 2:
        return items[mid]
    return (items[mid - 1] + items[mid]) / 2.0


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
