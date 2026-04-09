# core/models.py
"""
Модели данных для blockcheck (тестирование доступности)
и strategy scanner (подбор стратегий).

Чистые dataclass-ы (stdlib), с .to_dict() для JSON-сериализации
через REST API.

Использование:
    from core.models import (
        TestStatus, TestType, SingleTestResult, TargetResult,
        BlockcheckReport, StrategyProbeResult, StrategyScanReport,
        CatalogEntry,
    )
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════

class TestStatus(Enum):
    """Статус отдельного теста."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    ERROR = "error"


class TestType(Enum):
    """Тип сетевого теста."""
    DNS = "dns"
    HTTP = "http"
    TLS_12 = "tls12"
    TLS_13 = "tls13"
    STUN = "stun"
    TCP_16_20 = "tcp_16_20"
    PING = "ping"
    ISP_DETECT = "isp_detect"
    HTTP_INJECT = "http_inject"


class DPIClassification(Enum):
    """Тип обнаруженной DPI-блокировки."""
    NONE = "none"
    DNS_FAKE = "dns_fake"
    HTTP_INJECT = "http_inject"
    ISP_PAGE = "isp_page"
    TLS_DPI = "tls_dpi"
    TLS_MITM = "tls_mitm"
    TCP_RESET = "tcp_reset"
    TCP_16_20 = "tcp_16_20"
    STUN_BLOCK = "stun_block"
    FULL_BLOCK = "full_block"
    TIMEOUT_DROP = "timeout_drop"
    UNKNOWN = "unknown"


class ScanMode(Enum):
    """Режим сканирования стратегий."""
    QUICK = "quick"       # ~30 стратегий (recommended + первые N)
    STANDARD = "standard"  # ~80 стратегий
    FULL = "full"          # все стратегии из каталога


class ScanProtocol(Enum):
    """Протокол для сканирования."""
    TCP = "tcp"
    UDP = "udp"


# ═══════════════════════════════════════════════════════════
#  BlockCheck models
# ═══════════════════════════════════════════════════════════

@dataclass
class SingleTestResult:
    """Результат одного теста для одной цели."""

    target: str
    test_type: str          # значение TestType.value
    status: str             # значение TestStatus.value
    latency_ms: float = 0.0
    error: str = ""
    details: str = ""
    timestamp: float = 0.0
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "test_type": self.test_type,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
            "details": self.details,
            "timestamp": self.timestamp,
            "raw_data": self.raw_data,
        }


@dataclass
class TargetResult:
    """Агрегированные результаты тестов для одного домена/цели."""

    domain: str
    results: list[SingleTestResult] = field(default_factory=list)
    dpi_classification: str = DPIClassification.NONE.value
    dpi_detail: str = ""
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        # Собираем tests как dict по test_type для удобства фронтенда
        tests: dict[str, dict[str, Any]] = {}
        for r in self.results:
            tt = r.test_type
            # Если уже есть результат этого типа — не перезаписываем
            if tt not in tests:
                tests[tt] = r.to_dict()

        # Вычисляем overall_status
        overall = self._compute_overall_status()

        return {
            "domain": self.domain,
            "target": self.domain,
            "results": [r.to_dict() for r in self.results],
            "tests": tests,
            "overall_status": overall,
            "dpi_classification": self.dpi_classification,
            "dpi_detail": self.dpi_detail,
            "summary": self.summary,
        }

    def _compute_overall_status(self) -> str:
        """Вычислить общий статус цели на основе результатов тестов.

        FIX: timeout и error теперь считаются как failures,
        а не игнорируются (ранее только "failed" считался неуспехом,
        из-за чего домен с DNS=OK + TLS=Timeout показывался как "Доступен").
        """
        if not self.results:
            return "unknown"

        # Исключаем skipped и pending из анализа
        meaningful = [
            r for r in self.results
            if r.status not in (TestStatus.SKIPPED.value, TestStatus.PENDING.value)
        ]
        if not meaningful:
            return "unknown"

        success_count = sum(
            1 for r in meaningful if r.status == TestStatus.SUCCESS.value
        )
        # FIX: timeout, error и failed — все считаются как неуспех
        fail_count = sum(
            1 for r in meaningful if r.status in (
                TestStatus.FAILED.value,
                TestStatus.TIMEOUT.value,
                TestStatus.ERROR.value,
            )
        )

        # Проверяем DNS отдельно
        dns_results = [
            r for r in meaningful if r.test_type == TestType.DNS.value
        ]
        if dns_results and all(
            r.status in (TestStatus.FAILED.value, TestStatus.ERROR.value)
            for r in dns_results
        ):
            return "dns_blocked"

        if fail_count == 0 and success_count > 0:
            return "accessible"
        if success_count == 0 and fail_count > 0:
            return "blocked"
        if success_count > 0 and fail_count > 0:
            return "partial"
        return "unknown"


@dataclass
class BlockcheckReport:
    """Полный отчёт blockcheck."""

    targets: list[TargetResult] = field(default_factory=list)
    mode: str = "quick"
    started_at: float = 0.0
    finished_at: float = 0.0
    dpi_classification: str = DPIClassification.NONE.value
    dpi_detail: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        # Подсчёт статистики
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        for t in self.targets:
            for r in t.results:
                total_tests += 1
                if r.status == TestStatus.SUCCESS.value:
                    passed_tests += 1
                elif r.status in (TestStatus.FAILED.value, TestStatus.ERROR.value,
                                  TestStatus.TIMEOUT.value):
                    failed_tests += 1

        # Генерируем рекомендации
        recommendations = self._build_recommendations()

        return {
            "targets": [t.to_dict() for t in self.targets],
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.finished_at - self.started_at, 2)
                if self.finished_at > 0 and self.started_at > 0 else 0.0,
            "dpi_classification": self.dpi_classification,
            "dpi_detail": self.dpi_detail,
            "error": self.error,
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "recommendations": recommendations,
        }

    def _build_recommendations(self) -> list[str]:
        """Построить список рекомендаций на основе результатов."""
        recs: list[str] = []
        dpi = self.dpi_classification

        if dpi == DPIClassification.TLS_DPI.value:
            recs.append("Обнаружена DPI-блокировка TLS (SNI/ClientHello). Используйте стратегии с фрагментацией ClientHello.")
            recs.append("Попробуйте подбор стратегий в разделе «Подбор стратегий».")
        elif dpi == DPIClassification.DNS_FAKE.value:
            recs.append("DNS-подмена. Настройте DoH/DoT или пропишите IP в /etc/hosts.")
        elif dpi == DPIClassification.HTTP_INJECT.value:
            recs.append("HTTP injection. Используйте HTTPS и стратегии обхода DPI.")
        elif dpi == DPIClassification.ISP_PAGE.value:
            recs.append("ISP-заглушка. Используйте стратегии обхода DPI для HTTPS.")
        elif dpi == DPIClassification.TCP_RESET.value:
            recs.append("TCP RST блокировка. Попробуйте стратегии с desync=fake.")
        elif dpi == DPIClassification.TCP_16_20.value:
            recs.append("TCP-блокировка на 16-20KB. Попробуйте стратегии с split/disorder.")
        elif dpi == DPIClassification.STUN_BLOCK.value:
            recs.append("STUN/UDP заблокирован. Голосовые звонки могут не работать. Попробуйте UDP-стратегии.")
        elif dpi == DPIClassification.FULL_BLOCK.value:
            recs.append("Полная блокировка всех протоколов. Возможно требуется VPN/прокси.")
        elif dpi == DPIClassification.TIMEOUT_DROP.value:
            recs.append("Пакеты дропаются (timeout). Попробуйте стратегии с desync=fake.")
        elif dpi == DPIClassification.NONE.value:
            if self.error:
                pass  # ошибка запуска, не даём рекомендации
            else:
                recs.append("DPI не обнаружен. Ресурсы доступны без обхода.")

        return recs


# ═══════════════════════════════════════════════════════════
#  Strategy Scanner models
# ═══════════════════════════════════════════════════════════

@dataclass
class StrategyProbeResult:
    """Результат проверки одной стратегии на одной цели."""

    strategy_id: str
    strategy_name: str
    target: str
    success: bool = False
    latency_ms: float = 0.0
    error: str = ""
    http_code: int = 0
    timestamp: float = 0.0
    protocol: str = "tcp"
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "strategy_name": self.strategy_name,
            "target": self.target,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
            "http_code": self.http_code,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            # FIX: включаем raw_data — содержит args_preview, details и др.
            "raw_data": self.raw_data,
        }


@dataclass
class StrategyScanReport:
    """Полный отчёт сканирования стратегий."""

    target: str = ""
    protocol: str = "tcp"
    mode: str = "quick"
    results: list[StrategyProbeResult] = field(default_factory=list)
    best_strategy: Optional[StrategyProbeResult] = None
    total_tested: int = 0
    total_available: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    cancelled: bool = False
    baseline_accessible: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        working = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        # Считаем процент успешности
        total = len(self.results)
        success_rate = round(len(working) / total * 100, 1) if total > 0 else 0.0

        return {
            "target": self.target,
            "protocol": self.protocol,
            "mode": self.mode,
            "total_tested": self.total_tested,
            "total_available": self.total_available,
            "working_count": len(working),
            "failed_count": len(failed),
            "success_rate": success_rate,
            "working_strategies": [r.to_dict() for r in working],
            "failed_strategies": [r.to_dict() for r in failed],
            "best_strategy": self.best_strategy.to_dict()
                if self.best_strategy else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.finished_at - self.started_at, 2)
                if self.finished_at > 0 and self.started_at > 0 else 0.0,
            "cancelled": self.cancelled,
            "baseline_accessible": self.baseline_accessible,
            "error": self.error,
        }


# ═══════════════════════════════════════════════════════════
#  INI-каталог стратегий — модель записи
# ═══════════════════════════════════════════════════════════

@dataclass
class CatalogEntry:
    """
    Одна стратегия из INI-каталога.

    Поля:
        section_id:  ID секции в INI-файле (e.g. "s01_fake_sni")
        name:        Человекочитаемое имя стратегии
        description: Описание стратегии (опционально)
        author:      Автор
        label:       Метка ("recommended", "experimental", "")
        blobs:       Список имён блобов, нужных стратегии
        args:        Строка аргументов nfqws2 (разделены \\n)
        protocol:    "tcp" или "udp"
        level:       "basic", "advanced", "direct", "builtin"
        source_file: Путь к файлу-источнику
    """

    section_id: str
    name: str = ""
    description: str = ""
    author: str = ""
    label: str = ""
    blobs: list[str] = field(default_factory=list)
    args: str = ""
    protocol: str = "tcp"
    level: str = "basic"
    source_file: str = ""

    def get_args_list(self) -> list[str]:
        """
        Разбить строку аргументов на список.

        args хранится как '\\n'-joined строка (каждая строка — один аргумент
        nfqws2, например '--lua-desync=fake:blob=sni').
        Возвращает список непустых строк.
        """
        if not self.args:
            return []
        return [line.strip() for line in self.args.split("\n") if line.strip()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "label": self.label,
            "blobs": list(self.blobs),
            "args": self.args,
            "protocol": self.protocol,
            "level": self.level,
            "source_file": self.source_file,
        }

    @property
    def display_name(self) -> str:
        """Имя для отображения."""
        return self.name or self.section_id
