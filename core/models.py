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
        return {
            "domain": self.domain,
            "results": [r.to_dict() for r in self.results],
            "dpi_classification": self.dpi_classification,
            "dpi_detail": self.dpi_detail,
            "summary": self.summary,
        }


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
        }


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
        return {
            "target": self.target,
            "protocol": self.protocol,
            "mode": self.mode,
            "total_tested": self.total_tested,
            "total_available": self.total_available,
            "working_count": len(working),
            "failed_count": len(failed),
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

    INI-формат:
        [section_id]
        name = Display Name
        author = Author
        label = recommended
        description = Описание
        blobs = blob1,blob2
        --lua-desync=fake:blob=...
    """

    section_id: str
    name: str
    args: str               # многострочная строка аргументов (--lua-desync=...)
    author: str = ""
    label: str = ""         # recommended, experimental, game, stable, caution
    description: str = ""
    blobs: list[str] = field(default_factory=list)
    protocol: str = ""      # tcp / udp — определяется из имени файла
    level: str = ""         # basic / advanced / direct
    source_file: str = ""   # имя файла-источника

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "name": self.name,
            "args": self.args,
            "author": self.author,
            "label": self.label,
            "description": self.description,
            "blobs": self.blobs,
            "protocol": self.protocol,
            "level": self.level,
            "source_file": self.source_file,
        }

    def get_args_list(self) -> list[str]:
        """
        Разбить args на список строк-аргументов.

        Каждая строка в args начинается с '--' и представляет
        один аргумент nfqws2.

        Returns:
            ['--lua-desync=fake:blob=...', '--lua-desync=multisplit:...']
        """
        if not self.args:
            return []
        return [line.strip() for line in self.args.splitlines()
                if line.strip().startswith("--")]
