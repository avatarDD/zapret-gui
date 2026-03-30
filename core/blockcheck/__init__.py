"""BlockCheck — анализ сетевых блокировок и автоподбор стратегий.

Публичный API (фаза 13.0 — модели и конфигурация):
    TestStatus, DPIClassification, TestType, PreflightVerdict — enum-ы
    SingleTestResult, TargetResult, DNSIntegrityResult       — результаты тестов
    PreflightResult, BlockcheckReport                        — отчёты
    StrategyProbeResult, StrategyScanReport                   — результаты сканирования

Остальные компоненты (runner, scanner, тестеры) добавляются
в последующих фазах.
"""

from core.blockcheck.models import (
    BlockcheckReport,
    DPIClassification,
    DNSIntegrityResult,
    PreflightResult,
    PreflightVerdict,
    SingleTestResult,
    TargetResult,
    TestStatus,
    TestType,
)
from core.blockcheck.scan_models import (
    StrategyProbeResult,
    StrategyScanReport,
)

__all__ = [
    "BlockcheckReport",
    "DPIClassification",
    "DNSIntegrityResult",
    "PreflightResult",
    "PreflightVerdict",
    "SingleTestResult",
    "StrategyProbeResult",
    "StrategyScanReport",
    "TargetResult",
    "TestStatus",
    "TestType",
]
