"""Модели результатов сканирования стратегий — чистый Python.

Без dataclasses, без typing. JSON-сериализуемы через to_dict().
"""


class StrategyProbeResult:
    """Результат тестирования одной стратегии на одной цели."""

    __slots__ = (
        "strategy_name", "strategy_id", "strategy_args",
        "target", "success", "time_ms", "error",
        "http_code", "scan_protocol", "probe_type",
        "target_port", "raw_data",
    )

    def __init__(self, strategy_name, strategy_id, strategy_args,
                 target, success, time_ms,
                 error="", http_code=0,
                 scan_protocol="tcp_https", probe_type="https",
                 target_port=443, raw_data=None):
        self.strategy_name = strategy_name
        self.strategy_id = strategy_id
        self.strategy_args = strategy_args
        self.target = target
        self.success = success
        self.time_ms = time_ms
        self.error = error
        self.http_code = http_code
        self.scan_protocol = scan_protocol
        self.probe_type = probe_type
        self.target_port = target_port
        self.raw_data = raw_data if raw_data is not None else {}

    def to_dict(self):
        return {
            "strategy_name": self.strategy_name,
            "strategy_id": self.strategy_id,
            "strategy_args": self.strategy_args,
            "target": self.target,
            "success": self.success,
            "time_ms": self.time_ms,
            "error": self.error,
            "http_code": self.http_code,
            "scan_protocol": self.scan_protocol,
            "probe_type": self.probe_type,
            "target_port": self.target_port,
            "raw_data": self.raw_data,
        }


class StrategyScanReport:
    """Агрегированный результат сканирования множества стратегий."""

    __slots__ = (
        "target", "total_tested", "total_available",
        "working_strategies", "failed_strategies",
        "elapsed_seconds", "cancelled",
        "baseline_accessible", "scan_protocol",
    )

    def __init__(self, target, total_tested,
                 total_available=0, working_strategies=None,
                 failed_strategies=None, elapsed_seconds=0.0,
                 cancelled=False, baseline_accessible=False,
                 scan_protocol="tcp_https"):
        self.target = target
        self.total_tested = total_tested
        self.total_available = total_available
        self.working_strategies = working_strategies if working_strategies is not None else []
        self.failed_strategies = failed_strategies if failed_strategies is not None else []
        self.elapsed_seconds = elapsed_seconds
        self.cancelled = cancelled
        self.baseline_accessible = baseline_accessible
        self.scan_protocol = scan_protocol

    def to_dict(self):
        return {
            "target": self.target,
            "total_tested": self.total_tested,
            "total_available": self.total_available,
            "working_strategies": [s.to_dict() for s in self.working_strategies],
            "failed_strategies": [s.to_dict() for s in self.failed_strategies],
            "elapsed_seconds": self.elapsed_seconds,
            "cancelled": self.cancelled,
            "baseline_accessible": self.baseline_accessible,
            "scan_protocol": self.scan_protocol,
        }
