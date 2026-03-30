"""BlockCheck data models — чистый Python, без dataclasses.

Все модели JSON-сериализуемы через to_dict().
Совместимо с python3-light (Entware): enum с fallback,
без dataclasses и typing.
"""

# Enum с fallback для python3-light
try:
    from enum import Enum
except ImportError:
    class Enum:
        """Минимальная замена enum.Enum для python3-light."""
        def __init_subclass__(cls, **kw):
            super().__init_subclass__(**kw)
            cls._members = {}
            for k, v in list(cls.__dict__.items()):
                if not k.startswith("_"):
                    obj = cls.__new__(cls)
                    obj._name = k
                    obj._value = v
                    cls._members[k] = obj
                    setattr(cls, k, obj)

        @property
        def name(self):
            return self._name

        @property
        def value(self):
            return self._value

        def __repr__(self):
            return "<%s.%s: %r>" % (self.__class__.__name__, self._name, self._value)

        def __eq__(self, other):
            if isinstance(other, self.__class__):
                return self._value == other._value
            return NotImplemented

        def __hash__(self):
            return hash(self._value)


# ═══════════════════ Enums ═══════════════════


class TestStatus(Enum):
    """Статус отдельного теста."""
    OK = "ok"
    FAIL = "fail"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class DPIClassification(Enum):
    """Тип обнаруженного DPI / блокировки."""
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


class TestType(Enum):
    """Тип проводимого теста."""
    HTTP = "http"
    TLS_12 = "tls12"
    TLS_13 = "tls13"
    STUN = "stun"
    PING = "ping"
    DNS_UDP = "dns_udp"
    DNS_DOH = "dns_doh"
    ISP_PAGE = "isp_page"
    TCP_16_20 = "tcp_16_20"
    PREFLIGHT_DNS = "preflight_dns"
    PREFLIGHT_TCP = "preflight_tcp"
    PREFLIGHT_HTTP = "preflight_http"
    PREFLIGHT_PING = "preflight_ping"


class PreflightVerdict(Enum):
    """Результат предварительной проверки домена."""
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"


# ═══════════════════ Helpers ═══════════════════


def _enum_val(v):
    """Извлечь .value из Enum или вернуть как есть."""
    return v.value if isinstance(v, Enum) else v


# ═══════════════════ Models ═══════════════════


class SingleTestResult:
    """Результат одного теста для одной цели."""

    __slots__ = (
        "target_name", "test_type", "status",
        "time_ms", "error_code", "detail", "raw_data",
    )

    def __init__(self, target_name, test_type, status,
                 time_ms=None, error_code=None, detail="", raw_data=None):
        self.target_name = target_name
        self.test_type = test_type
        self.status = status
        self.time_ms = time_ms
        self.error_code = error_code
        self.detail = detail
        self.raw_data = raw_data if raw_data is not None else {}

    def to_dict(self):
        return {
            "target_name": self.target_name,
            "test_type": _enum_val(self.test_type),
            "status": _enum_val(self.status),
            "time_ms": self.time_ms,
            "error_code": self.error_code,
            "detail": self.detail,
            "raw_data": self.raw_data,
        }


class TargetResult:
    """Агрегированный результат проверки одной цели (домена)."""

    __slots__ = (
        "name", "value", "tests",
        "classification", "classification_detail",
    )

    def __init__(self, name, value, tests=None,
                 classification=None, classification_detail=""):
        self.name = name
        self.value = value
        self.tests = tests if tests is not None else []
        self.classification = classification or DPIClassification.NONE
        self.classification_detail = classification_detail

    def to_dict(self):
        return {
            "name": self.name,
            "value": self.value,
            "tests": [t.to_dict() for t in self.tests],
            "classification": _enum_val(self.classification),
            "classification_detail": self.classification_detail,
        }


class DNSIntegrityResult:
    """Результат проверки DNS-целостности (UDP vs DoH)."""

    __slots__ = (
        "domain", "udp_ips", "doh_ips",
        "is_comparable", "is_consistent", "is_stub", "stub_ip",
    )

    def __init__(self, domain, udp_ips=None, doh_ips=None,
                 is_comparable=False, is_consistent=True,
                 is_stub=False, stub_ip=None):
        self.domain = domain
        self.udp_ips = udp_ips if udp_ips is not None else []
        self.doh_ips = doh_ips if doh_ips is not None else []
        self.is_comparable = is_comparable
        self.is_consistent = is_consistent
        self.is_stub = is_stub
        self.stub_ip = stub_ip

    def to_dict(self):
        return {
            "domain": self.domain,
            "udp_ips": self.udp_ips,
            "doh_ips": self.doh_ips,
            "is_comparable": self.is_comparable,
            "is_consistent": self.is_consistent,
            "is_stub": self.is_stub,
            "stub_ip": self.stub_ip,
        }


class PreflightResult:
    """Результат preflight-проверки одного домена."""

    __slots__ = (
        "domain", "resolved_ips", "is_block_ip", "block_ip_detail",
        "ping", "tcp_443", "dns_result", "http_check",
        "verdict", "verdict_detail",
    )

    def __init__(self, domain, resolved_ips=None,
                 is_block_ip=False, block_ip_detail="",
                 ping=None, tcp_443=None, dns_result=None, http_check=None,
                 verdict=None, verdict_detail=""):
        self.domain = domain
        self.resolved_ips = resolved_ips if resolved_ips is not None else []
        self.is_block_ip = is_block_ip
        self.block_ip_detail = block_ip_detail
        self.ping = ping
        self.tcp_443 = tcp_443
        self.dns_result = dns_result
        self.http_check = http_check
        self.verdict = verdict or PreflightVerdict.PASSED
        self.verdict_detail = verdict_detail

    def to_dict(self):
        return {
            "domain": self.domain,
            "resolved_ips": self.resolved_ips,
            "is_block_ip": self.is_block_ip,
            "block_ip_detail": self.block_ip_detail,
            "ping": self.ping.to_dict() if self.ping else None,
            "tcp_443": self.tcp_443.to_dict() if self.tcp_443 else None,
            "dns_result": self.dns_result.to_dict() if self.dns_result else None,
            "http_check": self.http_check.to_dict() if self.http_check else None,
            "verdict": _enum_val(self.verdict),
            "verdict_detail": self.verdict_detail,
        }


class BlockcheckReport:
    """Итоговый отчёт blockcheck-диагностики."""

    __slots__ = (
        "preflight", "targets", "dns_integrity",
        "summary", "elapsed_seconds",
    )

    def __init__(self, preflight=None, targets=None, dns_integrity=None,
                 summary=None, elapsed_seconds=0.0):
        self.preflight = preflight if preflight is not None else []
        self.targets = targets if targets is not None else []
        self.dns_integrity = dns_integrity if dns_integrity is not None else []
        self.summary = summary if summary is not None else {}
        self.elapsed_seconds = elapsed_seconds

    def to_dict(self):
        return {
            "preflight": [p.to_dict() for p in self.preflight],
            "targets": [t.to_dict() for t in self.targets],
            "dns_integrity": [d.to_dict() for d in self.dns_integrity],
            "summary": self.summary,
            "elapsed_seconds": self.elapsed_seconds,
        }
