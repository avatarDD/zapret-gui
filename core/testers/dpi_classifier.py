# core/testers/dpi_classifier.py
"""
DPI classification engine — таксономия ошибок и агрегированная классификация.

Анализирует результаты тестов для одного домена и определяет тип DPI-блокировки:
TCP RST, TLS DPI, ISP-заглушка, DNS-подмена, HTTP inject, STUN block и др.

Использование:
    from core.testers.dpi_classifier import DPIClassifier, classify_ssl_error
    classification, detail = DPIClassifier.classify(target_result)
"""

from __future__ import annotations

import ssl

from core.models import (
    DPIClassification,
    SingleTestResult,
    TargetResult,
    TestStatus,
    TestType,
)
from core.testers.config import (
    ERRNO_HOST_UNREACH,
    ERRNO_NET_UNREACH,
    ERRNO_REFUSED,
    ERRNO_RESET,
    ERRNO_TIMEOUT,
)


# ---------------------------------------------------------------------------
# SSL / TLS error classification
# ---------------------------------------------------------------------------

def classify_ssl_error(
    error: Exception, bytes_read: int = 0,
) -> tuple[str, str, int]:
    """Классифицировать ssl.SSLError → (label, detail, bytes_read).

    Returns:
        label: короткий код ошибки
        detail: описание для человека
        bytes_read: примерное кол-во байт до ошибки
    """
    msg = str(error).lower()

    # Connection reset во время TLS handshake — классическая сигнатура DPI
    if "connection reset" in msg or "connection was reset" in msg:
        return "TLS_RESET", "TCP RST during TLS handshake (DPI)", 0

    # EOF во время handshake — другой паттерн DPI
    if "eof occurred" in msg or "unexpected eof" in msg:
        if bytes_read == 0:
            return "TLS_EOF_EARLY", "EOF during handshake (DPI or firewall)", 0
        return "TLS_EOF_DATA", "EOF after partial data", bytes_read

    # Ошибки сертификата — детекция MITM
    if "certificate verify failed" in msg:
        if "self signed" in msg or "self-signed" in msg:
            return "TLS_MITM_SELF", "Self-signed cert (possible MITM proxy)", 0
        if "unable to get local issuer" in msg:
            return "TLS_MITM_UNKNOWN_CA", "Unknown CA (possible MITM)", 0
        return "TLS_CERT_ERR", "Certificate verification failed", 0

    # Несовместимость версии / шифра
    if "unsupported" in msg or "no protocols available" in msg:
        return "TLS_UNSUPPORTED", "TLS version not supported by server", 0
    if "version" in msg:
        return "TLS_VERSION", "TLS version mismatch", 0
    if "handshake failure" in msg or "sslv3 alert handshake" in msg:
        return "TLS_HANDSHAKE", "Handshake failure", 0

    # Alert-based
    if "alert" in msg:
        if "internal error" in msg:
            return "TLS_ALERT_INTERNAL", "Server internal error alert", 0
        if "unrecognized_name" in msg:
            return "TLS_SNI_REJECT", "SNI rejected by server", 0
        return "TLS_ALERT", f"TLS alert: {msg[:80]}", 0

    # Timeout во время SSL
    if "timed out" in msg:
        return "TLS_TIMEOUT", "TLS handshake timeout (possible DPI)", 0

    return "TLS_ERR", f"SSL error: {msg[:100]}", bytes_read


# ---------------------------------------------------------------------------
# TCP connect error classification (Linux errno)
# ---------------------------------------------------------------------------

def classify_connect_error(
    error: Exception, bytes_read: int = 0,
) -> tuple[str, str, int]:
    """Классифицировать ошибку TCP-подключения (Linux errno)."""
    msg = str(error).lower()
    err_no = getattr(error, "errno", None) or 0

    if isinstance(error, ConnectionResetError) or err_no == ERRNO_RESET:
        return "TCP_RESET", "Connection reset by remote (DPI or firewall)", 0

    if isinstance(error, ConnectionRefusedError) or err_no == ERRNO_REFUSED:
        return "TCP_REFUSED", "Connection refused", 0

    if err_no == ERRNO_TIMEOUT or "timed out" in msg:
        return "TCP_TIMEOUT", "TCP connection timeout", 0

    if err_no == ERRNO_HOST_UNREACH:
        return "HOST_UNREACH", "Host unreachable", 0

    if err_no == ERRNO_NET_UNREACH:
        return "NET_UNREACH", "Network unreachable", 0

    if "connection aborted" in msg:
        return "TCP_ABORT", "Connection aborted", 0

    return "CONNECT_ERR", f"Connection error: {msg[:100]}", bytes_read


# ---------------------------------------------------------------------------
# Read / response error classification
# ---------------------------------------------------------------------------

def classify_read_error(
    error: Exception, bytes_read: int = 0,
) -> tuple[str, str, int]:
    """Классифицировать ошибку при чтении ответа."""
    msg = str(error).lower()

    if "reset" in msg:
        return "READ_RESET", f"Reset after {bytes_read}B read (DPI mid-stream)", bytes_read

    if "timed out" in msg:
        return "READ_TIMEOUT", f"Read timeout after {bytes_read}B", bytes_read

    if "broken pipe" in msg or "connection aborted" in msg:
        return "READ_BROKEN", f"Broken pipe after {bytes_read}B", bytes_read

    return "READ_ERR", f"Read error: {msg[:80]}", bytes_read


# ---------------------------------------------------------------------------
# Aggregate DPI classification
# ---------------------------------------------------------------------------

class DPIClassifier:
    """Агрегированная классификация DPI по результатам всех тестов для одного домена."""

    @staticmethod
    def classify(result: TargetResult) -> tuple[DPIClassification, str]:
        """Проанализировать все тесты для домена → (classification, detail).

        Логика приоритетов:
        1. ISP-заглушка / HTTP injection (самый явный признак)
        2. TLS MITM (подмена сертификата)
        3. TLS DPI (RST/EOF на handshake)
        4. TLS timeout при наличии connectivity
        5. TCP 16-20KB block
        6. STUN block (при рабочем HTTPS)
        7. Full block (все протоколы fail)
        8. TCP RST (не-TLS)
        9. DNS fake (как fallback)
        """
        tests = result.results
        if not tests:
            return DPIClassification.NONE, "No tests performed"

        # Группируем результаты по типу теста (test_type — строка из TestType.value)
        by_type: dict[str, list[SingleTestResult]] = {}
        for t in tests:
            by_type.setdefault(t.test_type, []).append(t)

        # --- ISP page / HTTP injection ---
        isp_tests = by_type.get(TestType.ISP_DETECT.value, [])
        inject_tests = by_type.get(TestType.HTTP_INJECT.value, [])
        all_isp = isp_tests + inject_tests

        if any(
            t.status == TestStatus.FAILED.value and t.error == "ISP_PAGE"
            for t in all_isp
        ):
            return DPIClassification.ISP_PAGE, "ISP block page detected"

        if any(
            t.status == TestStatus.FAILED.value and t.error == "HTTP_INJECT"
            for t in all_isp
        ):
            return DPIClassification.HTTP_INJECT, "HTTP injection detected"

        # --- TLS results ---
        tls_tests = (
            by_type.get(TestType.TLS_12.value, [])
            + by_type.get(TestType.TLS_13.value, [])
            + by_type.get(TestType.HTTP.value, [])
        )
        tls_fails = [
            t for t in tls_tests
            if t.status != TestStatus.SUCCESS.value
        ]

        # TLS MITM
        if any(t.error and "MITM" in t.error for t in tls_fails):
            return DPIClassification.TLS_MITM, "TLS MITM proxy detected"

        # TCP RST / EOF во время TLS — классический DPI
        dpi_error_codes = {"TLS_RESET", "TCP_RESET", "TLS_EOF_EARLY"}
        if any(t.error in dpi_error_codes for t in tls_fails):
            return DPIClassification.TLS_DPI, "TCP RST/EOF during TLS handshake"

        # Timeout-only TLS failures при наличии connectivity
        # Типичный DPI-drop: :443 висит, но ping / HTTP:80 работает
        timeout_codes = {"TIMEOUT", "TCP_TIMEOUT", "TLS_TIMEOUT", "READ_TIMEOUT"}
        tls_relevant = [
            t for t in tls_tests
            if t.status != TestStatus.SKIPPED.value
        ]
        tls_timeout_like = [
            t for t in tls_relevant
            if t.status == TestStatus.TIMEOUT.value or t.error in timeout_codes
        ]
        tls_ok = any(t.status == TestStatus.SUCCESS.value for t in tls_relevant)

        if tls_relevant and not tls_ok and len(tls_timeout_like) == len(tls_relevant):
            # Есть ли connectivity по другим протоколам?
            ping_tests = by_type.get(TestType.PING.value, [])
            isp_connectivity = any(
                t.status == TestStatus.SUCCESS.value for t in all_isp
            )
            ping_connectivity = any(
                t.status == TestStatus.SUCCESS.value for t in ping_tests
            )
            if isp_connectivity or ping_connectivity:
                return (
                    DPIClassification.TLS_DPI,
                    "HTTPS/TLS timeouts while connectivity exists",
                )

        # --- TCP 16-20KB block ---
        tcp_tests = by_type.get(TestType.TCP_16_20.value, [])
        if any(
            t.status == TestStatus.FAILED.value and t.error == "TCP_16_20"
            for t in tcp_tests
        ):
            return DPIClassification.TCP_16_20, "TCP block at 16-20KB boundary"

        # --- STUN block ---
        stun_tests = by_type.get(TestType.STUN.value, [])
        stun_all_fail = (
            stun_tests
            and all(t.status != TestStatus.SUCCESS.value for t in stun_tests)
        )
        if stun_all_fail:
            # Только если HTTPS работает — иначе это не специфичная STUN-блокировка
            http_ok = any(t.status == TestStatus.SUCCESS.value for t in tls_tests)
            if http_ok:
                return DPIClassification.STUN_BLOCK, "STUN/UDP blocked while HTTPS works"

        # --- Full block — все веб-протоколы fail ---
        non_diag_types = {TestType.PING.value, TestType.DNS.value}
        all_tests = [t for t in tests if t.test_type not in non_diag_types]
        web_probe_types = {
            TestType.HTTP.value, TestType.TLS_12.value,
            TestType.TLS_13.value, TestType.ISP_DETECT.value,
        }
        has_web_probe = any(t.test_type in web_probe_types for t in all_tests)
        if (
            has_web_probe
            and len(all_tests) >= 3
            and all(t.status != TestStatus.SUCCESS.value for t in all_tests)
        ):
            return DPIClassification.FULL_BLOCK, "All protocols blocked"

        # --- TCP reset (не-TLS) ---
        if any(t.error == "TCP_RESET" for t in tls_fails) and not any(
            t.error and "TLS" in t.error for t in tls_fails
        ):
            return DPIClassification.TCP_RESET, "TCP RST (non-TLS)"

        # --- DNS fake (fallback) ---
        dns_tests = by_type.get(TestType.DNS.value, [])
        if any(t.error == "DNS_FAKE" for t in dns_tests):
            return DPIClassification.DNS_FAKE, "DNS stub IP detected"

        return DPIClassification.NONE, "No DPI detected"
