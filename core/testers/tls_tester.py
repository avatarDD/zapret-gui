# core/testers/tls_tester.py
"""
HTTPS/TLS тестер — низкоуровневая проверка через socket + ssl (stdlib).

Дополняет существующий core/diagnostics.check_http() (curl/wget):
- Проверяет установление TLS-соединения (handshake)
- Определяет тип ошибки: timeout, connection reset, SSL error
- Поддерживает пинг TLS 1.2 / TLS 1.3 отдельно
- Классифицирует ошибки для DPI-детекции

Использование:
    from core.testers.tls_tester import test_tls
    result = test_tls("youtube.com")                    # → SingleTestResult
    result = test_tls("discord.com", tls_version="1.3") # TLS 1.3 only
"""

from __future__ import annotations

import re
import socket
import ssl
import time

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import HTTPS_TIMEOUT
from core.testers.dpi_classifier import classify_connect_error, classify_ssl_error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_ip_family(ip_family: str | None) -> str:
    """Нормализовать строку семейства IP."""
    family = str(ip_family or "auto").strip().lower()
    if family in ("ipv4", "ip4", "v4", "4"):
        return "ipv4"
    if family in ("ipv6", "ip6", "v6", "6"):
        return "ipv6"
    return "auto"


def _resolve_connect_addrs(
    host: str, port: int, ip_family: str,
) -> list[tuple[int, tuple]]:
    """Резолвить хост в список (af, sockaddr) для подключения."""
    if ip_family == "ipv4":
        family = socket.AF_INET
    elif ip_family == "ipv6":
        family = socket.AF_INET6
    else:
        family = socket.AF_UNSPEC

    infos = socket.getaddrinfo(
        host, port, family=family,
        type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
    )
    addrs: list[tuple[int, tuple]] = []
    seen: set[str] = set()
    for af, _socktype, _proto, _canonname, sockaddr in infos:
        key = f"{af}:{sockaddr[0]}:{sockaddr[1]}"
        if key not in seen:
            seen.add(key)
            addrs.append((af, sockaddr))
    return addrs


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def test_tls(
    host: str,
    port: int = 443,
    timeout: int = HTTPS_TIMEOUT,
    tls_version: str | None = None,
    ip_family: str = "auto",
) -> SingleTestResult:
    """Тест HTTPS/TLS-соединения с классификацией DPI-ошибок.

    Args:
        host: Целевой домен.
        port: Порт (по умолчанию 443).
        timeout: Таймаут соединения в секундах.
        tls_version: "1.2" или "1.3" для фиксации версии, None — любая.
        ip_family: "ipv4", "ipv6" или "auto".

    Returns:
        SingleTestResult с DPI-классификацией ошибки.
    """
    # Определяем тип теста
    test_type = TestType.HTTP.value
    if tls_version == "1.2":
        test_type = TestType.TLS_12.value
    elif tls_version == "1.3":
        test_type = TestType.TLS_13.value

    start = time.time()
    bytes_read = 0
    family = _normalize_ip_family(ip_family)

    # --- DNS resolve ---
    try:
        connect_addrs = _resolve_connect_addrs(host, port, family)
    except socket.gaierror as e:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="DNS_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"DNS resolution failed: {str(e)[:80]}",
            raw_data={"ip_family": family},
        )
    except Exception as e:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="RESOLVE_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"Resolve error: {str(e)[:80]}",
            raw_data={"ip_family": family},
        )

    if not connect_addrs:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.SKIPPED.value, error="NO_ADDR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=f"No addresses for requested family: {family}",
            raw_data={"ip_family": family},
        )

    last_exception: Exception | None = None

    # Общий deadline — не больше timeout*2 секунд на все адреса суммарно
    deadline = start + timeout * 2

    # --- Пробуем каждый адрес ---
    for addr_family, sockaddr in connect_addrs:
        remaining = deadline - time.time()
        if remaining <= 1:
            # Время вышло — не пробуем оставшиеся адреса
            if last_exception is None:
                last_exception = socket.timeout("total deadline exceeded")
            break

        sock = None
        ssock = None
        try:
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, remaining))

            # Создаём SSL-контекст
            context = ssl.create_default_context()
            if tls_version == "1.2":
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            elif tls_version == "1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3

            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.connect(sockaddr)

            actual_tls = ssock.version()

            # Отправляем HTTP-запрос для проверки полной связности
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            )
            ssock.send(request.encode())

            response = b""
            try:
                while len(response) < 2048:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except (socket.timeout, ssl.SSLError):
                pass  # Частичный ответ — не критично
            bytes_read = len(response)

            elapsed = (time.time() - start) * 1000

            # Парсим HTTP-статус
            status_code = None
            if response:
                first_line = response.decode("utf-8", errors="ignore").split("\r\n")[0]
                match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", first_line)
                if match:
                    status_code = int(match.group(1))

            resolved_family = "ipv6" if addr_family == socket.AF_INET6 else "ipv4"
            connected_ip = str(sockaddr[0]) if sockaddr else ""

            return SingleTestResult(
                target=host, test_type=test_type,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed, 2),
                details=f"{actual_tls} HTTP {status_code or '?'}",
                raw_data={
                    "tls_version": actual_tls,
                    "status_code": status_code,
                    "bytes_read": bytes_read,
                    "ip_family": resolved_family,
                    "connected_ip": connected_ip,
                },
            )

        except ssl.SSLError as e:
            last_exception = e
            continue
        except socket.timeout as e:
            last_exception = e
            continue
        except (ConnectionResetError, ConnectionRefusedError, OSError) as e:
            last_exception = e
            continue
        except Exception as e:
            last_exception = e
            continue
        finally:
            for s in (ssock, sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

    # --- Все адреса упали — классифицируем последнюю ошибку ---
    elapsed = (time.time() - start) * 1000

    if isinstance(last_exception, ssl.SSLError):
        label, detail, _ = classify_ssl_error(last_exception, bytes_read)

        # TLS version unsupported — не сбой, а пропуск
        if label == "TLS_UNSUPPORTED":
            return SingleTestResult(
                target=host, test_type=test_type,
                status=TestStatus.SKIPPED.value, error=label,
                latency_ms=round(elapsed, 2), details=detail,
                raw_data={"ip_family": family},
            )

        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.FAILED.value, error=label,
            latency_ms=round(elapsed, 2), details=detail,
            raw_data={"ip_family": family},
        )

    if isinstance(last_exception, socket.timeout):
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.TIMEOUT.value, error="TIMEOUT",
            latency_ms=round(elapsed, 2),
            details="Connection timeout",
            raw_data={"ip_family": family},
        )

    if isinstance(last_exception, (ConnectionResetError, ConnectionRefusedError, OSError)):
        label, detail, _ = classify_connect_error(last_exception, bytes_read)
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.FAILED.value, error=label,
            latency_ms=round(elapsed, 2), details=detail,
            raw_data={"ip_family": family},
        )

    if last_exception is not None:
        return SingleTestResult(
            target=host, test_type=test_type,
            status=TestStatus.ERROR.value, error="ERROR",
            latency_ms=round(elapsed, 2),
            details=str(last_exception)[:100],
            raw_data={"ip_family": family},
        )

    return SingleTestResult(
        target=host, test_type=test_type,
        status=TestStatus.ERROR.value, error="NO_RESULT",
        latency_ms=round(elapsed, 2),
        details="No connection attempts completed",
        raw_data={"ip_family": family},
    )
