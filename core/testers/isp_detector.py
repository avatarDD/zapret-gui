# core/testers/isp_detector.py
"""
ISP block page и HTTP injection detection.

Обнаруживает:
- ISP-заглушки (страницы блокировки провайдера)
- HTTP injection (DPI подменяет ответ на HTTP:80)
- Редиректы на страницы блокировки

Чистый stdlib (socket + http.client + ssl), без httpx/requests.

Использование:
    from core.testers.isp_detector import detect_isp_page, check_http_injection
    result = detect_isp_page("discord.com")       # HTTPS с проверкой тела
    result = check_http_injection("discord.com")   # HTTP:80, raw socket
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from urllib.parse import urlparse

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import ISP_BODY_MARKERS, ISP_PAGE_TIMEOUT, ISP_REDIRECT_MARKERS


# ---------------------------------------------------------------------------
# HTTP injection check (raw socket, port 80)
# ---------------------------------------------------------------------------

def check_http_injection(
    domain: str,
    timeout: int = ISP_PAGE_TIMEOUT,
) -> SingleTestResult:
    """Проверка HTTP injection на порту 80.

    Отправляет plain HTTP GET и проверяет, получен ли ответ
    от реального сервера или инжектированная страница блокировки.
    """
    start = time.time()
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((domain, 80))

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        sock.send(request.encode())

        response = b""
        while len(response) < 16384:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        elapsed = (time.time() - start) * 1000
        body = response.decode("utf-8", errors="ignore")

        # Проверяем маркеры ISP в теле ответа
        for marker in ISP_BODY_MARKERS:
            if marker.lower() in body.lower():
                return SingleTestResult(
                    target=domain,
                    test_type=TestType.HTTP_INJECT.value,
                    status=TestStatus.FAILED.value,
                    error="HTTP_INJECT",
                    latency_ms=round(elapsed, 2),
                    details=f"HTTP injection detected (marker: {marker})",
                    raw_data={"marker": marker, "body_len": len(body)},
                )

        # Проверяем редирект на ISP-заглушку
        location_match = re.search(
            r"Location:\s*(.+?)[\r\n]", body, re.IGNORECASE,
        )
        if location_match:
            location = location_match.group(1).strip()
            for redir_marker in ISP_REDIRECT_MARKERS:
                if redir_marker in location.lower():
                    return SingleTestResult(
                        target=domain,
                        test_type=TestType.HTTP_INJECT.value,
                        status=TestStatus.FAILED.value,
                        error="HTTP_INJECT",
                        latency_ms=round(elapsed, 2),
                        details=f"Redirect to ISP block page: {location}",
                        raw_data={"redirect": location},
                    )

        return SingleTestResult(
            target=domain,
            test_type=TestType.HTTP_INJECT.value,
            status=TestStatus.SUCCESS.value,
            latency_ms=round(elapsed, 2),
            details="No HTTP injection detected",
        )

    except socket.timeout:
        return SingleTestResult(
            target=domain,
            test_type=TestType.HTTP_INJECT.value,
            status=TestStatus.TIMEOUT.value,
            error="TIMEOUT",
            latency_ms=round((time.time() - start) * 1000, 2),
            details="HTTP connection timeout",
        )
    except (ConnectionResetError, ConnectionRefusedError, OSError) as e:
        return SingleTestResult(
            target=domain,
            test_type=TestType.HTTP_INJECT.value,
            status=TestStatus.FAILED.value,
            error="CONNECT_ERR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=str(e)[:100],
        )
    except Exception as e:
        return SingleTestResult(
            target=domain,
            test_type=TestType.HTTP_INJECT.value,
            status=TestStatus.ERROR.value,
            error="ERROR",
            latency_ms=round((time.time() - start) * 1000, 2),
            details=str(e)[:100],
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# ISP page detection via HTTPS (stdlib http.client + ssl)
# ---------------------------------------------------------------------------

def detect_isp_page(
    domain: str,
    timeout: int = ISP_PAGE_TIMEOUT,
) -> SingleTestResult:
    """Обнаружение ISP-заглушки через HTTPS с анализом тела ответа.

    Использует http.client + ssl (stdlib) для подключения,
    следует редиректам (до 5), проверяет тело и заголовки.
    """
    start = time.time()
    redirects_left = 5
    current_url = f"https://{domain}/"
    redirect_chain: list[str] = []

    while redirects_left > 0:
        parsed = urlparse(current_url)
        host = parsed.hostname or domain
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        conn = None
        try:
            if parsed.scheme == "https":
                # verify=False — хотим увидеть страницу даже с плохим сертификатом
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    host, port=port or 443, timeout=timeout, context=ctx,
                )
            else:
                conn = http.client.HTTPConnection(
                    host, port=port or 80, timeout=timeout,
                )

            conn.request(
                "GET", path,
                headers={
                    "Host": host,
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html,*/*",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()

            # Обработка редиректов
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location", "")
                if not location:
                    break

                # Проверяем маркеры ISP в URL редиректа
                for redir_marker in ISP_REDIRECT_MARKERS:
                    if redir_marker in location.lower():
                        elapsed = (time.time() - start) * 1000
                        return SingleTestResult(
                            target=domain,
                            test_type=TestType.ISP_DETECT.value,
                            status=TestStatus.FAILED.value,
                            error="ISP_PAGE",
                            latency_ms=round(elapsed, 2),
                            details=f"Redirected to ISP block page: {location}",
                            raw_data={
                                "redirect": location,
                                "chain": redirect_chain,
                            },
                        )

                redirect_chain.append(location)

                # Абсолютный или относительный URL
                if location.startswith("http"):
                    current_url = location
                else:
                    current_url = f"{parsed.scheme}://{host}{location}"

                redirects_left -= 1
                conn.close()
                continue

            # Читаем тело (до 8 КБ)
            body = resp.read(8192).decode("utf-8", errors="ignore")
            elapsed = (time.time() - start) * 1000

            # Проверяем маркеры ISP в теле
            for marker in ISP_BODY_MARKERS:
                if marker.lower() in body.lower():
                    return SingleTestResult(
                        target=domain,
                        test_type=TestType.ISP_DETECT.value,
                        status=TestStatus.FAILED.value,
                        error="ISP_PAGE",
                        latency_ms=round(elapsed, 2),
                        details=f"ISP block page detected (marker: {marker})",
                        raw_data={
                            "marker": marker,
                            "status_code": resp.status,
                            "chain": redirect_chain,
                        },
                    )

            return SingleTestResult(
                target=domain,
                test_type=TestType.ISP_DETECT.value,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed, 2),
                details=f"HTTP {resp.status}, no ISP page",
                raw_data={
                    "status_code": resp.status,
                    "chain": redirect_chain,
                },
            )

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return SingleTestResult(
                target=domain,
                test_type=TestType.ISP_DETECT.value,
                status=TestStatus.ERROR.value,
                error="ISP_ERR",
                latency_ms=round(elapsed, 2),
                details=str(e)[:100],
            )
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    # Исчерпали редиректы
    elapsed = (time.time() - start) * 1000
    return SingleTestResult(
        target=domain,
        test_type=TestType.ISP_DETECT.value,
        status=TestStatus.ERROR.value,
        error="TOO_MANY_REDIRECTS",
        latency_ms=round(elapsed, 2),
        details=f"Too many redirects ({len(redirect_chain)})",
        raw_data={"chain": redirect_chain},
    )
