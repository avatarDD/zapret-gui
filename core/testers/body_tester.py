# core/testers/body_tester.py
"""
Глубокая проба загрузки тела HTTP/HTTPS — для отсева «псевдо-успехов»,
когда DPI пускает ClientHello, но обрывает соединение через 16–20 КБ.

Делает GET к указанному хосту, читает поток до min_bytes, классифицирует
исход:

  - SUCCESS:    >TCP_BLOCK_RANGE_MAX (≥21 КБ) скачано без ошибок.
  - FAILED  TCP_16_20:   обрыв в диапазоне 15 000…21 000 (DPI).
  - FAILED  TLS_TIMEOUT/RST/etc.: до handshake/при чтении.
  - SUCCESS_PARTIAL: скачано меньше min_bytes, но >21 КБ — считаем ОК.

Использование:
    from core.testers.body_tester import probe_body
    res = probe_body("https://i.ytimg.com/generate_204",
                     min_bytes=65536, timeout=10)
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from urllib.parse import urlparse

from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import (
    TCP_BLOCK_RANGE_MAX,
    TCP_BLOCK_RANGE_MIN,
)


_DEFAULT_MIN_BYTES = 65_536   # 64 KB — заметно больше 16-20 KB порога
_READ_CHUNK = 4096


def probe_body(
    url: str,
    min_bytes: int = _DEFAULT_MIN_BYTES,
    timeout: float = 10.0,
) -> SingleTestResult:
    """Скачать ≥ min_bytes байт тела через GET и классифицировать исход.

    Args:
        url: Полный URL (http/https).
        min_bytes: Минимум байт, после которого можно остановить чтение.
        timeout: Сетевой таймаут в секундах.

    Returns:
        SingleTestResult со статусом SUCCESS/FAILED/ERROR/TIMEOUT и
        деталями: bytes_received, kbps, http_code, dpi_marker.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return SingleTestResult(
            target=url,
            test_type=TestType.HTTP.value,
            status=TestStatus.ERROR.value,
            error="BAD_URL",
            details="Невалидный URL",
        )

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    start = time.time()
    bytes_received = 0
    status_code = 0
    conn = None

    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            conn = http.client.HTTPSConnection(
                host, port=port, timeout=timeout, context=ctx,
            )
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)

        conn.request(
            "GET", path,
            headers={
                "Host": host,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/124.0 Safari/537.36",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
                # Range помогает: если сервер отдаёт 204/304 — всё равно
                # успех, и не качаем терабайт. Не все хосты понимают Range,
                # тогда просто читаем поток.
                "Range": "bytes=0-%d" % (min_bytes + 4096),
            },
        )
        resp = conn.getresponse()
        status_code = resp.status

        # 204/205/304/404/403 без тела — это всё ещё «трафик прошёл DPI».
        # Если код не пятиста и handshake состоялся, можно считать,
        # что десинк работает. Дочитываем сколько есть.
        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                raise TimeoutError("read timeout")
            chunk = resp.read(_READ_CHUNK)
            if not chunk:
                break
            bytes_received += len(chunk)
            if bytes_received >= min_bytes:
                break

        elapsed = time.time() - start
        kbps = (bytes_received / 1024.0) / max(elapsed, 0.001)

        # Классификация
        if (TCP_BLOCK_RANGE_MIN <= bytes_received <= TCP_BLOCK_RANGE_MAX
                and bytes_received < min_bytes):
            return SingleTestResult(
                target=url,
                test_type=TestType.TCP_16_20.value,
                status=TestStatus.FAILED.value,
                error="TCP_16_20",
                latency_ms=round(elapsed * 1000, 2),
                details="Обрыв на %d B (DPI 16-20 KB)" % bytes_received,
                raw_data={
                    "bytes_received": bytes_received,
                    "kbps": round(kbps, 1),
                    "status_code": status_code,
                    "dpi_marker": "tcp_16_20",
                },
            )

        # Достаточно прошло: либо ≥ min_bytes, либо честный EOF за пределами
        # подозрительного диапазона.
        passed = (bytes_received >= min_bytes
                  or bytes_received > TCP_BLOCK_RANGE_MAX
                  or status_code in (204, 205, 304))
        if passed:
            return SingleTestResult(
                target=url,
                test_type=TestType.HTTP.value,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed * 1000, 2),
                details="HTTP %d, %d B, %.1f KB/s"
                        % (status_code, bytes_received, kbps),
                raw_data={
                    "bytes_received": bytes_received,
                    "kbps": round(kbps, 1),
                    "status_code": status_code,
                    "dpi_marker": "",
                },
            )

        # Получили < TCP_BLOCK_RANGE_MIN — короткое тело и не из «безопасных»
        # кодов. Чаще всего это сразу обрыв после handshake.
        return SingleTestResult(
            target=url,
            test_type=TestType.HTTP.value,
            status=TestStatus.FAILED.value,
            error="SHORT_BODY",
            latency_ms=round(elapsed * 1000, 2),
            details="Тело %d B (HTTP %d) — слишком мало"
                    % (bytes_received, status_code),
            raw_data={
                "bytes_received": bytes_received,
                "kbps": round(kbps, 1),
                "status_code": status_code,
                "dpi_marker": "short_body",
            },
        )

    except (socket.timeout, TimeoutError):
        elapsed = time.time() - start
        marker = "tcp_16_20" if (
            TCP_BLOCK_RANGE_MIN <= bytes_received <= TCP_BLOCK_RANGE_MAX
        ) else "timeout"
        kbps = (bytes_received / 1024.0) / max(elapsed, 0.001)
        return SingleTestResult(
            target=url,
            test_type=TestType.HTTP.value,
            status=TestStatus.TIMEOUT.value,
            error="TIMEOUT" if marker == "timeout" else "TCP_16_20",
            latency_ms=round(elapsed * 1000, 2),
            details="Таймаут при чтении (получено %d B)" % bytes_received,
            raw_data={
                "bytes_received": bytes_received,
                "kbps": round(kbps, 1),
                "status_code": status_code,
                "dpi_marker": marker,
            },
        )
    except (ssl.SSLError, OSError, http.client.HTTPException) as e:
        elapsed = time.time() - start
        marker = "tcp_16_20" if (
            TCP_BLOCK_RANGE_MIN <= bytes_received <= TCP_BLOCK_RANGE_MAX
        ) else "rst"
        kbps = (bytes_received / 1024.0) / max(elapsed, 0.001)
        return SingleTestResult(
            target=url,
            test_type=TestType.HTTP.value,
            status=TestStatus.FAILED.value,
            error="TCP_16_20" if marker == "tcp_16_20" else "RST",
            latency_ms=round(elapsed * 1000, 2),
            details="%s (получено %d B)" % (str(e)[:80], bytes_received),
            raw_data={
                "bytes_received": bytes_received,
                "kbps": round(kbps, 1),
                "status_code": status_code,
                "dpi_marker": marker,
            },
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
