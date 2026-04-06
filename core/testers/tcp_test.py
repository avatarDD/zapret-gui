# core/testers/tcp_test.py
"""
TCP 16-20KB block detection — тестер DPI, обрывающего TCP на 16-20 КБ.

Некоторые DPI-системы обрывают TCP-соединения после передачи 16-20 КБ данных.
Тестер скачивает контент и проверяет, обрывается ли соединение в этом диапазоне.

Чистый stdlib (http.client + ssl), без httpx/requests.

Использование:
    from core.testers.tcp_test import check_tcp_16_20
    result = check_tcp_16_20("https://proof.ovh.net/files/1Mb.dat")
"""

from __future__ import annotations

import http.client
import json
import os
import random
import socket
import ssl
import time
from urllib.parse import urlparse

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.config import (
    TCP_16_20_RETRIES,
    TCP_16_20_TIMEOUT,
    TCP_BLOCK_RANGE_MAX,
    TCP_BLOCK_RANGE_MIN,
    TCP_HEALTH_TIMEOUT,
    TCP_TARGET_MAX_COUNT,
    TCP_TARGETS_PER_PROVIDER,
    TCP_HEALTH_MAX_CANDIDATES,
)


# ---------------------------------------------------------------------------
# Helpers — HTTP через stdlib
# ---------------------------------------------------------------------------

def _make_connection(
    parsed_url, timeout: int,
) -> http.client.HTTPConnection | http.client.HTTPSConnection:
    """Создать HTTP(S)-соединение из распарсенного URL."""
    host = parsed_url.hostname or ""
    port = parsed_url.port

    if parsed_url.scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            host, port=port or 443, timeout=timeout, context=ctx,
        )
    else:
        conn = http.client.HTTPConnection(
            host, port=port or 80, timeout=timeout,
        )
    return conn


def _stream_get(url: str, timeout: int, max_bytes: int = 25_000) -> tuple[int, int, str]:
    """Скачать до max_bytes по GET, вернуть (bytes_received, status_code, error).

    Следует до 5 редиректов.
    """
    redirects_left = 5
    current_url = url

    while redirects_left > 0:
        parsed = urlparse(current_url)
        conn = None
        try:
            conn = _make_connection(parsed, timeout)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            conn.request(
                "GET", path,
                headers={
                    "Host": parsed.hostname or "",
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()

            # Обработка редиректов
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location", "")
                if not location:
                    return 0, resp.status, "Redirect without Location"
                # Абсолютный или относительный URL
                if location.startswith("http"):
                    current_url = location
                else:
                    current_url = f"{parsed.scheme}://{parsed.hostname}{location}"
                redirects_left -= 1
                conn.close()
                continue

            # Стриминг тела
            bytes_received = 0
            while bytes_received < max_bytes:
                chunk = resp.read(1024)
                if not chunk:
                    break
                bytes_received += len(chunk)

            return bytes_received, resp.status, ""

        except Exception as e:
            # Пробрасываем наверх для анализа в основной функции
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    return 0, 0, "Too many redirects"


# ---------------------------------------------------------------------------
# Health probe (лёгкая проверка доступности цели)
# ---------------------------------------------------------------------------

def probe_tcp_target_health(url: str, timeout: int = TCP_HEALTH_TIMEOUT) -> tuple[bool, str, float]:
    """Лёгкая проверка доступности TCP 16-20KB цели.

    Returns:
        (is_healthy, detail, elapsed_ms)
    """
    start = time.time()
    parsed = urlparse(url)
    conn = None

    try:
        conn = _make_connection(parsed, timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        conn.request(
            "HEAD", path,
            headers={
                "Host": parsed.hostname or "",
                "User-Agent": "Mozilla/5.0",
                "Range": "bytes=0-1023",
            },
        )
        resp = conn.getresponse()
        elapsed = (time.time() - start) * 1000
        code = resp.status

        # HEAD может быть 405 — пробуем GET с малым чтением
        if code in (405, 501):
            conn.close()
            conn = _make_connection(parsed, timeout)
            conn.request(
                "GET", path,
                headers={
                    "Host": parsed.hostname or "",
                    "User-Agent": "Mozilla/5.0",
                    "Range": "bytes=0-1023",
                },
            )
            resp = conn.getresponse()
            resp.read(512)
            code = resp.status
            elapsed = (time.time() - start) * 1000

        healthy = (200 <= code < 400) or code in (401, 403, 404)
        return healthy, f"HTTP {code}", round(elapsed, 2)

    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return False, str(e)[:100], round(elapsed, 2)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Single test
# ---------------------------------------------------------------------------

def check_tcp_16_20_single(
    url: str,
    timeout: int = TCP_16_20_TIMEOUT,
) -> SingleTestResult:
    """Один TCP 16-20KB тест — скачать и проверить обрыв в диапазоне 16-20 КБ."""
    start = time.time()
    bytes_received = 0

    try:
        bytes_received, status_code, err_msg = _stream_get(
            url, timeout, max_bytes=25_000,
        )

        if err_msg:
            return SingleTestResult(
                target=url, test_type=TestType.TCP_16_20.value,
                status=TestStatus.ERROR.value, error="HTTP_ERR",
                latency_ms=round((time.time() - start) * 1000, 2),
                details=err_msg,
                raw_data={"bytes_received": bytes_received},
            )

        elapsed = (time.time() - start) * 1000

        if bytes_received > TCP_BLOCK_RANGE_MAX:
            return SingleTestResult(
                target=url, test_type=TestType.TCP_16_20.value,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed, 2),
                details=f"Received {bytes_received}B (no 16-20KB block)",
                raw_data={"bytes_received": bytes_received},
            )
        elif TCP_BLOCK_RANGE_MIN <= bytes_received <= TCP_BLOCK_RANGE_MAX:
            return SingleTestResult(
                target=url, test_type=TestType.TCP_16_20.value,
                status=TestStatus.FAILED.value, error="TCP_16_20",
                latency_ms=round(elapsed, 2),
                details=f"Connection dropped at {bytes_received}B (16-20KB range)",
                raw_data={"bytes_received": bytes_received},
            )
        else:
            return SingleTestResult(
                target=url, test_type=TestType.TCP_16_20.value,
                status=TestStatus.SUCCESS.value,
                latency_ms=round(elapsed, 2),
                details=f"Received {bytes_received}B",
                raw_data={"bytes_received": bytes_received},
            )

    except Exception as e:
        elapsed = (time.time() - start) * 1000
        error_msg = str(e).lower()

        # Обрыв соединения в диапазоне 16-20 КБ → DPI
        if bytes_received > 0 and TCP_BLOCK_RANGE_MIN <= bytes_received <= TCP_BLOCK_RANGE_MAX:
            if "reset" in error_msg or "aborted" in error_msg or "broken pipe" in error_msg:
                return SingleTestResult(
                    target=url, test_type=TestType.TCP_16_20.value,
                    status=TestStatus.FAILED.value, error="TCP_16_20",
                    latency_ms=round(elapsed, 2),
                    details=f"RST at {bytes_received}B (16-20KB DPI block)",
                    raw_data={"bytes_received": bytes_received, "error": str(e)[:80]},
                )

        return SingleTestResult(
            target=url, test_type=TestType.TCP_16_20.value,
            status=TestStatus.ERROR.value, error="TCP_ERR",
            latency_ms=round(elapsed, 2),
            details=f"{str(e)[:80]} ({bytes_received}B received)",
            raw_data={"bytes_received": bytes_received},
        )


# ---------------------------------------------------------------------------
# Main function with retries
# ---------------------------------------------------------------------------

def check_tcp_16_20(
    url: str,
    retries: int = TCP_16_20_RETRIES,
    timeout: int = TCP_16_20_TIMEOUT,
) -> SingleTestResult:
    """TCP 16-20KB тест с ретраями и анализом дисперсии.

    Несколько попыток помогают отличить реальный DPI от временных сбоев.
    Если соединение стабильно обрывается в диапазоне 16-20 КБ — это DPI.
    """
    results: list[SingleTestResult] = []

    for attempt in range(retries):
        result = check_tcp_16_20_single(url, timeout)
        results.append(result)

        # Если чётко получили >20 КБ — DPI нет, не надо ретраить
        if (result.status == TestStatus.SUCCESS.value
                and result.raw_data.get("bytes_received", 0) > TCP_BLOCK_RANGE_MAX):
            return result

    # Анализ результатов — стабильный обрыв в 16-20 КБ?
    fail_16_20 = [r for r in results if r.error == "TCP_16_20"]
    if len(fail_16_20) >= 2:
        bytes_vals = [r.raw_data.get("bytes_received", 0) for r in fail_16_20]
        return SingleTestResult(
            target=url, test_type=TestType.TCP_16_20.value,
            status=TestStatus.FAILED.value, error="TCP_16_20",
            latency_ms=fail_16_20[0].latency_ms,
            details=(
                f"Consistent 16-20KB block ({len(fail_16_20)}/{retries} attempts, "
                f"bytes: {', '.join(str(b) for b in bytes_vals)})"
            ),
            raw_data={
                "attempts": retries,
                "failures": len(fail_16_20),
                "bytes": bytes_vals,
            },
        )

    # Возвращаем последний результат
    return results[-1] if results else SingleTestResult(
        target=url, test_type=TestType.TCP_16_20.value,
        status=TestStatus.ERROR.value, error="NO_ATTEMPTS",
        details="No test attempts completed",
    )


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

def load_tcp_targets(data_dir: str | None = None) -> list[dict]:
    """Загрузить TCP 16-20KB цели из data/tcp_targets.json.

    Args:
        data_dir: Путь к директории data/.
            По умолчанию: <app_dir>/data/

    Returns:
        Список dict-ов с полями id, provider, url.
    """
    if data_dir is None:
        # <project_root>/data/
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)
        )))
        data_dir = os.path.join(app_dir, "data")

    targets_file = os.path.join(data_dir, "tcp_targets.json")
    if not os.path.isfile(targets_file):
        log.warning(f"TCP targets file not found: {targets_file}", source="tcp_test")
        return []

    try:
        with open(targets_file, "r", encoding="utf-8") as f:
            targets = json.load(f)
        return targets if isinstance(targets, list) else []
    except (json.JSONDecodeError, OSError) as e:
        log.error(f"Failed to load TCP targets: {e}", source="tcp_test")
        return []


def select_tcp_targets(
    targets: list[dict] | None = None,
    max_count: int = TCP_TARGET_MAX_COUNT,
    per_provider: int = TCP_TARGETS_PER_PROVIDER,
    check_health: bool = True,
    health_timeout: int = TCP_HEALTH_TIMEOUT,
) -> list[dict]:
    """Выбрать подмножество TCP-целей для тестирования.

    Стратегия: максимум per_provider целей от каждого провайдера,
    суммарно не более max_count. Опционально проверяет доступность.

    Returns:
        Список dict-ов (id, provider, url) для тестирования.
    """
    if targets is None:
        targets = load_tcp_targets()

    if not targets:
        return []

    # Группируем по провайдеру
    by_provider: dict[str, list[dict]] = {}
    for t in targets:
        provider = t.get("provider", "unknown")
        by_provider.setdefault(provider, []).append(t)

    # Выбираем per_provider от каждого провайдера (случайный порядок)
    selected: list[dict] = []
    for provider, items in by_provider.items():
        random.shuffle(items)
        selected.extend(items[:per_provider])

    random.shuffle(selected)

    # Ограничиваем кандидатов
    candidates = selected[:TCP_HEALTH_MAX_CANDIDATES]

    if not check_health:
        return candidates[:max_count]

    # Проверяем здоровье (лёгким HEAD-запросом)
    healthy: list[dict] = []
    for t in candidates:
        if len(healthy) >= max_count:
            break
        url = t.get("url", "")
        if not url:
            continue
        ok, detail, elapsed = probe_tcp_target_health(url, health_timeout)
        if ok:
            healthy.append(t)
        else:
            log.debug(
                f"TCP target unhealthy: {t.get('id', '?')} — {detail}",
                source="tcp_test",
            )

    return healthy
