# core/testers/youtube_cdn.py
"""
Динамическое определение реального CDN-шарда googlevideo + замер скорости.

Идея заимствована из YT-DPI: статичные шарды (rrX---sn-*.googlevideo.com)
в списке доменов у конкретного пользователя могут вообще не отвечать.
`redirector.googlevideo.com/report_mapping` возвращает именно те узлы,
которые обслуживают данного клиента — их и нужно тестировать на RST/троттлинг.

Дополнительно меряем реальную пропускную способность через загрузку
превью с i.ytimg.com (та же инфраструктура, что часто троттлится вместе
с видео): низкая скорость при рабочем соединении — признак троттлинга.

Использование:
    from core.testers.youtube_cdn import discover_cdn_hosts, measure_throughput
    hosts = discover_cdn_hosts()
    res = measure_throughput()
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.request

from core.log_buffer import log
from core.models import SingleTestResult, TestStatus, TestType
from core.testers.body_tester import probe_body
from core.testers.config import (
    CDN_DISCOVERY_TIMEOUT,
    CDN_MAX_HOSTS,
    THROTTLE_MIN_BYTES,
    THROTTLE_MIN_KBPS,
)

# Эндпоинт, отдающий карту edge-узлов googlevideo для текущего клиента.
_REPORT_MAPPING_URLS = (
    "https://redirector.googlevideo.com/report_mapping?di=no",
    "http://redirector.googlevideo.com/report_mapping?di=no",
)

# Шард googlevideo: r2---sn-jvhnu5g-c35k.googlevideo.com,
# rr5---sn-c0q7lnz7.googlevideo.com и т.п.
_SHARD_RE = re.compile(
    r"\b([a-z0-9]+---sn-[a-z0-9-]+\.googlevideo\.com)\b",
    re.IGNORECASE,
)

# Стабильное превью YouTube для замера скорости (~80–120 КБ JPEG).
# dQw4w9WgXcQ — общеизвестный публичный ролик, превью существует годами.
_THROUGHPUT_URL = "https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg"


def discover_cdn_hosts(
    timeout: int = CDN_DISCOVERY_TIMEOUT,
    max_hosts: int = CDN_MAX_HOSTS,
) -> tuple[list[str], str]:
    """Получить реальные CDN-шарды googlevideo для текущего клиента.

    Returns:
        (hosts, source) — список хостов и источник ("report_mapping" / "error:...").
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    last_err = ""
    for url in _REPORT_MAPPING_URLS:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
        except Exception as e:  # noqa: BLE001 — любая сетевая ошибка → пробуем дальше
            last_err = str(e)[:80]
            continue

        seen: set[str] = set()
        hosts: list[str] = []
        for m in _SHARD_RE.finditer(body):
            host = m.group(1).lower()
            if host not in seen:
                seen.add(host)
                hosts.append(host)
            if len(hosts) >= max_hosts:
                break

        if hosts:
            log.info(
                f"YouTube CDN: обнаружено {len(hosts)} реальных шардов "
                f"({', '.join(hosts)})",
                source="blockcheck",
            )
            return hosts, "report_mapping"

        last_err = "в ответе нет шардов googlevideo"

    log.warning(
        f"YouTube CDN: не удалось определить шарды ({last_err})",
        source="blockcheck",
    )
    return [], f"error:{last_err}"


def measure_throughput(
    timeout: int = 12,
    url: str = _THROUGHPUT_URL,
) -> SingleTestResult:
    """Замерить скорость загрузки превью YouTube (детекция троттлинга).

    Возвращает SingleTestResult:
      - SUCCESS                  — скорость выше порога;
      - FAILED + THROTTLE_SLOW   — соединение есть, но скорость низкая;
      - прочие коды от probe_body — при обрыве/таймауте/RST.
    """
    # min_bytes побольше, чтобы скорость измерялась на реальном объёме данных.
    res = probe_body(url, min_bytes=120_000, timeout=float(timeout))

    kbps = float(res.raw_data.get("kbps", 0.0) or 0.0)
    got = int(res.raw_data.get("bytes_received", 0) or 0)

    # Успешно скачали достаточно данных, но медленно → троттлинг.
    if (res.status == TestStatus.SUCCESS.value
            and got >= THROTTLE_MIN_BYTES
            and 0 < kbps < THROTTLE_MIN_KBPS):
        return SingleTestResult(
            target=url,
            test_type=TestType.HTTP.value,
            status=TestStatus.FAILED.value,
            error="THROTTLE_SLOW",
            latency_ms=res.latency_ms,
            details=f"Низкая скорость {kbps:.1f} KB/s ({got} B) — троттлинг",
            raw_data={**res.raw_data, "throttle": True},
        )

    # Иначе возвращаем как есть (но помечаем тип как throughput для UI).
    res.raw_data.setdefault("throughput_probe", True)
    return res
