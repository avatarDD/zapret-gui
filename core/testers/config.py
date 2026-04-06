# core/testers/config.py
"""
Константы для продвинутых сетевых тестеров.

Адаптировано из Windows blockcheck/config.py → Linux/Entware.
Таймауты, маркеры ISP-заглушек, DNS-серверы, пороги.
"""

from __future__ import annotations

import errno as _errno

# ---------------------------------------------------------------------------
# Timeouts (seconds)
# ---------------------------------------------------------------------------
HTTPS_TIMEOUT = 10
STUN_TIMEOUT = 5
PING_TIMEOUT = 3
PING_COUNT = 2
DNS_TIMEOUT = 5
ISP_PAGE_TIMEOUT = 8
TCP_16_20_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------
TCP_16_20_RETRIES = 3

# ---------------------------------------------------------------------------
# TCP target selection / health probing
# ---------------------------------------------------------------------------
TCP_TARGET_MAX_COUNT = 18
TCP_TARGETS_PER_PROVIDER = 2
TCP_HEALTH_TIMEOUT = 4
TCP_HEALTH_MAX_CANDIDATES = 36

# ---------------------------------------------------------------------------
# TCP 16-20 KB block detection thresholds
# ---------------------------------------------------------------------------
TCP_BLOCK_RANGE_MIN = 15_000   # 15 KB
TCP_BLOCK_RANGE_MAX = 21_000   # 21 KB

# ---------------------------------------------------------------------------
# ISP block page markers (body content)
# ---------------------------------------------------------------------------
ISP_BODY_MARKERS: list[str] = [
    "eais.rkn.gov.ru",
    "rkn.gov.ru",
    "nap.rkn.gov.ru",
    "blocklist.rkn.gov.ru",
    "Роскомнадзор",
    "Roskomnadzor",
    "blocked by",
    "заблокирован",
    "ограничен доступ",
    "access denied",
    "access restricted",
    "is blocked",
    "web filter",
    "content filter",
    "warning: this site",
    "этот ресурс заблокирован",
    "federalnyj-zakon",
    "149-fz",
    "zapret-info",
]

# ---------------------------------------------------------------------------
# ISP redirect markers (URL patterns)
# ---------------------------------------------------------------------------
ISP_REDIRECT_MARKERS: list[str] = [
    "warning.rt.ru",
    "block.mts.ru",
    "blocked.beeline.ru",
    "block.megafon.ru",
    "zapret.",
    "blackhole.",
    "sorm.",
]

# ---------------------------------------------------------------------------
# Known ISP block IPs (shared — also used by dns_checker)
# ---------------------------------------------------------------------------
KNOWN_BLOCK_IPS: set[str] = {
    "127.0.0.1",
    "0.0.0.0",
    "10.10.10.10",
    "195.82.146.214",    # Ростелеком
    "81.19.72.32",       # МТС
    "213.180.193.250",   # Билайн
    "217.169.80.229",    # Мегафон
    "62.33.207.196",     # РКН
    "62.33.207.197",     # РКН
    "62.33.207.198",     # РКН
}

# ---------------------------------------------------------------------------
# Linux errno codes for DPI classification
# (заменяют Windows WSAE* коды из исходного проекта)
# ---------------------------------------------------------------------------
ERRNO_RESET = _errno.ECONNRESET         # 104
ERRNO_TIMEOUT = _errno.ETIMEDOUT         # 110
ERRNO_REFUSED = _errno.ECONNREFUSED      # 111
ERRNO_HOST_UNREACH = _errno.EHOSTUNREACH  # 113
ERRNO_NET_UNREACH = _errno.ENETUNREACH    # 101

# ---------------------------------------------------------------------------
# Thread pool (роутер: мало RAM, медленный CPU)
# ---------------------------------------------------------------------------
DEFAULT_PARALLEL = 2

# ---------------------------------------------------------------------------
# Strategy scanner
# ---------------------------------------------------------------------------
STRATEGY_PROBE_TIMEOUT = 5
STRATEGY_RESPONSE_TIMEOUT = 3
STRATEGY_STARTUP_WAIT = 1.0
STRATEGY_KILL_TIMEOUT = 4
