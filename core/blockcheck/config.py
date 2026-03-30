"""BlockCheck configuration — таймауты, маркеры, DNS, errno (Linux).

Адаптировано для роутерного окружения (Entware/OpenWrt):
- Таймауты увеличены в ~1.5-2x (медленные CPU, нестабильный WAN)
- errno-коды заменены на Linux (POSIX)
- Пути адаптированы под /opt/etc/zapret-gui/
"""

# ═══════════════════ Paths ═══════════════════
# Fallback-константы; runtime-код должен читать из ConfigManager:
#   cfg.get("zapret", "nfqws_binary")
#   cfg.get("zapret", "base_path")

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"
DATA_DIR = "/opt/etc/zapret-gui/blockcheck/data/"
WORK_DIR = "/tmp/zapret-gui-probe/"

# ═══════════════════ Timeouts (seconds) ═══════════════════
# Увеличены относительно оригинала для медленных роутеров

HTTPS_TIMEOUT = 15
STUN_TIMEOUT = 8
PING_TIMEOUT = 5
PING_COUNT = 2
DNS_TIMEOUT = 8
DOH_TIMEOUT = 12
ISP_PAGE_TIMEOUT = 12
TCP_16_20_TIMEOUT = 25

# ═══════════════════ Retries ═══════════════════

TCP_16_20_RETRIES = 3
DNS_RETRIES = 2

# ═══════════════════ TCP target selection ═══════════════════

TCP_TARGET_MAX_COUNT = 18
TCP_TARGETS_PER_PROVIDER = 2
TCP_HEALTH_TIMEOUT = 6
TCP_HEALTH_MAX_CANDIDATES = 36

# ═══════════════════ TCP 16-20 KB block detection ═══════════════════

TCP_BLOCK_RANGE_MIN = 15000   # 15 KB
TCP_BLOCK_RANGE_MAX = 21000   # 21 KB

# ═══════════════════ ISP block page markers (body) ═══════════════════

ISP_BODY_MARKERS = [
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

# ═══════════════════ ISP redirect markers (URL) ═══════════════════

ISP_REDIRECT_MARKERS = [
    "warning.rt.ru",
    "block.mts.ru",
    "blocked.beeline.ru",
    "block.megafon.ru",
    "zapret.",
    "blackhole.",
    "sorm.",
]

# ═══════════════════ DNS servers ═══════════════════

DNS_UDP_SERVERS = [
    "8.8.8.8",         # Google
    "1.1.1.1",         # Cloudflare
    "77.88.8.8",       # Yandex
    "9.9.9.9",         # Quad9
]

DOH_SERVERS = [
    {"name": "Google", "url": "https://dns.google/resolve"},
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query"},
]

# ═══════════════════ DNS check domains ═══════════════════

DNS_CHECK_DOMAINS = [
    "discord.com",
    "youtube.com",
    "rutracker.org",
    "linkedin.com",
    "telegram.org",
]

# ═══════════════════ Linux errno codes (POSIX) ═══════════════════

ERRNO_RESET = 104         # ECONNRESET
ERRNO_TIMEOUT = 110        # ETIMEDOUT
ERRNO_REFUSED = 111        # ECONNREFUSED
ERRNO_HOST_UNREACH = 113   # EHOSTUNREACH
ERRNO_NET_UNREACH = 101    # ENETUNREACH

# ═══════════════════ Thread pool ═══════════════════
# Снижено для экономии RAM на роутерах

DEFAULT_PARALLEL = 2

# ═══════════════════ Strategy scanner ═══════════════════

STRATEGY_PROBE_TIMEOUT = 8        # HTTPS connect + TLS handshake
STRATEGY_RESPONSE_TIMEOUT = 5     # HTTP response after TLS ok
STRATEGY_STARTUP_WAIT = 1.5       # Ожидание запуска nfqws2
STRATEGY_KILL_TIMEOUT = 5         # Ожидание завершения nfqws2
PROBE_QUEUE_NUM = 200             # Отдельный nfqueue для probe-тестов
PROBE_TEMP_PRESET = "blockcheck_probe.txt"
PROBE_TEMP_HOSTLIST = "blockcheck_probe_hosts.txt"

# ═══════════════════ Preflight ═══════════════════

PREFLIGHT_DNS_TIMEOUT = 5
PREFLIGHT_TCP_TIMEOUT = 4
PREFLIGHT_HTTP_TIMEOUT = 4
PREFLIGHT_PING_COUNT = 1
PREFLIGHT_PING_TIMEOUT = 4

# ═══════════════════ Known ISP block IPs ═══════════════════

KNOWN_BLOCK_IPS = {
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
