# core/dns_providers.py
"""
Реестр DoH/DoT провайдеров для маршрутизации тестового трафика сканера.

Позволяет тестировать стратегии через разные DNS-серверы,
чтобы определить какие DNS + стратегия комбинации работают.
"""

# DoH провайдеры (DNS-over-HTTPS)
DOH_PROVIDERS = [
    {
        "id": "google",
        "name": "Google DoH",
        "url": "https://dns.google/dns-query",
        "ips": ["8.8.8.8", "8.8.4.4"],
    },
    {
        "id": "cloudflare",
        "name": "Cloudflare DoH",
        "url": "https://cloudflare-dns.com/dns-query",
        "ips": ["1.1.1.1", "1.0.0.1"],
    },
    {
        "id": "adguard",
        "name": "AdGuard DoH",
        "url": "https://dns.adguard.com/dns-query",
        "ips": ["94.140.14.14", "94.140.15.15"],
    },
    {
        "id": "yandex",
        "name": "Yandex DoH",
        "url": "https://dns.yandex.net/dns-query",
        "ips": ["77.88.8.8", "77.88.8.1"],
    },
    {
        "id": "quad9",
        "name": "Quad9 DoH",
        "url": "https://dns.quad9.net/dns-query",
        "ips": ["9.9.9.9", "149.112.112.112"],
    },
    {
        "id": "comss",
        "name": "Comss DNS",
        "url": "https://dns.comss.one/dns-query",
        "ips": ["9.9.9.10"],
    },
    {
        "id": "xbox-dns",
        "name": "Xbox DNS",
        "url": "https://dns.microsoft.com/dns-query",
        "ips": ["208.67.222.222"],
    },
    {
        "id": "geohide",
        "name": "GeoHide DoH",
        "url": "https://dns.geohide.ru:444/dns-query",
        "ips": ["45.155.204.190", "37.230.192.51", "95.182.120.241"],
    },
    {
        "id": "geohide-h3",
        "name": "GeoHide HTTP/3",
        "url": "h3://dns.geohide.ru:444",
        "ips": ["45.155.204.190", "37.230.192.51", "95.182.120.241"],
    },
]

# DoT провайдеры (DNS-over-TLS)
DOT_PROVIDERS = [
    {
        "id": "google-dot",
        "name": "Google DoT",
        "host": "dns.google",
        "port": 853,
        "ips": ["8.8.8.8"],
    },
    {
        "id": "cloudflare-dot",
        "name": "Cloudflare DoT",
        "host": "1.1.1.1",
        "port": 853,
        "ips": ["1.1.1.1"],
    },
    {
        "id": "adguard-dot",
        "name": "AdGuard DoT",
        "host": "dns.adguard.com",
        "port": 853,
        "ips": ["94.140.14.14"],
    },
    {
        "id": "geohide-dot",
        "name": "GeoHide DoT",
        "host": "dns.geohide.ru",
        "port": 853,
        "ips": ["45.155.204.190", "37.230.192.51", "95.182.120.241"],
    },
]


def list_providers() -> list:
    """Список всех DNS-провайдеров."""
    return DOH_PROVIDERS + DOT_PROVIDERS


def list_doh() -> list:
    """Только DoH провайдеры."""
    return DOH_PROVIDERS


def list_dot() -> list:
    """Только DoT провайдеры."""
    return DOT_PROVIDERS


def get_provider(provider_id: str) -> dict:
    """Получить провайдер по ID."""
    for p in DOH_PROVIDERS + DOT_PROVIDERS:
        if p["id"] == provider_id:
            return p
    return {}
