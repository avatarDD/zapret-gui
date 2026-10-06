# core/routing/set_ttl.py
"""
Срок жизни IP в наборах доменных маршрутов: TTL из DNS + запас.

## Зачем

Набор доменного правила (ipset/nftset) раньше только рос: рефрешер раз в
10 минут добавлял свежие IP, DNS-перехват — IP из ответов клиентам, а
старые не удалялись никогда («лишний IP в туннеле безвреден»). На
роутере с месяцами аптайма набор копил тысячи давно чужих адресов CDN —
и в туннель уходил трафик сайтов, которых в маршруте нет.

Приём MagiTrickle: запись кладётся со сроком = TTL ответа + запас (по
умолчанию час) и истекает в ядре сама; повторный ответ продлевает срок
(`ipset add … timeout N -exist`, `nft add element … timeout Ns`).
Живые соединения к истёкшему IP не рвутся: mark-правила восстанавливают
метку из connmark (см. ipset_backend/nftset_backend).

Только для наборов, которые наполняем МЫ (set-путь без dnsmasq:
рефрешер, DNS-перехват). Наборы dnsmasq-пути dnsmasq наполняет сам и
срок записи не продлевает — там записи бессрочные, как раньше.

Настройки (settings.json → routing.set_ttl):
    enabled   — по умолчанию true;
    extra_sec — запас к TTL, по умолчанию 3600;
    min_sec   — нижняя граница TTL ответа (CDN отдают 20–60 с),
                по умолчанию 300.
"""

DEFAULT_EXTRA = 3600
DEFAULT_MIN = 300
# Потолок ipset timeout (2^31/1000 с) с запасом — и nft его тоже примет.
MAX_TIMEOUT = 2000000


def _settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        sec = get_config_manager().get("routing", "set_ttl",
                                       default={}) or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:
        return {}


def _int(value, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def params(settings: dict = None) -> dict:
    """{enabled, extra, min} из настроек (или переданного словаря)."""
    sec = _settings() if settings is None else (settings or {})
    return {"enabled": bool(sec.get("enabled", True)),
            "extra": _int(sec.get("extra_sec"), DEFAULT_EXTRA),
            "min": _int(sec.get("min_sec"), DEFAULT_MIN)}


def timeout_for(dns_ttl=None, settings: dict = None) -> int:
    """Срок записи в секундах; 0 — бессрочно (механизм выключен).

    dns_ttl=None — TTL неизвестен (резолв через getaddrinfo): берём
    нижнюю границу, рефрешер продлит запись на следующем проходе.
    """
    p = params(settings)
    if not p["enabled"]:
        return 0
    ttl = _int(dns_ttl, 0) if dns_ttl is not None else 0
    return min(MAX_TIMEOUT, max(ttl, p["min"]) + p["extra"])
