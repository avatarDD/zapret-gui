# core/scan_targets.py
"""
Профили целей для подбора стратегий.

Каждой популярной цели (youtube, discord, telegram, ...) сопоставляется
набор тестовых хостов, ожидаемых hostlist'ов и параметров фильтрации
nfqws2 (--filter-l7, --payload, порты TCP/UDP).

Используется strategy_scanner для:
  1) построения временного hostlist'а под конкретную цель скана
     (чтобы nfqws2 действительно "видел" SNI/Host цели);
  2) обогащения "приёмов" (catalogs/basic|advanced|direct) корректными
     --filter-l7=/--payload= под TCP/UDP;
  3) расширенной пробы (несколько test_hosts, тело >=64 KB на TCP).

Полные пресеты (catalogs/builtin/*) используются как есть — у них уже
свои --filter-*/--hostlist=, мы их не трогаем.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanTarget:
    """Профиль цели сканирования."""

    # Ключ профиля ("youtube", "discord", ...) — для логов и UI.
    key: str

    # Основной домен ("youtube.com") — он же берётся из формы.
    primary_host: str = ""

    # Дополнительные домены, которые тоже нужно протестировать,
    # чтобы исключить «псевдо-успехи» (когда главный пускают, а CDN режут).
    test_hosts: list[str] = field(default_factory=list)

    # Все домены, которые добавляются во временный hostlist nfqws2.
    # Если пусто — берётся primary_host + test_hosts.
    hostlist_domains: list[str] = field(default_factory=list)

    # Имена hostlist-файлов (без пути), которые ожидаются в zapret2/lists/.
    # Если присутствуют — подставляются в "trick"-стратегии вместо other.txt.
    expected_hostlists: list[str] = field(default_factory=list)

    # TCP-параметры
    tcp_ports: str = "443"
    tcp_l7: str = "tls"
    tcp_payload: str = "tls_client_hello"

    # UDP-параметры
    udp_ports: str = "443"
    udp_l7: str = "quic"
    udp_payload: str = "quic_initial"

    # URL для тяжёлой пробы (загрузка >=64 KB).
    # Используется для детекта 16-20 KB DPI-блокировки.
    # Если пусто — собирается на лету: https://<primary_host>/
    probe_url: str = ""

    def all_hostlist_domains(self) -> list[str]:
        """Список доменов для временного hostlist nfqws2."""
        if self.hostlist_domains:
            return list(self.hostlist_domains)
        out: list[str] = []
        if self.primary_host:
            out.append(self.primary_host)
        for h in self.test_hosts:
            if h not in out:
                out.append(h)
        return out

    def get_probe_url(self) -> str:
        """URL для body-download пробы."""
        return self.probe_url or ("https://%s/" % self.primary_host)


# ═══════════════════════════════════════════════════════════
#  Известные профили
# ═══════════════════════════════════════════════════════════

_KNOWN: dict[str, ScanTarget] = {
    "youtube": ScanTarget(
        key="youtube",
        primary_host="youtube.com",
        test_hosts=[
            "www.youtube.com",
            "i.ytimg.com",
            "yt3.ggpht.com",
        ],
        # nfqws2 хостлист матчит по точному совпадению SNI/Host;
        # для youtube QUIC/TLS реально нужны три семейства доменов.
        hostlist_domains=[
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtu.be",
            "youtubei.googleapis.com",
            "youtube-nocookie.com",
            "googlevideo.com",
            "rr1---sn-axq7sn7s.googlevideo.com",
            "ytimg.com",
            "i.ytimg.com",
            "yt3.ggpht.com",
            "ggpht.com",
            "lh3.googleusercontent.com",
            "yt3.googleusercontent.com",
        ],
        expected_hostlists=[
            "youtube.txt",
            "youtubeGV.txt",
            "youtubeQ.txt",
            "youtube_v2.txt",
        ],
        tcp_ports="80,443",
        tcp_l7="tls",
        tcp_payload="tls_client_hello",
        udp_ports="443",
        udp_l7="quic",
        udp_payload="quic_initial",
        probe_url="https://i.ytimg.com/generate_204",
    ),
    "discord": ScanTarget(
        key="discord",
        primary_host="discord.com",
        test_hosts=[
            "gateway.discord.gg",
            "cdn.discordapp.com",
            "media.discordapp.net",
        ],
        hostlist_domains=[
            "discord.com",
            "discordapp.com",
            "discord.gg",
            "discord.media",
            "discord-attachments-uploads-prd.storage.googleapis.com",
            "gateway.discord.gg",
            "cdn.discordapp.com",
            "media.discordapp.net",
        ],
        expected_hostlists=["discord.txt"],
        tcp_ports="443",
        tcp_l7="tls",
        tcp_payload="tls_client_hello",
        udp_ports="50000-65535",  # Discord voice
        udp_l7="discord",
        udp_payload="",
        probe_url="https://discord.com/api/v9/gateway",
    ),
    "telegram": ScanTarget(
        key="telegram",
        primary_host="web.telegram.org",
        test_hosts=["telegram.org", "t.me"],
        hostlist_domains=[
            "telegram.org",
            "web.telegram.org",
            "telegram.me",
            "t.me",
            "cdn-telegram.org",
        ],
        expected_hostlists=["telegram.txt"],
        tcp_ports="443",
        tcp_l7="tls",
        tcp_payload="tls_client_hello",
        udp_ports="443",
        udp_l7="quic",
        udp_payload="quic_initial",
        probe_url="https://web.telegram.org/k/",
    ),
    "instagram": ScanTarget(
        key="instagram",
        primary_host="instagram.com",
        test_hosts=["www.instagram.com", "i.instagram.com"],
        hostlist_domains=[
            "instagram.com",
            "www.instagram.com",
            "i.instagram.com",
            "scontent.cdninstagram.com",
            "cdninstagram.com",
        ],
        expected_hostlists=["instagram.txt"],
    ),
    "twitter": ScanTarget(
        key="twitter",
        primary_host="x.com",
        test_hosts=["twitter.com", "abs.twimg.com"],
        hostlist_domains=[
            "x.com",
            "twitter.com",
            "t.co",
            "twimg.com",
            "abs.twimg.com",
            "video.twimg.com",
        ],
        expected_hostlists=["twitter.txt"],
    ),
    "facebook": ScanTarget(
        key="facebook",
        primary_host="facebook.com",
        test_hosts=["www.facebook.com", "scontent.xx.fbcdn.net"],
        hostlist_domains=[
            "facebook.com",
            "www.facebook.com",
            "fbcdn.net",
            "scontent.xx.fbcdn.net",
        ],
        expected_hostlists=["facebook.txt"],
    ),
    "google": ScanTarget(
        key="google",
        primary_host="www.google.com",
        test_hosts=["google.com", "fonts.gstatic.com"],
        hostlist_domains=[
            "google.com",
            "www.google.com",
            "gstatic.com",
            "fonts.gstatic.com",
        ],
    ),
}


# Маппинг признаков в имени домена → ключ профиля.
# Порядок важен: YouTube ловится по нескольким альтернативным именам.
_HOST_HINTS = (
    ("youtube", "youtube"),
    ("ytimg",   "youtube"),
    ("ggpht",   "youtube"),
    ("googlevideo", "youtube"),
    ("youtu.be", "youtube"),
    ("discord", "discord"),
    ("telegram", "telegram"),
    ("t.me",    "telegram"),
    ("instagram", "instagram"),
    ("cdninstagram", "instagram"),
    ("twitter", "twitter"),
    ("twimg",   "twitter"),
    ("x.com",   "twitter"),
    ("facebook", "facebook"),
    ("fbcdn",   "facebook"),
    ("google",  "google"),
)


def detect_target(host: str) -> ScanTarget:
    """
    Определить профиль цели по имени домена.

    Если профиль не известен — собирается generic-профиль на основе
    переданного хоста (без расширенного списка hostlist_domains).
    """
    host_lower = (host or "").strip().lower()
    if not host_lower:
        host_lower = "youtube.com"

    for hint, key in _HOST_HINTS:
        if hint in host_lower:
            base = _KNOWN[key]
            # Если пользователь указал нестандартный домен — добавляем его
            # в primary_host и в hostlist_domains как первую запись.
            if host_lower != base.primary_host:
                merged_domains = [host_lower] + [
                    d for d in base.hostlist_domains if d != host_lower
                ]
                merged_tests = [host_lower] + [
                    h for h in base.test_hosts if h != host_lower
                ]
                return ScanTarget(
                    key=base.key,
                    primary_host=host_lower,
                    test_hosts=merged_tests[:4],
                    hostlist_domains=merged_domains,
                    expected_hostlists=list(base.expected_hostlists),
                    tcp_ports=base.tcp_ports,
                    tcp_l7=base.tcp_l7,
                    tcp_payload=base.tcp_payload,
                    udp_ports=base.udp_ports,
                    udp_l7=base.udp_l7,
                    udp_payload=base.udp_payload,
                    probe_url=base.probe_url,
                )
            return base

    # Generic профиль для незнакомой цели.
    return ScanTarget(
        key="generic",
        primary_host=host_lower,
        test_hosts=[host_lower],
        hostlist_domains=[host_lower],
        tcp_ports="443",
        tcp_l7="tls",
        tcp_payload="tls_client_hello",
        udp_ports="443",
        udp_l7="quic",
        udp_payload="quic_initial",
    )
