# core/targets.py
"""
Каталог целей для проверок — единственный список «популярных сервисов».

До этого один и тот же набор был описан дважды и успел разъехаться:
  - core/diagnostics.SERVICES     — светофор «Сервисы» (ping/DNS/HTTP);
  - core/blockcheck._DEFAULT_DOMAINS — цели теста доступности.
В первом были ChatGPT и Claude, во втором — rutracker, spotify, linkedin,
facebook; добавляя сервис, приходилось помнить про оба места (и никто не
помнил).

Здесь один источник:
  SERVICES        — сервисы для карточек-светофоров: имя, иконка, хосты, URL;
  REFERENCE_HOSTS — дополнительные цели для теста доступности: эталонные
                    (заведомо не блокируются — проверяют, что интернет вообще
                    есть) и специфичные, которым карточка не нужна.

Кто что берёт:
  диагностика   → SERVICES (карточки),
  blockcheck    → default_check_domains() = хосты SERVICES + REFERENCE_HOSTS,
  block-detector→ ничего: он берёт домены из живого DNS.
"""

from __future__ import annotations

from typing import Any


# ─────────────────────── Сервисы (карточки-светофоры) ───────────────────────

SERVICES: dict[str, dict[str, Any]] = {
    "youtube": {
        "name": "YouTube",
        "icon": "▶",
        "hosts": ["youtube.com", "www.youtube.com", "i.ytimg.com"],
        "urls": ["https://www.youtube.com"],
    },
    "discord": {
        "name": "Discord",
        "icon": "💬",
        "hosts": ["discord.com", "cdn.discordapp.com", "gateway.discord.gg"],
        "urls": ["https://discord.com"],
    },
    "telegram": {
        "name": "Telegram",
        "icon": "✈",
        "hosts": ["t.me", "web.telegram.org", "core.telegram.org"],
        "urls": ["https://t.me"],
    },
    "instagram": {
        "name": "Instagram",
        "icon": "📷",
        "hosts": ["instagram.com", "i.instagram.com"],
        "urls": ["https://www.instagram.com"],
    },
    "twitter": {
        "name": "X / Twitter",
        "icon": "𝕏",
        "hosts": ["x.com", "twitter.com"],
        "urls": ["https://x.com"],
    },
    "chatgpt": {
        "name": "ChatGPT",
        "icon": "🤖",
        "hosts": ["chatgpt.com", "chat.openai.com"],
        "urls": ["https://chatgpt.com"],
    },
    "claude": {
        "name": "Claude",
        "icon": "🧠",
        "hosts": ["claude.ai"],
        "urls": ["https://claude.ai"],
    },
    "rutracker": {
        "name": "RuTracker",
        "icon": "🧲",
        "hosts": ["rutracker.org"],
        "urls": ["https://rutracker.org"],
    },
    "spotify": {
        "name": "Spotify",
        "icon": "🎵",
        "hosts": ["www.spotify.com", "open.spotify.com"],
        "urls": ["https://www.spotify.com"],
    },
    "facebook": {
        "name": "Facebook",
        "icon": "📘",
        "hosts": ["www.facebook.com", "facebook.com"],
        "urls": ["https://www.facebook.com"],
    },
    "linkedin": {
        "name": "LinkedIn",
        "icon": "💼",
        "hosts": ["www.linkedin.com"],
        "urls": ["https://www.linkedin.com"],
    },
}


# ─────────────────────── Эталонные цели (без карточек) ───────────────────────

# Заведомо доступные узлы: если ложатся и они — дело не в блокировках, а в
# том, что интернета нет вовсе. Карточка-светофор им не нужна, но в тесте
# доступности они задают точку отсчёта.
REFERENCE_HOSTS: list[str] = [
    "www.google.com",
    "www.cloudflare.com",
]


def service_hosts() -> list[str]:
    """Все хосты сервисов, без повторов, в порядке объявления."""
    out: list[str] = []
    for svc in SERVICES.values():
        for host in svc.get("hosts", []):
            if host not in out:
                out.append(host)
    return out


def default_check_domains() -> list[str]:
    """Список целей по умолчанию для теста доступности (blockcheck).

    Хосты сервисов + эталонные узлы. Пользовательский data/domains.txt,
    если он есть, всё равно имеет приоритет — это только дефолт.
    """
    out = service_hosts()
    for host in REFERENCE_HOSTS:
        if host not in out:
            out.append(host)
    return out


def available_services() -> dict[str, dict[str, Any]]:
    """Сервисы для API: имя, иконка, хосты, URL."""
    return {
        key: {
            "name": svc["name"],
            "icon": svc.get("icon", ""),
            "hosts": list(svc.get("hosts", [])),
            "urls": list(svc.get("urls", [])),
        }
        for key, svc in SERVICES.items()
    }
