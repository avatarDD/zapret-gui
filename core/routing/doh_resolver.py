# core/routing/doh_resolver.py
"""
DNS-over-HTTPS резолвер для pre-population ipset/nftset.

Зачем: на не-Keenetic платформах domain-маршрутизация работает
через dnsmasq + ipset/nftset с хуком на резолв. Чтобы set не оставался
пустым (когда браузер с DoH идёт мимо dnsmasq), мы делаем
pre-population — резолвим домены сами и добавляем IP в set заранее.

Раньше мы для этого использовали `socket.getaddrinfo()` — он идёт
через системный resolver и /etc/resolv.conf, то есть к тому же
upstream, на который указывает роутер. Это значит:
  - ISP может подменять ответы (Russian RKN delegations);
  - или DPI блокирует сам запрос (cleartext DNS на :53).

DoH (HTTPS-резолвинг через :443) обходит обе проблемы. Мы используем
JSON-формат (RFC 8484 binary тоже возможен, но JSON проще и без
сторонних зависимостей):

  GET https://cloudflare-dns.com/dns-query?name=example.com&type=A
  Accept: application/dns-json

Включается опционально. По умолчанию резолвинг идёт по-старому
через системный getaddrinfo — не ломаем существующее поведение.

Конфигурация: в settings.json под `routing.doh`:
  {
    "enabled": true,
    "providers": [
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/resolve"
    ],
    "timeout": 5
  }
"""

import json
import threading
import urllib.error
import urllib.parse
import urllib.request

from core.log_buffer import log


# ─────── известные DoH-провайдеры (JSON-формат) ───────
#
# Все три отдают application/dns-json по одной и той же схеме (RFC 8484
# JSON encoding), отличаются только URL'ами и стабильностью в РФ.

KNOWN_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/resolve",
    "quad9":      "https://dns.quad9.net:5053/dns-query",
}

DEFAULT_PROVIDERS = [
    KNOWN_PROVIDERS["cloudflare"],
    KNOWN_PROVIDERS["google"],
]

DEFAULT_TIMEOUT = 5
USER_AGENT = "zapret-gui/doh-resolver"


# ─────── settings access ───────

_settings_lock = threading.Lock()


def _get_settings() -> dict:
    """
    Вернуть `routing.doh` секцию из settings.json или дефолты.

    Не падаем, если конфига нет — просто возвращаем off-by-default.
    """
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load()
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    routing = cfg.get("routing") or {}
    doh = routing.get("doh") or {}
    if not isinstance(doh, dict):
        doh = {}
    return {
        "enabled":   bool(doh.get("enabled", False)),
        "providers": list(doh.get("providers") or DEFAULT_PROVIDERS),
        "timeout":   float(doh.get("timeout", DEFAULT_TIMEOUT)),
    }


def set_settings(enabled: bool = None, providers=None,
                 timeout: float = None) -> dict:
    """
    Обновить настройки DoH. Возвращает актуальные настройки.

    Параметры None означают «не трогать».
    """
    with _settings_lock:
        try:
            from core.config_manager import get_config_manager, save_config
        except Exception as e:
            log.warning("doh_resolver: settings unavailable: %s" % e,
                        source="routing")
            return _get_settings()

        cfg = get_config_manager().load()
        if not isinstance(cfg, dict):
            cfg = {}
        cfg.setdefault("routing", {}).setdefault("doh", {})
        sec = cfg["routing"]["doh"]
        if enabled is not None:
            sec["enabled"] = bool(enabled)
        if providers is not None:
            sec["providers"] = [str(p).strip() for p in providers
                                if str(p).strip()]
        if timeout is not None:
            try:
                sec["timeout"] = float(timeout)
            except (TypeError, ValueError):
                pass
        try:
            save_config()
        except Exception as e:
            log.warning("doh_resolver: save_config: %s" % e,
                        source="routing")
        return _get_settings()


def is_enabled() -> bool:
    """Включён ли DoH-резолвер прямо сейчас."""
    return _get_settings().get("enabled", False)


# ─────── resolve ───────

def resolve(domain: str, family: str = "v4") -> dict:
    """
    Зарезолвить domain через DoH-провайдеры.

    family ∈ {"v4", "v6"}.

    Возвращает:
      {"ok": bool, "ips": [...], "provider": "<url>", "error": "..."}

    Идём по списку провайдеров по очереди до первого успеха.
    Если ни один не отвечает — ok=False.
    """
    if not domain:
        return {"ok": False, "ips": [], "provider": "", "error": "empty"}

    settings = _get_settings()
    if not settings["enabled"]:
        return {"ok": False, "ips": [], "provider": "",
                "error": "DoH выключен в settings"}

    qtype = "AAAA" if family == "v6" else "A"
    timeout = settings["timeout"]
    last_err = ""

    for url in settings["providers"]:
        try:
            ips = _query_json(url, domain, qtype, timeout)
            if ips:
                return {"ok": True, "ips": ips, "provider": url,
                        "error": ""}
        except Exception as e:
            last_err = str(e)
            continue

    return {"ok": False, "ips": [], "provider": "",
            "error": last_err or "no provider answered"}


def _query_json(provider_url: str, domain: str, qtype: str,
                timeout: float) -> list:
    """
    Один запрос к одному DoH-провайдеру в JSON-формате.

    Возвращает list of IP-строк (может быть пустым, если NXDOMAIN).
    """
    qs = urllib.parse.urlencode({"name": domain, "type": qtype})
    url = "%s?%s" % (provider_url, qs)
    req = urllib.request.Request(
        url,
        headers={
            "Accept":     "application/dns-json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    # RFC 8484 JSON: {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]}
    answers = data.get("Answer") or []
    ips = []
    want_type = 1 if qtype == "A" else 28
    for a in answers:
        if not isinstance(a, dict):
            continue
        if a.get("type") != want_type:
            continue
        ip = (a.get("data") or "").strip()
        if ip:
            ips.append(ip)
    return ips
