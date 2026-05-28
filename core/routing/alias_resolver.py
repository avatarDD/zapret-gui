# core/routing/alias_resolver.py
"""
Резолвер geosite:/geoip: алиасов в полные списки доменов/CIDR
(HydraRoute Neo-совместимый).

Пользователь в правиле может писать:
    youtube.com
    geosite:youtube         ← разворачивается в полный список доменов YouTube
    geoip:ru                ← разворачивается в CIDR-список российских IP

Резолвер скачивает соответствующие списки из community-репозиториев
(по умолчанию — v2fly/domain-list-community и v2fly/geoip), хранит
кэш в `data/aliases/` и автоматически обновляет раз в TTL_HOURS часов.

На бэке используется в `apply_domain_rule()` (и в будущем — для
CIDR-правил, если в `cidrs` встретится `geoip:...`).

Источники списков и сам набор built-in алиасов можно переопределить
через `/api/routing/aliases/config` (см. api/routing.py).
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


# ─────── константы и пути ───────

TTL_HOURS = 24                    # обновлять кэш не чаще, чем раз в сутки
HTTP_TIMEOUT = 20                 # секунды на скачивание одного списка
MAX_ITEMS_PER_LIST = 50_000       # защита от случайно громадных списков
USER_AGENT = "zapret-gui/alias-resolver"


def _cache_dir() -> str:
    """
    Каталог кэша. Лежит рядом с проектом — `data/aliases/`.
    Не /var/lib (на роутерах это либо tmpfs либо несуществующий путь).
    """
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base = os.path.dirname(base)   # подняться из core/routing/ в корень
    d = os.path.join(base, "data", "aliases")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


# ─────── built-in alias mappings ───────
#
# Минимальный набор популярных алиасов. Каждый ведёт на raw-URL
# простого text-файла с доменами/CIDR (один элемент на строку,
# комментарии с # допустимы).
#
# geosite-источник: v2fly/domain-list-community (`data/<name>`).
# Файлы там в кастомном формате с include-директивами; мы их
# дёргаем построчно, фильтруем `include:`/`regexp:`/`@cn` и берём
# чистые domain-записи. Этого достаточно для bypass-цели.
#
# geoip-источник: v2fly/geoip (`text/<cc>.txt`) — простые CIDR-списки.

DEFAULT_GEOSITE_TEMPLATE = (
    "https://raw.githubusercontent.com/v2fly/domain-list-community/"
    "master/data/{name}"
)
DEFAULT_GEOIP_TEMPLATE = (
    "https://raw.githubusercontent.com/v2fly/geoip/release/text/{name}.txt"
)

# Алиасы, которые мы документируем как «гарантированно работают».
# Можно использовать любое имя из v2fly-репо — URL подставится из
# шаблона; но эти показываем в UI как саджесты.
SUGGESTED_GEOSITE = [
    "youtube", "netflix", "google", "facebook", "twitter", "twitch",
    "discord", "telegram", "reddit", "spotify", "github", "openai",
    "tiktok", "instagram", "amazon", "microsoft", "apple",
]
SUGGESTED_GEOIP = [
    "ru", "us", "cn", "ua", "by", "kz", "de", "gb",
    "cloudflare", "google", "cloudfront", "telegram",
]


# ─────── alias parsing ───────

_ALIAS_RE = re.compile(r"^(geosite|geoip):([A-Za-z0-9_\-]+)$",
                       re.IGNORECASE)


def is_alias(token: str) -> bool:
    if not token:
        return False
    return bool(_ALIAS_RE.match(token.strip()))


def parse_alias(token: str):
    """('geosite'|'geoip', '<name>') либо (None, None)."""
    if not token:
        return None, None
    m = _ALIAS_RE.match(token.strip())
    if not m:
        return None, None
    return m.group(1).lower(), m.group(2).lower()


# ─────── HTTP fetch ───────

_lock = threading.Lock()


def _http_get_text(url: str, timeout: float = HTTP_TIMEOUT) -> str:
    """GET <url>, вернуть тело как str. Пустая строка при ошибке."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError,
            OSError, TimeoutError) as e:
        log.warning("alias_resolver: fetch %s failed: %s" % (url, e),
                    source="routing")
        return ""


# ─────── parsing list bodies ───────

def _parse_geosite_body(text: str) -> list:
    """
    v2fly geosite-формат:
        # коммент
        domain
        full:foo.bar.com
        regexp:^.*$
        include:other-list
        domain @cn       (тэги; для нас — игнорируем)

    Берём:
      - `domain` как есть
      - `full:<domain>` без префикса
    Регэкспы, include'ы и тэги — пропускаем.

    include:other-list рекурсивно мы НЕ разворачиваем — иначе можем
    словить цикл и/или 100k доменов. Если кому-то нужно — пусть
    явно подключает второй алиас.
    """
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Срезаем inline-комментарии и tag-выражения
        line = line.split("#", 1)[0].strip()
        line = line.split("@", 1)[0].strip()
        if not line:
            continue
        if line.startswith("regexp:") or line.startswith("include:"):
            continue
        if line.startswith("full:"):
            line = line[5:].strip()
        elif line.startswith("domain:"):
            line = line[7:].strip()
        elif line.startswith("keyword:"):
            # «keyword» в v2fly — substring; в FQDN-группе нативно не
            # поддерживается, пропускаем.
            continue
        if not line:
            continue
        # Лёгкая санация: домены содержат только буквы/цифры/./-/_
        if not re.match(r"^[A-Za-z0-9_.\-]+$", line):
            continue
        out.append(line.lower())
        if len(out) >= MAX_ITEMS_PER_LIST:
            break
    return out


def _parse_geoip_body(text: str) -> list:
    """v2fly geoip text-формат — одна CIDR-запись на строку."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        # Минимальная валидация CIDR
        if not re.match(r"^[0-9a-fA-F:.\/]+$", line):
            continue
        out.append(line)
        if len(out) >= MAX_ITEMS_PER_LIST:
            break
    return out


# ─────── cache layer ───────

def _cache_path(kind: str, name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", name).lower()
    return os.path.join(_cache_dir(), "%s-%s.json" % (kind.lower(), safe))


def _read_cache(kind: str, name: str):
    path = _cache_path(kind, name)
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (IOError, OSError, ValueError, json.JSONDecodeError):
        return None


def _write_cache(kind: str, name: str, items: list, url: str):
    path = _cache_path(kind, name)
    blob = {
        "kind":  kind,
        "name":  name,
        "url":   url,
        "fetched_at": int(time.time()),
        "count": len(items),
        "items": items,
    }
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(blob, f)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("alias_resolver: write cache %s: %s" % (path, e),
                    source="routing")


def _cache_fresh(blob: dict) -> bool:
    if not blob:
        return False
    age = time.time() - int(blob.get("fetched_at") or 0)
    return age < (TTL_HOURS * 3600)


# ─────── public API ───────

def resolve_alias(kind: str, name: str, force_refresh: bool = False) -> list:
    """
    Разрешить один алиас в список элементов.

    kind  ∈ {'geosite', 'geoip'}
    name  ∈ имя списка (lowercase)

    Возвращает list[str] или [] при неудаче. Кэширует, использует TTL.
    """
    kind = (kind or "").lower()
    name = (name or "").lower()
    if kind not in ("geosite", "geoip") or not name:
        return []

    with _lock:
        if not force_refresh:
            cached = _read_cache(kind, name)
            if cached and _cache_fresh(cached):
                items = cached.get("items") or []
                return list(items)

        url = (DEFAULT_GEOSITE_TEMPLATE if kind == "geosite"
               else DEFAULT_GEOIP_TEMPLATE).format(name=name)
        text = _http_get_text(url)
        if not text:
            # Сеть могла отвалиться — используем устаревший кэш, если есть.
            cached = _read_cache(kind, name)
            if cached:
                log.info("alias_resolver: используем устаревший кэш %s:%s"
                         % (kind, name), source="routing")
                return list(cached.get("items") or [])
            return []

        items = (_parse_geosite_body(text) if kind == "geosite"
                 else _parse_geoip_body(text))
        if not items:
            log.warning("alias_resolver: пустой результат %s:%s"
                        % (kind, name), source="routing")
            return []

        _write_cache(kind, name, items, url)
        log.info("alias_resolver: обновлён %s:%s (%d записей)"
                 % (kind, name, len(items)), source="routing")
        return list(items)


def expand_domains(items, force_refresh: bool = False) -> dict:
    """
    Разделить смешанный вход на чистые домены, чистые CIDR и алиасы;
    алиасы развернуть.

    Параметр items — итерируемый список строк.

    Возвращает dict:
      {
        "domains": [...],          # все домены (raw + развёрнутые geosite)
        "cidrs":   [...],          # все CIDR (raw + развёрнутые geoip)
        "aliases_resolved": [{"kind": "...", "name": "...", "count": N}, ...],
        "aliases_failed":   [{"kind": "...", "name": "..."}, ...],
      }

    На неудачные алиасы возвращаемые списки не пополняются — UI должен
    показать предупреждение по `aliases_failed`.
    """
    out = {
        "domains": [],
        "cidrs":   [],
        "aliases_resolved": [],
        "aliases_failed":   [],
    }
    seen_d = set()
    seen_c = set()

    for token in items or []:
        s = str(token or "").strip()
        if not s:
            continue
        kind, name = parse_alias(s)
        if kind:
            resolved = resolve_alias(kind, name, force_refresh=force_refresh)
            if not resolved:
                out["aliases_failed"].append({"kind": kind, "name": name})
                continue
            out["aliases_resolved"].append(
                {"kind": kind, "name": name, "count": len(resolved)})
            for it in resolved:
                if kind == "geosite":
                    if it not in seen_d:
                        seen_d.add(it)
                        out["domains"].append(it)
                else:   # geoip
                    if it not in seen_c:
                        seen_c.add(it)
                        out["cidrs"].append(it)
            continue
        # Не алиас — bare-domain или bare-cidr.
        if "/" in s or _looks_like_ip(s):
            if s not in seen_c:
                seen_c.add(s)
                out["cidrs"].append(s)
        else:
            low = s.lower()
            if low not in seen_d:
                seen_d.add(low)
                out["domains"].append(low)

    return out


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", s)) or \
           bool(re.match(r"^[0-9a-fA-F:]+$", s)) and ":" in s


def refresh_all_cached(force: bool = True) -> dict:
    """
    Обновить все алиасы, которые когда-то были закэшированы.

    Возвращает {"refreshed": [...], "failed": [...]}.
    """
    result = {"refreshed": [], "failed": []}
    d = _cache_dir()
    if not os.path.isdir(d):
        return result
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        base = fn[:-5]
        kind, _, name = base.partition("-")
        if kind not in ("geosite", "geoip") or not name:
            continue
        items = resolve_alias(kind, name, force_refresh=force)
        entry = {"kind": kind, "name": name, "count": len(items)}
        (result["refreshed"] if items else result["failed"]).append(entry)
    return result


def list_cached() -> list:
    """Список того, что лежит в кэше прямо сейчас (для UI)."""
    out = []
    d = _cache_dir()
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if not fn.endswith(".json"):
            continue
        base = fn[:-5]
        kind, _, name = base.partition("-")
        if kind not in ("geosite", "geoip") or not name:
            continue
        blob = _read_cache(kind, name)
        if not blob:
            continue
        out.append({
            "kind":       kind,
            "name":       name,
            "count":      int(blob.get("count") or 0),
            "fetched_at": int(blob.get("fetched_at") or 0),
            "url":        str(blob.get("url") or ""),
            "fresh":      _cache_fresh(blob),
        })
    out.sort(key=lambda x: (x["kind"], x["name"]))
    return out


def list_suggestions() -> dict:
    """Алиасы, которые мы показываем в UI как «вероятно работающие»."""
    return {
        "geosite": list(SUGGESTED_GEOSITE),
        "geoip":   list(SUGGESTED_GEOIP),
    }
