# core/subscription_importer.py
"""
Импорт подписок Karing/Hiddify/VLESS-формата.

Подписка — URL, по которому отдаётся текст с одним или несколькими
конфигами VPN-туннелей. Формат варьируется:
  - base64-encoded одна большая строка → раскодировать → text/uri-list
  - plain text с одной URI на строку
  - сырой .conf (WireGuard/AmneziaWG) — иногда отдают так

URI-схемы, которые встречаются в подписках:
  - wireguard://    — WG share URI (приходит из Cloudflare WARP +
                       сторонних WG-провайдеров)
  - vless://        — VLESS (sing-box)
  - trojan://       — Trojan (sing-box)
  - ss://           — Shadowsocks (sing-box)
  - hysteria2://    — Hysteria 2 (sing-box)

В этом модуле мы умеем:
  - скачать подписку (HTTPS, с таймаутом)
  - распознать base64 vs plain
  - вытащить из текста все URI / .conf-блоки
  - **импортировать только WireGuard/AmneziaWG** — остальное
    пропускается с пометкой `skipped: needs sing-box`, потому что
    у нас sing-box ещё не интегрирован (отдельный TODO).

Когда придёт интеграция Sing-box, обработчики для других схем
добавятся в `_PROTOCOL_HANDLERS`.
"""

import base64
import re
import urllib.error
import urllib.parse
import urllib.request

from core.log_buffer import log


DEFAULT_TIMEOUT = 20
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024   # 5 МБ — защита от мусора
USER_AGENT = "zapret-gui/subscription-importer"

# Все URI-схемы, которые мы умеем распознать (даже если не умеем
# импортировать без sing-box).
_KNOWN_SCHEMES = (
    "wireguard", "wg",
    "vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "tuic",
)

_URI_RE = re.compile(
    r"\b(?:" + "|".join(_KNOWN_SCHEMES) + r")://[^\s'\"<>]+",
    re.IGNORECASE,
)

# Признак сырого .conf-блока — секции [Interface] / [Peer]
_CONF_SECTION_RE = re.compile(
    r"\[(Interface|Peer)\]", re.IGNORECASE | re.MULTILINE)


# ════════════════════════════════════════════════════════════
# fetch
# ════════════════════════════════════════════════════════════

def fetch_subscription(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """
    GET <url>. Возвращает body как str.

    Принимает HTTPS и HTTP. На неудачу — поднимает RuntimeError с
    описанием. Body ограничен MAX_DOWNLOAD_BYTES.
    """
    if not url or not isinstance(url, str):
        raise RuntimeError("Пустой URL")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError("URL должен начинаться с http:// или https://")

    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP %s при загрузке подписки" % e.code)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise RuntimeError("Не удалось загрузить подписку: %s" % e)

    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise RuntimeError("Подписка превышает %d МБ — отказ"
                           % (MAX_DOWNLOAD_BYTES // (1024 * 1024)))
    return raw.decode("utf-8", errors="replace")


# ════════════════════════════════════════════════════════════
# detect format & decode
# ════════════════════════════════════════════════════════════

def _maybe_decode_base64(text: str) -> str:
    """
    Если text похож на base64 — раскодировать и вернуть.

    Эвристика: достаточно длинный (>40 символов), без переносов или с
    переносами Юникс-стиль, и распадается на печатный UTF-8 после
    base64-декода.
    """
    s = (text or "").strip()
    if len(s) < 40:
        return text
    # base64 не содержит «://» — если содержит, это уже plain.
    if "://" in s or "[Interface]" in s or "[Peer]" in s:
        return text

    # Удалим whitespace для попытки декодирования.
    candidate = re.sub(r"\s+", "", s)
    # base64-набор: A-Z a-z 0-9 + / =, опционально - _ для urlsafe
    if not re.match(r"^[A-Za-z0-9+/=_\-]+$", candidate):
        return text
    try:
        # Подгоним padding и пробуем оба варианта.
        pad = (-len(candidate)) % 4
        decoded = base64.urlsafe_b64decode(candidate + "=" * pad)
        try:
            txt = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return text
        # Если в декодированном тексте есть URI — это та самая
        # base64-encoded подписка.
        if "://" in txt or "[Interface]" in txt:
            return txt
    except (ValueError, base64.binascii.Error):
        return text
    return text


# ════════════════════════════════════════════════════════════
# extract URIs / .conf blocks
# ════════════════════════════════════════════════════════════

def extract_items(text: str) -> list:
    """
    Достать из text список «item»-ов: URI или сырых .conf-блоков.

    Возвращает list of dict:
      {"type": "uri", "scheme": "...", "value": "<uri>"}
      {"type": "conf", "value": "<full .conf text>"}
    """
    text = _maybe_decode_base64(text or "")
    items = []
    seen = set()

    # 1) Сырые .conf-блоки. Берём весь text целиком — мы не пытаемся
    # извлечь множественные .conf'ы из одной подписки, потому что
    # эта схема не стандартизирована. Один text → ноль или один conf.
    if _CONF_SECTION_RE.search(text):
        items.append({"type": "conf", "value": text})

    # 2) URI'ы — построчно и через regex (на случай если они склеены
    # в одну строку с разделителями).
    for m in _URI_RE.finditer(text):
        uri = m.group(0).rstrip(",;|")
        scheme = uri.split("://", 1)[0].lower()
        key = (scheme, uri)
        if key in seen:
            continue
        seen.add(key)
        items.append({"type": "uri", "scheme": scheme, "value": uri})

    return items


# ════════════════════════════════════════════════════════════
# wireguard:// URI → .conf
# ════════════════════════════════════════════════════════════

def wireguard_uri_to_conf(uri: str) -> dict:
    """
    `wireguard://<private_key>@<host>:<port>?<params>#<name>`

    Возвращает {"ok": bool, "name": str, "conf": str, "error": str?}.
    """
    if not uri:
        return {"ok": False, "error": "пустой URI"}
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError as e:
        return {"ok": False, "error": "URI не распарсился: %s" % e}

    if p.scheme.lower() not in ("wireguard", "wg"):
        return {"ok": False, "error": "не wireguard-URI"}
    if not p.username:
        return {"ok": False, "error": "в URI нет private key"}
    if not p.hostname or not p.port:
        return {"ok": False, "error": "в URI нет endpoint"}

    private_key = urllib.parse.unquote(p.username)
    endpoint = "%s:%s" % (p.hostname, p.port)
    qs = urllib.parse.parse_qs(p.query)

    # Стандартные параметры в WG-URI (см. wg-quick share-формат):
    #   publickey       — публичный ключ peer'а
    #   presharedkey    — psk (опционально)
    #   address         — адрес интерфейса (CIDR)
    #   dns             — DNS-серверы через запятую
    #   mtu             — MTU
    #   allowedips      — AllowedIPs через запятую (default 0.0.0.0/0,::/0)
    #   persistentkeepalive — keepalive
    def _q(key, default=""):
        v = qs.get(key) or qs.get(key.lower())
        if not v:
            return default
        return urllib.parse.unquote(v[0]).strip()

    public_key  = _q("publickey")
    psk         = _q("presharedkey")
    address     = _q("address") or _q("ip")
    dns         = _q("dns")
    mtu         = _q("mtu")
    allowed_ips = _q("allowedips") or "0.0.0.0/0, ::/0"
    keepalive   = _q("persistentkeepalive") or _q("keepalive")

    name = urllib.parse.unquote(p.fragment or "")
    if not name:
        name = "wg-%s" % p.hostname.replace(".", "-")

    if not public_key:
        return {"ok": False, "error": "в URI нет PublicKey peer'а"}

    lines = ["[Interface]",
             "PrivateKey = %s" % private_key]
    if address:
        lines.append("Address = %s" % address)
    if dns:
        lines.append("DNS = %s" % dns)
    if mtu:
        lines.append("MTU = %s" % mtu)
    lines.append("")
    lines.append("[Peer]")
    lines.append("PublicKey = %s" % public_key)
    if psk:
        lines.append("PresharedKey = %s" % psk)
    lines.append("Endpoint = %s" % endpoint)
    lines.append("AllowedIPs = %s" % allowed_ips)
    if keepalive:
        lines.append("PersistentKeepalive = %s" % keepalive)

    return {"ok": True, "name": _safe_conf_name(name),
            "conf": "\n".join(lines) + "\n"}


_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_.\-]+")


def _safe_conf_name(name: str) -> str:
    s = _NAME_SAFE_RE.sub("-", (name or "").strip())
    s = s.strip("-.") or "imported"
    return s[:32]


# ════════════════════════════════════════════════════════════
# high-level import
# ════════════════════════════════════════════════════════════

def import_subscription(url: str = "", text: str = "",
                        save: bool = True) -> dict:
    """
    Импортировать подписку.

    Один из {url, text} должен быть непустым. Если оба — приоритет
    у text (полезно для случаев, когда подписку уже скачали через
    UI и присылают сырой текст).

    Возвращает:
      {
        "ok": bool,
        "items": [
          {"type":"wireguard", "name":"...", "ok":True, "saved":True},
          {"type":"vless",     "name":"...", "ok":False,
           "error":"needs sing-box"},
          ...
        ],
        "summary": {"imported": N, "skipped": M, "errors": K}
      }
    """
    if not url and not text:
        return {"ok": False, "error": "Нужен url или text"}

    body = text
    if not body:
        try:
            body = fetch_subscription(url)
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}

    items = extract_items(body or "")
    if not items:
        return {"ok": False,
                "error": "В подписке не нашлось ни URI, ни .conf"}

    result_items = []
    imported = skipped = errors = 0

    # Импорт WG-URI и .conf — через AwgManager
    awg_mgr = None
    if save:
        try:
            from core.awg_manager import AwgManager
            awg_mgr = AwgManager()
        except Exception as e:
            log.warning("subscription_importer: AwgManager init: %s" % e,
                        source="awg")

    for it in items:
        if it["type"] == "conf":
            r = _import_conf_block(awg_mgr, it["value"], save=save)
            result_items.append(r)
            if r.get("ok"):
                imported += 1
            else:
                errors += 1
            continue

        scheme = it.get("scheme", "")
        if scheme in ("wireguard", "wg"):
            parsed = wireguard_uri_to_conf(it["value"])
            if not parsed.get("ok"):
                errors += 1
                result_items.append({
                    "type": scheme, "ok": False,
                    "error": parsed.get("error", "parse error"),
                    "uri": _redact(it["value"]),
                })
                continue
            saved = False
            if awg_mgr:
                try:
                    save_res = awg_mgr.save_config(
                        name=parsed["name"], text=parsed["conf"])
                    saved = bool(save_res and save_res.get("ok"))
                except Exception as e:
                    log.warning(
                        "subscription_importer: save %s: %s"
                        % (parsed["name"], e), source="awg")
            imported += 1
            result_items.append({
                "type": scheme, "ok": True,
                "name": parsed["name"], "saved": saved,
            })
        else:
            # Sing-box-семейство схем: vless / trojan / ss /
            # hysteria2 / hy2 / tuic. Конвертируем в outbound и
            # добавляем в общий sing-box-конфиг 'imported-subscription'.
            sb_res = _try_import_singbox_uri(it["value"], save=save)
            if sb_res["handled"]:
                result_items.append(sb_res["item"])
                if sb_res["item"].get("ok"):
                    imported += 1
                else:
                    errors += 1
                continue

            skipped += 1
            result_items.append({
                "type": scheme, "ok": False,
                "error": "scheme %s не поддержан" % scheme,
                "uri": _redact(it["value"]),
            })

    return {
        "ok":      True,
        "items":   result_items,
        "summary": {"imported": imported, "skipped": skipped,
                    "errors": errors,
                    "total": len(result_items)},
    }


# Имя sing-box-конфига, в который мы агрегируем outbound'ы из всех
# успешно импортированных не-WG URI. Один файл — много outbound'ов.
SINGBOX_IMPORT_CONFIG = "imported-subscription"


def _try_import_singbox_uri(uri: str, save: bool = True) -> dict:
    """
    Попытка преобразовать URI в sing-box outbound и подмёрджить в
    конфиг 'imported-subscription'. Возвращает:
      {"handled": bool,             # пробовали ли мы вообще
       "item":    {...}}            # entry для result_items

    Если sing-box ещё не установлен / SingboxManager падает —
    handled=True, item с ошибкой (чтобы пользователь видел причину,
    а не «scheme не поддержан»).
    """
    try:
        from core.singbox_subscription import uri_to_outbound
    except Exception:
        return {"handled": False, "item": None}

    parsed = uri_to_outbound(uri)
    if not parsed.get("ok"):
        # uri_to_outbound возвращает 'не <scheme>-URI' для чужих схем —
        # это сигнал, что мы не отвечаем за этот URI.
        err = parsed.get("error", "")
        if err.startswith("не ") or "scheme" in err:
            return {"handled": False, "item": None}
        return {
            "handled": True,
            "item": {
                "type": uri.split("://", 1)[0].lower(),
                "ok": False, "error": err,
                "uri": _redact(uri),
            },
        }

    outbound = parsed["outbound"]
    tag      = parsed["tag"]
    scheme   = uri.split("://", 1)[0].lower()

    if not save:
        return {
            "handled": True,
            "item": {
                "type": scheme, "ok": True,
                "name": SINGBOX_IMPORT_CONFIG, "tag": tag,
                "outbound_type": outbound.get("type"),
                "saved": False,
            },
        }

    # Сейв через SingboxManager: подмёрджим outbound в существующий
    # 'imported-subscription' (или создадим новый).
    try:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import (
            parse_conf, render_conf, make_minimal_config,
        )
        mgr = get_singbox_manager()
    except Exception as e:
        return {
            "handled": True,
            "item": {
                "type": scheme, "ok": False,
                "error": "singbox-manager недоступен: %s" % e,
                "uri": _redact(uri),
            },
        }

    existing = mgr.get_config(SINGBOX_IMPORT_CONFIG)
    if existing.get("ok"):
        cfg = existing.get("parsed") or {}
    else:
        cfg = make_minimal_config(outbound_tag=tag)
        # Удаляем placeholder direct-outbound с тем же tag, что мы
        # хотим использовать — заменим на реальный.
        cfg["outbounds"] = [o for o in cfg.get("outbounds", [])
                            if not (o.get("type") == "direct"
                                    and o.get("tag") == tag)]

    obs = cfg.setdefault("outbounds", [])
    # Если outbound с таким же tag уже есть — заменяем, не дублируем.
    obs[:] = [o for o in obs if o.get("tag") != tag]
    obs.append(outbound)

    save_res = mgr.save_config(SINGBOX_IMPORT_CONFIG,
                               text=render_conf(cfg))
    saved = bool(save_res.get("ok"))
    item = {
        "type": scheme, "ok": saved,
        "name": SINGBOX_IMPORT_CONFIG, "tag": tag,
        "outbound_type": outbound.get("type"),
        "saved": saved,
    }
    if not saved:
        item["error"] = save_res.get("error", "save failed")
    return {"handled": True, "item": item}


def _import_conf_block(awg_mgr, conf_text: str, save: bool = True) -> dict:
    """Импорт сырого .conf-блока (или предпросмотр при save=False)."""
    # Сгенерим имя на основе первого валидного «# Name = ...» либо
    # дефолт.
    name = "imported"
    m = re.search(r"^\s*#\s*Name\s*=\s*(\S+)", conf_text or "",
                  re.MULTILINE)
    if m:
        name = _safe_conf_name(m.group(1))

    # Preview-режим: ничего не сохраняем, просто отчитываемся, что
    # блок распознался.
    if not save:
        return {"type": "conf", "ok": True, "name": name,
                "saved": False}

    if not awg_mgr:
        return {"type": "conf", "ok": False, "name": name,
                "error": "AwgManager недоступен"}

    try:
        res = awg_mgr.save_config(name=name, text=conf_text)
        if not res or not res.get("ok"):
            return {"type": "conf", "ok": False, "name": name,
                    "error": (res or {}).get("error", "save failed")}
        return {"type": "conf", "ok": True, "name": name, "saved": True}
    except Exception as e:
        return {"type": "conf", "ok": False, "name": name,
                "error": str(e)}


def _redact(uri: str) -> str:
    """Скрыть private_key/password в URI для логов и UI."""
    return re.sub(r"//[^@/]+@", "//***@", uri or "")
