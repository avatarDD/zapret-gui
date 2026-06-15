# core/singbox_subscription.py
"""
Конвертация URI-строк подписки в sing-box outbound dict'ы.

Поддерживаемые схемы:
  - vless://       (Reality / TLS / WebSocket / gRPC)
  - trojan://
  - ss://          (Shadowsocks; формат cipher:password@host:port
                    и base64(cipher:password)@host:port)
  - hysteria2://   (он же hy2://)
  - tuic://

Расширяет существующий `core/subscription_importer.py` — там
уже есть `extract_items()` (он распознаёт схемы из mixed-текста)
и `wireguard_uri_to_conf()` (для WG). Здесь — sing-box-specific
ветка.

Все парсеры возвращают единый формат:
  {"ok": bool, "tag": str, "outbound": dict, "error": str?}

где `outbound` — готовый JSON-объект, подходящий для секции
`outbounds` в sing-box-конфиге.
"""

import base64
import json
import re
import urllib.parse

from core.singbox_config import (
    make_vless_outbound, make_vmess_outbound, make_trojan_outbound,
    make_shadowsocks_outbound, make_hysteria2_outbound,
    make_tuic_outbound, is_x25519_key, vless_flow_supported,
)


# ─────── helpers ───────

_TAG_SAFE_RE = re.compile(r"[^A-Za-z0-9_\-]+")


def _safe_tag(name: str, fallback: str = "out") -> str:
    """sing-box принимает любые tag-строки, но для UI красивее `[A-Za-z0-9_-]`."""
    name = (name or "").strip()
    if not name:
        return fallback
    cleaned = _TAG_SAFE_RE.sub("-", name).strip("-")
    return cleaned[:48] or fallback


# Транспорты, которых НЕТ в sing-box (специфичны для Xray). Сервер, требующий
# такой транспорт, sing-box обслужить не может — ссылку надо отбраковывать
# сразу (как unsupported flow), иначе она молча превратится в «голый TCP» и
# соединение не заведётся, засоряя пул «как бы рабочими» серверами.
_XRAY_ONLY_TRANSPORTS = {"xhttp", "splithttp"}


def _parse_query(qs: str) -> dict:
    """urlparse.parse_qs, но возвращает первую запись каждого ключа как str."""
    if not qs:
        return {}
    raw = urllib.parse.parse_qs(qs, keep_blank_values=True)
    out = {}
    for k, v in raw.items():
        if not v:
            continue
        key = k.lower()
        # Часть подписок HTML-экранирует разделители (`&` → `&amp;`), из-за
        # чего ключи приходят как `amp;udp_relay_mode`/`amp;alpn`. Снимаем
        # префикс, чтобы такие параметры не терялись (TUIC/Hysteria2 и т.п.).
        if key.startswith("amp;"):
            key = key[4:]
        out[key] = urllib.parse.unquote(v[0])
    return out


def _b64_decode_padded(s: str) -> str:
    """base64 (urlsafe или обычная), padding фиксируем сами."""
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad).decode("utf-8",
                                                      errors="replace")
    except (ValueError, base64.binascii.Error):
        return ""


# ─────── vless ───────

def vless_to_outbound(uri: str) -> dict:
    """
    Формат: `vless://<uuid>@<host>:<port>?<params>#<name>`.

    Часто встречающиеся params:
      type=ws|grpc|tcp                          # transport
      security=tls|reality|none
      sni=<server_name>
      fp=<utls-fingerprint>                     # chrome / firefox / ...
      pbk=<reality-public-key>                  # security=reality
      sid=<reality-short-id>
      flow=xtls-rprx-vision                     # для Reality
      path=/...                                  # для type=ws
      host=<ws-host-header>
      serviceName=<grpc-service>                # для type=grpc
    """
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError as e:
        return {"ok": False, "error": "URI не распарсился: %s" % e}
    if p.scheme.lower() != "vless":
        return {"ok": False, "error": "не vless-URI"}
    if not p.username:
        return {"ok": False, "error": "нет UUID в URI"}
    if not p.hostname or not p.port:
        return {"ok": False, "error": "нет host:port в URI"}

    uuid = urllib.parse.unquote(p.username)
    server, port = p.hostname, p.port
    q = _parse_query(p.query)
    tag = _safe_tag(urllib.parse.unquote(p.fragment or "")
                    or "vless-%s" % server)

    # sing-box принимает только flow='xtls-rprx-vision' (вариант
    # '…-udp443' нормализуется до него в make_vless_outbound). Легаси
    # xtls-flow (origin/direct/splice) роняет sing-box на старте
    # («unsupported flow») — отсекаем сразу, как reality без pbk.
    flow = q.get("flow", "")
    if not vless_flow_supported(flow):
        return {"ok": False,
                "error": "flow '%s' не поддерживается sing-box" % flow}

    # transport
    transport = None
    t_type = q.get("type", "tcp").lower()
    if t_type in _XRAY_ONLY_TRANSPORTS:
        return {"ok": False,
                "error": "transport '%s' не поддерживается sing-box "
                         "(Xray-only)" % t_type}
    if t_type == "ws":
        transport = {"type": "ws",
                     "path": q.get("path") or "/"}
        host_hdr = q.get("host")
        if host_hdr:
            transport["headers"] = {"Host": host_hdr}
    elif t_type == "httpupgrade":
        # sing-box-нативный транспорт (НЕ Xray xhttp). host — отдельное поле.
        transport = {"type": "httpupgrade", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["host"] = q.get("host")
    elif t_type == "grpc":
        transport = {"type": "grpc",
                     "service_name": q.get("servicename") or
                                     q.get("service") or ""}
    elif t_type == "http":
        transport = {"type": "http",
                     "host": [q.get("host", "")] if q.get("host") else None,
                     "path": q.get("path") or "/"}
        transport = {k: v for k, v in transport.items() if v}
    # type=tcp → без transport

    # TLS
    tls = None
    sec = q.get("security", "").lower()
    sni = q.get("sni") or q.get("host") or ""
    fp  = q.get("fp", "")
    if sec == "reality":
        # reality без валидного pbk (public_key сервера) бесполезен и
        # роняет sing-box на старте («invalid public_key»). Отсекаем сразу,
        # чтобы такой сервер не попал в пул и не сломал запуск/тест.
        pbk = (q.get("pbk") or "").strip()
        if not is_x25519_key(pbk):
            return {"ok": False,
                    "error": "reality-ссылка без валидного pbk (public_key)"}
        tls = {
            "enabled":      True,
            "server_name":  sni,
            "reality": {
                "enabled":    True,
                "public_key": pbk,
                "short_id":   q.get("sid", ""),
            },
            # sing-box ТРЕБУЕТ utls для reality-клиента
            # («uTLS is required by reality client»). Если в URI нет fp —
            # подставляем дефолтный chrome, иначе конфиг не проходит check.
            "utls": {"enabled": True, "fingerprint": fp or "chrome"},
        }
    elif sec == "tls":
        tls = {"enabled": True}
        if sni:
            tls["server_name"] = sni
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if q.get("alpn"):
            tls["alpn"] = [a for a in q["alpn"].split(",") if a]

    outbound = make_vless_outbound(
        tag=tag, server=server, port=port, uuid=uuid,
        flow=flow, transport=transport, tls=tls)
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── vmess ───────

def vmess_to_outbound(uri: str) -> dict:
    """
    Формат (v2rayN/большинство публичных подписок):
        vmess://<base64(JSON)>

    где JSON — объект с полями:
        ps   — имя (remark)              add  — server host
        port — порт                      id   — uuid
        aid  — alterId (обычно 0)        scy  — security/cipher ('auto')
        net  — transport: tcp|ws|grpc|h2 type — header type ('none')
        host — ws/http Host-заголовок    path — ws path / grpc serviceName
        tls  — 'tls' либо ''             sni  — server_name
        alpn — 'h2,http/1.1'             fp   — utls fingerprint

    Изредка vmess:// содержит «сырой» URI вида
    `vmess://<uuid>@host:port?...` (как vless) — такой формат публичными
    репозиториями почти не используется; здесь поддерживаем именно
    base64-JSON, как самый распространённый.
    """
    if not uri.lower().startswith("vmess://"):
        return {"ok": False, "error": "не vmess-URI"}

    payload = uri[len("vmess://"):].strip()
    # Отрезаем возможный #fragment до base64-декода.
    if "#" in payload:
        payload = payload.split("#", 1)[0]
    decoded = _b64_decode_padded(payload)
    if not decoded:
        return {"ok": False, "error": "vmess: base64 не декодируется"}

    try:
        data = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        return {"ok": False, "error": "vmess: payload не JSON"}
    if not isinstance(data, dict):
        return {"ok": False, "error": "vmess: JSON не объект"}

    def _s(key: str, default: str = "") -> str:
        v = data.get(key, default)
        return str(v).strip() if v is not None else default

    server = _s("add")
    port_s = _s("port")
    uuid = _s("id")
    if not server or not port_s or not uuid:
        return {"ok": False, "error": "vmess: нет add/port/id"}
    try:
        port = int(port_s)
    except ValueError:
        return {"ok": False, "error": "vmess: порт не число"}

    tag = _safe_tag(_s("ps") or "vmess-%s" % server)
    security = _s("scy") or "auto"
    try:
        alter_id = int(_s("aid") or 0)
    except ValueError:
        alter_id = 0

    # transport
    net = (_s("net") or "tcp").lower()
    host_hdr = _s("host")
    path = _s("path")
    transport = None
    if net in _XRAY_ONLY_TRANSPORTS:
        return {"ok": False,
                "error": "transport '%s' не поддерживается sing-box "
                         "(Xray-only)" % net}
    if net == "ws":
        transport = {"type": "ws", "path": path or "/"}
        if host_hdr:
            transport["headers"] = {"Host": host_hdr}
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path or "/"}
        if host_hdr:
            transport["host"] = host_hdr
    elif net == "grpc":
        transport = {"type": "grpc", "service_name": path or ""}
    elif net in ("h2", "http"):
        transport = {"type": "http", "path": path or "/"}
        if host_hdr:
            transport["host"] = [h for h in host_hdr.split(",") if h]

    # TLS
    tls = None
    if _s("tls").lower() in ("tls", "reality", "1", "true"):
        tls = {"enabled": True}
        sni = _s("sni") or host_hdr
        if sni:
            tls["server_name"] = sni
        fp = _s("fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = _s("alpn")
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        # self-signed: некоторые ссылки несут флаг пропуска проверки TLS
        # (ключ в JSON в разном регистре/написании).
        low = {str(k).lower(): v for k, v in data.items()}
        ins = low.get("allowinsecure") or low.get("skip-cert-verify")
        if str(ins).strip().lower() in ("1", "true", "yes"):
            tls["insecure"] = True

    outbound = make_vmess_outbound(
        tag=tag, server=server, port=port, uuid=uuid,
        security=security, alter_id=alter_id,
        transport=transport, tls=tls)
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── trojan ───────

def trojan_to_outbound(uri: str) -> dict:
    """`trojan://<password>@<host>:<port>?<params>#<name>`."""
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError as e:
        return {"ok": False, "error": "URI не распарсился: %s" % e}
    if p.scheme.lower() != "trojan":
        return {"ok": False, "error": "не trojan-URI"}
    if not p.username:
        return {"ok": False, "error": "нет password в URI"}
    if not p.hostname or not p.port:
        return {"ok": False, "error": "нет host:port в URI"}

    password = urllib.parse.unquote(p.username)
    server, port = p.hostname, p.port
    q = _parse_query(p.query)
    tag = _safe_tag(urllib.parse.unquote(p.fragment or "")
                    or "trojan-%s" % server)

    transport = None
    t_type = q.get("type", "tcp").lower()
    if t_type in _XRAY_ONLY_TRANSPORTS:
        return {"ok": False,
                "error": "transport '%s' не поддерживается sing-box "
                         "(Xray-only)" % t_type}
    if t_type == "ws":
        transport = {"type": "ws", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}
    elif t_type == "httpupgrade":
        transport = {"type": "httpupgrade", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["host"] = q["host"]
    elif t_type == "grpc":
        transport = {"type": "grpc",
                     "service_name": q.get("servicename") or
                                     q.get("service") or ""}
    elif (q.get("ws") or "").strip() in ("1", "true"):
        # Trojan-Go-диалект: ws=1&wspath=/path вместо type=ws&path=.
        transport = {"type": "ws",
                     "path": q.get("wspath") or q.get("path") or "/"}
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}

    sni = q.get("sni") or q.get("peer") or ""
    # allowInsecure=1 / insecure=1 — self-signed сертификат: без пропуска
    # проверки TLS-рукопожатие к таким серверам падает. fp/alpn — uTLS-маскировка
    # и согласование ALPN (как у vless).
    insecure = (q.get("allowinsecure") or q.get("insecure")
                or "").strip().lower() in ("1", "true", "yes", "on")
    fp = q.get("fp", "")
    alpn = [a for a in (q.get("alpn") or "").split(",") if a]
    outbound = make_trojan_outbound(
        tag=tag, server=server, port=port, password=password,
        sni=sni, insecure=insecure, alpn=alpn, fp=fp, transport=transport)
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── shadowsocks ───────

def ss_to_outbound(uri: str) -> dict:
    """
    Два формата:
      ss://<base64(method:password)>@<host>:<port>#<name>
      ss://<method>:<password>@<host>:<port>#<name>     (urlencoded)
    """
    try:
        # URL-парсер не любит '@' внутри base64; разделим вручную.
        if not uri.lower().startswith("ss://"):
            return {"ok": False, "error": "не ss-URI"}
        rest = uri[5:]
        frag = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        query = ""
        if "?" in rest:
            rest, query = rest.split("?", 1)
        if "@" not in rest:
            # Старый формат: base64 целиком, потом #name
            try:
                decoded = _b64_decode_padded(rest)
            except Exception:
                decoded = ""
            if "@" not in decoded:
                return {"ok": False,
                        "error": "не получилось распарсить ss-URI"}
            rest = decoded
        userinfo, _, hostport = rest.rpartition("@")
        if not hostport or ":" not in hostport:
            return {"ok": False, "error": "нет host:port"}
        # userinfo может быть либо method:password, либо
        # base64(method:password)
        if ":" not in userinfo:
            userinfo = _b64_decode_padded(userinfo)
        if ":" not in userinfo:
            return {"ok": False, "error": "не разобрался с method:password"}
        method, _, password = userinfo.partition(":")
        host, _, port_s = hostport.partition(":")
        try:
            port = int(port_s)
        except ValueError:
            return {"ok": False, "error": "порт не число"}

        # sing-box принимает только AEAD/2022-шифры; легаси (aes-256-cfb,
        # chacha20-poly1305 без -ietf- и т.п.) — отбрасываем/нормализуем,
        # иначе sing-box падает «unknown method».
        from core.singbox_config import normalize_ss_method
        norm = normalize_ss_method(method)
        if not norm:
            return {"ok": False,
                    "error": "ss: метод '%s' не поддерживается sing-box"
                             % method}
        method = norm

        # SIP003-плагин: ss://...@host:port?plugin=<name>;<opts>. Без него
        # сервер с обфускацией не открывается (TCP есть, прокси нет).
        plugin, plugin_opts = "", ""
        if query:
            raw_plugin = _parse_query(query).get("plugin") or ""
            if raw_plugin:
                name, _, opts = raw_plugin.partition(";")
                plugin, plugin_opts = name.strip(), opts.strip()
                if plugin == "simple-obfs":      # алиас → имя sing-box
                    plugin = "obfs-local"
                supported = {"obfs-local", "v2ray-plugin", "shadow-tls"}
                if plugin not in supported:
                    return {"ok": False,
                            "error": "ss plugin '%s' не поддерживается "
                                     "sing-box" % plugin}

        tag = _safe_tag(urllib.parse.unquote(frag or "")
                        or "ss-%s" % host)
        outbound = make_shadowsocks_outbound(
            tag=tag, server=host, port=port,
            method=method, password=password,
            plugin=plugin, plugin_opts=plugin_opts)
        return {"ok": True, "tag": tag, "outbound": outbound}
    except Exception as e:
        return {"ok": False, "error": "ss parse: %s" % e}


# ─────── hysteria2 ───────

def hysteria2_to_outbound(uri: str) -> dict:
    """
    `hysteria2://<password>@<host>:<port>?<params>#<name>` либо
    `hy2://<password>@<host>:<port>?<params>#<name>`.
    """
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError as e:
        return {"ok": False, "error": "URI не распарсился: %s" % e}
    if p.scheme.lower() not in ("hysteria2", "hy2"):
        return {"ok": False, "error": "не hysteria2-URI"}
    if not p.username:
        return {"ok": False, "error": "нет password в URI"}
    if not p.hostname or not p.port:
        return {"ok": False, "error": "нет host:port"}

    password = urllib.parse.unquote(p.username)
    server, port = p.hostname, p.port
    q = _parse_query(p.query)
    tag = _safe_tag(urllib.parse.unquote(p.fragment or "")
                    or "hy2-%s" % server)
    sni = q.get("sni") or ""
    # Нормализуем регистр: insecure=TRUE/Yes/1 тоже должны включать
    # пропуск проверки TLS, иначе outbound к серверу с self-signed не
    # поднимется (handshake падает).
    insecure = (q.get("insecure") or "").strip().lower() in (
        "1", "true", "yes", "on")

    # Salamander-обфускация: без obfs-пароля сервер с obfs не отвечает.
    obfs_type = (q.get("obfs") or "").strip().lower()
    obfs_pw = q.get("obfs-password") or q.get("obfs_password") or ""
    if obfs_type and obfs_type != "salamander":
        return {"ok": False,
                "error": "hysteria2 obfs '%s' не поддерживается sing-box "
                         "(только salamander)" % obfs_type}

    outbound = make_hysteria2_outbound(
        tag=tag, server=server, port=port, password=password,
        sni=sni, insecure=insecure,
        obfs_password=obfs_pw, obfs_type=obfs_type or "salamander")
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── tuic ───────

def tuic_to_outbound(uri: str) -> dict:
    """`tuic://<uuid>:<password>@<host>:<port>?<params>#<name>`."""
    try:
        p = urllib.parse.urlparse(uri)
    except ValueError as e:
        return {"ok": False, "error": "URI не распарсился: %s" % e}
    if p.scheme.lower() != "tuic":
        return {"ok": False, "error": "не tuic-URI"}
    if not p.hostname or not p.port:
        return {"ok": False, "error": "нет host:port"}

    # username:password может прийти двумя путями:
    #  - urlparse уже их разделил → p.username + p.password;
    #  - либо пришло целиком в p.username (если в URI был только ':').
    uuid = urllib.parse.unquote(p.username or "")
    password = urllib.parse.unquote(p.password or "")
    if not password and ":" in uuid:
        # Корнер-кейс: 'uuid:pwd' попал целиком в username
        uuid, _, password = uuid.partition(":")
    if not uuid:
        return {"ok": False, "error": "нет UUID"}

    q = _parse_query(p.query)
    tag = _safe_tag(urllib.parse.unquote(p.fragment or "")
                    or "tuic-%s" % p.hostname)
    sni = q.get("sni") or ""
    alpn = [a for a in (q.get("alpn") or "").split(",") if a]
    insecure = (q.get("allow_insecure") or q.get("insecure")
                or "").strip().lower() in ("1", "true", "yes", "on")
    cc = (q.get("congestion_control") or q.get("congestion") or "").strip()
    urm = (q.get("udp_relay_mode") or "").strip()

    outbound = make_tuic_outbound(
        tag=tag, server=p.hostname, port=p.port,
        uuid=uuid, password=password, sni=sni, alpn=alpn,
        insecure=insecure, congestion_control=cc, udp_relay_mode=urm)
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── dispatcher ───────

_HANDLERS = {
    "vless":     vless_to_outbound,
    "vmess":     vmess_to_outbound,
    "trojan":    trojan_to_outbound,
    "ss":        ss_to_outbound,
    "hysteria2": hysteria2_to_outbound,
    "hy2":       hysteria2_to_outbound,
    "tuic":      tuic_to_outbound,
}


def uri_to_outbound(uri: str) -> dict:
    """
    Высокоуровневая точка входа. По схеме URI выбирает handler.
    Возвращает {"ok": bool, "tag": str, "outbound": dict, ...}.
    """
    if not uri or "://" not in uri:
        return {"ok": False, "error": "Не URI"}
    scheme = uri.split("://", 1)[0].lower()
    h = _HANDLERS.get(scheme)
    if not h:
        return {"ok": False, "error":
                "scheme '%s' не поддержан" % scheme}
    return h(uri)


# ═══════════════════════════════════════════════════════════════
# Обратное направление: outbound dict → share-URI.
#
# Нужно для «копирования» серверов из таблицы прокси в буфер обмена
# (как Throne `ExportToLink`): пользователь выделяет строки, жмёт
# Ctrl+C — получает `vless://…`/`ss://…`-ссылки, которые можно
# вставить в любой клиент. Это зеркало `uri_to_outbound` — поэтому
# `uri_to_outbound(outbound_to_uri(ob))` должно давать эквивалентный
# outbound (round-trip по ключевым полям).
# ═══════════════════════════════════════════════════════════════

def _fmt_hostport(server: str, port) -> str:
    """`host:port`, с обёрткой IPv6-литерала в квадратные скобки."""
    s = str(server or "")
    if ":" in s and not s.startswith("["):
        s = "[%s]" % s
    return "%s:%s" % (s, int(port))


def _q(value: str) -> str:
    """urlencode одного значения (для userinfo/path и т.п.)."""
    return urllib.parse.quote(str(value or ""), safe="")


def _build_query(params: dict) -> str:
    """Query-строка из непустых параметров (стабильный порядок вставки)."""
    items = [(k, v) for k, v in params.items()
             if v not in (None, "", [], {})]
    if not items:
        return ""
    return urllib.parse.urlencode(items, quote_via=urllib.parse.quote)


def _frag(tag: str) -> str:
    return urllib.parse.quote(str(tag or ""), safe="")


def _transport_params(tr: dict) -> dict:
    """Общие transport-параметры для vless/trojan (type/path/host/serviceName)."""
    out = {}
    if not isinstance(tr, dict) or not tr.get("type"):
        return out
    t_type = tr.get("type")
    out["type"] = t_type
    if t_type == "ws":
        if tr.get("path"):
            out["path"] = tr["path"]
        host = (tr.get("headers") or {}).get("Host")
        if host:
            out["host"] = host
    elif t_type == "grpc":
        if tr.get("service_name"):
            out["serviceName"] = tr["service_name"]
    elif t_type == "httpupgrade":
        if tr.get("path"):
            out["path"] = tr["path"]
        if tr.get("host"):
            out["host"] = tr["host"]
    elif t_type in ("http", "h2"):
        if tr.get("path"):
            out["path"] = tr["path"]
        h = tr.get("host")
        if isinstance(h, list) and h:
            out["host"] = h[0]
        elif isinstance(h, str) and h:
            out["host"] = h
    return out


def _vless_to_uri(ob: dict) -> str:
    server, port, uuid = ob.get("server"), ob.get("server_port"), ob.get("uuid")
    if not (server and port and uuid):
        return ""
    params = _transport_params(ob.get("transport") or {})
    params.setdefault("type", "tcp")

    tls = ob.get("tls") or {}
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        params["security"] = "reality"
        if reality.get("public_key"):
            params["pbk"] = reality["public_key"]
        if reality.get("short_id"):
            params["sid"] = reality["short_id"]
    elif tls.get("enabled"):
        params["security"] = "tls"
    else:
        params["security"] = "none"
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        params["fp"] = fp
    alpn = tls.get("alpn")
    if alpn:
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else alpn
    if ob.get("flow"):
        params["flow"] = ob["flow"]

    return "vless://%s@%s?%s#%s" % (
        _q(uuid), _fmt_hostport(server, port),
        _build_query(params), _frag(ob.get("tag")))


def _vmess_to_uri(ob: dict) -> str:
    server, port, uuid = ob.get("server"), ob.get("server_port"), ob.get("uuid")
    if not (server and port and uuid):
        return ""
    tr = ob.get("transport") or {}
    net = (tr.get("type") or "tcp").lower()
    host, path = "", ""
    if net == "ws":
        path = tr.get("path") or ""
        host = (tr.get("headers") or {}).get("Host") or ""
    elif net == "grpc":
        path = tr.get("service_name") or ""
    elif net in ("http", "h2"):
        net = "h2"
        path = tr.get("path") or ""
        h = tr.get("host")
        host = (h[0] if isinstance(h, list) and h else (h or "")) or ""

    tls = ob.get("tls") or {}
    data = {
        "v": "2", "ps": ob.get("tag") or "", "add": str(server),
        "port": str(int(port)), "id": str(uuid),
        "aid": str(ob.get("alter_id") or 0),
        "scy": ob.get("security") or "auto",
        "net": net, "type": "none", "host": host, "path": path,
        "tls": "tls" if tls.get("enabled") else "",
    }
    if tls.get("server_name"):
        data["sni"] = tls["server_name"]
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        data["fp"] = fp
    raw = base64.b64encode(
        json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return "vmess://" + raw


def _trojan_to_uri(ob: dict) -> str:
    server, port, pwd = ob.get("server"), ob.get("server_port"), ob.get("password")
    if not (server and port and pwd):
        return ""
    params = _transport_params(ob.get("transport") or {})
    tls = ob.get("tls") or {}
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    if tls.get("insecure"):
        params["allowInsecure"] = "1"
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        params["fp"] = fp
    if tls.get("alpn"):
        params["alpn"] = ",".join(tls["alpn"]) if isinstance(
            tls["alpn"], list) else tls["alpn"]
    return "trojan://%s@%s?%s#%s" % (
        _q(pwd), _fmt_hostport(server, port),
        _build_query(params), _frag(ob.get("tag")))


def _ss_to_uri(ob: dict) -> str:
    server, port = ob.get("server"), ob.get("server_port")
    method, pwd = ob.get("method"), ob.get("password")
    if not (server and port and method):
        return ""
    # SIP002: ss://base64(method:password)@host:port[?plugin=...]#tag
    userinfo = base64.b64encode(
        ("%s:%s" % (method, pwd or "")).encode("utf-8")).decode("ascii").rstrip("=")
    query = ""
    if ob.get("plugin"):
        pv = ob["plugin"]
        if ob.get("plugin_opts"):
            pv = "%s;%s" % (pv, ob["plugin_opts"])
        query = "?" + _build_query({"plugin": pv})
    return "ss://%s@%s%s#%s" % (
        userinfo, _fmt_hostport(server, port), query, _frag(ob.get("tag")))


def _hysteria2_to_uri(ob: dict) -> str:
    server, port, pwd = ob.get("server"), ob.get("server_port"), ob.get("password")
    if not (server and port and pwd):
        return ""
    tls = ob.get("tls") or {}
    params = {}
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    if tls.get("insecure"):
        params["insecure"] = "1"
    obfs = ob.get("obfs") or {}
    if obfs.get("password"):
        params["obfs"] = obfs.get("type") or "salamander"
        params["obfs-password"] = obfs["password"]
    return "hysteria2://%s@%s?%s#%s" % (
        _q(pwd), _fmt_hostport(server, port),
        _build_query(params), _frag(ob.get("tag")))


def _tuic_to_uri(ob: dict) -> str:
    server, port, uuid = ob.get("server"), ob.get("server_port"), ob.get("uuid")
    if not (server and port and uuid):
        return ""
    tls = ob.get("tls") or {}
    params = {}
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    if tls.get("insecure"):
        params["allow_insecure"] = "1"
    if tls.get("alpn"):
        params["alpn"] = ",".join(tls["alpn"]) if isinstance(
            tls["alpn"], list) else tls["alpn"]
    if ob.get("congestion_control"):
        params["congestion_control"] = ob["congestion_control"]
    if ob.get("udp_relay_mode"):
        params["udp_relay_mode"] = ob["udp_relay_mode"]
    userinfo = "%s:%s" % (_q(uuid), _q(ob.get("password") or ""))
    return "tuic://%s@%s?%s#%s" % (
        userinfo, _fmt_hostport(server, port),
        _build_query(params), _frag(ob.get("tag")))


_EXPORTERS = {
    "vless":       _vless_to_uri,
    "vmess":       _vmess_to_uri,
    "trojan":      _trojan_to_uri,
    "shadowsocks": _ss_to_uri,
    "hysteria2":   _hysteria2_to_uri,
    "tuic":        _tuic_to_uri,
}


def outbound_to_uri(ob: dict) -> str:
    """
    Конвертировать sing-box outbound dict в share-URI. Для служебных
    (direct/block/dns/selector/urltest) и неподдерживаемых типов
    возвращает "" (вызывающий код их отфильтрует).
    """
    if not isinstance(ob, dict):
        return ""
    fn = _EXPORTERS.get(ob.get("type"))
    if not fn:
        return ""
    try:
        return fn(ob) or ""
    except Exception:
        return ""


def outbounds_to_links(outbounds: list) -> list:
    """Список outbound'ов → список непустых share-ссылок (для копирования)."""
    links = []
    for ob in (outbounds or []):
        uri = outbound_to_uri(ob)
        if uri:
            links.append(uri)
    return links
