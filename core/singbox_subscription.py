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
import re
import urllib.parse

from core.singbox_config import (
    make_vless_outbound, make_trojan_outbound,
    make_shadowsocks_outbound, make_hysteria2_outbound,
    make_tuic_outbound,
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


def _parse_query(qs: str) -> dict:
    """urlparse.parse_qs, но возвращает первую запись каждого ключа как str."""
    if not qs:
        return {}
    raw = urllib.parse.parse_qs(qs, keep_blank_values=True)
    return {k.lower(): urllib.parse.unquote(v[0])
            for k, v in raw.items() if v}


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

    flow = q.get("flow", "")

    # transport
    transport = None
    t_type = q.get("type", "tcp").lower()
    if t_type == "ws":
        transport = {"type": "ws",
                     "path": q.get("path") or "/"}
        host_hdr = q.get("host")
        if host_hdr:
            transport["headers"] = {"Host": host_hdr}
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
        tls = {
            "enabled":      True,
            "server_name":  sni,
            "reality": {
                "enabled":    True,
                "public_key": q.get("pbk", ""),
                "short_id":   q.get("sid", ""),
            },
        }
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
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
    if t_type == "ws":
        transport = {"type": "ws", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}

    sni = q.get("sni") or q.get("peer") or ""
    outbound = make_trojan_outbound(
        tag=tag, server=server, port=port, password=password,
        sni=sni, transport=transport)
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

        tag = _safe_tag(urllib.parse.unquote(frag or "")
                        or "ss-%s" % host)
        outbound = make_shadowsocks_outbound(
            tag=tag, server=host, port=port,
            method=method, password=password)
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
    insecure = q.get("insecure") in ("1", "true", "True")

    outbound = make_hysteria2_outbound(
        tag=tag, server=server, port=port, password=password,
        sni=sni, insecure=insecure)
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

    outbound = make_tuic_outbound(
        tag=tag, server=p.hostname, port=p.port,
        uuid=uuid, password=password, sni=sni)
    return {"ok": True, "tag": tag, "outbound": outbound}


# ─────── dispatcher ───────

_HANDLERS = {
    "vless":     vless_to_outbound,
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
