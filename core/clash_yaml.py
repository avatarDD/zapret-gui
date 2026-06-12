# core/clash_yaml.py
"""
Парсер clash/mihomo YAML-подписок → sing-box outbound dict'ы.

Формат clash-YAML (упрощённый, без всей семантики clash):

    proxies:
      - name: "MyVPN-1"
        type: vless
        server: vpn.example.com
        port: 443
        uuid: <uuid>
        network: tcp
        tls: true
        servername: cf.com
        reality-opts:
          public-key: <pbk>
          short-id: 01
        client-fingerprint: chrome
      - name: "Trojan-2"
        type: trojan
        server: ...
        port: ...
        password: ...
        sni: ...
      - name: "SS-3"
        type: ss
        server: ...
        port: ...
        cipher: aes-128-gcm
        password: ...

Поддерживаемые типы: ss, vless, vmess (через прокси-конвертацию в
vless с UUID — vmess в sing-box тоже есть, но синтаксис маппится
напрямую), trojan, hysteria2, tuic.

Зависимости: пробуем `pyyaml` (если установлен), иначе минимальный
самописный парсер для типичных clash-payload'ов. Это означает, что
сложные многострочные литералы / якоря YAML могут не разобраться —
для них пользователю придётся пользоваться сырой sing-box-JSON
подпиской или плоским text-URI-листом.
"""

import re
from typing import Any


# ─────── YAML loader ───────

def _try_pyyaml(text: str):
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return None
    except Exception as e:
        raise ValueError("YAML: %s" % e)


def _fallback_yaml_parser(text: str):
    """
    Минимальный парсер clash-стиля YAML. Не претендует на
    полноту — только то, что используют типичные подписки:
      - корневой dict (key: value)
      - вложенный list-of-dicts через 'key:\\n  - name: ...\\n    type: ...'
      - простые scalar'ы (string / int / bool)
      - вложенные dict'ы один уровень (`reality-opts:\\n      public-key: ...`)

    Возвращает dict; на синтаксической нелепице кидает ValueError.
    """
    lines = text.splitlines()
    root = {}

    # Курсор: где мы сейчас сидим (для tracking вложенных list/dict)
    state = {
        "current_list_key": None,   # имя ключа, под которым идёт список
        "current_list":     None,
        "current_item":     None,
        "current_item_indent": -1,
        "current_subdict_key": None,
        "current_subdict":     None,
        "current_subdict_indent": -1,
    }

    def flush_item():
        if state["current_item"] is not None:
            state["current_list"].append(state["current_item"])
            state["current_item"] = None
            state["current_item_indent"] = -1
        state["current_subdict_key"] = None
        state["current_subdict"]     = None
        state["current_subdict_indent"] = -1

    for raw in lines:
        # Срезаем `#`-комментарии (но не внутри значения — упрощаем)
        line_no_comment = re.sub(r"\s+#.*$", "", raw)
        if not line_no_comment.strip():
            continue

        indent = len(line_no_comment) - len(line_no_comment.lstrip(" "))
        stripped = line_no_comment.strip()

        # Корневой ключ:
        #   key:                  → начало вложенной структуры
        #   key: value            → скаляр
        if indent == 0 and not stripped.startswith("-"):
            flush_item()
            state["current_list_key"] = None
            state["current_list"]     = None
            m = re.match(r"^([\w\-]+)\s*:\s*(.*)$", stripped)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            if val == "":
                # Возможно следующий блок — list или dict.
                # Подготовим контейнер «либо list, либо dict» —
                # решим по первому inner-элементу.
                root[key] = None
                state["current_list_key"] = key
            else:
                root[key] = _parse_scalar(val)
            continue

        # Элемент списка: `  - <key>: <value>` либо `  - <value>`
        if stripped.startswith("- "):
            inner = stripped[2:].strip()
            if state["current_list_key"] is None:
                # Список вне корневого ключа — игнорируем
                continue
            if root.get(state["current_list_key"]) is None:
                root[state["current_list_key"]] = []
                state["current_list"] = root[state["current_list_key"]]
            # Закрываем предыдущий item
            flush_item()
            state["current_item"] = {}
            state["current_item_indent"] = indent
            # Если inner — это `key: value`, тут же и кладём.
            m = re.match(r"^([\w\-]+)\s*:\s*(.*)$", inner)
            if m:
                k, v = m.group(1), m.group(2)
                if v == "":
                    # Подготовим вложенный sub-dict (например reality-opts:)
                    state["current_item"][k] = {}
                    state["current_subdict_key"] = k
                    state["current_subdict"]    = state["current_item"][k]
                    state["current_subdict_indent"] = indent + 2
                else:
                    state["current_item"][k] = _parse_scalar(v)
            else:
                # Скалярный list element (редко в clash) — пока скипаем
                pass
            continue

        # Поле внутри текущего item'а: `    key: value` или вложенный dict
        if state["current_item"] is not None and indent > state["current_item_indent"]:
            m = re.match(r"^([\w\-]+)\s*:\s*(.*)$", stripped)
            if not m:
                continue
            k, v = m.group(1), m.group(2)

            # Если мы внутри sub-dict (reality-opts → public-key, short-id):
            if (state["current_subdict"] is not None
                    and indent >= state["current_subdict_indent"]):
                if v == "":
                    # Вложенность глубже одного уровня — не поддерживаем.
                    state["current_subdict"][k] = {}
                else:
                    state["current_subdict"][k] = _parse_scalar(v)
                continue

            # Выход из sub-dict (отступ меньше → закрываем его)
            if (state["current_subdict"] is not None
                    and indent < state["current_subdict_indent"]):
                state["current_subdict_key"] = None
                state["current_subdict"]     = None
                state["current_subdict_indent"] = -1

            if v == "":
                # Вложенный dict у item'а (например reality-opts:)
                state["current_item"][k] = {}
                state["current_subdict_key"] = k
                state["current_subdict"]    = state["current_item"][k]
                state["current_subdict_indent"] = indent + 2
            else:
                state["current_item"][k] = _parse_scalar(v)
            continue

    # Финальный flush
    flush_item()
    return root


def _parse_scalar(s: str):
    """Превратить YAML-скаляр в Python-значение."""
    s = s.strip()
    if not s:
        return ""
    # Quoted strings
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    # Bool
    if s.lower() in ("true", "yes", "on"):
        return True
    if s.lower() in ("false", "no", "off"):
        return False
    if s.lower() == "null":
        return None
    # Int / float
    if re.match(r"^-?\d+$", s):
        try:
            return int(s)
        except ValueError:
            return s
    if re.match(r"^-?\d+\.\d+$", s):
        try:
            return float(s)
        except ValueError:
            return s
    return s


def parse_yaml(text: str) -> dict:
    """
    Высокоуровневая обёртка: пытается pyyaml, иначе fallback.
    Возвращает dict (или пустой dict, если контент пустой/не словарь).
    """
    if not text or not text.strip():
        return {}
    data = _try_pyyaml(text)
    if data is None:
        data = _fallback_yaml_parser(text)
    if not isinstance(data, dict):
        return {}
    return data


# ─────── clash-proxies → sing-box outbounds ───────

def parse_clash_yaml(text: str) -> dict:
    """
    Развернуть clash-YAML подписку в список sing-box outbound'ов.

    Возвращает:
      {
        "ok": bool,
        "outbounds": [<sing-box outbound>, ...],
        "skipped": [{"name": str, "type": str, "reason": str}],
        "error": str?
      }
    """
    try:
        data = parse_yaml(text)
    except ValueError as e:
        return {"ok": False, "outbounds": [], "skipped": [],
                "error": str(e)}

    proxies = data.get("proxies")
    if proxies is None:
        return {"ok": False, "outbounds": [], "skipped": [],
                "error": "В YAML отсутствует секция 'proxies'"}
    if not isinstance(proxies, list):
        return {"ok": False, "outbounds": [], "skipped": [],
                "error": "Секция 'proxies' не массив"}

    outbounds = []
    skipped   = []
    seen_tags = set()

    for p in proxies:
        if not isinstance(p, dict):
            skipped.append({"name": "?", "type": "?", "reason": "не dict"})
            continue
        t = str(p.get("type", "")).lower()
        name = str(p.get("name", "")).strip() or "%s-out" % t
        converter = _CLASH_CONVERTERS.get(t)
        if not converter:
            skipped.append({"name": name, "type": t,
                            "reason": "неподдерживаемый тип"})
            continue
        try:
            ob = converter(p)
            if not ob:
                skipped.append({"name": name, "type": t,
                                "reason": "конвертер вернул пусто"})
                continue
            tag = ob.get("tag") or name
            # Дедуп тэгов
            base = tag
            i = 2
            while tag in seen_tags:
                tag = "%s-%d" % (base, i)
                i += 1
            ob["tag"] = tag
            seen_tags.add(tag)
            outbounds.append(ob)
        except Exception as e:
            skipped.append({"name": name, "type": t,
                            "reason": "конвертация: %s" % e})

    return {"ok": True, "outbounds": outbounds, "skipped": skipped}


# ─────── converters ───────
#
# Каждый берёт clash-proxy dict, возвращает sing-box outbound dict
# (или None если в данных нет нужных полей).

def _safe_tag(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_\-]+", "-", name or "").strip("-")
    return (s or "out")[:48]


def _conv_ss(p: dict):
    if not p.get("server") or not p.get("port"):
        return None
    from core.singbox_config import normalize_ss_method
    raw = str(p.get("cipher") or p.get("method") or "aes-128-gcm")
    method = normalize_ss_method(raw)
    if not method:
        # Легаси stream-шифр, не поддержан sing-box — пропускаем сервер.
        return None
    return {
        "type":        "shadowsocks",
        "tag":         _safe_tag(p.get("name", "ss")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "method":      method,
        "password":    str(p.get("password") or ""),
    }


def _conv_vless(p: dict):
    if not p.get("server") or not p.get("port"):
        return None
    from core.singbox_config import normalize_vless_flow, vless_flow_supported
    if not vless_flow_supported(p.get("flow")):
        # Легаси xtls-flow (origin/direct/splice), sing-box такой outbound
        # не примет («unsupported flow») — пропускаем сервер.
        return None
    ob: dict[str, Any] = {
        "type":        "vless",
        "tag":         _safe_tag(p.get("name", "vless")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "uuid":        str(p.get("uuid") or ""),
    }
    flow = normalize_vless_flow(p.get("flow"))
    if flow:
        ob["flow"] = flow

    # network/transport
    net = str(p.get("network") or "tcp").lower()
    if net == "ws":
        ws = p.get("ws-opts") or {}
        tr: dict[str, Any] = {"type": "ws"}
        if isinstance(ws, dict):
            if ws.get("path"):
                tr["path"] = str(ws["path"])
            headers = ws.get("headers") or {}
            if isinstance(headers, dict) and headers.get("Host"):
                tr["headers"] = {"Host": str(headers["Host"])}
        ob["transport"] = tr
    elif net == "grpc":
        grpc = p.get("grpc-opts") or {}
        ob["transport"] = {
            "type": "grpc",
            "service_name": str(grpc.get("grpc-service-name") or
                                 grpc.get("service-name") or "")
                            if isinstance(grpc, dict) else "",
        }

    # TLS
    tls_enabled = bool(p.get("tls") or p.get("security") == "tls" or
                       p.get("security") == "reality")
    if tls_enabled:
        tls_obj: dict[str, Any] = {"enabled": True}
        sni = p.get("servername") or p.get("sni")
        if sni:
            tls_obj["server_name"] = str(sni)
        fp = p.get("client-fingerprint")
        if fp:
            tls_obj["utls"] = {"enabled": True, "fingerprint": str(fp)}
        reality = p.get("reality-opts")
        if isinstance(reality, dict):
            sid = reality.get("short-id")
            # YAML без кавычек '01' приходит как int 1 — теряем leading
            # zero. В реальных подписках hex-shortID лучше всегда
            # оборачивать в кавычки. Мы здесь делаем best-effort.
            tls_obj["reality"] = {
                "enabled":    True,
                "public_key": str(reality.get("public-key") or ""),
                "short_id":   "" if sid is None else str(sid),
            }
            # sing-box требует utls для reality — если client-fingerprint
            # не задан, ставим дефолтный chrome (иначе `sing-box check`
            # падает: «uTLS is required by reality client»).
            if "utls" not in tls_obj:
                tls_obj["utls"] = {"enabled": True, "fingerprint": "chrome"}
        ob["tls"] = tls_obj
    return ob


def _conv_trojan(p: dict):
    if not p.get("server") or not p.get("port"):
        return None
    ob = {
        "type":        "trojan",
        "tag":         _safe_tag(p.get("name", "trojan")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "password":    str(p.get("password") or ""),
        "tls":         {"enabled": True},
    }
    sni = p.get("sni") or p.get("servername")
    if sni:
        ob["tls"]["server_name"] = str(sni)
    if p.get("skip-cert-verify"):
        ob["tls"]["insecure"] = True
    net = str(p.get("network") or "tcp").lower()
    if net == "ws":
        ws = p.get("ws-opts") or {}
        tr: dict[str, Any] = {"type": "ws"}
        if isinstance(ws, dict) and ws.get("path"):
            tr["path"] = str(ws["path"])
        ob["transport"] = tr
    return ob


def _conv_hysteria2(p: dict):
    if not p.get("server") or not p.get("port"):
        return None
    ob = {
        "type":        "hysteria2",
        "tag":         _safe_tag(p.get("name", "hy2")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "password":    str(p.get("password") or p.get("auth") or ""),
        "tls":         {"enabled": True},
    }
    sni = p.get("sni") or p.get("servername")
    if sni:
        ob["tls"]["server_name"] = str(sni)
    if p.get("skip-cert-verify"):
        ob["tls"]["insecure"] = True
    return ob


def _conv_tuic(p: dict):
    if not p.get("server") or not p.get("port"):
        return None
    ob = {
        "type":        "tuic",
        "tag":         _safe_tag(p.get("name", "tuic")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "uuid":        str(p.get("uuid") or ""),
        "tls":         {"enabled": True},
    }
    pwd = p.get("password")
    if pwd:
        ob["password"] = str(pwd)
    sni = p.get("sni") or p.get("servername")
    if sni:
        ob["tls"]["server_name"] = str(sni)
    return ob


def _conv_vmess(p: dict):
    """
    VMess: sing-box поддерживает напрямую. Маппим стандартные
    clash-поля → sing-box.
    """
    if not p.get("server") or not p.get("port"):
        return None
    ob: dict[str, Any] = {
        "type":        "vmess",
        "tag":         _safe_tag(p.get("name", "vmess")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "uuid":        str(p.get("uuid") or ""),
        "security":    str(p.get("cipher") or "auto"),
        "alter_id":    int(p.get("alterId", 0) or 0),
    }
    net = str(p.get("network") or "tcp").lower()
    if net == "ws":
        ws = p.get("ws-opts") or {}
        tr: dict[str, Any] = {"type": "ws"}
        if isinstance(ws, dict):
            if ws.get("path"):
                tr["path"] = str(ws["path"])
            headers = ws.get("headers") or {}
            if isinstance(headers, dict) and headers.get("Host"):
                tr["headers"] = {"Host": str(headers["Host"])}
        ob["transport"] = tr
    if p.get("tls"):
        tls_obj: dict[str, Any] = {"enabled": True}
        sni = p.get("servername") or p.get("sni")
        if sni:
            tls_obj["server_name"] = str(sni)
        ob["tls"] = tls_obj
    return ob


_CLASH_CONVERTERS = {
    "ss":         _conv_ss,
    "vless":      _conv_vless,
    "vmess":      _conv_vmess,
    "trojan":     _conv_trojan,
    "hysteria2":  _conv_hysteria2,
    "hy2":        _conv_hysteria2,
    "tuic":       _conv_tuic,
}


# ─────── YAML emitter (python-структура → clash-YAML) ───────
#
# Нужен, чтобы:
#   1) собирать одноразовый конфиг для тестера прокси mihomo (§тестер);
#   2) безопасно перезаписывать список прокси из таблицы (только когда
#      доступен pyyaml — иначе самописный парсер теряет вложенность/rules
#      на round-trip и редактирование запрещается, см. mihomo_proxies).
#
# Когда установлен pyyaml — используем `yaml.safe_dump` (точнее и безопаснее).
# Иначе — минимальный рекурсивный эмиттер (dict/list/scalar) c корректным
# квотированием. mihomo читает YAML своим полнофункциональным парсером,
# поэтому даже глубоко вложенные структуры эмиттер выдаёт валидно.

def has_pyyaml() -> bool:
    """Доступен ли модуль pyyaml (определяет, можно ли безопасно
    перезаписывать сложные конфиги round-trip'ом)."""
    try:
        import yaml  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


_YAML_KEYWORDS = {"true", "false", "yes", "no", "on", "off", "null", "~",
                  "none"}
_QUOTE_CHARS_RE = re.compile(r"[:#\[\]{},&*!|>'\"%@`]")


def _needs_quote(s: str) -> bool:
    if s == "":
        return True
    low = s.lower()
    if low in _YAML_KEYWORDS:
        return True
    if re.match(r"^-?\d+$", s) or re.match(r"^-?\d+\.\d+$", s):
        return True
    if s != s.strip():
        return True
    if _QUOTE_CHARS_RE.search(s):
        return True
    if s[0] in "-?:,[]{}#&*!|>'\"%@` ":
        return True
    return False


def _yaml_scalar(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    s = str(v)
    if _needs_quote(s):
        return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')
    return s


def _emit_kv(key, value, indent: int, out: list):
    pad = " " * indent
    ks = _yaml_scalar(key) if _needs_quote(str(key)) else str(key)
    if isinstance(value, dict):
        if not value:
            out.append("%s%s: {}" % (pad, ks))
            return
        out.append("%s%s:" % (pad, ks))
        for k, v in value.items():
            _emit_kv(k, v, indent + 2, out)
    elif isinstance(value, list):
        if not value:
            out.append("%s%s: []" % (pad, ks))
            return
        out.append("%s%s:" % (pad, ks))
        _emit_seq(value, indent + 2, out)
    else:
        out.append("%s%s: %s" % (pad, ks, _yaml_scalar(value)))


def _emit_seq(seq: list, indent: int, out: list):
    pad = " " * indent
    for item in seq:
        if isinstance(item, dict) and item:
            keys = list(item.items())
            k0, v0 = keys[0]
            if isinstance(v0, (dict, list)) and v0:
                out.append("%s-" % pad)
                _emit_kv(k0, v0, indent + 2, out)
            else:
                ks = _yaml_scalar(k0) if _needs_quote(str(k0)) else str(k0)
                out.append("%s- %s: %s" % (pad, ks, _yaml_scalar(v0)))
            for k, v in keys[1:]:
                _emit_kv(k, v, indent + 2, out)
        elif isinstance(item, dict):
            out.append("%s- {}" % pad)
        elif isinstance(item, list) and item:
            out.append("%s-" % pad)
            _emit_seq(item, indent + 2, out)
        elif isinstance(item, list):
            out.append("%s- []" % pad)
        else:
            out.append("%s- %s" % (pad, _yaml_scalar(item)))


def dump_yaml(data) -> str:
    """Python-структура → текст clash/mihomo-YAML."""
    try:
        import yaml  # type: ignore
        return yaml.safe_dump(data, allow_unicode=True, sort_keys=False,
                              default_flow_style=False)
    except ImportError:
        pass
    out: list = []
    if isinstance(data, dict):
        for k, v in data.items():
            _emit_kv(k, v, 0, out)
    elif isinstance(data, list):
        _emit_seq(data, 0, out)
    else:
        out.append(_yaml_scalar(data))
    return "\n".join(out) + "\n"


def dump_seq(seq: list, indent: int = 2) -> list:
    """Список (обычно proxies) → строки YAML с отступом `indent` (для
    текстовой вставки в существующий блок без полного round-trip)."""
    out: list = []
    _emit_seq(seq, indent, out)
    return out


# ─────── clash-proxy ↔ share-URI (copy/paste в таблице прокси) ───────
#
# Экспорт (Ctrl+C): clash-proxy → sing-box outbound (готовые конвертеры
# выше) → share-URI (core.singbox_subscription.outbound_to_uri).
# Импорт (Ctrl+V): share-URI → sing-box outbound (uri_to_outbound) →
# clash-proxy (_singbox_outbound_to_clash). Это даёт переиспользование
# уже протестированных парсеров, а не дубль логики.

def clash_proxy_to_uri(p: dict) -> str:
    """clash-proxy dict → share-URI (или '' для неподдержанного типа)."""
    if not isinstance(p, dict):
        return ""
    conv = _CLASH_CONVERTERS.get(str(p.get("type", "")).lower())
    if not conv:
        return ""
    try:
        ob = conv(p)
    except Exception:
        ob = None
    if not ob:
        return ""
    name = str(p.get("name") or ob.get("tag") or "")
    if name:
        ob = dict(ob)
        ob["tag"] = name
    from core.singbox_subscription import outbound_to_uri
    return outbound_to_uri(ob)


def _apply_transport_to_clash(tr, base: dict):
    if not isinstance(tr, dict):
        return
    tt = tr.get("type")
    if tt == "ws":
        base["network"] = "ws"
        ws: dict = {}
        if tr.get("path"):
            ws["path"] = tr["path"]
        host = (tr.get("headers") or {}).get("Host")
        if host:
            ws["headers"] = {"Host": host}
        if ws:
            base["ws-opts"] = ws
    elif tt == "grpc":
        base["network"] = "grpc"
        if tr.get("service_name"):
            base["grpc-opts"] = {"grpc-service-name": tr["service_name"]}


def _apply_tls_to_clash(tls, base: dict, reality: bool):
    if not isinstance(tls, dict) or not tls.get("enabled"):
        return
    base["tls"] = True
    if tls.get("server_name"):
        base["servername"] = tls["server_name"]
    fp = (tls.get("utls") or {}).get("fingerprint")
    if fp:
        base["client-fingerprint"] = fp
    ro = tls.get("reality") or {}
    if reality and isinstance(ro, dict) and ro.get("enabled"):
        opts: dict = {}
        if ro.get("public_key"):
            opts["public-key"] = ro["public_key"]
        if ro.get("short_id"):
            opts["short-id"] = ro["short_id"]
        base["reality-opts"] = opts


def _singbox_outbound_to_clash(ob: dict):
    """sing-box outbound → clash-proxy dict (для 6 поддержанных типов)."""
    if not isinstance(ob, dict):
        return None
    t = ob.get("type")
    server, port = ob.get("server"), ob.get("server_port")
    if not server or not port:
        return None
    base = {"name": ob.get("tag") or str(t),
            "server": str(server), "port": int(port)}
    if t == "shadowsocks":
        base.update({"type": "ss",
                     "cipher": ob.get("method") or "aes-128-gcm",
                     "password": ob.get("password") or ""})
        return base
    if t == "vless":
        base.update({"type": "vless", "uuid": ob.get("uuid") or ""})
        if ob.get("flow"):
            base["flow"] = ob["flow"]
        _apply_transport_to_clash(ob.get("transport"), base)
        _apply_tls_to_clash(ob.get("tls"), base, reality=True)
        return base
    if t == "vmess":
        base.update({"type": "vmess", "uuid": ob.get("uuid") or "",
                     "alterId": int(ob.get("alter_id") or 0),
                     "cipher": ob.get("security") or "auto"})
        _apply_transport_to_clash(ob.get("transport"), base)
        _apply_tls_to_clash(ob.get("tls"), base, reality=False)
        return base
    if t == "trojan":
        base.update({"type": "trojan", "password": ob.get("password") or ""})
        tls = ob.get("tls") or {}
        if tls.get("server_name"):
            base["sni"] = tls["server_name"]
        if tls.get("insecure"):
            base["skip-cert-verify"] = True
        _apply_transport_to_clash(ob.get("transport"), base)
        return base
    if t == "hysteria2":
        base.update({"type": "hysteria2",
                     "password": ob.get("password") or ""})
        tls = ob.get("tls") or {}
        if tls.get("server_name"):
            base["sni"] = tls["server_name"]
        if tls.get("insecure"):
            base["skip-cert-verify"] = True
        return base
    if t == "tuic":
        base.update({"type": "tuic", "uuid": ob.get("uuid") or ""})
        if ob.get("password"):
            base["password"] = ob["password"]
        tls = ob.get("tls") or {}
        if tls.get("server_name"):
            base["sni"] = tls["server_name"]
        return base
    return None


def uri_to_clash_proxy(uri: str) -> dict:
    """share-URI → {"ok": bool, "proxy": dict} либо {"ok": False, "error"}."""
    from core.singbox_subscription import uri_to_outbound
    r = uri_to_outbound(uri)
    if not r.get("ok") or not r.get("outbound"):
        return {"ok": False, "error": r.get("error") or "URI не распознан"}
    p = _singbox_outbound_to_clash(r["outbound"])
    if not p:
        return {"ok": False, "error": "тип не конвертируется в clash-proxy"}
    return {"ok": True, "proxy": p}
