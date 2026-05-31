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
    ob: dict[str, Any] = {
        "type":        "vless",
        "tag":         _safe_tag(p.get("name", "vless")),
        "server":      str(p["server"]),
        "server_port": int(p["port"]),
        "uuid":        str(p.get("uuid") or ""),
    }
    flow = p.get("flow")
    if flow:
        ob["flow"] = str(flow)

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
