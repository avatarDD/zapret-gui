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


def _strip_yaml_comment(line: str) -> str:
    """Срезать трейлинг `#`-комментарий, НЕ трогая `#` внутри кавычек.

    YAML: `#` начинает комментарий только если перед ним пробел/начало
    строки. Прежний `re.sub(r"\\s+#.*$","")` портил значения с ` #` внутри
    кавычек (пароли/пути вида `password: "p@ss #1"`)."""
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i]
    return line


def _unquote(s: str) -> str:
    """Снять кавычки с YAML-скаляра, вернув строку (для ключей dict)."""
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    return s


def _split_kv(s: str):
    """
    Разбить строку `key: value` на (key, value), уважая кавычки.
    Разделитель — первый `:`, за которым идёт пробел/таб или конец строки
    (так `127.0.0.1:9090` в значении не дробится). Ключ деквотируется.
    Если строка не похожа на mapping — (None, None).
    """
    in_s = in_d = False
    n = len(s)
    for i, ch in enumerate(s):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == ":" and not in_s and not in_d:
            if i + 1 >= n or s[i + 1] in " \t":
                return _unquote(s[:i]), s[i + 1:].strip()
    return None, None


def _split_flow_items(s: str) -> list:
    """Разбить тело flow `{...}`/`[...]` по запятым верхнего уровня
    (учитывая вложенные `{}`/`[]` и кавычки)."""
    items, buf = [], []
    depth = 0
    in_s = in_d = False
    for ch in s:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if not in_s and not in_d:
            if ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
            elif ch == "," and depth == 0:
                items.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _parse_flow(s: str):
    """Разобрать flow-mapping `{k: v, ...}` или flow-seq `[a, b, ...]`."""
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        d = {}
        for part in _split_flow_items(s[1:-1].strip()):
            k, v = _split_kv(part)
            if k is not None:
                d[k] = _parse_value(v)
        return d
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_parse_value(p) for p in _split_flow_items(inner)] if inner \
            else []
    return _parse_scalar(s)


def _parse_value(s: str):
    """Значение справа от `:` или элемент flow-списка: scalar либо flow."""
    s = s.strip()
    if s[:1] in ("{", "["):
        return _parse_flow(s)
    return _parse_scalar(s)


def _fallback_yaml_parser(text: str):
    """
    Самописный парсер YAML-подмножества — когда pyyaml недоступен (типичная
    Entware-сборка python на роутере). Покрывает всё, что эмитит `dump_yaml`,
    и типовые clash-подписки:

      - mapping'и произвольной вложенности (`dns:`→`...`→`...`);
      - block-последовательности `- item` со скалярами, mapping'ами и
        вложенными списками (`rules:`, `payload:`, `proxy-groups[].proxies`);
      - последовательности и на отступе ключа (стиль pyyaml), и с отступом
        +2 (стиль нашего эмиттера);
      - flow-структуры `{k: v, ...}` / `[a, b, ...]` (компактные подписки);
      - пустые контейнеры `{}` / `[]`.

    Прежняя версия теряла скалярные list-элементы (превращая `rules:` в
    `[{}, {}, …]`), вложенные списки и flow-mapping'и — отсюда «битый»
    round-trip на роутере без pyyaml. На пустом/нелепом вводе → {}.
    """
    # Токенизируем в (indent, content), отбросив пустые строки/комментарии.
    toks = []
    for raw in text.splitlines():
        no_comment = _strip_yaml_comment(raw)
        if not no_comment.strip():
            continue
        content = no_comment.strip()
        if content in ("---", "..."):      # маркеры документа — игнор
            continue
        indent = len(no_comment) - len(no_comment.lstrip(" "))
        toks.append((indent, content))

    if not toks:
        return {}

    pos = [0]

    def _is_seq(content: str) -> bool:
        return content == "-" or content.startswith("- ")

    def parse_block(indent: int):
        _, content = toks[pos[0]]
        if _is_seq(content):
            return parse_seq(toks[pos[0]][0])
        return parse_map(indent)

    def parse_map(indent: int) -> dict:
        result: dict = {}
        while pos[0] < len(toks):
            cur_indent, content = toks[pos[0]]
            if cur_indent != indent or _is_seq(content):
                break
            key, val = _split_kv(content)
            if key is None:                 # не mapping-строка — пропускаем
                pos[0] += 1
                continue
            pos[0] += 1
            if val != "":
                result[key] = _parse_value(val)
                continue
            # Пустое значение → вложенный блок глубже, либо seq на том же
            # отступе (стиль pyyaml `key:\n- item`), иначе None.
            child = None
            if pos[0] < len(toks):
                nxt_i, nxt_c = toks[pos[0]]
                if nxt_i > indent:
                    child = parse_block(nxt_i)
                elif nxt_i == indent and _is_seq(nxt_c):
                    child = parse_seq(nxt_i)
            result[key] = child
        return result

    def parse_seq(indent: int) -> list:
        result: list = []
        while pos[0] < len(toks):
            cur_indent, content = toks[pos[0]]
            if cur_indent != indent or not _is_seq(content):
                break
            if content == "-":              # значение во вложенном блоке
                pos[0] += 1
                child = None
                if pos[0] < len(toks) and toks[pos[0]][0] > indent:
                    child = parse_block(toks[pos[0]][0])
                result.append(child)
                continue
            rest = content[2:].strip()
            if rest[:1] in ("{", "["):       # flow-элемент
                result.append(_parse_flow(rest))
                pos[0] += 1
                continue
            if rest[:1] in ('"', "'"):       # квотированный скаляр
                result.append(_parse_scalar(rest))
                pos[0] += 1
                continue
            key, _v = _split_kv(rest)
            if key is None:                  # обычный скаляр (`- MATCH,PROXY`)
                result.append(_parse_scalar(rest))
                pos[0] += 1
                continue
            # Mapping-элемент `- key: val` (+ продолжение на отступе+2).
            # Перепишем строку как обычный ключ и доверим parse_map собрать
            # весь mapping элемента целиком.
            item_indent = indent + 2
            toks[pos[0]] = (item_indent, rest)
            result.append(parse_map(item_indent))
        return result

    root_indent = toks[0][0]
    if _is_seq(toks[0][1]):                  # корень-список (нетипично)
        return {}
    return parse_map(root_indent)


def _parse_scalar(s: str):
    """Превратить YAML-скаляр в Python-значение."""
    s = s.strip()
    if not s:
        return ""
    # Quoted strings (деквотируем с разэкранированием — пара к эмиттеру).
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or
                        (s[0] == "'" and s[-1] == "'")):
        return _unquote(s)
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
            # YAML без кавычек ('01', '08') приходит как int → теряется
            # ведущий ноль. short-id — hex-строка чётной длины; трактуем
            # десятичную запись как hex-текст и доводим до чётной длины
            # (best-effort; в подписках hex-shortID стоит брать в кавычки).
            if sid is None:
                sid_str = ""
            elif isinstance(sid, int):
                sid_str = str(sid)
                if len(sid_str) % 2:
                    sid_str = "0" + sid_str
            else:
                sid_str = str(sid)
            tls_obj["reality"] = {
                "enabled":    True,
                "public_key": str(reality.get("public-key") or ""),
                "short_id":   sid_str,
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
                # Пустой dict/list НЕЛЬЗЯ прогонять через _yaml_scalar — он
                # вернул бы строку "{}"/"[]" (или закавычит её), исказив тип и
                # ломая YAML для mihomo. Эмитим корректные пустые контейнеры.
                if isinstance(v0, dict):
                    out.append("%s- %s: {}" % (pad, ks))
                elif isinstance(v0, list):
                    out.append("%s- %s: []" % (pad, ks))
                else:
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
