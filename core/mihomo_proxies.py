# core/mihomo_proxies.py
"""
Прокси-таблица mihomo (паритет с sing-box `singbox_proxies`).

Здесь — серверная логика для страницы «mihomo → Прокси»:
  - разбор секции `proxies` clash-YAML в строки таблицы (имя/тип/адрес);
  - доступ к запущенному инстансу через external-controller (RESTful
    Clash API): список групп/активный узел, переключение активного,
    замер задержки (тест) и трафик (см. core/proxy_traffic.py);
  - безопасное редактирование списка прокси из таблицы:
      * импорт share-ссылок (Ctrl+V) — текстовая дозапись в блок
        `proxies:` (работает и без pyyaml — операция аддитивная);
      * удаление выбранных — round-trip через pyyaml (parse→mutate→dump);
        без pyyaml самописный парсер теряет вложенность/rules, поэтому
        удаление в таком окружении честно отклоняется (не портим конфиг);
      * включение external-controller — текстовая дозапись двух скаляров.

mihomo сам по себе и есть эталонная реализация Clash, поэтому управление
активным прокси/замеры идут его родным API, а не нашей конвертацией.
"""

import json
import re
import urllib.error
import urllib.request

from core.clash_yaml import (parse_yaml, dump_yaml, dump_seq, has_pyyaml,
                             _parse_flow, _parse_scalar, _split_kv,
                             _strip_yaml_comment, _needs_quote)


_SELECT_TYPE = "Selector"   # как Clash API называет group типа select

# Как Clash API называет ГРУППЫ (их в таблицу узлов не кладём) и встроенные
# псевдо-прокси, которых нет в конфиге.
_GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}
_BUILTIN_PROXIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL",
                    "COMPATIBLE"}


# ─────── чтение конфига ───────

def list_proxies(cfg: dict) -> list:
    """Список proxy-dict'ов из секции `proxies` (только валидные записи)."""
    if not isinstance(cfg, dict):
        return []
    out = []
    for p in (cfg.get("proxies") or []):
        if isinstance(p, dict) and p.get("name") and p.get("type"):
            out.append(p)
    return out


def proxy_names(cfg: dict) -> list:
    """Имена всех прокси (ключ для трафика/снапшота)."""
    return [str(p["name"]) for p in list_proxies(cfg)]


def proxy_rows(cfg: dict) -> list:
    """Строки таблицы: {name, type, server, port}."""
    rows = []
    for p in list_proxies(cfg):
        port = p.get("port")
        rows.append({
            "name":   str(p.get("name")),
            "type":   str(p.get("type") or ""),
            "server": str(p.get("server") or ""),
            "port":   port if isinstance(port, int) else (
                int(port) if str(port).isdigit() else port),
        })
    return rows


# Ключи, которые нас интересуют в текстовом фолбэке (см. proxies_from_text).
_TEXT_ROW_KEYS = ("name", "type", "server", "port")


def proxies_from_text(text: str) -> list:
    """
    Строки таблицы прокси, вытащенные ПРЯМО ИЗ ТЕКСТА конфига.

    Фолбэк для случая «в редакторе прокси видно, а в таблице пусто»: если
    YAML не разобрался целиком (якоря/`<<:`-merge, нестандартный отступ,
    окружение без PyYAML, где самописный парсер покрывает не весь YAML),
    структурный путь отдаёт пустой список и страница врёт «в конфиге нет
    прокси». Здесь мы не пытаемся понять весь YAML — только пройти по
    элементам блока `proxies:` и снять с каждого name/type/server/port.

    Возвращает только записи, у которых есть и `name`, и `type` — как
    list_proxies(), чтобы таблица была одинаковой в обоих путях.
    """
    if not text or not text.strip():
        return []
    lines = text.splitlines()
    idx = _find_top_key(lines, "proxies")
    if idx is None:
        return []
    inline = lines[idx].split(":", 1)[1].strip()
    if inline and inline not in ("[]", "~", "null"):
        return []                       # `proxies: <якорь/flow-список>`
    end = _proxies_block_end(lines, idx)

    rows, cur = [], None

    def _flush():
        if cur and cur.get("name") and cur.get("type"):
            rows.append(dict(cur))

    for raw in lines[idx + 1:end]:
        line = _strip_yaml_comment(raw)
        s = line.strip()
        if not s:
            continue
        if s.startswith("- ") or s == "-":
            _flush()
            cur = {}
            rest = s[1:].strip()
            if rest.startswith("{"):    # flow-элемент `- {name: a, type: ss}`
                flow = _parse_flow(rest)
                if isinstance(flow, dict):
                    cur = {k: flow.get(k) for k in _TEXT_ROW_KEYS
                           if flow.get(k) is not None}
                continue
            s = rest
            if not s:
                continue
        if cur is None:
            continue
        key, val = _split_kv(s)
        if key in _TEXT_ROW_KEYS and val is not None:
            cur[key] = _parse_scalar(val)
    _flush()

    out = []
    for p in rows:
        port = p.get("port")
        out.append({
            "name":   str(p.get("name")),
            "type":   str(p.get("type") or ""),
            "server": str(p.get("server") or ""),
            "port":   port if isinstance(port, int) else (
                int(port) if str(port).isdigit() else port),
        })
    return out


def provider_rows(cfg: dict) -> list:
    """
    Подписки из секции `proxy-providers` — как строки для таблицы.

    Узлы такой подписки в конфиге НЕ лежат: mihomo сам скачивает их по
    url в рантайме. Поэтому таблица прокси, которая читает только
    `proxies:`, оставалась пустой, и это выглядело как «подписка не
    работает», хотя конфиг корректный (issue #248). Показываем сами
    провайдеры, чтобы было видно: подписка распознана.
    """
    if not isinstance(cfg, dict):
        return []
    rows = []
    providers = cfg.get("proxy-providers")
    if not isinstance(providers, dict):
        return []
    for name, p in providers.items():
        if not isinstance(p, dict):
            continue
        url = str(p.get("url") or "")
        rows.append({
            "name": str(name),
            "type": str(p.get("type") or ""),
            # URL подписки — это секрет (в нём токен доступа), поэтому в
            # таблицу отдаём только хост.
            "url_host": _url_host(url),
            "has_url": bool(url),
            "path": str(p.get("path") or ""),
            "interval": p.get("interval"),
        })
    return rows


def _url_host(url: str) -> str:
    try:
        import urllib.parse
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def controller_provider_proxies(ep: dict) -> dict:
    """
    Узлы, реально загруженные из proxy-providers, у ЗАПУЩЕННОГО инстанса.

    Clash API: GET /providers/proxies → {"providers": {name: {..., proxies:
    [{name, type, ...}]}}}. Единственный способ увидеть узлы подписки —
    спросить сам движок: в конфиге их нет.
    """
    st, body = _request(ep, "/providers/proxies")
    if st != 200 or not body:
        return {"ok": False, "error": "controller HTTP %s" % st}
    try:
        data = json.loads(body)
    except ValueError as e:
        return {"ok": False, "error": "bad json: %s" % e}
    providers = data.get("providers") if isinstance(data, dict) else None
    if not isinstance(providers, dict):
        return {"ok": False, "error": "no providers in response"}
    out = []
    for nm, info in providers.items():
        if not isinstance(info, dict):
            continue
        proxies = info.get("proxies")
        if not isinstance(proxies, list):
            proxies = []
        out.append({
            "name": str(nm),
            "vehicle": str(info.get("vehicleType") or ""),
            "updated_at": str(info.get("updatedAt") or ""),
            "count": len(proxies),
            "proxies": [
                {"name": str(p.get("name") or ""),
                 "type": str(p.get("type") or "")}
                for p in proxies if isinstance(p, dict)
            ][:200],
        })
    return {"ok": True, "providers": out}


def select_group_names(cfg: dict) -> list:
    """Имена proxy-groups типа select (через них переключают активный)."""
    out = []
    for g in (cfg.get("proxy-groups") or []):
        if isinstance(g, dict) and str(g.get("type") or "").lower() == "select" \
                and g.get("name"):
            out.append(str(g["name"]))
    return out


def external_controller_endpoint(cfg: dict):
    """
    {"host","port","secret"} из `external-controller`/`secret`, либо None.
    `:9090` / `0.0.0.0:9090` → опрашиваем через 127.0.0.1.
    """
    if not isinstance(cfg, dict):
        return None
    ctrl = cfg.get("external-controller")
    if not ctrl or ":" not in str(ctrl):
        return None
    host, _, port = str(ctrl).rpartition(":")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not host or host in ("0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    host = host.strip("[]")
    return {"host": host, "port": port, "secret": cfg.get("secret") or ""}


# ─────── RESTful Clash API (запущенный инстанс) ───────

def _request(ep: dict, path: str, method: str = "GET", data=None,
             timeout: float = 3.0) -> tuple:
    """(status, body). 0 — сеть/таймаут. Поддерживает GET/PUT с JSON."""
    url = "http://%s:%d%s" % (ep["host"], int(ep["port"]), path)
    headers = {}
    if ep.get("secret"):
        headers["Authorization"] = "Bearer %s" % ep["secret"]
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return 0, ""


def controller_proxies(ep: dict) -> dict:
    """
    GET /proxies → {"ok", "active", "groups": [{name, now, all}], "nodes"}.
    `active` — текущий узел первой select-группы (для отметки в таблице).
    `nodes`  — ВСЕ узлы, которые реально загрузил движок (не группы и не
    встроенные DIRECT/REJECT/…). Это единственный источник правды, когда
    конфиг не разобрался нашим YAML-парсером: узлы всё равно видно.
    """
    st, body = _request(ep, "/proxies")
    if st != 200 or not body:
        return {"ok": False}
    try:
        data = json.loads(body)
    except ValueError:
        return {"ok": False}
    proxies = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(proxies, dict):
        return {"ok": False}
    groups, nodes = [], []
    for nm, info in proxies.items():
        if not isinstance(info, dict):
            continue
        if info.get("type") == _SELECT_TYPE:
            groups.append({"name": nm,
                           "now": info.get("now") or "",
                           "all": info.get("all") or []})
        if (str(info.get("type") or "") not in _GROUP_TYPES
                and str(nm) not in _BUILTIN_PROXIES):
            nodes.append({"name": str(nm),
                          "type": str(info.get("type") or "")})
    # mihomo всегда добавляет встроенную группу GLOBAL (для mode: global). Когда
    # у конфига есть СВОИ select-группы (наш routing-флоу создаёт «PROXY»),
    # GLOBAL — шум: и показывать, и переключать надо именно пользовательскую
    # группу, иначе смена узла в GLOBAL не повлияет на трафик, который правила
    # шлют в «PROXY». Оставляем GLOBAL, только если других select-групп нет.
    non_global = [g for g in groups if g["name"] != "GLOBAL"]
    groups = non_global or groups
    active = groups[0]["now"] if groups else ""
    return {"ok": True, "active": active, "groups": groups, "nodes": nodes}


def controller_activate(ep: dict, tag: str) -> dict:
    """
    Переключить активный прокси вживую: PUT /proxies/<group> {"name": tag}.
    Группа — первая select, содержащая tag (иначе первая select).
    """
    info = controller_proxies(ep)
    if not info.get("ok"):
        return {"ok": False, "error": "external-controller недоступен"}
    groups = info.get("groups") or []
    if not groups:
        return {"ok": False,
                "error": "В конфиге нет proxy-group типа select"}
    grp = next((g for g in groups if tag in (g.get("all") or [])), groups[0])
    st, _body = _request(
        ep, "/proxies/%s" % urllib.request.quote(grp["name"], safe=""),
        method="PUT", data={"name": tag}, timeout=3.0)
    if st in (200, 204):
        return {"ok": True, "group": grp["name"], "active": tag, "live": True}
    return {"ok": False, "group": grp["name"],
            "error": "mihomo отклонил переключение (HTTP %s)" % st}


# ─────── текстовые правки (без pyyaml) ───────

def _find_top_key(lines: list, key: str):
    """Индекс строки верхнеуровневого ключа `key:` (col 0), иначе None."""
    pat = re.compile(r"^%s\s*:" % re.escape(key))
    for i, l in enumerate(lines):
        if pat.match(l):
            return i
    return None


def _proxies_block_end(lines: list, start: int) -> int:
    """
    Индекс конца блока `proxies:` — первый следующий КЛЮЧ верхнего уровня
    (col 0, вида `key:`). Элементы списка в col 0 (`- name: …` — именно так их
    пишет pyyaml/`dump_yaml`) и комментарии блок НЕ заканчивают: иначе дозапись
    в pyyaml-конфиг попадала бы между `proxies:` и первым узлом с чужим
    отступом и ломала YAML (`expected <block end>, but found '-'`).
    """
    end = len(lines)
    for j in range(start + 1, len(lines)):
        l = lines[j]
        if not l.strip():
            continue
        stripped = l.lstrip()
        if (not l[0].isspace()
                and not stripped.startswith("#")
                and not stripped.startswith("- ")
                and stripped != "-"):
            return j
        end = j + 1
    return end


def _seq_item_indent(lines: list, start: int, end: int):
    """Отступ элементов `-` блока (start, end) — 0 у pyyaml-стиля, 2 у
    рукописного. None, если элементов нет (пустой/инлайновый блок)."""
    for j in range(start + 1, end):
        s = lines[j].strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("- ") or s == "-":
            return len(lines[j]) - len(lines[j].lstrip(" "))
    return None


def append_proxies_text(text: str, new_proxies: list) -> str:
    """
    Дозаписать прокси в блок `proxies:` текстово (аддитивно, без полного
    round-trip — поэтому безопасно и без pyyaml). Если блока нет —
    добавить его в конец.
    """
    if not new_proxies:
        return text
    had_nl = text.endswith("\n") or text == ""
    lines = text.splitlines()
    idx = _find_top_key(lines, "proxies")
    if idx is None:
        block = ["proxies:"] + dump_seq(new_proxies, indent=2)
        base = "\n".join(lines)
        if base and not base.endswith("\n"):
            base += "\n"
        return base + "\n".join(block) + "\n"
    # Если `proxies:` имеет inline-значение (напр. `proxies: []`) —
    # текстовая дозапись блока сломала бы YAML; пусть caller использует
    # round-trip. Считаем такой случай неподдержанным здесь.
    inline = lines[idx].split(":", 1)[1].strip()
    if inline and inline not in ("[]", "~", "null"):
        return text
    if inline in ("[]", "~", "null"):
        lines[idx] = "proxies:"
    end = _proxies_block_end(lines, idx)
    # Отступ новых элементов = отступ существующих (col 0 у pyyaml/dump_yaml,
    # 2 у рукописных конфигов). Смешение col-0 и indent-2 ломает YAML.
    indent = _seq_item_indent(lines, idx, end)
    item_lines = dump_seq(new_proxies, indent=2 if indent is None else indent)
    new_lines = lines[:end] + item_lines + lines[end:]
    out = "\n".join(new_lines)
    return out + "\n" if had_nl else out


def _seq_items(lines: list, start: int, end: int, item_indent: int):
    """
    Разбить block-последовательность на элементы.

    Возвращает [(first, stop, key_col)]: индекс первой строки элемента,
    индекс ЗА последней и колонку, с которой идут ключи элемента (у
    `- name: a` это позиция `name`). Строки между элементами (пустые,
    комментарии) прилипают к предыдущему элементу — так их удаление вместе
    с ним не оставляет висячих хвостов.
    """
    starts = []
    for j in range(start + 1, end):
        line = lines[j]
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == item_indent and (s.startswith("- ") or s == "-"):
            starts.append(j)
    items = []
    for n, first in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else end
        line = lines[first]
        after = line[line.index("-") + 1:]
        if after.strip():
            key_col = len(line) - len(after) + (len(after) - len(after.lstrip(" ")))
        else:
            key_col = item_indent + 2
            for k in range(first + 1, stop):
                if lines[k].strip():
                    key_col = len(lines[k]) - len(lines[k].lstrip(" "))
                    break
        items.append((first, stop, key_col))
    return items


def _item_name(lines: list, first: int, stop: int, key_col: int):
    """Значение `name:` элемента последовательности (или None).

    Смотрим только ключи ПЕРВОГО уровня элемента: `name` внутри вложенных
    `ws-opts`/`headers` — чужой.
    """
    line = lines[first]
    rest = line[line.index("-") + 1:].strip()
    if rest.startswith("{"):
        flow = _parse_flow(rest)
        if isinstance(flow, dict) and flow.get("name") is not None:
            return str(flow["name"])
        return None
    candidates = [rest] if rest else []
    for k in range(first + 1, stop):
        cur = lines[k]
        if not cur.strip() or cur.strip().startswith("#"):
            continue
        if len(cur) - len(cur.lstrip(" ")) == key_col:
            candidates.append(cur.strip())
    for c in candidates:
        key, val = _split_kv(_strip_yaml_comment(c))
        if key == "name" and val is not None:
            return str(_parse_scalar(val))
    return None


def remove_proxies_text(text: str, names) -> dict:
    """
    Удалить прокси из блока `proxies:` ТЕКСТОМ, без round-trip.

    Зачем не через pyyaml: на роутере (Entware) его обычно нет, а
    round-trip самописным парсером повредил бы конфиг — из-за этого
    удаление из таблицы просто отказывало («требует модуля PyYAML»).
    Здесь мы не переписываем конфиг, а вырезаем строки удаляемых
    элементов; всё остальное — комментарии, отступы, порядок ключей,
    якоря — остаётся байт в байт.

    Ссылки на удалённые узлы вычищаются из `proxy-groups[].proxies`
    (`_strip_group_refs_lines`): группа, ссылающаяся на несуществующий
    прокси, не даст mihomo стартовать.

    Возвращает {ok, text, removed[], emptied_groups[]} либо
    {ok: False, unsupported: True, error} — если блок задан инлайном и
    текстовая правка небезопасна (тогда caller идёт в round-trip).
    """
    nameset = {str(n) for n in (names or []) if str(n)}
    if not nameset:
        return {"ok": True, "text": text, "removed": [],
                "emptied_groups": []}

    had_nl = text.endswith("\n") or text == ""
    lines = text.splitlines()
    idx = _find_top_key(lines, "proxies")
    if idx is None:
        return {"ok": True, "text": text, "removed": [],
                "emptied_groups": []}

    inline = lines[idx].split(":", 1)[1].strip()
    if inline and inline not in ("[]", "~", "null"):
        return {"ok": False, "unsupported": True,
                "error": "секция proxies задана инлайном — текстовое "
                         "удаление небезопасно"}

    end = _proxies_block_end(lines, idx)
    item_indent = _seq_item_indent(lines, idx, end)
    if item_indent is None:
        return {"ok": True, "text": text, "removed": [],
                "emptied_groups": []}

    drop, removed = set(), []
    for first, stop, key_col in _seq_items(lines, idx, end, item_indent):
        name = _item_name(lines, first, stop, key_col)
        if name is not None and name in nameset:
            removed.append(name)
            drop.update(range(first, stop))

    kept = [l for i, l in enumerate(lines) if i not in drop]
    # Не оставляем `proxies:` без значения: пустой ключ разбирается как
    # null, а `[]` — честный пустой список (и наш validate_yaml выдаёт
    # понятное предупреждение вместо «неправильный YAML»).
    if drop and len(removed) >= len(_seq_items(lines, idx, end, item_indent)):
        new_idx = _find_top_key(kept, "proxies")
        if new_idx is not None:
            kept[new_idx] = "proxies: []"
    kept, emptied = _strip_group_refs_lines(kept, nameset)
    out = "\n".join(kept)
    return {"ok": True, "text": (out + "\n" if had_nl else out),
            "removed": removed, "emptied_groups": emptied}


def _strip_group_refs_lines(lines: list, nameset: set):
    """
    Убрать удалённые имена из `proxy-groups[].proxies` (block и flow).

    Возвращает (lines, emptied_groups) — группы, у которых после чистки не
    осталось ни одного узла: такой конфиг mihomo тоже не примет, и об этом
    честнее предупредить, чем молча отдать нерабочий файл.
    """
    idx = _find_top_key(lines, "proxy-groups")
    if idx is None:
        return lines, []

    end = _proxies_block_end(lines, idx)
    out = list(lines[:idx + 1])
    emptied = []
    group_name = ""
    list_key_indent = None      # отступ ключа `proxies:` текущей группы
    list_key_line = None        # его индекс в out (чтобы дописать `[]`)
    kept_in_list = 0

    def _close_list():
        if list_key_indent is None or kept_in_list:
            return
        if group_name:
            emptied.append(group_name)
        if list_key_line is not None:
            out[list_key_line] = out[list_key_line].rstrip() + " []"

    for j in range(idx + 1, end):
        line = lines[j]
        s = line.strip()
        if not s or s.startswith("#"):
            out.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))

        if list_key_indent is not None:
            # Элемент списка. Отступ может быть и БОЛЬШЕ ключа (рукописный
            # стиль), и РАВНЫМ ему (стиль pyyaml: `proxies:` и `- A` на
            # одной колонке) — второе мы сначала не учли, и ссылки в
            # pyyaml-конфигах оставались висеть.
            if indent >= list_key_indent and (s.startswith("- ")
                                              or s == "-"):
                val = str(_parse_scalar(_strip_yaml_comment(s[1:].strip())))
                if val in nameset:
                    continue                    # ссылка на удалённый узел
                kept_in_list += 1
                out.append(line)
                continue
            _close_list()
            list_key_indent = None

        # Группа целиком записана flow-мэпом (`- {name: PROXY, proxies:
        # [A, B]}`) — правим только список внутри строки, остальное не
        # трогаем.
        if s.startswith("- ") and s[1:].strip().startswith("{"):
            new_line, gname, became_empty = _filter_flow_group_line(
                line, nameset)
            if became_empty and gname:
                emptied.append(gname)
            out.append(new_line)
            continue

        key, val = _split_kv(_strip_yaml_comment(s.lstrip("- ").strip())
                             if s.startswith("- ") else _strip_yaml_comment(s))
        if key == "name" and val is not None:
            group_name = str(_parse_scalar(val))
        elif key == "proxies":
            if val == "":
                list_key_indent = indent if not s.startswith("- ") \
                    else indent + 2
                kept_in_list = 0
                list_key_line = len(out)
                out.append(line)
                continue
            if val.startswith("["):
                items = _parse_flow(val)
                if isinstance(items, list):
                    left = [x for x in items if str(x) not in nameset]
                    if not left and group_name:
                        emptied.append(group_name)
                    prefix = line[:len(line) - len(line.lstrip(" "))]
                    body = ", ".join(_yaml_inline_scalar(x) for x in left)
                    dash = "- " if s.startswith("- ") else ""
                    out.append("%s%sproxies: [%s]" % (prefix, dash, body))
                    continue
        out.append(line)

    _close_list()
    out.extend(lines[end:])
    return out, emptied


# Имя, которое в flow-списке безопасно писать без кавычек. Всё остальное
# (пробелы, эмодзи, `|` — обычный вид имён в подписках) квотируем: голый
# скаляр с ними формально валиден, но слишком легко ломается.
_BARE_FLOW_SCALAR_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _yaml_inline_scalar(v) -> str:
    """Скаляр для flow-списка: квотируем всё, кроме простых токенов."""
    s = str(v)
    if _BARE_FLOW_SCALAR_RE.match(s) and not _needs_quote(s):
        return s
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


_FLOW_PROXIES_KEY_RE = re.compile(r"(?:(?<=\{)|(?<=,))\s*proxies\s*:\s*(?=\[)")


def _filter_flow_group_line(line: str, nameset: set):
    """
    Вырезать удалённые имена из `proxies: [...]` внутри flow-мэпа группы.

    Правим ТОЛЬКО span самого списка — остальная часть строки (порядок и
    квотирование прочих ключей) остаётся байт в байт. Возвращает
    (строка, имя группы, стала ли группа пустой).
    """
    m = _FLOW_PROXIES_KEY_RE.search(line)
    if not m:
        return line, "", False
    start = line.index("[", m.end() - 1)
    depth, stop = 0, -1
    in_s = in_d = False
    for i in range(start, len(line)):
        ch = line[i]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    stop = i
                    break
    if stop < 0:
        return line, "", False                  # незакрытый список — не лезем

    items = _parse_flow(line[start:stop + 1])
    if not isinstance(items, list):
        return line, "", False
    left = [x for x in items if str(x) not in nameset]
    if len(left) == len(items):
        return line, "", False                  # ничего не поменялось

    gname = ""
    flow = _parse_flow(line[line.index("{"):].rstrip())
    if isinstance(flow, dict) and flow.get("name") is not None:
        gname = str(flow["name"])
    body = ", ".join(_yaml_inline_scalar(x) for x in left)
    return (line[:start] + "[" + body + "]" + line[stop + 1:],
            gname, not left)


def enable_external_controller_text(text: str, host: str, port: int,
                                    secret: str = "") -> str:
    """Дозаписать `external-controller`/`secret` (если их нет) — два
    верхнеуровневых скаляра, безопасно текстом."""
    lines = text.splitlines()
    has_ctrl = any(re.match(r"^external-controller\s*:", l) for l in lines)
    has_secret = any(re.match(r"^secret\s*:", l) for l in lines)
    prepend = []
    if not has_ctrl:
        prepend.append("external-controller: %s:%d" % (host, int(port)))
    if secret and not has_secret:
        prepend.append("secret: %s" % secret)
    if not prepend:
        return text
    return "\n".join(prepend) + "\n" + text


# ─────── мутации dict (для round-trip через pyyaml) ───────

def remove_proxies(cfg: dict, names) -> dict:
    """Удалить прокси по именам + вычистить ссылки в proxy-groups."""
    nameset = {str(n) for n in (names or [])}
    if not nameset:
        return cfg
    proxies = cfg.get("proxies")
    if isinstance(proxies, list):
        cfg["proxies"] = [p for p in proxies
                          if not (isinstance(p, dict)
                                  and str(p.get("name")) in nameset)]
    clean_group_refs(cfg, nameset)
    return cfg


def clean_group_refs(cfg: dict, removed: set):
    """Убрать удалённые имена из `proxies:` каждой proxy-group, поправить
    висячие default/now-подобные поля."""
    for g in (cfg.get("proxy-groups") or []):
        if not isinstance(g, dict):
            continue
        plist = g.get("proxies")
        if isinstance(plist, list):
            g["proxies"] = [x for x in plist if str(x) not in removed]


def safe_mutate(text: str, mutate_fn) -> dict:
    """
    Round-trip правка конфига: parse → mutate(cfg) → dump.

    Доступно только при наличии pyyaml: самописный fallback-парсер теряет
    вложенные структуры/скалярные списки (rules) на round-trip, и
    перезапись повредила бы конфиг. В таком окружении возвращаем
    {"ok": False, "needs_pyyaml": True} — операция честно отклоняется.
    """
    if not has_pyyaml():
        return {"ok": False, "needs_pyyaml": True, "error":
                "Удаление прокси из таблицы требует модуля PyYAML "
                "(иначе сложный конфиг будет повреждён при перезаписи). "
                "Установите PyYAML (python3-yaml) или правьте список прокси "
                "в YAML на странице mihomo."}
    try:
        cfg = parse_yaml(text)
    except Exception as e:
        return {"ok": False, "error": "не удалось разобрать YAML: %s" % e}
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "корень YAML не является объектом"}
    new_cfg = mutate_fn(cfg)
    if new_cfg is None:
        new_cfg = cfg
    return {"ok": True, "text": dump_yaml(new_cfg)}
