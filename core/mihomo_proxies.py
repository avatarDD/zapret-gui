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

from core.clash_yaml import parse_yaml, dump_yaml, dump_seq, has_pyyaml


_SELECT_TYPE = "Selector"   # как Clash API называет group типа select


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
    GET /proxies → {"ok", "active", "groups": [{name, now, all}]}.
    `active` — текущий узел первой select-группы (для отметки в таблице).
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
    groups = []
    for nm, info in proxies.items():
        if isinstance(info, dict) and info.get("type") == _SELECT_TYPE:
            groups.append({"name": nm,
                           "now": info.get("now") or "",
                           "all": info.get("all") or []})
    active = groups[0]["now"] if groups else ""
    return {"ok": True, "active": active, "groups": groups}


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
    """Индекс конца блока `proxies:` — первый следующий ключ col 0."""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        l = lines[j]
        if not l.strip():
            continue
        if not l[0].isspace() and not l.lstrip().startswith("#"):
            return j
        end = j + 1
    return end


def append_proxies_text(text: str, new_proxies: list) -> str:
    """
    Дозаписать прокси в блок `proxies:` текстово (аддитивно, без полного
    round-trip — поэтому безопасно и без pyyaml). Если блока нет —
    добавить его в конец.
    """
    if not new_proxies:
        return text
    item_lines = dump_seq(new_proxies, indent=2)
    had_nl = text.endswith("\n") or text == ""
    lines = text.splitlines()
    idx = _find_top_key(lines, "proxies")
    if idx is None:
        block = ["proxies:"] + item_lines
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
    new_lines = lines[:end] + item_lines + lines[end:]
    out = "\n".join(new_lines)
    return out + "\n" if had_nl else out


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
