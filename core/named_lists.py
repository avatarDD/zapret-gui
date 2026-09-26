# core/named_lists.py
"""
Именованные списки — единое хранилище доменов и IP/CIDR, общее для
nfqws2-hostlist'ов и движка маршрутизации (см. «Объединение списков» в
TODO.md, предусловие к единому слою «назначение → метод»).

Один список = набор доменов и/или CIDR под именем. Списки:
  - редактируются на странице «Списки» (GUI);
  - импортируются текстом или по URL;
  - переиспользуются «назначениями» единого слоя маршрутизации
    (Destination может ссылаться на named-list по id);
  - могут экспортироваться в nfqws2-hostlist.

Хранилище — settings.json, секция "named_lists":
    "named_lists": [ {id, name, description, domains[], cidrs[],
                      created_at, updated_at, source_url}, ... ]

Чистые функции классификации/нормализации (`classify_entry`,
`parse_entries`) тестируются без I/O.
"""

import ipaddress
import os
import re
import threading
import time

from core.config_manager import get_config_manager


_lock = threading.Lock()

# Домен: метки a-z0-9, дефисы внутри, точки между; без схемы/пути.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# «1.2.3» — не домен и не IP: без этой проверки уезжало в домены.
_ALL_DIGITS_RE = re.compile(r"^[0-9.]+$")


# ─────────────────────── pure helpers ────────────────────────────────

def classify_entry(raw: str) -> tuple:
    """
    Определить тип записи. Возвращает (kind, normalized) где
    kind ∈ {'domain', 'cidr', None}. None — мусор/не распознано.
    """
    s = (raw or "").strip().lower()
    if not s or s.startswith("#"):
        return (None, "")
    # CIDR (IP с маской) — проверяем до срезки '/'.
    if _looks_like_cidr(s):
        try:
            return ("cidr", str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            return (None, "")
    # Убираем схему и путь, если вставили URL.
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/", 1)[0].strip()
    # «*.example.com» из чужих списков — то же, что домен: и nfqws2, и
    # dnsmasq-маршрутизация покрывают поддомены сами.
    if s.startswith("*."):
        s = s[2:]
    s = s.strip(".")
    if not s:
        return (None, "")
    # Голый IP → /32 или /128.
    try:
        ip = ipaddress.ip_address(s)
        # 0.0.0.0 / 127.0.0.1 — это не назначение, а первая колонка
        # hosts-файла («0.0.0.0 ads.example.com»): импорт такого списка
        # раньше заводил их в CIDR и заворачивал loopback в туннель.
        if ip.is_unspecified or ip.is_loopback:
            return (None, "")
        return ("cidr", "%s/%d" % (str(ip), 32 if ip.version == 4 else 128))
    except ValueError:
        pass
    # Кириллические домены — в punycode: так их видят DNS и SNI.
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return (None, "")
    if _DOMAIN_RE.match(s) and not _ALL_DIGITS_RE.match(s):
        return ("domain", s)
    return (None, "")


def _looks_like_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    head = s.split("/", 1)[0]
    try:
        ipaddress.ip_address(head)
        return True
    except ValueError:
        return False


def parse_entries(text) -> dict:
    """
    Разобрать текст/список в {'domains': [...], 'cidrs': [...]}.
    Принимает строку (разделители — пробелы/запятые/переводы строк) или
    список строк. Дедуплицирует, сохраняя порядок, отбрасывает мусор.
    """
    if isinstance(text, (list, tuple)):
        tokens = []
        for item in text:
            tokens.extend(re.split(r"[\s,;]+", str(item or "")))
    else:
        tokens = re.split(r"[\s,;]+", str(text or ""))
    domains, cidrs = [], []
    seen_d, seen_c = set(), set()
    for tok in tokens:
        kind, norm = classify_entry(tok)
        if kind == "domain" and norm not in seen_d:
            seen_d.add(norm)
            domains.append(norm)
        elif kind == "cidr" and norm not in seen_c:
            seen_c.add(norm)
            cidrs.append(norm)
    return {"domains": domains, "cidrs": cidrs}


# ─────────────────────── storage ─────────────────────────────────────

def _all_raw() -> list:
    cm = get_config_manager()
    lists = cm.get("named_lists")
    return list(lists) if isinstance(lists, list) else []


def _save_all(items: list):
    cm = get_config_manager()
    cm.set("named_lists", list(items))
    cm.save()


def list_all() -> list:
    """Все списки (с подсчётом записей, без полных массивов — для UI-таблицы
    отдаём всё; объёмы небольшие)."""
    out = []
    for it in _all_raw():
        if not isinstance(it, dict):
            continue
        d = dict(it)
        d.setdefault("domains", [])
        d.setdefault("cidrs", [])
        d["domain_count"] = len(d["domains"])
        d["cidr_count"] = len(d["cidrs"])
        out.append(d)
    return out


def get(list_id: str) -> dict:
    for it in _all_raw():
        if isinstance(it, dict) and it.get("id") == list_id:
            return it
    return None


def resolve(list_id: str) -> dict:
    """Вернуть {'domains': [...], 'cidrs': [...]} списка (или пустые)."""
    it = get(list_id) or {}
    return {"domains": list(it.get("domains") or []),
            "cidrs": list(it.get("cidrs") or [])}


def create(name: str, *, description: str = "",
           entries=None, source_url: str = "", transport: str = "") -> dict:
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "Пустое имя"}
    parsed = parse_entries(entries) if entries is not None else \
        {"domains": [], "cidrs": []}
    now = int(time.time())
    item = {
        # os.urandom, а не uuid: на Entware python3-light без модуля uuid
        "id": "list-" + os.urandom(4).hex(),
        "name": name,
        "description": (description or "").strip(),
        "domains": parsed["domains"],
        "cidrs": parsed["cidrs"],
        "source_url": (source_url or "").strip(),
        "transport": (transport or "").strip(),
        "created_at": now,
        "updated_at": now,
    }
    with _lock:
        items = _all_raw()
        if any(isinstance(x, dict) and x.get("name") == name for x in items):
            return {"ok": False, "error": "Список с таким именем уже есть"}
        items.append(item)
        _save_all(items)
    return {"ok": True, "list": item}


def update(list_id: str, *, name=None, description=None,
           entries=None, replace: bool = True) -> dict:
    """
    Обновить список. entries: если replace=True — заменить содержимое
    распарсенным; если replace=False — добавить к существующему.
    """
    with _lock:
        items = _all_raw()
        idx = next((i for i, x in enumerate(items)
                    if isinstance(x, dict) and x.get("id") == list_id), -1)
        if idx < 0:
            return {"ok": False, "error": "Список не найден"}
        item = dict(items[idx])
        if name is not None:
            new_name = (name or "").strip() or item.get("name")
            # Уникальность имени проверяет и create(): иначе переименование
            # давало два списка с одним именем, неразличимых в выборе
            # назначения маршрута.
            if any(i != idx and isinstance(x, dict)
                   and x.get("name") == new_name
                   for i, x in enumerate(items)):
                return {"ok": False, "error": "Список с таким именем уже есть"}
            item["name"] = new_name
        if description is not None:
            item["description"] = (description or "").strip()
        if entries is not None:
            parsed = parse_entries(entries)
            if replace:
                item["domains"] = parsed["domains"]
                item["cidrs"] = parsed["cidrs"]
            else:
                item["domains"] = _merge(item.get("domains"), parsed["domains"])
                item["cidrs"] = _merge(item.get("cidrs"), parsed["cidrs"])
        item["updated_at"] = int(time.time())
        items[idx] = item
        _save_all(items)
    if entries is not None:
        _notify(list_id)
    return {"ok": True, "list": item}


def update_fields(list_id: str, fields: dict) -> dict:
    """
    Низкоуровневое обновление произвольных полей списка (с блокировкой).

    Используется обновлятелем курируемых списков (core/list_updater.py),
    которому нужно записать не только domains/cidrs, но и служебные поля
    (`_remote`, `last_refresh`, `last_status`, `interval_hours`, …).
    """
    if not isinstance(fields, dict):
        return {"ok": False, "error": "fields должен быть dict"}
    with _lock:
        items = _all_raw()
        idx = next((i for i, x in enumerate(items)
                    if isinstance(x, dict) and x.get("id") == list_id), -1)
        if idx < 0:
            return {"ok": False, "error": "Список не найден"}
        item = dict(items[idx])
        item.update(fields)
        item["updated_at"] = int(time.time())
        items[idx] = item
        _save_all(items)
    if "domains" in fields or "cidrs" in fields:
        _notify(list_id)
    return {"ok": True, "list": item}


def mutate(list_id: str, fn) -> dict:
    """
    Атомарно «прочитать → изменить → записать» один список.

    fn(item) получает копию записи и возвращает dict полей для записи
    (или None — ничего не менять). Всё под замком модуля: обновлятель
    списков (list_updater) скачивает ответ секунды, и если он брал
    содержимое ДО скачивания, а писал после, автодобавление детектора
    или правка из GUI за это время молча терялись.
    """
    with _lock:
        items = _all_raw()
        idx = next((i for i, x in enumerate(items)
                    if isinstance(x, dict) and x.get("id") == list_id), -1)
        if idx < 0:
            return {"ok": False, "error": "Список не найден"}
        item = dict(items[idx])
        fields = fn(dict(item))
        if not fields:
            return {"ok": True, "list": item, "changed": False}
        item.update(fields)
        item["updated_at"] = int(time.time())
        items[idx] = item
        _save_all(items)
    if "domains" in fields or "cidrs" in fields:
        _notify(list_id)
    return {"ok": True, "list": item, "changed": True}


def add_entries(list_id: str, entries) -> dict:
    """Дописать записи в список атомарно; возвращает число добавленных."""
    parsed = parse_entries(entries)
    added = {"n": 0}

    def _fn(item):
        domains = list(item.get("domains") or [])
        cidrs = list(item.get("cidrs") or [])
        new_d = _merge(domains, parsed["domains"])
        new_c = _merge(cidrs, parsed["cidrs"])
        added["n"] = (len(new_d) - len(domains)) + (len(new_c) - len(cidrs))
        if not added["n"]:
            return None
        return {"domains": new_d, "cidrs": new_c}

    res = mutate(list_id, _fn)
    res["added"] = added["n"]
    return res


def _notify(list_id: str) -> None:
    """Маршруты единого слоя с этим списком — переприменить (отложенно)."""
    try:
        from core.unified.manager import notify_list_changed
        notify_list_changed(list_id)
    except Exception:
        pass


def delete(list_id: str) -> dict:
    with _lock:
        items = _all_raw()
        new = [x for x in items
               if not (isinstance(x, dict) and x.get("id") == list_id)]
        if len(new) == len(items):
            return {"ok": False, "error": "Список не найден"}
        _save_all(new)
    # Маршрут, ссылавшийся на список, теперь получит из него пустоту —
    # его правила надо снять, а не оставить с последним снимком.
    _notify(list_id)
    return {"ok": True, "id": list_id}


def _merge(a, b) -> list:
    seen = set()
    out = []
    for x in list(a or []) + list(b or []):
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
