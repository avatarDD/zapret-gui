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
import re
import threading
import time
import uuid

from core.config_manager import get_config_manager


_lock = threading.Lock()

# Домен: метки a-z0-9, дефисы внутри, точки между; без схемы/пути.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


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
    s = s.split("/", 1)[0].strip().strip(".")
    if not s:
        return (None, "")
    # Голый IP → /32 или /128.
    try:
        ip = ipaddress.ip_address(s)
        return ("cidr", "%s/%d" % (str(ip), 32 if ip.version == 4 else 128))
    except ValueError:
        pass
    if _DOMAIN_RE.match(s):
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
           entries=None, source_url: str = "") -> dict:
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "Пустое имя"}
    parsed = parse_entries(entries) if entries is not None else \
        {"domains": [], "cidrs": []}
    now = int(time.time())
    item = {
        "id": "list-" + uuid.uuid4().hex[:8],
        "name": name,
        "description": (description or "").strip(),
        "domains": parsed["domains"],
        "cidrs": parsed["cidrs"],
        "source_url": (source_url or "").strip(),
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
            item["name"] = (name or "").strip() or item.get("name")
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
    return {"ok": True, "list": item}


def delete(list_id: str) -> dict:
    with _lock:
        items = _all_raw()
        new = [x for x in items
               if not (isinstance(x, dict) and x.get("id") == list_id)]
        if len(new) == len(items):
            return {"ok": False, "error": "Список не найден"}
        _save_all(new)
    return {"ok": True, "id": list_id}


def _merge(a, b) -> list:
    seen = set()
    out = []
    for x in list(a or []) + list(b or []):
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
