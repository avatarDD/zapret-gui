# core/geneva_share.py
"""
Обмен найденными стратегиями geneva между пользователями.

**Экспорт** — рабочие стратегии этой сети (страница «Стратегии»:
сервисы «Авто» с обходом и удачный подбор) одним JSON-файлом::

    {"format": "zapret-gui/geneva-strategies", "version": 1,
     "exported_at": "2026-11-04T09:40:00Z",
     "items": [{"strategy": "...", "transport": "tcp",
                "services": ["youtube.com", ...], "fitness": 396.0}]}

В файл идут только стратегии, транспорт и имена сервисов (домены и
названия протоколов) — без адресов устройств, ключей книги и журналов.

**Импорт** — тот же файл или просто текст: одна стратегия Geneva на
строку (``#`` — комментарий). Каждая строка проверяется
``check_strategy_text``; принятые хранятся в ``<state>/geneva/auto/
imported.json`` и встают в подбор «Авто» в круг проверенных — сразу за
стратегиями, которые работают в этой сети. Применяется импорт только
подбором с проверкой на трафике сервиса, напрямую ничего не включается.
"""

from __future__ import annotations

import json
import os
import threading
import time

FORMAT = "zapret-gui/geneva-strategies"
VERSION = 1
MAX_ITEMS = 200
MAX_BYTES = 512 * 1024
MAX_SERVICES = 20

_lock = threading.Lock()


def _transport(strategy: str) -> str:
    low = strategy.lower()
    tcp = "[tcp:" in low
    udp = "[udp:" in low or "[dns" in low
    if tcp and udp:
        return "tcp,udp"
    return "udp" if udp else "tcp"


def _clean_name(v) -> str:
    v = str(v or "").strip()
    return v[:120] if v and all(ch.isprintable() for ch in v) else ""


def build_export(found_items, now: float = None) -> dict:
    """Строки ``found()`` → документ экспорта (без адресов и ключей)."""
    now = time.time() if now is None else now
    items = []
    for it in found_items or []:
        strategy = str(it.get("strategy") or "").strip()
        if not strategy:
            continue
        names = []
        for svc in it.get("services") or []:
            name = _clean_name(svc.get("name") if isinstance(svc, dict)
                               else svc)
            if name and name not in names:
                names.append(name)
        for t in it.get("targets") or []:
            name = _clean_name(t)
            if name and name not in names:
                names.append(name)
        row = {"strategy": strategy, "transport": _transport(strategy),
               "services": names[:MAX_SERVICES]}
        if it.get("fitness") is not None:
            try:
                row["fitness"] = float(it["fitness"])
            except (TypeError, ValueError):
                pass
        items.append(row)
    return {"format": FORMAT, "version": VERSION,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                         time.gmtime(now)),
            "items": items[:MAX_ITEMS]}


def parse_import(payload) -> tuple:
    """Документ экспорта (dict или JSON-текст) или текст «стратегия на
    строку» → ``([{strategy, services}], [ошибки])``. Стратегии
    проверены и приведены к каноническому виду."""
    from core.geneva_manager import check_strategy_text
    rows, errors = [], []
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        if len(payload) > MAX_BYTES:
            return [], ["файл больше %d КБ" % (MAX_BYTES // 1024)]
        text = payload.strip()
        if text.startswith("{"):
            try:
                payload = json.loads(text)
            except ValueError as e:
                return [], ["не JSON: %s" % e]
        else:
            payload = {"items": [{"strategy": line.strip()}
                                 for line in text.splitlines()
                                 if line.strip() and
                                 not line.strip().startswith("#")]}
    if not isinstance(payload, dict):
        return [], ["ожидался объект с items"]
    fmt = payload.get("format")
    if fmt not in (None, FORMAT):
        return [], ["чужой формат: %s" % str(fmt)[:60]]
    items = payload.get("items")
    if not isinstance(items, list):
        return [], ["нет списка items"]
    seen = set()
    for n, it in enumerate(items[:MAX_ITEMS], 1):
        raw = it.get("strategy") if isinstance(it, dict) else it
        raw = str(raw or "").strip()
        if not raw:
            continue
        try:
            strategy = check_strategy_text(raw)
        except ValueError as e:
            errors.append("%d: %s" % (n, str(e)[:120]))
            continue
        if strategy in seen:
            continue
        seen.add(strategy)
        services = []
        if isinstance(it, dict):
            for svc in it.get("services") or []:
                name = _clean_name(svc)
                if name and name not in services:
                    services.append(name)
        rows.append({"strategy": strategy, "services": services[:MAX_SERVICES]})
    if len(items) > MAX_ITEMS:
        errors.append("взяты первые %d из %d" % (MAX_ITEMS, len(items)))
    return rows, errors


class ImportStore:
    """Импортированные стратегии (``imported.json``)."""

    def __init__(self, path: str, clock=time.time):
        self.path = path
        self._clock = clock

    def load(self) -> list:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return []
        items = data.get("items") if isinstance(data, dict) else None
        return [i for i in items or []
                if isinstance(i, dict) and i.get("strategy")]

    def _save(self, items) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"items": items}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def add(self, rows) -> dict:
        with _lock:
            items = self.load()
            have = {i["strategy"]: i for i in items}
            added = 0
            for r in rows:
                cur = have.get(r["strategy"])
                if cur is None:
                    cur = {"strategy": r["strategy"], "services": [],
                           "imported_at": self._clock()}
                    items.append(cur)
                    have[r["strategy"]] = cur
                    added += 1
                for name in r.get("services") or []:
                    if name not in cur["services"] and \
                            len(cur["services"]) < MAX_SERVICES:
                        cur["services"].append(name)
            items = items[-MAX_ITEMS:]
            self._save(items)
            return {"added": added, "total": len(items)}

    def remove(self, strategy: str) -> bool:
        with _lock:
            items = self.load()
            keep = [i for i in items if i.get("strategy") != strategy]
            if len(keep) == len(items):
                return False
            self._save(keep)
            return True
