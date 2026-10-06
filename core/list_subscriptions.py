# core/list_subscriptions.py
"""
Подписки хостлистов и ipset-файлов nfqws2 на URL: автообновление.

## Зачем

Хостлист или ipset-файл nfqws2 можно было наполнить по ссылке только
разово («Импорт из URL»): список устаревал, пока пользователь не
повторит импорт руками. Автообновление было лишь у именованных списков
(core/list_updater) — а ими пользуется единый слой маршрутов, не
стратегии nfqws2.

Здесь — подписка файла на URL с тем же поведением, что у именованных
списков (и у MagiTrickle для его подписок):

* ручные правки сохраняются: прошлый ответ источника лежит рядом с
  файлом (``.<имя>.remote``), и всё, чего в нём не было, считается
  добавленным вручную и переживает обновление
  (:func:`core.list_updater.merge_preserving_manual`);
* пустой или ошибочный ответ файл не трогает;
* интервал — свой у каждой подписки, тикает тот же фоновый поток, что
  обновляет именованные списки (``ListRefresher``);
* скачивание — через транспорт и зеркало списков (``lists.transport``,
  ``install.mirror``) с потолком размера, как у именованных списков.

Хранение: ``settings.json → lists.subscriptions`` —
``{"hostlist:<имя>" | "ipset:<имя>": {url, interval_hours, last_*}}``.
"""

import os
import threading
import time

from core.log_buffer import log


KINDS = ("hostlist", "ipset")
DEFAULT_INTERVAL_HOURS = 24
MIN_INTERVAL_HOURS = 1

_lock = threading.Lock()


def _key(kind: str, name: str) -> str:
    return "%s:%s" % (kind, name)


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _load() -> dict:
    try:
        raw = _cfg().get("lists", "subscriptions", default={}) or {}
    except Exception:
        return {}
    return dict(raw) if isinstance(raw, dict) else {}


def _save(subs: dict) -> None:
    cm = _cfg()
    cm.set("lists", "subscriptions", subs)
    cm.save()


def _manager(kind: str):
    if kind == "ipset":
        from core.ipset_manager import get_ipset_manager
        return get_ipset_manager()
    from core.hostlist_manager import get_hostlist_manager
    return get_hostlist_manager()


def _file_path(kind: str, name: str) -> str:
    return _manager(kind)._file_path(name)


def _remote_path(kind: str, name: str) -> str:
    path = _file_path(kind, name)
    return os.path.join(os.path.dirname(path), ".%s.remote" % name)


def _read_remote(kind: str, name: str) -> list:
    try:
        with open(_remote_path(kind, name), encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except OSError:
        return []


def _write_remote(kind: str, name: str, entries: list) -> None:
    try:
        from core.safe_io import atomic_write_text
        atomic_write_text(_remote_path(kind, name),
                          "\n".join(entries) + ("\n" if entries else ""),
                          mode=0o644)
    except Exception as e:
        log.warning("подписка %s: снимок источника не записан: %s"
                    % (_key(kind, name), e), source="lists")


# ─────────────────────── разбор ──────────────────────────────────────

def parse_entries(kind: str, text: str, manager=None) -> list:
    """Строки источника → нормализованные записи (порядок, без дублей)."""
    out, seen = [], set()
    if kind == "ipset":
        from core.ipset_manager import validate_ip_entry
    else:
        manager = manager or _manager("hostlist")
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        line = line.split("#", 1)[0].strip()
        if kind == "ipset":
            entry = validate_ip_entry(line)
        else:
            entry = manager.normalize_domain(line)
        if entry and entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def merge(current: list, remote: list, prev_remote: list) -> list:
    """remote ∪ (current − prev_remote): ручные правки переживают
    обновление, пропавшие в источнике записи уходят. Чистая."""
    from core.list_updater import merge_preserving_manual
    return merge_preserving_manual({"domains": current},
                                   {"domains": remote},
                                   {"domains": prev_remote})["domains"]


# ─────────────────────── CRUD ────────────────────────────────────────

def get(kind: str, name: str) -> dict:
    sub = _load().get(_key(kind, name))
    return dict(sub, kind=kind, name=name) if isinstance(sub, dict) else {}


def list_all() -> list:
    out = []
    for key, sub in sorted(_load().items()):
        kind, _, name = key.partition(":")
        if kind in KINDS and name and isinstance(sub, dict):
            out.append(dict(sub, kind=kind, name=name))
    return out


def subscribe(kind: str, name: str, url: str,
              interval_hours=DEFAULT_INTERVAL_HOURS,
              refresh_now: bool = True) -> dict:
    """Подписать файл на URL (или сменить URL/интервал)."""
    from core.list_updater import get_list_refresher, is_safe_url
    if kind not in KINDS:
        return {"ok": False, "error": "неизвестный тип списка"}
    url = (url or "").strip()
    if not is_safe_url(url):
        return {"ok": False, "error": "Недопустимый или небезопасный URL"}
    if not os.path.isfile(_file_path(kind, name)):
        return {"ok": False, "error": "Список %s не найден" % name}
    try:
        hours = max(MIN_INTERVAL_HOURS, int(interval_hours))
    except (TypeError, ValueError):
        hours = DEFAULT_INTERVAL_HOURS
    with _lock:
        subs = _load()
        prev = subs.get(_key(kind, name)) or {}
        sub = {"url": url, "interval_hours": hours,
               "last_refresh": 0 if prev.get("url") != url
               else int(prev.get("last_refresh") or 0),
               "last_status": prev.get("last_status", ""),
               "last_error": prev.get("last_error", ""),
               "last_count": int(prev.get("last_count") or 0)}
        subs[_key(kind, name)] = sub
        _save(subs)
    out = {"ok": True, "subscription": dict(sub, kind=kind, name=name)}
    if refresh_now:
        out["refresh"] = refresh(kind, name)
    get_list_refresher().reconfigure()
    return out


def unsubscribe(kind: str, name: str) -> dict:
    """Снять подписку; содержимое файла остаётся как есть."""
    with _lock:
        subs = _load()
        existed = subs.pop(_key(kind, name), None) is not None
        if existed:
            _save(subs)
    try:
        os.remove(_remote_path(kind, name))
    except OSError:
        pass
    try:
        from core.list_updater import get_list_refresher
        get_list_refresher().reconfigure()
    except Exception:
        pass
    return {"ok": True, "removed": existed}


def rename(kind: str, old: str, new: str) -> None:
    """Список переименовали — подписка (и снимок источника) за ним."""
    with _lock:
        subs = _load()
        sub = subs.pop(_key(kind, old), None)
        if sub is None:
            return
        subs[_key(kind, new)] = sub
        _save(subs)
    try:
        os.replace(_remote_path(kind, old), _remote_path(kind, new))
    except OSError:
        pass


def _set_status(kind: str, name: str, **fields) -> None:
    with _lock:
        subs = _load()
        key = _key(kind, name)
        if key not in subs:
            return
        sub = dict(subs[key])
        sub.update(fields)
        subs[key] = sub
        _save(subs)


# ─────────────────────── обновление ──────────────────────────────────

def refresh(kind: str, name: str) -> dict:
    """Скачать источник и слить в файл с сохранением ручных правок."""
    from core.list_updater import _fetch, get_transport
    sub = get(kind, name)
    if not sub:
        return {"ok": False, "error": "подписки нет"}
    now = int(time.time())
    if not os.path.isfile(_file_path(kind, name)):
        # Список удалили — подписка больше ни к чему.
        unsubscribe(kind, name)
        log.info("подписка %s снята: списка больше нет"
                 % _key(kind, name), source="lists")
        return {"ok": False, "error": "список удалён — подписка снята"}
    try:
        text = _fetch(sub["url"], transport=get_transport())
    except Exception as e:                      # noqa: BLE001 — граница
        # Любой сбой (не только RuntimeError из _fetch: обрыв посреди
        # тела — http.client.IncompleteRead) — в статус со временем,
        # иначе тик повторял бы скачивание каждую минуту.
        err = str(e) or e.__class__.__name__
        _set_status(kind, name, last_refresh=now, last_status="error",
                    last_error=err)
        return {"ok": False, "error": err}
    mgr = _manager(kind)
    remote = parse_entries(kind, text, mgr)
    if not remote:
        _set_status(kind, name, last_refresh=now, last_status="empty",
                    last_error="пустой ответ — содержимое сохранено")
        return {"ok": False, "error": "пустой ответ (не затёрто)",
                "preserved": True}
    if kind == "ipset":
        current = list(mgr.get_ipset(name) or [])
    else:
        current = list(mgr.get_hostlist(name) or [])
    merged = merge(current, remote, _read_remote(kind, name))
    changed = merged != current
    if changed:
        ok = (mgr.save_ipset(name, merged) if kind == "ipset"
              else mgr.save_hostlist(name, merged))
        if not ok:
            _set_status(kind, name, last_refresh=now, last_status="error",
                        last_error="файл не записан")
            return {"ok": False, "error": "файл не записан"}
    _write_remote(kind, name, remote)
    _set_status(kind, name, last_refresh=now, last_status="ok",
                last_error="", last_count=len(merged))
    log.info("подписка %s: %d записей%s" % (
        _key(kind, name), len(merged), "" if changed else " (без изменений)"),
        source="lists")
    return {"ok": True, "count": len(merged), "changed": changed}


def tick(now: int = None) -> int:
    """Обновить подписки, у которых подошёл срок. Возвращает их число."""
    now = int(now or time.time())
    done = 0
    for sub in list_all():
        try:
            hours = max(MIN_INTERVAL_HOURS, int(sub.get("interval_hours")
                                                or DEFAULT_INTERVAL_HOURS))
        except (TypeError, ValueError):
            hours = DEFAULT_INTERVAL_HOURS
        if now - int(sub.get("last_refresh") or 0) < hours * 3600:
            continue
        try:
            refresh(sub["kind"], sub["name"])
        except Exception as e:
            log.warning("подписка %s: %s" % (_key(sub["kind"], sub["name"]),
                                             e), source="lists")
        done += 1
    return done
