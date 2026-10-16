# core/file_history.py
"""
История изменений файлов: что, когда и кем поменялось, разница и откат.

## Зачем

«Вчера работало, сегодня нет» — а что менялось, никто не помнит: пара
правок в списках, другая стратегия, галочка в настройках. Здесь каждая
запись отслеживаемого файла превращается в версию, которую можно
посмотреть (разница с предыдущей), вернуть по одной или откатить целым
действием. Приём nfqws2-ui (журнал версий + «отменить последнее»).

## Что отслеживается

* ``settings.json`` (каталог конфигурации);
* пользовательские стратегии ``config/strategies/user/*.json``;
* хостлисты ``lists_path/*.txt`` и ipset'ы ``ipset_path/*.txt`` — кроме
  служебных (``.*``, ``unified*`` — их пересобирает единый слой).

Файлы крупнее :data:`MAX_FILE_BYTES` не отслеживаются: многомегабайтный
ipset из подписки съел бы весь бюджет истории за пару обновлений.

## Откуда узнаём о записи

1. **Наши записи** — через наблюдателя ``core.safe_io`` (все сохранения
   идут через ``atomic_write_*``): прежнее содержимое читается до
   ``os.replace``, новое известно. Удаление и переименование —
   :func:`remove_file` / :func:`rename_file`.
2. **Чужие правки** (``vi`` по ssh, скрипт, другой GUI) — сверка
   отпечатков раз в :data:`SCAN_INTERVAL` секунд и при старте. Такие
   версии помечены ``source="external"``. Прежнее содержимое у них есть,
   потому что каждый известный отпечаток хранится в ``objects/``.

## Действие (операция)

Несколько файлов, записанных одной кнопкой («применить стратегию» —
настройки + автозапуск, «вернуть рабочее состояние» — всё сразу),
объединяются в одно действие :func:`operation`. «Отменить последнее»
откатывает действие целиком. Без явного действия запись — сама себе
действие; подряд идущие записи одного файла в течение
:data:`COALESCE_SEC` склеиваются (сохранение настроек по полю — не
двадцать версий).

## Хранилище

``<config_dir>/history/``: ``index.json`` (версии и известные
отпечатки) и ``objects/<sha256>.gz`` — содержимое, права 0600 (в
``settings.json`` токены). Пределы: :data:`PER_FILE` версий на файл и
``history.max_mb`` на всё хранилище — сверх них уходят самые старые;
версии старше ``history.max_days`` дней уходят и без этого.

Версия ``settings.json`` подписана изменёнными разделами («Изменён
settings.json: awg, strategy»): иначе правка автозапуска AWG терялась
среди двадцати одинаковых «Изменён settings.json».

В ``settings.json`` правки только полей-отметок (``last_*``,
``installed_at``) версией не считаются: статус подписки списков
пишется при каждом обновлении и вытеснял бы настоящие правки.
"""

from __future__ import annotations

import contextlib
import difflib
import gzip
import hashlib
import json
import os
import re
import threading
import time

from core.log_buffer import log

# Версий на один файл.
PER_FILE = 20
# Бюджет хранилища по умолчанию (сжатые объекты), МБ.
DEFAULT_MAX_MB = 8
# Версии старше — уходят (``history.max_days``; 0 — без предела), дней.
DEFAULT_MAX_DAYS = 30
# Файлы крупнее — не отслеживаются.
MAX_FILE_BYTES = 2 * 1024 * 1024
# Склейка подряд идущих записей одного файла, сек.
COALESCE_SEC = 120
# Период сверки с диском (правки вне GUI), сек.
SCAN_INTERVAL = 600
# Разница длиннее — обрезается.
DIFF_MAX_LINES = 400

SOURCES = ("gui", "external", "restore", "auto")

_VOLATILE_KEY = re.compile(r"^last_|_at$")

_lock = threading.RLock()
_tls = threading.local()
_state = None           # {"seq", "entries", "known", "baselined"}
_installed = False
_scanner = None


# ─────────────────────────── пути ────────────────────────────

def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _conf(section: str, key: str, default=None):
    """Значение настройки БЕЗ замка ``ConfigManager``.

    Наблюдатель записи зовётся из ``ConfigManager.save()``, который держит
    свой (нереентерабельный) замок, — ``cfg.get`` там повис бы навсегда.
    Чтение ссылки на словарь и значения из него в CPython атомарно.
    """
    try:
        value = (_cfg()._config or {}).get(section, {})
        value = value.get(key, default) if isinstance(value, dict) else default
    except Exception:                               # noqa: BLE001
        return default
    return default if value is None else value


def history_dir() -> str:
    return os.path.join(_cfg().config_dir, "history")


def _roots() -> list:
    """[(каталог, префикс для показа, суффикс)] отслеживаемых файлов."""
    roots = []
    try:
        from core.strategy_builder import get_strategy_manager
        roots.append((get_strategy_manager()._user_dir, "strategies", ".json"))
    except Exception:                               # noqa: BLE001
        pass
    for key, prefix in (("lists_path", "lists"), ("ipset_path", "ipset")):
        d = _conf("zapret", key, "")
        if d:
            roots.append((d, prefix, ".txt"))
    return roots


def _norm(path: str) -> str:
    return os.path.abspath(path)


def is_tracked(path: str) -> bool:
    """Отслеживается ли путь (по месту и имени, не по размеру)."""
    try:
        if not enabled():
            return False
        path = _norm(path)
        if path == _norm(_cfg().path):
            return True
        name = os.path.basename(path)
        if name.startswith(".") or name.startswith("unified"):
            return False
        parent = os.path.dirname(path)
        for root, _prefix, suffix in _roots():
            if parent == _norm(root) and name.endswith(suffix):
                return True
    except Exception:                               # noqa: BLE001
        return False
    return False


def display_name(path: str) -> str:
    """Короткое имя для UI: settings.json, lists/foo.txt, strategies/x.json."""
    path = _norm(path)
    try:
        if path == _norm(_cfg().path):
            return os.path.basename(path)
        parent = os.path.dirname(path)
        for root, prefix, _suffix in _roots():
            if parent == _norm(root):
                return "%s/%s" % (prefix, os.path.basename(path))
    except Exception:                               # noqa: BLE001
        pass
    return path


def tracked_files() -> list:
    """Существующие отслеживаемые файлы (не крупнее предела)."""
    out = []
    cfg_path = _cfg().path
    if os.path.isfile(cfg_path):
        out.append(_norm(cfg_path))
    for root, _prefix, suffix in _roots():
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            if (name.startswith(".") or name.startswith("unified")
                    or not name.endswith(suffix)):
                continue
            p = _norm(os.path.join(root, name))
            if os.path.isfile(p):
                out.append(p)
    return out


def enabled() -> bool:
    try:
        return bool(_conf("history", "enabled", True))
    except Exception:                               # noqa: BLE001
        return False


def _max_bytes() -> int:
    try:
        mb = float(_conf("history", "max_mb", DEFAULT_MAX_MB))
    except (TypeError, ValueError):
        mb = DEFAULT_MAX_MB
    return int(max(1.0, mb) * 1024 * 1024)


def _max_age_sec() -> float:
    """Предел возраста версии, сек (0 — без предела)."""
    try:
        days = float(_conf("history", "max_days", DEFAULT_MAX_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_MAX_DAYS
    return max(0.0, days) * 86400


# ─────────────────────────── хранилище ────────────────────────────

def _sha(data) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _obj_path(sha: str) -> str:
    return os.path.join(history_dir(), "objects", sha + ".gz")


def _put(data: bytes) -> str:
    """Сохранить содержимое (если ещё нет) и запомнить его сжатый размер.

    Размеры живут в индексе: бюджет считается без ``stat`` на каждую
    запись — а запись ``settings.json`` идёт под замком настроек.
    """
    from core.safe_io import atomic_write_bytes
    sha = _sha(data)
    p = _obj_path(sha)
    sizes = _load()["sizes"]
    if not os.path.exists(p):
        packed = gzip.compress(data, 6)
        atomic_write_bytes(p, packed)
        sizes[sha] = len(packed)
    elif sha not in sizes:
        try:
            sizes[sha] = os.path.getsize(p)
        except OSError:
            sizes[sha] = 0
    return sha


def get_object(sha) -> bytes | None:
    """Содержимое версии по отпечатку (``None`` — «файла не было»)."""
    if not sha:
        return None
    try:
        with open(_obj_path(sha), "rb") as f:
            return gzip.decompress(f.read())
    except (OSError, EOFError, gzip.BadGzipFile):
        raise FileNotFoundError("версия %s не сохранилась" % sha[:12])


def _index_path() -> str:
    return os.path.join(history_dir(), "index.json")


def _load() -> dict:
    global _state
    if _state is not None:
        return _state
    st = {"seq": 0, "entries": [], "known": {}, "sizes": {},
          "baselined": False}
    try:
        with open(_index_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            st["seq"] = int(data.get("seq") or 0)
            st["entries"] = [e for e in data.get("entries") or []
                             if isinstance(e, dict)]
            st["known"] = dict(data.get("known") or {})
            st["sizes"] = {k: int(v) for k, v in
                           (data.get("sizes") or {}).items()}
            st["baselined"] = bool(data.get("baselined"))
    except (OSError, ValueError, TypeError):
        pass
    _state = st
    return st


def _save() -> None:
    from core.safe_io import atomic_write_json
    atomic_write_json(_index_path(), _state, indent=0)


def _reset_for_tests() -> None:
    global _state
    with _lock:
        _state = None


def _note_trimmed(st: dict, entry: dict) -> None:
    """Запомнить, до какого момента история файла уже обрезана."""
    trimmed = st.setdefault("trimmed", {})
    trimmed[entry["path"]] = max(float(trimmed.get(entry["path"]) or 0),
                                 float(entry.get("ts") or 0))


def _gc(st: dict, sweep: bool = False) -> None:
    """Пределы: PER_FILE версий на файл, бюджет на старые версии.

    Бюджет считается только по версиям в прошлом: текущие копии файлов
    (``known``) нужны всегда, и если они одни больше бюджета, история
    просто короче — но не пуста.

    ``sweep`` — ещё и удалить с диска осиротевшие объекты (обход
    каталога — из фоновой сверки, не на каждую запись).
    """
    by_path = {}
    for e in st["entries"]:
        by_path.setdefault(e["path"], []).append(e)
    drop = set()
    for items in by_path.values():
        for e in items[:-PER_FILE]:
            drop.add(e["id"])
            _note_trimmed(st, e)
    max_age = _max_age_sec()
    if max_age:
        horizon = time.time() - max_age
        for e in st["entries"]:
            if float(e.get("ts") or 0) < horizon and e["id"] not in drop:
                drop.add(e["id"])
                _note_trimmed(st, e)
    if drop:
        st["entries"] = [e for e in st["entries"] if e["id"] not in drop]

    sizes = st["sizes"]
    current = {s for s in st["known"].values() if s}

    def _past():
        refs = set()
        for e in st["entries"]:
            refs.update(s for s in (e.get("before"), e.get("after")) if s)
        return refs - current

    budget = _max_bytes()
    past = _past()
    # Самые старые версии уходят первыми; пересчёт — только по мере
    # удаления (сумма — по словарю размеров, без обращений к диску).
    while st["entries"] and sum(sizes.get(x, 0) for x in past) > budget:
        _note_trimmed(st, st["entries"].pop(0))
        past = _past()
    if not sweep:
        return
    refs = past | current
    for sha in list(sizes):
        if sha not in refs:
            sizes.pop(sha, None)
    objdir = os.path.join(history_dir(), "objects")
    try:
        for name in os.listdir(objdir):
            if name.endswith(".gz") and name[:-3] not in refs:
                try:
                    os.remove(os.path.join(objdir, name))
                except OSError:
                    pass
    except OSError:
        pass


# ─────────────────────────── действие ────────────────────────────

@contextlib.contextmanager
def operation(label: str, source: str = "gui"):
    """Объединить записи внутри блока в одно действие с подписью.

    Вложенный блок не открывает нового действия — записи уходят во
    внешнее (одна кнопка = одна строка в истории).
    """
    outer = getattr(_tls, "op", None)
    if outer is not None:
        yield outer
        return
    with _lock:
        st = _load()
        st["seq"] += 1
        op = {"id": "op-%d" % st["seq"], "label": label or "",
              "source": source if source in SOURCES else "gui",
              "ts": time.time()}
    _tls.op = op
    try:
        yield op
    finally:
        _tls.op = None


def _strip_volatile(x):
    """Значение без полей-отметок (``last_*``, ``*_at``) на любой глубине."""
    if isinstance(x, dict):
        return {k: _strip_volatile(v) for k, v in x.items()
                if not _VOLATILE_KEY.search(str(k))}
    if isinstance(x, list):
        return [_strip_volatile(v) for v in x]
    return x


def _volatile_only(path: str, old, new) -> bool:
    """settings.json, у которого поменялись только поля-отметки."""
    if old is None or new is None:
        return False
    try:
        if _norm(path) != _norm(_cfg().path):
            return False
        a, b = json.loads(old), json.loads(new)
    except (ValueError, TypeError):
        return False

    return _strip_volatile(a) == _strip_volatile(b)


def _changed_sections(path: str, before_sha, after_sha) -> list:
    """Разделы ``settings.json``, которые разнятся у двух версий.

    Поля-отметки (``last_*``, ``*_at``) не в счёт — как в
    :func:`_volatile_only`. Не ``settings.json`` или не JSON — пусто.
    """
    if not before_sha or not after_sha:
        return []
    try:
        if _norm(path) != _norm(_cfg().path):
            return []
        a = json.loads(get_object(before_sha) or b"")
        b = json.loads(get_object(after_sha) or b"")
    except (ValueError, TypeError):
        return []
    if not isinstance(a, dict) or not isinstance(b, dict):
        return []

    return sorted(k for k in set(a) | set(b)
                  if not _VOLATILE_KEY.search(str(k))
                  and _strip_volatile(a.get(k)) != _strip_volatile(b.get(k)))


def _label_for(rel: str, before, after, sections=()) -> str:
    if before is None:
        return "Создан %s" % rel
    if after is None:
        return "Удалён %s" % rel
    if sections:
        return "Изменён %s: %s" % (rel, ", ".join(sections))
    return "Изменён %s" % rel


def _append(st, path, before_sha, after_sha, source, op=None,
            coalesce=False) -> dict | None:
    now = time.time()
    rel = display_name(path)
    if coalesce and st["entries"]:
        last = st["entries"][-1]
        if (last["path"] == path and last.get("auto_op")
                and not last.get("sealed")
                and last.get("source") == source
                and last.get("after") == before_sha
                and now - last["ts"] < COALESCE_SEC):
            last["after"] = after_sha
            last["ts"] = now
            if last["before"] == after_sha:
                # Правка вернула файл как было — версии нет.
                st["entries"].pop()
                return None
            last["sections"] = _changed_sections(path, last["before"],
                                                 after_sha)
            last["label"] = _label_for(rel, last["before"], after_sha,
                                       last["sections"])
            return last
    st["seq"] += 1
    sections = _changed_sections(path, before_sha, after_sha)
    entry = {"id": st["seq"], "ts": now, "path": path, "file": rel,
             "before": before_sha, "after": after_sha, "source": source,
             "sections": sections}
    if op:
        entry.update(op=op["id"], label=op["label"] or _label_for(
            rel, before_sha, after_sha, sections))
    else:
        entry.update(op="op-e%d" % st["seq"], auto_op=True,
                     label=_label_for(rel, before_sha, after_sha, sections))
    st["entries"].append(entry)
    return entry


def checkpoint() -> None:
    """Запретить склейку следующей записи с уже записанной версией.

    Нужна перед запоминанием момента (рабочая точка, начало проверки
    стратегии): иначе запись после него склеилась бы с версией до него,
    и состояние «на момент» не восстановить — его просто нет в истории.
    """
    with _lock:
        st = _load()
        if st["entries"] and not st["entries"][-1].get("sealed"):
            st["entries"][-1]["sealed"] = True
            _save()


def record(path: str, old, new, source: str = "gui") -> None:
    """Зафиксировать запись файла (``old``/``new`` — bytes или ``None``)."""
    if not enabled():
        return
    path = _norm(path)
    for blob in (old, new):
        if blob is not None and len(blob) > MAX_FILE_BYTES:
            # Файл перерос предел — перестаём его вести. Отпечаток
            # забываем: иначе следующая обычная запись приняла бы
            # устаревший отпечаток за правку вне GUI.
            with _lock:
                if _load()["known"].pop(path, None) is not None:
                    _save()
            return
    op = getattr(_tls, "op", None)
    if op:
        source = op["source"]
    sha_old, sha_new = _sha(old), _sha(new)
    try:
        with _lock:
            st = _load()
            known = st["known"].get(path, "")
            # Файл успели поменять мимо нас (не атомарной записью или
            # руками) — сначала эта правка, иначе её версия потерялась бы.
            if (st["baselined"] and known != "" and known != sha_old
                    and path in st["known"]):
                if old is not None:
                    _put(old)
                _append(st, path, known, sha_old, "external")
            if sha_old == sha_new:
                st["known"][path] = sha_new
                _save()
                return
            if old is not None:
                _put(old)
            if new is not None:
                _put(new)
            st["known"][path] = sha_new
            if not _volatile_only(path, old, new):
                _append(st, path, sha_old, sha_new, source, op=op,
                        coalesce=op is None)
            _gc(st)
            _save()
    except Exception as e:                          # noqa: BLE001 — граница
        log.warning("история файлов: не записано (%s): %s"
                    % (display_name(path), e), source="history")


def _observer(path, old, new) -> None:
    record(path, old, new)


def _wants(path: str) -> bool:
    """Для наблюдателя: отслеживается и не крупнее предела.

    Прежнее содержимое ``safe_io`` читает целиком, только если путь
    интересен, — многомегабайтный ipset читать впустую незачем.
    """
    if not is_tracked(path):
        return False
    try:
        return os.path.getsize(path) <= MAX_FILE_BYTES
    except OSError:
        return True                                 # файла ещё нет


def _too_big(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_FILE_BYTES
    except OSError:
        return False


def _read(path: str):
    """Содержимое или ``None`` (нет файла либо он крупнее предела —
    различать через :func:`_too_big`)."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def remove_file(path: str) -> None:
    """``os.remove`` с версией «до удаления» в истории."""
    old = _read(path) if is_tracked(path) else None
    os.remove(path)
    if old is not None:
        record(path, old, None)


def rename_file(src: str, dst: str) -> None:
    """``os.rename`` как удаление ``src`` + создание ``dst``."""
    tracked = is_tracked(src) or is_tracked(dst)
    data = _read(src) if tracked else None
    with operation("Переименован %s → %s" % (
            os.path.basename(src), os.path.basename(dst))):
        os.rename(src, dst)
        if data is not None:
            if is_tracked(src):
                record(src, data, None)
            if is_tracked(dst):
                record(dst, None, data)


def install() -> None:
    """Подписаться на записи ``safe_io`` (один раз за процесс)."""
    global _installed
    if _installed:
        return
    from core.safe_io import add_write_observer
    add_write_observer(_wants, _observer)
    _installed = True


# ─────────────────────────── сверка с диском ────────────────────────────

def scan() -> dict:
    """Найти правки вне GUI: файлы, чей отпечаток не совпал с известным.

    Первый запуск только запоминает отпечатки (истории ещё нет —
    «изменённым» был бы каждый файл).
    """
    if not enabled():
        return {"ok": True, "changed": 0, "disabled": True}
    files = tracked_files()
    current = {}
    for p in files:
        data = _read(p)
        if data is not None:
            current[p] = data
    changed = []
    with _lock:
        st = _load()
        if not st["baselined"]:
            for p, data in current.items():
                st["known"][p] = _put(data)
            st["baselined"] = True
            _gc(st)
            _save()
            return {"ok": True, "changed": 0, "baseline": len(current)}
        paths = set(current) | {p for p, s in st["known"].items() if s}
        op = None
        for p in sorted(paths):
            sha_new = _sha(current.get(p))
            known = st["known"].get(p)
            if sha_new == known:
                continue
            # Прочитано до замка — между чтением и замком GUI мог записать
            # файл (record() уже сменил known). Перечитываем под замком,
            # иначе старое содержимое записалось бы «правкой вне GUI».
            data = _read(p)
            if data is None:
                current.pop(p, None)
            else:
                current[p] = data
            sha_new = _sha(current.get(p))
            if sha_new == known:
                continue
            if p not in current and (not is_tracked(p) or _too_big(p)):
                # Каталог списков переехал в настройках или файл перерос
                # предел — это не «удаление», просто больше не ведём.
                st["known"].pop(p, None)
                continue
            if op is None:
                st["seq"] += 1
                op = {"id": "op-%d" % st["seq"], "label": "",
                      "source": "external"}
            if p in current:
                _put(current[p])
            st["known"][p] = sha_new
            e = _append(st, p, known, sha_new, "external", op=op)
            e["label"] = "Правка вне GUI: %s" % e["file"]
            changed.append(e["file"])
        _gc(st, sweep=True)
        _save()
    if changed:
        log.info("история файлов: правки вне GUI — %s"
                 % ", ".join(changed), source="history")
    return {"ok": True, "changed": len(changed), "files": changed}


class _Scanner:
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="file-history-scan")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                scan()
            except Exception as e:                  # noqa: BLE001 — граница
                log.warning("история файлов: сверка не удалась: %s" % e,
                            source="history")
            self._stop.wait(SCAN_INTERVAL)


def start() -> None:
    """Подписка на записи + фоновая сверка (из загрузки приложения)."""
    global _scanner
    install()
    if _scanner is None:
        _scanner = _Scanner()
    _scanner.start()


# ─────────────────────────── чтение ────────────────────────────

def _public(e: dict) -> dict:
    out = {k: e.get(k) for k in ("id", "ts", "file", "source", "op",
                                 "label")}
    out["sections"] = list(e.get("sections") or [])
    out.update(created=e.get("before") is None,
               deleted=e.get("after") is None,
               undone=bool(e.get("undone")))
    return out


def list_entries(file: str = "", limit: int = 100) -> dict:
    """Версии, новые первыми, сгруппированные по действиям."""
    with _lock:
        entries = list(_load()["entries"])
    if file:
        entries = [e for e in entries if e.get("file") == file]
    entries.reverse()
    ops, order = {}, []
    for e in entries:
        op = e.get("op") or "op-e%s" % e["id"]
        if op not in ops:
            if len(order) >= limit:
                continue
            ops[op] = {"op": op, "ts": e["ts"], "source": e.get("source"),
                       "label": e.get("label", ""), "entries": []}
            order.append(op)
        ops[op]["entries"].append(_public(e))
    groups = [ops[o] for o in order]
    for g in groups:
        if len(g["entries"]) > 1:
            g["label"] = _op_label(g)
    files = sorted({e.get("file") for e in _load()["entries"]})
    return {"ok": True, "groups": groups, "files": files,
            "undo": _undo_candidate_public()}


def _op_label(group: dict) -> str:
    labels = {e["label"] for e in group["entries"]}
    if len(labels) == 1:
        return labels.pop()
    return "%s (файлов: %d)" % (group["entries"][-1]["label"].split(":")[0]
                                if group["source"] == "external"
                                else group["entries"][0]["label"],
                                len(group["entries"]))


def _find(entry_id) -> dict | None:
    try:
        entry_id = int(entry_id)
    except (TypeError, ValueError):
        return None
    for e in _load()["entries"]:
        if e["id"] == entry_id:
            return e
    return None


def _text(data) -> list:
    if data is None:
        return []
    return data.decode("utf-8", errors="replace").splitlines(keepends=True)


def _masked_settings(data):
    """settings.json для показа: секреты маской, как на странице настроек."""
    if data is None:
        return None
    try:
        from core.mcp.redact import redact
        obj = redact(json.loads(data), force=True)
        return json.dumps(obj, indent=2, ensure_ascii=False).encode()
    except Exception:                               # noqa: BLE001
        return b"(settings.json: not JSON)\n"


def diff(entry_id) -> dict:
    """Разница версии с предыдущей (unified diff)."""
    with _lock:
        e = _find(entry_id)
        e = dict(e) if e else None
    if not e:
        return {"ok": False, "error": "версии нет"}
    try:
        before, after = get_object(e["before"]), get_object(e["after"])
    except FileNotFoundError as err:
        return {"ok": False, "error": str(err)}
    if e["path"] == _norm(_cfg().path):
        before, after = _masked_settings(before), _masked_settings(after)
    lines = list(difflib.unified_diff(
        _text(before), _text(after), fromfile="было", tofile="стало", n=2))
    truncated = len(lines) > DIFF_MAX_LINES
    return {"ok": True, "entry": _public(e),
            "diff": "".join(lines[:DIFF_MAX_LINES]),
            "truncated": truncated}


# ─────────────────────────── откат ────────────────────────────

def _file_mode(path: str):
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None if path == _norm(_cfg().path) else 0o644


def _write_version(path: str, data) -> None:
    from core.safe_io import atomic_write_bytes
    if data is None:
        if os.path.exists(path):
            remove_file(path)
        return
    atomic_write_bytes(path, data, mode=_file_mode(path))


def _after_restore(paths) -> list:
    """Перечитать то, что откатили: настройки, стратегии, списки."""
    notes = []
    cfg_path = _norm(_cfg().path)
    kinds = {display_name(p).split("/")[0] for p in paths}
    if cfg_path in paths:
        try:
            _cfg().load()
        except Exception as e:                      # noqa: BLE001
            notes.append("настройки не перечитаны: %s" % e)
    if "strategies" in kinds:
        try:
            from core.strategy_builder import get_strategy_manager
            get_strategy_manager().load_strategies()
        except Exception as e:                      # noqa: BLE001
            notes.append("стратегии не перечитаны: %s" % e)
    if kinds & {"lists", "ipset"}:
        try:
            from core.nfqws_reload import reload_lists
            reload_lists("откат списков")
        except Exception as e:                      # noqa: BLE001
            notes.append("списки не перечитаны движком: %s" % e)
    return notes


def _current_sha(path: str):
    return _sha(_read(path)) if os.path.exists(path) else None


def _same_as(path: str, sha) -> bool:
    """Файл сейчас такой же, как версия ``sha`` (отметки не в счёт)."""
    cur = _read(path) if os.path.exists(path) else None
    if _sha(cur) == sha:
        return True
    try:
        return _volatile_only(path, get_object(sha), cur)
    except FileNotFoundError:
        return False


def _apply(targets: dict, label: str) -> dict:
    """Записать {path: sha|None} одним действием «restore»."""
    written, errors, skipped = [], [], []
    with operation(label, source="restore"):
        for path, sha in targets.items():
            if _too_big(path):
                # Больше не ведётся: текущей версии в истории нет, и
                # затереть её старой — потерять без возврата.
                skipped.append(display_name(path))
                continue
            try:
                _write_version(path, get_object(sha))
                written.append(display_name(path))
            except Exception as e:                  # noqa: BLE001
                errors.append("%s: %s" % (display_name(path), e))
    notes = _after_restore(set(targets)) if written else []
    if written:
        log.info("история файлов: %s — %s" % (label, ", ".join(written)),
                 source="history")
    if skipped:
        notes.append("крупнее %d МБ, не тронуты: %s" % (
            MAX_FILE_BYTES // (1024 * 1024), ", ".join(skipped)))
    return {"ok": not errors, "restored": written, "errors": errors,
            "notes": notes,
            "error": "; ".join(errors) if errors else ""}


def restore(entry_id, side: str = "before") -> dict:
    """Вернуть файл к версии до (``before``) или после (``after``) правки."""
    with _lock:
        e = _find(entry_id)
        e = dict(e) if e else None
    if not e:
        return {"ok": False, "error": "версии нет"}
    sha = e["after"] if side == "after" else e["before"]
    if _current_sha(e["path"]) == sha:
        return {"ok": True, "restored": [], "errors": [], "notes": [],
                "unchanged": True}
    when = time.strftime("%d.%m %H:%M", time.localtime(e["ts"]))
    return _apply({e["path"]: sha}, "Возврат %s к версии %s %s" % (
        e["file"], "до правки" if side != "after" else "от", when))


def _last_op_entries() -> list:
    for e in reversed(_load()["entries"]):
        if e.get("source") == "restore" or e.get("undone"):
            continue
        op = e.get("op")
        return [x for x in _load()["entries"] if x.get("op") == op]
    return []


def _undo_candidate_public():
    with _lock:
        items = _last_op_entries()
    if not items:
        return None
    return {"op": items[0]["op"], "label": items[0].get("label", ""),
            "ts": items[-1]["ts"], "files": [e["file"] for e in items]}


def undo_last() -> dict:
    """Отменить последнее действие (не откат) целиком.

    Если файл после этого действия ещё менялся, отмена его затёрла бы —
    такой файл не трогаем и говорим об этом.
    """
    with _lock:
        items = [dict(e) for e in _last_op_entries()]
    if not items:
        return {"ok": False, "error": "отменять нечего"}
    targets, skipped = {}, []
    # Первое «before» каждого файла в действии — состояние до него.
    first = {}
    last = {}
    for e in items:
        first.setdefault(e["path"], e["before"])
        last[e["path"]] = e["after"]
    for path, sha in first.items():
        if not _same_as(path, last[path]):
            skipped.append(display_name(path))
            continue
        targets[path] = sha
    if not targets:
        return {"ok": False, "skipped": skipped,
                "error": "файлы с тех пор менялись: %s" % ", ".join(skipped)}
    res = _apply(targets, "Отмена: %s" % items[0].get("label", ""))
    with _lock:
        ids = {e["id"] for e in items if e["path"] in targets}
        for e in _load()["entries"]:
            if e["id"] in ids:
                e["undone"] = True
        _save()
    res["skipped"] = skipped
    return res


def versions_at(ts: float, paths=None) -> dict:
    """{path: sha|None} — каким был каждый файл в момент ``ts``.

    Файл без версий после ``ts`` не попадает в ответ: он не менялся.
    """
    out = {}
    with _lock:
        entries = list(_load()["entries"])
    by_path = {}
    for e in entries:
        by_path.setdefault(e["path"], []).append(e)
    for path, items in by_path.items():
        if paths is not None and path not in paths:
            continue
        later = [e for e in items if e["ts"] > ts]
        if not later:
            continue
        out[path] = later[0]["before"]
    return out


def incomplete_since(ts: float, paths=None) -> list:
    """Заметки о файлах, чья история после ``ts`` уже обрезана пределами:
    их «состояние на момент» — самая ранняя сохранённая версия, а не та."""
    with _lock:
        trimmed = dict(_load().get("trimmed") or {})
    return ["история %s обрезана — возвращена самая ранняя сохранённая "
            "версия, а не та, что была на момент" % display_name(p)
            for p, cut in sorted(trimmed.items())
            if cut > ts and (paths is None or p in paths)]


def changed_since(ts: float) -> list:
    """Файлы, которые сейчас не такие, как были в момент ``ts``."""
    return [display_name(p) for p, sha in versions_at(ts).items()
            if _current_sha(p) != sha]


def restore_to_targets(targets: dict, label: str) -> dict:
    """Записать {path: sha|None} одним действием, пропустив совпадающие."""
    targets = {p: sha for p, sha in targets.items()
               if _current_sha(p) != sha}
    if not targets:
        return {"ok": True, "restored": [], "errors": [], "notes": [],
                "unchanged": True}
    return _apply(targets, label)


def restore_to(ts: float, label: str = "") -> dict:
    """Вернуть все отслеживаемые файлы к состоянию на момент ``ts``."""
    return restore_to_targets(
        versions_at(ts), label or "Возврат к состоянию на %s" %
        time.strftime("%d.%m %H:%M", time.localtime(ts)))
