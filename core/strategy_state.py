# core/strategy_state.py
"""
Persist выученных стратегий (state.tsv от z2k-state-persist.lua).

z2k-state-persist.lua оборачивает функцию `circular` из zapret-auto.lua и
сохраняет на диск номер стратегии (`nstrategy`), которая закрепилась после
успеха на каждом домене. Запись — TSV-файл со строками:

    # key\thost\tstrategy\tts
    default\tyoutube.com\t2\t1704067200
    yt_tcp\tgooglevideo.com\t3\t1704067205

Где:
  - key — askey профиля (`desync.arg.key` из стратегии или `func_instance`);
    группирует state по логическим категориям (yt_tcp, rkn_tcp, default, ...).
  - host — нормализованный SNI/hostname (lowercase, без trailing dot).
  - strategy — номер закреплённой подстратегии в circular (1..N).
  - ts — unix-timestamp последнего успешного применения.

Каталог по умолчанию — `/opt/etc/zapret-gui/state/autocircular/state.tsv`
(см. core/nfqws_manager.Z2K_STATE_DIR; путь передаётся в Lua через env
`Z2K_STATE_DIR_OVERRIDE`). Fallback из самой Lua — `/tmp/...` (volatile).

Этот модуль НИ ЗА ЧТО НЕ ПИШЕТ в файл во время работы nfqws2 — Lua делает
это сам с lock/tmp/rename. Здесь только чтение и атомарная очистка
(rewrite пустого файла или удаление строк) под flock'ом совместимым с Lua.
"""

import errno
import fcntl
import os
import re
import shutil
import threading
import time

from core.log_buffer import log

# Должно совпадать с Z2K_STATE_DIR в core/nfqws_manager.py и Z2K_STATE_DIR в
# шаблоне S99zapret (core/autostart_manager.py). Если меняешь — меняй везде.
DEFAULT_STATE_DIR = "/opt/etc/zapret-gui/state/autocircular"
STATE_FILE_NAME = "state.tsv"
STATE_FILE_FALLBACK = "/tmp/z2k-autocircular-state.tsv"
LOCK_SUFFIX = ".lock"

# Тот же заголовок, который пишет z2k-state-persist.lua — чтобы наш rewrite
# не отличался для глаз и для merge'а в Lua.
_HEADER_LINES = (
    "# z2k autocircular state (persisted circular nstrategy)",
    "# key\thost\tstrategy\tts",
)


_lock = threading.Lock()


def get_state_dir() -> str:
    """Каталог state — из env (как в Lua) или дефолт."""
    return (os.environ.get("Z2K_STATE_DIR_OVERRIDE")
            or DEFAULT_STATE_DIR)


def get_state_file() -> str:
    return os.path.join(get_state_dir(), STATE_FILE_NAME)


def _candidate_files() -> list:
    """Все известные локации файла state — primary + fallback (читаем оба и
    объединяем, как делает Lua при merge_state_file_into)."""
    return [get_state_file(), STATE_FILE_FALLBACK]


def _parse_line(line: str):
    """Распарсить TSV-строку → dict или None для комментариев/пустых.

    Возвращает {"key", "host", "strategy", "ts"} либо None.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split("\t")
    if len(parts) < 4:
        return None
    key, host, strategy, ts = parts[0], parts[1], parts[2], parts[3]
    if not key or not host:
        return None
    try:
        return {
            "key": key,
            "host": host.lower().rstrip("."),
            "strategy": int(strategy),
            "ts": int(ts),
        }
    except (TypeError, ValueError):
        return None


def _serialize(entries: list) -> str:
    """Собрать TSV-текст из списка dict'ов."""
    out = list(_HEADER_LINES)
    for e in entries:
        out.append("\t".join((
            str(e["key"]), str(e["host"]),
            str(int(e["strategy"])), str(int(e["ts"])),
        )))
    return "\n".join(out) + "\n"


def _flock_path(path: str) -> str:
    return path + LOCK_SUFFIX


def _flock_exclusive(lock_path: str):
    """Открыть/создать lock-файл и взять exclusive flock. Возвращает fd."""
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _flock_release(fd: int):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


# ──────────────────────── Public API ────────────────────────

def list_entries() -> list:
    """Прочитать все записи из обоих кандидатов, merge по (key|host) с
    приоритетом более свежего ts.

    Возвращает список dict'ов, отсортированный по host."""
    merged = {}  # (key, host) → entry
    for path in _candidate_files():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                txt = f.read()
        except (OSError, IOError):
            continue
        for line in txt.splitlines():
            e = _parse_line(line)
            if not e:
                continue
            k = (e["key"], e["host"])
            old = merged.get(k)
            if old is None or e["ts"] >= old["ts"]:
                merged[k] = e
    return sorted(merged.values(), key=lambda x: (x["host"], x["key"]))


def get_summary() -> dict:
    """Сводка: сколько всего записей, по каким key, давность max ts."""
    entries = list_entries()
    by_key = {}
    last_ts = 0
    for e in entries:
        by_key[e["key"]] = by_key.get(e["key"], 0) + 1
        if e["ts"] > last_ts:
            last_ts = e["ts"]
    return {
        "total": len(entries),
        "by_key": by_key,
        "last_ts": last_ts,
        "state_file": get_state_file(),
        "state_dir_exists": os.path.isdir(get_state_dir()),
    }


def _rewrite_locked(path: str, entries: list):
    """Записать entries в path атомарно (tmp + rename) под уже взятым flock'ом.

    Так же, как делает z2k-state-persist.lua write_state() — без пути.
    """
    try:
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    except OSError:
        pass
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(_serialize(entries))
        os.rename(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _filter_entries(entries: list, *, host=None, key=None) -> list:
    """Оставить только те записи, что соответствуют фильтру (для delete-
    operations это «то, что НЕ удаляется»)."""
    def keep(e):
        if host is not None and e["host"].lower().rstrip(".") == host:
            return False
        if key is not None and e["key"] == key:
            return False
        return True
    return [e for e in entries if keep(e)]


def clear_all() -> dict:
    """Очистить весь state (оба файла-кандидата)."""
    with _lock:
        removed = 0
        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            fd = None
            try:
                fd = _flock_exclusive(_flock_path(path))
                entries = list_entries()
                # Удаляем все, оставляем пустой файл с заголовком — Lua
                # merge_state_file_into прочитает его и не «оживит» удалённое.
                _rewrite_locked(path, [])
                removed += len(entries)
            except OSError as e:
                log.error("strategy_state.clear_all: %s — %s" % (path, e),
                          source="strategy")
            finally:
                if fd is not None:
                    _flock_release(fd)
        log.info("Очищен autocircular-state (удалено записей: %d)" % removed,
                 source="strategy")
        return {"ok": True, "removed": removed}


def clear_host(host: str) -> dict:
    """Удалить все записи по конкретному хосту (всех category-key'ов)."""
    if not host:
        return {"ok": False, "error": "пустой host"}
    host = host.lower().rstrip(".")
    with _lock:
        removed = 0
        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            fd = None
            try:
                fd = _flock_exclusive(_flock_path(path))
                # Читаем именно из этого файла (без merge), чтобы не
                # размазывать удаление по обоим кандидатам.
                entries = _read_one(path)
                kept = _filter_entries(entries, host=host)
                _rewrite_locked(path, kept)
                removed += len(entries) - len(kept)
            except OSError as e:
                log.error("strategy_state.clear_host: %s — %s" % (path, e),
                          source="strategy")
            finally:
                if fd is not None:
                    _flock_release(fd)
        log.info("Сброшен autocircular-state для host=%s (удалено: %d)"
                 % (host, removed), source="strategy")
        return {"ok": True, "removed": removed, "host": host}


def clear_key(key: str) -> dict:
    """Удалить все записи по category-key (yt_tcp / rkn_tcp / default / ...)."""
    if not key:
        return {"ok": False, "error": "пустой key"}
    with _lock:
        removed = 0
        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            fd = None
            try:
                fd = _flock_exclusive(_flock_path(path))
                entries = _read_one(path)
                kept = _filter_entries(entries, key=key)
                _rewrite_locked(path, kept)
                removed += len(entries) - len(kept)
            except OSError as e:
                log.error("strategy_state.clear_key: %s — %s" % (path, e),
                          source="strategy")
            finally:
                if fd is not None:
                    _flock_release(fd)
        log.info("Сброшен autocircular-state для key=%s (удалено: %d)"
                 % (key, removed), source="strategy")
        return {"ok": True, "removed": removed, "key": key}


def _read_one(path: str) -> list:
    """Прочитать ровно один файл без merge'а (для удаления по конкретному
    источнику)."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                e = _parse_line(line)
                if e:
                    out.append(e)
    except (OSError, IOError):
        pass
    return out


def reload_nfqws() -> dict:
    """Подсказка nfqws2 перечитать state (SIGHUP).

    Lua-state в памяти nfqws2 — отдельный от файла на диске. Чтобы после
    нашего clear_*() Lua не написала обратно из своего in-RAM состояния,
    мы шлём SIGHUP — это nfqws2 интерпретирует как «перечитать хостлисты
    и сбросить кэши». state.tsv Lua заново подхватит при следующей записи.
    """
    pid_files = (
        "/var/run/zapret-gui-nfqws.pid",
        "/var/run/zapret-nfqws.pid",
    )
    for pf in pid_files:
        try:
            with open(pf, "r") as f:
                pid = int((f.read() or "0").strip())
            if pid > 0:
                os.kill(pid, 1)  # SIGHUP
                log.info("SIGHUP → nfqws2 PID %d (reload state)" % pid,
                         source="strategy")
                return {"ok": True, "pid": pid}
        except (OSError, ValueError):
            continue
    return {"ok": False, "error": "nfqws2 не запущен"}
