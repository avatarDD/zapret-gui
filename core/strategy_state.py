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

# Lua (z2k-state-persist.lua) считает lock протухшим спустя столько секунд —
# держим то же значение, чтобы протоколы совпадали байт-в-байт.
LOCK_STALE_SEC = 10

_last_clear_time = 0.0
_MIN_CLEAR_INTERVAL = 60.0
_pending_clear_hosts = set()

# Тот же заголовок, который пишет z2k-state-persist.lua — чтобы наш rewrite
# не отличался для глаз и для merge'а в Lua.
_HEADER_LINES = (
    "# z2k autocircular state (persisted circular nstrategy)",
    "# key\thost\tstrategy\tts",
)


_lock = threading.RLock()


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


# ВАЖНО (issue #151). Python и Lua (nfqws2) пишут в ОДИН state.tsv и берут
# ОДИН state.tsv.lock. Lua использует lock-файл с unix-ts внутри: свежий
# (<10s) = «занято другим писателем», протухший = «красть». Раньше Python
# брал на этом же файле fcntl.flock (advisory) — но Lua про flock не знает,
# а после release Python оставлял ПУСТОЙ .lock. Lua читал пустой файл,
# tonumber("")=nil, и его проверка протухания не срабатывала → Lua считал
# лок «занятым навсегда» и больше НЕ МОГ писать state. Итог: после «Сбросить
# всё» / авто-починки (healthcheck) подбор стратегий замирал, сайты не
# грузились, пока .lock не удалят вручную. Теперь Python говорит на ТОМ ЖЕ
# протоколе: пишет ts, крадёт пустой/протухший лок и УДАЛЯЕТ .lock на release.
def _acquire_lock(path: str, timeout: float = 2.0):
    """Взять Lua-совместимый ts-lock на ``path + .lock``.

    Возвращает путь lock-файла при успехе (caller обязан вызвать
    ``_release_lock``), либо None, если лок держит свежий писатель дольше
    ``timeout``."""
    lockfile = _flock_path(path)
    deadline = time.time() + timeout
    while True:
        # Сначала пробуем украсть пустой/битый/протухший lock (как Lua).
        try:
            with open(lockfile, "r") as f:
                content = (f.read() or "").strip()
            try:
                ts = float(content) if content else None
            except ValueError:
                ts = None
            if ts is None or (time.time() - ts) > LOCK_STALE_SEC:
                try:
                    os.remove(lockfile)
                except OSError:
                    pass
            elif time.time() < deadline:
                time.sleep(0.05)
                continue
            else:
                return None          # держит свежий писатель — сдаёмся
        except OSError:
            pass                     # файла нет — свободно
        # Эксклюзивное создание (как Lua "wx"); проигравший в гонке — ждёт.
        try:
            fd = os.open(lockfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            if time.time() < deadline:
                time.sleep(0.05)
                continue
            return None
        except OSError:
            return None
        try:
            os.write(fd, str(int(time.time())).encode("ascii"))
        finally:
            os.close(fd)
        return lockfile


def _release_lock(lockfile):
    """Снять lock — УДАЛИТЬ файл (как release_lock() в Lua). Никогда не
    оставляем пустой .lock, иначе заблокируем Lua-писателя (issue #151)."""
    if lockfile:
        try:
            os.remove(lockfile)
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
    """Записать entries в path атомарно под уже взятым flock'ом."""
    from core.safe_io import atomic_write_text
    try:
        atomic_write_text(path, _serialize(entries))
    except Exception as e:
        log.error("strategy_state._rewrite_locked: %s — %s" % (path, e),
                  source="strategy")


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
            lockfile = None
            try:
                lockfile = _acquire_lock(path)
                if lockfile is None:
                    log.warning("strategy_state.clear_all: lock занят, "
                                "пропускаем %s" % path, source="strategy")
                    continue
                entries = list_entries()
                # Удаляем все, оставляем пустой файл с заголовком — Lua
                # merge_state_file_into прочитает его и не «оживит» удалённое.
                _rewrite_locked(path, [])
                removed += len(entries)
            except OSError as e:
                log.error("strategy_state.clear_all: %s — %s" % (path, e),
                          source="strategy")
            finally:
                _release_lock(lockfile)
        log.info("Очищен autocircular-state (удалено записей: %d)" % removed,
                 source="strategy")
        return {"ok": True, "removed": removed}


def clear_hosts(hosts: list, flush: bool = True) -> dict:
    """Удалить все записи по списку хостов.
    Возвращает словарь {host: removed_count} для переданных хостов.
    """
    if not hosts:
        return {}

    hosts_normalized = {h.lower().rstrip(".") for h in hosts if h}
    if not hosts_normalized:
        return {}

    with _lock:
        _pending_clear_hosts.update(hosts_normalized)

        result_map = {}
        for h in hosts_normalized:
            result_map[h] = 0

        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            try:
                entries = _read_one(path)
                for e in entries:
                    eh = e["host"].lower().rstrip(".")
                    if eh in result_map:
                        result_map[eh] += 1
            except Exception:
                pass

        if flush:
            flush_clear_hosts(force=True)

        return result_map


def clear_host(host: str, flush: bool = True) -> dict:
    """Удалить все записи по конкретному хосту (всех category-key'ов)."""
    if not host:
        return {"ok": False, "error": "пустой host"}
    res = clear_hosts([host], flush=flush)
    host_norm = host.lower().rstrip(".")
    removed = res.get(host_norm, 0)
    return {"ok": True, "removed": removed, "host": host}


def flush_clear_hosts(force: bool = False) -> int:
    """Применить все отложенные сбросы хостов и записать их на диск.

    Если force=True, то записывает мгновенно, игнорируя debounce по времени.
    """
    global _last_clear_time
    with _lock:
        if not _pending_clear_hosts:
            return 0

        now = time.time()
        if not force and (now - _last_clear_time < _MIN_CLEAR_INTERVAL):
            log.info("strategy_state.flush_clear_hosts: запись на диск отложена по debounce (отложено: %d)"
                     % len(_pending_clear_hosts), source="strategy")
            return 0

        to_clear = list(_pending_clear_hosts)
        _pending_clear_hosts.clear()
        _last_clear_time = now

        removed = 0
        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            lockfile = None
            try:
                lockfile = _acquire_lock(path)
                if lockfile is None:
                    log.warning("strategy_state.flush_clear_hosts: lock занят, "
                                "пропускаем %s" % path, source="strategy")
                    continue
                entries = _read_one(path)
                kept = [e for e in entries if e["host"].lower().rstrip(".") not in to_clear]
                _rewrite_locked(path, kept)
                removed += len(entries) - len(kept)
            except OSError as e:
                log.error("strategy_state.flush_clear_hosts: %s — %s" % (path, e),
                          source="strategy")
            finally:
                _release_lock(lockfile)

        log.info("Сброшен autocircular-state для хостов %s (удалено: %d)"
                 % (", ".join(to_clear), removed), source="strategy")
        return removed


def clear_key(key: str) -> dict:
    """Удалить все записи по category-key (yt_tcp / rkn_tcp / default / ...)."""
    if not key:
        return {"ok": False, "error": "пустой key"}
    with _lock:
        removed = 0
        for path in _candidate_files():
            if not os.path.isfile(path):
                continue
            lockfile = None
            try:
                lockfile = _acquire_lock(path)
                if lockfile is None:
                    log.warning("strategy_state.clear_key: lock занят, "
                                "пропускаем %s" % path, source="strategy")
                    continue
                entries = _read_one(path)
                kept = _filter_entries(entries, key=key)
                _rewrite_locked(path, kept)
                removed += len(entries) - len(kept)
            except OSError as e:
                log.error("strategy_state.clear_key: %s — %s" % (path, e),
                          source="strategy")
            finally:
                _release_lock(lockfile)
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
