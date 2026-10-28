# core/flash_saver.py
"""
Снижение записи на постоянную память роутера: что можно держать в ОЗУ
вместо flash и как реже трогать носитель.

Каждый рычаг — отдельная настройка секции ``flash`` (плюс две уже
существующие: ``logging.persist_critical`` и ``history.enabled``), а
профили ``PRESETS`` — просто готовые наборы этих настроек:

  * ``engine_logs_ram`` — логи AWG/sing-box/mihomo в ``/tmp`` (ОЗУ)
    вместо ``/opt/var/log`` (на Entware это flash/USB). На OpenWrt и
    Linux ``/var/log`` и так в ОЗУ — рычаг ничего не меняет. Действует на
    следующий запуск туннеля (открытый файл процесс держит до рестарта).
    Сделано дескриптором :class:`RamLogDir` в платформах Keenetic.
  * ``counters_flush_sec`` — счётчики трафика прокси (опрос раз в 2 с)
    пишутся на диск не чаще этого (``core/proxy_traffic.py``).
  * ``stats_flush_hours`` — статистика записи самого этого раздела
    (``core/flash_wear.py``): копия в ОЗУ всегда, на flash — раз в N ч.
  * ``lazy_writeback`` + ``writeback_sec`` — ядро дольше держит изменённые
    страницы в ОЗУ (``vm.dirty_expire_centisecs`` и
    ``vm.dirty_writeback_centisecs``): повторные перезаписи одного блока
    сливаются в одну. Цена — при пропаже питания теряется до
    ``writeback_sec`` секунд последних изменений.
  * ``noatime`` — перемонтировать постоянные ФС с ``noatime``: чтение
    файла больше не пишет время доступа.
  * ``ext4_commit_sec`` — интервал журнала ext4 (``commit=``; у ядра 5 с).
    Тот же размен «меньше записи ↔ дольше окно потери при сбое питания».

Системные рекомендации (:func:`hints`) — то, что пишет на flash помимо
GUI: своп на постоянном носителе, системный журнал OpenWrt в файл на
flash, логи движков на Entware. Для журнала OpenWrt есть действие
«перенести в ОЗУ» с возвратом прежнего пути.

Что применено ядру и mount — помним в ``/tmp`` (ОЗУ): после
перезагрузки всё возвращается к умолчаниям системы, а boot-хук
``app.py`` (:func:`apply_on_boot`) применяет настройки заново.
"""

import json
import os
import shutil
import subprocess

from core.log_buffer import log

RAM_LOG_DIR = "/tmp/zapret-gui/log"
APPLIED_PATH = "/tmp/zapret-gui/flash-saver.json"

VM_KEYS = ("dirty_expire_centisecs", "dirty_writeback_centisecs")
KERNEL_DEFAULTS = {"dirty_expire_centisecs": 3000,
                   "dirty_writeback_centisecs": 500}
EXT4_DEFAULT_COMMIT = 5

_RAM_FS = ("tmpfs", "ramfs")

# Ключ настройки → (секция, ключ в settings.json).
FIELDS = {
    "engine_logs_ram":    ("flash", "engine_logs_ram"),
    "counters_flush_sec": ("flash", "counters_flush_sec"),
    "stats_enabled":      ("flash", "stats_enabled"),
    "stats_flush_hours":  ("flash", "stats_flush_hours"),
    "lazy_writeback":     ("flash", "lazy_writeback"),
    "writeback_sec":      ("flash", "writeback_sec"),
    "noatime":            ("flash", "noatime"),
    "ext4_commit_sec":    ("flash", "ext4_commit_sec"),
    "nand_endurance":     ("flash", "nand_endurance"),
    "persist_critical":   ("logging", "persist_critical"),
    "persist_min_level":  ("logging", "persist_min_level"),
    "history_enabled":    ("history", "enabled"),
}

DEFAULTS = {
    "engine_logs_ram": False, "counters_flush_sec": 300,
    "stats_enabled": True, "stats_flush_hours": 6,
    "lazy_writeback": False, "writeback_sec": 60,
    "noatime": False, "ext4_commit_sec": 0, "nand_endurance": 0,
    "persist_critical": True, "persist_min_level": "WARNING",
    "history_enabled": True,
}

# Границы целых: (минимум, максимум); 0 — «выключено», где это допустимо.
_BOUNDS = {
    "counters_flush_sec": (2, 86400),
    "stats_flush_hours": (0, 168),
    "writeback_sec": (30, 600),
    "ext4_commit_sec": (0, 600),
    "nand_endurance": (0, 10000000),
}

PRESETS = {
    "normal": {
        "title": "Обычный",
        "desc": "Как система задумала: всё сразу на диск.",
        "values": {"engine_logs_ram": False, "counters_flush_sec": 300,
                   "stats_flush_hours": 6, "lazy_writeback": False,
                   "noatime": False, "ext4_commit_sec": 0,
                   "persist_critical": True, "persist_min_level": "WARNING"},
    },
    "economy": {
        "title": "Экономный",
        "desc": "Логи туннелей в ОЗУ, отложенная запись 60 с, noatime. "
                "При пропаже питания теряется до минуты изменений.",
        "values": {"engine_logs_ram": True, "counters_flush_sec": 600,
                   "stats_flush_hours": 12, "lazy_writeback": True,
                   "writeback_sec": 60, "noatime": True,
                   "ext4_commit_sec": 0, "persist_critical": True,
                   "persist_min_level": "ERROR"},
    },
    "max": {
        "title": "Максимальная экономия",
        "desc": "Всё, что можно, — в ОЗУ: отложенная запись 2 мин, журнал "
                "ext4 раз в 2 мин, критичные события не пишутся на flash.",
        "values": {"engine_logs_ram": True, "counters_flush_sec": 3600,
                   "stats_flush_hours": 24, "lazy_writeback": True,
                   "writeback_sec": 120, "noatime": True,
                   "ext4_commit_sec": 120, "persist_critical": False},
    },
}


# ═══════════════════════════ настройки ═══════════════════════════

def _cm():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _conf(key: str):
    sec, k = FIELDS[key]
    try:
        v = _cm().get(sec, k, default=None)
    except Exception:                                    # noqa: BLE001
        v = None
    return DEFAULTS[key] if v is None else v


def get_settings() -> dict:
    return {k: _conf(k) for k in FIELDS}


def counters_flush_sec() -> int:
    try:
        return max(2, int(_conf("counters_flush_sec")))
    except (TypeError, ValueError):
        return DEFAULTS["counters_flush_sec"]


def normalize(data: dict) -> tuple:
    """Проверить присланные настройки → (значения, ошибки). Чистая функция."""
    out, errors = {}, []
    for key, val in (data or {}).items():
        if key not in FIELDS:
            continue
        default = DEFAULTS[key]
        if isinstance(default, bool):
            out[key] = bool(val)
        elif key == "persist_min_level":
            v = str(val or "").upper()
            if v not in ("WARNING", "ERROR"):
                errors.append("%s: WARNING или ERROR" % key)
                continue
            out[key] = v
        else:
            try:
                v = int(val)
            except (TypeError, ValueError):
                errors.append("%s: нужно целое число" % key)
                continue
            lo, hi = _BOUNDS[key]
            if key == "ext4_commit_sec" and 0 < v < 5:
                v = 5
            if not lo <= v <= hi:
                errors.append("%s: от %d до %d" % (key, lo, hi))
                continue
            out[key] = v
    return out, errors


def save_settings(data: dict) -> dict:
    values, errors = normalize(data)
    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    cm = _cm()
    for key, val in values.items():
        sec, k = FIELDS[key]
        cm.set(sec, k, val)
    if not cm.save():
        return {"ok": False, "error": "настройки не сохранились"}
    result = apply()
    try:
        from core.log_buffer import reconfigure_persistent_from_config
        reconfigure_persistent_from_config()
    except Exception:                                    # noqa: BLE001
        pass
    try:
        from core.flash_wear import get_flash_stats
        get_flash_stats().reconfigure()
    except Exception:                                    # noqa: BLE001
        pass
    result["settings"] = get_settings()
    return result


# ═══════════════════════════ логи движков ═══════════════════════════

def _mounts(root: str = "") -> list:
    from core.flash_wear import parse_mounts, _read
    return parse_mounts(_read(root + "/proc/mounts"))


def mount_of(path: str, mounts: list) -> dict:
    """Самая длинная точка монтирования, под которой лежит ``path``."""
    path = os.path.abspath(path or "/")
    best = None
    for m in mounts:
        mnt = m["mnt"]
        if path == mnt or path.startswith(mnt.rstrip("/") + "/") or mnt == "/":
            if best is None or len(mnt) > len(best["mnt"]):
                best = m
    return best or {}


def is_ram_path(path: str, mounts=None) -> bool:
    """Лежит ли путь в ОЗУ (tmpfs/ramfs). /var на OpenWrt — ссылка на /tmp."""
    try:
        real = os.path.realpath(path)
    except OSError:
        real = path
    mounts = mounts if mounts is not None else _mounts()
    return mount_of(real, mounts).get("fstype") in _RAM_FS


def engine_log_dir(default: str) -> str:
    """Каталог логов движка с учётом ``flash.engine_logs_ram``."""
    try:
        if _conf("engine_logs_ram") and not is_ram_path(default):
            os.makedirs(RAM_LOG_DIR, exist_ok=True)
            return RAM_LOG_DIR
    except Exception:                                    # noqa: BLE001
        pass
    return default


class RamLogDir:
    """Дескриптор ``log_dir`` платформы: ``/opt/var/log`` или ОЗУ по
    настройке. Читается при каждом обращении — смена настройки действует
    без перезапуска GUI (на следующий старт туннеля)."""

    def __init__(self, default: str):
        self.default = default

    def __get__(self, obj, owner=None):
        return engine_log_dir(self.default)


# ═══════════════════════════ ядро и mount ═══════════════════════════

def writeback_values(sec: int) -> dict:
    """Секунды отложенной записи → значения ``vm.*`` (сотые доли секунды).
    Поток сброса просыпается вчетверо чаще срока, но не чаще ядерных 5 с."""
    expire = max(30, int(sec)) * 100
    return {"dirty_expire_centisecs": expire,
            "dirty_writeback_centisecs": max(500, expire // 4)}


def remount_plan(mounts: list, persistent_mnts, want_noatime: bool,
                 commit: int, applied: dict) -> list:
    """Что перемонтировать: [(точка, опции, что_отметить)]. Чистая функция.

    Возврат делаем только для того, что меняли сами (``applied``), —
    чужой ``noatime`` из fstab не трогаем.
    """
    plan = []
    was_noatime = set(applied.get("noatime") or [])
    was_commit = set(applied.get("commit") or [])
    for m in mounts:
        mnt = m["mnt"]
        if mnt not in persistent_mnts or not m.get("rw"):
            continue
        opts = []
        has_noatime = "noatime" in m.get("opts", [])
        if want_noatime and not has_noatime:
            opts.append("noatime")
        elif not want_noatime and mnt in was_noatime:
            opts.append("relatime")
        if m.get("fstype") == "ext4":
            cur = [o for o in m.get("opts", []) if o.startswith("commit=")]
            cur = cur[0].split("=", 1)[1] if cur else ""
            if commit and cur != str(commit):
                opts.append("commit=%d" % commit)
            elif not commit and mnt in was_commit:
                opts.append("commit=%d" % EXT4_DEFAULT_COMMIT)
        if opts:
            plan.append((mnt, ",".join(opts)))
    return plan


def _load_applied() -> dict:
    try:
        with open(APPLIED_PATH, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_applied(st: dict) -> None:
    try:
        os.makedirs(os.path.dirname(APPLIED_PATH), exist_ok=True)
        with open(APPLIED_PATH, "w", encoding="utf-8") as f:
            json.dump(st, f)
    except OSError:
        pass


def _read_vm(key: str):
    try:
        with open("/proc/sys/vm/" + key) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _write_vm(key: str, value: int) -> bool:
    try:
        with open("/proc/sys/vm/" + key, "w") as f:
            f.write(str(int(value)))
        return True
    except OSError:
        return False


def _remount(mnt: str, opts: str) -> str:
    """Перемонтировать; пусто — успех, иначе текст ошибки."""
    try:
        r = subprocess.run(["mount", "-o", "remount," + opts, mnt],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return str(e)
    return "" if r.returncode == 0 else (r.stderr or r.stdout or
                                         "код %d" % r.returncode).strip()


def _persistent_mounts() -> set:
    from core.flash_wear import discover
    return {m["mnt"] for d in discover(smart=False) for m in d["mounts"]}


def apply() -> dict:
    """Привести ядро и mount в соответствие настройкам (идемпотентно)."""
    st = get_settings()
    applied = _load_applied()
    done, errors = [], []

    # ─── отложенная запись ядра ───
    orig = dict(applied.get("vm_orig") or {})
    if st["lazy_writeback"]:
        want = writeback_values(st["writeback_sec"])
        for key, val in want.items():
            cur = _read_vm(key)
            if cur is None:
                errors.append("vm.%s недоступен" % key)
                continue
            if key not in orig:
                orig[key] = cur
            if cur != val:
                if _write_vm(key, val):
                    done.append("vm.%s=%d" % (key, val))
                else:
                    errors.append("vm.%s: нет прав на запись" % key)
        applied["vm_orig"] = orig
    elif orig:
        for key in VM_KEYS:
            val = orig.get(key, KERNEL_DEFAULTS[key])
            if _read_vm(key) != val and _write_vm(key, val):
                done.append("vm.%s=%d (вернули)" % (key, val))
        applied.pop("vm_orig", None)

    # ─── noatime и commit ───
    try:
        mounts = _mounts()
        plan = remount_plan(mounts, _persistent_mounts(), st["noatime"],
                            int(st["ext4_commit_sec"] or 0), applied)
    except Exception as e:                               # noqa: BLE001
        plan, mounts = [], []
        errors.append("список ФС: %s" % e)
    noat = set(applied.get("noatime") or [])
    comm = set(applied.get("commit") or [])
    for mnt, opts in plan:
        err = _remount(mnt, opts)
        if err:
            errors.append("%s: %s" % (mnt, err))
            continue
        done.append("%s: %s" % (mnt, opts))
        for o in opts.split(","):
            if o == "noatime":
                noat.add(mnt)
            elif o == "relatime":
                noat.discard(mnt)
            elif o == "commit=%d" % EXT4_DEFAULT_COMMIT and \
                    not st["ext4_commit_sec"]:
                comm.discard(mnt)
            elif o.startswith("commit="):
                comm.add(mnt)
    applied["noatime"] = sorted(noat)
    applied["commit"] = sorted(comm)
    _save_applied(applied)
    if done:
        log.info("снижение записи на flash: %s" % ", ".join(done),
                 source="flash")
    for e in errors:
        log.warning("снижение записи на flash: %s" % e, source="flash")
    return {"ok": not errors, "applied": done, "errors": errors}


def apply_on_boot() -> None:
    st = get_settings()
    if st["lazy_writeback"] or st["noatime"] or st["ext4_commit_sec"]:
        apply()


def state() -> dict:
    """Что действует сейчас (для показа рядом с настройками)."""
    vm = {k: _read_vm(k) for k in VM_KEYS}
    mounts = []
    try:
        pers = _persistent_mounts()
        for m in _mounts():
            if m["mnt"] in pers:
                commit = [o.split("=", 1)[1] for o in m["opts"]
                          if o.startswith("commit=")]
                mounts.append({"mnt": m["mnt"], "fstype": m["fstype"],
                               "noatime": "noatime" in m["opts"],
                               "commit": int(commit[0]) if commit else None})
    except Exception:                                    # noqa: BLE001
        pass
    return {"vm": vm, "mounts": mounts,
            "engine_log_dir": _engine_log_dir_now()}


def _engine_log_dir_now() -> dict:
    try:
        from core.singbox_platform import detect_singbox_platform
        d = detect_singbox_platform().log_dir
        return {"path": d, "ram": is_ram_path(d)}
    except Exception:                                    # noqa: BLE001
        return {}


# ═══════════════════════════ системные подсказки ═══════════════════════════

def parse_swaps(text: str) -> list:
    out = []
    for line in (text or "").splitlines()[1:]:
        p = line.split()
        if len(p) >= 3:
            out.append({"name": p[0], "type": p[1]})
    return out


def _uci_get(key: str) -> str:
    exe = shutil.which("uci")
    if not exe:
        return ""
    try:
        r = subprocess.run([exe, "-q", "get", key], capture_output=True,
                           text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def _dir_size(path: str) -> int:
    total = 0
    try:
        for name in os.listdir(path):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                total += os.path.getsize(p)
    except OSError:
        pass
    return total


def hints() -> list:
    """Что ещё пишет на flash и что с этим сделать."""
    out = []
    mounts = _mounts()
    from core.flash_wear import _read
    for sw in parse_swaps(_read("/proc/swaps")):
        if "zram" in sw["name"]:
            continue
        out.append({"id": "swap", "level": "warn",
                    "text": "Своп на постоянном носителе (%s): при нехватке "
                            "ОЗУ ядро постоянно пишет туда страницы. Лучше "
                            "zram или своп на отдельной USB-флешке."
                            % sw["name"]})
    log_file = _uci_get("system.@system[0].log_file")
    if log_file and not is_ram_path(os.path.dirname(log_file) or "/", mounts):
        out.append({"id": "syslog", "level": "warn",
                    "text": "Системный журнал OpenWrt пишется в файл на "
                            "flash (%s)." % log_file,
                    "action": "syslog_ram",
                    "action_label": "Перенести журнал в ОЗУ"})
    try:
        cm = _cm()
        prev = cm.get("flash", "syslog_prev_file", default="")
    except Exception:                                    # noqa: BLE001
        prev = ""
    if prev and not log_file:
        out.append({"id": "syslog_moved", "level": "ok",
                    "text": "Системный журнал перенесён в ОЗУ (раньше: %s)."
                            % prev,
                    "action": "syslog_restore",
                    "action_label": "Вернуть как было"})
    if not _conf("engine_logs_ram"):
        for d in ("/opt/var/log",):
            if os.path.isdir(d) and not is_ram_path(d, mounts):
                size = _dir_size(d)
                out.append({"id": "engine_logs", "level": "info",
                            "text": "Логи туннелей и Entware-сервисов лежат "
                                    "в %s на постоянном носителе (сейчас "
                                    "%.1f МБ). Включите «Логи туннелей в "
                                    "ОЗУ»." % (d, size / 1048576.0)})
    if _conf("persist_critical"):
        out.append({"id": "critical_log", "level": "info",
                    "text": "Журнал критичных событий пишется на flash — "
                            "это немного (только предупреждения и ошибки), "
                            "зато он переживает перезагрузку."})
    return out


def action(name: str) -> dict:
    """Действия из подсказок (только обратимые)."""
    exe = shutil.which("uci")
    if name == "syslog_ram":
        if not exe:
            return {"ok": False, "error": "uci не найден (не OpenWrt)"}
        prev = _uci_get("system.@system[0].log_file")
        if not prev:
            return {"ok": True, "message": "журнал уже в ОЗУ"}
        cmds = [[exe, "delete", "system.@system[0].log_file"],
                [exe, "commit", "system"]]
        cm = _cm()
        cm.set("flash", "syslog_prev_file", prev)
        cm.save()
    elif name == "syslog_restore":
        if not exe:
            return {"ok": False, "error": "uci не найден (не OpenWrt)"}
        cm = _cm()
        prev = cm.get("flash", "syslog_prev_file", default="")
        if not prev:
            return {"ok": False, "error": "прежний путь неизвестен"}
        cmds = [[exe, "set", "system.@system[0].log_file=%s" % prev],
                [exe, "commit", "system"]]
        cm.set("flash", "syslog_prev_file", "")
        cm.save()
    else:
        return {"ok": False, "error": "неизвестное действие"}
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:
            return {"ok": False, "error": str(e)}
        if r.returncode != 0:
            return {"ok": False, "error": (r.stderr or "").strip()
                    or "код %d" % r.returncode}
    if os.path.exists("/etc/init.d/log"):
        try:
            subprocess.run(["/etc/init.d/log", "restart"],
                           capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
    log.info("системный журнал: %s" % name, source="flash")
    return {"ok": True}
