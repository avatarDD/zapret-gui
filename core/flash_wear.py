# core/flash_wear.py
"""
Износ постоянной памяти роутера и объём записи на неё.

Что умеет (на любом Linux-роутере, без сторонних утилит):

  * найти носители, на которых лежат постоянные файловые системы
    (``/proc/mounts`` → блочное устройство или UBI/MTD);
  * показать износ там, где носитель его сообщает:
      - eMMC 5.0+ — ``/sys/block/mmcblkN/device/life_time`` (две шкалы,
        шаг 10 %) и ``pre_eol_info`` (расход резервных блоков);
      - UBI на «сыром» NAND — ``max_ec`` (сколько раз стёрт самый
        изношенный блок) и число плохих блоков; процент — только оценка
        против ресурса стирания (``flash.nand_endurance``);
      - SSD/NVMe — через ``smartctl``, если он установлен;
      - SD-карты, USB-флешки, NOR — износ не сообщают, честно так и пишем;
  * считать, сколько записано: счётчик секторов ``/proc/diskstats``
    (ядро ведёт его с загрузки) → дельты раз в минуту → корзины по дням,
    из них — сутки, месяц, последние 30 дней. У ФС ext4/f2fs отдельно —
    ``lifetime_write_kbytes`` (за всю жизнь ФС);
  * «кто пишет» — ``/proc/<pid>/io`` (``write_bytes`` минус
    ``cancelled_write_bytes``), если ядро ведёт учёт по процессам.

Где хранится статистика (сама не должна изнашивать flash):
  ``/tmp/zapret-gui/flash-stats.json`` — копия в ОЗУ, пишется при каждом
  замере (переживает перезапуск GUI, но не перезагрузку);
  ``<config_dir>/flash-stats.json`` — на постоянном носителе, раз в
  ``flash.stats_flush_hours`` часов и при штатной остановке GUI (SIGTERM
  при перезагрузке роутера). 0 — на flash не пишем вовсе.

Чистые функции (``parse_*``, ``emmc_wear``, ``ubi_wear``, ``account``,
``summarize``) тестируются без железа; ввод-вывод — через ``root``
(префикс к ``/proc`` и ``/sys``) — его подменяют тесты.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import time

from core.log_buffer import log

SAMPLE_SEC = 60
KEEP_DAYS = 400
RAM_STATE = "/tmp/zapret-gui/flash-stats.json"
STATE_NAME = "flash-stats.json"
SECTOR = 512                    # /proc/diskstats всегда в 512-байтных секторах

# ФС, которые живут в ОЗУ или служебные, — не носитель.
_VIRTUAL_FS = {
    "tmpfs", "ramfs", "proc", "sysfs", "devtmpfs", "devpts", "cgroup",
    "cgroup2", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
    "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "binfmt_misc",
    "overlay", "overlayfs", "rootfs", "nsfs", "efivarfs", "selinuxfs",
    "rpc_pipefs", "nfsd", "zram", "squashfs", "iso9660", "nfs", "nfs4",
    "cifs", "smb3", "fuse.sshfs",
}

# Ресурс стирания блока NAND по типу (оценка «по худшему блоку»).
NAND_ENDURANCE = {"nand": 100000, "mlc-nand": 3000, "nor": 100000}


# ═══════════════════════════ чистые разборщики ═══════════════════════════

def _unescape(s: str) -> str:
    # /proc/mounts экранирует пробел и пр. как \040.
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_mounts(text: str) -> list:
    """``/proc/mounts`` → [{dev, mnt, fstype, opts:[…], rw}]."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        opts = parts[3].split(",")
        out.append({"dev": _unescape(parts[0]), "mnt": _unescape(parts[1]),
                    "fstype": parts[2], "opts": opts, "rw": "rw" in opts})
    return out


def parse_diskstats(text: str) -> dict:
    """``/proc/diskstats`` → {имя: {"read": байт, "written": байт,
    "writes": операций}}."""
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) < 10:
            continue
        try:
            out[p[2]] = {"read": int(p[5]) * SECTOR,
                         "writes": int(p[7]),
                         "written": int(p[9]) * SECTOR}
        except ValueError:
            continue
    return out


def disk_of(name: str) -> str:
    """Имя раздела → имя диска (по образцу, когда sysfs не помог):
    mmcblk0p5 → mmcblk0, sda1 → sda, nvme0n1p2 → nvme0n1."""
    m = re.match(r"^(mmcblk\d+|nvme\d+n\d+)(p\d+)?$", name)
    if m:
        return m.group(1)
    m = re.match(r"^((?:sd|vd|hd|xvd)[a-z]+)\d*$", name)
    if m:
        return m.group(1)
    return name


def source_of(dev: str, fstype: str) -> dict:
    """Источник монтирования → {kind: block|ubi|mtd, name}.

    ``/dev/mmcblk0p5`` → block mmcblk0p5; ``ubi0:rootfs_data``,
    ``/dev/ubi0_1`` → ubi ubi0; ``/dev/mtdblock6`` (jffs2) → mtd mtd6.
    """
    if fstype == "ubifs" or dev.startswith("ubi"):
        m = re.match(r"^(?:/dev/)?ubi(\d+)", dev)
        if m:
            return {"kind": "ubi", "name": "ubi" + m.group(1)}
    if fstype == "jffs2" or "mtdblock" in dev:
        m = re.search(r"mtd(?:block)?(\d+)", dev)
        if m:
            return {"kind": "mtd", "name": "mtd" + m.group(1)}
    if dev.startswith("/dev/"):
        name = os.path.basename(dev)
        if name.startswith(("ubiblock", "ram", "zram", "nbd")):
            return {}
        return {"kind": "block", "name": name}
    return {}


def _hex(v: str):
    try:
        return int(str(v).strip(), 16)
    except (TypeError, ValueError):
        return None


def emmc_wear(life_time: str, pre_eol: str) -> dict:
    """Разбор ``life_time`` («0x01 0x02») и ``pre_eol_info`` (JEDEC eMMC 5.0).

    Шкала 0x01…0x0A — «израсходовано 0–10 % … 90–100 %», 0x0B — ресурс
    исчерпан, 0x00 — не определено. Тип A — SLC-область, тип B — MLC
    (обычно главная). Итоговый процент — верхняя граница худшей шкалы.
    """
    def band(v):
        if v is None or v == 0:
            return None
        if v >= 0x0B:
            return {"min": 100, "max": 100, "exceeded": True}
        return {"min": (v - 1) * 10, "max": v * 10, "exceeded": False}

    vals = [_hex(x) for x in (life_time or "").split()]
    a = band(vals[0]) if vals else None
    b = band(vals[1]) if len(vals) > 1 else None
    eol = _hex(pre_eol)
    eol_text = {1: "норма", 2: "предупреждение: израсходовано 80 % резерва",
                3: "срочно: резерв почти исчерпан"}.get(eol, "")
    bands = [x for x in (a, b) if x]
    if not bands and not eol_text:
        return {}
    worst = max(bands, key=lambda x: x["max"]) if bands else None
    percent = worst["max"] if worst else None
    level = "ok"
    if (eol or 0) >= 3 or (percent or 0) >= 90:
        level = "bad"
    elif (eol or 0) == 2 or (percent or 0) >= 70:
        level = "warn"
    return {"source": "emmc", "type_a": a, "type_b": b,
            "pre_eol": eol, "pre_eol_text": eol_text,
            "percent": percent,
            "percent_range": [worst["min"], worst["max"]] if worst else None,
            "exact": False, "level": level}


def ubi_wear(max_ec, bad_peb, reserved_bad, endurance: int) -> dict:
    """Оценка износа UBI по худшему блоку: ``max_ec / endurance``."""
    try:
        max_ec = int(max_ec)
    except (TypeError, ValueError):
        return {}
    pct = None
    if endurance and endurance > 0:
        pct = round(min(100.0, max_ec * 100.0 / endurance), 2)
    level = "ok"
    if (pct or 0) >= 90:
        level = "bad"
    elif (pct or 0) >= 70:
        level = "warn"
    try:
        bad = int(bad_peb)
        res = int(reserved_bad)
        if res > 0 and bad >= res:
            level = "bad"
        elif res > 0 and bad * 2 >= res and level == "ok":
            level = "warn"
    except (TypeError, ValueError):
        bad = res = None
    return {"source": "ubi", "max_ec": max_ec, "endurance": endurance,
            "bad_blocks": bad, "reserved_for_bad": res,
            "percent": pct, "exact": False, "level": level}


def parse_smart(text: str) -> dict:
    """Вывод ``smartctl -A`` → {percent (израсходовано), written}."""
    text = text or ""
    m = re.search(r"Percentage Used:\s+(\d+)%", text)
    if m:                                    # NVMe
        out = {"source": "smart", "percent": int(m.group(1)), "exact": True}
        w = re.search(r"Data Units Written:\s+([\d,]+)", text)
        if w:
            out["written"] = int(w.group(1).replace(",", "")) * 512000
        return _smart_level(out)
    for line in text.splitlines():
        p = line.split()
        if len(p) < 10 or not p[0].isdigit():
            continue
        aid, value = int(p[0]), p[3]
        if aid in (177, 231, 233, 202, 169, 173) and value.isdigit():
            # VALUE — «сколько осталось» по нормированной шкале 100→0.
            left = int(value)
            if 0 <= left <= 100:
                return _smart_level({"source": "smart",
                                     "percent": 100 - left, "exact": True,
                                     "attribute": p[1]})
    return {}


def _smart_level(out: dict) -> dict:
    p = out.get("percent") or 0
    out["level"] = "bad" if p >= 90 else ("warn" if p >= 70 else "ok")
    return out


def parse_proc_io(text: str) -> int:
    """``/proc/<pid>/io`` → чистые байты на носитель (с вычетом отменённых)."""
    vals = {}
    for line in (text or "").splitlines():
        k, _, v = line.partition(":")
        try:
            vals[k.strip()] = int(v.strip())
        except ValueError:
            continue
    if "write_bytes" not in vals:
        return -1
    return max(0, vals["write_bytes"] - vals.get("cancelled_write_bytes", 0))


# ═══════════════════════════ учёт по дням ═══════════════════════════

def day_key(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def account(state: dict, counters: dict, boot_id: str, ts: float) -> dict:
    """Добавить замер счётчиков ``{устройство: байт с загрузки}`` в состояние.

    Дельта к прошлому замеру уходит в корзину дня ``ts``. Новая загрузка
    (другой ``boot_id``) или счётчик меньше прежнего (перезагрузка,
    переполнение 32-битного счётчика) — базой служит ноль: всё, что
    накоплено с загрузки, и есть новая запись. Чистая функция.
    """
    state = dict(state or {})
    days = dict(state.get("days") or {})
    last = dict(state.get("last") or {})
    if state.get("boot_id") != boot_id:
        last = {}
    key = day_key(ts)
    bucket = dict(days.get(key) or {})
    for dev, cur in counters.items():
        prev = last.get(dev)
        delta = cur - prev if (prev is not None and cur >= prev) else cur
        if delta > 0:
            bucket[dev] = int(bucket.get(dev, 0)) + int(delta)
        last[dev] = cur
    if bucket:
        days[key] = bucket
    if len(days) > KEEP_DAYS:
        for k in sorted(days)[:len(days) - KEEP_DAYS]:
            days.pop(k, None)
    state.update({"version": 1, "boot_id": boot_id, "last": last,
                  "days": days, "updated": ts})
    state.setdefault("since", ts)
    return state


def summarize(days: dict, devs, now: float) -> dict:
    """Корзины дней → today/yesterday/month/prev_month/last30/avg_day/series."""
    devs = set(devs) if devs is not None else None

    def total(bucket):
        return sum(int(v) for d, v in (bucket or {}).items()
                   if devs is None or d in devs)

    today = day_key(now)
    yesterday = day_key(now - 86400)
    month = today[:7]
    lt = time.localtime(now)
    pm = (lt.tm_year, lt.tm_mon - 1) if lt.tm_mon > 1 else (lt.tm_year - 1, 12)
    prev_month = "%04d-%02d" % pm
    series = []
    for i in range(29, -1, -1):
        k = day_key(now - i * 86400)
        series.append({"day": k, "bytes": total(days.get(k))})
    m_sum = sum(total(b) for k, b in days.items() if k.startswith(month))
    pm_sum = sum(total(b) for k, b in days.items()
                 if k.startswith(prev_month))
    full = [s["bytes"] for s in series[:-1] if s["day"] in days]
    return {
        "today": total(days.get(today)),
        "yesterday": total(days.get(yesterday)),
        "month": m_sum,
        "prev_month": pm_sum,
        "last30": sum(s["bytes"] for s in series),
        "avg_day": int(sum(full) / len(full)) if full else None,
        "days_counted": len(full),
        "series": series,
    }


# ═══════════════════════════ ввод-вывод ═══════════════════════════

def _read(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def _sys(root: str, *parts) -> str:
    return _read(os.path.join(root + "/sys", *parts)).strip()


def _disk_name(root: str, part: str) -> str:
    """Раздел → диск по sysfs (``/sys/class/block/<x>/partition``)."""
    base = root + "/sys/class/block/" + part
    if os.path.exists(base + "/partition"):
        try:
            return os.path.basename(os.path.dirname(os.path.realpath(base)))
        except OSError:
            pass
    if os.path.isdir(base):
        return part
    return disk_of(part)


def _resolve_block(root: str, name: str, mounts: list, depth: int = 0) -> str:
    """Устройство, на которое реально идёт запись: ``/dev/root`` → раздел,
    ``loop0`` → устройство его backing-файла (OpenWrt на eMMC держит
    ``/overlay`` на loop-устройстве поверх раздела rootfs)."""
    if depth > 3:
        return name
    if name == "root":
        real = os.path.basename(os.path.realpath(root + "/dev/root"))
        if real and real != "root":
            return real
        m = re.search(r"\broot=/dev/(\S+)", _read(root + "/proc/cmdline"))
        return m.group(1) if m else name
    if name.startswith("loop"):
        back = _sys(root, "block", name, "loop", "backing_file")
        if back.startswith("/dev/"):
            return _resolve_block(root, os.path.basename(back), mounts,
                                  depth + 1)
        if back:
            best = None
            for m in mounts:
                mnt = m["mnt"].rstrip("/") + "/"
                if back.startswith(mnt) and m["dev"].startswith("/dev/") \
                        and (best is None or len(mnt) > len(best["mnt"])):
                    best = m
            if best:
                return _resolve_block(root, os.path.basename(best["dev"]),
                                      mounts, depth + 1)
        return ""
    return name


def _block_kind(root: str, disk: str) -> str:
    if disk.startswith("mmcblk"):
        t = _sys(root, "block", disk, "device", "type").upper()
        return "sd" if t == "SD" else "emmc"
    if disk.startswith("nvme"):
        return "nvme"
    try:
        real = os.path.realpath(root + "/sys/block/" + disk)
    except OSError:
        real = ""
    if "/usb" in real:
        return "usb"
    if _sys(root, "block", disk, "queue", "rotational") == "1":
        return "hdd"
    return "ssd" if disk.startswith("sd") else "block"


KIND_LABEL = {
    "emmc": "eMMC", "sd": "SD-карта", "usb": "USB-накопитель",
    "nvme": "NVMe SSD", "ssd": "SSD/SATA", "hdd": "жёсткий диск",
    "block": "блочное устройство", "ubi": "NAND (UBI)", "mtd": "flash (MTD)",
}


def _mtd_info(root: str, num: str) -> dict:
    base = ("class", "mtd", "mtd" + num)
    return {"mtd_type": _sys(root, *base, "type"),
            "mtd_name": _sys(root, *base, "name"),
            "size": _int(_sys(root, *base, "size")),
            "bad_blocks": _int(_sys(root, *base, "bad_blocks")),
            "ecc_corrected": _int(_sys(root, *base, "corrected_bits")),
            "ecc_failures": _int(_sys(root, *base, "ecc_failures"))}


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _endurance(mtd_type: str) -> int:
    try:
        from core.config_manager import get_config_manager
        v = int(get_config_manager().get("flash", "nand_endurance",
                                         default=0) or 0)
        if v > 0:
            return v
    except Exception:                                    # noqa: BLE001
        pass
    return NAND_ENDURANCE.get((mtd_type or "nand").lower(), 100000)


def _smart(disk: str) -> dict:
    exe = shutil.which("smartctl")
    if not exe:
        return {}
    try:
        r = subprocess.run([exe, "-A", "/dev/" + disk], capture_output=True,
                           text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_smart(r.stdout)


def discover(root: str = "", smart: bool = True) -> list:
    """Носители с постоянными ФС: [{id, kind, label, model, size, mounts,
    wear, writes_supported}]. ``id`` — ключ в статистике записи."""
    mounts = parse_mounts(_read(root + "/proc/mounts"))
    stats = parse_diskstats(_read(root + "/proc/diskstats"))
    devs = {}
    for m in mounts:
        # Только перезаписываемые ФС: ro-раздел носитель не изнашивает.
        if not m["rw"] or m["fstype"] in _VIRTUAL_FS \
                or m["fstype"].startswith("fuse"):
            continue
        src = source_of(m["dev"], m["fstype"])
        if not src:
            continue
        if src["kind"] == "block":
            part = _resolve_block(root, src["name"], mounts)
            if not part:
                continue
            dev_id = _disk_name(root, part)
        else:
            dev_id = src["name"]
        d = devs.setdefault(dev_id, {"id": dev_id, "source": src["kind"],
                                     "mounts": []})
        lifetime = _fs_lifetime(root, m["fstype"], src.get("name", ""))
        d["mounts"].append({"mnt": m["mnt"], "fstype": m["fstype"],
                            "dev": m["dev"], "rw": m["rw"],
                            "noatime": "noatime" in m["opts"],
                            "lifetime_written": lifetime})
    out = []
    for dev_id, d in devs.items():
        info = {"id": dev_id, "mounts": d["mounts"], "wear": {}}
        if d["source"] == "block":
            kind = _block_kind(root, dev_id)
            info["kind"] = kind
            info["size"] = (_int(_sys(root, "block", dev_id, "size")) or 0) * 512
            if kind in ("emmc", "sd"):
                info["model"] = _sys(root, "block", dev_id, "device", "name")
                info["wear"] = emmc_wear(
                    _sys(root, "block", dev_id, "device", "life_time"),
                    _sys(root, "block", dev_id, "device", "pre_eol_info"))
            else:
                info["model"] = (_sys(root, "block", dev_id, "device", "model")
                                 or _sys(root, "block", dev_id, "device", "name"))
                if smart and kind in ("ssd", "nvme", "hdd") and not root:
                    info["wear"] = _smart(dev_id)
            info["writes_supported"] = dev_id in stats
            info["written_since_boot"] = (stats.get(dev_id) or {}).get("written")
        elif d["source"] == "ubi":
            info["kind"] = "ubi"
            base = ("class", "ubi", dev_id)
            mtd_num = _sys(root, *base, "mtd_num")
            mtd = _mtd_info(root, mtd_num) if mtd_num else {}
            info["model"] = mtd.get("mtd_name") or ""
            ebs = _int(_sys(root, *base, "eraseblock_size")) or 0
            info["size"] = (_int(_sys(root, *base, "total_eraseblocks")) or 0) * ebs
            info["wear"] = ubi_wear(_sys(root, *base, "max_ec"),
                                    _sys(root, *base, "bad_peb_count"),
                                    _sys(root, *base, "reserved_for_bad"),
                                    _endurance(mtd.get("mtd_type")))
            info["mtd"] = mtd
            info["writes_supported"] = False
        else:
            info["kind"] = "mtd"
            mtd = _mtd_info(root, dev_id[3:])
            info["model"] = mtd.get("mtd_name") or ""
            info["size"] = mtd.get("size")
            info["mtd"] = mtd
            info["writes_supported"] = False
        info["label"] = KIND_LABEL.get(info["kind"], info["kind"])
        if not info["wear"]:
            info["wear"] = {"source": "none", "level": "unknown"}
        out.append(info)
    out.sort(key=lambda x: (not any(m["mnt"] in ("/", "/overlay", "/opt")
                                    for m in x["mounts"]), x["id"]))
    return out


def _fs_lifetime(root: str, fstype: str, part: str):
    """ext4/f2fs: записано ФС за всё время её жизни, байт."""
    if fstype not in ("ext4", "f2fs") or not part:
        return None
    v = _int(_sys(root, "fs", fstype, part, "lifetime_write_kbytes"))
    return v * 1024 if v is not None else None


def counters(root: str = "", devices=None) -> dict:
    """{id: байт записано с загрузки} для носителей со счётчиком."""
    stats = parse_diskstats(_read(root + "/proc/diskstats"))
    devices = devices if devices is not None else discover(root, smart=False)
    return {d["id"]: stats[d["id"]]["written"] for d in devices
            if d.get("writes_supported") and d["id"] in stats}


def ubi_ec(devices) -> dict:
    return {d["id"]: d["wear"].get("max_ec") for d in devices
            if d.get("kind") == "ubi" and d["wear"].get("max_ec") is not None}


def top_writers(root: str = "", limit: int = 10) -> dict:
    """Процессы, больше всех записавшие на носители (с их старта)."""
    proc = root + "/proc"
    if not os.path.exists(proc + "/self/io") and not root:
        return {"supported": False, "items": []}
    items = []
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return {"supported": False, "items": []}
    seen_any = False
    for pid in pids:
        b = parse_proc_io(_read("%s/%s/io" % (proc, pid)))
        if b < 0:
            continue
        seen_any = True
        if b <= 0:
            continue
        comm = _read("%s/%s/comm" % (proc, pid)).strip()
        cmd = _read("%s/%s/cmdline" % (proc, pid)).replace("\0", " ").strip()
        items.append({"pid": int(pid), "comm": comm, "cmd": cmd[:160],
                      "written": b})
    items.sort(key=lambda x: -x["written"])
    return {"supported": seen_any, "items": items[:limit]}


def boot_id(root: str = "") -> str:
    v = _read(root + "/proc/sys/kernel/random/boot_id").strip()
    if v:
        return v
    # Нет boot_id — время загрузки из uptime (с точностью до минуты).
    try:
        up = float(_read(root + "/proc/uptime").split()[0])
        return "t%d" % int((time.time() - up) // 60)
    except (ValueError, IndexError):
        return ""


# ═══════════════════════════ фоновый учёт ═══════════════════════════

class FlashStats:
    """Раз в минуту — счётчики в ОЗУ, раз в N часов — на flash."""

    def __init__(self, root: str = "", ram_path: str = RAM_STATE,
                 disk_path=None):
        self._root = root
        self._ram_path = ram_path
        self._disk_path = disk_path
        self._lock = threading.Lock()
        self._state = None
        self._flushed_at = time.time()
        self._devices = []
        self._devices_at = 0.0
        self._thread = None
        self._stop = threading.Event()

    # ─── пути и настройки ───

    def disk_path(self) -> str:
        if self._disk_path:
            return self._disk_path
        from core.config_manager import get_config_manager
        return os.path.join(get_config_manager().config_dir, STATE_NAME)

    @staticmethod
    def _conf(key, default):
        try:
            from core.config_manager import get_config_manager
            v = get_config_manager().get("flash", key, default=default)
            return default if v is None else v
        except Exception:                                # noqa: BLE001
            return default

    # ─── состояние ───

    def _load(self) -> dict:
        best = {}
        for path in (self._ram_path, self.disk_path()):
            try:
                with open(path, encoding="utf-8") as f:
                    st = json.load(f)
            except (OSError, ValueError):
                continue
            if isinstance(st, dict) and \
                    float(st.get("updated") or 0) > float(best.get("updated") or 0):
                best = st
        return best

    def _ensure(self):
        if self._state is None:
            self._state = self._load()

    def devices(self, fresh: bool = False) -> list:
        now = time.time()
        if fresh or not self._devices or now - self._devices_at > 600:
            self._devices = discover(self._root, smart=False)
            self._devices_at = now
        return self._devices

    def sample(self, now=None) -> dict:
        """Один замер (зовётся потоком; в тестах — напрямую)."""
        now = time.time() if now is None else now
        devs = self.devices()
        cnt = counters(self._root, devs)
        with self._lock:
            self._ensure()
            st = account(self._state, cnt, boot_id(self._root), now)
            ec = ubi_ec(devs)
            if ec:
                ecd = dict(st.get("ec") or {})
                ecd[day_key(now)] = ec
                for k in sorted(ecd)[:-KEEP_DAYS]:
                    ecd.pop(k, None)
                st["ec"] = ecd
            self._state = st
            self._write(self._ram_path, st)
            hours = float(self._conf("stats_flush_hours", 6) or 0)
            if hours > 0 and now - self._flushed_at >= hours * 3600:
                self._flush_locked(now)
        return st

    def _write(self, path: str, st: dict) -> bool:
        from core.safe_io import atomic_write_json
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            atomic_write_json(path, st, indent=0)
            return True
        except (OSError, TypeError, ValueError):
            return False

    def _flush_locked(self, now: float) -> bool:
        self._flushed_at = now
        if not self._state:
            return False
        return self._write(self.disk_path(), self._state)

    def flush(self) -> bool:
        """Сохранить на постоянный носитель (если это не выключено)."""
        if float(self._conf("stats_flush_hours", 6) or 0) <= 0:
            return False
        with self._lock:
            return self._flush_locked(time.time())

    def reset(self) -> None:
        with self._lock:
            keep = {"boot_id": (self._state or {}).get("boot_id"),
                    "last": (self._state or {}).get("last") or {}}
            self._state = dict(keep, version=1, days={}, ec={},
                               since=time.time(), updated=time.time())
            self._write(self._ram_path, self._state)
            try:
                os.remove(self.disk_path())
            except OSError:
                pass

    def report(self, fresh: bool = False) -> dict:
        """Ответ для GUI: носители, износ, запись, «кто пишет»."""
        devs = discover(self._root) if fresh or not self._devices \
            else self._devices
        if fresh:
            self._devices, self._devices_at = devs, time.time()
        try:
            self.sample()
        except Exception as e:                           # noqa: BLE001
            log.warning("износ flash: замер не удался: %s" % e, source="flash")
        with self._lock:
            st = dict(self._state or {})
        days = st.get("days") or {}
        now = time.time()
        stats = parse_diskstats(_read(self._root + "/proc/diskstats"))
        for d in devs:
            if d.get("writes_supported"):
                d["written_since_boot"] = (stats.get(d["id"]) or {}).get("written")
                d["writes"] = summarize(days, [d["id"]], now)
            elif d.get("kind") == "ubi":
                d["ec_series"] = _ec_series(st.get("ec") or {}, d["id"], now)
        all_ids = [d["id"] for d in devs if d.get("writes_supported")]
        return {
            "ok": True,
            "devices": devs,
            "total": summarize(days, all_ids, now) if all_ids else None,
            "since": st.get("since"),
            "stats_flush_hours": float(self._conf("stats_flush_hours", 6) or 0),
            "top_writers": top_writers(self._root),
            "now": now,
        }

    # ─── поток ───

    def start(self):
        if not self._conf("stats_enabled", True):
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop():
            while not self._stop.is_set():
                try:
                    self.sample()
                except Exception as e:                   # noqa: BLE001
                    log.warning("износ flash: %s" % e, source="flash")
                self._stop.wait(SAMPLE_SEC)

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name="flash-stats")
        self._thread.start()

    def stop(self):
        """Остановить поток и сохранить статистику (SIGTERM, перезагрузка)."""
        self._stop.set()
        try:
            self.flush()
        except Exception:                                # noqa: BLE001
            pass

    def reconfigure(self):
        if self._conf("stats_enabled", True):
            self.start()
        else:
            self._stop.set()


def _ec_series(ec: dict, dev: str, now: float) -> list:
    out = []
    for i in range(29, -1, -1):
        k = day_key(now - i * 86400)
        v = (ec.get(k) or {}).get(dev)
        out.append({"day": k, "max_ec": v})
    return out


_stats = None
_stats_lock = threading.Lock()


def get_flash_stats() -> FlashStats:
    global _stats
    if _stats is None:
        with _stats_lock:
            if _stats is None:
                _stats = FlashStats()
    return _stats
