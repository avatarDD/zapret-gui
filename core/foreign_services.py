# core/foreign_services.py
"""
Сторонние экземпляры туннельных движков: найти, показать, отключить,
«усыновить».

Зачем. Шесть движков (usque, sing-box, mihomo, AmneziaWG, Opera Proxy,
Telegram-прокси) ставятся на роутер не только через GUI: Entware-пакеты
приносят свои init-скрипты (`S51usque`, `S99sing-box`, `S99mihomo`,
`S99amneziawg`…), кто-то запускает бинарник руками или из своих скриптов.
GUI о таких процессах не знал и честно писал «остановлен» про свои
профили, а на роутере в это время:

* работал второй экземпляр того же движка (видно в htop, не видно в GUI);
* чужой туннель занимал имя интерфейса (`opkgtun0`, `wg0`, `awg0`), и
  GUI-профиль на нём падал с EBUSY или вешал адрес на чужое устройство;
* два чужих скрипта претендовали на одно имя (`S51usque` и
  `S52awg-opkgtun0` — оба на `opkgtun0`): после перезагрузки поднимался
  тот, кто стартовал первым;
* после установки usque через GUI (запасной источник — пакет
  usque-keenetic) оставался включённым его `S51usque`.

Что модуль делает:

* :func:`scan` — только ЧИТАЕТ: чужие init-скрипты движков, чужие процессы
  и конфликты имён интерфейсов. Ничего не останавливает.
* :func:`disable_script` / :func:`enable_script` / :func:`stop_process` /
  :func:`adopt` — меняют систему, и только по явному действию
  пользователя (кнопка в GUI, CLI). Сами по себе не вызываются никогда.
* :func:`adopt` — «усыновить» запущенный чужой экземпляр: перенести его
  конфиг в профиль GUI (с тем же именем интерфейса, чтобы маршруты не
  протухли), погасить чужой процесс, отключить его скрипт, поднять тот же
  туннель силами GUI и включить ему автозапуск GUI. Не поднялся — чужой
  скрипт возвращается на место.
* Отключённые через GUI скрипты помнятся (``foreign-services.json`` рядом
  с ``settings.json``): обновление пакета возвращает им бит исполнения, и
  :func:`enforce` отключает их снова. Режим «только GUI» (``exclusive``,
  тоже только по кнопке) распространяет это на все найденные чужие
  скрипты и процессы.

Что считается «своим». Наши init-скрипты всегда с суффиксом ``-gui``
(``S51amneziawg-gui``, ``S52sing-box-gui``, ``S53mihomo-gui``) или с
маркером «zapret-gui» внутри; скрипт пакета tg-ws-proxy GUI использует
сам (Telegram-прокси управляется через него), поэтому он тоже свой.
Свои процессы — те, что записаны в pid-файлах наших менеджеров, и
потомки самого GUI.

Как отключается скрипт. Entware (``/opt/etc/init.d``) запускает при
загрузке только исполняемые ``S*`` (rc.unslung: ``find -perm -u+x``),
поэтому отключение — это ``stop`` и снятие бита исполнения; прежний режим
запоминается, «Включить» его возвращает. На OpenWrt (procd,
``/etc/init.d`` + ``/etc/rc.d``) — штатные ``stop`` и ``disable``.
Файлы не удаляются: они принадлежат пакету, и удалять их — дело
``opkg remove``.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time

from core.log_buffer import log


ENGINES = ("usque", "singbox", "mihomo", "awg", "opera", "tgproxy")

TITLES = {
    "usque":   "usque (MASQUE/WARP)",
    "singbox": "sing-box",
    "mihomo":  "mihomo",
    "awg":     "AmneziaWG",
    "opera":   "Opera Proxy",
    "tgproxy": "Telegram-прокси",
}

# Имя бинарника (basename argv[0]) → движок.
BINARY_ENGINE = {
    "usque":             "usque",
    "sing-box":          "singbox",
    "mihomo":            "mihomo",
    "clash-meta":        "mihomo",
    "amneziawg-go":      "awg",
    "opera-proxy":       "opera",
    "tg-ws-proxy":       "tgproxy",
    "tg-mtproxy-client": "tgproxy",
}

# По имени скрипта: `S51usque`, `S99sing-box`, `S99mihomo`, `S99amneziawg`,
# `S52awg-opkgtun0`, `S99opera-proxy`, `S98tg-tunnel`. Порядок важен:
# `amneziawg`/`awg` проверяются раньше общего `wg`.
_SCRIPT_NAME_RULES = (
    ("usque",   re.compile(r"usque|masque", re.I)),
    ("singbox", re.compile(r"sing-?box", re.I)),
    ("mihomo",  re.compile(r"mihomo|clash", re.I)),
    ("awg",     re.compile(r"amneziawg|(?:^|[^a-z])awg|wg-quick|wireguard",
                           re.I)),
    ("opera",   re.compile(r"opera", re.I)),
    ("tgproxy", re.compile(r"tg-ws-proxy|tg-mtproxy|tg-tunnel|mtproxy", re.I)),
)

# По содержимому: скрипт с невнятным именем, который запускает бинарник
# движка (`S51z2k-warp` с usque внутри).
_SCRIPT_BODY_RULES = (
    ("usque",   re.compile(r"\busque\b")),
    ("singbox", re.compile(r"\bsing-box\b")),
    ("mihomo",  re.compile(r"\bmihomo\b")),
    ("awg",     re.compile(r"\bamneziawg-go\b|\bawg-quick\b|\bawg setconf\b")),
    ("opera",   re.compile(r"\bopera-proxy\b")),
    ("tgproxy", re.compile(r"\btg-ws-proxy\b|\btg-mtproxy-client\b")),
)

# Каталоги init-скриптов. Entware — первым: на Keenetic именно там живут
# все сторонние сервисы. Переопределяются в тестах.
INIT_DIRS = ("/opt/etc/init.d", "/etc/init.d")
RC_D_DIR = "/etc/rc.d"
PROC_ROOT = "/proc"
SYS_NET = "/sys/class/net"

# Наши скрипты: суффикс `-gui` у всех генерируемых автозапусков и маркер
# в шапке. S99zapret* (nfqws2) сюда не относится вовсе — это не туннель, и
# чужой S99zapret разбирает core/diagnostics.
# Маркер — строка-комментарий в шапке («# zapret-gui: sing-box autostart»,
# «# zapret-gui:nfqws-autostart»), а не любое вхождение: чужой скрипт
# вполне может упоминать путь /opt/zapret-gui.
_OWN_MARKER_RE = re.compile(r"^#\s*zapret-gui\b", re.M)
_SKIP_NAME_RE = re.compile(r"zapret", re.I)

# Скрипт пакета tg-ws-proxy: GUI сам ведёт Telegram-прокси через него
# (core/tgproxy_manager), отключать его — значит сломать свой же движок.
_GUI_DRIVEN_SCRIPTS = (
    "/opt/etc/init.d/S99tg-ws-proxy",
    "/etc/init.d/S99tg-ws-proxy",
    "/etc/init.d/tg-ws-proxy",
)

# Имена туннельных интерфейсов, которые ищем в тексте скрипта. За именем
# не может идти «-»: в `awg0-opkgtun0.conf` (схема `<метка>-<интерфейс>`,
# как у оберток awg-quick) `awg0` — метка, интерфейс — `opkgtun0`.
_IFACE_RE = re.compile(
    r"(?<![A-Za-z0-9_])((?:opkgtun|awg|wg|usque|tun|utun|singtun|mihomo)"
    r"\d{1,3})(?![A-Za-z0-9_\-])")
_IFACE_OPT_RE = re.compile(
    r"(?:-n|--interface-name|--iface|IFACE|INTERFACE|IFNAME|DEV)"
    r"[=\s]+[\"']?([A-Za-z0-9_.][A-Za-z0-9_.\-]{0,14})")

_MAX_SCRIPT_BYTES = 64 * 1024
_STATE_FILE = "foreign-services.json"

_lock = threading.RLock()


# ───────────────────────────── состояние ─────────────────────────────

def _state_path() -> str:
    from core.platform_dirs import config_dir
    return os.path.join(config_dir(), _STATE_FILE)


def load_state() -> dict:
    """{"exclusive": bool, "disabled": {path: {...}}} — что GUI отключил сам."""
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    disabled = data.get("disabled")
    return {
        "exclusive": bool(data.get("exclusive", False)),
        "disabled": disabled if isinstance(disabled, dict) else {},
    }


def _save_state(state: dict) -> None:
    from core.safe_io import atomic_write_json
    path = _state_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        atomic_write_json(path, state)
    except OSError as e:
        log.warning("foreign: состояние не сохранено (%s): %s" % (path, e),
                    source="foreign")


# ─────────────────────────────── /proc ───────────────────────────────

def _argv(pid: int) -> list:
    try:
        with open(os.path.join(PROC_ROOT, str(pid), "cmdline"), "rb") as f:
            raw = f.read()
    except (IOError, OSError):
        return []
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]


def _ppid(pid: int):
    try:
        with open(os.path.join(PROC_ROOT, str(pid), "stat"), "rb") as f:
            data = f.read()
    except (IOError, OSError):
        return None
    idx = data.rfind(b")")
    fields = data[idx + 1:].split() if idx != -1 else []
    try:
        return int(fields[1])
    except (IndexError, ValueError):
        return None


def _descends_from(pid: int, ancestor: int, depth: int = 16) -> bool:
    cur = pid
    for _ in range(depth):
        parent = _ppid(cur)
        if parent is None or parent <= 1:
            return False
        if parent == ancestor:
            return True
        cur = parent
    return False


def _pids() -> list:
    try:
        return sorted(int(e) for e in os.listdir(PROC_ROOT) if e.isdigit())
    except OSError:
        return []


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _opt(argv: list, names: tuple) -> str:
    """Значение опции: `-c x`, `--config x`, `-c=x`, `--config=x`."""
    for i, arg in enumerate(argv):
        if arg in names and i + 1 < len(argv):
            return argv[i + 1]
        for name in names:
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return ""


def _cwd(pid: int) -> str:
    try:
        return os.readlink(os.path.join(PROC_ROOT, str(pid), "cwd"))
    except OSError:
        return ""


def _abs(path: str, pid: int) -> str:
    """Относительный путь из argv — относительно cwd процесса."""
    if not path or os.path.isabs(path):
        return path
    cwd = _cwd(pid)
    return os.path.normpath(os.path.join(cwd, path)) if cwd else path


def parse_process(engine: str, argv: list, pid: int = 0) -> dict:
    """Что можно понять о туннеле по командной строке: интерфейс, конфиг.

    Чистая функция (кроме разрешения относительного пути по cwd).
    """
    iface = config = ""
    if engine == "usque":
        iface = _opt(argv, ("-n", "--interface-name"))
        config = _opt(argv, ("-c", "--config")) or "config.json"
    elif engine == "singbox":
        config = _opt(argv, ("-c", "--config"))
        workdir = _opt(argv, ("-D", "--directory"))
        if config and workdir and not os.path.isabs(config):
            config = os.path.join(workdir, config)
    elif engine == "mihomo":
        config = _opt(argv, ("-f",))
        home = _opt(argv, ("-d",))
        if not config:
            config = os.path.join(home, "config.yaml") if home else ""
        elif home and not os.path.isabs(config):
            config = os.path.join(home, config)
    elif engine == "awg":
        # amneziawg-go [-f] <iface>: единственный позиционный аргумент.
        rest = [a for a in argv[1:] if not a.startswith("-")]
        iface = rest[0] if rest else ""
    elif engine == "opera":
        config = _opt(argv, ("-config", "--config"))
    return {"iface": iface, "config": _abs(config, pid) if pid else config}


# ──────────────────────────── свои процессы ──────────────────────────

def _pid_files(run_dir: str, prefix: str = "") -> set:
    out = set()
    try:
        names = os.listdir(run_dir)
    except OSError:
        return out
    for fn in names:
        if not fn.endswith(".pid") or not fn.startswith(prefix):
            continue
        try:
            with open(os.path.join(run_dir, fn)) as f:
                value = f.read().strip()
        except OSError:
            continue
        if value.isdigit():
            out.add(int(value))
    return out


def own_pids() -> set:
    """PID процессов движков, которые запустил GUI (по pid-файлам)."""
    pids = set()
    try:
        from core.singbox_platform import detect_singbox_platform
        pids |= _pid_files(detect_singbox_platform().run_dir)
    except Exception:
        pass
    try:
        from core.mihomo_platform import detect_mihomo_platform
        pids |= _pid_files(detect_mihomo_platform().run_dir)
    except Exception:
        pass
    try:
        from core.awg_detector import get_awg_detector
        pids |= _pid_files(get_awg_detector().detect_platform().run_dir,
                           "awg-")
    except Exception:
        pass
    try:
        from core.opera_proxy_manager import get_opera_proxy_manager
        mgr = get_opera_proxy_manager()
        pid = mgr._read_pid()
        if pid:
            pids.add(pid)
        proc = getattr(mgr, "_process", None)
        if proc is not None and proc.poll() is None:
            pids.add(proc.pid)
    except Exception:
        pass
    try:
        from core.tgproxy_manager import get_mtproxy_client_manager
        proc = getattr(get_mtproxy_client_manager(), "_proc", None)
        if proc is not None and proc.poll() is None:
            pids.add(proc.pid)
    except Exception:
        pass
    return pids


def _tgwsproxy_driven() -> bool:
    """GUI ведёт tg-ws-proxy через скрипт пакета — значит, процесс свой."""
    return any(os.path.isfile(p) for p in _GUI_DRIVEN_SCRIPTS)


def find_processes(own=None, usque_external=None) -> list:
    """Чужие процессы движков: [{pid, engine, binary, cmdline, iface, config}].

    usque берётся из UsqueManager.find_external() (там своё, более точное
    понимание «своего»: дочерние процессы, .run-файлы профилей), остальные
    движки — по /proc и pid-файлам наших менеджеров.
    """
    own = own_pids() if own is None else set(own)
    me = os.getpid()
    out = []
    if usque_external is None:
        try:
            from core.usque_manager import get_usque_manager
            usque_external = get_usque_manager().find_external()
        except Exception:
            usque_external = []
    for ext in usque_external or []:
        argv = (ext.get("cmdline") or "").split()
        out.append({
            "pid": ext.get("pid"), "engine": "usque",
            "binary": argv[0] if argv else "usque",
            "cmdline": ext.get("cmdline", ""),
            "iface": ext.get("iface", ""),
            "config": _abs(ext.get("config") or "config.json",
                           ext.get("pid") or 0),
        })
    tg_driven = None
    for pid in _pids():
        if pid == me or pid in own:
            continue
        argv = _argv(pid)
        if not argv:
            continue
        base = os.path.basename(argv[0])
        engine = BINARY_ENGINE.get(base)
        if not engine or engine == "usque":
            continue
        # Подкоманды-однодневки (`sing-box check`, `mihomo -t`, версия) —
        # не экземпляры туннеля.
        if engine == "singbox" and "run" not in argv[1:3]:
            continue
        if engine == "mihomo" and ("-t" in argv or "-v" in argv):
            continue
        if engine == "awg" and ("--version" in argv or len(argv) < 2):
            continue
        if base == "tg-ws-proxy":
            if tg_driven is None:
                tg_driven = _tgwsproxy_driven()
            if tg_driven:
                continue
        if _descends_from(pid, me):
            continue
        info = parse_process(engine, argv, pid)
        out.append({
            "pid": pid, "engine": engine, "binary": argv[0],
            "cmdline": " ".join(argv)[:300],
            "iface": info["iface"], "config": info["config"],
        })
    return out


# ──────────────────────────── init-скрипты ───────────────────────────

def _read_head(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(_MAX_SCRIPT_BYTES)
    except (IOError, OSError):
        return ""


def classify_script(name: str, body: str) -> str:
    """Движок, к которому относится init-скрипт ('' — не наш случай).

    Чистая функция: имя файла и его текст.
    """
    if not name or name.startswith(".") or _SKIP_NAME_RE.search(name):
        return ""
    if name.endswith("-gui") or _OWN_MARKER_RE.search(body or ""):
        return ""
    for engine, rx in _SCRIPT_NAME_RULES:
        if rx.search(name):
            return engine
    for engine, rx in _SCRIPT_BODY_RULES:
        if rx.search(body or ""):
            return engine
    return ""


def script_ifaces(name: str, body: str) -> list:
    """Имена интерфейсов, на которые претендует скрипт (чистая функция).

    Берутся из `-n X`/`IFACE=X` и из упоминаний вида `opkgtun0`, `wg0`,
    `awg1` в тексте, плюс хвост имени `S52awg-opkgtun0` → `opkgtun0`.
    """
    found = []

    def _add(value):
        value = (value or "").strip()
        if value and not value.startswith("-") and value not in found \
                and len(value) <= 15 and not value.startswith("$"):
            found.append(value)

    for line in (body or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for m in _IFACE_OPT_RE.finditer(line):
            if _IFACE_RE.fullmatch(m.group(1)) or m.group(1).startswith(
                    ("opkgtun", "awg", "wg", "usque", "tun")):
                _add(m.group(1))
        for m in _IFACE_RE.finditer(line):
            _add(m.group(1))
    tail = re.search(r"-((?:opkgtun|awg|wg|usque|tun)\d{1,3})$", name or "")
    if tail:
        _add(tail.group(1))
    return found


def _is_procd(path: str) -> bool:
    return (os.path.dirname(path) == "/etc/init.d"
            and os.path.isdir(RC_D_DIR))


def script_enabled(path: str, body: str = None) -> bool:
    """Запустится ли скрипт при загрузке."""
    if _is_procd(path):
        name = os.path.basename(path)
        try:
            for fn in os.listdir(RC_D_DIR):
                if re.fullmatch(r"S\d+" + re.escape(name), fn):
                    return True
        except OSError:
            pass
        return False
    if not os.access(path, os.X_OK):
        return False
    body = _read_head(path) if body is None else body
    # Entware-скрипты на rc.func часто несут ENABLED=yes|no.
    m = re.search(r"^\s*ENABLED=[\"']?(\w+)", body, re.M)
    return not (m and m.group(1).lower() in ("no", "0", "false"))


def find_scripts() -> list:
    """Чужие init-скрипты движков.

    [{path, name, engine, enabled, ifaces, configs, gui_disabled}].
    """
    state = load_state()
    out = []
    seen = set()
    for d in INIT_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            path = os.path.join(d, name)
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(path):
                continue
            seen.add(real)
            if path in _GUI_DRIVEN_SCRIPTS:
                continue
            body = _read_head(path)
            engine = classify_script(name, body)
            if not engine:
                continue
            out.append({
                "path": path, "name": name, "engine": engine,
                "enabled": script_enabled(path, body),
                "ifaces": script_ifaces(name, body),
                "configs": _script_configs(body),
                "gui_disabled": path in state["disabled"],
            })
    return out


_CONF_PATH_RE = re.compile(r"(/[\w./\-]+\.(?:json|ya?ml|conf))")


def _script_configs(body: str) -> list:
    out = []
    for m in _CONF_PATH_RE.finditer(body or ""):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out[:10]


def _attribute(proc: dict, scripts: list) -> tuple:
    """Какой скрипт, вероятно, запустил процесс → (путь, как узнали).

    «config»/«iface» — скрипт называет конфиг или интерфейс процесса;
    «guess» — единственный скрипт того же движка. Догадке хватает, чтобы
    показать человеку и добить процесс сразу после его же «Отключить»,
    но не чтобы сторож потом молча убивал процесс, который пользователь
    мог запустить руками.
    """
    same = [s for s in scripts if s["engine"] == proc["engine"]]
    for s in same:
        if proc.get("config") and proc["config"] in s["configs"]:
            return s["path"], "config"
    for s in same:
        if proc.get("iface") and proc["iface"] in s["ifaces"]:
            return s["path"], "iface"
    enabled = [s for s in same if s["enabled"]]
    if len(enabled) == 1:
        return enabled[0]["path"], "guess"
    if len(same) == 1:
        return same[0]["path"], "guess"
    return "", ""


# ───────────────────────── претензии на имена ────────────────────────

def _gui_claims() -> list:
    """[(iface, label, engine)] — имена, за которыми стоят профили GUI."""
    out = []
    try:
        from core.usque_manager import get_usque_manager
        for c in get_usque_manager().list_configs():
            if c.get("iface"):
                out.append((c["iface"], "профиль usque «%s»" % c["name"],
                            "usque", c.get("path", "")))
    except Exception:
        pass
    try:
        from core.awg_manager import get_awg_manager
        for c in get_awg_manager().list_configs():
            iface = c.get("iface") or c.get("name")
            if iface:
                out.append((iface, "конфиг AWG «%s»" % c.get("name"),
                            "awg", c.get("path", "")))
    except Exception:
        pass
    try:
        from core.singbox_manager import get_singbox_manager
        for c in get_singbox_manager().list_configs():
            if c.get("tun_iface"):
                out.append((c["tun_iface"],
                            "конфиг sing-box «%s»" % c["name"], "singbox",
                            c.get("path", "")))
    except Exception:
        pass
    return out


def find_conflicts(scripts: list, processes: list, gui=None) -> list:
    """Имена интерфейсов, на которые претендует больше одного владельца.

    Чистая функция. Владелец — скрипт, процесс без скрипта или профиль
    GUI. Профиль GUI, чей конфиг-файл использует сам чужой скрипт
    (`awg0-opkgtun0.conf` у `S52awg-opkgtun0`), — это тот же туннель, а не
    второй претендент.
    """
    claims = {}

    def _claim(iface, owner, item):
        if not iface:
            return
        bucket = claims.setdefault(iface, {})
        bucket.setdefault(owner, item)

    for s in scripts:
        for iface in s.get("ifaces") or []:
            _claim(iface, s["path"], {"kind": "script", "engine": s["engine"],
                                      "label": s["name"], "path": s["path"],
                                      "enabled": s["enabled"]})
    for p in processes:
        owner = p.get("script") or "pid:%s" % p.get("pid")
        _claim(p.get("iface"), owner,
               {"kind": "script" if p.get("script") else "process",
                "engine": p["engine"],
                "label": (os.path.basename(p["script"]) if p.get("script")
                          else "%s (pid %s)" % (os.path.basename(
                              p.get("binary") or p["engine"]), p.get("pid"))),
                "path": p.get("script", ""), "pid": p.get("pid"),
                "running": True})
    script_text = {s["path"]: " ".join(s.get("configs") or []) + " " +
                   s["name"] for s in scripts}
    for iface, label, engine, cfg_path in (gui or []):
        base = os.path.basename(cfg_path or "")
        stem = base.rsplit(".", 1)[0] if base else ""
        shared = any(stem and (base in txt or stem in txt)
                     for txt in script_text.values())
        if shared:
            continue
        _claim(iface, "gui:%s:%s" % (engine, label),
               {"kind": "gui", "engine": engine, "label": label})
    out = []
    for iface in sorted(claims):
        owners = list(claims[iface].values())
        if len(owners) < 2:
            continue
        out.append({"iface": iface, "claimants": owners,
                    "hint": _conflict_hint(iface, owners)})
    return out


def _conflict_hint(iface: str, owners: list) -> str:
    names = ", ".join(o["label"] for o in owners)
    return ("На интерфейс %s претендуют сразу несколько: %s. Поднимется "
            "тот, кто стартует первым, остальные упадут («устройство "
            "занято») или повесят свои адреса на чужой туннель. Оставьте "
            "одного владельца: лишний скрипт отключите, а нужный туннель "
            "передайте GUI." % (iface, names))


# ─────────────────────────────── scan ────────────────────────────────

def scan(gui_claims: bool = True) -> dict:
    """Полная картина: чужие скрипты, процессы, конфликты. Только чтение."""
    scripts = find_scripts()
    processes = find_processes()
    for p in processes:
        p["script"], p["script_match"] = _attribute(p, scripts)
        p["adoptable"], p["adopt_hint"] = _adoptable(p)
    running_by_script = {}
    for p in processes:
        if p["script"]:
            running_by_script.setdefault(p["script"], []).append(p["pid"])
    for s in scripts:
        s["running_pids"] = running_by_script.get(s["path"], [])
    conflicts = find_conflicts(scripts, processes,
                               _gui_claims() if gui_claims else [])
    state = load_state()
    return {
        "ok": True,
        "scripts": scripts,
        "processes": processes,
        "conflicts": conflicts,
        "exclusive": state["exclusive"],
        "has_foreign": bool(processes or any(s["enabled"] for s in scripts)
                            or conflicts),
    }


def _adoptable(proc: dict) -> tuple:
    engine = proc["engine"]
    if engine == "tgproxy":
        return False, ("Telegram-прокси GUI ведёт через скрипт пакета "
                       "tg-ws-proxy; сторонний экземпляр можно только "
                       "остановить и отключить")
    if engine in ("usque", "singbox", "mihomo") and not proc.get("config"):
        return False, "конфиг процесса не определить по его командной строке"
    if engine in ("usque", "singbox", "mihomo") and not os.path.isfile(
            proc["config"]):
        return False, "конфиг %s не найден" % proc["config"]
    if engine == "awg" and not proc.get("iface"):
        return False, "имя интерфейса не определить"
    return True, ""


def summary() -> dict:
    """Короткая сводка для дашборда и страниц движков."""
    data = scan(gui_claims=True)
    by_engine = {}
    for p in data["processes"]:
        by_engine.setdefault(p["engine"], {"processes": 0, "scripts": 0})
        by_engine[p["engine"]]["processes"] += 1
    for s in data["scripts"]:
        if s["enabled"]:
            by_engine.setdefault(s["engine"], {"processes": 0, "scripts": 0})
            by_engine[s["engine"]]["scripts"] += 1
    return {"ok": True, "has_foreign": data["has_foreign"],
            "engines": by_engine, "conflicts": len(data["conflicts"]),
            "exclusive": data["exclusive"]}


# ───────────────────────────── действия ──────────────────────────────

def _run(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout)
        return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, str(e)


def _script_cmd(path: str, action: str) -> list:
    # Снятый бит исполнения не должен мешать `stop`: зовём через sh.
    if os.access(path, os.X_OK):
        return [path, action]
    return ["sh", path, action]


def _known_script(path: str) -> dict:
    """Проверка: путь — это найденный нами чужой скрипт (а не что угодно)."""
    for s in find_scripts():
        if s["path"] == path:
            return s
    return {}


def _kill(pid: int, wait: float = 3.0) -> bool:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except OSError:
            return True
        deadline = time.time() + wait
        while time.time() < deadline:
            if not _alive(pid):
                return True
            time.sleep(0.1)
    return not _alive(pid)


def _disable_file(path: str, engine: str, reason: str) -> dict:
    """Отключить скрипт без проверки «найден ли он» (для своих вызовов)."""
    rc, out = _run(_script_cmd(path, "stop"), timeout=30)
    stopped = rc == 0
    state = load_state()
    entry = state["disabled"].get(path) or {}
    try:
        if _is_procd(path):
            _run([path, "disable"], timeout=15)
            entry.setdefault("kind", "procd")
        else:
            mode = os.stat(path).st_mode & 0o7777
            if mode & 0o111:
                entry["mode"] = mode
            entry.setdefault("mode", mode)
            entry["kind"] = "entware"
            os.chmod(path, mode & ~0o111)
    except OSError as e:
        return {"ok": False, "error": "не удалось отключить %s: %s"
                % (path, e)}
    entry.update({"engine": engine, "reason": reason,
                  "ts": entry.get("ts") or int(time.time())})
    state["disabled"][path] = entry
    _save_state(state)
    log.info("foreign: отключён сторонний скрипт %s (%s)%s"
             % (path, reason, "" if stopped else
                "; stop вернул %s: %s" % (rc, out[:120])),
             source="foreign")
    return {"ok": True, "path": path, "stopped": stopped,
            "stop_output": out[:400]}


def disable_script(path: str, kill_leftovers: bool = True) -> dict:
    """Остановить и отключить чужой init-скрипт (по кнопке пользователя).

    После `stop` добиваем процессы, которые этот скрипт явно запускал (его
    текст называет их конфиг или интерфейс): у многих Entware-скриптов
    `stop` ищет процесс по имени и промахивается, а цель — чтобы чужой
    экземпляр не работал. Процесс того же движка, приписанный скрипту лишь
    догадкой, не трогаем — его могли запустить руками; он уходит в
    `still_running`, остановить его можно отдельной кнопкой.
    """
    with _lock:
        script = _known_script(path)
        if not script:
            return {"ok": False, "error": "%s — не найденный сторонний "
                    "скрипт движка" % path}
        res = _disable_file(path, script["engine"], "user")
        if not res.get("ok") or not kill_leftovers:
            return res
        killed, left = [], []
        for p in scan(gui_claims=False)["processes"]:
            if p.get("script") != path:
                continue
            if p.get("script_match") in ("config", "iface") \
                    and _kill(p["pid"]):
                killed.append(p["pid"])
            else:
                left.append(p["pid"])
        res["killed"] = killed
        res["still_running"] = left
        return res


def enable_script(path: str, start: bool = False) -> dict:
    """Вернуть скрипт, отключённый через GUI, в прежнее состояние."""
    with _lock:
        state = load_state()
        entry = state["disabled"].get(path)
        if entry is None:
            return {"ok": False, "error": "%s GUI не отключал" % path}
        try:
            if entry.get("kind") == "procd":
                _run([path, "enable"], timeout=15)
            elif os.path.isfile(path):
                os.chmod(path, int(entry.get("mode") or 0o755))
        except OSError as e:
            return {"ok": False, "error": str(e)}
        state["disabled"].pop(path, None)
        _save_state(state)
        out = {"ok": True, "path": path}
        if start and os.path.isfile(path):
            rc, text = _run(_script_cmd(path, "start"), timeout=30)
            out["started"] = rc == 0
            out["start_output"] = text[:400]
        log.info("foreign: скрипт %s снова включён" % path, source="foreign")
        return out


def stop_process(pid: int) -> dict:
    """Остановить чужой процесс движка (только из найденных scan())."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "error": "неверный pid"}
    with _lock:
        procs = {p["pid"]: p for p in find_processes()}
        if pid not in procs:
            return {"ok": False, "error": "pid %d — не сторонний процесс "
                    "движка" % pid}
        ok = _kill(pid)
        log.info("foreign: остановлен сторонний %s (pid %d)%s"
                 % (procs[pid]["engine"], pid, "" if ok else " — не сразу"),
                 source="foreign")
        return {"ok": ok, "pid": pid,
                "error": "" if ok else "процесс не завершился"}


def set_exclusive(enabled: bool) -> dict:
    """Режим «туннелями владеет только GUI» (включается только вручную)."""
    with _lock:
        state = load_state()
        state["exclusive"] = bool(enabled)
        _save_state(state)
    log.info("foreign: режим «только GUI» %s"
             % ("включён" if enabled else "выключен"), source="foreign")
    res = {"ok": True, "exclusive": bool(enabled)}
    if enabled:
        res["enforced"] = enforce()
    get_guard().reconfigure()
    return res


def enforce() -> dict:
    """Не дать отключённому вернуться (и, в режиме «только GUI», — чужому).

    * скрипт, отключённый через GUI, снова исполняемый (пакет обновился и
      вернул бит) — отключаем снова;
    * процесс, приписанный такому скрипту, работает — останавливаем;
    * exclusive: любой найденный включённый чужой скрипт отключается,
      любой чужой процесс движка останавливается.

    Без отключённых скриптов и без exclusive — ничего не делает.
    """
    with _lock:
        state = load_state()
        disabled = state["disabled"]
        # Пакет удалили вместе со скриптом — помнить нечего.
        gone = [p for p in disabled if not os.path.exists(p)]
        if gone:
            for p in gone:
                disabled.pop(p, None)
            _save_state(state)
        if not disabled and not state["exclusive"]:
            return {"redisabled": [], "killed": []}
        redisabled, killed = [], []
        data = scan(gui_claims=False)
        for s in data["scripts"]:
            if s["enabled"] and (s["path"] in disabled or state["exclusive"]):
                why = ("re-enabled" if s["path"] in disabled else "exclusive")
                if _disable_file(s["path"], s["engine"], why).get("ok"):
                    redisabled.append(s["path"])
        blocked = set(disabled) | set(redisabled)
        for p in data["processes"]:
            strong = p.get("script") in blocked and \
                p.get("script_match") in ("config", "iface")
            # Telegram-прокси без скрипта — это может быть и наш же
            # tg-mtproxy-client, переживший перезапуск GUI: не трогаем.
            loose = state["exclusive"] and (p["engine"] != "tgproxy"
                                            or p.get("script"))
            if (strong or loose) and _kill(p["pid"]):
                killed.append(p["pid"])
        if redisabled or killed:
            log.warning("foreign: сторонние сервисы снова отключены: "
                        "скрипты %s, процессы %s"
                        % (", ".join(redisabled) or "—",
                           ", ".join(str(k) for k in killed) or "—"),
                        source="foreign")
        return {"redisabled": redisabled, "killed": killed}


# ─────────────────────── скрипты пакетов (установка) ─────────────────

def package_init_scripts(package: str) -> list:
    """init-скрипты, которые принёс пакет (opkg files / apk info -L)."""
    if not package:
        return []
    out = []
    for cmd in (["opkg", "files", package], ["apk", "info", "-L", package]):
        if not shutil.which(cmd[0]):
            continue
        rc, text = _run(cmd, timeout=15)
        if rc != 0:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("/"):
                line = "/" + line if line.startswith(("opt/", "etc/")) \
                    else ""
            if line and os.path.dirname(line) in INIT_DIRS \
                    and os.path.isfile(line) and line not in out:
                out.append(line)
        if out:
            break
    return out


def neutralize_package_scripts(package: str, engine: str) -> list:
    """Отключить init-скрипты пакета, который GUI сам поставил.

    Пакет нужен GUI только ради бинарника (запасной источник usque —
    usque-keenetic), а его собственный сервис поднимал бы при загрузке
    второй туннель (`S51usque` на `opkgtun0`) параллельно профилям GUI.
    Скрипт отключается и запоминается: обновление пакета его не вернёт.
    """
    done = []
    with _lock:
        for path in package_init_scripts(package):
            if path in _GUI_DRIVEN_SCRIPTS:
                continue
            res = _disable_file(path, engine, "installed-by-gui:%s" % package)
            if res.get("ok"):
                done.append(path)
    if done:
        log.info("foreign: у пакета %s отключён собственный автозапуск: %s"
                 " — туннелем управляет GUI" % (package, ", ".join(done)),
                 source="foreign")
    return done


def engine_foreign(engine: str) -> dict:
    """Что чужого есть у одного движка — для ответа установщика и страниц."""
    data = scan(gui_claims=False)
    return {
        "scripts": [s for s in data["scripts"] if s["engine"] == engine],
        "processes": [p for p in data["processes"] if p["engine"] == engine],
    }


# ──────────────────────────── усыновление ────────────────────────────

_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_name(*parts) -> str:
    raw = "-".join(p for p in parts if p)
    name = _NAME_SAFE_RE.sub("-", raw).strip("-")[:48]
    return name or "adopted"


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _copy_into(src: str, dst_dir: str, name: str, ext: str) -> tuple:
    """Скопировать конфиг в каталог GUI под свободным именем.

    → (name, path, created): уже лежащая там копия того же файла
    переиспользуется (повторное «Передать GUI» не плодит дублей).
    """
    os.makedirs(dst_dir, exist_ok=True)
    base = name
    for n in range(0, 100):
        cand = base if n == 0 else "%s-%d" % (base, n)
        dst = os.path.join(dst_dir, cand + ext)
        if os.path.exists(dst):
            if _same_file(src, dst) or _files_equal(src, dst):
                return cand, dst, False
            continue
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o600)
        return cand, dst, True
    raise OSError("нет свободного имени для %s" % name)


def _files_equal(a: str, b: str) -> bool:
    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            return fa.read() == fb.read()
    except OSError:
        return False


def _json_equal(a: str, b: str) -> bool:
    """Тот же JSON по смыслу: import_config пересохраняет его с отступами."""
    try:
        with open(a, "r", encoding="utf-8") as fa, \
                open(b, "r", encoding="utf-8") as fb:
            return json.load(fa) == json.load(fb)
    except (OSError, ValueError):
        return False


def _drop_created(prep: dict) -> None:
    """Убрать профиль, созданный этой попыткой «передать GUI»."""
    path = prep.get("created_path") or ""
    for p in (path, path + ".iface") if path else ():
        try:
            os.remove(p)
        except OSError:
            pass


def _wait_iface_gone(iface: str, timeout: float = 5.0) -> bool:
    if not iface:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not os.path.exists(os.path.join(SYS_NET, iface)):
            return True
        time.sleep(0.2)
    return not os.path.exists(os.path.join(SYS_NET, iface))


def _stop_foreign(proc: dict) -> dict:
    """Погасить чужой экземпляр: скрипт (stop+disable) и сам процесс."""
    info = {"script": proc.get("script", ""), "script_disabled": False}
    if proc.get("script"):
        res = _disable_file(proc["script"], proc["engine"], "adopted")
        info["script_disabled"] = bool(res.get("ok"))
    if _alive(proc["pid"]):
        _kill(proc["pid"])
    if proc.get("iface") and not _wait_iface_gone(proc["iface"]):
        # usque --persist / amneziawg-go оставляют TUN после смерти.
        _run(["ip", "link", "del", "dev", proc["iface"]], timeout=5)
    if proc["engine"] == "awg" and proc.get("iface"):
        # После SIGKILL демон не убирает UAPI-сокет, и подъём того же
        # имени силами GUI споткнулся бы о мёртвый сокет.
        try:
            from core.awg_detector import get_awg_detector
            for sock in get_awg_detector().detect_platform().uapi_paths(
                    proc["iface"]):
                if os.path.exists(sock):
                    os.remove(sock)
        except Exception:
            pass
    return info


def _rollback(proc: dict, stopped: dict) -> dict:
    """GUI не поднял туннель — вернуть чужой скрипт и запустить его."""
    if stopped.get("script_disabled") and stopped.get("script"):
        return enable_script(stopped["script"], start=True)
    return {"ok": False, "error": "процесс был запущен без init-скрипта — "
            "перезапустить его GUI не может"}


def adopt(engine: str, pid: int) -> dict:
    """Передать работающий чужой экземпляр под управление GUI.

    Только по явному действию пользователя. Порядок: подготовить профиль
    GUI (конфиг, имя интерфейса) → погасить чужое (скрипт отключается) →
    поднять силами GUI → включить автозапуск GUI. Если GUI не поднял
    туннель, чужой скрипт включается и запускается обратно.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "error": "неверный pid"}
    with _lock:
        data = scan(gui_claims=False)
        proc = next((p for p in data["processes"]
                     if p["pid"] == pid and p["engine"] == engine), None)
        if not proc:
            return {"ok": False, "error": "сторонний процесс %s с pid %d не "
                    "найден" % (TITLES.get(engine, engine), pid)}
        ok, why = _adoptable(proc)
        if not ok:
            return {"ok": False, "error": why}
        handler = _ADOPTERS[engine]
        try:
            prepared = handler["prepare"](proc)
        except (OSError, ValueError) as e:
            return {"ok": False, "error": "подготовка профиля: %s" % e}
        if not prepared.get("ok", True):
            return prepared
        stopped = _stop_foreign(proc)
        try:
            started = handler["start"](prepared)
        except Exception as e:                  # noqa: BLE001 — откат ниже
            started = {"ok": False, "error": str(e)}
        if not (isinstance(started, dict) and started.get("ok")):
            _drop_created(prepared)
            rollback = _rollback(proc, stopped)
            log.warning("foreign: усыновить %s (pid %d) не вышло: %s; "
                        "откат: %s" % (engine, pid,
                                       (started or {}).get("error"),
                                       "ок" if rollback.get("ok") else
                                       rollback.get("error")),
                        source="foreign")
            return {"ok": False,
                    "error": "GUI не поднял туннель: %s"
                             % (started or {}).get("error", "ошибка"),
                    "rollback": rollback, "profile": prepared.get("name")}
        try:
            handler["autostart"](prepared)
            autostart = True
        except Exception as e:                  # noqa: BLE001
            log.warning("foreign: автозапуск для %s не включён: %s"
                        % (prepared.get("name"), e), source="foreign")
            autostart = False
        log.success("foreign: %s (pid %d) теперь под управлением GUI — "
                    "профиль «%s»%s" % (TITLES.get(engine, engine), pid,
                                        prepared.get("name", ""),
                                        (", скрипт %s отключён"
                                         % stopped["script"])
                                        if stopped.get("script") else ""),
                    source="foreign")
        out = {"ok": True, "engine": engine, "name": prepared.get("name"),
               "iface": prepared.get("iface", ""),
               "script_disabled": stopped.get("script", ""),
               "autostart": autostart}
        for key in ("warning", "renamed_from"):
            if prepared.get(key):
                out[key] = prepared[key]
        return out


# usque ───────────────────────────────────────────────────────────────

def _usque_prepare(proc: dict) -> dict:
    from core.usque_manager import get_usque_manager
    mgr = get_usque_manager()
    with open(proc["config"], "r", encoding="utf-8") as f:
        text = f.read()
    iface = proc.get("iface") or ""
    name = _safe_name("adopted", iface or "usque")
    existing = next((c for c in mgr.list_configs()
                     if _json_equal(c.get("path", ""), proc["config"])),
                    None)
    created = ""
    if existing:
        name, path = existing["name"], existing["path"]
    else:
        base, n = name, 0
        while mgr._profile_file(name):
            n += 1
            name = "%s-%d" % (base, n)
        res = mgr.import_config(name, text)
        if not res.get("ok"):
            return res
        path = created = res["path"]
    out = {"name": name, "path": path, "created_path": created}
    # Имя интерфейса сохраняем: на `warp:opkgtun0` уже смотрят маршруты.
    # Но если на это имя претендует AWG-конфиг (S52awg-opkgtun0), отдать
    # его usque — значит увести чужой трафик; тогда выдаём новое.
    claimed = set()
    try:
        from core.awg_manager import get_awg_manager
        for c in get_awg_manager().list_configs():
            claimed.update(v for v in (c.get("iface"), c.get("name")) if v)
    except Exception:
        pass
    if iface and iface not in claimed:
        mgr._assign_iface(path, iface)
        out["iface"] = iface
    else:
        mgr.forget_iface(path)
        out["iface"] = mgr.iface_for_config(path, reserved={iface})
        if iface:
            out["renamed_from"] = iface
            out["warning"] = ("имя %s занято конфигом AWG, туннель usque "
                              "поднят как %s — правила warp:%s перенастройте"
                              % (iface, out["iface"], iface))
    return out


def _usque_start(prep: dict) -> dict:
    from core import tunnels_control
    return tunnels_control.up("usque", prep["name"])


def _usque_autostart(prep: dict) -> None:
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    cfg.set("usque", "enabled", True)
    cfg.set("usque", "autostart", True)
    cfg.save()


# sing-box / mihomo ───────────────────────────────────────────────────

def _file_prepare(proc: dict, platform, ext: str) -> dict:
    src = proc["config"]
    cfg_dir = platform.config_dir
    stem = os.path.basename(src).rsplit(".", 1)[0]
    if os.path.dirname(os.path.realpath(src)) == os.path.realpath(cfg_dir) \
            and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", stem) \
            and src.endswith(ext):
        return {"name": stem, "path": src}
    name, path, created = _copy_into(src, cfg_dir,
                                     _safe_name("adopted", stem), ext)
    return {"name": name, "path": path, "copied_from": src,
            "created_path": path if created else ""}


def _singbox_prepare(proc: dict) -> dict:
    from core.singbox_platform import detect_singbox_platform
    return _file_prepare(proc, detect_singbox_platform(), ".json")


def _mihomo_prepare(proc: dict) -> dict:
    from core.mihomo_platform import detect_mihomo_platform
    platform = detect_mihomo_platform()
    out = _file_prepare(proc, platform, ".yaml")
    home = _opt(proc.get("cmdline", "").split(), ("-d",))
    if home and os.path.realpath(home) != os.path.realpath(
            platform.config_dir):
        out["warning"] = ("mihomo работал с каталогом %s, GUI запускает с %s:"
                          " geo-базы и файлы провайдеров с относительными "
                          "путями ищутся теперь там" % (home,
                                                        platform.config_dir))
    return out


def _singbox_start(prep):
    from core import tunnels_control
    return tunnels_control.up("singbox", prep["name"])


def _mihomo_start(prep):
    from core import tunnels_control
    return tunnels_control.up("mihomo", prep["name"])


def _singbox_autostart(prep):
    from core.singbox_autostart import regenerate, set_autostart
    if set_autostart(prep["name"], True).get("ok"):
        regenerate()


def _mihomo_autostart(prep):
    from core.mihomo_autostart import regenerate, set_autostart
    if set_autostart(prep["name"], True).get("ok"):
        regenerate()


# AmneziaWG ───────────────────────────────────────────────────────────

def _awg_prepare(proc: dict) -> dict:
    from core.awg_manager import get_awg_manager
    mgr = get_awg_manager()
    iface = proc["iface"]
    for c in mgr.list_configs():
        if iface in (c.get("iface"), c.get("name")):
            return {"name": c["name"], "iface": iface}
    # Конфига в каталогах GUI нет — ищем в самом скрипте.
    if proc.get("script"):
        body = _read_head(proc["script"])
        for path in _script_configs(body):
            if path.endswith(".conf") and os.path.isfile(path):
                name, dst, created = _copy_into(path, mgr._config_dir(),
                                                iface, ".conf")
                return {"name": name, "iface": iface, "copied_from": path,
                        "created_path": dst if created else ""}
    raise ValueError("конфиг для %s не найден ни в каталогах GUI, ни в "
                     "скрипте — импортируйте .conf на странице AmneziaWG, "
                     "затем повторите" % iface)


def _awg_start(prep):
    from core import tunnels_control
    return tunnels_control.up("awg", prep["name"])


def _awg_autostart(prep):
    from core.awg_autostart_manager import get_awg_autostart_manager
    get_awg_autostart_manager().set_enabled(prep["name"], True)


# Opera Proxy ─────────────────────────────────────────────────────────

def parse_opera_args(argv: list) -> dict:
    """Флаги opera-proxy → поля настроек GUI (чистая функция)."""
    def flag(name):
        for i, a in enumerate(argv):
            for form in ("-" + name, "--" + name):
                if a == form:
                    nxt = argv[i + 1] if i + 1 < len(argv) else ""
                    return nxt if not nxt.startswith("-") else True
                if a.startswith(form + "="):
                    return a.split("=", 1)[1]
        return None

    out = {}
    for opt, key in (("country", "country"), ("bind-address", "bind"),
                     ("proxy-bypass", "proxy_bypass"),
                     ("fake-SNI", "fake_sni"), ("verbosity", "verbosity")):
        v = flag(opt)
        if isinstance(v, str) and v:
            out[key] = v
    socks = flag("socks-mode")
    if socks is not None:
        out["socks_mode"] = socks is True or str(socks).lower() in (
            "1", "true", "yes")
    return out


def _opera_prepare(proc: dict) -> dict:
    from core.opera_proxy_manager import validate_settings
    settings = validate_settings(parse_opera_args(proc["cmdline"].split()))
    return {"name": "opera", "settings": settings}


def _opera_start(prep):
    from core import tunnels_control
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    for key, value in prep["settings"].items():
        cfg.set("opera_proxy", key, value)
    cfg.save()
    return tunnels_control.up("opera")


def _opera_autostart(prep):
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    cfg.set("opera_proxy", "autostart", True)
    cfg.save()


_ADOPTERS = {
    "usque":   {"prepare": _usque_prepare, "start": _usque_start,
                "autostart": _usque_autostart},
    "singbox": {"prepare": _singbox_prepare, "start": _singbox_start,
                "autostart": _singbox_autostart},
    "mihomo":  {"prepare": _mihomo_prepare, "start": _mihomo_start,
                "autostart": _mihomo_autostart},
    "awg":     {"prepare": _awg_prepare, "start": _awg_start,
                "autostart": _awg_autostart},
    "opera":   {"prepare": _opera_prepare, "start": _opera_start,
                "autostart": _opera_autostart},
}


# ─────────────────────────────── сторож ──────────────────────────────

class ForeignGuard:
    """Раз в минуту — :func:`enforce`. Спит, пока отключать нечего."""

    INTERVAL = 60

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()

    def reconfigure(self):
        state = load_state()
        need = bool(state["disabled"]) or state["exclusive"]
        with self._lock:
            alive = self._thread is not None and self._thread.is_alive()
            if need and not alive:
                self._stop_evt = threading.Event()
                self._thread = threading.Thread(
                    target=self._loop, args=(self._stop_evt,),
                    name="foreign-guard", daemon=True)
                self._thread.start()
            elif not need and alive:
                self._stop_evt.set()

    def _stop(self):
        with self._lock:
            self._stop_evt.set()

    def _loop(self, stop_evt):
        while not stop_evt.wait(self.INTERVAL):
            try:
                enforce()
                state = load_state()
                if not state["disabled"] and not state["exclusive"]:
                    return
            except Exception as e:              # noqa: BLE001 — поток живёт
                log.warning("foreign: сторож: %s" % e, source="foreign")


_guard = None


def get_guard() -> ForeignGuard:
    global _guard
    if _guard is None:
        _guard = ForeignGuard()
    return _guard


def boot() -> None:
    """При старте GUI: применить отключения и поднять сторожа.

    Зовётся ДО автоподъёма туннелей GUI: чужой экземпляр, который успел
    стартовать из Entware раньше нас, должен освободить интерфейс.
    """
    enforce()
    get_guard().reconfigure()
