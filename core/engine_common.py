# core/engine_common.py
"""
Общая обвязка туннельных движков на Go: AmneziaWG (amneziawg-go),
sing-box и mihomo.

Три движка управляются тремя менеджерами, но часть обвязки у них одна и
та же по смыслу — и обязана быть одной и той же по поведению:

  * **лимит памяти Go** (GOGC / GOMEMLIMIT). Все три бинаря — Go-программы
    с одним и тем же сборщиком мусора; на роутере с 128–256 МБ любой из
    них способен разрастись до OOM. Раньше лимит умел только AWG.
  * **режим отладки** — один ключ ``<секция>.debug_log`` у каждого движка.
  * **снимок процесса** для диагностики: RSS, пик памяти, потоки, аптайм.

Настройки лежат в settings.json под секцией движка (``awg``, ``singbox``,
``mihomo``) с одинаковыми именами ключей — так их одинаково читают API,
MCP и init-скрипт (через app.py).
"""

import os

from core.log_buffer import log


ENGINES = ("awg", "singbox", "mihomo")

# Ключи settings.json и значения по умолчанию. Имена исторически взяты у
# AWG (go_mem_enabled/go_gogc/go_memlimit_mb) — не переименовываем, чтобы
# не терять сохранённые у пользователей настройки.
GO_MEM_DEFAULTS = {"enabled": False, "gogc": 50, "memlimit_mb": 64}
_GO_MEM_KEYS = {"enabled": "go_mem_enabled", "gogc": "go_gogc",
                "memlimit_mb": "go_memlimit_mb"}

# Границы: GOGC=0 и GOMEMLIMIT=0 значат «не задавать». Сверху — с запасом
# для ПК/VPS; на роутере полезный диапазон 20–100 и 32–256 МиБ.
GOGC_MAX = 1000
MEMLIMIT_MAX_MB = 16384

# Что движок печатает в лог при отладке и чем она включается — для
# подписей в UI и ответов MCP.
DEBUG_HOW = {
    "awg": "LOG_LEVEL=verbose у amneziawg-go, вывод демона — в лог-файл",
    "singbox": "log.level=debug (overlay-конфиг при запуске)",
    "mihomo": "log-level: debug (launch-конфиг при запуске)",
}


class SettingsError(ValueError):
    """Некорректное значение настройки обвязки (для API → 400)."""


def _engine(engine: str) -> str:
    engine = (engine or "").strip().lower()
    if engine not in ENGINES:
        raise SettingsError("неизвестный движок «%s» (есть: %s)"
                            % (engine, ", ".join(ENGINES)))
    return engine


def _cm():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _int(value, name: str, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingsError("%s: ожидается целое число, получено %r"
                            % (name, value))
    if n < lo or n > hi:
        raise SettingsError("%s: допустимо %d…%d, получено %d"
                            % (name, lo, hi, n))
    return n


# ───────────────────────── лимит памяти Go ──────────────────────────

def go_memory_get(engine: str) -> dict:
    """Текущие настройки лимита памяти движка: {enabled, gogc, memlimit_mb}."""
    engine = _engine(engine)
    cm = _cm()
    out = {}
    for field, key in _GO_MEM_KEYS.items():
        value = cm.get(engine, key, default=GO_MEM_DEFAULTS[field])
        if field == "enabled":
            out[field] = bool(value)
        else:
            try:
                out[field] = max(0, int(value))
            except (TypeError, ValueError):
                out[field] = GO_MEM_DEFAULTS[field]
    return out


def go_memory_set(engine: str, enabled=None, gogc=None,
                  memlimit_mb=None) -> dict:
    """Изменить лимит памяти движка (любое подмножество полей).

    Проверяем всё ДО записи: половина сохранённых полей при ошибке во
    второй — худший исход для настройки, которую применяют при подъёме.
    """
    engine = _engine(engine)
    updates = {}
    if enabled is not None:
        updates["go_mem_enabled"] = bool(enabled)
    if gogc is not None:
        updates["go_gogc"] = _int(gogc, "gogc", 0, GOGC_MAX)
    if memlimit_mb is not None:
        updates["go_memlimit_mb"] = _int(memlimit_mb, "memlimit_mb",
                                         0, MEMLIMIT_MAX_MB)
    if updates:
        # Пишем все три поля разом: показанное в GUI (с умолчаниями) и
        # применённое при запуске должно совпадать, даже если в
        # settings.json какого-то ключа ещё не было.
        current = go_memory_get(engine)
        for field, key in _GO_MEM_KEYS.items():
            updates.setdefault(key, current[field])
        cm = _cm()
        for key, value in updates.items():
            cm.set(engine, key, value)
        cm.save()
        log.info("%s: лимит памяти Go — %s" % (engine, go_memory_get(engine)),
                 source=engine)
    return go_memory_get(engine)


def go_memory_vars(engine: str) -> dict:
    """Переменные окружения лимита: {} если выключен или всё по нулям."""
    try:
        s = go_memory_get(engine)
    except Exception:                       # noqa: BLE001 — запуск важнее
        return {}
    if not s["enabled"]:
        return {}
    out = {}
    if s["gogc"] > 0:
        out["GOGC"] = str(s["gogc"])
    if s["memlimit_mb"] > 0:
        out["GOMEMLIMIT"] = "%dMiB" % s["memlimit_mb"]
    return out


def launch_env(engine: str, extra: dict = None):
    """Окружение для запуска бинаря движка.

    None — наследовать окружение GUI как есть (лимит выключен, добавок
    нет): так запуск без настроек остаётся байт-в-байт прежним.
    """
    add = dict(go_memory_vars(engine))
    add.update(extra or {})
    if not add:
        return None
    env = dict(os.environ)
    env.update(add)
    return env


# ───────────────────────── режим отладки ────────────────────────────

def debug_enabled(engine: str) -> bool:
    try:
        return bool(_cm().get(_engine(engine), "debug_log", default=False))
    except Exception:                       # noqa: BLE001
        return False


def set_debug(engine: str, enabled: bool) -> dict:
    engine = _engine(engine)
    try:
        cm = _cm()
        cm.set(engine, "debug_log", bool(enabled))
        cm.save()
    except Exception as e:                  # noqa: BLE001 — ответ API
        return {"ok": False, "error": str(e)}
    log.info("%s: режим отладки %s" % (engine, "включён" if enabled
                                       else "выключен"), source=engine)
    return {"ok": True, "enabled": bool(enabled)}


# ───────────────────────── лог-файлы ────────────────────────────────

def tail_file(path: str, lines: int = 80) -> str:
    """Последние `lines` строк файла (читаем только хвост, не весь файл)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            # Прикинем: 200 байт на строку с запасом.
            block = min(size, max(1, lines) * 200)
            f.seek(size - block)
            data = f.read(block)
        text = data.decode("utf-8", errors="replace")
        return "\n".join(text.splitlines()[-lines:])
    except (IOError, OSError):
        return ""


# ───────────────────────── init-скрипт автозапуска ──────────────────
#
# Как у AWG (core/awg_init_script.py): скрипт не запускает бинарь сам, а
# зовёт app.py в CLI-режиме. Тогда при загрузке движок поднимается ТЕМ ЖЕ
# кодом, что и кнопкой в GUI: все отмеченные конфиги (systemd-юнит раньше
# поднимал только первый), с режимом отладки, лимитом памяти Go, проверкой
# конфига, перехватом DNS для FakeIP и прозрачным проксированием.
# Содержимое скрипта не зависит от списка конфигов — список читается из
# settings.json при старте, поэтому скрипт не надо пересоздавать на
# каждую галку.

APP_PY = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "app.py")

# Вид скрипта по имени платформы движка (platform.name).
FLAVORS = {"linux": "systemd", "openwrt": "procd"}


def python_bin() -> str:
    import sys
    return sys.executable or "/opt/bin/python3"


def script_flavor(platform_name: str) -> str:
    return FLAVORS.get(platform_name, "sh")


def _flags(engine: str):
    return ("--apply-%s-autostart" % engine, "--stop-%s-autostart" % engine)


def render_autostart_script(engine: str, label: str, flavor: str,
                            log_path: str, python: str = "",
                            app_py: str = "") -> str:
    """Init-скрипт автозапуска движка через app.py.

    engine — суффикс CLI-флагов (--apply-<engine>-autostart /
    --stop-<engine>-autostart), label — имя для людей (sing-box, mihomo),
    flavor — systemd | procd (OpenWrt, rc.common) | sh (Entware).

    systemd: ExecStart с «-» — частичный отказ (один конфиг из трёх не
    поднялся) не должен делать юнит failed: тогда systemd прибил бы весь
    cgroup юнита вместе с поднявшимися инстансами.
    """
    python = python or python_bin()
    app_py = app_py or APP_PY
    apply_flag, stop_flag = _flags(engine)
    if flavor == "systemd":
        return f"""[Unit]
Description={label} autostart (zapret-gui)
After=network-online.target zapret-gui.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-{python} {app_py} {apply_flag}
ExecStop=-{python} {app_py} {stop_flag}

[Install]
WantedBy=multi-user.target
"""
    if flavor == "procd":
        return f"""#!/bin/sh /etc/rc.common
# zapret-gui: {label} autostart (OpenWrt)
# Поднимает отмеченные в GUI конфиги через app.py (как кнопка «Запустить»).
# Управляется через web-GUI; не редактируйте вручную.
START=96
STOP=09

PYTHON="{python}"
APP_PY="{app_py}"
LOG="{log_path}"

start() {{
    [ -f "$APP_PY" ] || {{
        logger -t {engine}-gui-autostart "app.py не найден: $APP_PY"
        return 1
    }}
    "$PYTHON" "$APP_PY" {apply_flag} >>"$LOG" 2>&1
}}

stop() {{
    [ -f "$APP_PY" ] || return 0
    "$PYTHON" "$APP_PY" {stop_flag} >>"$LOG" 2>&1
}}
"""
    return f"""#!/bin/sh
# zapret-gui: {label} autostart
# Поднимает отмеченные в GUI конфиги через app.py (как кнопка «Запустить»).
# Управляется через web-GUI; не редактируйте вручную.

PYTHON="{python}"
APP_PY="{app_py}"
LOG="{log_path}"

start() {{
    if [ ! -f "$APP_PY" ]; then
        echo "{label}: $APP_PY не найден" >&2
        return 1
    fi
    "$PYTHON" "$APP_PY" {apply_flag} >>"$LOG" 2>&1
}}

stop() {{
    [ -f "$APP_PY" ] || return 0
    "$PYTHON" "$APP_PY" {stop_flag} >>"$LOG" 2>&1
}}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    *)       echo "Usage: $0 {{start|stop|restart}}"; exit 1 ;;
esac
"""


def script_is_current(engine: str, platform, app_py: str = "") -> bool:
    """Установленный скрипт — нового образца (зовёт app.py нужного вида).

    Не сравниваем побайтно: путь интерпретатора в тексте зависит от того,
    под каким python запущен GUI (venv, python3 vs python3.11), и такой
    скрипт рабочий — переписывать его на каждом старте незачем. Старый
    образец (бинарь напрямую, на systemd — только первый конфиг) флага
    --apply-<engine>-autostart не содержит.
    """
    try:
        with open(platform.init_script_path(), "r") as f:
            text = f.read()
    except OSError:
        return False
    apply_flag, _stop = _flags(engine)
    if apply_flag not in text or (app_py or APP_PY) not in text:
        return False
    flavor = script_flavor(platform.name)
    if flavor == "systemd":
        return "ExecStart=-" in text
    if flavor == "procd":
        return text.startswith("#!/bin/sh /etc/rc.common")
    return True


def autostart_status(engine: str, platform, autostart: dict) -> dict:
    """Состояние автозапуска — одна форма у sing-box и mihomo, а имена
    script_installed/script_path — те же, что у AWG."""
    path = platform.init_script_path()
    installed = os.path.exists(path)
    return {
        "installed": installed, "path": path,
        "script_installed": installed, "script_path": path,
        "up_to_date": (script_is_current(engine, platform)
                       if installed else None),
        "autostart": autostart,
    }


def autostart_apply(engine: str, mgr, autostart: dict) -> dict:
    """Поднять отмеченные конфиги. Конфиг, которого уже нет (удалили, не
    сняв галку), пропускаем — это не отказ автозапуска, как и раньше в
    shell-скрипте («пропускаем — конфига нет»)."""
    existing = {c.get("name") for c in (mgr.list_configs() or [])}
    results = []
    for name, enabled in autostart.items():
        if not enabled:
            continue
        if name not in existing:
            log.warning("%s autostart: конфига %s нет — пропуск"
                        % (engine, name), source=engine)
            results.append({"name": name, "skipped": True,
                            "result": {"ok": True,
                                       "message": "Конфиг не найден"}})
            continue
        results.append({"name": name, "result": mgr.up(name)})
    ok = all((r["result"] or {}).get("ok") for r in results)
    return {"ok": ok, "applied": results}


def autostart_stop(mgr, autostart: dict) -> dict:
    results = [{"name": name, "result": mgr.down(name)}
               for name, enabled in autostart.items() if enabled]
    return {"ok": True, "stopped": results}


# ───────────────────────── размер логов движков ─────────────────────
#
# Движки пишут лог в файл всё время работы (sing-box/mihomo — всегда,
# amneziawg-go — в режиме отладки), а в отладке это десятки строк в
# минуту. На роутере /opt/var/log — флешка, /var/log — tmpfs в ОЗУ:
# неограниченный лог рано или поздно кладёт роутер. Сторож раз в
# LOG_GUARD_INTERVAL обрезает такие файлы до хвоста. Обрезать на месте
# безопасно: движки держат лог с O_APPEND и пишут в новый конец.

LOG_MAX_BYTES = 2 * 1024 * 1024
LOG_KEEP_BYTES = 256 * 1024
LOG_GUARD_INTERVAL = 600


def trim_log(path: str, max_bytes: int = LOG_MAX_BYTES,
             keep_bytes: int = LOG_KEEP_BYTES) -> bool:
    """Оставить от лога последние keep_bytes, если он больше max_bytes."""
    try:
        if os.path.getsize(path) <= max_bytes:
            return False
        with open(path, "r+b") as f:
            f.seek(-keep_bytes, 2)
            tail = f.read()
            # Начинаем с целой строки.
            cut = tail.find(b"\n")
            if 0 <= cut < len(tail) - 1:
                tail = tail[cut + 1:]
            f.seek(0)
            f.truncate()
            f.write(b"--- zapret-gui: older log lines dropped ---\n" + tail)
        return True
    except OSError:
        return False


def _engine_log_files() -> list:
    import glob
    out = []
    for prefix, detect in (
            ("awg", "core.awg_detector:get_awg_detector"),
            ("singbox", "core.singbox_platform:detect_singbox_platform"),
            ("mihomo", "core.mihomo_platform:detect_mihomo_platform")):
        try:
            mod_name, fn = detect.split(":")
            mod = __import__(mod_name, fromlist=[fn])
            obj = getattr(mod, fn)()
            platform = (obj.detect_platform() if prefix == "awg" else obj)
            out.extend(glob.glob(os.path.join(platform.log_dir,
                                              "%s-*.log" % prefix)))
        except Exception:                   # noqa: BLE001 — сторож живёт
            continue
    return out


_log_guard = None


def start_log_guard(interval: int = LOG_GUARD_INTERVAL):
    """Фоновый поток, обрезающий логи трёх движков (идемпотентно)."""
    import threading

    global _log_guard
    if _log_guard is not None and _log_guard.is_alive():
        return _log_guard

    def _loop():
        import time
        while True:
            for path in _engine_log_files():
                if trim_log(path):
                    log.info("лог %s обрезан до последних %d КБ"
                             % (path, LOG_KEEP_BYTES // 1024),
                             source="engines")
            time.sleep(interval)

    _log_guard = threading.Thread(target=_loop, daemon=True,
                                  name="engine-log-guard")
    _log_guard.start()
    return _log_guard


# ───────────────────────── снимок процесса ──────────────────────────

def _clock_ticks() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK")) or 100
    except (ValueError, OSError, AttributeError):
        return 100


def process_info(pid, proc_root: str = "/proc") -> dict:
    """RSS, пик RSS, число потоков и аптайм процесса из /proc.

    Пустой dict — процесса нет или /proc недоступен (не Linux). Нужен
    диагностике: «движок съел всю память» и «движок перезапускался
    минуту назад» видно отсюда, а не из лога.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {}
    if pid <= 0:
        return {}
    base = os.path.join(proc_root, str(pid))
    info = {"pid": pid}
    try:
        with open(os.path.join(base, "status"), "r") as f:
            for line in f:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if key == "VmRSS" and parts:
                    info["rss_kb"] = int(parts[0])
                elif key == "VmHWM" and parts:
                    info["rss_peak_kb"] = int(parts[0])
                elif key == "Threads" and parts:
                    info["threads"] = int(parts[0])
    except (OSError, ValueError):
        return {}
    try:
        with open(os.path.join(base, "stat"), "r") as f:
            stat = f.read()
        # Имя процесса в скобках может содержать пробелы — режем по
        # последней «)», дальше поля фиксированные (starttime — 22-е).
        fields = stat.rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])
        with open(os.path.join(proc_root, "uptime"), "r") as f:
            uptime = float(f.read().split()[0])
        info["uptime_sec"] = max(0, int(uptime - start_ticks / _clock_ticks()))
    except (OSError, ValueError, IndexError):
        pass
    return info


def controller_check(ep: dict, timeout: float = 2.0) -> dict:
    """Отвечает ли Clash API движка: GET /version мимо системных прокси.

    Без ProxyHandler({}) urllib пошёл бы на 127.0.0.1 через HTTP(S)_PROXY
    окружения — и «контроллер мёртв» оказался бы правдой про прокси.
    """
    import json
    import urllib.request

    if not ep:
        return {"configured": False}
    host = ep.get("host") or "127.0.0.1"
    url = "http://%s:%s/version" % (
        "[%s]" % host if ":" in host else host, ep.get("port"))
    out = {"configured": True, "endpoint": "%s:%s" % (host, ep.get("port"))}
    req = urllib.request.Request(url)
    if ep.get("secret"):
        req.add_header("Authorization", "Bearer %s" % ep["secret"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
        out["reachable"] = True
        try:
            out["version"] = (json.loads(body) or {}).get("version", "")
        except ValueError:
            pass
    except Exception as e:                  # noqa: BLE001 — это и есть ответ
        out["reachable"] = False
        out["error"] = str(e)
    return out


def _cmd(args, timeout: float = 5.0) -> str:
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return "%s: %s" % (args[0], e)


def file_meta(path: str) -> dict:
    try:
        st = os.stat(path)
    except OSError:
        return {"path": path, "exists": False}
    return {"path": path, "exists": True, "size": st.st_size,
            "mtime": int(st.st_mtime)}


def proxy_diagnostics(engine: str, name: str, *, pid, active: bool,
                      binary: dict, config_path: str, config_check: dict,
                      log_path: str, autostart, controller=None,
                      tun_iface: str = "", extra: dict = None) -> dict:
    """Снимок прокси-движка (sing-box / mihomo) для кнопки «Диагностика».

    Аналог AwgManager.diagnostics: всё, что нужно, чтобы понять, почему
    инстанс не работает, одним ответом — и в баг-репорт. Секрет
    контроллера и текст конфига (там ключи) сюда НЕ попадают.
    """
    errors = []
    try:
        from core.version import GUI_VERSION as gui_version
    except Exception:                       # noqa: BLE001
        gui_version = "?"

    info = {
        "engine": engine,
        "name": name,
        "gui_version": gui_version,
        "active": bool(active),
        "process": process_info(pid) if (active and pid) else {},
        "binary": {"path": (binary or {}).get("path", ""),
                   "installed": bool((binary or {}).get("installed")),
                   "version": (binary or {}).get("version", "")},
        "config": file_meta(config_path),
        "config_check": config_check or {},
        "wrapper": {
            "debug": debug_enabled(engine),
            "go_memory": go_memory_get(engine),
            "go_env": go_memory_vars(engine),
            "autostart": autostart,
        },
        "controller": {"configured": False},
        "tun": {},
        "log_path": log_path,
        "log_tail": tail_file(log_path, 80),
        "gui_log_tail": gui_log_tail(engine, 40, needle=name),
        "errors": errors,
    }
    if controller:
        info["controller"] = (controller_check(controller) if active
                              else {"configured": True,
                                    "endpoint": "%s:%s" % (
                                        controller.get("host"),
                                        controller.get("port")),
                                    "reachable": None})
    if tun_iface:
        info["tun"] = {"iface": tun_iface,
                       "addr": _cmd(["ip", "addr", "show", "dev", tun_iface])
                       if active else ""}
    if extra:
        info.update(extra)
    return info


def gui_log_tail(source: str, limit: int = 60, needle: str = "") -> list:
    """Последние записи GUI-лога движка (кольцевой буфер в памяти).

    needle — оставить только строки, где упомянут конфиг: в общем
    источнике движка перемешаны все его инстансы.
    """
    try:
        from core.log_buffer import get_log_buffer
        return get_log_buffer().get_filtered(source=source, search=needle
                                             or None, n=limit) or []
    except Exception:                       # noqa: BLE001
        return []
