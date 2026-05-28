# core/singbox_autostart.py
"""
Автозапуск sing-box-инстансов через init-скрипт.

Дублирует паттерн `core/awg_autostart_manager.py`, но проще:
sing-box — один бинарь + JSON-конфиг, один процесс на инстанс.

Генерирует init-скрипт, который при старте роутера/Linux
поднимает все инсталляции, помеченные `autostart=True` в
settings.json под ключом `singbox.autostart[name]`.
"""

import json
import os
import threading

from core.log_buffer import log
from core.singbox_platform import detect_singbox_platform


# ─────── settings ───────

_lock = threading.Lock()


def _load_settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load() or {}
    except Exception:
        return {}
    sb = cfg.get("singbox") or {}
    return sb if isinstance(sb, dict) else {}


def _save_settings(singbox_section: dict):
    try:
        from core.config_manager import get_config_manager, save_config
    except Exception as e:
        log.warning("singbox_autostart: settings unavailable: %s" % e,
                    source="singbox")
        return
    cfg = get_config_manager().load() or {}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg["singbox"] = singbox_section
    try:
        save_config()
    except Exception as e:
        log.warning("singbox_autostart: save: %s" % e, source="singbox")


def list_autostart() -> dict:
    """{name: bool} — какие конфиги отмечены к автозапуску."""
    sb = _load_settings()
    a = sb.get("autostart") or {}
    if not isinstance(a, dict):
        return {}
    return {str(k): bool(v) for k, v in a.items()}


def set_autostart(name: str, enabled: bool) -> dict:
    """Поставить/снять флаг автозапуска для конфига."""
    if not name:
        return {"ok": False, "error": "Пустое имя"}
    with _lock:
        sb = _load_settings()
        a = sb.get("autostart") or {}
        if not isinstance(a, dict):
            a = {}
        if enabled:
            a[name] = True
        else:
            a.pop(name, None)
        sb["autostart"] = a
        _save_settings(sb)
    return {"ok": True, "autostart": dict(a)}


# ─────── init-script generator ───────

def _entware_init_script(binary: str, configs_dir: str,
                         pids_dir: str, logs_dir: str,
                         names: list) -> str:
    """
    Init-скрипт под Entware (Keenetic / OpenWrt-Entware). BusyBox-shell.
    """
    names_quoted = " ".join('"%s"' % n for n in names)
    return f"""#!/bin/sh
# zapret-gui: sing-box autostart
# Управляется через web-GUI; не редактируйте вручную.

BINARY="{binary}"
CONFIGS_DIR="{configs_dir}"
PIDS_DIR="{pids_dir}"
LOGS_DIR="{logs_dir}"
NAMES={names_quoted}

mkdir -p "$PIDS_DIR" "$LOGS_DIR"

start_one() {{
    name="$1"
    config="$CONFIGS_DIR/$name.json"
    pidfile="$PIDS_DIR/singbox-$name.pid"
    logfile="$LOGS_DIR/singbox-$name.log"
    if [ ! -f "$config" ]; then
        echo "sing-box: пропускаем $name — конфига нет"
        return
    fi
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "sing-box: $name уже запущен"
        return
    fi
    echo "sing-box: запускаем $name"
    setsid "$BINARY" run -c "$config" >> "$logfile" 2>&1 &
    echo $! > "$pidfile"
}}

stop_one() {{
    name="$1"
    pidfile="$PIDS_DIR/singbox-$name.pid"
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            echo "sing-box: останавливаем $name"
            kill -TERM "$pid"
            sleep 1
            kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
        fi
        rm -f "$pidfile"
    fi
}}

case "$1" in
    start)
        for n in $NAMES; do start_one "$n"; done
        ;;
    stop)
        for n in $NAMES; do stop_one "$n"; done
        ;;
    restart)
        for n in $NAMES; do stop_one "$n"; done
        sleep 1
        for n in $NAMES; do start_one "$n"; done
        ;;
    status)
        for n in $NAMES; do
            pidfile="$PIDS_DIR/singbox-$n.pid"
            if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
                echo "$n: running (pid $(cat "$pidfile"))"
            else
                echo "$n: stopped"
            fi
        done
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart|status}}"
        exit 1
        ;;
esac
"""


def _systemd_unit(binary: str, configs_dir: str, pids_dir: str,
                  logs_dir: str, names: list) -> str:
    """
    Простой systemd-юнит. Запускает первый sing-box-инстанс из списка
    (если их несколько — следующий старт делается через `systemctl
    start sing-box-gui@<name>`, который unit-template — позже).
    """
    name = names[0] if names else ""
    return f"""[Unit]
Description=sing-box autostart (zapret-gui)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} run -c {configs_dir}/{name}.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def regenerate() -> dict:
    """
    Создать/обновить init-скрипт под текущий набор autostart-конфигов.
    """
    platform = detect_singbox_platform()
    enabled = [n for n, v in list_autostart().items() if v]
    if not enabled:
        # Если автозапусков не осталось — снимаем init.
        return remove()

    from core.singbox_detector import get_singbox_detector
    bin_info = get_singbox_detector().detect_binary()
    if not bin_info.get("installed"):
        return {"ok": False, "error": "sing-box не установлен"}

    if platform.name == "linux":
        content = _systemd_unit(
            bin_info["path"], platform.config_dir,
            platform.run_dir, platform.log_dir, enabled)
    else:
        content = _entware_init_script(
            bin_info["path"], platform.config_dir,
            platform.run_dir, platform.log_dir, enabled)

    path = platform.install_init_script(content)
    log.info("singbox: автозапуск установлен (%d конфигов): %s"
             % (len(enabled), path), source="singbox")
    return {"ok": True, "path": path, "names": enabled}


def remove() -> dict:
    platform = detect_singbox_platform()
    path = platform.init_script_path()
    if not os.path.exists(path):
        return {"ok": True, "noop": True}
    platform.remove_init_script()
    log.info("singbox: автозапуск удалён: %s" % path, source="singbox")
    return {"ok": True, "path": path}


def status() -> dict:
    platform = detect_singbox_platform()
    path = platform.init_script_path()
    return {
        "installed":   os.path.exists(path),
        "path":        path,
        "autostart":   list_autostart(),
    }


def apply_now() -> dict:
    """Поднять все enabled-конфиги прямо сейчас (для UI-кнопки)."""
    from core.singbox_manager import get_singbox_manager
    mgr = get_singbox_manager()
    results = []
    for name, en in list_autostart().items():
        if not en:
            continue
        results.append({"name": name, "result": mgr.up(name)})
    return {"ok": True, "applied": results}
