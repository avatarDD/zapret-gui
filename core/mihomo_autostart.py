# core/mihomo_autostart.py
"""
Автозапуск mihomo-инстансов через init-скрипт. Аналог
core/singbox_autostart.py.

Хранит флаги в settings.json под ключом `mihomo.autostart[name]`.
Генерит init-скрипт (Entware sh / systemd unit), который при старте
роутера/Linux поднимает все помеченные конфиги командой
`mihomo -d <config_dir> -f <config>.yaml`.
"""

import os
import threading

from core.log_buffer import log
from core.mihomo_platform import detect_mihomo_platform


_lock = threading.Lock()


def _load_settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load() or {}
    except Exception:
        return {}
    m = cfg.get("mihomo") or {}
    return m if isinstance(m, dict) else {}


def _save_settings(section: dict):
    try:
        from core.config_manager import get_config_manager
    except Exception as e:
        log.warning("mihomo_autostart: settings unavailable: %s" % e,
                    source="mihomo")
        return
    mgr = get_config_manager()
    cfg = mgr.load() or {}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg["mihomo"] = section
    try:
        mgr.save()
    except Exception as e:
        log.warning("mihomo_autostart: save: %s" % e, source="mihomo")


def list_autostart() -> dict:
    m = _load_settings()
    a = m.get("autostart") or {}
    if not isinstance(a, dict):
        return {}
    return {str(k): bool(v) for k, v in a.items()}


def set_autostart(name: str, enabled: bool) -> dict:
    if not name:
        return {"ok": False, "error": "Пустое имя"}
    with _lock:
        m = _load_settings()
        a = m.get("autostart") or {}
        if not isinstance(a, dict):
            a = {}
        if enabled:
            a[name] = True
        else:
            a.pop(name, None)
        m["autostart"] = a
        _save_settings(m)
    return {"ok": True, "autostart": dict(a)}


def _entware_init_script(binary: str, config_dir: str, pids_dir: str,
                         logs_dir: str, names: list) -> str:
    names_quoted = " ".join('"%s"' % n for n in names)
    return f"""#!/bin/sh
# zapret-gui: mihomo autostart
# Управляется через web-GUI; не редактируйте вручную.

BINARY="{binary}"
CONFIG_DIR="{config_dir}"
PIDS_DIR="{pids_dir}"
LOGS_DIR="{logs_dir}"
NAMES={names_quoted}

mkdir -p "$PIDS_DIR" "$LOGS_DIR"

# Прокси под нагрузкой упирается в дефолтные 1024 дескриптора.
ulimit -n 65536 2>/dev/null || true

start_one() {{
    name="$1"
    config="$CONFIG_DIR/$name.yaml"
    pidfile="$PIDS_DIR/mihomo-$name.pid"
    logfile="$LOGS_DIR/mihomo-$name.log"
    if [ ! -f "$config" ]; then
        echo "mihomo: пропускаем $name — конфига нет"
        return
    fi
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "mihomo: $name уже запущен"
        return
    fi
    echo "mihomo: запускаем $name"
    setsid "$BINARY" -d "$CONFIG_DIR" -f "$config" >> "$logfile" 2>&1 &
    echo $! > "$pidfile"
}}

stop_one() {{
    name="$1"
    pidfile="$PIDS_DIR/mihomo-$name.pid"
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            echo "mihomo: останавливаем $name"
            kill -TERM "$pid"
            sleep 1
            kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
        fi
        rm -f "$pidfile"
    fi
}}

case "$1" in
    start)   for n in $NAMES; do start_one "$n"; done ;;
    stop)    for n in $NAMES; do stop_one "$n"; done ;;
    restart) for n in $NAMES; do stop_one "$n"; done; sleep 1;
             for n in $NAMES; do start_one "$n"; done ;;
    status)
        for n in $NAMES; do
            pidfile="$PIDS_DIR/mihomo-$n.pid"
            if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
                echo "$n: running (pid $(cat "$pidfile"))"
            else
                echo "$n: stopped"
            fi
        done ;;
    *) echo "Usage: $0 {{start|stop|restart|status}}"; exit 1 ;;
esac
"""


def _systemd_unit(binary: str, config_dir: str, names: list) -> str:
    name = names[0] if names else ""
    return f"""[Unit]
Description=mihomo autostart (zapret-gui)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} -d {config_dir} -f {config_dir}/{name}.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


def regenerate() -> dict:
    platform = detect_mihomo_platform()
    enabled = [n for n, v in list_autostart().items() if v]
    if not enabled:
        return remove()
    from core.mihomo_detector import get_mihomo_detector
    bin_info = get_mihomo_detector().detect_binary()
    if not bin_info.get("installed"):
        return {"ok": False, "error": "mihomo не установлен"}
    if platform.name == "linux":
        content = _systemd_unit(bin_info["path"], platform.config_dir, enabled)
    else:
        content = _entware_init_script(
            bin_info["path"], platform.config_dir,
            platform.run_dir, platform.log_dir, enabled)
    path = platform.install_init_script(content)
    log.info("mihomo: автозапуск установлен (%d конфигов): %s"
             % (len(enabled), path), source="mihomo")
    return {"ok": True, "path": path, "names": enabled}


def remove() -> dict:
    platform = detect_mihomo_platform()
    path = platform.init_script_path()
    if not os.path.exists(path):
        return {"ok": True, "noop": True}
    platform.remove_init_script()
    log.info("mihomo: автозапуск удалён: %s" % path, source="mihomo")
    return {"ok": True, "path": path}


def status() -> dict:
    platform = detect_mihomo_platform()
    path = platform.init_script_path()
    return {"installed": os.path.exists(path), "path": path,
            "autostart": list_autostart()}


def apply_now() -> dict:
    from core.mihomo_manager import get_mihomo_manager
    mgr = get_mihomo_manager()
    results = []
    for name, en in list_autostart().items():
        if en:
            results.append({"name": name, "result": mgr.up(name)})
    return {"ok": True, "applied": results}
