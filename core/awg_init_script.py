# core/awg_init_script.py
"""
Генерация init-скриптов для автозапуска AmneziaWG-интерфейсов.

Скрипты вызывают app.py в CLI-режиме (`--apply-awg-autostart`),
который поднимает все интерфейсы с per-config флагом autostart=true,
применяет к ним routing-правила (это делает AwgManager.up через
core.routing.applier) и восстанавливает WARP-in-WARP, если он был
активен.

Каждый платформенный рендерер возвращает текст; реальная установка
делается через AwgPlatform.install_init_script(). См.
core.awg_autostart_manager.
"""

from core.awg_platform import (
    AwgPlatform,
    OpenWrtPlatform,
    GenericLinuxPlatform,
)


DEFAULT_PYTHON = "/usr/bin/python3"
DEFAULT_APP_PY = "/opt/zapret-gui/app.py"


def render_init_script(platform: AwgPlatform,
                       python_bin: str = DEFAULT_PYTHON,
                       app_py: str = DEFAULT_APP_PY) -> str:
    """Сгенерировать содержимое init-скрипта для платформы."""
    if isinstance(platform, OpenWrtPlatform):
        return _openwrt_procd(python_bin, app_py)
    if isinstance(platform, GenericLinuxPlatform):
        return _systemd_unit(python_bin, app_py)
    # Keenetic / Entware (default)
    return _entware_init(python_bin, app_py)


def install_init_script(platform: AwgPlatform,
                        python_bin: str = DEFAULT_PYTHON,
                        app_py: str = DEFAULT_APP_PY) -> str:
    """
    Записать init-скрипт через platform.install_init_script.
    Возвращает путь к установленному скрипту.
    """
    content = render_init_script(platform, python_bin=python_bin, app_py=app_py)
    return platform.install_init_script(content)


# ───────────────────────── Entware (Keenetic) ────────────────────────

def _entware_init(python_bin: str, app_py: str) -> str:
    return f"""#!/bin/sh
# zapret-gui: AmneziaWG autostart (Entware/Keenetic)
# Поднимает enabled-AWG-интерфейсы и применяет routing-правила.
# Сгенерировано автоматически. Не редактируйте вручную.

PYTHON="{python_bin}"
APP_PY="{app_py}"
LOG="/opt/var/log/awg-gui-autostart.log"

start() {{
    if [ ! -f "$APP_PY" ]; then
        echo "awg-gui-autostart: $APP_PY не найден" >&2
        return 1
    fi
    "$PYTHON" "$APP_PY" --apply-awg-autostart >>"$LOG" 2>&1
}}

stop() {{
    if [ -f "$APP_PY" ]; then
        "$PYTHON" "$APP_PY" --stop-awg-autostart >>"$LOG" 2>&1
    fi
}}

case "$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    *)       echo "Usage: $0 {{start|stop|restart}}"; exit 1 ;;
esac
"""


# ───────────────────────── OpenWrt (procd) ───────────────────────────

def _openwrt_procd(python_bin: str, app_py: str) -> str:
    return f"""#!/bin/sh /etc/rc.common
# zapret-gui: AmneziaWG autostart (OpenWrt procd)
# Сгенерировано автоматически. Не редактируйте вручную.
START=95
STOP=10
USE_PROCD=1

PYTHON="{python_bin}"
APP_PY="{app_py}"
LOG="/var/log/awg-gui-autostart.log"

start_service() {{
    [ -f "$APP_PY" ] || {{
        logger -t awg-gui-autostart "app.py не найден: $APP_PY"
        return 1
    }}
    procd_open_instance
    procd_set_param command /bin/sh -c "$PYTHON $APP_PY --apply-awg-autostart >>$LOG 2>&1"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}}

stop_service() {{
    [ -f "$APP_PY" ] || return 0
    "$PYTHON" "$APP_PY" --stop-awg-autostart >>"$LOG" 2>&1
}}
"""


# ───────────────────────── systemd ───────────────────────────────────

def _systemd_unit(python_bin: str, app_py: str) -> str:
    return f"""[Unit]
Description=zapret-gui AmneziaWG autostart
After=network-online.target zapret-gui.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={python_bin} {app_py} --apply-awg-autostart
ExecStop={python_bin} {app_py} --stop-awg-autostart

[Install]
WantedBy=multi-user.target
"""
