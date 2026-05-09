# core/awg_init_script.py
"""
Генерация init-скриптов для автозапуска AmneziaWG-интерфейсов.

В этом промте мы только формируем содержимое скриптов и сохраняем их
через AwgPlatform.install_init_script(); полноценная интеграция с
autostart-менеджером — следующий этап (промт 11).

Каждый скрипт по умолчанию обрабатывает интерфейсы, имена которых
переданы аргументом или прочитаны из переменной окружения AWG_IFACES.
Если ничего не задано — поднимаются все .conf из config_dir.
"""

from core.awg_platform import (
    AwgPlatform,
    KeeneticPlatform,
    OpenWrtPlatform,
    GenericLinuxPlatform,
)


def render_init_script(platform: AwgPlatform, ifaces=None,
                       gui_url: str = "http://127.0.0.1:8080") -> str:
    """
    Сгенерировать содержимое init-скрипта для платформы.

    Скрипт дёргает API zapret-gui, чтобы поднять/опустить интерфейсы.
    Это делает скрипт максимально простым и переносимым: вся логика
    остаётся в Python-коде GUI.
    """
    iface_arg = ""
    if ifaces:
        iface_arg = ",".join(ifaces)

    if isinstance(platform, OpenWrtPlatform):
        return _openwrt_procd(gui_url, iface_arg)
    if isinstance(platform, GenericLinuxPlatform):
        return _systemd_unit(gui_url, iface_arg)
    # Keenetic / Entware (default)
    return _entware_init(gui_url, iface_arg)


def install_init_script(platform: AwgPlatform, ifaces=None,
                        gui_url: str = "http://127.0.0.1:8080") -> str:
    """
    Записать init-скрипт через platform.install_init_script.
    Возвращает путь к установленному скрипту.
    """
    content = render_init_script(platform, ifaces=ifaces, gui_url=gui_url)
    return platform.install_init_script(content)


# ───────────────────────── Entware (Keenetic) ────────────────────────

def _entware_init(gui_url: str, iface_arg: str) -> str:
    return f"""#!/bin/sh
# zapret-gui: AmneziaWG autostart (Entware/Keenetic)
# Поднимает интерфейсы через REST API локально работающего GUI.

GUI_URL="{gui_url}"
IFACES="${{AWG_IFACES:-{iface_arg}}}"

start() {{
    if [ -n "$IFACES" ]; then
        for i in $(echo "$IFACES" | tr ',' ' '); do
            curl -s -X POST "$GUI_URL/api/awg/configs/$i/up" >/dev/null 2>&1
        done
    else
        curl -s -X POST "$GUI_URL/api/awg/autostart/up" >/dev/null 2>&1
    fi
}}

stop() {{
    if [ -n "$IFACES" ]; then
        for i in $(echo "$IFACES" | tr ',' ' '); do
            curl -s -X POST "$GUI_URL/api/awg/configs/$i/down" >/dev/null 2>&1
        done
    else
        curl -s -X POST "$GUI_URL/api/awg/autostart/down" >/dev/null 2>&1
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

def _openwrt_procd(gui_url: str, iface_arg: str) -> str:
    return f"""#!/bin/sh /etc/rc.common
# zapret-gui: AmneziaWG autostart (OpenWrt procd)
START=95
STOP=10

GUI_URL="{gui_url}"
IFACES="{iface_arg}"

start_service() {{
    if [ -n "$IFACES" ]; then
        for i in $(echo "$IFACES" | tr ',' ' '); do
            curl -s -X POST "$GUI_URL/api/awg/configs/$i/up" >/dev/null 2>&1
        done
    else
        curl -s -X POST "$GUI_URL/api/awg/autostart/up" >/dev/null 2>&1
    fi
}}

stop_service() {{
    if [ -n "$IFACES" ]; then
        for i in $(echo "$IFACES" | tr ',' ' '); do
            curl -s -X POST "$GUI_URL/api/awg/configs/$i/down" >/dev/null 2>&1
        done
    else
        curl -s -X POST "$GUI_URL/api/awg/autostart/down" >/dev/null 2>&1
    fi
}}
"""


# ───────────────────────── systemd ───────────────────────────────────

def _systemd_unit(gui_url: str, iface_arg: str) -> str:
    iface_env = f'Environment="AWG_IFACES={iface_arg}"' if iface_arg else ""
    return f"""[Unit]
Description=zapret-gui AmneziaWG autostart
After=network-online.target zapret-gui.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
{iface_env}
Environment="GUI_URL={gui_url}"
ExecStart=/bin/sh -c 'if [ -n "$AWG_IFACES" ]; then for i in $(echo "$AWG_IFACES" | tr "," " "); do curl -s -X POST "$GUI_URL/api/awg/configs/$i/up" >/dev/null; done; else curl -s -X POST "$GUI_URL/api/awg/autostart/up" >/dev/null; fi'
ExecStop=/bin/sh -c 'if [ -n "$AWG_IFACES" ]; then for i in $(echo "$AWG_IFACES" | tr "," " "); do curl -s -X POST "$GUI_URL/api/awg/configs/$i/down" >/dev/null; done; else curl -s -X POST "$GUI_URL/api/awg/autostart/down" >/dev/null; fi'

[Install]
WantedBy=multi-user.target
"""
