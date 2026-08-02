# core/system_control.py
"""
Перезапуск демона zapret-gui и перезагрузка устройства.

Обе операции разрывают текущее HTTP-соединение (в первом случае умирает
сам процесс, во втором — вся система), поэтому выполняются НЕ синхронно:
мы отвечаем браузеру, а команду запускаем отложенно, в отвязанном
процессе. Иначе клиент всегда видел бы «сеть недоступна» вместо
подтверждения, и было бы неясно, приняли команду или нет.

Способ перезапуска подбирается так же, как в core/autostart_manager:
Entware (S99zapret-gui) → OpenWrt procd → systemd. Перезагрузка на
Keenetic идёт через ndmc (штатный путь прошивки, с корректным
размонтированием), с фолбэком на обычный reboot.
"""

import os
import shutil
import subprocess

from core.log_buffer import log

_ENTWARE_INIT = "/opt/etc/init.d/S99zapret-gui"
_OPENWRT_INIT = "/etc/init.d/zapret-gui"

# Задержка перед выполнением: за это время bottle успевает отдать ответ и
# закрыть соединение. Полсекунды мало на медленном роутере, 2 с хватает с
# запасом и не выглядит зависанием.
_DELAY_SEC = 2


def _detached(command: str) -> dict:
    """Запустить shell-команду отвязанно от текущего процесса.

    start_new_session отвязывает от группы процессов GUI: иначе
    `S99zapret-gui restart` убил бы вместе с GUI и собственного
    родителя, не дойдя до старта.
    """
    try:
        subprocess.Popen(
            ["/bin/sh", "-c", "sleep %d; %s" % (_DELAY_SEC, command)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"ok": True}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def restart_command() -> str:
    """Чем перезапускать демон на этой системе ('' — нечем)."""
    if os.path.isfile(_ENTWARE_INIT):
        return "%s restart" % _ENTWARE_INIT
    if os.path.isfile(_OPENWRT_INIT):
        return "%s restart" % _OPENWRT_INIT
    if (shutil.which("systemctl")
            and os.path.isdir("/etc/systemd/system")):
        return "systemctl restart zapret-gui"
    return ""


def reboot_command() -> str:
    """Чем перезагружать устройство ('' — нечем).

    На Keenetic правильный путь — ndmc: прошивка сама корректно гасит
    сервисы и размонтирует USB. `reboot` там тоже работает, но грубее.
    """
    if shutil.which("ndmc"):
        return 'ndmc -c "system reboot"'
    for path in ("/sbin/reboot", "/usr/sbin/reboot", "/opt/sbin/reboot"):
        if os.path.isfile(path):
            return path
    if shutil.which("reboot"):
        return "reboot"
    return ""


def restart_gui() -> dict:
    """Перезапустить демон zapret-gui (отложенно)."""
    cmd = restart_command()
    if not cmd:
        return {"ok": False,
                "error": "Не найден способ перезапуска: нет ни %s, ни %s, ни"
                         " systemd-юнита zapret-gui. Перезапустите вручную."
                         % (_ENTWARE_INIT, _OPENWRT_INIT)}
    log.warning("Запрошен перезапуск GUI: %s" % cmd, source="system")
    res = _detached(cmd)
    if not res.get("ok"):
        return res
    return {"ok": True, "command": cmd, "delay_sec": _DELAY_SEC,
            "message": "Демон перезапускается. Страница переподключится "
                       "через несколько секунд."}


def reboot_device() -> dict:
    """Перезагрузить устройство целиком (отложенно)."""
    cmd = reboot_command()
    if not cmd:
        return {"ok": False,
                "error": "Не найдена команда перезагрузки (ndmc/reboot)."}
    log.warning("Запрошена ПЕРЕЗАГРУЗКА устройства: %s" % cmd,
                source="system")
    res = _detached(cmd)
    if not res.get("ok"):
        return res
    return {"ok": True, "command": cmd, "delay_sec": _DELAY_SEC,
            "message": "Устройство перезагружается. Это займёт 1–2 минуты."}


def capabilities() -> dict:
    """Что доступно на этой системе — чтобы GUI не показывал мёртвых кнопок."""
    restart = restart_command()
    reboot = reboot_command()
    return {
        "ok": True,
        "restart_gui": bool(restart),
        "reboot": bool(reboot),
        "restart_command": restart,
        "reboot_command": reboot,
    }
