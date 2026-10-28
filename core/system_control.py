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

Успех перезагрузки проверяется по boot_id ядра, а не по «GUI снова
ответил»: если команда молча не сработала (нет прав, busybox из Entware
не достучался до init прошивки), GUI просто продолжает отвечать, и без
сравнения boot_id страница рапортовала бы об успешной перезагрузке.
Вывод команды пишется в /tmp (это RAM — после настоящей перезагрузки
файла уже нет, а при сбое в нём видна причина).
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

# Вывод команды перезагрузки. /tmp — tmpfs и на OpenWrt, и на Keenetic:
# flash не трогаем, а после удачной перезагрузки файл исчезает сам.
_REBOOT_LOG = "/tmp/zapret-gui-reboot.log"

_NDMC_PATHS = ("/bin/ndmc", "/usr/bin/ndmc", "/sbin/ndmc", "/usr/sbin/ndmc")
_REBOOT_PATHS = ("/sbin/reboot", "/usr/sbin/reboot", "/bin/reboot",
                 "/opt/sbin/reboot")


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


def _ndmc() -> str:
    """Путь к ndmc (Keenetic) или ''. PATH демона может не содержать /bin."""
    found = shutil.which("ndmc")
    if found:
        return found
    for path in _NDMC_PATHS:
        if os.path.isfile(path):
            return path
    return ""


def _reboot_binary() -> str:
    """Системный reboot. Прошивочный (/sbin) раньше Entware-шного (/opt):
    busybox из Entware шлёт сигнал «чужому» init и может не сработать."""
    for path in _REBOOT_PATHS:
        if os.path.isfile(path):
            return path
    return shutil.which("reboot") or ""


def reboot_command() -> str:
    """Чем перезагружать устройство ('' — нечем).

    На Keenetic правильный путь — ndmc: прошивка сама корректно гасит
    сервисы и размонтирует USB. `reboot` там тоже работает, но грубее,
    поэтому идёт запасным вариантом через `||`: если ndmc вернул ошибку,
    роутер всё равно перезагрузится. На OpenWrt `reboot` — это сигнал
    procd, который штатно гасит службы и перезагружает систему.
    """
    ndmc = _ndmc()
    reboot = _reboot_binary()
    parts = []
    if ndmc:
        parts.append('%s -c "system reboot"' % ndmc)
    if reboot:
        parts.append(reboot)
    return " || ".join(parts)


def boot_id() -> str:
    """Идентификатор текущей загрузки ядра ('' — не удалось узнать).

    Меняется при каждой перезагрузке — по нему GUI отличает «роутер
    перезагрузился» от «команда не сработала, GUI просто жив».
    Фолбэк — время загрузки из /proc/stat (btime).
    """
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return "btime-" + line.split()[1]
    except (OSError, IndexError):
        pass
    return ""


def last_reboot_output() -> str:
    """Хвост вывода последней команды перезагрузки этой загрузки ('' — нет)."""
    try:
        with open(_REBOOT_LOG, errors="replace") as f:
            return f.read()[-2000:].strip()
    except OSError:
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
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return {"ok": False,
                "error": "GUI запущен не от root — перезагрузить роутер "
                         "нельзя. Команда: %s" % cmd}
    log.warning("Запрошена ПЕРЕЗАГРУЗКА устройства: %s" % cmd,
                source="system")
    res = _detached("( %s ) >%s 2>&1" % (cmd, _REBOOT_LOG))
    if not res.get("ok"):
        return res
    return {"ok": True, "command": cmd, "delay_sec": _DELAY_SEC,
            "boot_id": boot_id(),
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
        "boot_id": boot_id(),
        "reboot_output": last_reboot_output(),
    }
