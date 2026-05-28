# core/awg_keenetic_setup.py
"""
Helpers для установки AWG на Keenetic (KeenOS 4.x и 5.x).

Способ подъёма TUN-устройства различается по поколениям:
  - KeenOS 5.x: системный компонент «Поддержка TUN/TAP для OPKG»
    (он же OpkgTun).
  - KeenOS 4.x: opkg-пакет `kmod-tun` либо системный компонент
    «Прокси-сервер OpenVPN», который подтягивает TUN-модуль.
Универсальный индикатор результата в обоих случаях — наличие
`/dev/net/tun`. Платформенная развилка вынесена в
`KeeneticPlatform.tun_instructions()`.
"""

import os
import subprocess

from core.awg_detector import get_awg_detector
from core.awg_platform import KeeneticPlatform, is_keenetic


def _cmd_ok(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def check_opkg_tun() -> dict:
    """
    Полный отчёт о состоянии TUN на Keenetic:

      {
        "is_keenetic":     bool,
        "keenos_version":  str,
        "needs_opkg_tun":  bool,    # True для KeenOS >= 5
        "installed":       bool,    # opkg-tun установлен
        "tun_device":      bool,    # /dev/net/tun существует
        "ready":           bool,    # всё ОК, можно ставить AWG
        "instructions":    str,     # пошаговый текст для пользователя
      }
    """
    det = get_awg_detector()
    platform = det.detect_platform()

    result = {
        "is_keenetic":    is_keenetic(platform),
        "keenos_version": "",
        "needs_opkg_tun": False,
        "installed":      False,
        "tun_device":     os.path.exists("/dev/net/tun"),
        "ready":          False,
        "instructions":   "",
    }

    if not is_keenetic(platform):
        # Не Keenetic — просто отдаём состояние TUN
        result["ready"] = result["tun_device"]
        return result

    result["keenos_version"] = platform._keenos_version
    try:
        major = int((platform._keenos_version or "0").split(".")[0])
    except (ValueError, IndexError):
        major = 0

    result["keenos_major"]   = major
    # На 5.x нужен OpkgTun-компонент; на 4.x достаточно kmod-tun
    # либо системного компонента OpenVPN.
    result["needs_opkg_tun"] = major >= 5

    # Универсальный индикатор для всех поколений: реально появилось ли
    # /dev/net/tun.
    result["installed"] = result["tun_device"]
    result["ready"]     = result["tun_device"]

    if not result["ready"]:
        # Делегируем платформе — она знает версионную развилку.
        result["instructions"] = platform.tun_instructions()

    return result


def generate_install_instructions() -> str:
    """
    Универсальная (версионно-агностичная) подсказка по подъёму TUN
    на Keenetic. Для версионно-специфичной — используйте
    `KeeneticPlatform.tun_instructions()`.
    """
    return (
        "Чтобы amneziawg-go мог поднять TUN-интерфейс, нужен TUN-модуль:\n"
        "  - KeenOS 5.x: установите системный компонент OpkgTun\n"
        "    (Управление → Компоненты → «Поддержка TUN/TAP для OPKG»).\n"
        "  - KeenOS 4.x: opkg install kmod-tun (или включите системный\n"
        "    компонент «Прокси-сервер OpenVPN», который подтянет TUN).\n"
        "После — перезагрузите роутер и повторите установку."
    )
