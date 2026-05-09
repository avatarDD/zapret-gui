# core/awg_keenetic_setup.py
"""
Helpers для установки AWG на Keenetic (KeenOS 5.x).

KeenOS 5.x по умолчанию не предоставляет /dev/net/tun — для запуска
amneziawg-go нужен компонент 'opkg-tun'. Этот модуль умеет:
  - детектить наличие opkg-tun
  - возвращать пошаговую инструкцию для пользователя
"""

import os
import subprocess

from core.awg_detector import get_awg_detector
from core.awg_platform import KeeneticPlatform


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
        "is_keenetic":    isinstance(platform, KeeneticPlatform),
        "keenos_version": "",
        "needs_opkg_tun": False,
        "installed":      False,
        "tun_device":     os.path.exists("/dev/net/tun"),
        "ready":          False,
        "instructions":   "",
    }

    if not isinstance(platform, KeeneticPlatform):
        # Не Keenetic — просто отдаём состояние TUN
        result["ready"] = result["tun_device"]
        return result

    result["keenos_version"] = platform._keenos_version
    try:
        major = int((platform._keenos_version or "0").split(".")[0])
    except (ValueError, IndexError):
        major = 0

    result["needs_opkg_tun"] = major >= 5

    if result["needs_opkg_tun"]:
        result["installed"] = _cmd_ok(["opkg", "status", "opkg-tun"])
        result["ready"] = result["installed"] and result["tun_device"]
    else:
        result["installed"] = result["tun_device"]
        result["ready"] = result["tun_device"]

    if not result["ready"]:
        result["instructions"] = generate_install_instructions()

    return result


def generate_install_instructions() -> str:
    """Пошаговая инструкция по установке OpkgTun через веб-админку Keenetic."""
    return (
        "Чтобы amneziawg-go мог поднять TUN-интерфейс на KeenOS 5.x,\n"
        "необходимо установить системный компонент OpkgTun.\n"
        "\n"
        "Шаги:\n"
        "  1. Откройте веб-интерфейс Keenetic (обычно http://192.168.1.1)\n"
        "  2. Перейдите в раздел «Управление → Общие настройки»\n"
        "     → «Изменить набор компонентов».\n"
        "  3. Включите фильтр по слову «opkg».\n"
        "  4. Найдите компонент «Поддержка TUN/TAP для OPKG» (opkg-tun)\n"
        "     и поставьте галочку.\n"
        "  5. Нажмите «Установить обновление». Роутер перезагрузится.\n"
        "  6. После перезагрузки вернитесь сюда и нажмите «Проверить снова»."
    )
