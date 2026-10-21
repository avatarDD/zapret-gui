# core/singbox_autostart.py
"""
Автозапуск sing-box-инстансов через init-скрипт.

Дублирует паттерн `core/awg_autostart_manager.py`, но проще:
sing-box — один бинарь + JSON-конфиг, один процесс на инстанс.

Генерирует init-скрипт, который при старте роутера/Linux зовёт
`app.py --apply-singbox-autostart` (как AWG): тот поднимает все
инсталляции, помеченные `autostart=True` в settings.json под ключом
`singbox.autostart[name]`, тем же кодом, что и кнопка в GUI.
"""

import os
import sys
import threading

from core.log_buffer import log
from core.singbox_platform import detect_singbox_platform


# Путь к app.py — для вызова CLI-режима из init-скрипта (переприменение
# transparent-firewall на загрузке, по аналогии с AWG).
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(APP_DIR, "app.py")
PYTHON_BIN = sys.executable or "/opt/bin/python3"


# ─────── settings ───────

_lock = threading.Lock()


def _load_settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().current() or {}
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
    cfg = get_config_manager().current() or {}
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

def render_script(platform=None) -> str:
    """Текст init-скрипта под платформу (через app.py, как у AWG)."""
    from core import engine_common
    platform = platform or detect_singbox_platform()
    return engine_common.render_autostart_script(
        "singbox", "sing-box", engine_common.script_flavor(platform.name),
        log_path=os.path.join(platform.log_dir, "singbox-autostart.log"),
        python=PYTHON_BIN, app_py=APP_PY)


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

    path = platform.install_init_script(render_script(platform))
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
    from core import engine_common
    return engine_common.autostart_status(
        "singbox", detect_singbox_platform(), list_autostart())


def apply_now() -> dict:
    """Поднять все enabled-конфиги (UI-кнопка, init-скрипт через
    `app.py --apply-singbox-autostart`, старт GUI без скрипта)."""
    from core import engine_common
    from core.singbox_manager import get_singbox_manager
    result = engine_common.autostart_apply("singbox", get_singbox_manager(),
                                           list_autostart())
    # Прозрачное проксирование (firewall) не переживает перезагрузку —
    # переприменяем из сохранённых настроек вместе с движком.
    transparent = None
    try:
        from core.singbox_transparent import reapply_saved
        transparent = reapply_saved()
    except Exception as e:
        log.warning("singbox: reapply transparent: %s" % e, source="singbox")
    result["transparent"] = transparent
    return result


def stop_now() -> dict:
    """Снять прозрачное проксирование и погасить отмеченные конфиги
    (init-скрипт stop через `app.py --stop-singbox-autostart`)."""
    from core import engine_common
    from core.singbox_manager import get_singbox_manager
    transparent = None
    try:
        from core.singbox_transparent import remove as tp_remove
        transparent = tp_remove()
    except Exception as e:
        log.warning("singbox: remove transparent: %s" % e, source="singbox")
    result = engine_common.autostart_stop(get_singbox_manager(),
                                          list_autostart())
    result["transparent"] = transparent
    return result
