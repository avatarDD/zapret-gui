# core/mihomo_autostart.py
"""
Автозапуск mihomo-инстансов через init-скрипт. Аналог
core/singbox_autostart.py.

Хранит флаги в settings.json под ключом `mihomo.autostart[name]`.
Генерит init-скрипт (Entware sh / systemd unit), который при старте
роутера/Linux зовёт `app.py --apply-mihomo-autostart` (как AWG): тот
поднимает все помеченные конфиги тем же кодом, что и кнопка в GUI.
"""

import os
import sys
import threading

from core.log_buffer import log
from core.mihomo_platform import detect_mihomo_platform


# init-скрипт зовёт app.py в CLI-режиме (см. engine_common).
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(APP_DIR, "app.py")
PYTHON_BIN = sys.executable or "/opt/bin/python3"


_lock = threading.Lock()


def _load_settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().current() or {}
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
    cfg = mgr.current() or {}
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


def render_script(platform=None) -> str:
    """Текст init-скрипта под платформу (через app.py, как у AWG)."""
    from core import engine_common
    platform = platform or detect_mihomo_platform()
    return engine_common.render_autostart_script(
        "mihomo", "mihomo", engine_common.script_flavor(platform.name),
        log_path=os.path.join(platform.log_dir, "mihomo-autostart.log"),
        python=PYTHON_BIN, app_py=APP_PY)


def regenerate() -> dict:
    """
    Создать/обновить init-скрипт под текущий набор autostart-конфигов.
    """
    platform = detect_mihomo_platform()
    enabled = [n for n, v in list_autostart().items() if v]
    if not enabled:
        # Если автозапусков не осталось — снимаем init.
        return remove()

    from core.mihomo_detector import get_mihomo_detector
    bin_info = get_mihomo_detector().detect_binary()
    if not bin_info.get("installed"):
        return {"ok": False, "error": "mihomo не установлен"}

    path = platform.install_init_script(render_script(platform))
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
    from core import engine_common
    return engine_common.autostart_status(
        "mihomo", detect_mihomo_platform(), list_autostart())


def apply_now() -> dict:
    """Поднять все enabled-конфиги (UI-кнопка, init-скрипт через
    `app.py --apply-mihomo-autostart`, старт GUI без скрипта)."""
    from core import engine_common
    from core.mihomo_manager import get_mihomo_manager
    return engine_common.autostart_apply("mihomo", get_mihomo_manager(),
                                         list_autostart())


def stop_now() -> dict:
    """Погасить отмеченные конфиги (init-скрипт stop)."""
    from core import engine_common
    from core.mihomo_manager import get_mihomo_manager
    return engine_common.autostart_stop(get_mihomo_manager(),
                                        list_autostart())
