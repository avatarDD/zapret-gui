# api/usque.py
"""
API-модуль управления WARP/MASQUE (usque).

Эндпоинты:
  GET  /api/usque/environment  — детект бинарника
  GET  /api/usque/version      — версия + проверка обновлений
  POST /api/usque/register     — регистрация WARP-сессии
  GET  /api/usque/configs      — список профилей
  POST /api/usque/configs/<name>/up    — старт туннеля
  POST /api/usque/configs/<name>/down  — стоп
  GET  /api/usque/configs/<name>/status
  POST /api/usque/configs/<name>/remove
"""

import json
import os

from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты usque в Bottle-приложении."""

    @app.route("/api/usque/environment", method="GET")
    def usque_environment():
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        env = mgr.detect()

        # Проверяем наличие usque-keenetic в opkg (для установки)
        opkg_available = False
        try:
            import subprocess
            r = subprocess.run(["opkg", "info", "usque-keenetic"],
                               capture_output=True, text=True, timeout=5)
            opkg_available = r.returncode == 0
        except Exception:
            pass

        env["opkg_available"] = opkg_available
        return env

    @app.route("/api/usque/version", method="GET")
    def usque_version():
        from core.usque_manager import get_usque_manager
        from core.config_manager import get_config_manager
        mgr = get_usque_manager()
        env = mgr.detect()
        cfg = get_config_manager()
        return {
            "installed": env["installed"],
            "version": env["version"],
            "arch": env["arch"],
            "installed_tag": cfg.get("usque", "installed_tag", default=""),
        }

    @app.route("/api/usque/register", method="POST")
    def usque_register():
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        data = json.loads(request.body.read()) if request.body else {}
        config_name = data.get("name", "warp-default")
        config_dir = mgr._config_dir()
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "%s.conf" % config_name)
        return mgr.register(config_path)

    @app.route("/api/usque/configs", method="GET")
    def usque_configs():
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        return {"ok": True, "configs": mgr.list_configs()}

    @app.route("/api/usque/configs/<name>/up", method="POST")
    def usque_config_up(name):
        from core.usque_manager import get_usque_manager
        from core.config_manager import get_config_manager
        mgr = get_usque_manager()
        cfg = get_config_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        sni = cfg.get("usque", "default_sni", default="")
        http2 = cfg.get("usque", "http2_enable", default=False)
        return mgr.start(target["iface"], target["path"],
                         sni=sni, http2=http2)

    @app.route("/api/usque/configs/<name>/down", method="POST")
    def usque_config_down(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        return mgr.stop(target["iface"])

    @app.route("/api/usque/configs/<name>/status", method="GET")
    def usque_config_status(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        return mgr.status(target["iface"])

    @app.route("/api/usque/configs/<name>/remove", method="POST")
    def usque_config_remove(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        # Останавливаем если активен
        if target["active"]:
            mgr.stop(target["iface"])

        # Удаляем файл
        try:
            if os.path.isfile(target["path"]):
                os.remove(target["path"])
        except Exception as e:
            return {"ok": False, "error": str(e)}

        return {"ok": True}
