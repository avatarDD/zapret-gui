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
        import re
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        data = request.json or {}
        config_name = data.get("name", "warp-default")

        # MR-08: валидация config_name против path-traversal → root RCE
        # config_name="../../etc/init.d/S99evil" → usque пишет .conf туда
        # → S99* автозапускается при буте → RCE
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", config_name):
            return {"ok": False, "error": "Недопустимое имя конфига (только a-z A-Z 0-9 _ -)"}

        config_dir = mgr._config_dir()
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "%s.conf" % config_name)

        # Дополнительная проверка через realpath (защита от symlink-атак)
        real_config_dir = os.path.realpath(config_dir)
        real_config_path = os.path.realpath(config_path)
        if not real_config_path.startswith(real_config_dir + os.sep):
            return {"ok": False, "error": "path traversal denied"}

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

    @app.route("/api/usque/environment/refresh", method="POST")
    def usque_environment_refresh():
        return usque_environment()

    @app.route("/api/usque/install/status", method="GET")
    def usque_install_status():
        from core.ext_binary_installer import get_operation_status
        return {"ok": True, "progress": get_operation_status("usque")}

    @app.route("/api/usque/install", method="POST")
    def usque_install():
        import threading
        from core.ext_binary_installer import install_binary_by_name, _operation_status

        name = "usque"
        _operation_status[name] = {"status": "starting", "progress": 0, "message": "Запуск установки..."}

        def _cb(stage, pct, label):
            _operation_status[name] = {"status": stage, "progress": pct, "message": label}

        def _run():
            try:
                res = install_binary_by_name(name, progress_cb=_cb)
                if res.get("ok"):
                    _operation_status[name] = {"status": "done", "progress": 100, "message": "Установка завершена"}
                else:
                    _operation_status[name] = {"status": "error", "progress": 0, "message": res.get("error", "Ошибка")}
            except Exception as e:
                _operation_status[name] = {"status": "error", "progress": 0, "message": str(e)}

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "progress": _operation_status[name]}

    @app.route("/api/usque/uninstall", method="POST")
    def usque_uninstall():
        from core.ext_binary_installer import uninstall_binary
        return uninstall_binary("usque")
