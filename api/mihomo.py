# api/mihomo.py
"""
REST API для mihomo (Clash.Meta). По структуре повторяет api/singbox.py.

  GET    /api/mihomo/environment
  POST   /api/mihomo/environment/refresh
  GET    /api/mihomo/install/status
  POST   /api/mihomo/install               — body: {arch?, tag?}
  POST   /api/mihomo/uninstall
  GET    /api/mihomo/version

  GET    /api/mihomo/configs
  POST   /api/mihomo/configs               — body: {name, text}
  GET    /api/mihomo/configs/<name>
  PUT    /api/mihomo/configs/<name>        — body: {text}
  DELETE /api/mihomo/configs/<name>
  POST   /api/mihomo/configs/<name>/up
  POST   /api/mihomo/configs/<name>/down
  POST   /api/mihomo/configs/<name>/restart
  GET    /api/mihomo/configs/<name>/status
  POST   /api/mihomo/configs/<name>/validate   — mihomo -t -f <file>

  GET    /api/mihomo/autostart
  POST   /api/mihomo/autostart/<name>      — body: {"enabled": bool}
  POST   /api/mihomo/autostart/regenerate
  POST   /api/mihomo/autostart/remove
  POST   /api/mihomo/autostart/apply
"""

import threading
from bottle import request, response


INSTALL_API_WAIT = 8


def register(app):

    # ─────── environment / install ────────────────────────────────

    @app.route("/api/mihomo/environment")
    def mihomo_environment():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_detector import get_mihomo_detector
        return get_mihomo_detector().get_environment_report()

    @app.route("/api/mihomo/environment/refresh", method="POST")
    def mihomo_environment_refresh():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_detector import get_mihomo_detector
        return get_mihomo_detector().get_environment_report(force=True)

    @app.route("/api/mihomo/install/status")
    def mihomo_install_status():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        return {"ok": True,
                "progress": get_mihomo_installer().get_operation_status()}

    @app.route("/api/mihomo/install", method="POST")
    def mihomo_install():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = (body.get("arch") or "").strip()
        tag  = (body.get("tag")  or "").strip()

        from core.mihomo_installer import get_mihomo_installer
        installer = get_mihomo_installer()
        result_box = {}
        done = threading.Event()

        def _run():
            try:
                result_box["result"] = installer.install(arch=arch, tag=tag)
            except Exception as e:
                result_box["result"] = {"ok": False, "error": str(e)}
            finally:
                done.set()

        threading.Thread(target=_run, daemon=True).start()
        if done.wait(timeout=INSTALL_API_WAIT):
            return result_box.get("result") or {"ok": False,
                                                "error": "no result"}
        return {"ok": True, "in_progress": True,
                "progress": installer.get_operation_status()}

    @app.route("/api/mihomo/uninstall", method="POST")
    def mihomo_uninstall():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        try:
            return get_mihomo_installer().uninstall()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/mihomo/version")
    def mihomo_version():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        try:
            return get_mihomo_installer().check_for_updates()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── configs ──────────────────────────────────────────────

    @app.route("/api/mihomo/configs")
    def mihomo_configs():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return {"ok": True, "configs": get_mihomo_manager().list_configs()}

    @app.route("/api/mihomo/configs", method="POST")
    def mihomo_configs_create():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        text = body.get("text") or ""
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().save_config(name, text=text)

    @app.route("/api/mihomo/configs/<name>")
    def mihomo_configs_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().get_config(name)
        if not res.get("ok"):
            response.status = 404
        return res

    @app.route("/api/mihomo/configs/<name>", method="PUT")
    def mihomo_configs_put(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().save_config(name, text=body.get("text") or "")

    @app.route("/api/mihomo/configs/<name>", method="DELETE")
    def mihomo_configs_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().delete_config(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/mihomo/configs/<name>/up", method="POST")
    def mihomo_configs_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().up(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/mihomo/configs/<name>/down", method="POST")
    def mihomo_configs_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().down(name)

    @app.route("/api/mihomo/configs/<name>/restart", method="POST")
    def mihomo_configs_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().restart(name)

    @app.route("/api/mihomo/configs/<name>/status")
    def mihomo_configs_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return {"ok": True, "status": get_mihomo_manager().status(name)}

    @app.route("/api/mihomo/configs/<name>/validate", method="POST")
    def mihomo_configs_validate(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().validate_via_binary(name)

    # ─────── autostart ────────────────────────────────────────────

    @app.route("/api/mihomo/autostart")
    def mihomo_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import status
        return {"ok": True, "status": status()}

    @app.route("/api/mihomo/autostart/<name>", method="POST")
    def mihomo_autostart_set(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        enabled = bool(body.get("enabled", False))
        from core.mihomo_autostart import set_autostart, regenerate
        r = set_autostart(name, enabled)
        if r.get("ok"):
            regenerate()
        return r

    @app.route("/api/mihomo/autostart/regenerate", method="POST")
    def mihomo_autostart_regen():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import regenerate
        return regenerate()

    @app.route("/api/mihomo/autostart/remove", method="POST")
    def mihomo_autostart_remove():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import remove
        return remove()

    @app.route("/api/mihomo/autostart/apply", method="POST")
    def mihomo_autostart_apply():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import apply_now
        return apply_now()
