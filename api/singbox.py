# api/singbox.py
"""
REST API для sing-box.

Маршруты (по аналогии с api/awg.py):

  GET    /api/singbox/environment           — полный отчёт об окружении
  POST   /api/singbox/environment/refresh   — сбросить кэш

  GET    /api/singbox/manifest              — manifest.json релиза
  GET    /api/singbox/install/status        — прогресс текущей операции
  POST   /api/singbox/install               — установить бинарь
  POST   /api/singbox/uninstall             — удалить бинарь
  GET    /api/singbox/version               — установленная версия + апдейт

  GET    /api/singbox/configs               — список конфигов
  POST   /api/singbox/configs               — создать (body: name, text|parsed)
  GET    /api/singbox/configs/<name>        — получить конфиг
  PUT    /api/singbox/configs/<name>        — сохранить
  DELETE /api/singbox/configs/<name>        — удалить
  POST   /api/singbox/configs/<name>/up
  POST   /api/singbox/configs/<name>/down
  POST   /api/singbox/configs/<name>/restart
  GET    /api/singbox/configs/<name>/status
  POST   /api/singbox/configs/<name>/validate  — sing-box check -c <file>

  GET    /api/singbox/autostart             — статус автозапуска
  POST   /api/singbox/autostart/<name>      — body: {"enabled": bool}
  POST   /api/singbox/autostart/regenerate
  POST   /api/singbox/autostart/remove
  POST   /api/singbox/autostart/apply

  GET    /api/singbox/subscriptions         — список сохранённых подписок
  POST   /api/singbox/subscriptions         — добавить подписку
                                                (name, url, format, interval_hours)
  PUT    /api/singbox/subscriptions/<id>    — обновить настройки подписки
  DELETE /api/singbox/subscriptions/<id>    — удалить подписку
  POST   /api/singbox/subscriptions/<id>/refresh — force-refresh одной
  POST   /api/singbox/subscriptions/refresh-all  — force-refresh всех
"""

import threading
from bottle import request, response


# Сколько ждать в HTTP-запросе install перед тем как вернуть in_progress
INSTALL_API_WAIT = 8


def register(app):

    # ─────── environment / install ────────────────────────────────

    @app.route("/api/singbox/environment")
    def singbox_environment():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_detector import get_singbox_detector
        return get_singbox_detector().get_environment_report()

    @app.route("/api/singbox/environment/refresh", method="POST")
    def singbox_environment_refresh():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_detector import get_singbox_detector
        return get_singbox_detector().get_environment_report(force=True)

    @app.route("/api/singbox/manifest")
    def singbox_manifest():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            tag = (request.params.get("tag") or "").strip()
            force = request.params.get("force") in ("1", "true", "True")
            data = get_singbox_installer().get_manifest(
                tag=tag, force=force)
            return {"ok": True, "manifest": data}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/singbox/install/status")
    def singbox_install_status():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        return {"ok": True,
                "progress": get_singbox_installer().get_operation_status()}

    @app.route("/api/singbox/install", method="POST")
    def singbox_install():
        """
        Запустить установку в фоне; вернуть результат если уложились
        в INSTALL_API_WAIT, иначе in_progress.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = (body.get("arch") or "").strip()
        tag  = (body.get("tag")  or "").strip()

        from core.singbox_installer import get_singbox_installer
        installer = get_singbox_installer()

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
        finished = done.wait(timeout=INSTALL_API_WAIT)
        if finished:
            return result_box.get("result") or {"ok": False,
                                                 "error": "no result"}
        return {"ok": True, "in_progress": True,
                "progress": installer.get_operation_status()}

    @app.route("/api/singbox/uninstall", method="POST")
    def singbox_uninstall():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            return get_singbox_installer().uninstall()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/singbox/version")
    def singbox_version():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            return get_singbox_installer().check_for_updates()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── configs ──────────────────────────────────────────────

    @app.route("/api/singbox/configs")
    def singbox_configs():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return {"ok": True,
                "configs": get_singbox_manager().list_configs()}

    @app.route("/api/singbox/configs", method="POST")
    def singbox_configs_create():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        text = body.get("text") or ""
        parsed = body.get("parsed")
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().save_config(
            name, text=text, parsed=parsed)

    @app.route("/api/singbox/configs/<name>")
    def singbox_configs_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().get_config(name)
        if not res.get("ok"):
            response.status = 404
        return res

    @app.route("/api/singbox/configs/<name>", method="PUT")
    def singbox_configs_put(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        text = body.get("text") or ""
        parsed = body.get("parsed")
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().save_config(
            name, text=text, parsed=parsed)

    @app.route("/api/singbox/configs/<name>", method="DELETE")
    def singbox_configs_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().delete_config(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/singbox/configs/<name>/up", method="POST")
    def singbox_configs_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().up(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/singbox/configs/<name>/down", method="POST")
    def singbox_configs_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().down(name)

    @app.route("/api/singbox/configs/<name>/restart", method="POST")
    def singbox_configs_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().restart(name)

    @app.route("/api/singbox/configs/<name>/status")
    def singbox_configs_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return {"ok": True, "status": get_singbox_manager().status(name)}

    @app.route("/api/singbox/configs/<name>/validate", method="POST")
    def singbox_configs_validate(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().validate_via_binary(name)

    # ─────── autostart ────────────────────────────────────────────

    @app.route("/api/singbox/autostart")
    def singbox_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import status
        return {"ok": True, "status": status()}

    @app.route("/api/singbox/autostart/<name>", method="POST")
    def singbox_autostart_set(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        enabled = bool(body.get("enabled", False))
        from core.singbox_autostart import set_autostart, regenerate
        r = set_autostart(name, enabled)
        # При смене состояния перегенерим init-скрипт.
        if r.get("ok"):
            regenerate()
        return r

    @app.route("/api/singbox/autostart/regenerate", method="POST")
    def singbox_autostart_regen():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import regenerate
        return regenerate()

    @app.route("/api/singbox/autostart/remove", method="POST")
    def singbox_autostart_remove():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import remove
        return remove()

    @app.route("/api/singbox/autostart/apply", method="POST")
    def singbox_autostart_apply():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import apply_now
        return apply_now()

    # ─────── subscriptions ────────────────────────────────────────

    @app.route("/api/singbox/subscriptions")
    def singbox_subscriptions_list():
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import list_subscriptions, get_refresher
        return {
            "ok": True,
            "subscriptions": list_subscriptions(),
            "refresher": get_refresher().get_status(),
        }

    @app.route("/api/singbox/subscriptions", method="POST")
    def singbox_subscriptions_add():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        url  = (body.get("url")  or "").strip()
        fmt  = (body.get("format") or "auto").strip()
        try:
            interval = int(body.get("interval_hours") or 6)
        except (TypeError, ValueError):
            interval = 6
        if not name or not url:
            response.status = 400
            return {"ok": False, "error": "Нужны поля name и url"}
        from core.subscription_manager import add_subscription
        return add_subscription(name=name, url=url, fmt=fmt,
                                interval_hours=interval)

    @app.route("/api/singbox/subscriptions/<sid>", method="PUT")
    def singbox_subscriptions_update(sid):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        # Передаём через **kwargs — функция возьмёт только известные поля.
        from core.subscription_manager import update_subscription
        kw = {}
        for k in ("name", "url", "format", "interval_hours"):
            if k in body:
                kw[k] = body[k]
        if "interval_hours" in kw:
            try:
                kw["interval_hours"] = max(1, int(kw["interval_hours"]))
            except (TypeError, ValueError):
                kw.pop("interval_hours")
        return update_subscription(sid, **kw)

    @app.route("/api/singbox/subscriptions/<sid>", method="DELETE")
    def singbox_subscriptions_remove(sid):
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import remove_subscription
        return remove_subscription(sid)

    @app.route("/api/singbox/subscriptions/<sid>/refresh", method="POST")
    def singbox_subscriptions_refresh_one(sid):
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import refresh_one
        return refresh_one(sid)

    @app.route("/api/singbox/subscriptions/refresh-all", method="POST")
    def singbox_subscriptions_refresh_all():
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import refresh_all
        return refresh_all()
