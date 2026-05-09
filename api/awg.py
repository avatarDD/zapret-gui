# api/awg.py
"""
REST API для интеграции amneziawg-go.

Маршруты:
  GET  /api/awg/environment             — полный отчёт об окружении
  POST /api/awg/environment/refresh     — сбросить кэш и пересканировать

  GET  /api/awg/manifest                — manifest.json последнего релиза
  GET  /api/awg/install/status          — прогресс текущей операции
  POST /api/awg/install                 — установить бинарники
  POST /api/awg/uninstall               — удалить бинарники

  GET  /api/awg/keenetic/opkg-tun       — состояние OpkgTun на Keenetic

  GET    /api/awg/configs               — список конфигов
  POST   /api/awg/configs               — создать новый (JSON: name, text|parsed)
  GET    /api/awg/configs/<name>        — получить конфиг (text + parsed + errors)
  PUT    /api/awg/configs/<name>        — сохранить (text|parsed)
  DELETE /api/awg/configs/<name>        — удалить

  POST   /api/awg/configs/<name>/up     — поднять
  POST   /api/awg/configs/<name>/down   — опустить
  POST   /api/awg/configs/<name>/restart
  GET    /api/awg/configs/<name>/status

  POST   /api/awg/configs/validate      — валидация без сохранения
  POST   /api/awg/keypair               — сгенерировать пару ключей
  GET    /api/awg/interfaces            — все активные AWG/WG интерфейсы
"""

import threading

from bottle import request, response


# Сколько ждём в основном HTTP-запросе перед тем как вернуть in_progress
INSTALL_API_WAIT = 8


def register(app):

    @app.route("/api/awg/environment")
    def awg_environment():
        """
        Полный отчёт об окружении (см. core.awg_detector).
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report()

    @app.route("/api/awg/environment/refresh", method="POST")
    def awg_environment_refresh():
        """Сбросить кэш детекта и вернуть свежий отчёт."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report(force=True)

    # ─────────── manifest / installer ────────────────────────────

    @app.route("/api/awg/manifest")
    def awg_manifest():
        """Manifest последнего релиза с бинарниками AWG."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        try:
            force = request.params.get("force", "").lower() in ("1", "true")
            tag = request.params.get("tag") or None
            manifest = inst.get_manifest(tag=tag, force=force)
            return {"ok": True, "manifest": manifest}
        except RuntimeError as e:
            response.status = 502
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/install/status")
    def awg_install_status():
        """
        Текущий статус установки/удаления + установленная версия +
        информация о target_dir и потенциальных конфликтах с внешней
        установкой.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        op = inst.get_operation_status()
        installed = inst.get_installed_version()
        target = inst.get_target_info()
        return {
            "ok":         True,
            "operation":  op,
            "installed":  installed,
            "target":     target,
        }

    @app.route("/api/awg/install", method="POST")
    def awg_install():
        """
        Запустить установку бинарников. Тело: {"arch": "...", "tag": "..."}.
        Оба поля опциональны — без них берётся detector + последний релиз.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()

        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = body.get("arch") or None
        tag = body.get("tag") or None

        result_holder = {"result": None}

        def task():
            result_holder["result"] = inst.install_binaries(arch=arch, tag=tag)

        t = threading.Thread(target=task, daemon=True, name="awg-install")
        t.start()
        t.join(timeout=INSTALL_API_WAIT)

        if t.is_alive():
            return {
                "ok":          True,
                "in_progress": True,
                "message":     "Установка запущена. Следите за прогрессом.",
            }

        result = result_holder["result"] or {
            "ok": False, "message": "Внутренняя ошибка"
        }
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/uninstall", method="POST")
    def awg_uninstall():
        """Удалить установленные AWG-бинарники."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()

        result = inst.uninstall_binaries()
        if not result.get("ok"):
            response.status = 500
        return result

    # ─────────── Keenetic helpers ───────────────────────────────

    @app.route("/api/awg/keenetic/opkg-tun")
    def awg_keenetic_opkg_tun():
        """Состояние OpkgTun + инструкция (если требуется)."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_keenetic_setup import check_opkg_tun
        return check_opkg_tun()

    # ─────────── Configs CRUD ──────────────────────────────────

    @app.route("/api/awg/configs")
    def awg_configs_list():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "configs": get_awg_manager().list_configs()}

    @app.route("/api/awg/configs", method="POST")
    def awg_configs_create():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        body = request.json or {}
        name = (body.get("name") or "").strip()
        text = body.get("text")
        parsed = body.get("parsed")
        if not name:
            response.status = 400
            return {"ok": False, "error": "name обязателен"}
        try:
            cfg = get_awg_manager().save_config(
                name, text=text, parsed=parsed, allow_overwrite=False
            )
            return {"ok": True, "config": cfg}
        except (ValueError, FileExistsError) as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/validate", method="POST")
    def awg_configs_validate():
        """Распарсить и проверить .conf-текст без сохранения."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_config import parse_conf, validate as validate_cfg
        body = request.json or {}
        text = body.get("text") or ""
        try:
            parsed = parse_conf(text)
            errors = validate_cfg(parsed)
            return {"ok": not errors, "parsed": parsed, "errors": errors}
        except Exception as e:
            response.status = 400
            return {"ok": False, "errors": [str(e)]}

    @app.route("/api/awg/configs/<name>")
    def awg_config_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        try:
            return {"ok": True, "config": get_awg_manager().get_config(name)}
        except FileNotFoundError:
            response.status = 404
            return {"ok": False, "error": "Конфиг не найден"}
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/<name>", method="PUT")
    def awg_config_save(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        body = request.json or {}
        try:
            cfg = get_awg_manager().save_config(
                name, text=body.get("text"), parsed=body.get("parsed"),
                allow_overwrite=True,
            )
            return {"ok": True, "config": cfg}
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/<name>", method="DELETE")
    def awg_config_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        try:
            return get_awg_manager().delete_config(name)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    # ─────────── Interface up/down/status ──────────────────────

    @app.route("/api/awg/configs/<name>/up", method="POST")
    def awg_iface_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().up(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/down", method="POST")
    def awg_iface_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().down(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/restart", method="POST")
    def awg_iface_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().restart(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/status")
    def awg_iface_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "status": get_awg_manager().status(name)}

    @app.route("/api/awg/interfaces")
    def awg_interfaces_list():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "interfaces": get_awg_manager().list_interfaces()}

    # ─────────── Keypair ───────────────────────────────────────

    @app.route("/api/awg/keypair", method="POST")
    def awg_keypair():
        """Сгенерировать пару ключей X25519."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_config import generate_keypair
        from core.awg_installer import get_awg_installer
        info = get_awg_installer().get_installed_version()
        try:
            priv, pub = generate_keypair(awg_binary=info.get("awg") or None)
            return {"ok": True, "private_key": priv, "public_key": pub}
        except RuntimeError as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
