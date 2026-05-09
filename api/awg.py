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
        Текущий статус установки/удаления + установленная версия.
        Используется фронтом для polling-а прогресса.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        op = inst.get_operation_status()
        installed = inst.get_installed_version()
        return {
            "ok":         True,
            "operation":  op,
            "installed":  installed,
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
