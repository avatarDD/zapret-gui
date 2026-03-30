import threading
from bottle import request, response
def register(app):
    @app.route("/api/zapret")
    def api_zapret_status():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        comparison = inst.get_version_comparison()
        running = inst.is_nfqws_running()
        op_status = inst.get_operation_status()
        return {
            "ok": True,
            "installed": comparison["installed"],
            "latest": comparison["latest"],
            "update_available": comparison["update_available"],
            "is_installed": comparison["is_installed"],
            "nfqws_running": running,
            "operation": op_status,
            "arch": inst.get_arch(),
            "platform": inst.get_platform_type(),
        }
    @app.route("/api/zapret/installed")
    def api_zapret_installed():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        data = inst.get_installed_version()
        return {"ok": True, **data}
    @app.route("/api/zapret/latest")
    def api_zapret_latest():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        force = request.params.get("force", "").lower() in ("1", "true", "yes")
        data = inst.get_latest_version(force_refresh=force)
        return data
    @app.route("/api/zapret/check")
    def api_zapret_check():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        comparison = inst.get_version_comparison()
        return {
            "ok": True,
            "update_available": comparison["update_available"],
            "installed_version": comparison["installed"].get("version"),
            "latest_version": comparison["latest"].get("version"),
            "is_installed": comparison["is_installed"],
        }
    @app.route("/api/zapret/running")
    def api_zapret_running():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        data = inst.is_nfqws_running()
        return {"ok": True, **data}
    @app.route("/api/zapret/progress")
    def api_zapret_progress():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        data = inst.get_operation_status()
        return {"ok": True, **data}
    @app.post("/api/zapret/install")
    def api_zapret_install():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        from core.log_buffer import log
        inst = get_zapret_installer()
        installed = inst.get_installed_version()
        if installed["installed"]:
            response.status = 400
            return {
                "ok": False,
                "message": "zapret2 уже установлен (версия: %s). "
                           "Используйте обновление."
                           % (installed["version"] or "?"),
            }
        result_holder = {"result": None}
        def install_task():
            result_holder["result"] = inst.install()
        t = threading.Thread(target=install_task, daemon=True,
                             name="zapret-install")
        t.start()
        t.join(timeout=INSTALL_API_TIMEOUT)
        if t.is_alive():
            return {
                "ok": True,
                "message": "Установка запущена. Следите за прогрессом.",
                "in_progress": True,
            }
        result = result_holder["result"]
        if result:
            if not result.get("ok"):
                response.status = 500
            return result
        response.status = 500
        return {"ok": False, "message": "Внутренняя ошибка установки"}
    @app.post("/api/zapret/update")
    def api_zapret_update():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        installed = inst.get_installed_version()
        if not installed["installed"]:
            response.status = 400
            return {
                "ok": False,
                "message": "zapret2 не установлен. "
                           "Сначала выполните установку.",
            }
        result_holder = {"result": None}
        def update_task():
            result_holder["result"] = inst.update()
        t = threading.Thread(target=update_task, daemon=True,
                             name="zapret-update")
        t.start()
        t.join(timeout=INSTALL_API_TIMEOUT)
        if t.is_alive():
            return {
                "ok": True,
                "message": "Обновление запущено. Следите за прогрессом.",
                "in_progress": True,
            }
        result = result_holder["result"]
        if result:
            if not result.get("ok"):
                response.status = 500
            return result
        response.status = 500
        return {"ok": False, "message": "Внутренняя ошибка обновления"}
    @app.route("/api/zapret/uninstall-plan")
    def api_zapret_uninstall_plan():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        plan = inst.get_uninstall_plan()
        return plan
    @app.post("/api/zapret/uninstall")
    def api_zapret_uninstall():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        try:
            body = request.json or {}
        except Exception:
            body = {}
        if not body.get("confirm"):
            response.status = 400
            return {
                "ok": False,
                "message": "Требуется подтверждение. "
                           "Отправьте {\"confirm\": true}.",
            }
        result_holder = {"result": None}
        def uninstall_task():
            result_holder["result"] = inst.uninstall()
        t = threading.Thread(target=uninstall_task, daemon=True,
                             name="zapret-uninstall")
        t.start()
        t.join(timeout=60)
        if t.is_alive():
            return {
                "ok": True,
                "message": "Удаление запущено. Следите за прогрессом.",
                "in_progress": True,
            }
        result = result_holder["result"]
        if result:
            if not result.get("ok"):
                response.status = 500
            return result
        response.status = 500
        return {"ok": False, "message": "Внутренняя ошибка удаления",
                "removed": []}
    @app.post("/api/zapret/stop")
    def api_zapret_stop():
        response.content_type = "application/json; charset=utf-8"
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        result = inst.stop_nfqws()
        if not result["ok"]:
            response.status = 500
        return result
INSTALL_API_TIMEOUT = 300
