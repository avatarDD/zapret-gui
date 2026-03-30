from bottle import request, response
def register(app):
    @app.route("/api/autostart")
    def api_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        status = am.get_status()
        return {"ok": True, **status}
    @app.post("/api/autostart/enable")
    def api_autostart_enable():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        result = am.enable()
        if not result["ok"]:
            response.status = 400
        return result
    @app.post("/api/autostart/disable")
    def api_autostart_disable():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        result = am.disable()
        return result
    @app.post("/api/autostart/regenerate")
    def api_autostart_regenerate():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        result = am.regenerate()
        if not result["ok"]:
            response.status = 400
        return result
    @app.route("/api/autostart/script")
    def api_autostart_script():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        content = am.get_script_content()
        return {
            "ok": True,
            "script": content,
            "exists": bool(content),
        }
    @app.route("/api/autostart/preview")
    def api_autostart_preview():
        response.content_type = "application/json; charset=utf-8"
        from core.autostart_manager import get_autostart_manager
        am = get_autostart_manager()
        preview = am.get_script_preview()
        return {
            "ok": True,
            "script": preview,
        }
