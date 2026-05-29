# api/unified.py
"""
REST API единого слоя маршрутизации (core/unified).

  GET    /api/unified/routes              — список маршрутов
  POST   /api/unified/routes              — создать/обновить (route dict)
  GET    /api/unified/routes/<id>
  PUT    /api/unified/routes/<id>
  DELETE /api/unified/routes/<id>
  POST   /api/unified/routes/<id>/apply   — применить один
  POST   /api/unified/apply-all
  GET    /api/unified/status              — сводка (успешность/метод/подсказки)
  POST   /api/unified/monitor             — {enabled, interval}
  POST   /api/unified/routes/<id>/scan    — подбор стратегии (nfqws2)
  POST   /api/unified/apply-best-strategy — применить лучшую найденную
"""

from bottle import request, response


def _json_body():
    try:
        return request.json or {}
    except Exception:
        return {}


def register(app):

    @app.route("/api/unified/routes")
    def unified_routes():
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        return {"ok": True, "routes": manager.list_routes()}

    @app.route("/api/unified/routes", method="POST")
    def unified_routes_create():
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        r = manager.save_route(_json_body())
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/unified/routes/<route_id>")
    def unified_route_get(route_id):
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        item = manager.get_route(route_id)
        if item is None:
            response.status = 404
            return {"ok": False, "error": "Маршрут не найден"}
        return {"ok": True, "route": item}

    @app.route("/api/unified/routes/<route_id>", method="PUT")
    def unified_route_put(route_id):
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        body = _json_body()
        body["id"] = route_id
        r = manager.save_route(body)
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/unified/routes/<route_id>", method="DELETE")
    def unified_route_delete(route_id):
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        r = manager.delete_route(route_id)
        if not r.get("ok"):
            response.status = 404
        return r

    @app.route("/api/unified/routes/<route_id>/apply", method="POST")
    def unified_route_apply(route_id):
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        r = manager.apply_route_by_id(route_id)
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/unified/apply-all", method="POST")
    def unified_apply_all():
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        return manager.apply_all()

    @app.route("/api/unified/status")
    def unified_status():
        response.content_type = "application/json; charset=utf-8"
        from core.unified import manager
        return manager.status()

    @app.route("/api/unified/monitor", method="POST")
    def unified_monitor():
        response.content_type = "application/json; charset=utf-8"
        body = _json_body()
        from core.unified import monitor
        mon = monitor.get_monitor()
        if body.get("enabled"):
            mon.start(interval=int(body.get("interval") or 60))
        else:
            mon.stop()
        return {"ok": True, "running": mon.running()}

    @app.route("/api/unified/routes/<route_id>/scan", method="POST")
    def unified_route_scan(route_id):
        response.content_type = "application/json; charset=utf-8"
        from core.unified import storage, scanner_hint
        route = storage.get_route(route_id)
        if route is None:
            response.status = 404
            return {"ok": False, "error": "Маршрут не найден"}
        body = _json_body()
        r = scanner_hint.run_scan_for_route(
            route, protocol=(body.get("protocol") or "tcp"),
            mode=(body.get("mode") or "quick"))
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/unified/apply-best-strategy", method="POST")
    def unified_apply_best():
        response.content_type = "application/json; charset=utf-8"
        from core.unified import scanner_hint
        r = scanner_hint.apply_best_found()
        if not r.get("ok"):
            response.status = 400
        return r
