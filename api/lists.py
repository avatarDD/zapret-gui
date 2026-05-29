# api/lists.py
"""
REST API для именованных списков (core/named_lists).

  GET    /api/lists              — все списки (с подсчётом записей)
  POST   /api/lists              — создать {name, description, entries}
  GET    /api/lists/<id>         — получить один список
  PUT    /api/lists/<id>         — обновить {name?, description?, entries?, replace?}
  DELETE /api/lists/<id>         — удалить
"""

from bottle import request, response


def register(app):

    @app.route("/api/lists")
    def lists_all():
        response.content_type = "application/json; charset=utf-8"
        from core import named_lists
        return {"ok": True, "lists": named_lists.list_all()}

    @app.route("/api/lists", method="POST")
    def lists_create():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import named_lists
        r = named_lists.create(
            (body.get("name") or "").strip(),
            description=body.get("description") or "",
            entries=body.get("entries"),
            source_url=body.get("source_url") or "")
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/lists/<list_id>")
    def lists_get(list_id):
        response.content_type = "application/json; charset=utf-8"
        from core import named_lists
        item = named_lists.get(list_id)
        if item is None:
            response.status = 404
            return {"ok": False, "error": "Список не найден"}
        return {"ok": True, "list": item}

    @app.route("/api/lists/<list_id>", method="PUT")
    def lists_update(list_id):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import named_lists
        r = named_lists.update(
            list_id,
            name=body.get("name"),
            description=body.get("description"),
            entries=body.get("entries"),
            replace=bool(body.get("replace", True)))
        if not r.get("ok"):
            response.status = 400 if "найден" not in r.get("error", "") else 404
        return r

    @app.route("/api/lists/<list_id>", method="DELETE")
    def lists_delete(list_id):
        response.content_type = "application/json; charset=utf-8"
        from core import named_lists
        r = named_lists.delete(list_id)
        if not r.get("ok"):
            response.status = 404
        return r
