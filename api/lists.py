# api/lists.py
"""
REST API для именованных списков (core/named_lists).

  GET    /api/lists              — все списки (с подсчётом записей)
  POST   /api/lists              — создать {name, description, entries}
  GET    /api/lists/<id>         — получить один список
  PUT    /api/lists/<id>         — обновить {name?, description?, entries?, replace?}
  DELETE /api/lists/<id>         — удалить

  GET    /api/lists/curated      — курируемые пресеты + статус обновлятеля
                                    + транспорт скачивания
  POST   /api/lists/curated      — добавить {url} (пресет) или
                                    {url, name?, description?, interval_hours?}
  POST   /api/lists/curated/settings — {transport} — через что качать
                                    автообновляемые списки
  POST   /api/lists/<id>/refresh — обновить управляемый список из source_url
  POST   /api/lists/refresh-all  — обновить все управляемые списки

PUT /api/lists/<id> дополнительно принимает interval_hours — период
автообновления управляемого списка (часы).
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
        if r.get("ok") and body.get("interval_hours") is not None:
            # Период автообновления управляемого списка (с source_url).
            try:
                named_lists.update_fields(list_id, {
                    "interval_hours": max(1, int(body["interval_hours"]))})
            except (TypeError, ValueError):
                pass
        if r.get("ok") and "transport" in body:
            # Per-list transport override ('' = глобальный, 'awg:wg0' и т.д.)
            named_lists.update_fields(list_id, {
                "transport": (body.get("transport") or "").strip()})
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

    # ─────── курируемые списки (автообновление по URL) ───────

    @app.route("/api/lists/curated")
    def lists_curated():
        response.content_type = "application/json; charset=utf-8"
        from core import list_updater as lu
        return {
            "ok": True,
            "presets": lu.presets(),
            "refresher": lu.get_list_refresher().get_status(),
            "transport": lu.get_transport(),
        }

    @app.route("/api/lists/curated/settings", method="POST")
    def lists_curated_settings():
        """Настройки автообновления списков: {transport}."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import list_updater as lu
        r = lu.set_transport(body.get("transport") or "")
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/lists/curated", method="POST")
    def lists_curated_add():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        url = (body.get("url") or "").strip()
        if not url:
            response.status = 400
            return {"ok": False, "error": "Нужен url"}
        from core import list_updater as lu
        # Если это в точности один из пресетов — используем его метаданные.
        if any(p["url"] == url for p in lu.CURATED_PRESETS):
            r = lu.add_preset(url)
        else:
            try:
                interval = int(body.get("interval_hours") or 12)
            except (TypeError, ValueError):
                interval = 12
            r = lu.add_from_url(
                url, name=(body.get("name") or "").strip(),
                description=(body.get("description") or "").strip(),
                interval_hours=interval)
        if not r.get("ok"):
            response.status = 400
        return r

    @app.route("/api/lists/<list_id>/refresh", method="POST")
    def lists_refresh_one(list_id):
        response.content_type = "application/json; charset=utf-8"
        from core import list_updater as lu
        return lu.refresh_one(list_id)

    @app.route("/api/lists/refresh-all", method="POST")
    def lists_refresh_all():
        response.content_type = "application/json; charset=utf-8"
        from core import list_updater as lu
        return lu.refresh_all()
