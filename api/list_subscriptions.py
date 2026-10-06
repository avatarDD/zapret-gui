# api/list_subscriptions.py
"""
API подписок хостлистов и ipset-файлов nfqws2 на URL
(core/list_subscriptions).

Эндпоинты (kind — hostlists | ipsets):
  GET    /api/<kind>/:name/subscription          — подписка или null
  PUT    /api/<kind>/:name/subscription          — {url, interval_hours}
  DELETE /api/<kind>/:name/subscription          — снять (файл остаётся)
  POST   /api/<kind>/:name/subscription/refresh  — обновить сейчас
  GET    /api/list-subscriptions                 — все подписки
"""

from bottle import request, response


_KINDS = {"hostlists": "hostlist", "ipsets": "ipset"}


def _manager(kind):
    if kind == "ipset":
        from core.ipset_manager import get_ipset_manager
        return get_ipset_manager()
    from core.hostlist_manager import get_hostlist_manager
    return get_hostlist_manager()


def _resolve(section, name):
    """(kind, None) или (None, ответ-ошибка)."""
    kind = _KINDS.get(section)
    if not kind:
        response.status = 404
        return None, {"ok": False, "error": "неизвестный тип списка"}
    if not _manager(kind)._validate_name(name):
        response.status = 400
        return None, {"ok": False, "error": "Недопустимое имя: %s" % name}
    return kind, None


def register(app):

    @app.route("/api/list-subscriptions")
    def api_list_subscriptions():
        response.content_type = "application/json; charset=utf-8"
        from core import list_subscriptions
        return {"ok": True, "subscriptions": list_subscriptions.list_all()}

    @app.route("/api/<section:re:hostlists|ipsets>/<name>/subscription")
    def api_subscription_get(section, name):
        response.content_type = "application/json; charset=utf-8"
        kind, err = _resolve(section, name)
        if err:
            return err
        from core import list_subscriptions
        return {"ok": True,
                "subscription": list_subscriptions.get(kind, name) or None}

    @app.put("/api/<section:re:hostlists|ipsets>/<name>/subscription")
    def api_subscription_put(section, name):
        response.content_type = "application/json; charset=utf-8"
        kind, err = _resolve(section, name)
        if err:
            return err
        try:
            body = request.json or {}
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}
        from core import list_subscriptions
        res = list_subscriptions.subscribe(
            kind, name, body.get("url", ""),
            interval_hours=body.get("interval_hours",
                                    list_subscriptions.DEFAULT_INTERVAL_HOURS),
            refresh_now=bool(body.get("refresh_now", True)))
        if not res.get("ok"):
            response.status = 400
        return res

    @app.delete("/api/<section:re:hostlists|ipsets>/<name>/subscription")
    def api_subscription_delete(section, name):
        response.content_type = "application/json; charset=utf-8"
        kind, err = _resolve(section, name)
        if err:
            return err
        from core import list_subscriptions
        return list_subscriptions.unsubscribe(kind, name)

    @app.post("/api/<section:re:hostlists|ipsets>/<name>/subscription/refresh")
    def api_subscription_refresh(section, name):
        response.content_type = "application/json; charset=utf-8"
        kind, err = _resolve(section, name)
        if err:
            return err
        from core import list_subscriptions
        res = list_subscriptions.refresh(kind, name)
        if not res.get("ok") and not res.get("preserved"):
            response.status = 502
        return res
