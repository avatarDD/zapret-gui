# api/notify.py
"""
REST API уведомлений в Telegram (core/notify.py).

  GET  /api/notify             — настройки (без токена: has_token) и очередь
  POST /api/notify/settings    — сохранить {enabled, token?, chat_id,
                                 transport, proxy, events, clear_token?};
                                 пустой token — оставить прежний
  POST /api/notify/test        — отправить пробное сообщение сразу
                                 (значения из тела важнее сохранённых —
                                 проверить можно до сохранения)
  POST /api/notify/find-chats  — чаты, писавшие боту (getUpdates)
  POST /api/notify/flush       — отправить очередь сейчас
"""

from bottle import request, response


def _json_body():
    try:
        return request.json or {}
    except Exception:
        return {}


def _merged(body: dict) -> dict:
    """Сохранённые настройки, поверх — непустые поля из запроса."""
    from core import notify
    st = notify.settings()
    for key in ("token", "chat_id", "transport", "proxy"):
        if key in body and (key != "token" or str(body[key]).strip()):
            st[key] = str(body[key] or "").strip()
    # Пустое поле токена — «не менять»; удалить — явным флагом.
    if body.get("clear_token"):
        st["token"] = ""
    if "interactive" in body:
        st["interactive"] = bool(body["interactive"])
    if "allowed_users" in body:
        raw = body["allowed_users"]
        if isinstance(raw, str):
            raw = raw.replace(",", " ").split()
        st["allowed_users"] = [str(u).strip() for u in (raw or [])
                               if str(u).strip()]
    return st


def _proxy_ok(proxy: str) -> bool:
    return not proxy or proxy.startswith(("http://", "https://"))


def register(app):

    @app.route("/api/notify")
    def api_notify_get():
        response.content_type = "application/json; charset=utf-8"
        from core import notify
        st = notify.settings()
        has_token = bool(st.pop("token"))
        st["has_token"] = has_token
        status = notify.status()
        try:
            from core import notify_bot
            status["bot"] = notify_bot.status()
        except Exception:
            pass
        return {"ok": True, "settings": st, "status": status}

    @app.route("/api/notify/settings", method="POST")
    def api_notify_save():
        response.content_type = "application/json; charset=utf-8"
        from core import notify
        from core.config_manager import get_config_manager
        body = _json_body()
        st = _merged(body)
        if not _proxy_ok(st["proxy"]):
            response.status = 400
            return {"ok": False, "error": "прокси — http://хост:порт"}
        events = body.get("events")
        if not isinstance(events, dict):
            events = st["events"]
        cfg = get_config_manager()
        cfg.set("notify", "telegram", {
            "enabled": bool(body.get("enabled", st["enabled"])),
            "token": st["token"], "chat_id": st["chat_id"],
            "transport": st["transport"], "proxy": st["proxy"],
            "interactive": st["interactive"],
            "allowed_users": st["allowed_users"]})
        cfg.set("notify", "events", {k: bool(events.get(k, True))
                                     for k in notify.EVENTS})
        if not cfg.save():
            response.status = 500
            return {"ok": False, "error": "настройки не сохранены"}
        # Бот: включили — поднять опрос; выключили — поток сам выйдет
        # после текущего опроса.
        try:
            from core import notify_bot
            notify_bot.start()
        except Exception:
            pass
        return {"ok": True}

    @app.route("/api/notify/test", method="POST")
    def api_notify_test():
        response.content_type = "application/json; charset=utf-8"
        from core import notify
        st = _merged(_json_body())
        if not _proxy_ok(st["proxy"]):
            response.status = 400
            return {"ok": False, "error": "прокси — http://хост:порт"}
        return notify.send_now("Проверка уведомлений: связь есть ✅", st)

    @app.route("/api/notify/find-chats", method="POST")
    def api_notify_find_chats():
        response.content_type = "application/json; charset=utf-8"
        from core import notify
        st = _merged(_json_body())
        if not _proxy_ok(st["proxy"]):
            response.status = 400
            return {"ok": False, "error": "прокси — http://хост:порт"}
        return notify.find_chats(st)

    @app.route("/api/notify/flush", method="POST")
    def api_notify_flush():
        response.content_type = "application/json; charset=utf-8"
        from core import notify
        return notify.flush()
