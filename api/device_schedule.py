# api/device_schedule.py
"""
REST API расписания обхода по устройствам (core/device_schedule.py).

Маршруты:
  GET  /api/device-schedule  — настройки + состояние (время роутера,
                               действующие правила, адреса мимо обхода)
  POST /api/device-schedule  — сохранить {enabled, tz_offset, rules}
                               и сразу применить
  GET  /api/device-quota     — квоты времени: настройки и счёт за сегодня
  POST /api/device-quota     — сохранить {enabled, tz_offset,
                               active_packets, rules} и применить
  POST /api/device-quota/grant — {rule, minutes}: добавить минут на
                               сегодня (core/device_quota.py)
"""

import json

from bottle import request, response


def register(app):

    def _state():
        from core.device_schedule import get_device_scheduler
        sched = get_device_scheduler()
        # Для формы — все правила, битые с полем error: иначе одно
        # неверное правило в settings.json прятало бы все остальные, и
        # следующее сохранение их стирало.
        return {"ok": True, "settings": sched.form_settings(),
                "status": sched.status()}

    @app.route("/api/device-schedule")
    def device_schedule_get():
        response.content_type = "application/json; charset=utf-8"
        try:
            return _state()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/device-schedule", method="POST")
    def device_schedule_save():
        response.content_type = "application/json; charset=utf-8"
        # Тело разбираем сами и строго: без Content-Type application/json
        # bottle отдаёт request.json = None, и пустой объект молча
        # сохранился бы поверх расписания («выключено, правил нет»).
        try:
            body = json.loads(request.body.read() or b"null")
        except (ValueError, UnicodeDecodeError):
            body = None
        if not isinstance(body, dict) or "rules" not in body:
            response.status = 400
            return {"ok": False,
                    "error": "ожидается JSON-объект {enabled, tz_offset, rules}"}
        from core.config_manager import get_config_manager
        from core.device_schedule import get_device_scheduler, \
            normalize_settings
        try:
            data = normalize_settings(body)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        cfg = get_config_manager()
        cfg.set("firewall", "device_schedule", data)
        if not cfg.save():
            response.status = 500
            return {"ok": False, "error": "не удалось сохранить настройки"}
        try:
            get_device_scheduler().reconfigure(apply_now=True)
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": "сохранено, но не применено: %s" % e}
        return _state()

    # ── Дневные квоты времени (core/device_quota.py) ──

    def _quota_state():
        from core.config_manager import get_config_manager
        from core.device_quota import get_device_quota, load_settings
        raw = get_config_manager().get("firewall", "device_quota",
                                       default={}) or {}
        work, form, errors = load_settings(raw)
        return {"ok": True, "settings": dict(work, rules=form, errors=errors),
                "status": get_device_quota().status()}

    @app.route("/api/device-quota")
    def device_quota_get():
        response.content_type = "application/json; charset=utf-8"
        return _quota_state()

    @app.route("/api/device-quota", method="POST")
    def device_quota_save():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = json.loads(request.body.read() or b"null")
        except (ValueError, UnicodeDecodeError):
            body = None
        if not isinstance(body, dict) or "rules" not in body:
            response.status = 400
            return {"ok": False, "error": "ожидается JSON-объект "
                                          "{enabled, tz_offset, rules}"}
        from core.config_manager import get_config_manager
        from core.device_quota import get_device_quota, normalize_settings
        try:
            data = normalize_settings(body)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        cfg = get_config_manager()
        cfg.set("firewall", "device_quota", data)
        if not cfg.save():
            response.status = 500
            return {"ok": False, "error": "не удалось сохранить настройки"}
        q = get_device_quota()
        q.start()
        q.tick()
        return _quota_state()

    @app.route("/api/device-quota/grant", method="POST")
    def device_quota_grant():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = json.loads(request.body.read() or b"null") or {}
        except (ValueError, UnicodeDecodeError):
            body = {}
        from core.device_quota import get_device_quota
        r = get_device_quota().grant(str(body.get("rule") or ""),
                                     body.get("minutes"))
        if r.get("ok"):
            r.update(_quota_state())
        return r
