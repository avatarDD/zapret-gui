# api/tgproxy.py
"""
API-модуль управления Telegram MTProto Proxy.

Эндпоинты:
  GET  /api/tgproxy/status    — статус (running, engine, pid)
  GET  /api/tgproxy/detect    — обнаружение движков
  POST /api/tgproxy/up        — запуск
  POST /api/tgproxy/down      — остановка
  GET  /api/tgproxy/config    — текущие настройки
  PUT  /api/tgproxy/config    — обновить настройки
  POST /api/tgproxy/engine    — выбрать движок
"""

import json

from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты tgproxy в Bottle-приложении."""

    @app.route("/api/tgproxy/status", method="GET")
    def tgproxy_status():
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()
        return mgr.status()

    @app.route("/api/tgproxy/detect", method="GET")
    def tgproxy_detect():
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()
        return mgr.detect()

    @app.route("/api/tgproxy/up", method="POST")
    def tgproxy_up():
        from core.tgproxy_manager import get_tgproxy_manager
        from core.config_manager import get_config_manager
        mgr = get_tgproxy_manager()
        cfg = get_config_manager()

        data = json.loads(request.body.read()) if request.body else {}
        return mgr.start(
            engine=data.get("engine", ""),
            port=data.get("port", cfg.get("tgproxy", "port", default=9443)),
            secret=data.get("secret", ""),
            domain=data.get("domain", ""),
            tunnel_url=data.get("tunnel_url", ""),
            tunnel_secret=data.get("tunnel_secret", ""),
            direct_dc=data.get("direct_dc"),
        )

    @app.route("/api/tgproxy/down", method="POST")
    def tgproxy_down():
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()
        return mgr.stop()

    @app.route("/api/tgproxy/config", method="GET")
    def tgproxy_config_get():
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return {
            "ok": True,
            "engine": cfg.get("tgproxy", "engine", default="auto"),
            "port": cfg.get("tgproxy", "port", default=9443),
            "teleproxy_secret": cfg.get("tgproxy", "teleproxy_secret", default=""),
            "teleproxy_domain": cfg.get("tgproxy", "teleproxy_domain", default=""),
            "teleproxy_direct_dc": cfg.get("tgproxy", "teleproxy_direct_dc", default=True),
            "tunnel_url": cfg.get("tgproxy", "tunnel_url", default=""),
            "tunnel_secret": cfg.get("tgproxy", "tunnel_secret", default=""),
            "max_conns": cfg.get("tgproxy", "max_conns", default=1024),
            "verbose": cfg.get("tgproxy", "verbose", default=False),
            "autostart": cfg.get("tgproxy", "autostart", default=False),
        }

    @app.route("/api/tgproxy/config", method="PUT")
    def tgproxy_config_put():
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        data = json.loads(request.body.read()) if request.body else {}

        fields = [
            "engine", "port", "teleproxy_secret", "teleproxy_domain",
            "teleproxy_direct_dc", "tunnel_url", "tunnel_secret",
            "max_conns", "verbose", "autostart",
        ]
        for f in fields:
            if f in data:
                cm.set("tgproxy", f, data[f])
        cm.save()
        return {"ok": True}

    @app.route("/api/tgproxy/engine", method="POST")
    def tgproxy_engine():
        from core.tgproxy_manager import get_tgproxy_manager
        mgr = get_tgproxy_manager()
        data = json.loads(request.body.read()) if request.body else {}
        return mgr.select_engine(data.get("engine", "auto"))
