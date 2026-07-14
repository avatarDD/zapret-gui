# api/opera_proxy.py
"""
API-модуль управления Opera Proxy.

Эндпоинты:
  GET  /api/opera-proxy/status   — статус (running, pid)
  GET  /api/opera-proxy/detect   — обнаружение binary, страны
  POST /api/opera-proxy/up       — запуск
  POST /api/opera-proxy/down     — остановка
  GET  /api/opera-proxy/config   — текущие настройки
  PUT  /api/opera-proxy/config   — обновить настройки
"""

import json

from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты opera-proxy."""

    @app.route("/api/opera-proxy/status", method="GET")
    def opera_status():
        from core.opera_proxy_manager import get_opera_proxy_manager
        return get_opera_proxy_manager().status()

    @app.route("/api/opera-proxy/detect", method="GET")
    def opera_detect():
        from core.opera_proxy_manager import get_opera_proxy_manager
        return get_opera_proxy_manager().detect()

    @app.route("/api/opera-proxy/up", method="POST")
    def opera_up():
        from core.opera_proxy_manager import get_opera_proxy_manager
        from core.config_manager import get_config_manager
        mgr = get_opera_proxy_manager()
        cfg = get_config_manager()

        data = json.loads(request.body.read()) if request.body else {}
        return mgr.start(
            country=data.get("country",
                             cfg.get("opera_proxy", "country", default="EU")),
            bind=data.get("bind",
                          cfg.get("opera_proxy", "bind", default="127.0.0.1:18080")),
            socks_mode=data.get("socks_mode",
                                cfg.get("opera_proxy", "socks_mode", default=False)),
            proxy_bypass=data.get("proxy_bypass",
                                  cfg.get("opera_proxy", "proxy_bypass", default="")),
            fake_sni=data.get("fake_sni",
                              cfg.get("opera_proxy", "fake_sni", default="")),
            verbosity=data.get("verbosity",
                               cfg.get("opera_proxy", "verbosity", default=20)),
        )

    @app.route("/api/opera-proxy/down", method="POST")
    def opera_down():
        from core.opera_proxy_manager import get_opera_proxy_manager
        return get_opera_proxy_manager().stop()

    @app.route("/api/opera-proxy/config", method="GET")
    def opera_config_get():
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return {
            "ok": True,
            "country": cfg.get("opera_proxy", "country", default="EU"),
            "bind": cfg.get("opera_proxy", "bind", default="127.0.0.1:18080"),
            "socks_mode": cfg.get("opera_proxy", "socks_mode", default=False),
            "proxy_bypass": cfg.get("opera_proxy", "proxy_bypass", default=""),
            "fake_sni": cfg.get("opera_proxy", "fake_sni", default=""),
            "verbosity": cfg.get("opera_proxy", "verbosity", default=20),
            "autostart": cfg.get("opera_proxy", "autostart", default=False),
        }

    @app.route("/api/opera-proxy/config", method="PUT")
    def opera_config_put():
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        data = json.loads(request.body.read()) if request.body else {}

        fields = ["country", "bind", "socks_mode", "proxy_bypass",
                  "fake_sni", "verbosity", "autostart"]
        for f in fields:
            if f in data:
                cm.set("opera_proxy", f, data[f])
        cm.save()
        return {"ok": True}

    @app.route("/api/opera-proxy/install", method="POST")
    def opera_install():
        from core.ext_binary_installer import install_binary_by_name
        return install_binary_by_name("opera")

    @app.route("/api/opera-proxy/uninstall", method="POST")
    def opera_uninstall():
        from core.ext_binary_installer import uninstall_binary
        return uninstall_binary("opera")
