# api/opera_proxy.py
"""
API-модуль управления Opera Proxy.

Эндпоинты:
  GET  /api/opera-proxy/status    — статус (running, pid, listening)
  GET  /api/opera-proxy/detect    — обнаружение binary (дёшево, из кэша)
  GET  /api/opera-proxy/countries — список стран (сетевой запрос!)
  POST /api/opera-proxy/up        — запуск
  POST /api/opera-proxy/down      — остановка
  GET  /api/opera-proxy/config    — текущие настройки
  PUT  /api/opera-proxy/config    — обновить настройки
"""


from bottle import request, response

from core.log_buffer import log


def _body() -> dict:
    """Тело запроса. Кривой JSON не должен превращаться в HTTP 500."""
    try:
        data = request.json
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


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

    @app.route("/api/opera-proxy/countries", method="GET")
    def opera_countries():
        """
        Список стран Opera VPN.

        Отдельно от detect(), потому что `-list-countries` — сетевая
        операция: opera-proxy регистрирует анонимный аккаунт и устройство
        в API SurfEasy. Раньше она висела внутри detect(), который GUI
        дёргал каждые 3 секунды опросом статуса.
        """
        from core.opera_proxy_manager import get_opera_proxy_manager
        refresh = str(request.query.get("refresh") or "").lower() \
            in ("1", "true", "yes")
        return get_opera_proxy_manager().list_countries(refresh=refresh)

    @app.route("/api/opera-proxy/up", method="POST")
    def opera_up():
        from core.opera_proxy_manager import get_opera_proxy_manager
        from core.config_manager import get_config_manager
        mgr = get_opera_proxy_manager()
        cfg = get_config_manager()

        data = _body()
        # База — сохранённые настройки, поверх — то, что явно передали в
        # запросе. Один источник с автозапуском и watchdog'ом.
        from core.opera_proxy_manager import (start_kwargs_from_config,
                                              validate_settings)
        kwargs = start_kwargs_from_config(cfg)
        try:
            overrides = validate_settings(
                {k: v for k, v in data.items() if k in kwargs})
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        kwargs.update(overrides)
        result = mgr.start(**kwargs)
        # enabled отражает «opera должна работать». Без его выставления
        # boot-автозапуск и watchdog (оба гейтятся enabled) были мертвы —
        # флаг нигде не писался. Ставим при успешном старте.
        if result.get("ok"):
            cfg.set("opera_proxy", "enabled", True)
            cfg.save()
            try:
                from core.opera_proxy_watchdog import get_opera_proxy_watchdog
                get_opera_proxy_watchdog().reconfigure()
            except Exception:
                pass
        return result

    @app.route("/api/opera-proxy/down", method="POST")
    def opera_down():
        from core.opera_proxy_manager import get_opera_proxy_manager
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("opera_proxy", "enabled", False)
        cfg.save()
        result = get_opera_proxy_manager().stop()
        try:
            from core.opera_proxy_watchdog import get_opera_proxy_watchdog
            get_opera_proxy_watchdog().reconfigure()
        except Exception:
            pass
        return result

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
        from core.opera_proxy_manager import validate_settings
        cm = get_config_manager()
        data = _body()

        fields = ["country", "bind", "socks_mode", "proxy_bypass",
                  "fake_sni", "verbosity", "autostart"]
        # Валидация до записи: негодный bind в settings.json оборачивался
        # невнятным падением при старте и вечным рестарт-циклом watchdog'а.
        try:
            clean = validate_settings(
                {f: data[f] for f in fields if f in data})
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        for f, value in clean.items():
            cm.set("opera_proxy", f, value)
        cm.save()
        # Тумблер autostart влияет на watchdog — применяем сразу, без ребута.
        try:
            from core.opera_proxy_watchdog import get_opera_proxy_watchdog
            get_opera_proxy_watchdog().reconfigure()
        except Exception:
            pass
        return {"ok": True}

    @app.route("/api/opera-proxy/debug", method="GET")
    def opera_debug_get():
        from core.opera_proxy_manager import debug_enabled
        return {"ok": True, "enabled": debug_enabled()}

    @app.route("/api/opera-proxy/debug", method="POST")
    def opera_debug_set():
        from core.config_manager import get_config_manager
        from core.opera_proxy_manager import debug_enabled
        body = _body()
        cfg = get_config_manager()
        cfg.set("opera_proxy", "debug_log", bool(body.get("enabled")))
        cfg.save()
        return {"ok": True, "enabled": debug_enabled(),
                "note": "Глубина буфера меняется при следующем запуске;"
                        " для подробных строк выберите Verbosity = Debug (10)"}

    @app.route("/api/opera-proxy/log", method="GET")
    def opera_log():
        from core.opera_proxy_manager import get_opera_proxy_manager
        try:
            lines = int(request.query.get("lines") or 200)
        except (TypeError, ValueError):
            lines = 200
        return get_opera_proxy_manager().read_log(lines=lines)

    @app.route("/api/opera-proxy/install", method="POST")
    def opera_install():
        from core.ext_binary_installer import install_binary_by_name
        return install_binary_by_name("opera")

    @app.route("/api/opera-proxy/uninstall", method="POST")
    def opera_uninstall():
        from core.ext_binary_installer import uninstall_binary
        return uninstall_binary("opera")
