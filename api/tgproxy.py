# api/tgproxy.py
"""
API управления обходом блокировки Telegram.

Два движка (см. core/tgproxy_manager.py):
  tgwsproxy — tg-ws-proxy-go, основной. CF-домен настраивается ЯВНО
              через PUT /api/tgproxy/tgwsproxy/config (поля cf_domain /
              cf_worker_domain) — это то самое явное поле в GUI.
  mtproto   — tg-mtproxy-client, резервный (relay-based).

Эндпоинты:
  GET  /api/tgproxy/status                    — статус обоих движков
  GET  /api/tgproxy/detect                    — что установлено

  GET  /api/tgproxy/tgwsproxy/config          — текущий конфиг
  PUT  /api/tgproxy/tgwsproxy/config          — сохранить конфиг (тут и
                                                 задаётся cf_domain)
  POST /api/tgproxy/tgwsproxy/up
  POST /api/tgproxy/tgwsproxy/down
  POST /api/tgproxy/tgwsproxy/restart
  GET  /api/tgproxy/tgwsproxy/connect-info    — tg://proxy ссылка

  POST /api/tgproxy/mtproto/up
  POST /api/tgproxy/mtproto/down
  GET  /api/tgproxy/mtproto/connect-info
"""

import re
import socket

from bottle import request


# Валидация домена на уровне API — сама по себе core/tgproxy_manager.py
# уже безопасна (значения экранируются перед записью в config.conf и
# передаются через shlex.quote в EXTRA_ARGS — инъекция в файл/shell
# невозможна), но проверка здесь — defense-in-depth и понятная ошибка
# пользователю сразу, а не после записи битого конфига.
_DOMAIN_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$")


def _valid_domain_or_empty(v: str) -> bool:
    v = (v or "").strip()
    if not v:
        return True
    return bool(_DOMAIN_RE.match(v))


def _lan_ip_fallback() -> str:
    """Best-effort LAN IP для конфигурации tgwsproxy.

    Не используем 0.0.0.0 как silent default bind: если IP определить не
    удалось, отдаём loopback и пользователь должен явно выбрать адрес.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def register(app):
    """Зарегистрировать API-маршруты tgproxy в Bottle-приложении."""

    # ─────────────────────────── общее ───────────────────────────

    @app.route("/api/tgproxy/status", method="GET")
    def tgproxy_status():
        from core.tgproxy_manager import get_active_engine_status
        return get_active_engine_status()

    @app.route("/api/tgproxy/detect", method="GET")
    def tgproxy_detect():
        from core.tgproxy_manager import (get_tgwsproxy_manager,
                                          get_mtproxy_client_manager)
        return {
            "tgwsproxy": get_tgwsproxy_manager().detect(),
            "mtproto": get_mtproxy_client_manager().detect(),
        }

    # ─────────────────────────── tgwsproxy ───────────────────────────

    @app.route("/api/tgproxy/tgwsproxy/config", method="GET")
    def tgwsproxy_config_get():
        from core.tgproxy_manager import get_tgwsproxy_manager
        cfg = get_tgwsproxy_manager().get_config()
        # secret не отдаём в открытую конфигурацию по GET без явного
        # запроса — фронтенд получает его отдельно через connect-info,
        # где он и так неизбежно нужен для tg://proxy ссылки.
        cfg = dict(cfg)
        cfg.pop("secret", None)

        # Текущий активный маршрут "Telegram DC через WARP-туннель"
        # (если есть) — фронтенду нужно это знать, чтобы правильно
        # определить активный режим при перезагрузке страницы.
        cfg["route_via_tunnel"] = None
        try:
            from core.unified import manager as unified_manager
            from core.tgproxy_manager import _DC_ROUTE_ID
            route = unified_manager.get_route(_DC_ROUTE_ID)
            if route:
                method = route.get("method", "")
                if ":" in method:
                    kind, iface = method.split(":", 1)
                    cfg["route_via_tunnel"] = {"kind": kind, "iface": iface}
        except Exception:
            pass

        return {"ok": True, "config": cfg}

    @app.route("/api/tgproxy/tgwsproxy/config", method="PUT")
    def tgwsproxy_config_put():
        from core.tgproxy_manager import get_tgwsproxy_manager
        mgr = get_tgwsproxy_manager()
        data = request.json or {}

        cf_domain = (data.get("cf_domain") or "").strip()
        cf_worker_domain = (data.get("cf_worker_domain") or "").strip()
        fake_tls_domain = (data.get("fake_tls_domain") or "").strip()

        for label, val in (("cf_domain", cf_domain),
                           ("cf_worker_domain", cf_worker_domain),
                           ("fake_tls_domain", fake_tls_domain)):
            if not _valid_domain_or_empty(val):
                return {"ok": False, "error":
                        "Недопустимый домен в поле %s: %r" % (label, val)}

        try:
            port = int(data.get("port", 1443))
        except (TypeError, ValueError):
            return {"ok": False, "error": "port должен быть числом"}
        if not (1 <= port <= 65535):
            return {"ok": False, "error": "port вне диапазона 1-65535"}

        return mgr.save_config(
            host=(data.get("host") or "").strip() or _lan_ip_fallback(),
            port=port,
            dc_ip_default=data.get("dc_ip_default", ""),
            dc_ip_default_pool=data.get("dc_ip_default_pool", ""),
            fake_tls_domain=fake_tls_domain,
            cf_domain=cf_domain,
            cf_worker_domain=cf_worker_domain,
            cfproxy_domains=data.get("cfproxy_domains", ""),
            cfproxy_domains_url=data.get("cfproxy_domains_url", ""),
            extra_args=data.get("extra_args", ""),
            secret=data.get("secret", ""),
            log_level=str(data.get("log_level", "0")),
        )

    @app.route("/api/tgproxy/tgwsproxy/up", method="POST")
    def tgwsproxy_up():
        from core.tgproxy_manager import get_tgwsproxy_manager
        return get_tgwsproxy_manager().start()

    @app.route("/api/tgproxy/tgwsproxy/down", method="POST")
    def tgwsproxy_down():
        from core.tgproxy_manager import get_tgwsproxy_manager
        return get_tgwsproxy_manager().stop()

    @app.route("/api/tgproxy/tgwsproxy/restart", method="POST")
    def tgwsproxy_restart():
        from core.tgproxy_manager import get_tgwsproxy_manager
        return get_tgwsproxy_manager().restart()

    @app.route("/api/tgproxy/tgwsproxy/connect-info", method="GET")
    def tgwsproxy_connect_info():
        from core.tgproxy_manager import get_tgwsproxy_manager
        return get_tgwsproxy_manager().get_connect_info()

    # ─────── маршрутизация Telegram DC через уже поднятый WARP-туннель ───────
    # (альтернатива CF-домену/CF-Worker — см. core.tgproxy_manager для
    # объяснения компромиссов: общий failure domain с самим WARP-туннелем)

    @app.route("/api/tgproxy/tgwsproxy/tunnels", method="GET")
    def tgwsproxy_tunnels():
        from core.tgproxy_manager import list_available_warp_tunnels
        return {"ok": True, "tunnels": list_available_warp_tunnels()}

    @app.route("/api/tgproxy/tgwsproxy/route-via-tunnel", method="POST")
    def tgwsproxy_route_via_tunnel():
        from core.tgproxy_manager import route_telegram_dc_via_tunnel
        data = request.json or {}
        kind = (data.get("kind") or "").strip()
        iface = (data.get("iface") or "").strip()
        if kind not in ("warp", "awg"):
            return {"ok": False, "error": "kind должен быть 'warp' или 'awg'"}
        if not iface:
            return {"ok": False, "error": "Не указан интерфейс туннеля"}
        return route_telegram_dc_via_tunnel(kind, iface)

    @app.route("/api/tgproxy/tgwsproxy/route-via-tunnel", method="DELETE")
    def tgwsproxy_unroute_via_tunnel():
        from core.tgproxy_manager import unroute_telegram_dc_via_tunnel
        return unroute_telegram_dc_via_tunnel()

    # ─────────────────────────── mtproto (резерв) ───────────────────────────

    @app.route("/api/tgproxy/mtproto/up", method="POST")
    def mtproto_up():
        from core.tgproxy_manager import (get_mtproxy_client_manager,
                                          MTPROXY_LOCAL_PORT)
        mgr = get_mtproxy_client_manager()
        data = request.json or {}
        try:
            port = int(data.get("port", MTPROXY_LOCAL_PORT))
        except (TypeError, ValueError):
            return {"ok": False, "error": "port должен быть числом"}
        return mgr.start(
            port=port,
            relay=(data.get("relay") or "").strip(),
            secret=data.get("secret", ""),
        )

    @app.route("/api/tgproxy/mtproto/down", method="POST")
    def mtproto_down():
        from core.tgproxy_manager import get_mtproxy_client_manager
        return get_mtproxy_client_manager().stop()

    @app.route("/api/tgproxy/mtproto/connect-info", method="GET")
    def mtproto_connect_info():
        from core.tgproxy_manager import get_mtproxy_client_manager
        return get_mtproxy_client_manager().get_connect_info()
