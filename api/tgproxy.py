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
  GET  /api/tgproxy/autostart                 — автозапуск при загрузке
  PUT  /api/tgproxy/autostart                 — включить/выключить его

  GET  /api/tgproxy/tgwsproxy/config          — текущий конфиг
  PUT  /api/tgproxy/tgwsproxy/config          — частичное обновление
                                                 конфига (тут и задаётся
                                                 cf_domain); поля, которых
                                                 нет в теле, сохраняют
                                                 текущее значение
  POST /api/tgproxy/tgwsproxy/up
  POST /api/tgproxy/tgwsproxy/down
  POST /api/tgproxy/tgwsproxy/restart
  POST /api/tgproxy/tgwsproxy/secret/rotate
  GET  /api/tgproxy/tgwsproxy/connect-info    — tg://proxy ссылка

  GET  /api/tgproxy/mtproto/config            — сохранённый relay
  POST /api/tgproxy/mtproto/up                — relay из тела или конфига
  POST /api/tgproxy/mtproto/down
  GET  /api/tgproxy/mtproto/connect-info

  POST /api/tgproxy/install                   — установить/обновить движок
  GET  /api/tgproxy/install/status            — прогресс установки
    Обе ручки принимают engine=tgwsproxy|mtproto; без него — tgwsproxy
    (так их звал старый фронтенд).
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


# Движок GUI → имя в манифесте core/ext_binary_installer.BINARIES.
# Имена не совпадают исторически: в GUI резервный движок зовётся
# "mtproto" (по имени панели), в манифесте — "tgproto" (по репозиторию).
_ENGINE_INSTALLERS = {
    "tgwsproxy": "tgwsproxy",
    "mtproto": "tgproto",
}
_ENGINE_BY_INSTALLER = {v: k for k, v in _ENGINE_INSTALLERS.items()}


def _installer_for(engine) -> str:
    """Имя в BINARIES по значению engine из запроса ("" — неизвестный).

    Пустой engine — это старый фронтенд, который ручку не параметризовал;
    для него сохраняем прежнее поведение (основной движок).
    """
    engine = (engine or "tgwsproxy").strip()
    return _ENGINE_INSTALLERS.get(engine, "")


def _remember_installed_tag(engine: str, res: dict) -> None:
    """Записать тег установленного tg-mtproxy-client в настройки.

    У бинарника нет `--version`, спросить его после установки не у кого —
    а «Обновления» без версии не могут сказать, есть ли обновление. Тег
    известен ровно здесь, в момент установки.
    """
    if engine != "mtproto":
        return
    tag = (res.get("tag") or res.get("version") or "").strip()
    if not tag:
        return
    try:
        from core.config_manager import get_config_manager, save_config
        get_config_manager().set("tgproxy", "mtproto_installed_tag", tag)
        save_config()
    except Exception:
        pass


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
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
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
        from core.ext_binary_installer import get_installability

        out = {
            "tgwsproxy": get_tgwsproxy_manager().detect(),
            "mtproto": get_mtproxy_client_manager().detect(),
        }
        # Можно ли ВООБЩЕ поставить движок на этой машине. У
        # tg-mtproxy-client в манифесте есть сборки только под mips/
        # mipsel/x86_64 — на aarch64-Keenetic кнопка «Установить» падала
        # бы всегда, поэтому GUI должен знать об этом заранее.
        for engine, installer in _ENGINE_INSTALLERS.items():
            info = get_installability(installer)
            out.setdefault(engine, {}).update({
                "installable": info["installable"],
                "arch": info["arch"],
                "supported_archs": info["supported_archs"],
            })
        return out

    # ─────────────────────────── установка ───────────────────────────

    @app.route("/api/tgproxy/install/status", method="GET")
    def tgproxy_install_status():
        from core.ext_binary_installer import get_operation_status
        installer = _installer_for(request.query.get("engine"))
        if not installer:
            return {"ok": False, "error": "Неизвестный движок"}
        return {"ok": True, "engine": _ENGINE_BY_INSTALLER[installer],
                "progress": get_operation_status(installer)}

    @app.route("/api/tgproxy/install", method="POST")
    def tgproxy_install():
        # Ставит движок из GitHub-релиза — ПОСЛЕДНИЙ релиз, sha256
        # сверяется с манифестом для известной версии. Асинхронно,
        # прогресс — через /api/tgproxy/install/status?engine=...
        #
        # engine выбирает, ЧТО ставить. Раньше ручка знала только про
        # tg-ws-proxy, поэтому у резервного tg-mtproxy-client в GUI не
        # было кнопки установки вовсе, хотя манифест для него в
        # ext_binary_installer уже лежал (issue #272).
        import threading
        from core.ext_binary_installer import (install_binary_by_name,
                                               _operation_status)

        body = request.json or {}
        engine_arg = body.get("engine") or request.query.get("engine")
        name = _installer_for(engine_arg)
        if not name:
            return {"ok": False, "error": "Неизвестный движок: %s" % engine_arg}
        engine = _ENGINE_BY_INSTALLER[name]

        # Второй POST во время работы установщика поднял бы второй поток
        # на тот же dest, а _operation_status у них общий — статусы
        # затирали бы друг друга. Отдаём текущий прогресс.
        cur = _operation_status.get(name) or {}
        if cur.get("status") not in (None, "", "idle", "done", "error"):
            return {"ok": True, "engine": engine, "progress": cur}

        _operation_status[name] = {"status": "starting", "progress": 0,
                                   "message": "Запуск установки..."}

        def _cb(stage, pct, label):
            _operation_status[name] = {"status": stage, "progress": pct,
                                       "message": label}

        def _run():
            try:
                res = install_binary_by_name(name, progress_cb=_cb)
                if res.get("ok"):
                    _remember_installed_tag(engine, res)
                    # Версию и признак сверки хэша тащим в статус: у
                    # «последнего релиза» пользователь должен видеть, что
                    # именно приехало и сверялся ли хэш.
                    _operation_status[name] = {
                        "status": "done", "progress": 100,
                        "message": ("Уже актуальная версия %s"
                                    % res.get("version", "")) if res.get("noop")
                                   else ("Установлено: %s" % res.get("version", "")),
                        "version": res.get("version", ""),
                        "tag": res.get("tag", ""),
                        "noop": bool(res.get("noop")),
                        "sha256_verified": res.get("sha256_verified"),
                    }
                else:
                    _operation_status[name] = {"status": "error", "progress": 0,
                                               "message": res.get("error", "Ошибка")}
            except Exception as e:
                _operation_status[name] = {"status": "error", "progress": 0,
                                           "message": str(e)}

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "engine": engine,
                "progress": _operation_status[name]}

    # ─────────────────────────── tgwsproxy ───────────────────────────

    @app.route("/api/tgproxy/tgwsproxy/config", method="GET")
    def tgwsproxy_config_get():
        from core.tgproxy_manager import get_tgwsproxy_manager
        cfg = get_tgwsproxy_manager().get_config()
        # secret не отдаём в открытую конфигурацию по GET без явного
        # запроса — фронтенд получает его отдельно через connect-info,
        # где он и так неизбежно нужен для tg://proxy ссылки.
        cfg = dict(cfg)
        cfg["secret_configured"] = bool(cfg.get("secret"))
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
        from core.tgproxy_manager import get_tgwsproxy_manager, _TGWSPROXY_MODES
        mgr = get_tgwsproxy_manager()
        data = request.json or {}

        # PUT — частичное обновление поверх текущего config.conf, а не
        # запись «с нуля». Раньше отсутствующие в теле поля молча
        # подменялись дефолтами: страница шлёт только port/mode/домены/
        # профиль ресурсов, и каждое «Сохранить» сбрасывало HOST на
        # адрес, определённый на стороне сервера, LOG_LEVEL в "0",
        # DC_IP_DEFAULT_POOL в пустую строку, а собственный
        # CFPROXY_DOMAINS_URL — на community-пул по умолчанию.
        current = mgr.get_config()

        def _field(key):
            return current.get(key, "") if key not in data else data.get(key)

        cf_domain = (_field("cf_domain") or "").strip()
        cf_worker_domain = (_field("cf_worker_domain") or "").strip()
        fake_tls_domain = (_field("fake_tls_domain") or "").strip()
        mode = (_field("mode") or "direct").strip()
        if mode not in _TGWSPROXY_MODES:
            return {"ok": False, "error": "Неизвестный режим: %s" % mode}

        for label, val in (("cf_domain", cf_domain),
                           ("cf_worker_domain", cf_worker_domain),
                           ("fake_tls_domain", fake_tls_domain)):
            if not _valid_domain_or_empty(val):
                return {"ok": False, "error":
                        "Недопустимый домен в поле %s: %r" % (label, val)}

        try:
            port = int(data.get("port", current.get("port") or 1443))
        except (TypeError, ValueError):
            return {"ok": False, "error": "port должен быть числом"}
        if not (1 <= port <= 65535):
            return {"ok": False, "error": "port вне диапазона 1-65535"}

        host = (_field("host") or "").strip() or _lan_ip_fallback()
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in host):
            return {"ok": False, "error": "Недопустимый host"}
        return mgr.save_config(
            host=host,
            port=port,
            dc_ip_default=_field("dc_ip_default") or "149.154.167.220",
            dc_ip_default_pool=_field("dc_ip_default_pool") or "",
            fake_tls_domain=fake_tls_domain,
            cf_domain=cf_domain,
            cf_worker_domain=cf_worker_domain,
            cfproxy_domains=_field("cfproxy_domains") or "",
            cfproxy_domains_url=_field("cfproxy_domains_url") or "",
            extra_args=_field("extra_args") or "",
            secret=data.get("secret", ""),
            log_level=str(_field("log_level") or "0"),
            mode=mode,
            pool_size=data.get("pool_size", current.get("pool_size", 2)),
            max_conns=data.get("max_conns", current.get("max_conns", 64)),
            buf_kb=data.get("buf_kb", current.get("buf_kb", 64)),
            no_cfproxy_domain_refresh=bool(
                _field("no_cfproxy_domain_refresh")),
        )

    @app.route("/api/tgproxy/tgwsproxy/secret/rotate", method="POST")
    def tgwsproxy_secret_rotate():
        from core.tgproxy_manager import get_tgwsproxy_manager
        data = request.json or {}
        return get_tgwsproxy_manager().rotate_secret(
            confirm=data.get("confirm") is True)

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

    # ─────────────────────────── автозапуск ───────────────────────────
    # app.py при старте поднимает tg-ws-proxy-go, если включены ОБА
    # флага tgproxy.enabled и tgproxy.autostart. Ставить их было нечем —
    # ни API, ни страницы: код автозапуска не мог сработать ни при каких
    # действиях пользователя, и после перезагрузки роутера прокси
    # оставался лежать. Один переключатель выставляет оба флага.

    @app.route("/api/tgproxy/autostart", method="GET")
    def tgproxy_autostart_get():
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        return {
            "ok": True,
            "autostart": bool(cfg.get("tgproxy", "enabled", default=False)
                              and cfg.get("tgproxy", "autostart", default=False)),
        }

    @app.route("/api/tgproxy/autostart", method="PUT")
    def tgproxy_autostart_put():
        from core.config_manager import get_config_manager
        data = request.json or {}
        if "autostart" not in data:
            return {"ok": False, "error": "Не передан autostart"}
        enabled = bool(data.get("autostart"))
        cfg = get_config_manager()
        cfg.set("tgproxy", "enabled", enabled)
        cfg.set("tgproxy", "autostart", enabled)
        cfg.set("tgproxy", "engine", "tgwsproxy")
        if not cfg.save():
            return {"ok": False, "error": "Не удалось сохранить настройки"}
        return {"ok": True, "autostart": enabled}

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

    @app.route("/api/tgproxy/mtproto/config", method="GET")
    def mtproto_config_get():
        """Relay/secret резервного движка (secret не отдаём открытым)."""
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        from core.tgproxy_manager import (MTPROXY_DEFAULT_RELAY,
                                          MTPROXY_LOCAL_PORT)
        relay = cfg.get("tgproxy", "tunnel_url", default="") or ""
        secret = cfg.get("tgproxy", "tunnel_secret", default="") or ""
        return {
            "ok": True,
            "config": {
                "relay": relay,
                "default_relay": MTPROXY_DEFAULT_RELAY,
                # Пусто = используется общий дефолт; отличаем это от
                # «пользователь задал свой», иначе в UI не понять, что
                # именно поедет в запуск.
                "secret_configured": bool(secret),
                "using_defaults": not (relay and secret),
                "port": cfg.get("tgproxy", "port", default=MTPROXY_LOCAL_PORT),
            },
        }

    @app.route("/api/tgproxy/mtproto/config", method="POST")
    def mtproto_config_set():
        """Задать свой релей и/или секрет (пустое поле — вернуть дефолт).

        Секрет — ключ HMAC для аутентификации на релее. По умолчанию
        используется общий ключ публичного релея (core/tgproxy_manager);
        сюда его вводят те, у кого свой релей.
        """
        import re as _re
        from core.config_manager import get_config_manager
        from core.tgproxy_manager import _TUNNEL_SECRET_RE
        try:
            body = request.json or {}
        except Exception:
            body = {}
        cfg = get_config_manager()

        if "relay" in body:
            relay = str(body.get("relay") or "").strip()
            if relay and not _re.match(r"^(wss?|https?)://[^\s]{3,300}$",
                                       relay):
                return {"ok": False,
                        "error": "relay должен быть URL ws://, wss://, "
                                 "http:// или https:// (пусто — дефолтный)"}
            cfg.set("tgproxy", "tunnel_url", relay)

        if "secret" in body:
            secret = str(body.get("secret") or "").strip()
            if secret and not _TUNNEL_SECRET_RE.match(secret):
                return {"ok": False,
                        "error": "secret релея — hex-строка (16–128 "
                                 "символов); пусто — использовать дефолтный"}
            cfg.set("tgproxy", "tunnel_secret", secret)

        cfg.save()
        return mtproto_config_get()

    @app.route("/api/tgproxy/mtproto/up", method="POST")
    def mtproto_up():
        from core.tgproxy_manager import (get_mtproxy_client_manager,
                                          MTPROXY_LOCAL_PORT)
        from core.config_manager import get_config_manager
        mgr = get_mtproxy_client_manager()
        data = request.json or {}
        cfg = get_config_manager()

        # Relay/secret берём из тела запроса, а при отсутствии — из
        # сохранённых tgproxy.tunnel_url/tunnel_secret. Без этого кнопка
        # «Запустить» на странице (она шлёт пустое тело) всегда падала в
        # «relay обязателен для mtproto-режима»: ввести relay было негде,
        # а сохранённый в конфиге никто не читал.
        relay = (data.get("relay") or "").strip()
        persist = bool(relay)
        if not relay:
            relay = (cfg.get("tgproxy", "tunnel_url", default="") or "").strip()
        secret = (data.get("secret") or "").strip()
        if not secret:
            secret = (cfg.get("tgproxy", "tunnel_secret", default="") or "").strip()

        try:
            port = int(data.get("port")
                       or cfg.get("tgproxy", "port", default=MTPROXY_LOCAL_PORT)
                       or MTPROXY_LOCAL_PORT)
        except (TypeError, ValueError):
            return {"ok": False, "error": "port должен быть числом"}

        res = mgr.start(
            port=port,
            relay=relay,
            secret=secret,
            host=(data.get("host") or "").strip(),
        )
        if res.get("ok") and persist:
            # Запомнить рабочий relay, чтобы после перезагрузки GUI его
            # не приходилось вводить заново. Секрет сюда НЕ пишем: пустая
            # настройка означает «использовать общий дефолт», и если
            # записать его значение, смена дефолта в коде до этого
            # роутера уже не доедет. Свой секрет задают явно —
            # POST /api/tgproxy/mtproto/config.
            try:
                cfg.set("tgproxy", "tunnel_url", relay)
                cfg.set("tgproxy", "port", port)
                cfg.save()
            except Exception:
                pass
        return res

    @app.route("/api/tgproxy/mtproto/down", method="POST")
    def mtproto_down():
        from core.tgproxy_manager import get_mtproxy_client_manager
        return get_mtproxy_client_manager().stop()

    @app.route("/api/tgproxy/mtproto/connect-info", method="GET")
    def mtproto_connect_info():
        from core.tgproxy_manager import get_mtproxy_client_manager
        return get_mtproxy_client_manager().get_connect_info()
