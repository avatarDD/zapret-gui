#!/usr/bin/env python3
# app.py
"""
Zapret Web-GUI — веб-интерфейс для управления nfqws2 на роутерах.

Запуск:
    python3 app.py
    python3 app.py --port 8080 --host 0.0.0.0
    python3 app.py --config /opt/etc/zapret-gui
"""

import os
import sys
import argparse

# Корневая директория проекта
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(APP_DIR, "web")

# Bottle — микрофреймворк (один файл, 0 зависимостей). Системный
# приоритетен; если его нет — подключается встроенный vendor/bottle.py
# (установка не требует сети, dev-окружение работает без pip).
try:
    from core.bottle_vendor import ensure_bottle
    ensure_bottle()
    from bottle import Bottle, static_file, response, request, ServerAdapter
    import bottle as _bottle
    # Поднимаем лимит тела запроса (дефолт 100 KB): импорт бэкапа и
    # крупные blob/конфиг-POST'ы могут быть больше.
    _bottle.BaseRequest.MEMFILE_MAX = 16 * 1024 * 1024
except ImportError:
    print("ОШИБКА: Bottle не найден (нет ни системного, ни vendor/bottle.py).")
    print("  Копия проекта неполная? Переустановите zapret-gui")
    print("  или поставьте вручную: opkg install python3-bottle / pip3 install bottle")
    sys.exit(1)


# ── Threaded WSGI-сервер ──────────────────────────────────────────
#
# Стандартный wsgiref.simple_server — ОДНОПОТОЧНЫЙ.
# SSE-эндпоинт (/api/logs/stream) держит соединение бесконечно
# и полностью блокирует все остальные запросы.
#
# Решение: ThreadingMixIn — каждое входящее соединение
# обрабатывается в отдельном daemon-потоке.
# Это стандартная библиотека Python, 0 зависимостей.

class ThreadedWSGIServer(ServerAdapter):
    """
    Многопоточный WSGI-сервер на базе wsgiref (stdlib).
    Каждое входящее соединение обрабатывается в отдельном потоке,
    что позволяет SSE работать параллельно с API и статикой.
    """

    def run(self, handler):
        from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server
        import socketserver

        # Тихий request handler: подавляем не только логи каждого запроса,
        # но и traceback при разрыве соединения клиентом во время SSE
        # (BrokenPipeError/ConnectionResetError) — это нормальная ситуация,
        # а wsgiref по умолчанию выводит полный stderr-traceback.
        class QuietHandler(WSGIRequestHandler):
            def log_request(self, *args, **kwargs):
                pass  # Bottle сам логирует в debug-режиме

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    self.close_connection = True

        # Добавляем ThreadingMixIn к WSGIServer
        class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                import sys
                exc_type, exc_value = sys.exc_info()[:2]
                if exc_type in (BrokenPipeError, ConnectionResetError,
                                ConnectionAbortedError):
                    return  # тихо игнорируем разрыв соединения
                super().handle_error(request, client_address)

        handler_cls = QuietHandler if self.quiet else WSGIRequestHandler

        srv = make_server(
            self.host, self.port, handler,
            server_class=_ThreadingWSGIServer,
            handler_class=handler_cls,
        )
        srv.serve_forever()


def _apply_saved_strategy_on_boot():
    """
    Автоприменение сохранённой стратегии при старте GUI.

    На платформах без отдельного init.d-скрипта nfqws2 (например, Ubuntu
    с systemd) сам GUI-сервис должен запустить nfqws2 с сохранённой
    стратегией после перезагрузки системы. На Entware это делает
    отдельный init.d/S99zapret — в этом случае пропускаем, чтобы
    не запустить второй экземпляр nfqws2.

    Вызывается в фоновом потоке, чтобы не блокировать подъём web-сервера.
    """
    import threading
    import time

    def _do_apply():
        try:
            # Даём web-серверу подняться, чтобы статус был доступен
            time.sleep(1.0)

            from core.config_manager import get_config_manager
            from core.log_buffer import log

            cfg = get_config_manager()
            if not cfg.get("autostart", "enabled", default=False):
                return

            # На Entware отдельный init.d/S99zapret сам запускает nfqws2
            # при загрузке (через rc.unslung) — GUI не должен дублировать.
            # ВАЖНО: проверяем именно «скрипт реально исполняется при
            # загрузке», а не просто факт его наличия. На systemd-дистрибутивах
            # (Debian/Ubuntu) каталог /opt/etc/init.d может существовать, но
            # systemd НЕ запускает эти скрипты — там nfqws2 должен поднять
            # сам GUI (issue #107).
            from core.autostart_manager import external_boot_starts_nfqws
            if external_boot_starts_nfqws():
                log.info(
                    "init.d/S99zapret (Entware) сам запускает nfqws2 при "
                    "загрузке — GUI пропускает",
                    source="autostart",
                )
                return

            strategy_id = cfg.get("strategy", "current_id")
            if not strategy_id:
                log.info(
                    "Автозапуск включён, но активная стратегия не выбрана",
                    source="autostart",
                )
                return

            from core.nfqws_manager import get_nfqws_manager
            mgr = get_nfqws_manager()

            # Если nfqws2 уже запущен (например, после restart GUI без
            # перезагрузки системы) — ничего не делаем.
            if mgr.is_running():
                log.info(
                    "nfqws2 уже запущен — пропуск автоприменения стратегии",
                    source="autostart",
                )
                return

            from core.strategy_builder import get_strategy_manager
            sm = get_strategy_manager()
            strategy = sm.get_strategy(strategy_id)
            if not strategy:
                log.warning(
                    "Сохранённая стратегия не найдена: %s" % strategy_id,
                    source="autostart",
                )
                return

            args = sm.build_nfqws_args(strategy)
            if not args:
                log.warning(
                    "Стратегия %s не содержит включённых профилей"
                    % strategy_id,
                    source="autostart",
                )
                return

            log.info(
                "Автоприменение сохранённой стратегии: %s"
                % strategy.get("name", strategy_id),
                source="autostart",
            )

            # Применяем правила firewall
            try:
                from core.firewall import get_firewall_manager
                fw = get_firewall_manager()
                if cfg.get("firewall", "apply_on_start", default=True):
                    fw.remove_rules()
                    fw.apply_rules()
            except Exception as e:
                log.warning(
                    "Не удалось применить правила firewall: %s" % e,
                    source="autostart",
                )

            if mgr.start(args):
                log.success(
                    "Стратегия применена при автозапуске",
                    source="autostart",
                )
            else:
                log.error(
                    "Не удалось применить стратегию при автозапуске",
                    source="autostart",
                )
        except Exception as e:
            try:
                from core.log_buffer import log
                log.error("Ошибка автозапуска: %s" % e, source="autostart")
            except Exception:
                pass

    t = threading.Thread(target=_do_apply, daemon=True, name="autostart-boot")
    t.start()


def _apply_awg_autostart_on_boot():
    """
    Поднять AWG-интерфейсы при старте GUI, если:
      * есть enabled-конфиги в settings.json
      * и отдельный init-скрипт НЕ установлен (иначе он делает это сам,
        и нам не надо дублировать).

    Запускается в фоновом потоке.
    """
    import threading
    import time

    def _do_apply():
        try:
            time.sleep(1.2)

            from core.config_manager import get_config_manager
            from core.awg_autostart_manager import get_awg_autostart_manager
            from core.log_buffer import log

            am = get_awg_autostart_manager()
            enabled = am.get_enabled_interfaces()
            if not enabled:
                return

            # Если init-скрипт установлен — он сам поднимает интерфейсы
            # при старте системы. Не дублируем.
            status = am.get_status()
            if status.get("script_installed"):
                log.info(
                    "AWG init-скрипт установлен — автозапуск AWG выполняется им",
                    source="awg_autostart",
                )
                return

            log.info("Автоподъём AWG-интерфейсов при старте GUI: %s"
                     % ", ".join(enabled), source="awg_autostart")
            am.apply_autostart()
        except Exception as e:
            try:
                from core.log_buffer import log
                log.error("Ошибка автозапуска AWG: %s" % e,
                          source="awg_autostart")
            except Exception:
                pass

    t = threading.Thread(target=_do_apply, daemon=True, name="awg-autostart-boot")
    t.start()


def _apply_usque_autostart_on_boot():
    """
    Поднять WARP/MASQUE туннели при старте GUI, если:
      * usque.enabled = true
      * usque.autostart = true
      * есть конфиги для запуска

    Запускается в фоновом потоке.
    """
    import threading
    import time

    def _do_apply():
        try:
            time.sleep(1.5)

            from core.config_manager import get_config_manager
            from core.log_buffer import log

            cfg = get_config_manager()
            if not cfg.get("usque", "enabled", default=False):
                return
            if not cfg.get("usque", "autostart", default=False):
                return

            from core.usque_manager import get_usque_manager
            mgr = get_usque_manager()
            env = mgr.detect()
            if not env.get("installed"):
                log.info("usque autostart: бинарник не установлен, пропуск",
                         source="usque")
                return

            configs = mgr.list_configs()
            if not configs:
                log.info("usque autostart: нет конфигов, пропуск",
                         source="usque")
                return

            sni = cfg.get("usque", "default_sni", default="")
            http2 = cfg.get("usque", "http2_enable", default=False)

            for c in configs:
                if c.get("active"):
                    log.info("usque: %s уже запущен, пропуск" % c["name"],
                             source="usque")
                    continue
                log.info("usque autostart: запуск %s" % c["name"],
                         source="usque")
                result = mgr.start(c["iface"], c["path"],
                                   sni=sni, http2=http2)
                if not result.get("ok"):
                    log.warning("usque autostart: %s — %s" % (
                        c["name"], result.get("error", "ошибка")),
                        source="usque")

        except Exception as e:
            try:
                from core.log_buffer import log
                log.error("usque autostart: %s" % e, source="usque")
            except Exception:
                pass

    t = threading.Thread(target=_do_apply, daemon=True, name="usque-autostart-boot")
    t.start()


def _run_awg_autostart_cli(args, stop: bool = False):
    """
    CLI-режим автозапуска AmneziaWG: вызывается init-скриптом.
    Инициализирует только ядро (без Bottle), выполняет apply/stop и выходит.
    """
    from core.config_manager import init_config
    from core.log_buffer import log

    init_config(args.config)

    try:
        from core.awg_autostart_manager import get_awg_autostart_manager
        am = get_awg_autostart_manager()
        if stop:
            result = am.stop_autostart()
        else:
            result = am.apply_autostart()
        ok = result.get("ok", False)
        if ok:
            log.success(
                "CLI awg %s: ok" % ("stop" if stop else "apply"),
                source="awg_autostart",
            )
        else:
            log.error(
                "CLI awg %s: %s" % (
                    "stop" if stop else "apply",
                    result.get("error") or "часть операций завершилась с ошибкой",
                ),
                source="awg_autostart",
            )
        sys.exit(0 if ok else 1)
    except Exception as e:
        try:
            from core.log_buffer import log
            log.error("CLI awg autostart: %s" % e, source="awg_autostart")
        except Exception:
            pass
        sys.exit(2)


def _run_singbox_transparent_cli(args, remove: bool = False):
    """
    CLI-режим прозрачного проксирования sing-box: вызывается init-скриптом
    на старте (reapply из сохранённых настроек) / стопе (снять правила).
    """
    from core.config_manager import init_config
    from core.log_buffer import log

    init_config(args.config)
    try:
        from core import singbox_transparent as tp
        if remove:
            result = tp.remove()
        else:
            result = tp.reapply_saved()
        ok = bool(result.get("ok", False))
        log.info("CLI singbox transparent %s: %s"
                 % ("remove" if remove else "apply",
                    "ok" if ok else result.get("error", "ошибка")),
                 source="singbox")
        sys.exit(0 if ok else 1)
    except Exception as e:
        try:
            from core.log_buffer import log as _log
            _log.error("CLI singbox transparent: %s" % e, source="singbox")
        except Exception:
            pass
        sys.exit(2)


def create_app(config_dir: str = None) -> Bottle:
    """
    Создать и настроить Bottle-приложение.

    Args:
        config_dir: Путь к директории конфигурации.
    """
    app = Bottle()

    # --- Инициализация ядра ---
    from core.config_manager import init_config, get_config_manager
    from core.log_buffer import log

    cfg_data = init_config(config_dir)
    cfg = get_config_manager()

    # Персистентный лог критичных событий (переживает перезагрузку) —
    # настраиваем сразу после загрузки конфига.
    try:
        from core.log_buffer import reconfigure_persistent_from_config
        reconfigure_persistent_from_config()
    except Exception:
        pass

    log.info("=" * 50, source="app")
    log.info("Zapret Web-GUI запускается", source="app")
    log.info(f"Конфигурация: {cfg.path}", source="app")
    log.info(f"Zapret path: {cfg.get('zapret', 'base_path')}", source="app")

    # --- Безопасность: аутентификация + CORS/CSRF ---
    import hmac
    import urllib.parse as _urlparse
    from bottle import HTTPResponse

    if cfg.get("gui", "auth_enabled", default=False) and not (
            cfg.get("gui", "auth_password", default="") or ""):
        log.warning("gui.auth_enabled=true, но пароль пуст — HTTP-"
                    "аутентификация НЕ активна; задайте gui.auth_password",
                    source="app")

    def _allowed_origins():
        origins = cfg.get("gui", "cors_origins", default=[])
        return origins if isinstance(origins, list) else []

    def _origin_ok(origin: str) -> bool:
        """Origin допустим, если он same-origin (host:port совпадает с
        запросом — без учёта схемы, чтобы пережить TLS-терминирующий прокси)
        либо явно в allowlist gui.cors_origins."""
        if not origin:
            return True  # запрос без Origin — не cross-site
        try:
            o = _urlparse.urlparse(origin)
            host_req = (request.get_header("Host") or "").lower()
            if o.netloc.lower() == host_req and host_req:
                return True
        except Exception:
            pass
        return origin in _allowed_origins()

    @app.hook("before_request")
    def _security_gate():
        # OPTIONS (CORS preflight) — без проверок: браузер не шлёт ни
        # креденшелы, ни тело; ответ отдаёт options_handler.
        if request.method == "OPTIONS":
            return
        # 1) CSRF: мутирующий cross-origin запрос отвергаем. Браузер шлёт
        #    Origin на POST/PUT/DELETE; same-origin SPA проходит. Без этого
        #    Basic-креды браузер сам приложил бы к cross-site запросу.
        if request.method in ("POST", "PUT", "DELETE"):
            origin = request.headers.get("Origin", "")
            if origin and not _origin_ok(origin):
                raise HTTPResponse(
                    '{"ok": false, "error": "cross-origin запрос отклонён"}',
                    status=403,
                    headers={"Content-Type":
                             "application/json; charset=utf-8"})
        # 2) Аутентификация (если включена и задан непустой пароль).
        if cfg.get("gui", "auth_enabled", default=False):
            password = cfg.get("gui", "auth_password", default="") or ""
            if password:
                user = cfg.get("gui", "auth_user", default="admin") or "admin"
                auth = request.auth  # (user, pass) | None — парсит Basic
                ok = (auth is not None
                      and hmac.compare_digest(auth[0], user)
                      and hmac.compare_digest(auth[1], password))
                if not ok:
                    raise HTTPResponse(
                        "401 Unauthorized", status=401,
                        headers={"WWW-Authenticate":
                                 'Basic realm="zapret-gui"'})

    @app.hook("after_request")
    def _set_response_headers():
        # CORS: отражаем Origin ТОЛЬКО для разрешённых источников (никогда
        # `*`) — иначе любой сайт мог бы читать ответы API роутера.
        origin = request.headers.get("Origin", "")
        if origin and _origin_ok(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Methods"] = \
                "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = \
                "Origin, Content-Type, Accept, Authorization"
        # Запрещаем кеширование API-ответов — без этого браузер может
        # вернуть устаревшие данные после POST/PUT/DELETE.
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = \
                "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"

    @app.route("/api/<path:path>", method="OPTIONS")
    def options_handler(path):
        return {}

    # --- Регистрация API ---
    from api import register_routes
    register_routes(app)

    # --- Статические файлы ---
    @app.route("/")
    def index():
        return static_file("index.html", root=WEB_DIR)

    @app.route("/css/<filepath:path>")
    def serve_css(filepath):
        return static_file(filepath, root=os.path.join(WEB_DIR, "css"))

    @app.route("/js/<filepath:path>")
    def serve_js(filepath):
        return static_file(filepath, root=os.path.join(WEB_DIR, "js"))

    @app.route("/img/<filepath:path>")
    def serve_img(filepath):
        return static_file(filepath, root=os.path.join(WEB_DIR, "img"))

    # --- Favicon ---
    @app.route("/favicon.ico")
    def favicon():
        return static_file("img/favicon.svg", root=WEB_DIR)

    # --- 404 для SPA ---
    @app.error(404)
    def error404(error):
        # Для API — JSON ошибка
        if request.path.startswith("/api/"):
            response.content_type = "application/json; charset=utf-8"
            return '{"ok": false, "error": "Не найдено"}'
        # Для остального — SPA fallback
        return static_file("index.html", root=WEB_DIR)

    # --- 500 для API — JSON вместо HTML ---
    # Без этого SSE-клиент (EventSource) получает HTML-ответ
    # «Critical error while processing request» вместо корректного
    # SSE-потока, что приводит к циклу переподключений и спаму ошибок.
    @app.error(500)
    def error500(error):
        if request.path.startswith("/api/"):
            response.content_type = "application/json; charset=utf-8"
            msg = str(error.body) if hasattr(error, 'body') else "Внутренняя ошибка сервера"
            return '{"ok": false, "error": "%s"}' % msg.replace('"', '\\"')
        return '<h1>Внутренняя ошибка сервера</h1><p>%s</p>' % str(error)

    log.success("Web-GUI инициализирован", source="app")

    # Автоприменение сохранённой стратегии при старте
    # (для платформ без отдельного nfqws2-init: Ubuntu/systemd и пр.)
    _apply_saved_strategy_on_boot()

    # Миграция legacy-правил selective routing в единый слой —
    # ДО автоподъёма AWG, чтобы iface-up хук применял уже только
    # производные uni-* правила (no-op, когда legacy-правил нет).
    try:
        from core.unified import migration as _uni_migration
        _uni_migration.migrate_on_boot()
    except Exception:
        pass

    # Автоподъём AWG-интерфейсов при старте GUI (если init-скрипт не
    # установлен — иначе он сам справится при загрузке системы).
    _apply_awg_autostart_on_boot()

    # Поднять фоновый мониторинг единого слоя, если есть маршруты с
    # включённым мониторингом/автопереключением (переживает рестарт GUI).
    try:
        from core.unified import monitor as _uni_monitor
        _uni_monitor.autostart_if_needed()
    except Exception:
        pass

    # Поднять фоновые обновлятели подписок и пула серверов, если они
    # настроены — чтобы автообновление по таймеру переживало рестарт GUI.
    try:
        from core.subscription_manager import get_refresher
        get_refresher().reconfigure()
    except Exception:
        pass
    try:
        from core.server_pool import get_pool_refresher
        get_pool_refresher().reconfigure()
    except Exception:
        pass
    try:
        from core.list_updater import get_list_refresher
        get_list_refresher().reconfigure()
    except Exception:
        pass

    # AWG-watchdog: автоперезапуск «зависших» туннелей (handshake устарел
    # ИЛИ приём встал). Поднимаем при старте GUI, чтобы защита работала
    # автономно после ребута роутера, а не только когда открыта страница
    # AWG. Ничего не делает, если awg.watchdog.enabled = false (дефолт).
    try:
        from core.awg_watchdog import get_watchdog
        get_watchdog().reconfigure()
    except Exception as e:
        log.warning("AWG-watchdog при boot: %s" % e, source="awg")

    # sing-box watchdog: авто-перезапуск инстанса, если прокси «завис»
    # (проба через Clash API не проходит). Ничего не делает, если
    # singbox.watchdog.enabled = false (дефолт).
    try:
        from core.singbox_watchdog import get_watchdog as _sb_watchdog
        _sb_watchdog().reconfigure()
    except Exception as e:
        log.warning("sing-box watchdog при boot: %s" % e, source="singbox")

    # mihomo watchdog: то же, что у sing-box, но проба через external-controller
    # mihomo. Ничего не делает, если mihomo.watchdog.enabled = false (дефолт).
    try:
        from core.mihomo_watchdog import get_watchdog as _mh_watchdog
        _mh_watchdog().reconfigure()
    except Exception as e:
        log.warning("mihomo watchdog при boot: %s" % e, source="mihomo")

    # Tunnel Optimizer: применить оптимизации если включены.
    try:
        from core.config_manager import get_config_manager as _cfg_opt
        _cfg_opt2 = _cfg_opt()
        if _cfg_opt2.get("tunnel_optimizer", "enabled", default=False):
            from core.tunnel_optimizer import optimize_all_tunnels
            profile = _cfg_opt2.get("tunnel_optimizer", "profile", default="balanced")
            optimize_all_tunnels(profile)
            log.info("tunnel-optimizer: оптимизации применены (profile=%s)" % profile,
                     source="optimizer")
    except Exception as e:
        log.warning("tunnel-optimizer при boot: %s" % e, source="optimizer")

    # Tunnel Monitor: запустить сбор метрик туннелей.
    try:
        from core.tunnel_monitor import get_tunnel_monitor
        get_tunnel_monitor().start()
    except Exception as e:
        log.warning("tunnel-monitor при boot: %s" % e, source="monitor")

    # WARP-in-WARP watchdog: проверка двойных туннелей.
    try:
        from core.warp_in_warp_watchdog import get_warp_in_warp_watchdog
        get_warp_in_warp_watchdog().reconfigure()
    except Exception as e:
        log.warning("warp-in-warp watchdog при boot: %s" % e, source="warp_in_warp")

    # Update Checker: запустить фоновую проверку обновлений если включена.
    try:
        from core.update_checker import get_update_checker
        get_update_checker().reconfigure()
    except Exception as e:
        log.warning("update-checker при boot: %s" % e, source="update_checker")

    # Opera Proxy watchdog: авто-рестарт если процесс упал.
    try:
        from core.opera_proxy_watchdog import get_opera_proxy_watchdog
        get_opera_proxy_watchdog().reconfigure()
    except Exception as e:
        log.warning("opera-proxy watchdog при boot: %s" % e, source="opera_proxy")

    # Opera Proxy autostart: запустить если включён.
    try:
        from core.config_manager import get_config_manager as _cfg_op
        _cfg_op2 = _cfg_op()
        if _cfg_op2.get("opera_proxy", "enabled", default=False) and \
           _cfg_op2.get("opera_proxy", "autostart", default=False):
            from core.opera_proxy_manager import get_opera_proxy_manager
            _opmgr = get_opera_proxy_manager()
            if not _opmgr._is_running():
                _opmgr.start(
                    country=_cfg_op2.get("opera_proxy", "country", default="EU"),
                    bind=_cfg_op2.get("opera_proxy", "bind", default="127.0.0.1:18080"),
                    socks_mode=_cfg_op2.get("opera_proxy", "socks_mode", default=False),
                )
                log.info("opera-proxy: автозапуск при старте", source="opera_proxy")
    except Exception as e:
        log.warning("opera-proxy autostart при boot: %s" % e, source="opera_proxy")

    # Telegram proxy autostart: запустить если включён.
    try:
        from core.config_manager import get_config_manager as _cfg_tg
        _cfg_tg2 = _cfg_tg()
        if _cfg_tg2.get("tgproxy", "enabled", default=False) and \
           _cfg_tg2.get("tgproxy", "autostart", default=False):
            from core.tgproxy_manager import get_tgproxy_manager
            _tgmgr = get_tgproxy_manager()
            if not _tgmgr._is_running():
                _tgmgr.start(
                    engine=_cfg_tg2.get("tgproxy", "engine", default="auto"),
                    port=_cfg_tg2.get("tgproxy", "port", default=9443),
                )
                log.info("tgproxy: автозапуск при старте", source="tgproxy")
    except Exception as e:
        log.warning("tgproxy autostart при boot: %s" % e, source="tgproxy")

    # Block Detector: запустить DNS-мониторинг если включён.
    try:
        from core.block_detector import get_block_detector
        get_block_detector().start()
    except Exception as e:
        log.warning("block-detector при boot: %s" % e, source="block_detector")

    # WARP/MASQUE watchdog: авто-рестарт если туннель упал.
    try:
        from core.usque_watchdog import get_usque_watchdog
        get_usque_watchdog().reconfigure()
    except Exception as e:
        log.warning("usque watchdog при boot: %s" % e, source="usque")

    # Telegram proxy watchdog: авто-рестарт если процесс упал.
    try:
        from core.tgproxy_watchdog import get_tgproxy_watchdog
        get_tgproxy_watchdog().reconfigure()
    except Exception as e:
        log.warning("tgproxy watchdog при boot: %s" % e, source="tgproxy")

    # WARP/MASQUE autostart: поднять usque-туннели при старте, если
    # включён autostart и нет отдельного init.d-скрипта.
    try:
        _apply_usque_autostart_on_boot()
    except Exception as e:
        log.warning("usque autostart при boot: %s" % e, source="usque")

    # Healthcheck-демон (autocircular watchdog): ничего не делает, если
    # cfg.healthcheck.enabled = false (дефолт). Включается через GUI.
    try:
        from core.healthcheck import get_healthcheck
        get_healthcheck().start()
    except Exception as e:
        log.warning("Healthcheck при boot: %s" % e, source="app")

    return app


def _cli_command_in(argv) -> bool:
    """
    Является ли это CLI-вызовом (status/nfqws/…)? Допускаем ведущий
    `--config DIR` / `--config=DIR` перед подкомандой, чтобы команда
    `zapret-gui` (обёртка) могла передать каталог установленного конфига.
    Любые другие опции (`--host`/`--port`/`--debug`/…) означают web-режим.
    """
    from core.cli import COMMANDS as _CLI_COMMANDS
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--config":
            i += 2
            continue
        if a.startswith("--config="):
            i += 1
            continue
        return a in _CLI_COMMANDS
    return False


def main():
    """Точка входа: парсинг аргументов и запуск сервера."""
    # CLI-подкоманды (status / nfqws / strategy / singbox / mihomo) — если
    # первый позиционный аргумент один из них, работаем как консольная
    # утилита, а не web (с учётом возможного ведущего --config).
    if _cli_command_in(sys.argv[1:]):
        from core.cli import run as _cli_run
        sys.exit(_cli_run(sys.argv[1:]))

    parser = argparse.ArgumentParser(
        description="Zapret Web-GUI для роутеров"
    )
    parser.add_argument(
        "--host", default=None,
        help="Адрес привязки (по умолчанию из конфига)"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Порт (по умолчанию из конфига)"
    )
    parser.add_argument(
        "--config", default=None,
        help="Путь к директории конфигурации"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Режим отладки"
    )
    parser.add_argument(
        "--apply-awg-autostart", action="store_true",
        help="CLI-режим: поднять все enabled-AWG-интерфейсы "
             "(вызывается init-скриптом при загрузке) и выйти"
    )
    parser.add_argument(
        "--stop-awg-autostart", action="store_true",
        help="CLI-режим: опустить все поднятые AWG-интерфейсы и выйти"
    )
    parser.add_argument(
        "--apply-singbox-transparent", action="store_true",
        help="CLI-режим: переприменить firewall прозрачного "
             "проксирования из сохранённых настроек и выйти"
    )
    parser.add_argument(
        "--remove-singbox-transparent", action="store_true",
        help="CLI-режим: снять firewall прозрачного проксирования и выйти"
    )

    args = parser.parse_args()

    # CLI-режимы (не запускаем web-сервер)
    if args.apply_awg_autostart or args.stop_awg_autostart:
        _run_awg_autostart_cli(args, stop=args.stop_awg_autostart)
        return
    if args.apply_singbox_transparent or args.remove_singbox_transparent:
        _run_singbox_transparent_cli(
            args, remove=args.remove_singbox_transparent)
        return

    # Создаём приложение
    app = create_app(config_dir=args.config)

    # Параметры сервера из конфига или аргументов командной строки
    from core.config_manager import get_config_manager
    from core.log_buffer import log

    cfg = get_config_manager()

    host = args.host or cfg.get("gui", "host", default="0.0.0.0")
    port = args.port or cfg.get("gui", "port", default=8080)
    debug = args.debug or cfg.get("gui", "debug", default=False)

    log.info(f"Сервер: http://{host}:{port}", source="app")
    log.info("Режим: многопоточный (ThreadedWSGI)", source="app")
    if debug:
        log.warning("Режим отладки включён", source="app")

    # Запуск — используем ThreadedWSGIServer для поддержки SSE
    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            quiet=not debug,
            server=ThreadedWSGIServer,
        )
    except KeyboardInterrupt:
        log.info("Сервер остановлен (Ctrl+C)", source="app")
    except Exception as e:
        log.error(f"Ошибка сервера: {e}", source="app")
        sys.exit(1)


if __name__ == "__main__":
    main()
