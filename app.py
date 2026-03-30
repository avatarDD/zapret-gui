import os
import sys
import argparse
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(APP_DIR, "web")
try:
    from bottle import Bottle, static_file, response, request, ServerAdapter
except ImportError:
    print("ОШИБКА: Bottle не найден. Установите: pip3 install bottle")
    print("  или: opkg install python3-bottle")
    sys.exit(1)
class ThreadedWSGIServer(ServerAdapter):
    def run(self, handler):
        from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server
        import socketserver
        class QuietHandler(WSGIRequestHandler):
            def log_request(self, *args, **kwargs):
                pass
        class _ThreadingWSGIServer(socketserver.ThreadingMixIn, WSGIServer):
            daemon_threads = True
            allow_reuse_address = True
        handler_cls = QuietHandler if self.quiet else WSGIRequestHandler
        srv = make_server(
            self.host, self.port, handler,
            server_class=_ThreadingWSGIServer,
            handler_class=handler_cls,
        )
        srv.serve_forever()
def create_app(config_dir: str = None) -> Bottle:
    app = Bottle()
    from core.config_manager import init_config, get_config_manager
    from core.log_buffer import log
    cfg_data = init_config(config_dir)
    cfg = get_config_manager()
    log.info("=" * 50, source="app")
    log.info("Zapret Web-GUI запускается", source="app")
    log.info(f"Конфигурация: {cfg.path}", source="app")
    log.info(f"Zapret path: {cfg.get('zapret', 'base_path')}", source="app")
    @app.hook("after_request")
    def enable_cors():
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = \
            "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = \
            "Origin, Content-Type, Accept"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
    @app.route("/api/<path:path>", method="OPTIONS")
    def options_handler(path):
        return {}
    from api import register_routes
    register_routes(app)
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
    @app.route("/favicon.ico")
    def favicon():
        return static_file("img/favicon.svg", root=WEB_DIR)
    @app.error(404)
    def error404(error):
        if request.path.startswith("/api/"):
            response.content_type = "application/json; charset=utf-8"
            return '{"ok": false, "error": "Не найдено"}'
        return static_file("index.html", root=WEB_DIR)
    @app.error(500)
    def error500(error):
        if request.path.startswith("/api/"):
            response.content_type = "application/json; charset=utf-8"
            msg = str(error.body) if hasattr(error, 'body') else "Внутренняя ошибка сервера"
            return '{"ok": false, "error": "%s"}' % msg.replace('"', '\\"')
        return '<h1>Внутренняя ошибка сервера</h1><p>%s</p>' % str(error)
    log.success("Web-GUI инициализирован", source="app")
    return app
def main():
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
    args = parser.parse_args()
    app = create_app(config_dir=args.config)
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
