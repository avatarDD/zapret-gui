# tests/_wsgi_client.py
"""
Минимальный WSGI test-client для bottle-приложения zapret-gui.

Не использует webtest или другие внешние зависимости — bottle-app
является WSGI-callable, поэтому мы напрямую вызываем `app(environ,
start_response)` и собираем ответ.

Пример:
    client = WSGIClient(build_app())
    status, body = client.get('/api/singbox/configs')
    assert status.startswith('200')
    data = client.get_json('/api/singbox/configs')
    assert data['ok'] is True
"""

import io
import json
import sys


def make_environ(method: str, path: str, *,
                 body: bytes = None,
                 query: str = "",
                 content_type: str = "") -> dict:
    env = {
        "REQUEST_METHOD":    method.upper(),
        "PATH_INFO":         path,
        "QUERY_STRING":      query,
        "SERVER_NAME":       "localhost",
        "SERVER_PORT":       "80",
        "SERVER_PROTOCOL":   "HTTP/1.1",
        "HTTP_HOST":         "localhost",
        "wsgi.version":      (1, 0),
        "wsgi.url_scheme":   "http",
        "wsgi.input":        io.BytesIO(),
        "wsgi.errors":       sys.stderr,
        "wsgi.multithread":  False,
        "wsgi.multiprocess": False,
        "wsgi.run_once":     False,
    }
    if body is not None:
        env["wsgi.input"]     = io.BytesIO(body)
        env["CONTENT_LENGTH"] = str(len(body))
        if content_type:
            env["CONTENT_TYPE"] = content_type
    return env


class WSGIClient:
    """Простая обёртка для unit-тестов API endpoint'ов."""

    def __init__(self, app):
        self.app = app

    # ─── low-level ───

    def _call(self, method: str, path: str, *,
              body: bytes = None,
              content_type: str = ""):
        env = make_environ(method, path,
                           body=body, content_type=content_type)
        result = {"status": "", "headers": []}

        def start_response(status, headers, exc_info=None):
            result["status"]  = status
            result["headers"] = headers
            return lambda s: None

        body_iter = self.app(env, start_response)
        try:
            chunks = [b if isinstance(b, bytes) else b.encode("utf-8")
                      for b in body_iter]
            response_body = b"".join(chunks)
        finally:
            close = getattr(body_iter, "close", None)
            if callable(close):
                close()
        return result["status"], response_body

    # ─── high-level shortcuts ───

    def get(self, path: str):
        return self._call("GET", path)

    def post(self, path: str, body=None):
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            return self._call("POST", path, body=data,
                              content_type="application/json")
        return self._call("POST", path, body=body or b"")

    def put(self, path: str, body=None):
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            return self._call("PUT", path, body=data,
                              content_type="application/json")
        return self._call("PUT", path, body=body or b"")

    def delete(self, path: str):
        return self._call("DELETE", path)

    # ─── parsing ───

    def get_json(self, path: str):
        status, body = self.get(path)
        return _parse_response(status, body)

    def post_json(self, path: str, body=None):
        status, body = self.post(path, body)
        return _parse_response(status, body)

    def put_json(self, path: str, body=None):
        status, body = self.put(path, body)
        return _parse_response(status, body)

    def delete_json(self, path: str):
        status, body = self.delete(path)
        return _parse_response(status, body)


def _parse_response(status: str, body: bytes) -> dict:
    """Распарсить JSON-ответ + завернуть статус-код в .status."""
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = {"_raw": body.decode("utf-8", errors="replace")}
    code = 0
    if status:
        try:
            code = int(status.split(" ", 1)[0])
        except (ValueError, IndexError):
            code = 0
    if not isinstance(data, dict):
        data = {"_data": data}
    data["_status"] = code
    return data


# ─── helper для построения test-app ───

def build_test_app():
    """Создать чистое bottle-приложение с зарегистрированными API.

    ensure_bottle(): в dev-окружении системного bottle может не быть —
    тогда используется встроенный vendor/bottle.py, и api-тесты
    работают без pip install.
    """
    from core.bottle_vendor import ensure_bottle
    ensure_bottle()
    from bottle import Bottle
    from api import register_routes
    app = Bottle()
    register_routes(app)
    return app
