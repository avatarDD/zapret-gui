# tests/test_mcp_transport.py
"""
HTTP-слой MCP (api/mcp.py).

Основной транспорт — без SSE: единственный рабочий метод у `/api/mcp` —
POST. GET и DELETE обязаны отвечать 405 с `Allow: POST` и **понятным
текстом**: клиент, получивший голый 405, пишет в лог «сервер не
поддерживает MCP», хотя поддерживает.

Вторая половина файла — legacy-SSE (S14): схема «два канала» для
клиентов, которые ничего другого не умеют. Там проверяется то, из-за
чего роутер со 128 МБ умирает не сразу, а через сутки: брошенные
сессии.
"""

import json
import unittest

from core.mcp import auth, server
from core.mcp import session as mcp_session
from tests._wsgi_client import WSGIClient, build_test_app, make_environ


TOKEN = "a" * 64


class _McpHTTPBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", True)
        cfg.set("mcp", "token", TOKEN)
        cfg.set("mcp", "bind", "inherit")
        cfg.set("mcp", "allow_gui_auth", False)
        cfg.set("mcp", "limits", "calls_per_minute", 10000)
        auth.reset_rate_limit()

    def tearDown(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        auth.reset_rate_limit()

    def rpc(self, payload, headers=None, **kw):
        head = {"Authorization": "Bearer " + TOKEN}
        head.update(headers or {})
        return self.client.request("POST", "/api/mcp", body=payload,
                                   headers=head, **kw)


class TestMethods(_McpHTTPBase):

    def test_post_initialize(self):
        code, headers, body = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": server.PROTOCOL_VERSION}})
        self.assertEqual(code, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "zapret-gui")
        self.assertIn("application/json", headers["content-type"])

    def test_get_is_405_with_allow_and_explanation(self):
        code, headers, body = self.client.request("GET", "/api/mcp")
        self.assertEqual(code, 405)
        self.assertEqual(headers["allow"], "POST")
        self.assertIn("POST", body["error"])
        self.assertIn("не ошибка", body["error"])
        # И сразу подсказка, куда идти клиенту, который умеет только
        # старую схему: иначе он так и решит, что сервер её не знает.
        self.assertIn("/api/mcp/sse", body["error"])

    def test_delete_is_405_with_allow(self):
        code, headers, body = self.client.request("DELETE", "/api/mcp")
        self.assertEqual(code, 405)
        self.assertEqual(headers["allow"], "POST")
        self.assertIn("сесси", body["error"])


class TestProtocolHeader(_McpHTTPBase):

    def test_unknown_version_is_400_and_lists_supported(self):
        code, _, body = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"MCP-Protocol-Version": "1999-01-01"})
        self.assertEqual(code, 400)
        self.assertIn(server.PROTOCOL_VERSION, body["supported"])

    def test_known_version_passes(self):
        code, _, _ = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"MCP-Protocol-Version": "2025-03-26"})
        self.assertEqual(code, 200)

    def test_absent_header_is_not_an_error(self):
        # Первый initialize идёт без заголовка — это штатно.
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize", "params": {}})
        self.assertEqual(code, 200)


class TestBodyHandling(_McpHTTPBase):

    def test_broken_json_is_parse_error_with_http_200(self):
        # Ошибка JSON-RPC едет телом с кодом 200: клиент разбирает её
        # как ответ, а не как сбой транспорта.
        code, _, body = self.client.request(
            "POST", "/api/mcp", body="{не json",
            content_type="application/json",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 200)
        self.assertEqual(body["error"]["code"], server.PARSE_ERROR)

    def test_wrong_content_type_is_415(self):
        code, _, body = self.client.request(
            "POST", "/api/mcp", body="{}", content_type="text/plain",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 415)
        self.assertIn("application/json", body["error"])

    def test_notification_only_body_is_202(self):
        code, _, _ = self.rpc({"jsonrpc": "2.0",
                               "method": "notifications/initialized"})
        self.assertEqual(code, 202)

    def test_batch_over_http(self):
        code, _, body = self.rpc([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        self.assertEqual(code, 200)
        self.assertEqual(len(body["_data"]), 2)

    def test_cyrillic_body_is_not_truncated(self):
        # Bottle считает Content-Length по байтам: str с кириллицей
        # разъезжается с длиной и доезжает обрезанным.
        code, _, body = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call",
                                  "params": {"name": "нет_такого"}})
        self.assertEqual(code, 200)
        self.assertIn("не найден", body["error"]["message"])


class TestBrokenHeaders(_McpHTTPBase):
    """Мусор в заголовках — это 4xx, а не 500.

    bottle декодирует заголовок как latin-1 → utf-8 и бросает на
    байтах, которые в UTF-8 не складываются. Точка, куда каждый
    желающий шлёт Authorization, обязана пережить один неверный байт.
    """

    def test_broken_authorization_is_401_not_500(self):
        code, _, _ = self.client.request(
            "POST", "/api/mcp", body={"jsonrpc": "2.0", "id": 1,
                                      "method": "ping"},
            headers={"Authorization": "Bearer \udcff\udcfe"})
        self.assertEqual(code, 401)

    def test_broken_session_id_is_not_500(self):
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              headers={"Mcp-Session-Id": "\udcff"})
        self.assertEqual(code, 200)


class TestSession(_McpHTTPBase):

    def test_session_id_is_issued(self):
        _, headers, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "initialize", "params": {}})
        self.assertTrue(headers.get("mcp-session-id"))

    def test_client_session_id_is_echoed_back(self):
        _, headers, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "ping"},
                                 headers={"Mcp-Session-Id": "abc123"})
        self.assertEqual(headers.get("mcp-session-id"), "abc123")

    def test_unknown_session_id_still_works(self):
        # Сервер без состояния: чужая сессия — не повод отказывать,
        # иначе после ребута роутера клиент получает «сессия не найдена».
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              headers={"Mcp-Session-Id": "неизвестная"})
        self.assertEqual(code, 200)


class TestInfo(_McpHTTPBase):

    def test_info_is_open_locally_without_token(self):
        code, _, body = self.client.request("GET", "/api/mcp/info",
                                            remote_addr="127.0.0.1")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["protocol_version"], server.PROTOCOL_VERSION)
        self.assertGreaterEqual(body["tools_total"], 2)
        self.assertIn("control", body["permissions"])

    def test_info_never_returns_the_token(self):
        _, _, body = self.client.request("GET", "/api/mcp/info")
        self.assertTrue(body["token_set"])
        self.assertNotIn(TOKEN, json.dumps(body, ensure_ascii=False))
        self.assertNotIn("token", [k for k in body if k != "token_set"])

    def test_info_is_403_from_outside(self):
        code, _, body = self.client.request("GET", "/api/mcp/info",
                                            remote_addr="192.168.1.50")
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])

    def test_info_allows_ipv4_mapped_loopback(self):
        code, _, _ = self.client.request("GET", "/api/mcp/info",
                                         remote_addr="::ffff:127.0.0.1")
        self.assertEqual(code, 200)


# ───────────────────────── legacy-SSE (S14) ─────────────────────────

class _Stream:
    """Открытый SSE-поток: заголовки сразу, события — по одному.

    ``WSGIClient`` дочитывает тело до конца, а поток не кончается
    никогда — поэтому здесь собственный вызов приложения и ручное
    вытягивание событий. Так же ведёт себя и настоящий клиент: читает
    по событию и держит соединение.
    """

    def __init__(self, app, path="/api/mcp/sse", headers=None,
                 remote_addr="127.0.0.1"):
        env = make_environ("GET", path, headers=headers,
                           remote_addr=remote_addr)
        captured = {"status": "", "headers": []}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = response_headers
            return lambda chunk: None

        self._body = app(env, start_response)
        self._iter = iter(self._body)
        self.code = int((captured["status"] or "0").split(" ", 1)[0])
        self.headers = {k.lower(): v for k, v in captured["headers"]}

    def chunk(self) -> str:
        """Следующее событие (блокирует, как настоящий поток)."""
        piece = next(self._iter)
        return piece.decode("utf-8") if isinstance(piece, bytes) else piece

    def event(self) -> tuple:
        """Следующее событие как (имя, данные); комментарий — («», текст)."""
        raw = self.chunk()
        if raw.startswith(":"):
            return "", raw[1:].strip()
        name, data = "", ""
        for line in raw.splitlines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                data = line[6:]
        return name, data

    def json_body(self) -> dict:
        """Тело отказа (404/429): поток не открылся, читаем целиком."""
        raw = b"".join(c if isinstance(c, bytes) else c.encode("utf-8")
                       for c in self._iter)
        return json.loads(raw.decode("utf-8") or "{}")

    def close(self):
        close = getattr(self._body, "close", None)
        if callable(close):
            close()


class _SSEBase(_McpHTTPBase):

    def setUp(self):
        super().setUp()
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "transports", {"http": True, "sse": True})
        cfg.set("mcp", "limits", "max_sessions", 4)
        mcp_session.reset()
        self._keepalive = mcp_session.KEEPALIVE_SEC
        self._idle = mcp_session.IDLE_TIMEOUT_SEC

    def tearDown(self):
        mcp_session.KEEPALIVE_SEC = self._keepalive
        mcp_session.IDLE_TIMEOUT_SEC = self._idle
        mcp_session.reset()
        from core.config_manager import get_config_manager
        get_config_manager().set("mcp", "transports",
                                 {"http": True, "sse": False})
        super().tearDown()

    def open_stream(self, **kw):
        stream = _Stream(self.client.app,
                         headers={"Authorization": "Bearer " + TOKEN}, **kw)
        self.addCleanup(stream.close)
        return stream

    def endpoint_of(self, stream) -> str:
        name, data = stream.event()
        self.assertEqual(name, "endpoint")
        return data

    def session_of(self, stream) -> str:
        return self.endpoint_of(stream).split("session=", 1)[1]

    def send(self, session_id, payload, **kw):
        head = {"Authorization": "Bearer " + TOKEN}
        head.update(kw.pop("headers", None) or {})
        path = "/api/mcp/messages"
        if session_id is not None:
            path += "?session=" + session_id
        return self.client.request("POST", path, body=payload,
                                   headers=head, **kw)


class TestSSEDisabled(_McpHTTPBase):
    """По умолчанию SSE выключен, и это видно из ответа, а не из молчания."""

    def setUp(self):
        super().setUp()
        from core.config_manager import get_config_manager
        get_config_manager().set("mcp", "transports",
                                 {"http": True, "sse": False})
        mcp_session.reset()

    def test_sse_is_404_with_explanation(self):
        stream = _Stream(self.client.app,
                         headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(stream.code, 404)
        body = stream.json_body()
        self.assertIn("mcp.transports.sse", body["error"])
        self.assertEqual(body["endpoint"], "/api/mcp")

    def test_messages_is_404_too(self):
        code, _, body = self.client.request(
            "POST", "/api/mcp/messages?session=x",
            body={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 404)
        self.assertIn("mcp.transports.sse", body["error"])

    def test_no_session_is_left_behind(self):
        self.assertEqual(mcp_session.count(), 0)


class TestSSEStream(_SSEBase):

    def test_endpoint_event_comes_first(self):
        stream = self.open_stream()
        self.assertEqual(stream.code, 200)
        self.assertIn("text/event-stream", stream.headers["content-type"])
        endpoint = self.endpoint_of(stream)
        self.assertTrue(endpoint.startswith("/api/mcp/messages?session="))
        # Сессия названа и в заголовке: клиенту так удобнее, нам — тоже.
        self.assertIn(stream.headers["mcp-session-id"], endpoint)

    def test_no_hop_by_hop_headers(self):
        # wsgiref (сервер GUI) на hop-by-hop заголовке вроде
        # «Connection: keep-alive» падает AssertionError-ом, и вместо
        # потока клиент получает 500 «Critical error». Тестовый клиент
        # такого не ловит — проверяем явно, и для потока логов тоже.
        from wsgiref.util import is_hop_by_hop
        for path, head in (("/api/mcp/sse",
                            {"Authorization": "Bearer " + TOKEN}),
                           ("/api/logs/stream", {})):
            with self.subTest(path=path):
                stream = _Stream(self.client.app, path=path, headers=head)
                self.addCleanup(stream.close)
                self.assertEqual(stream.code, 200)
                bad = [k for k in stream.headers if is_hop_by_hop(k)]
                self.assertEqual(bad, [])

    def test_message_is_delivered_into_the_stream(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        code, _, _ = self.send(session_id,
                               {"jsonrpc": "2.0", "id": 1,
                                "method": "initialize", "params": {}})
        # Ответа в теле POST нет и быть не может: клиент этой схемы
        # читает только поток.
        self.assertEqual(code, 202)
        name, data = stream.event()
        self.assertEqual(name, "message")
        answer = json.loads(data)
        self.assertEqual(answer["id"], 1)
        self.assertEqual(answer["result"]["serverInfo"]["name"],
                         "zapret-gui")

    def test_tools_call_goes_through_the_same_dispatcher(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        self.send(session_id, {"jsonrpc": "2.0", "id": 2,
                               "method": "tools/call",
                               "params": {"name": "system_status"}})
        _, data = stream.event()
        answer = json.loads(data)
        self.assertFalse(answer["result"]["isError"])

    def test_answer_is_one_event_without_raw_newlines(self):
        # Перевод строки внутри data разорвал бы событие надвое.
        stream = self.open_stream()
        session_id = self.session_of(stream)
        self.send(session_id, {"jsonrpc": "2.0", "id": 3,
                               "method": "tools/list"})
        raw = stream.chunk()
        self.assertEqual(len([line for line in raw.splitlines()
                              if line.startswith("data: ")]), 1)

    def test_batch_is_delivered_as_one_event(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        self.send(session_id, [{"jsonrpc": "2.0", "id": 1, "method": "ping"},
                               {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
        _, data = stream.event()
        self.assertEqual([item["id"] for item in json.loads(data)], [1, 2])

    def test_notification_leaves_the_stream_silent(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        code, _, _ = self.send(session_id,
                               {"jsonrpc": "2.0",
                                "method": "notifications/initialized"})
        self.assertEqual(code, 202)
        self.assertEqual(mcp_session.get(session_id).pending(), 0)

    def test_broken_json_arrives_as_parse_error_in_the_stream(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        code, _, _ = self.send(session_id, "{не json",
                               content_type="application/json")
        self.assertEqual(code, 202)
        _, data = stream.event()
        self.assertEqual(json.loads(data)["error"]["code"],
                         server.PARSE_ERROR)

    def test_keepalive_when_nothing_happens(self):
        # Без пинга соединение закроет первый же прокси по дороге.
        mcp_session.KEEPALIVE_SEC = 0.05
        stream = self.open_stream()
        self.endpoint_of(stream)
        name, text = stream.event()
        self.assertEqual(name, "")
        self.assertIn("keep-alive", text)


class TestSSESessions(_SSEBase):
    """Мёртвая сессия на роутере со 128 МБ — это утечка, а не мелочь."""

    def test_client_disconnect_frees_the_session(self):
        stream = self.open_stream()
        self.endpoint_of(stream)
        self.assertEqual(mcp_session.count(), 1)
        stream.close()
        self.assertEqual(mcp_session.count(), 0)

    def test_max_sessions_is_enforced(self):
        from core.config_manager import get_config_manager
        get_config_manager().set("mcp", "limits", "max_sessions", 1)
        first = self.open_stream()
        self.endpoint_of(first)
        second = self.open_stream()
        self.assertEqual(second.code, 429)
        body = second.json_body()
        self.assertEqual(body["max_sessions"], 1)
        self.assertIn("max_sessions", body["error"])

    def test_freed_slot_is_reusable(self):
        from core.config_manager import get_config_manager
        get_config_manager().set("mcp", "limits", "max_sessions", 1)
        first = self.open_stream()
        self.endpoint_of(first)
        first.close()
        second = self.open_stream()
        self.assertEqual(second.code, 200)

    def test_idle_session_is_swept(self):
        # Сервер, бросивший генератор не закрыв, оставил бы очередь
        # навсегда: подметание — сеть под штатным путём.
        stream = self.open_stream()
        self.endpoint_of(stream)
        mcp_session.IDLE_TIMEOUT_SEC = -1
        self.assertEqual(mcp_session.count(), 0)

    def test_unknown_session_is_404_and_says_what_to_do(self):
        code, _, body = self.send("нет-такой",
                                  {"jsonrpc": "2.0", "id": 1,
                                   "method": "ping"})
        self.assertEqual(code, 404)
        self.assertIn("/api/mcp/sse", body["error"])

    def test_messages_without_session_is_404(self):
        code, _, body = self.send(None, {"jsonrpc": "2.0", "id": 1,
                                         "method": "ping"})
        self.assertEqual(code, 404)
        self.assertIn("не найдена", body["error"])

    def test_session_id_alias_is_accepted(self):
        # Клиенты, собранные по старым SDK, шлют sessionId.
        stream = self.open_stream()
        session_id = self.session_of(stream)
        code, _, _ = self.client.request(
            "POST", "/api/mcp/messages?sessionId=" + session_id,
            body={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 202)

    def test_messages_without_token_is_401(self):
        stream = self.open_stream()
        session_id = self.session_of(stream)
        code, _, _ = self.client.request(
            "POST", "/api/mcp/messages?session=" + session_id,
            body={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(code, 401)

    def test_stream_without_token_is_401(self):
        stream = _Stream(self.client.app)
        self.assertEqual(stream.code, 401)
        self.assertEqual(mcp_session.count(), 0)


class TestSSENotifications(_SSEBase):
    """Смена разрешений = смена набора инструментов, и клиент это узнаёт."""

    def test_permission_change_broadcasts_tools_list_changed(self):
        from core.config_manager import get_config_manager
        mcp_session.KEEPALIVE_SEC = 0.05
        stream = self.open_stream()
        self.endpoint_of(stream)
        get_config_manager().set("mcp", "permissions", "control", True)
        try:
            name, data = stream.event()
        finally:
            get_config_manager().set("mcp", "permissions", "control", False)
        self.assertEqual(name, "message")
        self.assertEqual(json.loads(data)["method"],
                         "notifications/tools/list_changed")

    def test_no_notification_while_nothing_changes(self):
        mcp_session.KEEPALIVE_SEC = 0.05
        stream = self.open_stream()
        self.endpoint_of(stream)
        name, text = stream.event()
        self.assertEqual(name, "")
        self.assertIn("keep-alive", text)


class TestSSEToggle(_SSEBase):
    """Включение и выключение SSE не требует перезапуска GUI."""

    def test_flag_is_read_per_request(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        first = self.open_stream()
        self.assertEqual(first.code, 200)
        self.endpoint_of(first)
        cfg.set("mcp", "transports", {"http": True, "sse": False})
        closed = _Stream(self.client.app,
                         headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(closed.code, 404)
        cfg.set("mcp", "transports", {"http": True, "sse": True})
        again = self.open_stream()
        self.assertEqual(again.code, 200)


class TestSSEInfo(_SSEBase):

    def test_info_reports_sse_state(self):
        _, _, body = self.client.request("GET", "/api/mcp/info",
                                         remote_addr="127.0.0.1")
        self.assertTrue(body["sse"]["enabled"])
        self.assertEqual(body["sse"]["endpoint"], "/api/mcp/sse")
        self.assertEqual(body["sse"]["sessions"], 0)

    def test_info_counts_open_sessions(self):
        stream = self.open_stream()
        self.endpoint_of(stream)
        _, _, body = self.client.request("GET", "/api/mcp/info",
                                         remote_addr="127.0.0.1")
        self.assertEqual(body["sse"]["sessions"], 1)


class TestHttpTransportToggle(_McpHTTPBase):
    """`mcp.transports.http` — переключатель, а не украшение (S17).

    До S17 флаг висел в настройках и не влиял ни на что: пользователь
    выключал транспорт и продолжал работать. Это хуже отсутствия флага.
    """

    def disable(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        self.addCleanup(cfg.set, "mcp", "transports", "http", True)
        cfg.set("mcp", "transports", "http", False)

    def test_enabled_by_default(self):
        self.assertTrue(auth.http_enabled())

    def test_missing_key_means_enabled(self):
        # Обновление GUI не должно молча выключать транспорт, который
        # работал всегда.
        saved = auth.settings
        self.addCleanup(setattr, auth, "settings", saved)
        auth.settings = lambda: {"transports": {"sse": False}}
        self.assertTrue(auth.http_enabled())

    def test_post_is_503_when_disabled(self):
        self.disable()
        code, headers, body = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        # 503, а не 404: точка вернётся, как только транспорт включат, —
        # клиенту есть смысл повторить.
        self.assertEqual(code, 503)
        self.assertEqual(headers.get("retry-after"), "60")
        self.assertIn("mcp.transports.http", body["error"])

    def test_refusal_names_the_way_back(self):
        self.disable()
        _, _, body = self.rpc({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize"})
        # Отрезать себя этим нельзя, и в ответе сказано чем включить.
        self.assertIn("MCP-сервер", body["error"])
        self.assertIn("stdio", body["hint"])

    def test_refused_before_authorization(self):
        # Для подбирающего токен это неотличимо от «точки нет».
        self.disable()
        code, _, _ = self.client.request(
            "POST", "/api/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(code, 503)

    def test_get_also_says_so(self):
        self.disable()
        code, _, _ = self.client.request("GET", "/api/mcp")
        self.assertEqual(code, 503)

    def test_ui_panel_keeps_working(self):
        # Главное свойство: страница MCP — отдельная дверь, и она
        # включает транспорт обратно.
        self.disable()
        answer = self.client.get_json("/api/mcp/ui/state")
        self.assertEqual(answer["_status"], 200)

    def test_post_works_again_once_enabled(self):
        self.disable()
        from core.config_manager import get_config_manager
        get_config_manager().set("mcp", "transports", "http", True)
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize"})
        self.assertEqual(code, 200)


class TestExistingRoutesIntact(_McpHTTPBase):
    """MCP не должен ничего сдвинуть в уже работающем API."""

    def test_status_still_works(self):
        self.assertEqual(self.client.get_json("/api/status")["_status"], 200)

    def test_ping_still_works(self):
        self.assertEqual(self.client.get_json("/api/ping")["_status"], 200)


if __name__ == "__main__":
    unittest.main()
