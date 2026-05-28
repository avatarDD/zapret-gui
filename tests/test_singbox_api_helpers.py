# tests/test_singbox_api_helpers.py
"""
Unit-тесты для CRUD-helpers из api/singbox.py:
    _build_outbound_from_body, _build_transport_from_form,
    _build_tls_from_form, _do_add, _do_replace, _do_delete.

Эти функции pure (никаких subprocess / network), идеальны для unit.
"""

import unittest

from api.singbox import (
    _build_outbound_from_body, _build_transport_from_form,
    _build_tls_from_form, _do_add, _do_replace, _do_delete,
    _strip_form_keys,
)


class TestStripFormKeys(unittest.TestCase):

    def test_strips_underscore_prefixed(self):
        body = {"type": "vless", "tag": "t1", "_form": "vless",
                "_editing_tag": "old", "server": "h"}
        out = _strip_form_keys(body)
        self.assertNotIn("_form", out)
        self.assertNotIn("_editing_tag", out)
        self.assertEqual(out["type"], "vless")
        self.assertEqual(out["server"], "h")


class TestBuildTransport(unittest.TestCase):

    def test_tcp_returns_none(self):
        self.assertIsNone(_build_transport_from_form({"transport": "tcp"}))
        self.assertIsNone(_build_transport_from_form({}))

    def test_ws(self):
        tr = _build_transport_from_form({
            "transport": "ws",
            "ws_path": "/ws", "ws_host": "ws.example",
        })
        self.assertEqual(tr["type"], "ws")
        self.assertEqual(tr["path"], "/ws")
        self.assertEqual(tr["headers"]["Host"], "ws.example")

    def test_ws_default_path(self):
        tr = _build_transport_from_form({"transport": "ws"})
        self.assertEqual(tr["path"], "/")
        self.assertNotIn("headers", tr)

    def test_grpc(self):
        tr = _build_transport_from_form({
            "transport": "grpc", "grpc_service": "svc",
        })
        self.assertEqual(tr["type"], "grpc")
        self.assertEqual(tr["service_name"], "svc")


class TestBuildTls(unittest.TestCase):

    def test_no_security_returns_none(self):
        self.assertIsNone(_build_tls_from_form({}))
        self.assertIsNone(_build_tls_from_form({"security": ""}))

    def test_tls(self):
        tls = _build_tls_from_form({
            "security": "tls", "sni": "h.com", "fingerprint": "chrome",
        })
        self.assertTrue(tls["enabled"])
        self.assertEqual(tls["server_name"], "h.com")
        self.assertEqual(tls["utls"]["fingerprint"], "chrome")
        self.assertNotIn("reality", tls)

    def test_reality(self):
        tls = _build_tls_from_form({
            "security": "reality", "sni": "cf.com",
            "fingerprint": "chrome",
            "reality_pbk": "PBK", "reality_sid": "01",
        })
        self.assertTrue(tls["reality"]["enabled"])
        self.assertEqual(tls["reality"]["public_key"], "PBK")
        self.assertEqual(tls["reality"]["short_id"], "01")

    def test_insecure(self):
        tls = _build_tls_from_form({"security": "tls", "insecure": True})
        self.assertTrue(tls["insecure"])


class TestBuildOutboundFromBody(unittest.TestCase):

    def test_raw_outbound_passthrough(self):
        body = {"type": "vless", "tag": "v1",
                "server": "h", "server_port": 443, "uuid": "u"}
        ob = _build_outbound_from_body(body)
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server_port"], 443)

    def test_raw_missing_required(self):
        with self.assertRaises(ValueError):
            _build_outbound_from_body({"type": "vless"})   # нет tag
        with self.assertRaises(ValueError):
            _build_outbound_from_body({"tag": "v1"})       # нет type

    def test_form_vless_minimal(self):
        ob = _build_outbound_from_body({
            "_form": "vless", "tag": "v1",
            "server": "h", "port": 443, "uuid": "u",
        })
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["uuid"], "u")
        self.assertNotIn("tls", ob)
        self.assertNotIn("transport", ob)

    def test_form_vless_full(self):
        ob = _build_outbound_from_body({
            "_form": "vless", "tag": "v1",
            "server": "h", "port": 443, "uuid": "u",
            "flow": "xtls-rprx-vision",
            "transport": "grpc", "grpc_service": "svc",
            "security": "reality", "sni": "cf.com",
            "fingerprint": "chrome",
            "reality_pbk": "PBK", "reality_sid": "01",
        })
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertEqual(ob["transport"]["type"], "grpc")
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PBK")

    def test_form_trojan(self):
        ob = _build_outbound_from_body({
            "_form": "trojan", "tag": "t1",
            "server": "h", "port": 443, "password": "pwd",
            "sni": "h.com",
        })
        self.assertEqual(ob["type"], "trojan")
        self.assertEqual(ob["password"], "pwd")
        self.assertEqual(ob["tls"]["server_name"], "h.com")

    def test_form_shadowsocks(self):
        ob = _build_outbound_from_body({
            "_form": "shadowsocks", "tag": "s1",
            "server": "h", "port": 8388,
            "method": "aes-256-gcm", "password": "pwd",
        })
        self.assertEqual(ob["type"], "shadowsocks")
        self.assertEqual(ob["method"], "aes-256-gcm")

    def test_form_hysteria2(self):
        ob = _build_outbound_from_body({
            "_form": "hysteria2", "tag": "h1",
            "server": "h", "port": 443, "password": "pwd",
            "sni": "h.com", "insecure": True,
        })
        self.assertEqual(ob["type"], "hysteria2")
        self.assertTrue(ob["tls"]["insecure"])

    def test_form_tuic(self):
        ob = _build_outbound_from_body({
            "_form": "tuic", "tag": "tu",
            "server": "h", "port": 443,
            "uuid": "u", "password": "pwd", "sni": "h.com",
        })
        self.assertEqual(ob["type"], "tuic")
        self.assertEqual(ob["password"], "pwd")

    def test_form_missing_required(self):
        with self.assertRaises(ValueError):
            _build_outbound_from_body({
                "_form": "vless", "tag": "v1", "server": "h", "port": 443,
                # нет uuid
            })
        with self.assertRaises(ValueError):
            _build_outbound_from_body({
                "_form": "trojan", "tag": "t1",
                "server": "h", "port": 443,
                # нет password
            })
        with self.assertRaises(ValueError):
            _build_outbound_from_body({
                "_form": "vless", "tag": "v1",
                # нет server/port/uuid
            })

    def test_form_invalid_port(self):
        with self.assertRaises(ValueError):
            _build_outbound_from_body({
                "_form": "vless", "tag": "v1",
                "server": "h", "port": "not-a-number", "uuid": "u",
            })

    def test_form_unknown(self):
        with self.assertRaises(ValueError):
            _build_outbound_from_body({
                "_form": "wireguard-pro", "tag": "w1",
                "server": "h", "port": 443,
            })


class TestDoAdd(unittest.TestCase):

    def test_adds_to_list(self):
        obs = [{"type": "direct", "tag": "direct"}]
        res = _do_add(obs, {"type": "vless", "tag": "v1"})
        self.assertIsNone(res)
        self.assertEqual(len(obs), 2)

    def test_duplicate_tag(self):
        obs = [{"type": "vless", "tag": "v1"}]
        res = _do_add(obs, {"type": "trojan", "tag": "v1"})
        self.assertIsNotNone(res)
        self.assertIn("уже существует", res["error"])
        self.assertEqual(res["_status"], 409)

    def test_no_tag(self):
        obs = []
        res = _do_add(obs, {"type": "vless"})
        self.assertIsNotNone(res)
        self.assertEqual(res["_status"], 400)


class TestDoReplace(unittest.TestCase):

    def test_replaces(self):
        obs = [{"type": "direct", "tag": "d"},
               {"type": "vless",  "tag": "v1"}]
        res = _do_replace(obs, "v1",
                          {"type": "vless", "tag": "v1", "uuid": "new"})
        self.assertIsNone(res)
        self.assertEqual(obs[1]["uuid"], "new")

    def test_rename_with_collision(self):
        obs = [{"type": "vless", "tag": "v1"},
               {"type": "trojan", "tag": "t1"}]
        res = _do_replace(obs, "v1",
                          {"type": "vless", "tag": "t1"})
        self.assertIsNotNone(res)
        self.assertEqual(res["_status"], 409)

    def test_not_found(self):
        obs = [{"type": "direct", "tag": "d"}]
        res = _do_replace(obs, "nope", {"type": "vless", "tag": "nope"})
        self.assertIsNotNone(res)
        self.assertEqual(res["_status"], 404)


class TestDoDelete(unittest.TestCase):

    def test_deletes(self):
        obs = [{"type": "direct", "tag": "d"},
               {"type": "vless",  "tag": "v1"}]
        res = _do_delete(obs, "v1")
        self.assertIsNone(res)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["tag"], "d")

    def test_not_found(self):
        obs = [{"type": "direct", "tag": "d"}]
        res = _do_delete(obs, "v1")
        self.assertIsNotNone(res)
        self.assertEqual(res["_status"], 404)


if __name__ == "__main__":
    unittest.main()
