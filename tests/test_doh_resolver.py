# tests/test_doh_resolver.py
"""Unit-тесты для core/routing/doh_resolver.py."""

import json
import unittest
from unittest import mock

from core.routing import doh_resolver


class FakeConfigManager:
    def __init__(self, data=None):
        self.data = data or {}

    def load(self):
        return self.data


class TestGetSettings(unittest.TestCase):

    def test_default_disabled(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = doh_resolver._get_settings()
            self.assertFalse(s["enabled"])
            self.assertIsInstance(s["providers"], list)
            self.assertTrue(s["providers"])
            self.assertGreater(s["timeout"], 0)

    def test_custom_settings(self):
        cfg = {"routing": {"doh": {
            "enabled": True,
            "providers": ["https://my.doh/dns-query"],
            "timeout": 10,
        }}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager(cfg)):
            s = doh_resolver._get_settings()
            self.assertTrue(s["enabled"])
            self.assertEqual(s["providers"],
                             ["https://my.doh/dns-query"])
            self.assertEqual(s["timeout"], 10.0)

    def test_garbage_settings_falls_back(self):
        cfg = {"routing": {"doh": "garbage"}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager(cfg)):
            s = doh_resolver._get_settings()
            # Не падает; возвращает значения по умолчанию.
            self.assertFalse(s["enabled"])


class TestIsEnabled(unittest.TestCase):

    def test_off(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            self.assertFalse(doh_resolver.is_enabled())

    def test_on(self):
        cfg = {"routing": {"doh": {"enabled": True}}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager(cfg)):
            self.assertTrue(doh_resolver.is_enabled())


class TestResolveDisabled(unittest.TestCase):
    """resolve() при выключенном DoH сразу возвращает ok=False."""

    def test_returns_disabled(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            r = doh_resolver.resolve("example.com")
            self.assertFalse(r["ok"])
            self.assertIn("DoH", r["error"])


class FakeHTTPResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class TestQueryJSON(unittest.TestCase):
    """_query_json парсит RFC 8484 JSON-ответ."""

    def _fake_urlopen(self, body):
        return mock.patch("urllib.request.urlopen",
                          return_value=FakeHTTPResponse(body))

    def test_parses_a_records(self):
        body = json.dumps({
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 1, "data": "1.2.3.4"},
                {"name": "example.com", "type": 1, "data": "5.6.7.8"},
                {"name": "example.com", "type": 5, "data": "cname.example"},
            ],
        }).encode()
        with self._fake_urlopen(body):
            ips = doh_resolver._query_json(
                "https://x/dns-query", "example.com", "A", 5)
        self.assertEqual(ips, ["1.2.3.4", "5.6.7.8"])

    def test_parses_aaaa(self):
        body = json.dumps({
            "Answer": [{"type": 28, "data": "2001:db8::1"}],
        }).encode()
        with self._fake_urlopen(body):
            ips = doh_resolver._query_json(
                "https://x/dns-query", "example.com", "AAAA", 5)
        self.assertEqual(ips, ["2001:db8::1"])

    def test_empty_answer(self):
        body = json.dumps({"Status": 3, "Answer": []}).encode()
        with self._fake_urlopen(body):
            self.assertEqual(
                doh_resolver._query_json("https://x", "h.com", "A", 5), [])

    def test_garbage_body(self):
        with self._fake_urlopen(b"not json"):
            self.assertEqual(
                doh_resolver._query_json("https://x", "h.com", "A", 5), [])


class TestKnownProviders(unittest.TestCase):

    def test_includes_main_providers(self):
        for p in ("cloudflare", "google", "quad9"):
            self.assertIn(p, doh_resolver.KNOWN_PROVIDERS)


if __name__ == "__main__":
    unittest.main()
