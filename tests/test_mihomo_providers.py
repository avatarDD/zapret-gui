# tests/test_mihomo_providers.py
"""
mihomo: подписки через `proxy-providers` (GitHub issue #248).

Симптом из issue: «Не видит подписку, файл сохраняет». Конфиг при этом
корректный — узлы такой подписки в него не попадают ВООБЩЕ: их скачивает
сам mihomo по url в рантайме. Таблица прокси читала только статическую
секцию `proxies:` и оставалась пустой, из-за чего подписка выглядела
нерабочей.
"""

import unittest
from unittest import mock

from core.clash_yaml import parse_yaml
from core import mihomo_proxies as mp
from core.mihomo_manager import validate_yaml


# Конфиг из issue #248 (url обезличен).
ISSUE_248_YAML = """
mixed-port: 7890
proxy-providers:
  Blanc:
    type: http
    url: "https://example-vpn.invalid/s/SECRET-TOKEN"
    path: ./proxy-providers/Blanc.yaml
    interval: 1800
    header:
      User-Agent:
      - "FlClash"
      x-hwid:
      - "OpenWrt"
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 120
proxy-groups:
  - name: PROXY
    type: select
    use:
      - Blanc
rules:
  - MATCH,PROXY
"""


class TestProviderConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = parse_yaml(ISSUE_248_YAML)

    def test_config_is_valid(self):
        # Конфиг корректный — проблема была не в нём.
        self.assertEqual(validate_yaml(ISSUE_248_YAML), [])

    def test_static_proxies_are_empty(self):
        # Это и есть причина «пустой таблицы»: узлов в конфиге нет.
        self.assertEqual(mp.proxy_rows(self.cfg), [])

    def test_provider_is_detected(self):
        rows = mp.provider_rows(self.cfg)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Blanc")
        self.assertEqual(rows[0]["type"], "http")
        self.assertEqual(rows[0]["interval"], 1800)

    def test_subscription_url_is_not_leaked(self):
        # В url подписки лежит токен доступа — наружу отдаём только хост.
        blob = str(mp.provider_rows(self.cfg))
        self.assertNotIn("SECRET-TOKEN", blob)
        self.assertIn("example-vpn.invalid", blob)

    def test_no_providers_section_is_empty_list(self):
        self.assertEqual(mp.provider_rows({"proxies": []}), [])
        self.assertEqual(mp.provider_rows({}), [])
        self.assertEqual(mp.provider_rows(None), [])

    def test_malformed_providers_do_not_crash(self):
        self.assertEqual(mp.provider_rows({"proxy-providers": "мусор"}), [])
        rows = mp.provider_rows({"proxy-providers": {"a": None, "b": {}}})
        self.assertEqual([r["name"] for r in rows], ["b"])


class TestControllerProviderProxies(unittest.TestCase):
    """Узлы подписки берутся у запущенного движка через Clash API."""

    EP = {"host": "127.0.0.1", "port": 9090, "secret": ""}

    def test_parses_providers_response(self):
        body = ('{"providers": {"Blanc": {"vehicleType": "HTTP",'
                ' "updatedAt": "2026-07-25T10:00:00Z",'
                ' "proxies": [{"name": "NL-1", "type": "Vless"},'
                '             {"name": "DE-2", "type": "Vless"}]}}}')
        with mock.patch.object(mp, "_request", return_value=(200, body)):
            r = mp.controller_provider_proxies(self.EP)
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(r["providers"]), 1)
        prov = r["providers"][0]
        self.assertEqual(prov["name"], "Blanc")
        self.assertEqual(prov["count"], 2)
        self.assertEqual([p["name"] for p in prov["proxies"]], ["NL-1", "DE-2"])

    def test_controller_unavailable(self):
        with mock.patch.object(mp, "_request", return_value=(0, "")):
            r = mp.controller_provider_proxies(self.EP)
        self.assertFalse(r["ok"])

    def test_bad_json(self):
        with mock.patch.object(mp, "_request", return_value=(200, "не json")):
            r = mp.controller_provider_proxies(self.EP)
        self.assertFalse(r["ok"])

    def test_response_without_providers_key(self):
        with mock.patch.object(mp, "_request", return_value=(200, '{"x": 1}')):
            r = mp.controller_provider_proxies(self.EP)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
