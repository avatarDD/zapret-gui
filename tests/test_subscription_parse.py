# tests/test_subscription_parse.py
"""
Тесты разбора подписок (core/subscription_manager._parse_payload):
формат singbox-json и чистка сырых outbound'ов — vless-flow
'…-vision-udp443' нормализуется, неподдерживаемый flow отбрасывается
(один такой outbound валит весь sing-box и каждый батч тестера:
«FATAL create service: initialize outbound[N]: unsupported flow»).
"""

import json
import unittest

from core import subscription_manager as sm


def _vless(tag, flow=None):
    ob = {"type": "vless", "tag": tag, "server": "s.example",
          "server_port": 443, "uuid": "u-1"}
    if flow is not None:
        ob["flow"] = flow
    return ob


class TestParseSingboxJson(unittest.TestCase):

    def test_whole_config_and_bare_list(self):
        obs = [_vless("a"), {"type": "direct", "tag": "d"}]
        whole = json.dumps({"outbounds": obs, "log": {}})
        bare = json.dumps(obs)
        for payload in (whole, bare):
            parsed = sm._parse_singbox_json(payload)
            self.assertEqual([o["tag"] for o in parsed], ["a", "d"])

    def test_udp443_flow_normalized(self):
        payload = json.dumps(
            {"outbounds": [_vless("v", "xtls-rprx-vision-udp443")]})
        parsed = sm._parse_singbox_json(payload)
        self.assertEqual(parsed[0]["flow"], "xtls-rprx-vision")

    def test_unsupported_flow_dropped(self):
        payload = json.dumps({"outbounds": [
            _vless("ok", "xtls-rprx-vision"),
            _vless("legacy", "xtls-rprx-direct"),
            _vless("plain"),
        ]})
        parsed = sm._parse_singbox_json(payload)
        self.assertEqual([o["tag"] for o in parsed], ["ok", "plain"])

    def test_garbage(self):
        self.assertEqual(sm._parse_singbox_json("not json"), [])
        self.assertEqual(sm._parse_singbox_json("[1, 2]"), [])
        self.assertEqual(sm._parse_singbox_json('{"outbounds": 5}'), [])

    def test_payload_auto_detects_singbox_json(self):
        payload = json.dumps(
            {"outbounds": [_vless("v", "xtls-rprx-vision-udp443")]})
        outbounds, fmt = sm._parse_payload(payload, "auto")
        self.assertEqual(fmt, "singbox-json")
        self.assertEqual(outbounds[0]["flow"], "xtls-rprx-vision")


if __name__ == "__main__":
    unittest.main()
