# tests/test_ndms_commands.py
"""
Unit-тесты для core/ndms/commands.py — pure-функции и помощники,
работающие без сети. RCI-операции с реальным HTTP в этом
файле не тестируются.
"""

import unittest

from core.ndms.commands import (
    make_owned_name, is_owned_name, _normalize_mac, _is_wg_iface_name,
    _is_not_found_error, _extract_iface_address, _extract_dns_proxy_routes,
)


class TestMakeOwnedName(unittest.TestCase):

    def test_basic(self):
        name = make_owned_name("domain-abc123")
        self.assertTrue(name.startswith("ZGUI_"))
        self.assertIn("abc123", name)

    def test_unsafe_chars_replaced(self):
        name = make_owned_name("rule/with*bad?chars")
        self.assertFalse(any(c in name for c in "/*?"))

    def test_length_capped(self):
        name = make_owned_name("x" * 200)
        self.assertLessEqual(len(name), 62)

    def test_empty_input(self):
        name = make_owned_name("")
        # Должен дать sensible default — не падать.
        self.assertTrue(name.startswith("ZGUI_"))


class TestIsOwnedName(unittest.TestCase):

    def test_matches_prefix(self):
        self.assertTrue(is_owned_name("ZGUI_foo"))
        self.assertTrue(is_owned_name("ZGUI_rule-123"))

    def test_no_match(self):
        self.assertFalse(is_owned_name("foo"))
        self.assertFalse(is_owned_name("zgui_foo"))  # case-sensitive
        self.assertFalse(is_owned_name(""))


class TestNormalizeMac(unittest.TestCase):

    def test_colon_form_uppercased(self):
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff"),
                         "AA:BB:CC:DD:EE:FF")

    def test_dash_form_converted(self):
        self.assertEqual(_normalize_mac("aa-bb-cc-dd-ee-ff"),
                         "AA:BB:CC:DD:EE:FF")

    def test_already_canonical(self):
        self.assertEqual(_normalize_mac("AA:BB:CC:DD:EE:FF"),
                         "AA:BB:CC:DD:EE:FF")

    def test_invalid_input(self):
        self.assertEqual(_normalize_mac(""), "")
        self.assertEqual(_normalize_mac("notamac"), "")
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee"), "")  # too short
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff:gg"), "")  # too long
        self.assertEqual(_normalize_mac("zz:bb:cc:dd:ee:ff"), "")  # invalid hex


class TestIsWgIfaceName(unittest.TestCase):

    def test_keenetic_native(self):
        self.assertTrue(_is_wg_iface_name("Wireguard0"))
        self.assertTrue(_is_wg_iface_name("Wireguard12"))
        self.assertTrue(_is_wg_iface_name("wireguard0"))  # case-insensitive

    def test_userspace_awg(self):
        self.assertFalse(_is_wg_iface_name("awg0"))
        self.assertFalse(_is_wg_iface_name("wg0"))
        self.assertFalse(_is_wg_iface_name("opkgtun0"))

    def test_garbage(self):
        self.assertFalse(_is_wg_iface_name(""))
        self.assertFalse(_is_wg_iface_name("Wireguard"))   # без цифры
        self.assertFalse(_is_wg_iface_name("WireguardX"))  # буква вместо цифры


class TestIsNotFoundError(unittest.TestCase):

    def test_matches_common_phrases(self):
        self.assertTrue(_is_not_found_error("Not Found"))
        self.assertTrue(_is_not_found_error("no such object"))
        self.assertTrue(_is_not_found_error("Object doesn't exist"))

    def test_no_match_other_errors(self):
        self.assertFalse(_is_not_found_error("HTTP 404"))
        self.assertFalse(_is_not_found_error("unknown command"))
        self.assertFalse(_is_not_found_error("Permission denied"))
        self.assertFalse(_is_not_found_error("Internal error"))
        self.assertFalse(_is_not_found_error(""))


class TestExtractIfaceAddress(unittest.TestCase):

    def test_string_address(self):
        self.assertEqual(_extract_iface_address(
            {"address": "10.0.0.2/24"}), "10.0.0.2/24")

    def test_dict_address_with_mask(self):
        self.assertEqual(_extract_iface_address({
            "address": {"address": "10.0.0.2", "mask": "255.255.255.0"},
        }), "10.0.0.2/255.255.255.0")

    def test_ipv4_block(self):
        self.assertEqual(_extract_iface_address({
            "ipv4": {
                "address": [
                    {"address": "10.0.0.2", "prefix-length": 24},
                ],
            },
        }), "10.0.0.2/24")

    def test_missing(self):
        self.assertEqual(_extract_iface_address({}), "")


class TestExtractDnsProxyRoutes(unittest.TestCase):

    def test_list_format(self):
        cfg = {
            "dns-proxy": {
                "route": [
                    {"group": "g1", "interface": "Wireguard0"},
                    {"group": "g2", "interface": "Wireguard1"},
                ]
            }
        }
        routes = _extract_dns_proxy_routes(cfg)
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0]["group"], "g1")

    def test_single_object(self):
        cfg = {"dns-proxy": {"route": {"group": "g1", "interface": "Wg0"}}}
        routes = _extract_dns_proxy_routes(cfg)
        self.assertEqual(len(routes), 1)

    def test_missing_section(self):
        self.assertEqual(_extract_dns_proxy_routes({}), [])
        self.assertEqual(_extract_dns_proxy_routes({"dns-proxy": None}), [])


if __name__ == "__main__":
    unittest.main()


class _FakeClient:
    """Мини-RCI-клиент: отдаёт заранее заданный ответ на get()."""
    def __init__(self, get_result=None, post_result=None):
        self._get = get_result or {"ok": True, "data": {}}
        self._post = post_result or {"ok": True, "data": {}}
        self.posts = []

    def get(self, path, timeout=0):
        return self._get

    def post(self, payload, timeout=0):
        self.posts.append(payload)
        return self._post


class TestGetHostPolicy(unittest.TestCase):

    def _cmd(self, get_result):
        from core.ndms.commands import NdmsCommands
        return NdmsCommands(client=_FakeClient(get_result=get_result))

    def test_found_with_policy(self):
        data = {"data": {"host": [
            {"mac": "aa:bb:cc:dd:ee:ff", "policy": "ParentalControl"},
            {"mac": "11:22:33:44:55:66", "policy": "Other"},
        ]}, "ok": True}
        cmd = self._cmd(data)
        r = cmd.get_host_policy("aa:bb:cc:dd:ee:ff")
        self.assertTrue(r["ok"])
        self.assertTrue(r["found"])
        self.assertEqual(r["policy"], "ParentalControl")

    def test_found_no_policy(self):
        data = {"ok": True, "data": {"host": [
            {"mac": "aa:bb:cc:dd:ee:ff"},
        ]}}
        cmd = self._cmd(data)
        r = cmd.get_host_policy("aa:bb:cc:dd:ee:ff")
        self.assertTrue(r["found"])
        self.assertEqual(r["policy"], "")

    def test_not_found(self):
        data = {"ok": True, "data": {"host": []}}
        cmd = self._cmd(data)
        r = cmd.get_host_policy("aa:bb:cc:dd:ee:ff")
        self.assertFalse(r["found"])

    def test_single_host_dict(self):
        # NDMS может вернуть один хост как объект, а не список.
        data = {"ok": True, "data": {"host":
                {"mac": "aa:bb:cc:dd:ee:ff", "policy": "P1"}}}
        cmd = self._cmd(data)
        r = cmd.get_host_policy("AA:BB:CC:DD:EE:FF")
        self.assertEqual(r["policy"], "P1")

    def test_bad_mac(self):
        cmd = self._cmd({"ok": True, "data": {}})
        self.assertFalse(cmd.get_host_policy("nope")["ok"])
