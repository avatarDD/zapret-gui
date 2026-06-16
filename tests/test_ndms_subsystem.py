# tests/test_ndms_subsystem.py
"""
Unit-тесты для core/ndms/rci_client.py, ping_check.py, wg_discovery.py.
Тесты не делают сетевых запросов: мокаем urlopen / is_ndms_available.
"""

import json
import unittest
import urllib.error
from unittest import mock

from core.ndms import rci_client, ping_check, wg_discovery


# ─────── rci_client ───────

class TestScanErrorInStatus(unittest.TestCase):
    """Парсер ответов NDMS на наличие status='error'."""

    def test_no_error_in_ok(self):
        data = [{"status": [{"status": "ok", "message": "done"}]}]
        self.assertEqual(rci_client._scan_error_in_status(data), "")

    def test_error_caught(self):
        data = [{"status": [{"status": "error",
                              "message": "interface not found"}]}]
        err = rci_client._scan_error_in_status(data)
        self.assertIn("interface", err)

    def test_critical_treated_as_error(self):
        data = {"status": "critical", "message": "boom"}
        self.assertEqual(rci_client._scan_error_in_status(data), "boom")

    def test_nested_dict(self):
        data = {"outer": {"inner": {"status": "error", "message": "nested"}}}
        self.assertEqual(rci_client._scan_error_in_status(data), "nested")

    def test_garbage_safe(self):
        # Не падает на нелепом вводе
        self.assertEqual(rci_client._scan_error_in_status(None), "")
        self.assertEqual(rci_client._scan_error_in_status(42), "")
        self.assertEqual(rci_client._scan_error_in_status("string"), "")


class TestClientRequestErrors(unittest.TestCase):
    """Поведение HTTP-клиента при недоступном RCI.

    urlopen мокаем (URLError) — иначе на реальном Keenetic, где RCI слушает
    на :79, эти тесты ловили бы живой ответ и падали (см. самодиагностику на
    роутере). Тесты обязаны быть герметичными — без зависимости от того, что
    на localhost:79 ничего не отвечает.
    """

    def setUp(self):
        self.client = rci_client.NdmsRciClient()
        self._refused = mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"))
        self._refused.start()
        self.addCleanup(self._refused.stop)

    def test_connection_refused(self):
        ok, data, err = self.client._request("GET", path="show/version",
                                              timeout=1)
        self.assertFalse(ok)
        self.assertIsNone(data)
        self.assertIn("URLError", err)

    def test_post_returns_failure(self):
        r = self.client.post({"hello": "world"}, timeout=1)
        self.assertFalse(r["ok"])
        self.assertIn("error", r)

    def test_is_available_false_when_no_server(self):
        # RCI недоступен (urlopen → URLError) — False.
        c = rci_client.NdmsRciClient()
        self.assertFalse(c.is_available())

    def test_is_available_cached(self):
        c = rci_client.NdmsRciClient()
        c._available = True
        c._version_cache = "5.0.3"
        # Без force берёт кэш.
        self.assertTrue(c.is_available())
        self.assertEqual(c.version(), "5.0.3")


class TestRciClientGetPost(unittest.TestCase):
    """GET/POST с мокированным urlopen."""

    def test_get_returns_parsed_json(self):
        class _Resp:
            def __init__(self, body): self.body = body
            def read(self): return self.body
            def __enter__(self): return self
            def __exit__(self, *a): pass

        body = b'{"title": "5.0.3"}'
        with mock.patch("urllib.request.urlopen",
                        return_value=_Resp(body)):
            data = self.client_get("show/version")
        self.assertEqual(data, {"title": "5.0.3"})

    def client_get(self, path):
        c = rci_client.NdmsRciClient()
        return c.get(path)


# ─────── ping_check ───────

class TestPingCheckHelpers(unittest.TestCase):

    def test_safe_int(self):
        self.assertEqual(ping_check._safe_int(None), 0)
        self.assertEqual(ping_check._safe_int(""), 0)
        self.assertEqual(ping_check._safe_int("42"), 42)
        self.assertEqual(ping_check._safe_int(42), 42)
        self.assertEqual(ping_check._safe_int("garbage"), 0)

    def test_dig_first_path_wins(self):
        d = {"a": {"b": "found"}}
        self.assertEqual(ping_check._dig(d, ("a", "b"), ("c",)), "found")

    def test_dig_skip_empty(self):
        d = {"a": "", "b": "value"}
        # Первый путь — пустая строка, второй — нет.
        self.assertEqual(ping_check._dig(d, ("a",), ("b",)), "value")

    def test_dig_none_if_nothing(self):
        self.assertIsNone(ping_check._dig({}, ("a",), ("b",)))

    def test_extract_endpoint_string(self):
        self.assertEqual(
            ping_check._extract_endpoint({"endpoint": "1.2.3.4:51820"}),
            "1.2.3.4:51820")

    def test_extract_endpoint_dict(self):
        self.assertEqual(
            ping_check._extract_endpoint(
                {"endpoint": {"address": "h", "port": 1234}}),
            "h:1234")

    def test_extract_endpoint_empty(self):
        self.assertEqual(ping_check._extract_endpoint({}), "")
        self.assertEqual(ping_check._extract_endpoint(None), "")


class TestNativeWgStatus(unittest.TestCase):

    def test_unavailable_when_no_ndms(self):
        with mock.patch("core.ndms.is_ndms_available", return_value=False):
            r = ping_check.get_native_wg_status("Wireguard0")
            self.assertFalse(r["available"])
            self.assertEqual(r["name"], "Wireguard0")

    def test_empty_name_returns_unavailable(self):
        r = ping_check.get_native_wg_status("")
        self.assertFalse(r["available"])

    def test_parses_status(self):
        info = {
            "state":          "up",
            "last-handshake": 1700000000,
            "rxbytes":        1024,
            "txbytes":        2048,
            "endpoint":       "1.2.3.4:51820",
        }
        with mock.patch("core.ndms.is_ndms_available", return_value=True):
            with mock.patch(
                    "core.ndms.get_ndms_commands") as m_cmd:
                m_cmd.return_value.show_interface.return_value = info
                r = ping_check.get_native_wg_status("Wireguard0")
        self.assertTrue(r["available"])
        self.assertTrue(r["active"])
        self.assertEqual(r["state"], "up")
        self.assertEqual(r["last_handshake"], 1700000000)
        self.assertEqual(r["rx_bytes"], 1024)
        self.assertEqual(r["tx_bytes"], 2048)


class TestShouldDelegateMonitoring(unittest.TestCase):

    def test_false_when_no_ndms(self):
        with mock.patch("core.ndms.wg_discovery.is_native_wg",
                        return_value=False):
            self.assertFalse(ping_check.should_delegate_monitoring("awg0"))

    def test_true_for_native(self):
        with mock.patch("core.ndms.wg_discovery.is_native_wg",
                        return_value=True):
            self.assertTrue(
                ping_check.should_delegate_monitoring("Wireguard0"))


# ─────── wg_discovery ───────

class TestWgDiscovery(unittest.TestCase):

    def setUp(self):
        wg_discovery.invalidate_cache()

    def test_empty_on_non_keenetic(self):
        with mock.patch("core.ndms.is_ndms_available", return_value=False):
            self.assertEqual(wg_discovery.list_native_wg_interfaces(), [])

    def test_returns_data_when_ndms(self):
        fake = [{"name": "Wireguard0", "state": "up",
                  "description": "MyVPN", "address": "10.0.0.2/24"}]
        with mock.patch("core.ndms.is_ndms_available", return_value=True):
            with mock.patch("core.ndms.get_ndms_commands") as m:
                m.return_value.list_wireguard_interfaces.return_value = fake
                ifs = wg_discovery.list_native_wg_interfaces(force=True)
        self.assertEqual(len(ifs), 1)
        self.assertEqual(ifs[0]["name"], "Wireguard0")

    def test_is_native_wg_false(self):
        with mock.patch("core.ndms.is_ndms_available", return_value=False):
            self.assertFalse(wg_discovery.is_native_wg("Wireguard0"))
            self.assertFalse(wg_discovery.is_native_wg(""))


if __name__ == "__main__":
    unittest.main()
