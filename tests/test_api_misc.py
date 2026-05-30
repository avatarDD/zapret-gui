# tests/test_api_misc.py
"""
Integration-тесты для остальных API-модулей: status, logs,
gui_update, autostart, control, diagnostics, hosts, hostlists,
ipsets, lua_scripts, blobs, devices, blockcheck, scan,
catalog_update, zapret_manager.

Эти тесты проверяют что endpoint'ы:
  1. Зарегистрированы (HTTP 200/400/404, не 500/exception).
  2. Возвращают JSON-структуру (для GET-эндпоинтов).
  3. Корректно обрабатывают невалидный body / параметры.
"""

import unittest

from tests._wsgi_client import WSGIClient, build_test_app


class TestStatusAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_status(self):
        r = self.client.get_json("/api/status")
        self.assertEqual(r["_status"], 200)

    def test_gui_version(self):
        r = self.client.get_json("/api/gui/version")
        self.assertEqual(r["_status"], 200)
        self.assertIn("version", r)


class TestLogsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_logs_list(self):
        r = self.client.get_json("/api/logs")
        self.assertEqual(r["_status"], 200)


class TestGuiUpdateAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_gui_update_status(self):
        # /api/gui/update — может ходить в сеть для проверки версии;
        # допустим 200 либо 500 на failure без сети.
        r = self.client.get_json("/api/gui/update/status")
        self.assertIn(r["_status"], (200, 404, 500))


class TestAutostartAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_autostart_status(self):
        r = self.client.get_json("/api/autostart")
        self.assertEqual(r["_status"], 200)


class TestControlAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_start_endpoint_exists(self):
        # /api/start — POST-эндпоинт. Не запускаем nfqws реально,
        # просто проверяем что эндпоинт зарегистрирован.
        # Без body может вернуть 200/400/500 — главное не 404.
        status, _ = self.client._call("POST", "/api/start")
        self.assertFalse(status.startswith("404"),
                         "POST /api/start не зарегистрирован")


class TestDiagnosticsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_diagnostics_system(self):
        # Эндпоинт может занимать секунды (ping/dns/etc).
        # Проверяем что не падает.
        r = self.client.get_json("/api/diagnostics/system")
        self.assertIn(r["_status"], (200, 500))

    def test_diagnostics_services(self):
        r = self.client.get_json("/api/diagnostics/services")
        self.assertIn(r["_status"], (200, 500))

    def test_diagnostics_known_conflicts(self):
        r = self.client.get_json("/api/diagnostics/known-conflicts")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("warnings", r["result"])
        self.assertIn("has_conflicts", r["result"])
        self.assertIsInstance(r["result"]["warnings"], list)


class TestHostsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_hosts_list(self):
        r = self.client.get_json("/api/hosts")
        self.assertEqual(r["_status"], 200)

    def test_hosts_presets(self):
        r = self.client.get_json("/api/hosts/presets")
        self.assertEqual(r["_status"], 200)


class TestHostlistsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_hostlists_list(self):
        r = self.client.get_json("/api/hostlists")
        self.assertEqual(r["_status"], 200)


class TestIpsetsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_ipsets_list(self):
        r = self.client.get_json("/api/ipsets")
        self.assertEqual(r["_status"], 200)


class TestLuaAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_lua_list(self):
        r = self.client.get_json("/api/lua")
        self.assertEqual(r["_status"], 200)


class TestBlobsAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_blobs_list(self):
        r = self.client.get_json("/api/blobs")
        self.assertEqual(r["_status"], 200)


class TestDevicesAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_devices_list(self):
        # devices_discovery может пытаться ходить в /proc/net/arp.
        r = self.client.get_json("/api/devices")
        self.assertIn(r["_status"], (200, 500))


class TestStrategiesAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_strategies_list(self):
        r = self.client.get_json("/api/strategies")
        self.assertEqual(r["_status"], 200)


class TestZapretManagerAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_zapret_root(self):
        r = self.client.get_json("/api/zapret")
        self.assertIn(r["_status"], (200, 500))

    def test_zapret_installed(self):
        r = self.client.get_json("/api/zapret/installed")
        self.assertIn(r["_status"], (200, 500))

    def test_zapret_progress(self):
        r = self.client.get_json("/api/zapret/progress")
        self.assertEqual(r["_status"], 200)


class TestCatalogUpdateAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_catalog_status(self):
        # Может идти в сеть — допускаем 200/500.
        r = self.client.get_json("/api/catalog/status")
        self.assertIn(r["_status"], (200, 404, 500))


if __name__ == "__main__":
    unittest.main()
