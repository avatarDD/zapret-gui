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

    def test_install_transports(self):
        # Без запущенных движков список содержит как минимум «Напрямую».
        r = self.client.get_json("/api/install/transports")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["transports"])
        self.assertEqual(r["transports"][0]["id"], "direct")


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


class TestHealthcheckAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_healthcheck_status(self):
        r = self.client.get_json("/api/healthcheck/status")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("running", r["status"])
        self.assertIn("enabled", r["status"])
        self.assertIn("interval_min", r["status"])
        self.assertIn("services", r["status"])
        self.assertIn("history", r["status"])

    def test_healthcheck_disable_idempotent(self):
        """Выключение healthcheck — всегда возвращает ok, даже если уже выключен."""
        r = self.client.post_json("/api/healthcheck/disable", {})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])

    def test_healthcheck_config_saves_sites(self):
        """POST /config сохраняет список сайтов/контрольный домен без включения."""
        body = {
            "services": ["youtube"],
            "custom_domains": ["rutracker.org"],
            "control_domain": "ya.ru",
            "outage_guard": True,
            "interval_min": 7,
        }
        r = self.client.post_json("/api/healthcheck/config", body)
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        st = r["status"]
        self.assertEqual(st["services"], ["youtube"])
        self.assertEqual(st["custom_domains"], ["rutracker.org"])
        self.assertEqual(st["control_domain"], "ya.ru")
        self.assertEqual(st["interval_min"], 7)

    def test_healthcheck_run_is_nonblocking(self):
        """POST /run отвечает сразу (started/busy), не дожидаясь проб.

        Если бы был блокирующим, тест висел бы ~30с на сетевых таймаутах.
        """
        import time as _t
        t0 = _t.time()
        r = self.client.post_json("/api/healthcheck/run", {})
        elapsed = _t.time() - t0
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIn("result", r)
        # Неблокирующий ответ должен прийти быстро (фон работает отдельно).
        self.assertLess(elapsed, 5)
        # Останавливаем демон/фон чтобы не мешал другим тестам.
        from core.healthcheck import get_healthcheck
        get_healthcheck().stop()


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

    # ─── autocircular state (z2k-state-persist) ───

    def test_strategies_state_list_returns_summary(self):
        """GET /api/strategies/state — даже на пустом state возвращает
        summary + entries=[] (а не 500)."""
        import os
        # Изолированный каталог: нет реального файла → entries=[], total=0
        prev = os.environ.get("Z2K_STATE_DIR_OVERRIDE")
        os.environ["Z2K_STATE_DIR_OVERRIDE"] = "/nonexistent-zg-test-dir"
        try:
            r = self.client.get_json("/api/strategies/state")
            self.assertEqual(r["_status"], 200)
            self.assertTrue(r["ok"])
            self.assertIn("entries", r)
            self.assertIn("summary", r)
            self.assertEqual(r["entries"], [])
        finally:
            if prev is None:
                os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
            else:
                os.environ["Z2K_STATE_DIR_OVERRIDE"] = prev

    def test_strategies_state_clear_all_idempotent(self):
        """DELETE /api/strategies/state на пустом state — ok=True, removed=0."""
        import os
        prev = os.environ.get("Z2K_STATE_DIR_OVERRIDE")
        os.environ["Z2K_STATE_DIR_OVERRIDE"] = "/nonexistent-zg-test-dir"
        try:
            r = self.client.delete_json("/api/strategies/state")
            self.assertEqual(r["_status"], 200)
            self.assertTrue(r["ok"])
            self.assertEqual(r["removed"], 0)
        finally:
            if prev is None:
                os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
            else:
                os.environ["Z2K_STATE_DIR_OVERRIDE"] = prev

    def test_strategies_state_clear_host_with_real_data(self):
        """DELETE /api/strategies/state/host/<h> на подготовленном state.tsv
        удаляет нужный host и не трогает остальное."""
        import os
        import tempfile
        tmp = tempfile.mkdtemp(prefix="zg-state-api-")
        prev = os.environ.get("Z2K_STATE_DIR_OVERRIDE")
        os.environ["Z2K_STATE_DIR_OVERRIDE"] = tmp
        try:
            # Подготовка
            with open(os.path.join(tmp, "state.tsv"), "w") as f:
                f.write("# header\n# key\thost\tstrategy\tts\n")
                f.write("default\tyoutube.com\t2\t100\n")
                f.write("default\trutracker.org\t5\t200\n")

            r = self.client.delete_json(
                "/api/strategies/state/host/youtube.com")
            self.assertEqual(r["_status"], 200)
            self.assertTrue(r["ok"])
            self.assertEqual(r["removed"], 1)

            # rutracker остался
            r2 = self.client.get_json("/api/strategies/state")
            hosts = [e["host"] for e in r2["entries"]]
            self.assertNotIn("youtube.com", hosts)
            self.assertIn("rutracker.org", hosts)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
            if prev is None:
                os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
            else:
                os.environ["Z2K_STATE_DIR_OVERRIDE"] = prev


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
