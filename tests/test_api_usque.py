# tests/test_api_usque.py
"""
Integration-тесты для API usque (/api/usque/*).

Ключевое: до появления /api/usque/settings настройки usque.enabled /
usque.autostart / usque.watchdog.* нельзя было выставить из GUI вообще,
хотя автоподъём после перезагрузки (_apply_usque_autostart_on_boot) и
сторожевой перезапуск зависят именно от них.
"""

import shutil
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
from tests._wsgi_client import WSGIClient, build_test_app


class _IsolatedConfig(unittest.TestCase):
    """Подменяет глобальный ConfigManager на временный каталог.

    Без этого POST /api/usque/settings пишет в НАСТОЯЩИЙ
    /opt/etc/zapret-gui/settings.json — прогон тестов менял бы рабочие
    настройки разработчика (а на роутере — боевые).
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="usque-api-test-")
        cls._saved_cm = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=cls._tmp)
        cm_mod._config_manager.load()
        cls.client = WSGIClient(build_test_app())

    @classmethod
    def tearDownClass(cls):
        cm_mod._config_manager = cls._saved_cm
        shutil.rmtree(cls._tmp, ignore_errors=True)


class TestUsqueSettings(_IsolatedConfig):
    pass

    def _get(self):
        r = self.client.get_json("/api/usque/settings")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        return r["settings"]

    def test_get_defaults(self):
        s = self._get()
        for key in ("enabled", "autostart", "default_sni",
                    "transport_profile", "http2_enable", "watchdog"):
            self.assertIn(key, s)
        for key in ("enabled", "interval_sec", "probe_host", "probe_port"):
            self.assertIn(key, s["watchdog"])

    def test_set_autostart_and_enabled_roundtrip(self):
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            r = self.client.post_json("/api/usque/settings",
                                      {"enabled": True, "autostart": True})
        self.assertTrue(r["ok"], r)
        self.assertIs(r["settings"]["enabled"], True)
        self.assertIs(r["settings"]["autostart"], True)
        # Значение переживает повторное чтение (реально сохранено).
        self.assertIs(self._get()["autostart"], True)

        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            self.client.post_json("/api/usque/settings",
                                  {"enabled": False, "autostart": False})

    def test_transport_profile_validated(self):
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            bad = self.client.post_json("/api/usque/settings",
                                        {"transport_profile": "turbo"})
        self.assertFalse(bad["ok"])
        self.assertIn("transport_profile", bad["error"])

        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            good = self.client.post_json("/api/usque/settings",
                                         {"transport_profile": "restricted"})
        self.assertTrue(good["ok"], good)
        self.assertEqual(good["settings"]["transport_profile"], "restricted")

    def test_sni_validated_and_empty_allowed(self):
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            bad = self.client.post_json("/api/usque/settings",
                                        {"default_sni": "не домен!"})
        self.assertFalse(bad["ok"])

        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            ok = self.client.post_json("/api/usque/settings",
                                       {"default_sni": "ozon.ru"})
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(ok["settings"]["default_sni"], "ozon.ru")

        # Пустая строка = «не маскировать», должна приниматься.
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            empty = self.client.post_json("/api/usque/settings",
                                          {"default_sni": ""})
        self.assertTrue(empty["ok"], empty)
        self.assertEqual(empty["settings"]["default_sni"], "")

    def test_watchdog_bounds(self):
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            r = self.client.post_json(
                "/api/usque/settings",
                {"watchdog": {"enabled": True, "interval_sec": 1,
                              "probe_port": 443}})
        self.assertTrue(r["ok"], r)
        # Слишком частый опрос ужимается до разумного минимума.
        self.assertGreaterEqual(r["settings"]["watchdog"]["interval_sec"], 10)

        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            bad = self.client.post_json("/api/usque/settings",
                                        {"watchdog": {"probe_port": 99999}})
        self.assertFalse(bad["ok"])

        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            self.client.post_json("/api/usque/settings",
                                  {"watchdog": {"enabled": False}})

    def test_settings_change_reconfigures_watchdog(self):
        # Без reconfigure() новый режим применился бы только после
        # перезапуска GUI.
        with mock.patch("core.usque_watchdog.get_usque_watchdog") as gw:
            self.client.post_json("/api/usque/settings", {"enabled": True})
            gw.return_value.reconfigure.assert_called_once()
        with mock.patch("core.usque_watchdog.get_usque_watchdog"):
            self.client.post_json("/api/usque/settings", {"enabled": False})


class TestUsqueConfigsApi(_IsolatedConfig):

    def test_configs_list_shape(self):
        r = self.client.get_json("/api/usque/configs")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["configs"], list)

    def test_unknown_config_actions_report_error(self):
        for path in ("up", "down", "status", "remove"):
            r = self.client.post_json(
                "/api/usque/configs/nosuch/%s" % path, {}) \
                if path != "status" else \
                self.client.get_json("/api/usque/configs/nosuch/status")
            self.assertFalse(r.get("ok"), path)
            self.assertIn("не найден", r.get("error", ""))

    def test_register_rejects_path_traversal(self):
        r = self.client.post_json("/api/usque/register",
                                  {"name": "../../etc/init.d/S99evil"})
        self.assertFalse(r["ok"])

    def test_environment_shape(self):
        r = self.client.get_json("/api/usque/environment")
        self.assertEqual(r["_status"], 200)
        # SetupUI ждёт binary объектом, основная страница — плоские поля.
        self.assertIsInstance(r["binary"], dict)
        self.assertIn("installed", r["binary"])
        self.assertIn("ready", r)


if __name__ == "__main__":
    unittest.main()
