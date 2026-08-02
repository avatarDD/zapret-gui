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



class TestUsqueDebugMode(_IsolatedConfig):
    """Режим отладки: тумблер + чтение лога."""

    def test_debug_toggle_roundtrip(self):
        off = self.client.get_json("/api/usque/debug")
        self.assertTrue(off["ok"])
        self.assertIs(off["enabled"], False)

        on = self.client.post_json("/api/usque/debug", {"enabled": True})
        self.assertIs(on["enabled"], True)
        self.assertIs(self.client.get_json("/api/usque/debug")["enabled"], True)

        self.client.post_json("/api/usque/debug", {"enabled": False})

    def test_debug_changes_buffer_depth(self):
        from core.usque_manager import get_usque_manager, _MAX_DIAGNOSTIC_LINES, _MAX_DEBUG_LINES
        mgr = get_usque_manager()
        self.client.post_json("/api/usque/debug", {"enabled": False})
        self.assertEqual(mgr._buf_size(), _MAX_DIAGNOSTIC_LINES)
        self.client.post_json("/api/usque/debug", {"enabled": True})
        self.assertEqual(mgr._buf_size(), _MAX_DEBUG_LINES)
        self.client.post_json("/api/usque/debug", {"enabled": False})

    def test_log_of_unknown_config_errors(self):
        r = self.client.get_json("/api/usque/configs/nosuch/log")
        self.assertFalse(r["ok"])

    def test_read_log_rejects_bad_iface(self):
        from core.usque_manager import get_usque_manager
        r = get_usque_manager().read_log("../etc/passwd")
        self.assertFalse(r["ok"])

    def test_read_log_returns_tail(self):
        from core.usque_manager import get_usque_manager
        from collections import deque
        mgr = get_usque_manager()
        mgr._stderr["opkgtun7"] = deque(
            ["строка %d" % i for i in range(50)], maxlen=500)
        r = mgr.read_log("opkgtun7", lines=10)
        self.assertTrue(r["ok"])
        self.assertEqual(r["captured"], 50)
        self.assertEqual(len(r["log"].splitlines()), 10)
        self.assertIn("строка 49", r["log"])
        mgr._stderr.pop("opkgtun7", None)


class TestUsqueImport(_IsolatedConfig):
    """Импорт готового usque-конфига.

    Сессию usque НЕЛЬЗЯ собрать из .conf AmneziaWG: это MASQUE поверх
    HTTP/3, а не WireGuard, и ключи разных алгоритмов (X25519 против
    ECDSA P-256). Апстрим прямо заявляет «no support for WireGuard».
    Поэтому импорт принимает только родной config.json, а на AWG-конфиг
    обязан отвечать понятным объяснением, а не «невалидный JSON».
    """

    AWG_CONF = (
        "[Interface]\n"
        "PrivateKey = 4FU5KJ7mCnBSJcaPZxqacRHm52OsFcYLkZ4k+LQOE0w=\n"
        "Address = 172.16.0.2/32\n"
        "Jc = 4\n\n"
        "[Peer]\n"
        "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n"
        "Endpoint = engage.cloudflareclient.com:1014\n"
    )
    GOOD = ('{"private_key": "MHcCAQEE", "access_token": "tok",'
            ' "id": "dev-1", "ipv4": "172.16.0.2"}')

    def test_awg_conf_rejected_with_explanation(self):
        r = self.client.post_json("/api/usque/configs/import",
                                  {"name": "fromawg", "text": self.AWG_CONF})
        self.assertFalse(r["ok"])
        self.assertIn("AmneziaWG", r["error"])

    def test_json_without_usque_fields_rejected(self):
        r = self.client.post_json("/api/usque/configs/import",
                                  {"name": "bad", "text": '{"foo": 1}'})
        self.assertFalse(r["ok"])
        for field in ("private_key", "access_token", "id"):
            self.assertIn(field, r["error"])

    def test_valid_config_imported_and_listed(self):
        r = self.client.post_json("/api/usque/configs/import",
                                  {"name": "imported-ok", "text": self.GOOD})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["path"].endswith("imported-ok.json"))
        names = [c["name"] for c in
                 self.client.get_json("/api/usque/configs")["configs"]]
        self.assertIn("imported-ok", names)

    def test_duplicate_name_rejected(self):
        self.client.post_json("/api/usque/configs/import",
                              {"name": "dup", "text": self.GOOD})
        again = self.client.post_json("/api/usque/configs/import",
                                      {"name": "dup", "text": self.GOOD})
        self.assertFalse(again["ok"])

    def test_name_traversal_rejected(self):
        r = self.client.post_json("/api/usque/configs/import",
                                  {"name": "../../evil", "text": self.GOOD})
        self.assertFalse(r["ok"])

if __name__ == "__main__":
    unittest.main()


class TestUsqueReleases(_IsolatedConfig):
    """Страница установки: выбор версии и установка выбранного тега.

    Раньше маршрутов /releases и /install/local не было вовсе — SetupUI
    показывал «список релизов недоступен: method not allowed», и выбрать
    версию было нельзя.
    """

    def test_releases_endpoint_exists_and_returns_list(self):
        with mock.patch("core.ext_binary_installer.list_releases",
                        return_value={"ok": True, "releases": [
                            {"tag": "v0.3.0", "published_at": "2026-07-02",
                             "prerelease": False}]}) as lr:
            r = self.client.get_json("/api/usque/releases")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(r["releases"][0]["tag"], "v0.3.0")
        self.assertEqual(lr.call_args.args[0], "usque")

    def test_releases_passes_transport_through(self):
        with mock.patch("core.ext_binary_installer.list_releases",
                        return_value={"ok": True, "releases": []}) as lr:
            self.client.get_json("/api/usque/releases?transport=awg:wg0&force=1")
        self.assertEqual(lr.call_args.kwargs["transport"], "awg:wg0")
        self.assertTrue(lr.call_args.kwargs["force"])

    def test_install_forwards_tag_and_transport(self):
        seen = {}

        def _fake(name, *, progress_cb=None, tag="", transport=""):
            seen["name"] = name
            seen["tag"] = tag
            seen["transport"] = transport
            return {"ok": True, "tag": tag}

        with mock.patch("core.ext_binary_installer.install_binary_by_name",
                        side_effect=_fake):
            r = self.client.post_json("/api/usque/install",
                                      {"tag": "v0.2.0",
                                       "transport": "singbox:main"})
            self.assertTrue(r["ok"])
            for _ in range(50):
                if "tag" in seen:
                    break
                import time as _t
                _t.sleep(0.02)
        self.assertEqual(seen.get("tag"), "v0.2.0")
        self.assertEqual(seen.get("transport"), "singbox:main")

    def test_install_rejects_bogus_tag(self):
        r = self.client.post_json("/api/usque/install",
                                  {"tag": "../../etc/passwd"})
        self.assertFalse(r["ok"])
        self.assertIn("тег", r["error"].lower())

    def test_install_rejects_unknown_transport(self):
        r = self.client.post_json("/api/usque/install",
                                  {"transport": "telepathy"})
        self.assertFalse(r["ok"])
        self.assertIn("транспорт", r["error"].lower())


class TestUsqueRegisterTransport(_IsolatedConfig):
    """Регистрация через уже работающий обход.

    Провайдер может резать api.cloudflareclient.com — тогда прямая
    регистрация падает с «TLS handshake timeout», хотя AWG на роутере уже
    поднят.
    """

    def test_register_forwards_transport(self):
        with mock.patch("core.usque_manager.UsqueManager.register",
                        return_value={"ok": True}) as reg:
            r = self.client.post_json("/api/usque/register",
                                      {"name": "warp-x",
                                       "transport": "awg:wg0"})
        self.assertTrue(r["ok"])
        self.assertEqual(reg.call_args.kwargs["transport"], "awg:wg0")

    def test_register_rejects_unknown_transport(self):
        r = self.client.post_json("/api/usque/register",
                                  {"name": "warp-x", "transport": "nonsense"})
        self.assertFalse(r["ok"])
        self.assertIn("транспорт", r["error"].lower())

    def test_register_without_transport_still_works(self):
        with mock.patch("core.usque_manager.UsqueManager.register",
                        return_value={"ok": True}) as reg:
            r = self.client.post_json("/api/usque/register", {"name": "warp-y"})
        self.assertTrue(r["ok"])
        self.assertEqual(reg.call_args.kwargs["transport"], "")


class TestUsqueVersionSpaces(_IsolatedConfig):
    """Версия движка usque и тег пакета usque-keenetic — разные величины.

    Пакет v0.3.0 несёт usque 4.2.0. Сравнение «4.2.0 != 0.3.0» давало
    вечное «доступно обновление» на странице установки.
    """

    def _env(self, installed_tag="", engine="4.2.0"):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("usque", "installed_tag", installed_tag)
        with mock.patch("core.usque_manager.UsqueManager.detect",
                        return_value={"installed": True,
                                      "binary": "/opt/usr/bin/usque",
                                      "version": engine, "arch": "aarch64"}):
            return (self.client.get_json("/api/usque/environment"),
                    self.client.get_json("/api/usque/version"))

    def test_environment_reports_package_tag_and_engine_separately(self):
        env, _ver = self._env(installed_tag="v0.3.0")
        # SetupUI сравнивает именно binary.version с «В релизе».
        self.assertEqual(env["binary"]["version"], "v0.3.0")
        self.assertEqual(env["binary"]["engine_version"], "4.2.0")
        # Основная страница usque.js читает плоское поле — там движок.
        self.assertEqual(env["version"], "4.2.0")

    def test_no_phantom_update_when_pinned_tag_installed(self):
        from core.ext_binary_installer import BINARIES
        pinned = BINARIES["usque"]["release_tag"]
        _env, ver = self._env(installed_tag=pinned)
        self.assertFalse(ver["has_update"])

    def test_update_offered_for_older_package_tag(self):
        _env, ver = self._env(installed_tag="v0.2.0")
        self.assertTrue(ver["has_update"])

    def test_no_update_claim_when_tag_unknown(self):
        """Пакет поставлен мимо GUI — сравнивать не с чем, значит молчим."""
        _env, ver = self._env(installed_tag="")
        self.assertFalse(ver["has_update"])
