# tests/test_api_tgproxy.py
"""
Integration-тесты для Telegram Proxy API (/api/tgproxy/*).

Проверяем:
  1. GET  /status                 — статус обоих движков
  2. GET  /detect                 — обнаружение установленных пакетов
  3. GET  /tgwsproxy/config       — чтение конфига
  4. PUT  /tgwsproxy/config       — запись конфига (с валидацией)
  5. GET  /tgwsproxy/connect-info — connect-info без запуска
  6. POST /tgwsproxy/down         — остановка (идемпотентность)
  7. POST /mtproto/down           — остановка mtproto (идемпотентность)
  8. GET  /tgwsproxy/tunnels      — список WARP-туннелей
  9. POST /tgwsproxy/route-via-tunnel — валидация kind/iface
"""

import threading
import unittest
from unittest import mock

from tests._wsgi_client import WSGIClient, build_test_app


class TestTgproxyStatusDetect(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_status(self):
        """GET /api/tgproxy/status — структура."""
        r = self.client.get_json("/api/tgproxy/status")
        self.assertEqual(r["_status"], 200)
        self.assertIn("tgwsproxy", r)
        self.assertIn("mtproto", r)
        self.assertIn("any_running", r)
        # без запуска — false
        self.assertIs(r["any_running"], False)

    def test_detect(self):
        """GET /api/tgproxy/detect — структура."""
        r = self.client.get_json("/api/tgproxy/detect")
        self.assertEqual(r["_status"], 200)
        self.assertIn("tgwsproxy", r)
        self.assertIn("mtproto", r)
        self.assertIn("installed", r["tgwsproxy"])
        self.assertIn("installed", r["mtproto"])

    def test_tgwsproxy_config_get(self):
        """GET /api/tgproxy/tgwsproxy/config — структура."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/config")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))
        self.assertIn("config", r)
        cfg = r["config"]
        self.assertIn("host", cfg)
        self.assertIn("port", cfg)
        self.assertIn("fake_tls_domain", cfg)
        self.assertIn("cf_domain", cfg)
        self.assertIn("secret_configured", cfg)
        self.assertNotIn("secret", cfg)

    def test_tgwsproxy_connect_info(self):
        """GET /api/tgproxy/tgwsproxy/connect-info — 200."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/connect-info")
        self.assertEqual(r["_status"], 200)

    def test_tgwsproxy_down(self):
        """POST /api/tgproxy/tgwsproxy/down — идемпотентность."""
        r = self.client.post_json("/api/tgproxy/tgwsproxy/down")
        self.assertEqual(r["_status"], 200)

    def test_mtproto_down(self):
        """POST /api/tgproxy/mtproto/down — идемпотентность."""
        r = self.client.post_json("/api/tgproxy/mtproto/down")
        self.assertEqual(r["_status"], 200)

    def test_mtproto_connect_info_not_running(self):
        """GET /api/tgproxy/mtproto/connect-info — без запуска."""
        r = self.client.get_json("/api/tgproxy/mtproto/connect-info")
        self.assertEqual(r["_status"], 200)
        self.assertIn("link", r)

    def test_tunnels_list(self):
        """GET /api/tgproxy/tgwsproxy/tunnels — 200."""
        r = self.client.get_json("/api/tgproxy/tgwsproxy/tunnels")
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))
        self.assertIsInstance(r.get("tunnels"), list)


class TestTgproxyConfigPut(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_put_config_valid(self):
        """PUT /api/tgproxy/tgwsproxy/config — корректные параметры."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "host": "0.0.0.0",
            "port": 1443,
            "log_level": "0",
        })
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    def test_put_config_with_domain(self):
        """PUT с валидным cf_domain."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "cf_domain": "example.com",
        })
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    def test_put_config_invalid_port_low(self):
        """PUT с портом 0 — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": 0,
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_port_high(self):
        """PUT с портом 99999 — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": 99999,
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_port_string(self):
        """PUT с портом-строкой — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": "not-a-number",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_cf_domain(self):
        """PUT с невалидным cf_domain — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "cf_domain": "not a domain!@#",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_config_invalid_fake_tls_domain(self):
        """PUT с невалидным fake_tls_domain — ошибка."""
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "fake_tls_domain": "spaces in domain",
        })
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_put_hybrid_profile(self):
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "mode": "hybrid",
            "pool_size": 1,
            "max_conns": 32,
            "buf_kb": 32,
        })
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"))

    def test_rotate_secret_requires_explicit_confirmation(self):
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/secret/rotate", {"confirm": False})
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r.get("ok"))

    def test_put_keeps_fields_absent_from_body(self):
        """PUT — частичное обновление. Страница шлёт только часть полей;
        раньше остальные молча уезжали в дефолты (HOST, LOG_LEVEL,
        DC_IP_DEFAULT_POOL, свой CFPROXY_DOMAINS_URL)."""
        first = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "host": "192.168.10.1",
            "port": 1443,
            "log_level": "2",
            "dc_ip_default_pool": "149.154.167.220,149.154.175.50",
            "cfproxy_domains_url": "https://example.org/pool.txt",
            "mode": "direct",
        })
        self.assertTrue(first.get("ok"), first)

        # Тело ровно такое, какое шлёт страница при «Сохранить».
        second = self.client.put_json("/api/tgproxy/tgwsproxy/config", {
            "port": 1443, "fake_tls_domain": "",
            "cf_domain": "", "cf_worker_domain": "",
            "dc_ip_default": "149.154.167.220", "mode": "direct",
            "pool_size": 2, "max_conns": 64, "buf_kb": 64,
        })
        self.assertTrue(second.get("ok"), second)

        cfg = self.client.get_json("/api/tgproxy/tgwsproxy/config")["config"]
        self.assertEqual(cfg["host"], "192.168.10.1")
        self.assertEqual(cfg["log_level"], "2")
        self.assertEqual(cfg["dc_ip_default_pool"],
                         "149.154.167.220,149.154.175.50")
        self.assertEqual(cfg["cfproxy_domains_url"],
                         "https://example.org/pool.txt")

    def test_get_put_config_round_trip(self):
        """GET → PUT тем же телом не должен падать на extra_args."""
        cfg = self.client.get_json("/api/tgproxy/tgwsproxy/config")["config"]
        r = self.client.put_json("/api/tgproxy/tgwsproxy/config", cfg)
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r.get("ok"), r)


class TestTgproxyAutostart(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_autostart_toggle_round_trip(self):
        """app.py поднимает прокси при загрузке по tgproxy.enabled +
        tgproxy.autostart — выставить их было нечем."""
        try:
            r = self.client.put_json("/api/tgproxy/autostart",
                                     {"autostart": True})
            self.assertEqual(r["_status"], 200)
            self.assertTrue(r.get("ok"), r)
            self.assertIs(
                self.client.get_json("/api/tgproxy/autostart")["autostart"],
                True)

            from core.config_manager import get_config_manager
            cfg = get_config_manager()
            self.assertTrue(cfg.get("tgproxy", "enabled"))
            self.assertTrue(cfg.get("tgproxy", "autostart"))
        finally:
            self.client.put_json("/api/tgproxy/autostart", {"autostart": False})

    def test_autostart_requires_field(self):
        r = self.client.put_json("/api/tgproxy/autostart", {})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)


class TestTgproxyRouteViaTunnel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_route_via_tunnel_missing_kind(self):
        """POST /route-via-tunnel без kind — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"iface": "awg0"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)
        self.assertIn("error", r)

    def test_route_via_tunnel_invalid_kind(self):
        """POST /route-via-tunnel с kind=invalid — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"kind": "invalid", "iface": "tun0"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_route_via_tunnel_missing_iface(self):
        """POST /route-via-tunnel без iface — ошибка."""
        r = self.client.post_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel",
            {"kind": "warp"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r.get("ok"), False)

    def test_unroute_via_tunnel(self):
        """DELETE /route-via-tunnel — идемпотентность."""
        r = self.client.delete_json(
            "/api/tgproxy/tgwsproxy/route-via-tunnel")
        self.assertEqual(r["_status"], 200)


class TestMtprotoUpAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    @mock.patch("core.tgproxy_manager.get_mtproxy_client_manager")
    def test_mtproto_up_without_relay(self, mock_get_mgr):
        mgr = mock.Mock()
        mgr.start.return_value = {"ok": False, "error": "relay обязателен для mtproto-режима"}
        mock_get_mgr.return_value = mgr
        r = self.client.post_json("/api/tgproxy/mtproto/up", {"port": 1443})
        self.assertEqual(r["_status"], 200)
        self.assertFalse(r["ok"])
        mgr.start.assert_called_once()
        self.assertEqual(mgr.start.call_args.kwargs["relay"], "")


class TestTgproxyInstallEngine(unittest.TestCase):
    """POST/GET /api/tgproxy/install — выбор движка через engine.

    Регрессия issue #272: ручка знала только tg-ws-proxy, поэтому у
    резервного tg-mtproxy-client в GUI не было способа установиться, хотя
    манифест для него в ext_binary_installer уже лежал.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        from core.ext_binary_installer import _operation_status
        _operation_status.clear()

    def _install(self, body):
        """POST /install с замоканным установщиком → имя из BINARIES."""
        done = threading.Event()
        seen = []

        def _fake_install(name, progress_cb=None):
            seen.append(name)
            done.set()
            return {"ok": True, "version": "1.0", "tag": "v1.0"}

        with mock.patch("core.ext_binary_installer.install_binary_by_name",
                        _fake_install):
            r = self.client.post_json("/api/tgproxy/install", body)
            done.wait(timeout=5)
        return r, seen

    def test_default_engine_is_tgwsproxy(self):
        """Без engine — прежнее поведение (старый фронтенд)."""
        r, seen = self._install({})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(r["engine"], "tgwsproxy")
        self.assertEqual(seen, ["tgwsproxy"])

    def test_mtproto_engine_maps_to_tgproto(self):
        """engine=mtproto ставит tgproto — имена GUI и манифеста разные."""
        r, seen = self._install({"engine": "mtproto"})
        self.assertEqual(r["_status"], 200)
        self.assertTrue(r["ok"])
        self.assertEqual(r["engine"], "mtproto")
        self.assertEqual(seen, ["tgproto"])

    def test_unknown_engine_rejected(self):
        """Неизвестный engine не запускает установку ничего."""
        r = self.client.post_json("/api/tgproxy/install", {"engine": "teleproxy"})
        self.assertEqual(r["_status"], 200)
        self.assertIs(r["ok"], False)
        self.assertIn("teleproxy", r["error"])

    def test_status_is_per_engine(self):
        """Прогресс у движков раздельный, а не общий на двоих."""
        from core.ext_binary_installer import _operation_status
        _operation_status["tgproto"] = {"status": "download", "progress": 30,
                                        "message": "качаем"}
        r = self.client.get_json("/api/tgproxy/install/status?engine=mtproto")
        self.assertEqual(r["engine"], "mtproto")
        self.assertEqual(r["progress"]["progress"], 30)

        r = self.client.get_json("/api/tgproxy/install/status")
        self.assertEqual(r["engine"], "tgwsproxy")
        self.assertEqual(r["progress"]["status"], "idle")

    def test_concurrent_install_not_restarted(self):
        """Повторный POST во время установки не плодит второй поток."""
        from core.ext_binary_installer import _operation_status
        _operation_status["tgwsproxy"] = {"status": "download", "progress": 40,
                                          "message": "качаем"}
        with mock.patch("core.ext_binary_installer.install_binary_by_name") as m:
            r = self.client.post_json("/api/tgproxy/install", {})
        self.assertTrue(r["ok"])
        self.assertEqual(r["progress"]["progress"], 40)
        m.assert_not_called()

    def test_detect_reports_installability(self):
        """/detect говорит, есть ли сборка под архитектуру роутера."""
        r = self.client.get_json("/api/tgproxy/detect")
        for engine in ("tgwsproxy", "mtproto"):
            self.assertIn("installable", r[engine])
            self.assertIn("supported_archs", r[engine])
            self.assertIsInstance(r[engine]["supported_archs"], list)


class TestMtprotoInstalledTag(unittest.TestCase):
    """Тег установленного tg-mtproxy-client запоминается в настройках.

    У бинарника нет `--version`, и попытка спросить её просто запускает
    прокси — поэтому единственный момент, когда версия известна, это сама
    установка. Без записи «Обновления» навсегда показывали бы пустую
    текущую версию.
    """

    def test_tag_recorded_for_mtproto(self):
        from api.tgproxy import _remember_installed_tag
        cm = mock.Mock()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm), \
             mock.patch("core.config_manager.save_config") as save:
            _remember_installed_tag("mtproto", {"tag": "z2k-classify-rolling",
                                                "version": ""})
        cm.set.assert_called_once_with(
            "tgproxy", "mtproto_installed_tag", "z2k-classify-rolling")
        save.assert_called_once()

    def test_tag_not_recorded_for_tgwsproxy(self):
        """У tg-ws-proxy версию отдаёт opkg/apk — своё поле ему не нужно."""
        from api.tgproxy import _remember_installed_tag
        cm = mock.Mock()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm):
            _remember_installed_tag("tgwsproxy", {"tag": "v0.9.3"})
        cm.set.assert_not_called()

    def _check_with(self, installed_version, releases):
        from core.update_checker import _check_tgproto
        mgr = mock.Mock()
        mgr.detect.return_value = {"installed": True,
                                   "version": installed_version}
        with mock.patch("core.update_checker._github_latest") as gl, \
             mock.patch("core.ext_binary_installer.list_releases",
                        return_value={"ok": True, "releases": releases}), \
             mock.patch("core.tgproxy_manager.get_mtproxy_client_manager",
                        return_value=mgr):
            return _check_tgproto(), gl

    def test_update_check_uses_our_build_not_upstream_latest(self):
        """«Последняя» — та, которую реально поставит кнопка «Установить».

        tg-mtproxy-client мы теперь собираем сами; спрашивать latest у
        апстрима значило бы обещать версию, которую установщик не
        поставит.
        """
        res, gl = self._check_with(
            "tgproto-bin-v20260802-fe773fa",
            [{"tag": "tgproto-bin-v20260802-fe773fa"}])
        gl.assert_not_called()
        self.assertEqual(res["latest"], "20260802-fe773fa")
        self.assertIs(res["has_update"], False)

    def test_update_offered_when_our_build_is_newer(self):
        res, _gl = self._check_with(
            "tgproto-bin-v20260701-aaaaaaa",
            [{"tag": "tgproto-bin-v20260802-fe773fa"}])
        self.assertTrue(res["has_update"])

    def test_falls_back_to_upstream_until_first_build(self):
        """Пока нашего релиза нет, установщик идёт к апстриму — и мы тоже."""
        from core.update_checker import _check_tgproto
        mgr = mock.Mock()
        mgr.detect.return_value = {"installed": True,
                                   "version": "z2k-classify-rolling"}
        with mock.patch("core.update_checker._github_latest",
                        return_value="z2k-classify-rolling") as gl, \
             mock.patch("core.ext_binary_installer.list_releases",
                        return_value={"ok": True, "releases": []}), \
             mock.patch("core.tgproxy_manager.get_mtproxy_client_manager",
                        return_value=mgr):
            res = _check_tgproto()
        gl.assert_called_once()
        self.assertIs(res["has_update"], False)


class TestTgwsproxyUpdateCheck(unittest.TestCase):
    """Версия пакета против тега релиза.

    Issue #272: opkg/apk отдают версию с ревизией сборки (`0.9.3-1`), а
    тег релиза — без неё (`0.9.3`). Сравнение строк «в лоб» держало
    кнопку «Обновить» вечно зажжённой на уже актуальной версии.
    """

    def _check(self, installed, latest):
        from core.update_checker import _check_tgwsproxy
        mgr = mock.Mock()
        mgr.detect.return_value = {"installed": True, "version": installed}
        with mock.patch("core.update_checker._github_latest",
                        return_value=latest), \
             mock.patch("core.tgproxy_manager.get_tgwsproxy_manager",
                        return_value=mgr):
            return _check_tgwsproxy()

    def test_build_revision_is_not_an_update(self):
        for installed in ("0.9.3-1", "0.9.3-r1", "0.9.3"):
            res = self._check(installed, "0.9.3")
            self.assertIs(res["has_update"], False, installed)
            self.assertEqual(res["current"], installed)

    def test_newer_upstream_is_an_update(self):
        res = self._check("0.9.3-1", "0.9.4")
        self.assertTrue(res["has_update"])

    def test_unknown_versions_do_not_offer_update(self):
        self.assertIs(self._check("", "0.9.3")["has_update"], False)
        self.assertIs(self._check("0.9.3-1", "")["has_update"], False)


class TestTgproxyUninstall(unittest.TestCase):
    """POST /api/tgproxy/uninstall — удаление движка из GUI (issue #272)."""

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def _uninstall(self, body, *, result=None, stop=None):
        removed = []

        def _fake_uninstall(name):
            removed.append(name)
            return result if result is not None else {"ok": True}

        mgr = mock.Mock()
        mgr.stop.return_value = stop if stop is not None else {"ok": True}
        with mock.patch("core.ext_binary_installer.uninstall_binary",
                        _fake_uninstall), \
             mock.patch("core.tgproxy_manager.get_tgwsproxy_manager",
                        return_value=mgr), \
             mock.patch("core.tgproxy_manager.get_mtproxy_client_manager",
                        return_value=mgr):
            r = self.client.post_json("/api/tgproxy/uninstall", body)
        return r, removed, mgr

    def test_default_engine_is_tgwsproxy(self):
        r, removed, mgr = self._uninstall({})
        self.assertTrue(r["ok"])
        self.assertEqual(r["engine"], "tgwsproxy")
        self.assertEqual(removed, ["tgwsproxy"])
        mgr.stop.assert_called_once()

    def test_mtproto_engine_maps_to_tgproto(self):
        r, removed, _mgr = self._uninstall({"engine": "mtproto"})
        self.assertTrue(r["ok"])
        self.assertEqual(removed, ["tgproto"])

    def test_unknown_engine_rejected(self):
        r, removed, _mgr = self._uninstall({"engine": "teleproxy"})
        self.assertIs(r["ok"], False)
        self.assertEqual(removed, [])

    def test_stopped_before_removal(self):
        """Иначе останется процесс без файлов и занятый порт."""
        _r, _removed, mgr = self._uninstall({})
        mgr.stop.assert_called_once()

    def test_stop_failure_does_not_block_removal(self):
        """Движок мог быть и не запущен — это не повод не удалять."""
        r, removed, _mgr = self._uninstall(
            {}, stop={"ok": False, "error": "не запущен"})
        self.assertTrue(r["ok"])
        self.assertEqual(removed, ["tgwsproxy"])
        self.assertIn("не запущен", r["stop_warning"])

    def test_removal_error_is_reported(self):
        r, _removed, _mgr = self._uninstall(
            {}, result={"ok": False, "error": "opkg remove: busy"})
        self.assertIs(r["ok"], False)
        self.assertIn("opkg remove", r["error"])

    def test_installed_tag_forgotten_for_mtproto(self):
        """Иначе «Обновления» показывают версию удалённого движка."""
        from api.tgproxy import _forget_installed_tag
        cm = mock.Mock()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm), \
             mock.patch("core.config_manager.save_config") as save:
            _forget_installed_tag("mtproto")
        cm.set.assert_called_once_with("tgproxy", "mtproto_installed_tag", "")
        save.assert_called_once()

    def test_installed_tag_untouched_for_tgwsproxy(self):
        from api.tgproxy import _forget_installed_tag
        cm = mock.Mock()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm):
            _forget_installed_tag("tgwsproxy")
        cm.set.assert_not_called()
