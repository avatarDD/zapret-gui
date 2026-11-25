# tests/test_geneva_install_api.py
"""
Выбор версии geneva_c: GET /api/geneva/releases, POST /api/geneva/install
с {tag, transport} и installed_tag в GET /api/geneva/status.

Установщик и список релизов подменены моками: здесь проверяется граница
(валидация тега и транспорта, проброс аргументов, форма ответа), а не
скачивание — его механику гоняют тесты ext_binary_installer.
"""

import unittest
from unittest import mock

from core import ext_binary_installer
from tests._wsgi_client import WSGIClient, build_test_app


def _cfg_mock():
    cfg = mock.Mock(name="config_manager")
    cfg.get.return_value = {}
    return cfg


class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        self.installer = mock.Mock(name="install_binary_by_name")
        self.installer.return_value = {"ok": True, "tag": "v2.0.1",
                                       "version": "2.0.1",
                                       "binary": "/opt/usr/bin/geneva"}
        self.cfg = _cfg_mock()
        gm = mock.Mock(name="geneva_manager")
        gm.detect.return_value = {"installed": True, "version": "2.0.1"}
        gm.is_running.return_value = False
        for target, attr, repl in (
                ("core.ext_binary_installer", "install_binary_by_name",
                 self.installer),
                ("core.ext_binary_installer", "list_releases",
                 mock.Mock(name="list_releases")),
                ("core.config_manager", "get_config_manager",
                 mock.Mock(return_value=self.cfg)),
                ("core.geneva_manager", "get_geneva_manager",
                 mock.Mock(return_value=gm))):
            p = mock.patch.object(__import__(target, fromlist=[attr]),
                                  attr, repl)
            p.start()
            self.addCleanup(p.stop)


class TestReleases(_Base):

    def test_list_passes_transport_and_force(self):
        mod = ext_binary_installer
        mod.list_releases.return_value = {
            "ok": True, "pinned": "v2.0.2",
            "releases": [{"tag": "v2.0.2", "published_at": "2026-11-24",
                          "prerelease": False},
                         {"tag": "v2.0.1", "published_at": "2026-11-18",
                          "prerelease": False}]}
        data = self.client.get_json(
            "/api/geneva/releases?transport=awg%3Awg0&force=1")
        mod.list_releases.assert_called_once_with(
            "geneva", transport="awg:wg0", force=True)
        self.assertTrue(data["ok"])
        self.assertEqual(data["pinned"], "v2.0.2")
        self.assertEqual([r["tag"] for r in data["releases"]],
                         ["v2.0.2", "v2.0.1"])

    def test_defaults_without_query(self):
        mod = ext_binary_installer
        mod.list_releases.return_value = {"ok": True, "releases": []}
        self.client.get_json("/api/geneva/releases")
        mod.list_releases.assert_called_once_with(
            "geneva", transport="", force=False)

    def test_error_shape(self):
        mod = ext_binary_installer
        mod.list_releases.side_effect = RuntimeError("сеть недоступна")
        data = self.client.get_json("/api/geneva/releases")
        self.assertFalse(data["ok"])
        self.assertIn("сеть недоступна", data["error"])


class TestInstallBody(_Base):

    def test_tag_and_transport_pass_through(self):
        data = self.client.post_json(
            "/api/geneva/install",
            {"tag": "v2.0.1", "transport": "singbox:main"})
        self.installer.assert_called_once_with(
            "geneva", tag="v2.0.1", transport="singbox:main")
        self.assertTrue(data["ok"])
        # Успех запоминается тегом установки и перечитывает детект.
        self.assertEqual(
            self.cfg.set.call_args,
            mock.call("geneva", "installed_tag", "v2.0.1"))
        self.assertTrue(self.cfg.save.called)
        self.assertEqual(data["detect"]["version"], "2.0.1")

    def test_empty_body_means_latest(self):
        self.client.post_json("/api/geneva/install", {})
        self.installer.assert_called_once_with(
            "geneva", tag="", transport="")

    def test_bad_tag_refused(self):
        data = self.client.post_json(
            "/api/geneva/install", {"tag": "v2.0.2/../../other"})
        self.assertFalse(data["ok"])
        self.assertFalse(self.installer.called)
        self.assertIn("Недопустимый тег", data["error"])

    def test_tag_charset_and_length_limits(self):
        for tag in ("с пробелом", "v\t2", "x" * 65):
            data = self.client.post_json("/api/geneva/install", {"tag": tag})
            self.assertFalse(data["ok"], tag)

    def test_unknown_transport_refused(self):
        data = self.client.post_json(
            "/api/geneva/install", {"transport": "nope:nope"})
        self.assertFalse(data["ok"])
        self.assertFalse(self.installer.called)
        self.assertIn("Неизвестный транспорт", data["error"])

    def test_failure_shape_is_reply_not_500(self):
        self.installer.return_value = {"ok": False,
                                       "error": "архитектура не поддерживается"}
        data = self.client.post_json("/api/geneva/install", {})
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "архитектура не поддерживается")

    def test_restart_needed_when_engine_running(self):
        """Файл заменён через rename: работающий процесс остался на старом
        бинарнике — ответ обязан это показать."""
        gm = mock.Mock(name="geneva_manager")
        gm.detect.return_value = {"installed": True, "version": "2.0.1"}
        gm.is_running.return_value = True
        with mock.patch.object(
                __import__("core.geneva_manager",
                           fromlist=["get_geneva_manager"]),
                "get_geneva_manager", mock.Mock(return_value=gm)):
            data = self.client.post_json("/api/geneva/install", {})
        self.assertTrue(data["ok"])
        self.assertTrue(data["restart_needed"])
        # на остановленном движке перезапуск не нужен
        gm.is_running.return_value = False
        with mock.patch.object(
                __import__("core.geneva_manager",
                           fromlist=["get_geneva_manager"]),
                "get_geneva_manager", mock.Mock(return_value=gm)):
            data = self.client.post_json("/api/geneva/install", {})
        self.assertFalse(data["restart_needed"])


class TestStatusTag(_Base):
    """GET /api/geneva/status отдаёт installed_tag — тег последней
    установки: иначе ключ писался бы в конфиг, но нигде не читался."""

    def test_detect_carries_installed_tag(self):
        gm = mock.Mock(name="geneva_manager")
        gm.detect.return_value = {"installed": True, "version": "2.0.1"}
        gm.status.return_value = {"running": False}
        gm.search_status.return_value = {"owner": "manual"}
        self.cfg.get.return_value = "v2.0.2"
        for target, attr, repl in (
                ("core.bypass_engine", "get_active", lambda: "nfqws2"),
                ("core.update_checker", "geneva_release_info",
                 lambda v: {"latest": "2.0.2", "tag": "v2.0.2",
                            "release_build": True, "has_update": True}),
                ("core.geneva_manager", "get_geneva_manager",
                 mock.Mock(return_value=gm))):
            p = mock.patch.object(__import__(target, fromlist=[attr]),
                                  attr, repl)
            p.start()
            self.addCleanup(p.stop)
        r = self.client.get_json("/api/geneva/status")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["detect"]["installed_tag"], "v2.0.2")
