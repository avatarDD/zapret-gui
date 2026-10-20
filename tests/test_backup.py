# tests/test_backup.py
"""Unit-тесты для core/backup.py (бэкап/восстановление конфигурации)."""

import unittest
from unittest import mock

from core import backup as bk


class TestValidate(unittest.TestCase):

    def test_not_dict(self):
        self.assertTrue(bk.validate_backup("nope"))

    def test_wrong_format(self):
        self.assertTrue(bk.validate_backup({"format": "other"}))

    def test_ok(self):
        self.assertEqual(bk.validate_backup({"format": bk.FORMAT}), [])

    def test_bad_section_type(self):
        errs = bk.validate_backup({"format": bk.FORMAT, "singbox": {}})
        self.assertTrue(any("singbox" in e for e in errs))


class TestNormalizeSections(unittest.TestCase):

    def test_none_all(self):
        self.assertEqual(bk._normalize_sections(None), set(bk.SECTIONS))

    def test_filter_unknown(self):
        self.assertEqual(bk._normalize_sections(["settings", "bogus"]),
                         {"settings"})

    def test_string(self):
        self.assertEqual(bk._normalize_sections("singbox"), {"singbox"})


class TestBuildBackup(unittest.TestCase):

    def test_includes_selected_only(self):
        with mock.patch("core.backup._collect_settings", return_value={"a": 1}), \
             mock.patch("core.backup._collect_strategies", return_value=[]), \
             mock.patch("core.backup._collect_engine_configs", return_value=[]), \
             mock.patch("core.backup._collect_hostlists", return_value=[]):
            b = bk.build_backup(include=["settings"])
        self.assertEqual(b["format"], bk.FORMAT)
        self.assertIn("settings", b)
        self.assertNotIn("singbox", b)

    def test_summary(self):
        b = {"format": bk.FORMAT, "settings": {"x": 1},
             "singbox": [{"name": "a"}], "hostlists": []}
        s = bk.summary(b)
        self.assertTrue(s["has_settings"])
        self.assertEqual(s["singbox"], 1)
        self.assertEqual(s["hostlists"], 0)


class TestRestoreSettings(unittest.TestCase):

    def setUp(self):
        self.cm = mock.Mock()
        self._p = mock.patch("core.config_manager.get_config_manager",
                             return_value=self.cm)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_skips_gui_by_default(self):
        errs = []
        n = bk._restore_settings({"gui": {"port": 9}, "nfqws": {"x": 1}},
                                 restore_gui=False, errors=errs)
        keys = [c.args[0] for c in self.cm.set.call_args_list]
        self.assertIn("nfqws", keys)
        self.assertNotIn("gui", keys)
        self.assertEqual(n, 1)
        self.cm.save.assert_called_once()

    def test_restores_gui_when_flag(self):
        errs = []
        bk._restore_settings({"gui": {"port": 9}}, restore_gui=True, errors=errs)
        keys = [c.args[0] for c in self.cm.set.call_args_list]
        self.assertIn("gui", keys)


class TestRestoreBackup(unittest.TestCase):

    def test_invalid_rejected(self):
        r = bk.restore_backup({"format": "x"})
        self.assertFalse(r["ok"])

    def test_dispatches_sections(self):
        data = {
            "format": bk.FORMAT,
            "settings": {"nfqws": {"a": 1}},
            "strategies": [{"id": "s1", "name": "S"}],
            "singbox": [{"name": "v", "text": "{}"}],
            "hostlists": [{"name": "list1", "domains": ["a.com"]}],
        }
        with mock.patch("core.backup._restore_settings", return_value=1) as rs, \
             mock.patch("core.backup._restore_strategies", return_value=1) as rst, \
             mock.patch("core.backup._restore_engine", return_value=1) as re_, \
             mock.patch("core.backup._restore_hostlists", return_value=1) as rh:
            r = bk.restore_backup(data)
        self.assertTrue(r["ok"])
        rs.assert_called_once()
        rst.assert_called_once()
        re_.assert_called_once()   # singbox (mihomo отсутствует в data)
        rh.assert_called_once()

    def test_only_selected_sections(self):
        data = {"format": bk.FORMAT, "settings": {"a": 1},
                "hostlists": [{"name": "l", "domains": []}]}
        with mock.patch("core.backup._restore_settings", return_value=1) as rs, \
             mock.patch("core.backup._restore_hostlists", return_value=1) as rh:
            r = bk.restore_backup(data, sections=["hostlists"])
        rs.assert_not_called()
        rh.assert_called_once()
        self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main()


class TestBackupApiRoundtrip(unittest.TestCase):
    """Сквозной тест через реальный WSGI-app: export → summary → import."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from tests._wsgi_client import WSGIClient, build_test_app
        from core.config_manager import init_config
        init_config(tempfile.mkdtemp(prefix="bk-api-"))
        cls.client = WSGIClient(build_test_app())

    def test_export_then_import(self):
        import json
        # Коллекторы движков и runtime-reconfigure мокаем: на реальном
        # роутере они читают живые конфиги sing-box/mihomo/hostlist'ов и
        # дёргают фоновые задачи (подписки/пул/мониторинг) — тест проверяет
        # сквозной pipeline бэкапа (settings), а не состояние роутера.
        with mock.patch.object(bk, "_collect_strategies", return_value=[]), \
             mock.patch.object(bk, "_collect_engine_configs", return_value=[]), \
             mock.patch.object(bk, "_collect_hostlists", return_value=[]), \
             mock.patch.object(bk, "_reconfigure_runtime"):
            # export → валидный бэкап нашего формата
            status, body = self.client.get('/api/backup/export')
            self.assertTrue(status.startswith('200'), status)
            data = json.loads(body)
            self.assertEqual(data['format'], bk.FORMAT)
            self.assertIn('settings', data)
            # summary
            s = self.client.post_json('/api/backup/summary', data)
            self.assertTrue(s['ok'])
            self.assertTrue(s['summary']['has_settings'])
            # import (только settings)
            r = self.client.post_json('/api/backup/import',
                                      {'backup': data, 'sections': ['settings']})
        self.assertTrue(r['ok'], r)
        self.assertIn('settings', r['restored'])

    def test_import_garbage_rejected(self):
        status, _b = self.client.post('/api/backup/import',
                                      {'backup': {'format': 'nope'}})
        self.assertTrue(status.startswith('400'))


class TestIpsetsAndBlobs(unittest.TestCase):

    def test_collect_skips_builtin(self):
        im = mock.Mock()
        im.list_names.return_value = ["my-ipset", "zt-a-ipset"]
        im.get_ipset.return_value = ["1.2.3.0/24"]
        bm = mock.Mock()
        bm.get_blobs.return_value = [{"name": "fake_default_tls",
                                      "is_builtin": True},
                                     {"name": "tls1", "is_builtin": False}]
        bm.get_blob_content.return_value = b"\x01\x02"
        with mock.patch("core.ipset_manager.get_ipset_manager",
                        return_value=im), \
             mock.patch("core.blob_manager.get_blob_manager",
                        return_value=bm):
            self.assertEqual(bk._collect_ipsets(),
                             [{"name": "zt-a-ipset",
                               "entries": ["1.2.3.0/24"]}])
            self.assertEqual(bk._collect_blobs(),
                             [{"name": "tls1", "base64": "AQI="}])

    def test_restore(self):
        im = mock.Mock()
        im.list_names.return_value = []
        im.create_ipset.return_value = (True, "")
        im.save_ipset.return_value = True
        bm = mock.Mock()
        bm.save_blob.return_value = (True, None)
        bm.is_builtin.side_effect = lambda n: n.startswith("fake_default_")
        errs = []
        with mock.patch("core.ipset_manager.get_ipset_manager",
                        return_value=im), \
             mock.patch("core.blob_manager.get_blob_manager",
                        return_value=bm):
            n = bk._restore_ipsets([{"name": "my-ipset", "entries": []},
                                    {"name": "zt-a-ipset",
                                     "entries": ["1.1.1.1"]}], errs)
            m = bk._restore_blobs([{"name": "tls1", "base64": "AQI="},
                                   {"name": "fake_default_x",
                                    "base64": "AQI="},
                                   {"name": "bad", "base64": "!!"}], errs)
        self.assertEqual(n, 1)
        im.create_ipset.assert_called_once_with("zt-a-ipset")
        self.assertEqual(m, 1)
        bm.save_blob.assert_called_once_with("tls1", b"\x01\x02")
        self.assertEqual(len(errs), 1, errs)

    def test_summary_counts(self):
        s = bk.summary({"format": bk.FORMAT, "ipsets": [{}], "blobs": [{}, {}]})
        self.assertEqual((s["ipsets"], s["blobs"]), (1, 2))
