# tests/test_server_pool.py
"""Unit-тесты для core/server_pool.py."""

import os
import tempfile
import unittest
from unittest import mock

from core import server_pool as sp


class TestDedup(unittest.TestCase):

    def test_dedup_by_identity(self):
        obs = [
            {"type": "vless", "tag": "a", "server": "1.1.1.1",
             "server_port": 443, "uuid": "u1"},
            {"type": "vless", "tag": "dup", "server": "1.1.1.1",
             "server_port": 443, "uuid": "u1"},   # тот же сервер
            {"type": "vless", "tag": "b", "server": "2.2.2.2",
             "server_port": 443, "uuid": "u2"},
        ]
        out = sp.dedup_outbounds(obs)
        self.assertEqual(len(out), 2)
        self.assertEqual({o["server"] for o in out}, {"1.1.1.1", "2.2.2.2"})

    def test_tag_uniqueness(self):
        obs = [
            {"type": "ss", "tag": "node", "server": "1.1.1.1",
             "server_port": 1, "password": "p1"},
            {"type": "ss", "tag": "node", "server": "2.2.2.2",
             "server_port": 2, "password": "p2"},
        ]
        out = sp.dedup_outbounds(obs)
        self.assertEqual(len(out), 2)
        self.assertEqual(len({o["tag"] for o in out}), 2)

    def test_skips_invalid(self):
        out = sp.dedup_outbounds([{"no": "type"}, "junk", None])
        self.assertEqual(out, [])


class FakeCM:
    def __init__(self, cfg_dir):
        self.data = {}
        self.config_path = os.path.join(cfg_dir, "settings.json")
        self.saved = 0

    def load(self):
        return self.data

    def save(self):
        self.saved += 1
        return True


class TestSourcesCrud(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pooltest-")
        self.fake = FakeCM(self.tmp)
        self._patches = [
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.fake),
            # Не дёргаем реальный фоновый поток в тестах.
            mock.patch.object(sp, "get_pool_refresher",
                              return_value=mock.Mock()),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_add_list_remove(self):
        r = sp.add_source("Src1", "https://example.com/sub.txt")
        self.assertTrue(r["ok"], msg=r.get("error"))
        sid = r["id"]
        lst = sp.list_sources()
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["name"], "Src1")
        self.assertTrue(lst[0]["enabled"])

        sp.update_source(sid, enabled=False, name="Renamed")
        lst = sp.list_sources()
        self.assertEqual(lst[0]["name"], "Renamed")
        self.assertFalse(lst[0]["enabled"])

        sp.remove_source(sid)
        self.assertEqual(sp.list_sources(), [])

    def test_reject_bad_url(self):
        self.assertFalse(sp.add_source("x", "ftp://nope")["ok"])
        self.assertFalse(sp.add_source("", "")["ok"])

    def test_dedup_url(self):
        sp.add_source("A", "https://example.com/x")
        r = sp.add_source("B", "https://example.com/x")
        self.assertFalse(r["ok"])

    def test_settings_roundtrip(self):
        sp.update_settings(interval_hours=24, cap=50, health_filter=True,
                           group="selector", target="amazon")
        s = sp.get_settings()
        self.assertEqual(s["interval_hours"], 24)
        self.assertEqual(s["cap"], 50)
        self.assertTrue(s["health_filter"])
        self.assertEqual(s["group"], "selector")
        self.assertEqual(s["target"], "amazon")

    def test_cap_clamped(self):
        sp.update_settings(cap=99999)
        self.assertLessEqual(sp.get_settings()["cap"], sp.MAX_CAP)

    def test_presets_added_flag(self):
        # Добавим первый пресет и проверим, что он помечается added.
        preset_url = sp.BUILTIN_PRESETS[0]["url"]
        sp.add_source("p", preset_url)
        presets = sp.presets()
        added = {p["url"]: p["added"] for p in presets}
        self.assertTrue(added[preset_url])

    def test_last_good_cache_roundtrip(self):
        cache = {"src-1": {"outbounds": [{"type": "vless", "tag": "a"}],
                           "count": 1}}
        sp._save_cache(cache)
        self.assertEqual(sp._load_cache(), cache)


if __name__ == "__main__":
    unittest.main()
