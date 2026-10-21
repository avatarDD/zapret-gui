# tests/test_known_good.py
"""Рабочая точка туннелей и маршрутов (core/known_good)."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import known_good as kg


def _probe(ok_sites, all_sites=("a", "b", "c")):
    sites = {s: s in ok_sites for s in all_sites}
    return {"ok": sum(sites.values()), "total": len(sites), "sites": sites}


class _FakeMgr:
    def __init__(self, kind, dirpath):
        self.kind, self.dir = kind, dirpath
        self.restarted = []
        self.running = set()

    def list_configs(self):
        out = []
        for fn in sorted(os.listdir(self.dir)):
            name = fn.rsplit(".", 1)[0]
            out.append({"name": name, "path": os.path.join(self.dir, fn),
                        "active": name in self.running})
        return out

    def is_running(self, name):
        return name in self.running

    def restart(self, name):
        self.restarted.append(name)
        return {"ok": True}


class KnownGoodCase(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm
        self.dir = tempfile.mkdtemp(prefix="kg-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager
        self.mgrs = {}
        for kind in kg.KINDS:
            d = os.path.join(self.dir, kind)
            os.makedirs(d)
            self.mgrs[kind] = _FakeMgr(kind, d)
        self.awg = os.path.join(self.dir, "awg", "awg0.conf")
        self._write(self.awg, "[Interface]\nPrivateKey = A\n")
        kg._text_cache.clear()
        for target, value in (
                ("_manager", lambda kind: self.mgrs[kind]),
                ("_dirs", lambda kind: [self.mgrs[kind].dir]),
                ("_wan_down", lambda: False),
                ("_notify", mock.MagicMock())):
            p = mock.patch.object(kg, target, value)
            p.start()
            self.addCleanup(p.stop)
        self.probe = mock.patch.object(kg, "_probe",
                                       return_value=_probe("abc"))
        self.probe_mock = self.probe.start()
        self.addCleanup(self.probe.stop)
        p = mock.patch("core.safe_apply.active", return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def _write(self, path, text):
        with open(path, "w") as f:
            f.write(text)
        # Тот же размер в тот же тик часов ФС — кеш принял бы файл за
        # неизменный; в жизни правки так быстро не идут.
        kg._text_cache.pop(path, None)

    def _read(self, path):
        with open(path) as f:
            return f.read()


class TestPure(unittest.TestCase):

    def test_fingerprint_stable_and_sensitive(self):
        a = {"routes": [{"id": "r"}], "files": {"/x": {"text": "1"}}}
        b = {"routes": [{"id": "r"}], "files": {"/x": {"text": "1",
                                                       "kind": "awg"}}}
        self.assertEqual(kg.fingerprint(a), kg.fingerprint(b))
        c = {"routes": [{"id": "r"}], "files": {"/x": {"text": "2"}}}
        self.assertNotEqual(kg.fingerprint(a), kg.fingerprint(c))

    def test_judge(self):
        good = _probe("ab")
        self.assertTrue(kg.judge(good, _probe("abc"))["promote"])
        bad = kg.judge(good, _probe("a"))
        self.assertFalse(bad["promote"])
        self.assertEqual(bad["lost"], ["b"])
        nosites = kg.judge(good, {"ok": 0, "total": 0, "sites": {}})
        self.assertTrue(nosites["promote"])
        self.assertFalse(nosites["verified"])
        self.assertTrue(kg.judge(_probe(""), _probe("a"))["promote"])

    def test_diff_summary(self):
        good = {"routes": [], "files": {
            "/a": {"kind": "awg", "name": "a", "text": "1"},
            "/b": {"kind": "mihomo", "name": "b", "text": "1"}}}
        cur = {"routes": [{"id": "r"}], "files": {
            "/a": {"kind": "awg", "name": "a", "text": "2"},
            "/c": {"kind": "singbox", "name": "c", "text": "1"}}}
        d = kg.diff_summary(good, cur)
        self.assertTrue(d["routes_changed"])
        self.assertEqual(d["files_changed"], ["awg a"])
        self.assertEqual(d["files_added"], ["singbox c"])
        self.assertEqual(d["files_removed"], ["mihomo b"])


class TestTick(KnownGoodCase):

    def test_baseline_then_same(self):
        self.assertEqual(kg.tick(now=0)["action"], "baseline")
        self.assertEqual(kg.tick(now=60)["action"], "same")
        self.assertTrue(kg.status()["matches_good"])
        st = os.stat(kg._state_path()).st_mode & 0o777
        self.assertEqual(st, 0o600)

    def test_change_promoted_after_window(self):
        kg.tick(now=0)
        self._write(self.awg, "[Interface]\nPrivateKey = B\n")
        self.assertEqual(kg.tick(now=100)["action"], "watching")
        self.assertEqual(kg.tick(now=300)["action"], "watching")
        self.assertIn("candidate", kg.status())
        self.assertEqual(kg.tick(now=800)["action"], "promoted")
        self.assertTrue(kg.status()["matches_good"])

    def test_edit_inside_window_restarts_it(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        self._write(self.awg, "C")
        self.assertEqual(kg.tick(now=650)["action"], "watching")
        self.assertEqual(kg.tick(now=700)["action"], "watching")
        self.assertEqual(kg.tick(now=1300)["action"], "promoted")

    def test_wan_down_postpones_judgement(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        with mock.patch.object(kg, "_wan_down", return_value=True):
            self.assertEqual(kg.tick(now=800)["action"], "wan_down")
        self.assertEqual(kg.tick(now=900)["action"], "promoted")

    def test_broken_change_notifies_and_is_remembered(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        self.probe_mock.return_value = _probe("a")
        res = kg.tick(now=800)
        self.assertEqual(res["action"], "failed")
        self.assertEqual(res["lost"], ["b", "c"])
        kg._notify.assert_called_once()
        self.assertEqual(self._read(self.awg), "B")     # без авто — не трогаем
        self.assertEqual(kg.tick(now=900)["action"], "known_bad")
        self.assertEqual(kg.status()["last_failure"]["changes"]
                         ["files_changed"], ["awg awg0"])

    def test_auto_rollback_once(self):
        self.cfg.set("known_good", "auto_rollback", True)
        self.mgrs["awg"].running.add("awg0")
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        self.probe_mock.return_value = _probe("a")
        self.assertEqual(kg.tick(now=800)["action"], "rolled_back")
        self.assertIn("PrivateKey = A", self._read(self.awg))
        self.assertEqual(self.mgrs["awg"].restarted, ["awg0"])
        # Вторая поломка на той же точке — только уведомление.
        self._write(self.awg, "C")
        kg.tick(now=900)
        self.assertEqual(kg.tick(now=1600)["action"], "failed")
        self.assertEqual(self._read(self.awg), "C")

    def test_disabled_and_busy(self):
        self.cfg.set("known_good", "enabled", False)
        self.assertEqual(kg.tick()["action"], "disabled")
        self.cfg.set("known_good", "enabled", True)
        with mock.patch("core.safe_apply.active", return_value=True):
            self.assertEqual(kg.tick()["action"], "busy")


class TestActions(KnownGoodCase):

    def test_rollback_routes_and_files(self):
        self.cfg.set("unified_routes", [{"id": "r1"}])
        kg.tick(now=0)
        self.cfg.set("unified_routes", [{"id": "r1"}, {"id": "r2"}])
        self._write(self.awg, "B")
        new = os.path.join(self.dir, "singbox", "new.json")
        self._write(new, "{}")
        with mock.patch("core.unified.applier.apply_all") as ap, \
                mock.patch("core.unified.applier.remove_route") as rm:
            res = kg.rollback()
        self.assertTrue(res["ok"], res)
        ap.assert_called_once()
        # Добавленный после точки маршрут снят и из ядра.
        self.assertEqual([c.args[0].id for c in rm.call_args_list], ["r2"])
        self.assertEqual(self.cfg.get("unified_routes"), [{"id": "r1"}])
        self.assertIn("PrivateKey = A", self._read(self.awg))
        self.assertTrue(os.path.exists(new))            # новое не трогаем
        self.assertEqual(self.mgrs["awg"].restarted, [])  # не был поднят

    def test_unreadable_kind_is_neither_judged_nor_rolled_back(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        real = kg._dirs

        def broken(kind):
            if kind == "awg":
                raise OSError("нет каталога")
            return real(kind)
        with mock.patch.object(kg, "_dirs", side_effect=broken):
            self.assertEqual(kg.tick(now=100)["action"], "incomplete")
            self.assertFalse(kg.promote()["ok"])
            res = kg.rollback()
        self.assertFalse(res["ok"])
        self.assertEqual(self._read(self.awg), "B")

    def test_monitoring_list_change_is_not_a_failure(self):
        self.probe_mock.return_value = _probe("abc", ("a", "b", "c"))
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        # «c» убрали из мониторинга — его нет в новой пробе.
        self.probe_mock.return_value = _probe("ab", ("a", "b"))
        self.assertEqual(kg.tick(now=800)["action"], "promoted")

    def test_probe_refreshed_while_unchanged(self):
        kg.tick(now=0)
        self.probe_mock.return_value = _probe("a")
        self.assertNotIn("refreshed", kg.tick(now=60))
        self.assertTrue(kg.tick(now=kg.PROBE_REFRESH + 10)["refreshed"])
        self.assertEqual(kg._read()["good"]["probe"]["ok"], 1)

    def test_failure_cleared_by_promotion(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        self.probe_mock.return_value = _probe("a")
        kg.tick(now=800)
        self.assertIn("last_failure", kg.status())
        self.probe_mock.return_value = _probe("abc")
        self._write(self.awg, "C")
        kg.tick(now=900)
        self.assertEqual(kg.tick(now=1600)["action"], "promoted")
        self.assertNotIn("last_failure", kg.status())

    def test_rollback_without_point(self):
        self.assertFalse(kg.rollback()["ok"])

    def test_promote_clears_failed(self):
        kg.tick(now=0)
        self._write(self.awg, "B")
        kg.tick(now=100)
        self.probe_mock.return_value = _probe("a")
        kg.tick(now=800)
        res = kg.promote("руками")
        self.assertTrue(res["ok"])
        self.assertTrue(kg.status()["matches_good"])
        self.assertEqual(kg._read()["failed"], [])

    def test_big_files_skipped(self):
        big = os.path.join(self.dir, "mihomo", "big.yaml")
        self._write(big, "x" * (kg.MAX_FILE_BYTES + 1))
        self.assertNotIn(big, kg.collect()["files"])

    def test_save_settings_clamps(self):
        r = kg.save_settings({"window_sec": 5, "auto_rollback": 1})
        self.assertEqual(r["settings"]["window_sec"], kg.MIN_WINDOW)
        self.assertTrue(r["settings"]["auto_rollback"])
        bad = kg.save_settings({"window_sec": "x", "enabled": False})
        self.assertFalse(bad["ok"])
        self.assertTrue(kg.settings()["enabled"])       # ничего не применено


if __name__ == "__main__":
    unittest.main()
