# tests/test_scan_resume_persist.py
"""
Прогресс подбора nfqws2 переживает перезагрузку.

Раньше resume-файл лежал в /tmp: после перезагрузки роутера «Продолжить»
пропадала, а найденные до остановки стратегии оставались только числом.
Теперь файл — в <config>/state/scan/, в нём лучшие найденные, и статус
сканера в простое отдаёт сохранённый прогон для кнопки на странице.
"""

import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import ext_binary_installer as ebi
from core.models import StrategyProbeResult
from core.strategy_scanner import RESUME_KEEP_WORKING, StrategyScanner


def _probe(sid, success, score):
    return StrategyProbeResult(strategy_id=sid, strategy_name=sid,
                               target="example.org", success=success,
                               score=score)


class TestScanResumePersist(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scan-resume-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._saved_cm = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self.tmp)
        cm_mod._config_manager.load()
        self.addCleanup(setattr, cm_mod, "_config_manager", self._saved_cm)

    def _scanner(self):
        s = StrategyScanner()
        s._target = "example.org"
        s._protocol = "tcp"
        s._mode = "standard"
        return s

    def test_file_lives_next_to_settings(self):
        path = self._scanner()._resume_file_path()
        self.assertEqual(path, os.path.join(self.tmp, "state", "scan",
                                            "resume.json"))

    def test_working_saved_best_first_and_restored(self):
        s = self._scanner()
        s._results = [_probe("bad", False, 0)] + [
            _probe("s%02d" % i, True, i) for i in range(30)]
        s._save_resume_state(42)
        with open(s._resume_file_path()) as f:
            state = json.load(f)
        self.assertEqual(state["next_index"], 42)
        self.assertEqual(state["working_count"], 30)
        self.assertEqual(len(state["working"]), RESUME_KEEP_WORKING)
        self.assertEqual(state["working"][0]["strategy_id"], "s29")

        fresh = self._scanner()          # «после перезагрузки»
        info = fresh.saved_resume_info()
        self.assertEqual(info["next_index"], 42)
        self.assertEqual(info["target"], "example.org")
        self.assertEqual(info["working_count"], 30)
        fresh._results = []
        self.assertEqual(fresh._restore_working(), RESUME_KEEP_WORKING)
        self.assertTrue(all(r.success for r in fresh._results))
        self.assertEqual(fresh._results[0].strategy_id, "s29")

    def test_custom_mode_does_not_overwrite(self):
        s = self._scanner()
        s._results = []
        s._save_resume_state(10)
        s._mode = "custom"
        s._save_resume_state(99)
        self.assertEqual(self._scanner().saved_resume_info()["next_index"],
                         10)

    def test_nothing_saved(self):
        self.assertEqual(self._scanner().saved_resume_info(), {})

    def test_broken_working_items_are_skipped(self):
        path = self._scanner()._resume_file_path()
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as f:
            json.dump({"next_index": 5, "working": [
                "junk", {"success": False, "strategy_id": "x"},
                {"success": True, "strategy_id": "ok", "strategy_name": "ok",
                 "target": "example.org", "score": 3}]}, f)
        s = self._scanner()
        s._results = []
        self.assertEqual(s._restore_working(), 1)


class TestArchiveMember(unittest.TestCase):
    """В тарболе geneva_c первым лежит LICENSE — берём член по имени."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "geneva-1.0.0-linux-x86_64.tar.gz")
        with tarfile.open(self.path, "w:gz") as tar:
            for name, data in (("geneva-1.0.0/LICENSE", b"BSD"),
                               ("geneva-1.0.0/geneva", b"\x7fELFbin"),
                               ("geneva-1.0.0/README.md", b"readme")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    def test_member_by_name(self):
        out, tmp, err = ebi._unpack_if_needed(self.path, "geneva")
        self.assertEqual(err, "")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"\x7fELFbin")

    def test_first_file_without_member(self):
        out, _tmp, err = ebi._unpack_if_needed(self.path)
        self.assertEqual(err, "")
        self.assertEqual(os.path.basename(out), "LICENSE")

    def test_missing_member(self):
        out, _tmp, err = ebi._unpack_if_needed(self.path, "nope")
        self.assertEqual(out, "")
        self.assertIn("nope", err)

    def test_geneva_entry_is_pinned_with_hashes(self):
        cfg = ebi.BINARIES["geneva"]
        self.assertEqual(cfg["repo"], "avatarDD/geneva_c")
        self.assertEqual(cfg["archive_member"], "geneva")
        self.assertEqual(set(cfg["sha256_map"]), set(cfg["arch_map"]))
        for digest in cfg["sha256_map"].values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
