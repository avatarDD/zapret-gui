# tests/test_file_history.py
"""История файлов (core/file_history) и применение с проверкой
(core/safe_apply): версии, склейка, правки вне GUI, откат, отмена."""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import file_history as fh
from core import safe_apply as sa
from core.safe_io import atomic_write_text, remove_write_observer


class HistoryCase(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm
        self.dir = tempfile.mkdtemp(prefix="hist-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager
        self.lists = os.path.join(self.dir, "lists")
        os.makedirs(self.lists)
        patcher = mock.patch.object(
            fh, "_roots", lambda: [(self.lists, "lists", ".txt")])
        patcher.start()
        self.addCleanup(patcher.stop)
        fh._reset_for_tests()
        self.addCleanup(fh._reset_for_tests)
        fh.install()
        self.addCleanup(self._uninstall)
        # Без перечитывания движка/стратегий в тестах.
        p2 = mock.patch.object(fh, "_after_restore", lambda paths: [])
        p2.start()
        self.addCleanup(p2.stop)

    def _uninstall(self):
        remove_write_observer(fh._observer)
        fh._installed = False

    def path(self, name):
        return os.path.join(self.lists, name)

    def write(self, name, text):
        atomic_write_text(self.path(name), text, mode=0o644)

    def read(self, name):
        with open(self.path(name), encoding="utf-8") as f:
            return f.read()

    def entries(self):
        return fh._load()["entries"]


class TestRecord(HistoryCase):

    def test_tracked_and_untracked(self):
        self.assertTrue(fh.is_tracked(self.path("a.txt")))
        self.assertFalse(fh.is_tracked(self.path(".a.remote")))
        self.assertFalse(fh.is_tracked(self.path("unified-x.txt")))
        self.assertFalse(fh.is_tracked(self.path("a.json")))
        self.assertTrue(fh.is_tracked(self.cfg.path))

    def test_write_creates_version_and_diff(self):
        self.write("a.txt", "one\n")
        with fh.operation("правка"):
            self.write("a.txt", "one\ntwo\n")
        e = self.entries()[-1]
        self.assertEqual(e["file"], "lists/a.txt")
        self.assertEqual(e["label"], "правка")
        d = fh.diff(e["id"])
        self.assertTrue(d["ok"])
        self.assertIn("+two", d["diff"])

    def test_coalesce_quick_writes(self):
        self.write("a.txt", "1\n")
        self.write("a.txt", "2\n")
        self.write("a.txt", "3\n")
        items = [e for e in self.entries() if e["file"] == "lists/a.txt"]
        self.assertEqual(len(items), 1)
        self.assertIsNone(items[0]["before"])

    def test_write_back_to_original_drops_version(self):
        self.write("a.txt", "1\n")
        with fh.operation("x"):
            self.write("a.txt", "2\n")
        self.write("b.txt", "z\n")
        n = len(self.entries())
        self.write("b.txt", "y\n")      # склеится с созданием b
        self.assertEqual(len(self.entries()), n)

    def test_per_file_cap(self):
        for i in range(fh.PER_FILE + 5):
            with fh.operation("v%d" % i):
                self.write("a.txt", "%d\n" % i)
        items = [e for e in self.entries() if e["file"] == "lists/a.txt"]
        self.assertEqual(len(items), fh.PER_FILE)

    def test_settings_volatile_only_not_versioned(self):
        self.cfg.save()
        n = len(self.entries())
        self.cfg.set("history", "last_note", "x")
        self.cfg.save()
        self.assertEqual(len(self.entries()), n)
        with fh.operation("настройка"):
            self.cfg.set("history", "max_mb", 4)
            self.cfg.save()
        self.assertEqual(self.entries()[-1]["label"], "настройка")

    def test_settings_diff_masks_secrets(self):
        self.cfg.save()
        with fh.operation("токен"):
            self.cfg.set("mcp", "token", "supersecret-value-123")
            self.cfg.save()
        d = fh.diff(self.entries()[-1]["id"])
        self.assertNotIn("supersecret-value-123", d["diff"])

    def test_settings_version_names_changed_sections(self):
        # «Не нашёл в истории про awg»: версия settings.json подписана
        # разделами, которые в ней поменялись.
        self.cfg.save()
        fh.checkpoint()
        self.cfg.set("awg", "autostart", {"interfaces": {"WARPv1_30": False}})
        self.cfg.set("strategy", "current_id", "x")
        self.cfg.set("strategy", "last_applied_at", 1)   # отметка — не в счёт
        self.cfg.save()
        e = self.entries()[-1]
        self.assertEqual(e["sections"], ["awg", "strategy"])
        self.assertEqual(e["label"], "Изменён settings.json: awg, strategy")
        public = fh.list_entries()["groups"][0]["entries"][0]
        self.assertEqual(public["sections"], ["awg", "strategy"])

    def test_old_versions_expire(self):
        self.write("a.txt", "1\n")
        with fh.operation("старая"):
            self.write("a.txt", "2\n")
        for e in self.entries():
            e["ts"] -= 40 * 86400
        with fh.operation("новая"):
            self.write("a.txt", "3\n")
        labels = [e["label"] for e in self.entries()]
        self.assertEqual(labels, ["новая"])

    def test_zero_days_means_no_age_limit(self):
        self.cfg.set("history", "max_days", 0)
        with fh.operation("старая"):
            self.write("a.txt", "1\n")
        for e in self.entries():
            e["ts"] -= 4000 * 86400
        with fh.operation("новая"):
            self.write("a.txt", "2\n")
        self.assertEqual(len(self.entries()), 2)

    def test_remove_and_rename(self):
        self.write("a.txt", "1\n")
        with fh.operation("x"):
            self.write("a.txt", "2\n")
        fh.remove_file(self.path("a.txt"))
        self.assertTrue(self.entries()[-1]["after"] is None)
        self.write("b.txt", "q\n")
        fh.rename_file(self.path("b.txt"), self.path("c.txt"))
        last = [e for e in self.entries() if e["op"] == self.entries()[-1]["op"]]
        self.assertEqual({e["file"] for e in last}, {"lists/b.txt", "lists/c.txt"})


class TestExternal(HistoryCase):

    def test_baseline_then_external_edit(self):
        with open(self.path("a.txt"), "w") as f:
            f.write("old\n")
        r = fh.scan()
        self.assertEqual(r.get("baseline"), 2)   # settings.json + a.txt
        with open(self.path("a.txt"), "w") as f:
            f.write("new\n")
        r = fh.scan()
        self.assertEqual(r["files"], ["lists/a.txt"])
        e = self.entries()[-1]
        self.assertEqual(e["source"], "external")
        self.assertIn("-old", fh.diff(e["id"])["diff"])

    def test_external_delete(self):
        with open(self.path("a.txt"), "w") as f:
            f.write("x\n")
        fh.scan()
        os.remove(self.path("a.txt"))
        fh.scan()
        self.assertIsNone(self.entries()[-1]["after"])
        r = fh.restore(self.entries()[-1]["id"])
        self.assertTrue(r["ok"])
        self.assertEqual(self.read("a.txt"), "x\n")

    def test_non_atomic_edit_caught_on_next_write(self):
        fh.scan()
        self.write("a.txt", "1\n")
        with open(self.path("a.txt"), "w") as f:     # мимо safe_io
            f.write("hand\n")
        with fh.operation("gui"):
            self.write("a.txt", "2\n")
        sources = [e["source"] for e in self.entries()
                   if e["file"] == "lists/a.txt"]
        self.assertEqual(sources[-2:], ["external", "gui"])


class TestRestore(HistoryCase):

    def test_restore_before(self):
        self.write("a.txt", "1\n")
        with fh.operation("x"):
            self.write("a.txt", "2\n")
        r = fh.restore(self.entries()[-1]["id"], "before")
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read("a.txt"), "1\n")
        self.assertEqual(self.entries()[-1]["source"], "restore")

    def test_undo_last_whole_operation(self):
        self.write("a.txt", "a1\n")
        self.write("b.txt", "b1\n")
        with fh.operation("обе"):
            self.write("a.txt", "a2\n")
            self.write("b.txt", "b2\n")
        r = fh.undo_last()
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read("a.txt"), "a1\n")
        self.assertEqual(self.read("b.txt"), "b1\n")
        # Откат сам не отменяется «отменой последнего» — отменится
        # действие до него (здесь — создание b.txt).
        self.assertIn("b.txt", fh._undo_candidate_public()["label"])

    def test_undo_skips_file_changed_since(self):
        self.write("a.txt", "a1\n")
        with fh.operation("правка"):
            self.write("a.txt", "a2\n")
        with open(self.path("a.txt"), "w") as f:
            f.write("hand\n")
        r = fh.undo_last()
        self.assertFalse(r["ok"])
        self.assertEqual(r["skipped"], ["lists/a.txt"])

    def test_restore_to_time(self):
        self.write("a.txt", "a1\n")
        with fh.operation("x"):
            self.write("a.txt", "a1b\n")
        time.sleep(0.01)
        t = time.time()
        time.sleep(0.01)
        with fh.operation("y"):
            self.write("a.txt", "a2\n")
            self.write("n.txt", "new\n")
        self.assertEqual(sorted(fh.changed_since(t)),
                         ["lists/a.txt", "lists/n.txt"])
        r = fh.restore_to(t)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read("a.txt"), "a1b\n")
        self.assertFalse(os.path.exists(self.path("n.txt")))
        self.assertEqual(fh.changed_since(t), [])


class TestReviewEdges(HistoryCase):

    def test_checkpoint_stops_coalescing(self):
        self.write("a.txt", "1\n")
        fh.checkpoint()
        time.sleep(0.01)
        t = time.time()
        time.sleep(0.01)
        self.write("a.txt", "2\n")         # без checkpoint склеилась бы
        r = fh.restore_to(t)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.read("a.txt"), "1\n")

    def test_file_grown_past_limit_is_not_deleted(self):
        with open(self.path("big.txt"), "w") as f:
            f.write("small\n")
        fh.scan()
        with mock.patch.object(fh, "MAX_FILE_BYTES", 10):
            with open(self.path("big.txt"), "w") as f:
                f.write("x" * 50)
            r = fh.scan()
            self.assertEqual(r["changed"], 0)
            self.assertNotIn(fh._norm(self.path("big.txt")),
                             fh._load()["known"])
            # Откат «к прошлому» большой файл не затирает.
            res = fh._apply({fh._norm(self.path("big.txt")): None}, "t")
            self.assertTrue(os.path.exists(self.path("big.txt")))
            self.assertTrue(res["notes"])

    def test_oversized_write_forgets_known(self):
        fh.scan()
        self.write("a.txt", "1\n")
        with mock.patch.object(fh, "MAX_FILE_BYTES", 5):
            self.write("a.txt", "x" * 20)
        self.assertNotIn(fh._norm(self.path("a.txt")), fh._load()["known"])
        n = len(self.entries())
        self.write("a.txt", "2\n")
        self.assertFalse(any(e["source"] == "external"
                             for e in self.entries()[n:]))

    def test_budget_ignores_current_copies(self):
        self.write("a.txt", "1\n")
        with fh.operation("x"):
            self.write("a.txt", "2\n")
        with mock.patch.object(fh, "_max_bytes", lambda: 1):
            # Текущая копия одна больше бюджета — прошлые версии уходят,
            # но сама история не обнуляется из-за текущих копий.
            fh._gc(fh._load())
        self.assertLessEqual(len(self.entries()), 1)
        with mock.patch.object(fh, "_max_bytes", lambda: 10 ** 9):
            with fh.operation("y"):
                self.write("a.txt", "3\n")
            fh._gc(fh._load())
        self.assertTrue(self.entries())


class TestSafeApplyCompare(unittest.TestCase):

    def test_targets_from_healthcheck(self):
        # Настоящая функция, без подмены: имя класса мониторинга менялось.
        with mock.patch.object(sa, "_cfg") as cfg:
            cfg.return_value.get.side_effect = (
                lambda *k, default=None: ["x.test"]
                if k == ("healthcheck", "custom_domains") else default)
            self.assertEqual([t["display"] for t in sa._targets()],
                             ["x.test"])

    def test_broken_all(self):
        v = sa.compare({"sites": {"a": True, "b": True, "c": False}},
                       {"sites": {"a": False, "b": False, "c": True}})
        self.assertTrue(v["broken_all"])
        self.assertEqual(v["lost"], ["a", "b"])
        self.assertEqual(v["gained"], ["c"])

    def test_partial_loss_not_broken_all(self):
        v = sa.compare({"sites": {"a": True, "b": True}},
                       {"sites": {"a": True, "b": False}})
        self.assertFalse(v["broken_all"])

    def test_nothing_worked_before(self):
        v = sa.compare({"sites": {"a": False}}, {"sites": {"a": False}})
        self.assertFalse(v["broken_all"])


class FakeEngine:
    def __init__(self, running=True, args=None):
        self.running = running
        self.args = list(args or ["--old"])

    def is_running(self):
        return self.running

    def get_last_args(self):
        return list(self.args)


class TestSafeApplyFlow(HistoryCase):

    def setUp(self):
        super().setUp()
        self.eng = FakeEngine()
        self.calls = []
        patches = [
            mock.patch.object(sa, "_engine", lambda: self.eng),
            mock.patch.object(sa, "SETTLE_SEC", 0),
            mock.patch.object(sa, "_regen_autostart", lambda: None),
            mock.patch.object(sa, "_restart_engine", self._restart),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.cfg.set("strategy", "current_id", "old")
        self.cfg.set("strategy", "current_name", "Old")
        self.cfg.save()
        sa._changed_cache["key"] = None

    def _restart(self, was_running, args):
        self.calls.append(("restart", was_running, args))
        return {"ok": True}

    def _fake_apply(self, sid, source=""):
        self.cfg.set("strategy", "current_id", sid)
        self.cfg.save()
        self.eng.args = ["--new"]
        return {"ok": True}

    def _session(self):
        return sa._read().get("session") or {}

    def _run(self, before, after, **kw):
        probes = iter([before, after])
        from core import nfqws_control
        from core.strategy_builder import get_strategy_manager
        with mock.patch.object(sa, "probe", lambda: next(probes)), \
                mock.patch.object(nfqws_control, "apply_strategy",
                                  self._fake_apply), \
                mock.patch.object(get_strategy_manager(), "get_strategy",
                                  lambda sid: {"id": sid, "name": "New"}), \
                mock.patch.object(sa, "_wait", lambda: None):
            r = sa.start("new", 60, **kw)
            self.assertTrue(r["ok"], r)
            sa._thread.join(5)

    def test_broken_all_rolls_back(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": False}})
        s = self._session()
        self.assertEqual(s["phase"], "rolled_back")
        self.cfg.load()
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")
        self.assertEqual(self.calls, [("restart", True, ["--old"])])

    def test_waiting_then_confirm_marks_working(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        self.assertEqual(self._session()["phase"], "waiting")
        r = sa.confirm()
        self.assertTrue(r["ok"])
        st = sa.status()
        self.assertEqual(st["session"]["phase"], "confirmed")
        self.assertEqual(st["working"]["strategy_id"], "new")
        self.assertEqual(st["working"]["args"], ["--new"])

    def test_rollback_keeps_unrelated_settings(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        self.cfg.set("history", "max_mb", 3)
        self.cfg.save()
        sa.cancel()
        self.cfg.load()
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")
        self.assertEqual(self.cfg.get("history", "max_mb"), 3)

    def test_rollback_without_history(self):
        self.cfg.set("history", "enabled", False)
        self.cfg.save()
        self._run({"sites": {"a": True}}, {"sites": {"a": False}})
        self.cfg.load()
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")

    def test_double_rollback_runs_once(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        sa._update(phase="rolling_back")
        r = sa._rollback("второй")
        self.assertEqual(r.get("already"), "rolling_back")
        self.assertEqual(self.calls, [])

    def _run_auto(self, before, after):
        probes = iter([before, after])
        from core import nfqws_control
        from core.strategy_builder import get_strategy_manager
        with mock.patch.object(sa, "probe", lambda: next(probes)), \
                mock.patch.object(nfqws_control, "apply_strategy",
                                  self._fake_apply), \
                mock.patch.object(get_strategy_manager(), "get_strategy",
                                  lambda sid: {"id": sid, "name": "New"}):
            r = sa.start("new", 60, auto_target="a")
            self.assertTrue(r["ok"], r)
            sa._thread.join(5)

    def test_auto_target_opened_keeps(self):
        self._run_auto({"sites": {"a": False, "b": True}},
                       {"sites": {"a": True, "b": True}})
        st = sa.status()
        self.assertEqual(st["session"]["phase"], "confirmed")
        self.assertEqual(st["working"]["strategy_id"], "new")

    def test_auto_regression_rolls_back(self):
        self._run_auto({"sites": {"a": False, "b": True}},
                       {"sites": {"a": True, "b": False}})
        self.assertEqual(self._session()["phase"], "rolled_back")
        self.cfg.load()
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")

    def test_manual_rollback(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        r = sa.cancel()
        self.assertTrue(r["ok"], r)
        self.cfg.load()
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")

    def test_recover_expired_rolls_back(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        sa._update(deadline=time.time() - 1)
        sa.recover()
        self.assertEqual(self._session()["phase"], "rolled_back")

    def test_second_start_refused_while_waiting(self):
        self._run({"sites": {"a": True}}, {"sites": {"a": True}})
        from core.strategy_builder import get_strategy_manager
        with mock.patch.object(get_strategy_manager(), "get_strategy",
                               lambda sid: {"id": sid, "name": "X"}):
            r = sa.start("other")
        self.assertEqual(r.get("error_code"), "busy")

    def test_restore_working(self):
        sa.mark_working("тест")
        time.sleep(0.01)
        with fh.operation("потом"):
            self.write("a.txt", "later\n")
        self.assertIn("lists/a.txt", sa.status()["changed_since_working"])
        r = sa.restore_working()
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(self.path("a.txt")))


    def test_rollback_returns_files_written_before_start(self):
        # Вызывающий (замер по сетям) пишет список ДО старта проверки:
        # откат возвращает его к моменту since, а не к началу проверки.
        with fh.operation("было"):
            self.write("a.txt", "v1\n")
        fh.checkpoint()
        since = time.time()
        time.sleep(0.01)
        with fh.operation("замер"):
            self.write("a.txt", "v2\n")
        self._run({"sites": {"a": True}}, {"sites": {"a": False}},
                  since=since, paths=[self.path("a.txt")])
        self.assertEqual(self._session()["phase"], "rolled_back")
        self.assertEqual(self.read("a.txt"), "v1\n")

    def test_restore_working_keeps_other_settings(self):
        sa.mark_working("тест")
        time.sleep(0.01)
        self.cfg.set("strategy", "current_id", "other")
        self.cfg.set("history", "max_mb", 3)
        self.cfg.save()
        r = sa.restore_working()
        self.assertTrue(r["ok"], r)
        self.cfg.load()
        # Выбор стратегии вернулся, чужая правка настроек — осталась.
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old")
        self.assertEqual(self.cfg.get("history", "max_mb"), 3)


class TestIncomplete(HistoryCase):

    def test_trimmed_history_is_reported(self):
        ts = time.time()
        for i in range(fh.PER_FILE + 2):
            with fh.operation("v%d" % i):
                self.write("a.txt", "v%d\n" % i)
            fh.checkpoint()
        self.assertTrue(fh.incomplete_since(ts - 60))
        self.assertTrue(fh.incomplete_since(ts - 60, {self.path("a.txt")}))
        self.assertEqual(fh.incomplete_since(ts - 60, {"/nope"}), [])
        self.assertEqual(fh.incomplete_since(time.time() + 60), [])

    def test_scan_rereads_under_lock(self):
        # Содержимое, прочитанное до замка, устарело: GUI успел записать.
        fh.scan()
        with fh.operation("gui"):
            self.write("a.txt", "v1\n")
        before = len(self.entries())
        real = fh._read
        first = {"done": False}

        def stale(p):
            if p == self.path("a.txt") and not first["done"]:
                first["done"] = True
                return b"v0\n"
            return real(p)

        with mock.patch.object(fh, "_read", stale):
            r = fh.scan()
        self.assertTrue(first["done"])
        self.assertEqual(r["changed"], 0, r)
        self.assertEqual(len(self.entries()), before)


if __name__ == "__main__":
    unittest.main()
