# tests/test_bypass_engine.py
"""
Тесты выбора движка обхода (core/bypass_engine.py): nfqws2 или geneva_c.

Работает ровно один движок. Проверяем, что переключение:
  * останавливает прежний движок и выключает его автозапуск, а его
    настройки запоминает в state/engines.json — вернуться можно в клик;
  * откатывается целиком, если новый движок не поднялся;
  * не идёт поверх сканера nfqws2 и подбора geneva;
и что nfqws2 не поднимается в обход выбора (nfqws_control отказывает),
а сканер и blockcheck на своё время останавливают geneva.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import bypass_engine as be


class FakeGeneva:
    """Менеджер geneva без процессов: только то, что зовёт bypass_engine."""

    def __init__(self):
        self.installed = True
        self.running = False
        self.job = False
        self.start_ok = True
        self.calls = []

    def detect(self):
        return {"installed": self.installed, "proto_ok": self.installed,
                "version": "1.0.0", "hint": ""}

    def is_running(self):
        return self.running

    def job_running(self):
        return self.job

    def start(self, strategy=""):
        self.calls.append("start")
        if not self.start_ok:
            return {"ok": False, "error": "exit 4"}
        self.running = True
        return {"ok": True, "pid": 1}

    def stop(self):
        self.calls.append("stop")
        self.running = False
        return {"ok": True}

    def search_status(self):
        return {"running": self.job, "status": "idle"}


class FakeNfqws:
    def __init__(self):
        self.running = True
        self.busy = {}
        self.calls = []

    def is_running(self):
        return self.running

    def start(self, source="control"):
        self.calls.append(("start", source))
        self.running = True
        return {"ok": True}

    def stop(self, source="control"):
        self.calls.append(("stop", source))
        self.running = False
        return {"ok": True}


class FakeAutostart:
    def __init__(self, cfg):
        self.cfg = cfg

    def enable(self):
        self.cfg.set("autostart", "enabled", True)
        return {"ok": True}

    def disable(self):
        self.cfg.set("autostart", "enabled", False)
        return {"ok": True}


class _Case(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="engine-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._saved_cm = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self.tmp)
        cm_mod._config_manager.load()
        self.addCleanup(setattr, cm_mod, "_config_manager", self._saved_cm)
        self.cfg = cm_mod._config_manager
        self.cfg.set("strategy", "current_id", "tls_multisplit")
        self.cfg.set("autostart", "enabled", True)
        self.cfg.set("geneva", "strategy", "[TCP:flags:PA]-duplicate-| \\/")

        self.ge = FakeGeneva()
        self.nf = FakeNfqws()
        auto = FakeAutostart(self.cfg)
        patches = [
            mock.patch("core.geneva_manager.get_geneva_manager",
                       return_value=self.ge),
            mock.patch("core.nfqws_control.running",
                       side_effect=lambda: self.nf.running),
            mock.patch("core.nfqws_control.busy",
                       side_effect=lambda: self.nf.busy),
            mock.patch("core.nfqws_control.start",
                       side_effect=lambda *a, **kw: self.nf.start(
                           kw.get("source", "control"))),
            mock.patch("core.nfqws_control.stop",
                       side_effect=lambda *a, **kw: self.nf.stop(
                           kw.get("source", "control"))),
            mock.patch("core.autostart_manager.get_autostart_manager",
                       return_value=auto),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class TestActive(_Case):

    def test_default_and_garbage(self):
        self.assertEqual(be.get_active(), "nfqws2")
        self.cfg.set("bypass", "engine", "something")
        self.assertEqual(be.get_active(), "nfqws2")
        self.cfg.set("bypass", "engine", "geneva")
        self.assertTrue(be.is_geneva_active())

    def test_unknown_target(self):
        self.assertFalse(be.switch("wireguard")["ok"])

    def test_aliases(self):
        self.assertTrue(be.switch("geneva_c")["ok"])
        self.assertEqual(be.get_active(), "geneva")
        self.assertTrue(be.switch("zapret2")["ok"])
        self.assertEqual(be.get_active(), "nfqws2")


class TestSwitch(_Case):

    def test_to_geneva_and_back_keeps_settings(self):
        res = be.switch("geneva")
        self.assertTrue(res["ok"], res)
        self.assertEqual(be.get_active(), "geneva")
        self.assertTrue(res["nfqws2_stopped"])
        self.assertEqual(self.nf.calls, [("stop", "engine_switch")])
        self.assertTrue(self.ge.running)
        # Автозапуск переехал вместе с движком.
        self.assertFalse(self.cfg.get("autostart", "enabled"))
        self.assertTrue(self.cfg.get("geneva", "autostart"))
        snaps = be.load_snapshots()
        self.assertEqual(snaps["nfqws2"]["strategy_id"], "tls_multisplit")
        self.assertTrue(snaps["nfqws2"]["running"])
        self.assertTrue(os.path.isfile(be.snapshot_path()))
        self.assertTrue(be.snapshot_path().startswith(self.tmp))

        res = be.switch("nfqws2")
        self.assertTrue(res["ok"], res)
        self.assertEqual(be.get_active(), "nfqws2")
        self.assertFalse(self.ge.running)
        self.assertTrue(self.nf.running)
        self.assertTrue(self.cfg.get("autostart", "enabled"))
        hist = be.load_snapshots()["history"]
        self.assertEqual([(h["from"], h["to"], h["ok"]) for h in hist],
                         [("nfqws2", "geneva", True),
                          ("geneva", "nfqws2", True)])
        # Рабочая стратегия geneva никуда не делась.
        self.assertEqual(self.cfg.get("geneva", "strategy"),
                         "[TCP:flags:PA]-duplicate-| \\/")

    def test_rollback_when_geneva_fails(self):
        self.ge.start_ok = False
        res = be.switch("geneva")
        self.assertFalse(res["ok"])
        self.assertTrue(res["rolled_back"])
        self.assertEqual(be.get_active(), "nfqws2")
        self.assertTrue(self.nf.running)
        self.assertTrue(self.cfg.get("autostart", "enabled"))
        self.assertFalse(self.cfg.get("geneva", "autostart"))
        self.assertFalse(be.load_snapshots()["history"][-1]["ok"])

    def test_no_strategy_can_switch_without_start(self):
        self.cfg.set("geneva", "strategy", "")
        res = be.switch("geneva")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "no_strategy")
        self.assertEqual(be.get_active(), "nfqws2")
        self.assertTrue(self.nf.running)
        res = be.switch("geneva", start=False)
        self.assertTrue(res["ok"], res)
        self.assertEqual(be.get_active(), "geneva")
        self.assertFalse(self.nf.running)
        self.assertNotIn("start", self.ge.calls)

    def test_not_installed(self):
        self.ge.installed = False
        res = be.switch("geneva")
        self.assertFalse(res["ok"])
        self.assertEqual(be.get_active(), "nfqws2")

    def test_refuses_while_scanner_or_search_runs(self):
        self.nf.busy = {"who": "scanner", "reason": "подбор стратегий"}
        res = be.switch("geneva")
        self.assertEqual(res["error_code"], "busy")
        self.nf.busy = {}
        self.ge.job = True
        res = be.switch("geneva")
        self.assertEqual(res["error_code"], "busy")
        self.assertEqual(be.get_active(), "nfqws2")
        self.assertEqual(self.nf.calls, [])

    def test_back_to_nfqws_that_was_stopped_stays_stopped(self):
        self.nf.running = False
        self.assertTrue(be.switch("geneva")["ok"])
        res = be.switch("nfqws2")
        self.assertTrue(res["ok"])
        self.assertFalse(res["started"])
        self.assertFalse(self.nf.running)

    def test_overview(self):
        with mock.patch("core.strategy_scanner.get_strategy_scanner") as sc:
            sc.return_value.saved_resume_info.return_value = {
                "target": "x.example", "next_index": 40}
            out = be.overview()
        self.assertEqual(out["active"], "nfqws2")
        self.assertEqual(out["nfqws2"]["scan_resume"]["next_index"], 40)
        self.assertTrue(out["geneva"]["installed"])


class TestPauseForSearch(_Case):

    def test_pauses_nfqws2_and_returns_it(self):
        self.assertEqual(be.pause_for_search(), "nfqws2")
        self.assertFalse(self.nf.running)
        be.resume_after_search("nfqws2")
        self.assertTrue(self.nf.running)

    def test_busy_nfqws2_is_not_touched(self):
        self.nf.busy = {"who": "blockcheck"}
        self.assertEqual(be.pause_for_search(), "busy")
        self.assertTrue(self.nf.running)

    def test_geneva_paused_and_returned(self):
        self.cfg.set("bypass", "engine", "geneva")
        self.nf.running = False
        self.ge.running = True
        self.assertEqual(be.pause_for_search(), "geneva")
        self.assertFalse(self.ge.running)
        be.resume_after_search("geneva")
        self.assertTrue(self.ge.running)

    def test_switched_meanwhile_is_not_resurrected(self):
        self.assertEqual(be.pause_for_search(), "nfqws2")
        self.cfg.set("bypass", "engine", "geneva")
        be.resume_after_search("nfqws2")
        self.assertFalse(self.nf.running)


class TestNfqwsGuards(_Case):

    def test_refusal(self):
        self.assertEqual(be.nfqws_refusal("control"), {})
        self.cfg.set("bypass", "engine", "geneva")
        self.assertEqual(be.nfqws_refusal("control")["error_code"],
                         "engine_geneva")
        self.assertEqual(be.nfqws_refusal("engine_switch"), {})

    def test_hold_geneva_for_scanner(self):
        self.cfg.set("bypass", "engine", "geneva")
        self.ge.running = True
        self.assertEqual(be.hold_geneva_for("scanner"), "paused")
        self.assertFalse(self.ge.running)
        be.release_geneva_hold("scanner")
        self.assertTrue(self.ge.running)
        self.ge.job = True
        self.assertEqual(be.hold_geneva_for("scanner"), "busy")

    def test_release_respects_engine_change(self):
        self.cfg.set("bypass", "engine", "geneva")
        self.ge.running = True
        be.hold_geneva_for("blockcheck")
        self.cfg.set("bypass", "engine", "nfqws2")
        be.release_geneva_hold("blockcheck")
        self.assertFalse(self.ge.running)


class TestSessionStopsGeneva(_Case):
    """Сканер берёт общий мьютекс nfqws2 — на это время geneva стоит."""

    def setUp(self):
        super().setUp()
        from core import nfqws_session
        self.ns = nfqws_session
        self.session = nfqws_session.NfqwsSession()
        p = mock.patch.object(self.session, "_lock_path", return_value="")
        p.start()
        self.addCleanup(p.stop)

    def test_scanner_pauses_and_returns_geneva(self):
        self.cfg.set("bypass", "engine", "geneva")
        self.ge.running = True
        with self.session.acquire(self.ns.OWNER_SCANNER):
            self.assertFalse(self.ge.running)
        self.assertTrue(self.ge.running)

    def test_ui_does_not_touch_geneva(self):
        self.cfg.set("bypass", "engine", "geneva")
        self.ge.running = True
        with self.session.acquire(self.ns.OWNER_UI):
            self.assertTrue(self.ge.running)
        self.assertEqual(self.ge.calls, [])

    def test_geneva_search_makes_scanner_busy(self):
        self.ge.job = True
        with self.assertRaises(self.ns.SessionBusy) as ctx:
            with self.session.acquire(self.ns.OWNER_SCANNER):
                pass
        self.assertIn("geneva", str(ctx.exception))
        # Захват отпущен — следующий берёт без помех.
        self.ge.job = False
        with self.session.acquire(self.ns.OWNER_SCANNER):
            pass


if __name__ == "__main__":
    unittest.main()
