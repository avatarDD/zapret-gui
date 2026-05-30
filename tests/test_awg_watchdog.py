# tests/test_awg_watchdog.py
"""
Unit-тесты для core/awg_watchdog.py — pure logic (без фонового потока).
"""

import time
import unittest
from unittest import mock

from core import awg_watchdog


class FakeConfigManager:
    def __init__(self, data=None):
        self.data = data or {}

    def load(self):
        return self.data


class TestGetSettings(unittest.TestCase):

    def test_defaults(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = awg_watchdog._get_settings()
            self.assertFalse(s["enabled"])
            self.assertEqual(s["handshake_timeout_sec"],
                             awg_watchdog.DEFAULT_HANDSHAKE_TIMEOUT_SEC)
            self.assertEqual(s["check_interval_sec"],
                             awg_watchdog.DEFAULT_CHECK_INTERVAL_SEC)
            self.assertEqual(s["max_restarts_per_hour"],
                             awg_watchdog.DEFAULT_MAX_RESTARTS_PER_HOUR)

    def test_custom(self):
        cfg = {"awg": {"watchdog": {
            "enabled": True,
            "handshake_timeout_sec": 600,
            "check_interval_sec": 60,
        }}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager(cfg)):
            s = awg_watchdog._get_settings()
            self.assertTrue(s["enabled"])
            self.assertEqual(s["handshake_timeout_sec"], 600)
            self.assertEqual(s["check_interval_sec"], 60)


class TestMaybeRestart(unittest.TestCase):
    """Pure-логика принятия решения о рестарте."""

    def _watchdog(self):
        return awg_watchdog.AwgWatchdog()

    def _settings(self, **over):
        base = {
            "handshake_timeout_sec": 180,
            "check_interval_sec":    30,
            "cooldown_sec":          300,
            "max_restarts_per_hour": 6,
            "enabled": True,
        }
        base.update(over)
        return base

    def test_skip_if_no_peers(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        status = {"peers": []}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=time.time())
        mgr.restart.assert_not_called()

    def test_skip_if_no_handshake(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        status = {"peers": [{"latest_handshake": 0}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=time.time())
        mgr.restart.assert_not_called()

    def test_skip_if_handshake_fresh(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        now = int(time.time())
        status = {"peers": [{"latest_handshake": now - 30}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=now)
        mgr.restart.assert_not_called()

    def test_restarts_when_stale(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        now = int(time.time())
        status = {"peers": [{"latest_handshake": now - 1000}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=now)
        mgr.restart.assert_called_once_with("awg0")

    def test_cooldown_blocks_restart(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        now = time.time()
        wd._last_restart["awg0"] = now - 60   # 60с назад — cooldown 300с
        status = {"peers": [{"latest_handshake": int(now) - 1000}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=now)
        mgr.restart.assert_not_called()

    def test_rate_limit_blocks_restart(self):
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        now = time.time()
        # Уже было 6 рестартов в последний час — лимит исчерпан.
        wd._restart_log["awg0"] = [now - i * 100 for i in range(6)]
        status = {"peers": [{"latest_handshake": int(now) - 1000}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=now)
        mgr.restart.assert_not_called()

    def test_picks_latest_handshake_across_peers(self):
        # Несколько peer'ов; самый свежий — недавно → не рестартим.
        wd  = self._watchdog()
        mgr = mock.MagicMock()
        now = int(time.time())
        status = {"peers": [
            {"latest_handshake": now - 1000},
            {"latest_handshake": now - 5},   # свежий
        ]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(),
                          now=now)
        mgr.restart.assert_not_called()


class TestStatus(unittest.TestCase):

    def test_status_includes_required_fields(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            wd = awg_watchdog.AwgWatchdog()
            s = wd.get_status()
            self.assertIn("enabled", s)
            self.assertIn("running", s)
            self.assertIn("settings", s)
            self.assertIn("restarts_last_hour", s)


if __name__ == "__main__":
    unittest.main()


class TestDecideRestart(unittest.TestCase):
    """Решение о рестарте: handshake-age + активная проба через туннель."""

    def test_fresh_handshake_no_probe(self):
        should, _ = awg_watchdog.decide_restart(
            handshake_age=10, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2)
        self.assertFalse(should)

    def test_stale_handshake_restarts(self):
        should, reason = awg_watchdog.decide_restart(
            handshake_age=200, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2)
        self.assertTrue(should)
        self.assertIn("handshake", reason)

    def test_no_handshake_yet_holds(self):
        should, _ = awg_watchdog.decide_restart(
            handshake_age=None, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2)
        self.assertFalse(should)

    def test_probe_fail_restarts_even_with_fresh_handshake(self):
        should, reason = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=True, probe_consecutive_fails=2, probe_threshold=2)
        self.assertTrue(should)
        self.assertIn("проба", reason)

    def test_probe_below_threshold_holds(self):
        should, _ = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=True, probe_consecutive_fails=1, probe_threshold=2)
        self.assertFalse(should)

    def test_probe_disabled_ignores_fails(self):
        should, _ = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=9, probe_threshold=2)
        self.assertFalse(should)


class TestProbeSettings(unittest.TestCase):

    def test_probe_defaults_present(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = awg_watchdog._get_settings()
        self.assertIn("probe_enabled", s)
        self.assertEqual(s["probe_enabled"], False)
        self.assertIn("probe_host", s)
        self.assertIn("probe_fail_threshold", s)
