# tests/test_mihomo_watchdog.py
"""
Unit-тесты core/mihomo_watchdog.py — чистая логика и интеграция _maybe_restart
(без фонового потока и без бинаря mihomo).
"""

import time
import unittest
from unittest import mock

from core import mihomo_watchdog
from core.clash_yaml import dump_yaml


class FakeConfigManager:
    def __init__(self, data=None):
        self.data = data or {}

    def load(self):
        return self.data


class TestGetSettings(unittest.TestCase):

    def test_defaults(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = mihomo_watchdog._get_settings()
        self.assertFalse(s["enabled"])
        self.assertEqual(s["check_interval_sec"],
                         mihomo_watchdog.DEFAULT_CHECK_INTERVAL_SEC)
        self.assertEqual(s["probe_fail_threshold"],
                         mihomo_watchdog.DEFAULT_PROBE_FAIL_THRESHOLD)

    def test_custom(self):
        cfg = {"mihomo": {"watchdog": {
            "enabled": True, "check_interval_sec": 30,
            "probe_fail_threshold": 3}}}
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager(cfg)):
            s = mihomo_watchdog._get_settings()
        self.assertTrue(s["enabled"])
        self.assertEqual(s["check_interval_sec"], 30)
        self.assertEqual(s["probe_fail_threshold"], 3)


class TestDecideRestart(unittest.TestCase):

    def test_holds_below_threshold(self):
        should, _ = mihomo_watchdog.decide_restart(
            probe_fails=1, probe_threshold=2)
        self.assertFalse(should)

    def test_restarts_at_threshold(self):
        should, reason = mihomo_watchdog.decide_restart(
            probe_fails=2, probe_threshold=2)
        self.assertTrue(should)
        self.assertIn("проба", reason)

    def test_threshold_floor_is_one(self):
        should, _ = mihomo_watchdog.decide_restart(
            probe_fails=1, probe_threshold=0)
        self.assertTrue(should)


class _FakeResp:
    def __init__(self, code, body):
        self._code = code
        self._body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getcode(self):
        return self._code

    def read(self):
        return self._body


class TestProbeProxy(unittest.TestCase):

    EP = {"host": "127.0.0.1", "port": 9090, "secret": "s"}

    def test_ok_on_delay(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResp(200, '{"delay": 120}')):
            self.assertTrue(mihomo_watchdog.probe_proxy(
                self.EP, "PROXY", "http://x/generate_204", 5000))

    def test_fail_on_error_body(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResp(200, '{"message": "timeout"}')):
            self.assertFalse(mihomo_watchdog.probe_proxy(
                self.EP, "PROXY", "http://x/generate_204", 5000))

    def test_fail_on_connection_error(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=OSError("refused")):
            self.assertFalse(mihomo_watchdog.probe_proxy(
                self.EP, "PROXY", "http://x/generate_204", 5000))

    def test_empty_args(self):
        self.assertFalse(mihomo_watchdog.probe_proxy({}, "", "u", 1000))


class TestMaybeRestart(unittest.TestCase):
    """Интеграция: cooldown / порог проб / rate-limit / рестарт."""

    CFG_TEXT = dump_yaml({
        "external-controller": "127.0.0.1:9090",
        "secret": "x",
        "proxies": [{"name": "s1", "type": "vless", "server": "a", "port": 1}],
        "proxy-groups": [{"name": "PROXY", "type": "select",
                          "proxies": ["s1"]}],
    })

    def _settings(self, **over):
        base = {
            "check_interval_sec": 60, "cooldown_sec": 300,
            "max_restarts_per_hour": 6, "probe_target": "cloudflare",
            "probe_timeout_ms": 5000, "probe_fail_threshold": 2,
            "enabled": True,
        }
        base.update(over)
        return base

    def _mgr(self):
        mgr = mock.MagicMock()
        mgr.get_config.return_value = {"ok": True, "text": self.CFG_TEXT}
        return mgr

    def test_restarts_after_threshold_fails(self):
        wd = mihomo_watchdog.MihomoWatchdog()
        mgr = self._mgr()
        now = time.time()
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=False):
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
            mgr.restart.assert_not_called()
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
            mgr.restart.assert_called_once_with("vpn")

    def test_ok_probe_resets_fails(self):
        wd = mihomo_watchdog.MihomoWatchdog()
        mgr = self._mgr()
        now = time.time()
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=False):
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=True):
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
        self.assertEqual(wd._probe_fails.get("vpn"), 0)
        mgr.restart.assert_not_called()

    def test_cooldown_blocks(self):
        wd = mihomo_watchdog.MihomoWatchdog()
        mgr = self._mgr()
        now = time.time()
        wd._last_restart["vpn"] = now - 60     # cooldown 300с
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=False):
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
        mgr.restart.assert_not_called()

    def test_skip_without_controller(self):
        wd = mihomo_watchdog.MihomoWatchdog()
        mgr = mock.MagicMock()
        # Конфиг без external-controller / proxy-group — проверять нечем.
        mgr.get_config.return_value = {"ok": True, "text": dump_yaml({
            "proxies": [{"name": "s1", "type": "vless"}]})}
        now = time.time()
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=False) as p:
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
        p.assert_not_called()
        mgr.restart.assert_not_called()

    def test_rate_limit_blocks(self):
        wd = mihomo_watchdog.MihomoWatchdog()
        mgr = self._mgr()
        now = time.time()
        wd._restart_log["vpn"] = [now - i * 100 for i in range(6)]
        with mock.patch("core.mihomo_watchdog.probe_proxy",
                        return_value=False):
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
            wd._maybe_restart(mgr, "vpn", self._settings(), now)
        mgr.restart.assert_not_called()


class TestStatus(unittest.TestCase):

    def test_status_fields(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = mihomo_watchdog.MihomoWatchdog().get_status()
        for k in ("enabled", "running", "settings", "restarts_last_hour"):
            self.assertIn(k, s)


if __name__ == "__main__":
    unittest.main()
