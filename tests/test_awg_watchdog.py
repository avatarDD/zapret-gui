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


class TestRxStallSettings(unittest.TestCase):

    def test_rx_stall_defaults(self):
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=FakeConfigManager({})):
            s = awg_watchdog._get_settings()
        # rx-stall детектор включён по умолчанию — это главный сигнал.
        self.assertTrue(s["rx_stall_enabled"])
        self.assertEqual(s["rx_stall_timeout_sec"],
                         awg_watchdog.DEFAULT_RX_STALL_TIMEOUT_SEC)
        self.assertEqual(s["rx_stall_min_tx_bytes"],
                         awg_watchdog.DEFAULT_RX_STALL_MIN_TX_BYTES)


class TestEvalRxStall(unittest.TestCase):
    """Пассивный детектор «приём встал» (чистая функция)."""

    def _eval(self, state, rx, tx, now, timeout=120, min_tx=4096):
        return awg_watchdog.eval_rx_stall(
            state, rx, tx, now, timeout=timeout, min_tx=min_tx)

    def test_first_sample_rebaselines(self):
        state, stalled = self._eval(None, 1000, 2000, now=100.0)
        self.assertFalse(stalled)
        self.assertEqual(state["rx"], 1000)
        self.assertEqual(state["tx_at_rx"], 2000)
        self.assertEqual(state["rx_ts"], 100.0)

    def test_rx_progress_resets(self):
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 0.0}
        # rx вырос → приняли данные → не застой, отсчёт от текущего tx/now.
        state, stalled = self._eval(prev, 1500, 9000, now=300.0)
        self.assertFalse(stalled)
        self.assertEqual(state["rx"], 1500)
        self.assertEqual(state["tx_at_rx"], 9000)
        self.assertEqual(state["rx_ts"], 300.0)

    def test_idle_does_not_stall(self):
        # rx и tx стоят (нет трафика вообще) — это простой, не зависание.
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 0.0}
        _state, stalled = self._eval(prev, 1000, 2000, now=10_000.0)
        self.assertFalse(stalled)

    def test_keepalive_noise_does_not_stall(self):
        # rx стоит, но отправлено всего ~300 байт (keepalive) < min_tx=4096.
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 0.0}
        _state, stalled = self._eval(prev, 1000, 2300, now=10_000.0)
        self.assertFalse(stalled)

    def test_stall_fires_when_sending_but_silent(self):
        # rx стоит, отправлено > min_tx, прошло > timeout → застой.
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 0.0}
        _state, stalled = self._eval(prev, 1000, 2000 + 5000, now=200.0,
                                     timeout=120, min_tx=4096)
        self.assertTrue(stalled)

    def test_no_stall_before_timeout(self):
        # Отправили много, но времени с последнего приёма мало.
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 100.0}
        _state, stalled = self._eval(prev, 1000, 2000 + 50_000, now=150.0,
                                     timeout=120, min_tx=4096)
        self.assertFalse(stalled)

    def test_counter_reset_rebaselines(self):
        # После рестарта демона счётчики обнулились (rx/tx меньше прежних) —
        # не считаем это застоем, ре-базируемся.
        prev = {"rx": 50_000, "tx_at_rx": 80_000, "rx_ts": 0.0}
        state, stalled = self._eval(prev, 100, 200, now=9999.0)
        self.assertFalse(stalled)
        self.assertEqual(state["rx"], 100)
        self.assertEqual(state["tx_at_rx"], 200)
        self.assertEqual(state["rx_ts"], 9999.0)

    def test_stall_accumulates_across_flat_ticks(self):
        # Несколько тиков подряд rx стоит — момент последнего приёма
        # (rx_ts/tx_at_rx) сохраняется, возраст копится до срабатывания.
        prev = {"rx": 1000, "tx_at_rx": 2000, "rx_ts": 1000.0}
        s1, st1 = self._eval(prev, 1000, 4000, now=1030.0)   # +30с
        self.assertFalse(st1)
        self.assertEqual(s1["rx_ts"], 1000.0)        # точка приёма не сдвинулась
        self.assertEqual(s1["tx_at_rx"], 2000)
        s2, st2 = self._eval(s1, 1000, 8000, now=1130.0)     # +130с, tx>min
        self.assertTrue(st2)


class TestDecideRestartRxStall(unittest.TestCase):

    def test_rx_stall_restarts_with_fresh_handshake(self):
        should, reason = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2,
            rx_stalled=True)
        self.assertTrue(should)
        self.assertIn("не принимает", reason)

    def test_rx_stall_false_holds(self):
        should, _ = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2,
            rx_stalled=False)
        self.assertFalse(should)

    def test_default_rx_stalled_is_false(self):
        # Обратная совместимость: без kwarg ведёт себя как раньше.
        should, _ = awg_watchdog.decide_restart(
            handshake_age=5, handshake_timeout=180,
            probe_enabled=False, probe_consecutive_fails=0, probe_threshold=2)
        self.assertFalse(should)


class TestMaybeRestartRxStall(unittest.TestCase):
    """Интеграция rx-stall в _maybe_restart (без фонового потока)."""

    def _settings(self, **over):
        base = {
            "handshake_timeout_sec": 180,
            "check_interval_sec":    30,
            "cooldown_sec":          300,
            "max_restarts_per_hour": 6,
            "enabled": True,
            "rx_stall_enabled": True,
            "rx_stall_timeout_sec": 120,
            "rx_stall_min_tx_bytes": 4096,
        }
        base.update(over)
        return base

    def test_restarts_on_rx_stall_even_if_handshake_fresh(self):
        wd  = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        now = time.time()
        # Затравка: последний приём давно (>timeout назад), tx тогда был 2000.
        wd._rx_state["awg0"] = {"rx": 1000, "tx_at_rx": 2000,
                                "rx_ts": now - 200}
        # handshake свежий (не сработал бы старый триггер), rx стоит,
        # tx вырос на 5000 (> min_tx) → застой приёма.
        status = {"peers": [{"latest_handshake": int(now) - 5,
                             "rx_bytes": 1000, "tx_bytes": 7000}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(), now=now)
        mgr.restart.assert_called_once_with("awg0")

    def test_no_restart_when_rx_progresses(self):
        wd  = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        now = time.time()
        wd._rx_state["awg0"] = {"rx": 1000, "tx_at_rx": 2000,
                                "rx_ts": now - 200}
        # rx ВЫРОС (приняли данные) → туннель жив, рестарта нет.
        status = {"peers": [{"latest_handshake": int(now) - 5,
                             "rx_bytes": 5000, "tx_bytes": 7000}]}
        wd._maybe_restart(mgr, "awg0", status, self._settings(), now=now)
        mgr.restart.assert_not_called()

    def test_rx_stall_disabled_holds(self):
        wd  = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        now = time.time()
        wd._rx_state["awg0"] = {"rx": 1000, "tx_at_rx": 2000,
                                "rx_ts": now - 200}
        status = {"peers": [{"latest_handshake": int(now) - 5,
                             "rx_bytes": 1000, "tx_bytes": 7000}]}
        wd._maybe_restart(mgr, "awg0", status,
                          self._settings(rx_stall_enabled=False), now=now)
        mgr.restart.assert_not_called()
