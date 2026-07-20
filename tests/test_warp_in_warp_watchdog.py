"""Regression tests for fail-closed WARP-in-WARP health checks."""

import unittest
from unittest import mock

from core import warp_in_warp_watchdog as wdmod


class TestWarpInWarpWatchdog(unittest.TestCase):
    @mock.patch("core.warp_in_warp_watchdog.socket.socket")
    def test_bind_failure_is_unknown_not_healthy(self, socket_factory):
        sock = mock.Mock()
        sock.setsockopt.side_effect = OSError("not permitted")
        socket_factory.return_value = sock
        self.assertIsNone(wdmod._probe_through_wiw("opkgtun1"))

    @mock.patch("core.warp_in_warp.get_warp_in_warp_manager")
    def test_inactive_layer_counts_toward_restart(self, get_manager):
        mgr = mock.Mock()
        mgr.get_status.return_value = {
            "mode": "masque_awg", "active": False,
            "outer_running": True, "inner_running": False,
        }
        get_manager.return_value = mgr
        watchdog = wdmod.WarpInWarpWatchdog()
        watchdog._tick()
        self.assertEqual(watchdog.get_status()["fail_count"], 1)
        self.assertEqual(watchdog.get_status()["health"], "unhealthy")


if __name__ == "__main__":
    unittest.main()
