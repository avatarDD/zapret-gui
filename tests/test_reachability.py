# tests/test_reachability.py
"""Классификатор «WAN упал / туннель сломан / зарубеж закрыт»."""

import unittest
from unittest import mock

from core import quick_fix as qf
from core import reachability as rc


DOMESTIC = {a for a, _p in rc.DOMESTIC_TARGETS}


def _net(domestic: bool, foreign: bool):
    """Подмена TCP-пробы: отвечают ли отечественные и зарубежные адреса."""
    def _connect(addr, timeout=None):
        return domestic if addr[0] in DOMESTIC else foreign
    return mock.patch.object(rc, "_connect", side_effect=_connect)


class TestClassify(unittest.TestCase):

    def test_table(self):
        self.assertEqual(rc.classify(False, False, False), "wan_down")
        self.assertEqual(rc.classify(False, False, None), "wan_down")
        self.assertEqual(rc.classify(True, None, False), "tunnel_broken")
        self.assertEqual(rc.classify(True, True, False), "tunnel_broken")
        self.assertEqual(rc.classify(True, False, True), "foreign_blocked")
        self.assertEqual(rc.classify(True, True, True), "normal")
        self.assertEqual(rc.classify(True, True, None), "wan_up")
        self.assertEqual(rc.classify(None, None, None), "unknown")

    def test_tunnel_alive_is_never_wan_down(self):
        # Туннель отвечает — значит пакеты уходят, WAN жив.
        self.assertNotEqual(rc.classify(False, False, True), "wan_down")


class TestUplink(unittest.TestCase):

    def setUp(self):
        rc.reset()
        span = mock.patch.object(rc, "DOWN_CONFIRM_SPAN", 0.0)
        span.start()
        self.notify = mock.patch("core.notify.event").start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(rc.reset)

    def test_up(self):
        with _net(True, True):
            self.assertEqual(rc.uplink()["state"], "up")
        self.assertFalse(rc.wan_down())

    def test_foreign_blocked(self):
        with _net(True, False):
            self.assertEqual(rc.uplink()["state"], "foreign_blocked")
            self.assertFalse(rc.hold_restart("awg", "awg0"))

    def test_down_needs_two_misses(self):
        with _net(False, False):
            self.assertEqual(rc.uplink(force=True)["state"], "suspect")
            self.assertFalse(rc.hold_restart("awg", "awg0"))
            self.assertEqual(rc.uplink(force=True)["state"], "down")
        self.assertTrue(rc.wan_down())

    def test_two_misses_in_one_moment_are_not_confirmation(self):
        with _net(False, False), \
                mock.patch.object(rc, "DOWN_CONFIRM_SPAN", 15.0):
            rc.uplink(force=True)
            self.assertEqual(rc.uplink(force=True)["state"], "suspect")
            with mock.patch.object(rc.time, "time",
                                   return_value=rc.time.time() + 20):
                self.assertEqual(rc.uplink(force=True)["state"], "down")

    def test_result_is_cached(self):
        with _net(True, True) as conn:
            rc.uplink()
            calls = conn.call_count
            rc.uplink()
            self.assertEqual(conn.call_count, calls)
            rc.uplink(force=True)
            self.assertGreater(conn.call_count, calls)

    def test_hold_and_single_notifications(self):
        with _net(False, False):
            rc.uplink(force=True)
            rc.uplink(force=True)
            self.assertTrue(rc.hold_restart("awg", "awg0"))
            self.assertTrue(rc.hold_restart("mihomo"))
            rc.uplink(force=True)
        self.assertEqual(self.notify.call_count, 1)
        self.assertEqual(rc.status()["held"], ["awg awg0", "mihomo"])
        with _net(True, True):
            rc.uplink(force=True)
            rc.uplink(force=True)
        self.assertEqual(self.notify.call_count, 2)
        back = self.notify.call_args[0][1]
        self.assertIn("вернулся", back)
        self.assertIn("awg awg0", back)
        self.assertEqual(rc.status()["held"], [])
        self.assertIsNone(rc.status()["outage_since"])

    def test_probe_error_counts_as_alive(self):
        with mock.patch.object(rc, "uplink", side_effect=RuntimeError):
            self.assertFalse(rc.wan_down())


class TestQuickFixUplink(unittest.TestCase):

    def test_evaluate(self):
        self.assertEqual(qf.evaluate_uplink({"state": "up"})["status"], "ok")
        self.assertEqual(
            qf.evaluate_uplink({"state": "foreign_blocked"})["status"],
            "warning")
        self.assertEqual(qf.evaluate_uplink({"state": "down"})["status"],
                         "error")
        self.assertEqual(qf.evaluate_uplink({"state": "suspect"})["status"],
                         "warning")
        self.assertEqual(qf.evaluate_uplink({})["status"], "unknown")


class TestFailoverHold(unittest.TestCase):
    """Пропавший WAN — не повод переводить маршрут на запасной метод."""

    def test_no_switch_when_wan_down(self):
        from core.unified import failover, monitor
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="t", method="nfqws2",
                             fallbacks=["awg:awg0"],
                             destination=Destination(domains=["a.com"]))
        monitor.clear()
        self.addCleanup(monitor.clear)
        for _ in range(10):
            monitor.record(route.id, False, method="nfqws2")
        failover.set_current(route.id, "nfqws2", ts=0)
        with mock.patch.object(rc, "wan_down", return_value=True), \
                mock.patch("core.unified.applier.apply_route") as ap:
            res = failover.step(route)
        self.assertFalse(res["switched"])
        self.assertEqual(res["method"], "nfqws2")
        ap.assert_not_called()
        rc.reset()


class TestMonitorSkipsOutage(unittest.TestCase):

    def test_failed_sample_during_outage_not_recorded(self):
        from core.unified import monitor
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="t", method="nfqws2",
                             destination=Destination(domains=["a.com"]),
                             monitor_enabled=True)
        monitor.clear()
        self.addCleanup(monitor.clear)
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
                mock.patch.object(monitor, "probe_route",
                                  return_value=False), \
                mock.patch.object(monitor, "_wan_down", return_value=True):
            monitor._loop._tick()
        self.assertEqual(monitor.history(route.id), [])
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
                mock.patch.object(monitor, "probe_route",
                                  return_value=False), \
                mock.patch.object(monitor, "_wan_down", return_value=False):
            monitor._loop._tick()
        self.assertEqual(len(monitor.history(route.id)), 1)


if __name__ == "__main__":
    unittest.main()
