# tests/test_unified_monitor_failover.py
"""Unit-тесты для core/unified/monitor.py и failover.py."""

import unittest
from unittest import mock

from core.unified import monitor, failover


class TestMonitorHistory(unittest.TestCase):

    def setUp(self):
        monitor.clear()

    def tearDown(self):
        monitor.clear()

    def test_record_and_rate(self):
        for ok in (True, True, False, True):
            monitor.record("r1", ok)
        self.assertAlmostEqual(monitor.success_rate("r1"), 0.75)
        self.assertEqual(monitor.last_ok("r1"), True)

    def test_rate_none_when_empty(self):
        self.assertIsNone(monitor.success_rate("nope"))
        self.assertIsNone(monitor.last_ok("nope"))

    def test_window(self):
        for _ in range(20):
            monitor.record("r2", False)
        monitor.record("r2", True)
        # окно 10: 9 неудач + 1 успех
        self.assertAlmostEqual(monitor.success_rate("r2", window=10), 0.1)

    def test_stats(self):
        monitor.record("r3", True)
        s = monitor.stats()
        self.assertIn("r3", s)
        self.assertEqual(s["r3"]["samples"], 1)


class TestFailoverDecide(unittest.TestCase):

    CHAIN = ["nfqws2", "awg:awg0", "direct"]

    def test_init_picks_primary(self):
        d = failover.decide(chain=self.CHAIN, current="", rate=None,
                            samples=0, now=100, last_switch=0)
        self.assertTrue(d["switch"])
        self.assertEqual(d["method"], "nfqws2")

    def test_insufficient_data_holds(self):
        d = failover.decide(chain=self.CHAIN, current="nfqws2", rate=0.0,
                            samples=2, now=100, last_switch=0)
        self.assertFalse(d["switch"])

    def test_healthy_holds(self):
        d = failover.decide(chain=self.CHAIN, current="nfqws2", rate=0.9,
                            samples=10, now=1000, last_switch=0)
        self.assertFalse(d["switch"])

    def test_degraded_switches_next(self):
        d = failover.decide(chain=self.CHAIN, current="nfqws2", rate=0.1,
                            samples=10, now=10_000, last_switch=0)
        self.assertTrue(d["switch"])
        self.assertEqual(d["method"], "awg:awg0")

    def test_cooldown_blocks(self):
        d = failover.decide(chain=self.CHAIN, current="nfqws2", rate=0.1,
                            samples=10, now=100, last_switch=50)
        self.assertFalse(d["switch"])
        self.assertEqual(d["reason"], "cooldown")

    def test_cycles_through_chain(self):
        d = failover.decide(chain=self.CHAIN, current="direct", rate=0.0,
                            samples=10, now=10_000, last_switch=0)
        self.assertTrue(d["switch"])
        self.assertEqual(d["method"], "nfqws2")  # wrap-around


class TestFailoverState(unittest.TestCase):

    def setUp(self):
        failover.reset()

    def tearDown(self):
        failover.reset()

    def test_set_and_get_current(self):
        self.assertEqual(failover.current_method("r1"), "")
        failover.set_current("r1", "awg:awg0")
        self.assertEqual(failover.current_method("r1"), "awg:awg0")

    def test_switch_updates_last_switch(self):
        failover.set_current("r1", "nfqws2", ts=100)
        failover.set_current("r1", "awg:awg0", ts=200)
        st = failover.state("r1")
        self.assertEqual(st["last_switch"], 200)

    def test_step_switches_and_applies(self):
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="t", method="nfqws2",
                             fallbacks=["awg:awg0"],
                             destination=Destination(domains=["a.com"]))
        # история — сплошные неудачи
        monitor.clear()
        for _ in range(10):
            monitor.record(route.id, False)
        failover.set_current(route.id, "nfqws2", ts=0)
        with mock.patch("core.unified.applier.apply_route",
                        return_value={"ok": True}) as ap:
            res = failover.step(route)
        self.assertTrue(res["switched"])
        self.assertEqual(res["method"], "awg:awg0")
        ap.assert_called_once()
        monitor.clear()


if __name__ == "__main__":
    unittest.main()
