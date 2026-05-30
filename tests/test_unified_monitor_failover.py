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


class TestNeedsMonitorAutostart(unittest.TestCase):

    def _route(self, **kw):
        from core.unified.model import UnifiedRoute, Destination
        return UnifiedRoute(destination=Destination(domains=["a.com"]), **kw)

    def test_needs_monitor_true_when_failover(self):
        r = self._route(name="r", method="awg:awg0", failover_enabled=True)
        with mock.patch("core.unified.storage.load_routes", return_value=[r]):
            self.assertTrue(monitor.needs_monitor())

    def test_needs_monitor_true_when_monitor(self):
        r = self._route(name="r", method="awg:awg0", monitor_enabled=True)
        with mock.patch("core.unified.storage.load_routes", return_value=[r]):
            self.assertTrue(monitor.needs_monitor())

    def test_needs_monitor_false_when_none(self):
        r = self._route(name="r", method="awg:awg0")
        with mock.patch("core.unified.storage.load_routes", return_value=[r]):
            self.assertFalse(monitor.needs_monitor())

    def test_needs_monitor_ignores_disabled_route(self):
        r = self._route(name="r", method="awg:awg0", enabled=False,
                        failover_enabled=True)
        with mock.patch("core.unified.storage.load_routes", return_value=[r]):
            self.assertFalse(monitor.needs_monitor())

    def test_autostart_starts_and_stops(self):
        loop = monitor.get_monitor()
        try:
            with mock.patch("core.unified.monitor.needs_monitor",
                            return_value=True):
                monitor.autostart_if_needed(interval=15)
            self.assertTrue(loop.running())
            with mock.patch("core.unified.monitor.needs_monitor",
                            return_value=False):
                monitor.autostart_if_needed()
            self.assertFalse(loop.running())
        finally:
            loop.stop()


class TestFailoverNeedsProbeOnly(unittest.TestCase):
    """failover_enabled без monitor_enabled теперь тоже пробится (tick)."""

    def test_tick_probes_failover_only_route(self):
        from core.unified.model import UnifiedRoute, Destination
        r = UnifiedRoute(name="r", method="awg:awg0",
                         destination=Destination(domains=["a.com"]),
                         monitor_enabled=False, failover_enabled=True)
        loop = monitor._MonitorLoop()
        with mock.patch("core.unified.storage.load_routes", return_value=[r]), \
             mock.patch("core.unified.monitor.probe_route",
                        return_value=True) as pr, \
             mock.patch("core.unified.failover.step") as st:
            loop._tick()
        pr.assert_called_once()
        st.assert_called_once()
