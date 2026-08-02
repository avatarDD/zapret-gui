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

    def test_rate_is_per_method(self):
        """Провалы старого метода не должны портить успешность нового."""
        for _ in range(9):
            monitor.record("r4", False, method="awg:awg0")
        monitor.record("r4", True, method="nfqws2")
        self.assertAlmostEqual(monitor.success_rate("r4", method="nfqws2"), 1.0)
        self.assertAlmostEqual(monitor.success_rate("r4", method="awg:awg0"), 0.0)
        # Без фильтра — как раньше, по всем замерам.
        self.assertAlmostEqual(monitor.success_rate("r4"), 0.1)

    def test_stats_reports_active_method_only(self):
        for _ in range(9):
            monitor.record("r5", False, method="awg:awg0")
        monitor.record("r5", True, method="nfqws2")
        s = monitor.stats()["r5"]
        self.assertEqual(s["method"], "nfqws2")
        self.assertAlmostEqual(s["rate"], 1.0)
        self.assertEqual(s["samples"], 1)

    def test_history_filter_drops_samples_without_method(self):
        """Замер без метода нельзя зачесть новому методу."""
        monitor.record("r6", False)
        self.assertEqual(len(monitor.history("r6")), 1)
        self.assertEqual(monitor.history("r6", method="nfqws2"), [])


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
        # история — сплошные неудачи ТЕКУЩЕГО метода
        monitor.clear()
        for _ in range(10):
            monitor.record(route.id, False, method="nfqws2")
        failover.set_current(route.id, "nfqws2", ts=0)
        with mock.patch("core.unified.applier.apply_route",
                        return_value={"ok": True}) as ap:
            res = failover.step(route)
        self.assertTrue(res["switched"])
        self.assertEqual(res["method"], "awg:awg0")
        ap.assert_called_once()
        monitor.clear()

    def test_step_does_not_reapply_when_method_unchanged(self):
        """Первый шаг лишь фиксирует активный метод.

        Раньше он ещё и переприменял маршрут — то есть сносил и заново
        собирал ipset'ы с перезагрузкой dnsmasq на ровном месте.
        """
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="t", method="nfqws2",
                             fallbacks=["awg:awg0"],
                             destination=Destination(domains=["a.com"]))
        monitor.clear()
        with mock.patch("core.unified.applier.apply_route") as ap:
            res = failover.step(route)
        self.assertFalse(res["switched"])
        ap.assert_not_called()
        self.assertEqual(failover.current_method(route.id), "nfqws2")

    def test_healthy_fallback_is_not_abandoned(self):
        """Переключившись на исправный метод, маршрут на нём и остаётся.

        Регрессия: успешность считалась по сквозной истории, поэтому
        сразу после переключения окно состояло из провалов ПРЕДЫДУЩЕГО
        метода. Через cooldown маршрут уходил с исправного метода обратно
        на сломанный — и так по кругу.
        """
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="t", method="awg:awg0",
                             fallbacks=["nfqws2"],
                             destination=Destination(domains=["a.com"]),
                             failover_enabled=True)
        healthy = "nfqws2"
        monitor.clear()
        now = [0.0]
        switches = []
        with mock.patch("core.unified.applier.apply_route",
                        return_value={"ok": True}), \
             mock.patch("core.unified.failover.time.time",
                        side_effect=lambda: now[0]):
            for _ in range(40):                       # 40 тиков по минуте
                cur = failover.current_method(route.id) or route.method
                monitor.record(route.id, cur == healthy, ts=now[0], method=cur)
                r = failover.step(route)
                if r.get("switched"):
                    switches.append(r["method"])
                now[0] += 60
        self.assertEqual(switches, [healthy])
        self.assertEqual(failover.current_method(route.id), healthy)
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


class TestUnprobeableRoutes(unittest.TestCase):
    """Маршрут по geosite/geoip пробовать нечем — и это не «деградация».

    Регрессия: probe_route возвращал False (конкретного адреса у такого
    маршрута нет), маршрут выглядел вечно сломанным, и failover
    бесконечно гонял его по всей цепочке методов.
    """

    def setUp(self):
        monitor.clear()

    def tearDown(self):
        monitor.clear()

    def _route(self, **kw):
        from core.unified.model import UnifiedRoute, Destination
        kw.setdefault("destination", Destination(geosite=["youtube"]))
        return UnifiedRoute(name="geo", method="awg:awg0",
                            fallbacks=["nfqws2"], failover_enabled=True, **kw)

    def test_probe_returns_none_for_geo_only(self):
        self.assertIsNone(monitor.probe_route(self._route()))

    def test_probe_domain_makes_route_probeable(self):
        route = self._route(probe_domain="youtube.com")
        with mock.patch("core.unified.monitor.probe_host",
                        return_value=True) as ph:
            self.assertTrue(monitor.probe_route(route))
        ph.assert_called_once()

    def test_tick_records_nothing_and_skips_failover(self):
        route = self._route()
        loop = monitor._MonitorLoop()
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
             mock.patch("core.unified.failover.step") as st:
            loop._tick()
        self.assertEqual(monitor.history(route.id), [])
        st.assert_not_called()

    def test_tick_records_active_method(self):
        from core.unified.model import UnifiedRoute, Destination
        route = UnifiedRoute(name="d", method="awg:awg0",
                             destination=Destination(domains=["a.com"]),
                             monitor_enabled=True)
        loop = monitor._MonitorLoop()
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
             mock.patch("core.unified.monitor.probe_route", return_value=True):
            loop._tick()
        self.assertEqual(monitor.history(route.id)[0][2], "awg:awg0")


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
