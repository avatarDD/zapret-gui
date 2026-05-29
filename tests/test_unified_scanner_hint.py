# tests/test_unified_scanner_hint.py
"""Unit-тесты для core/unified/scanner_hint.py."""

import unittest
from unittest import mock

from core.unified import scanner_hint as sh
from core.unified.model import UnifiedRoute, Destination


class TestShouldSuggest(unittest.TestCase):

    def test_only_nfqws2(self):
        self.assertFalse(sh.should_suggest("awg:awg0", 0.0, 10))
        self.assertFalse(sh.should_suggest("direct", 0.0, 10))

    def test_needs_samples(self):
        self.assertFalse(sh.should_suggest("nfqws2", 0.0, 2))
        self.assertFalse(sh.should_suggest("nfqws2", None, 10))

    def test_healthy_no_suggest(self):
        self.assertFalse(sh.should_suggest("nfqws2", 0.9, 10))

    def test_degraded_suggests(self):
        self.assertTrue(sh.should_suggest("nfqws2", 0.2, 10))

    def test_bad_method(self):
        self.assertFalse(sh.should_suggest("bogus", 0.0, 10))


class TestSuggestForRoute(unittest.TestCase):

    def _route(self):
        return UnifiedRoute(name="t", method="nfqws2",
                            probe_domain="youtube.com",
                            destination=Destination(domains=["youtube.com"]))

    def test_suggests_when_degraded(self):
        r = self._route()
        with mock.patch("core.unified.applier.active_method",
                        return_value="nfqws2"), \
             mock.patch("core.unified.monitor.success_rate", return_value=0.1), \
             mock.patch("core.unified.monitor.history", return_value=[0]*10):
            res = sh.suggest_for_route(r)
        self.assertTrue(res["suggest"])
        self.assertEqual(res["target"], "youtube.com")
        self.assertIn("nfqws2 не тянет", res["reason"])

    def test_no_suggest_when_healthy(self):
        r = self._route()
        with mock.patch("core.unified.applier.active_method",
                        return_value="nfqws2"), \
             mock.patch("core.unified.monitor.success_rate", return_value=0.95), \
             mock.patch("core.unified.monitor.history", return_value=[1]*10):
            res = sh.suggest_for_route(r)
        self.assertFalse(res["suggest"])


class TestRunScan(unittest.TestCase):

    def test_no_target(self):
        r = UnifiedRoute(name="t", method="nfqws2",
                         destination=Destination(cidrs=["1.2.3.0/24"]))
        res = sh.run_scan_for_route(r)
        self.assertFalse(res["ok"])

    def test_starts_scanner(self):
        r = UnifiedRoute(name="t", method="nfqws2", probe_domain="x.com",
                         destination=Destination(domains=["x.com"]))
        scanner = mock.Mock()
        scanner.start.return_value = True
        scanner.get_status.return_value = {"running": True}
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        return_value=scanner):
            res = sh.run_scan_for_route(r)
        self.assertTrue(res["ok"])
        scanner.start.assert_called_once()
        self.assertEqual(scanner.start.call_args.kwargs["target"], "x.com")


class TestApplyBest(unittest.TestCase):

    def test_applies_top(self):
        scanner = mock.Mock()
        scanner.get_working_strategies.return_value = [{"id": "s1"}, {"id": "s2"}]
        scanner.apply_strategy_by_id.return_value = True
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        return_value=scanner):
            res = sh.apply_best_found()
        self.assertTrue(res["ok"])
        self.assertEqual(res["applied"], "s1")

    def test_none_found(self):
        scanner = mock.Mock()
        scanner.get_working_strategies.return_value = []
        with mock.patch("core.strategy_scanner.get_strategy_scanner",
                        return_value=scanner):
            res = sh.apply_best_found()
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
