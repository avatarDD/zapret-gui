# tests/test_unified_nfqws_hostlist.py
"""Тесты core/unified/nfqws_hostlist.py."""

import unittest
from unittest import mock

from core.unified import nfqws_hostlist as nh
from core.unified.model import UnifiedRoute, Destination


def _routes():
    return [
        UnifiedRoute(name="a", method="nfqws2",
                     destination=Destination(domains=["a.com", "b.com"])),
        UnifiedRoute(name="b", method="nfqws2", enabled=False,
                     destination=Destination(domains=["disabled.com"])),
        UnifiedRoute(name="c", method="awg:awg0",
                     destination=Destination(domains=["tunnel.com"])),
        UnifiedRoute(name="d", method="nfqws2",
                     destination=Destination(domains=["b.com", "c.com"])),
    ]


class TestCollect(unittest.TestCase):

    def test_only_enabled_nfqws2_unioned(self):
        with mock.patch("core.unified.storage.load_routes",
                        return_value=_routes()):
            doms = nh._collect_domains()
        # a.com,b.com (route a) + b.com,c.com (route d), dedup; tunnel/disabled excl.
        self.assertEqual(doms, ["a.com", "b.com", "c.com"])


class TestComposeExtraArgs(unittest.TestCase):

    def test_disabled_returns_empty(self):
        with mock.patch("core.unified.nfqws_hostlist.enabled",
                        return_value=False):
            self.assertEqual(nh.compose_extra_args(), [])

    def test_enabled_empty_domains(self):
        with mock.patch("core.unified.nfqws_hostlist.enabled",
                        return_value=True), \
             mock.patch("core.unified.nfqws_hostlist._collect_domains",
                        return_value=[]):
            self.assertEqual(nh.compose_extra_args(), [])

    def test_enabled_with_domains(self):
        with mock.patch("core.unified.nfqws_hostlist.enabled",
                        return_value=True), \
             mock.patch("core.unified.nfqws_hostlist._collect_domains",
                        return_value=["a.com"]), \
             mock.patch("core.unified.nfqws_hostlist.aggregate_path",
                        return_value="/opt/zapret2/lists/unified_nfqws.txt"):
            args = nh.compose_extra_args()
        self.assertEqual(args, ["--hostlist=/opt/zapret2/lists/unified_nfqws.txt"])


class TestRebuild(unittest.TestCase):

    def test_rebuild_saves_and_no_restart_when_disabled(self):
        hm = mock.Mock()
        with mock.patch("core.unified.nfqws_hostlist._collect_domains",
                        return_value=["a.com", "b.com"]), \
             mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm), \
             mock.patch("core.unified.nfqws_hostlist.enabled",
                        return_value=False), \
             mock.patch("core.unified.nfqws_hostlist.aggregate_path",
                        return_value="/x.txt"):
            res = nh.rebuild()
        self.assertTrue(res["ok"])
        self.assertEqual(res["domains"], 2)
        self.assertFalse(res["restarted"])
        hm.save_hostlist.assert_called_once_with("unified_nfqws", ["a.com", "b.com"])

    def test_rebuild_restarts_when_enabled_and_running(self):
        hm = mock.Mock()
        nfq = mock.Mock()
        nfq.is_running.return_value = True
        with mock.patch("core.unified.nfqws_hostlist._collect_domains",
                        return_value=["a.com"]), \
             mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm), \
             mock.patch("core.unified.nfqws_hostlist.enabled",
                        return_value=True), \
             mock.patch("core.unified.nfqws_hostlist.aggregate_path",
                        return_value="/x.txt"), \
             mock.patch("core.nfqws_manager.get_nfqws_manager",
                        return_value=nfq):
            res = nh.rebuild()
        self.assertTrue(res["restarted"])
        nfq.restart.assert_called_once()


if __name__ == "__main__":
    unittest.main()
