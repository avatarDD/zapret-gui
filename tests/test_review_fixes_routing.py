"""Регрессии по код-ревью ветки «приёмы MagiTrickle»: каждая — сценарий
из находки ревью."""

import errno
import time
import unittest
from unittest import mock

from core.routing import dns_intercept, domain_match, guardian, ipset_backend
from core.routing.dns_intercept import DnsIntercept


class TestInterceptRestart(unittest.TestCase):

    def test_old_loop_does_not_tear_down_restarted_intercept(self):
        di = DnsIntercept()
        old, new = object(), object()
        di._running, di._sock = True, new
        with mock.patch.object(di, "_teardown_locked") as td:
            di._loop_died(old, "_sock", "приёмный цикл")
            td.assert_not_called()
            di._loop_died(new, "_sock", "приёмный цикл")
            td.assert_called_once()

    def test_sync_rules_forgets_seen(self):
        di = DnsIntercept()
        di._seen[("r", "1.1.1.1")] = time.time() + 1000
        di.sync_rules()
        self.assertEqual(di._seen, {})


class TestDnsmasqPathRules(unittest.TestCase):

    def _di(self):
        di = DnsIntercept()
        di._rules_cache = [{
            "id": "r", "kind": "ipset", "table": 1, "iface": "wg",
            "set_v4": "awgr_r", "set_v6": "awgr_r6", "ttl": False,
            "matcher": domain_match.Matcher(["youtube.com", "cdn*.x.net"]),
            "add_matcher": domain_match.Matcher(["cdn*.x.net"])}]
        di._rules_at = time.time() + 3600
        return di

    def test_plain_domain_matches_for_aaaa_but_dnsmasq_adds_ip(self):
        di = self._di()
        with mock.patch("core.routing.ipset_backend.add_entry") as add:
            self.assertTrue(di._harvest(["youtube.com"],
                                        [("1.2.3.4", "v4", 60)]))
        add.assert_not_called()

    def test_pattern_ip_goes_to_dnsmasq_set_without_expiry(self):
        di = self._di()
        with mock.patch("core.routing.ipset_backend.add_entry",
                        return_value=True) as add:
            di._harvest(["cdn7.x.net"], [("5.6.7.8", "v4", 60)])
        add.assert_called_once_with("awgr_r", "5.6.7.8", 0)


class TestChainLock(unittest.TestCase):

    def test_read_and_write_under_one_lock(self):
        seen = []

        def cur(_cmd):
            seen.append(ipset_backend._chain_lock.locked())
            return []

        def sync(entries, family):
            seen.append(ipset_backend._chain_lock.locked())
            return {"ok": True, "errors": []}
        with mock.patch.object(ipset_backend, "_current_entries",
                               side_effect=cur), \
                mock.patch.object(ipset_backend, "_sync_locked",
                                  side_effect=sync):
            ipset_backend.setup_mark_rule("s", 0x10000)
        self.assertEqual(seen, [True, True])


class TestNetlinkOverflow(unittest.TestCase):

    def test_enobufs_rescans_instead_of_dying(self):
        class Sock:
            n = 0

            def recv(self, _n):
                self.n += 1
                if self.n == 1:
                    raise OSError(errno.ENOBUFS, "No buffer space")
                raise OSError(errno.EBADF, "closed")
        guardian._pending_links.clear()
        with mock.patch.object(guardian, "_managed_ifaces",
                               return_value={"tun0"}), \
                mock.patch.object(guardian, "_iface_exists",
                                  return_value=True):
            guardian._netlink_loop(Sock())
        self.assertIn("tun0", guardian._pending_links)
        guardian._pending_links.clear()


class TestSubscriptionsFixes(unittest.TestCase):

    def test_any_fetch_error_is_recorded(self):
        import http.client
        from core import list_subscriptions as ls
        statuses = []
        with mock.patch.object(ls, "get", return_value={"url": "https://x"}), \
                mock.patch.object(ls, "_file_path", return_value=__file__), \
                mock.patch("core.list_updater.get_transport", return_value=""), \
                mock.patch("core.list_updater._fetch",
                           side_effect=http.client.IncompleteRead(b"x")), \
                mock.patch.object(ls, "_set_status",
                                  side_effect=lambda *a, **k:
                                  statuses.append(k)):
            res = ls.refresh("hostlist", "my")
        self.assertFalse(res["ok"])
        self.assertEqual(statuses[0]["last_status"], "error")
        self.assertTrue(statuses[0]["last_refresh"])

    def test_deleting_list_drops_subscription(self):
        import os
        import tempfile
        from core.hostlist_manager import HostlistManager
        hm = HostlistManager()
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        with open(os.path.join(tmp, "mylist.txt"), "w") as f:
            f.write("a.com\n")
        with mock.patch.object(HostlistManager, "lists_path",
                               new_callable=mock.PropertyMock,
                               return_value=tmp), \
                mock.patch("core.list_subscriptions.unsubscribe") as unsub:
            ok, _err = hm.delete_hostlist("mylist")
        self.assertTrue(ok)
        unsub.assert_called_once_with("hostlist", "mylist")


class TestValidateCidrInDomains(unittest.TestCase):

    def test_addresses_in_domains_are_checked_as_networks(self):
        from core.unified.bulk import validate_destination
        self.assertEqual(validate_destination(
            {"domains": ["a.com", "1.2.3.0/24", "2001:db8::/32", "8.8.8.8"]}),
            [])
        self.assertEqual(len(validate_destination(
            {"domains": ["1.2.3.0/40"]})), 1)


if __name__ == "__main__":
    unittest.main()
