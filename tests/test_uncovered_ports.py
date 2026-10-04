"""Порты профилей стратегии вне перехвата firewall (core.firewall)."""

import unittest

from core.firewall import uncovered_filter_ports

TCP = "80,443,2053,2083,2087,2096,5222,8443"
UDP = "443,3478:3481,5349,19294:19344,50000:65535"


class TestUncovered(unittest.TestCase):

    def test_wardogs_udp_4192(self):
        r = uncovered_filter_ports(["--filter-udp=4192", "--payload=all"],
                                   TCP, UDP)
        self.assertEqual(r, {"tcp": [], "udp": ["4192"]})

    def test_dot_853(self):
        r = uncovered_filter_ports(["--filter-tcp=443,853"], TCP, UDP)
        self.assertEqual(r["tcp"], ["853"])

    def test_partial_overlap_is_fine(self):
        r = uncovered_filter_ports(["--filter-udp=1024-65535"], TCP, UDP)
        self.assertEqual(r["udp"], [])

    def test_ranges_and_dedup(self):
        args = ["--filter-udp=590-600,1400,3478-3481", "--new",
                "--filter-udp=1400"]
        r = uncovered_filter_ports(args, TCP, UDP)
        self.assertEqual(r["udp"], ["590-600", "1400"])

    def test_wildcard_and_inversion_skipped(self):
        r = uncovered_filter_ports(["--filter-tcp=*", "--filter-udp=~443"],
                                   TCP, UDP)
        self.assertEqual(r, {"tcp": [], "udp": []})


if __name__ == "__main__":
    unittest.main()
