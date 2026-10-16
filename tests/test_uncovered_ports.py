"""Порты профилей стратегии вне перехвата firewall (core.firewall)."""

import unittest

from core.firewall import uncovered_filter_ports, with_filter_ports

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


class TestWithFilterPorts(unittest.TestCase):
    """Перехват дополняется портами фильтров стратегии."""

    # Профили пресета MartinBacker (nfqws-menu) на дефолте nfqws2-keenetic.
    MARTIN = ["--filter-udp=590-600,1400,3478-3481,5349,19294-19344,"
              "49152-65535", "--new", "--filter-udp=443", "--new",
              "--filter-tcp=443,80,1984,5222"]

    def test_preset_ports_join_the_intercept(self):
        tcp, udp, added = with_filter_ports(TCP, UDP, self.MARTIN)
        self.assertEqual(added, {"tcp": ["1984"], "udp": ["590-600", "1400"]})
        self.assertEqual(tcp, TCP + ",1984")
        # в синтаксисе firewall — через двоеточие
        self.assertEqual(udp, UDP + ",590:600,1400")

    def test_nothing_to_add_keeps_the_string(self):
        tcp, udp, added = with_filter_ports(TCP, UDP, ["--filter-tcp=443"])
        self.assertEqual((tcp, udp), (TCP, UDP))
        self.assertEqual(added, {"tcp": [], "udp": []})

    def test_no_strategy(self):
        self.assertEqual(with_filter_ports(TCP, UDP, None)[:2], (TCP, UDP))

    def test_empty_intercept_gets_only_strategy_ports(self):
        tcp, udp, _ = with_filter_ports("", "", ["--filter-udp=853"])
        self.assertEqual((tcp, udp), ("", "853"))


if __name__ == "__main__":
    unittest.main()
