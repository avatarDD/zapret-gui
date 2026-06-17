# tests/test_dnsmasq_nftset_detect.py
"""
Регрессия: детект поддержки nftset/ipset у dnsmasq по compile-time опциям.

Баг: `supports_nftset()` делал `"nftset" in output` — но dnsmasq, собранный
БЕЗ фичи, печатает `no-nftset` в «Compile time options» (содержит подстроку
"nftset"), плюс версия >= 2.87 ≠ HAVE_NFTSET. Ложный + → мы писали `nftset=`
в managed-файл, и dnsmasq не стартовал («recompile with HAVE_NFTSET
defined»), роняя DNS. Чиним: точный токен-матч по compile-options.
"""

import unittest
from unittest import mock

from core.routing import dnsmasq_integration as di
from core.routing import domain_rule


_HDR = "Dnsmasq version 2.91  Copyright (c) 2000-2024 Simon Kelley\n"

VERSION_BOTH = _HDR + (
    "Compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP "
    "DHCPv6 no-Lua TFTP no-conntrack ipset nftset auth cryptohash DNSSEC "
    "loop-detect inotify dumpfile\n"
)
# Как у пользователя: 2.91, но HAVE_NFTSET выключен (есть ipset).
VERSION_NO_NFTSET = _HDR + (
    "Compile time options: IPv6 GNU-getopt no-DBus no-UBus no-i18n IDN2 "
    "DHCP DHCPv6 no-Lua TFTP no-conntrack ipset no-nftset auth cryptohash "
    "DNSSEC loop-detect inotify\n"
)
VERSION_NEITHER = (
    "Dnsmasq version 2.80  Copyright (c) 2000-2018 Simon Kelley\n"
    "Compile time options: IPv6 GNU-getopt no-DBus i18n DHCP DHCPv6 no-Lua "
    "TFTP no-conntrack no-ipset no-nftset auth DNSSEC loop-detect inotify\n"
)


class TestDnsmasqCompileOptionDetect(unittest.TestCase):

    def test_no_nftset_is_not_false_positive(self):
        # «no-nftset» НЕ должно считаться поддержкой nftset (был баг).
        with mock.patch.object(di, "_run",
                               return_value=(0, VERSION_NO_NFTSET, "")):
            dn = di.DnsmasqIntegration()
            self.assertFalse(dn.supports_nftset())
            self.assertTrue(dn.supports_ipset())

    def test_both_supported(self):
        with mock.patch.object(di, "_run",
                               return_value=(0, VERSION_BOTH, "")):
            dn = di.DnsmasqIntegration()
            self.assertTrue(dn.supports_nftset())
            self.assertTrue(dn.supports_ipset())

    def test_neither_supported(self):
        with mock.patch.object(di, "_run",
                               return_value=(0, VERSION_NEITHER, "")):
            dn = di.DnsmasqIntegration()
            self.assertFalse(dn.supports_nftset())
            self.assertFalse(dn.supports_ipset())

    def test_no_version_output_is_conservative_false(self):
        with mock.patch.object(di, "_run", return_value=(127, "", "boom")):
            dn = di.DnsmasqIntegration()
            self.assertFalse(dn.supports_nftset())
            self.assertFalse(dn.supports_ipset())


class TestChooseSetKind(unittest.TestCase):
    """Тип set выбирается только если его поддерживают И dnsmasq, И система."""

    def _dn(self, nft, ips):
        dn = mock.Mock()
        dn.supports_nftset.return_value = nft
        dn.supports_ipset.return_value = ips
        return dn

    def _backends(self, nft_avail, ips_avail):
        return (
            mock.patch.object(domain_rule.nftset_backend, "available",
                              return_value=nft_avail),
            mock.patch.object(domain_rule.ipset_backend, "available",
                              return_value=ips_avail),
        )

    def test_prefers_nftset(self):
        a, b = self._backends(True, True)
        with a, b:
            self.assertEqual(
                domain_rule._choose_set_kind(self._dn(True, True)), "nftset")

    def test_falls_back_to_ipset_without_nftset(self):
        # пользовательский кейс: dnsmasq без nftset, но с ipset
        a, b = self._backends(True, True)
        with a, b:
            self.assertEqual(
                domain_rule._choose_set_kind(self._dn(False, True)), "ipset")

    def test_empty_when_dnsmasq_supports_neither(self):
        a, b = self._backends(True, True)
        with a, b:
            self.assertEqual(
                domain_rule._choose_set_kind(self._dn(False, False)), "")

    def test_empty_when_no_system_backend(self):
        a, b = self._backends(False, False)
        with a, b:
            self.assertEqual(
                domain_rule._choose_set_kind(self._dn(True, True)), "")


if __name__ == "__main__":
    unittest.main()
