# tests/test_auto_remediation.py
"""Unit-тесты для core/auto_remediation.py."""

import unittest

from core import auto_remediation as ar


class TestRemediationActions(unittest.TestCase):
    """Тесты маппинга DPI-типов на действия."""

    def test_tls_dpi_maps_to_zapret(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("tls_dpi"), "zapret_scan")

    def test_ip_block_maps_to_tunnel(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("ip_block"), "tunnel")

    def test_dns_fake_maps_to_dns(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("dns_fake"), "dns_fix")

    def test_full_block_maps_to_tunnel(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("full_block"), "tunnel")

    def test_none_maps_to_skip(self):
        self.assertEqual(ar.REMEDIATION_ACTIONS.get("none"), "skip")

    def test_all_dpi_types_have_actions(self):
        """Все 13 типов DPI должны иметь action."""
        dpi_types = [
            "none", "dns_fake", "http_inject", "isp_page", "tls_dpi",
            "tls_mitm", "clienthello_dpi", "tcp_reset", "tcp_16_20",
            "stun_block", "quic_block", "throttled", "ip_block",
            "full_block", "timeout_drop", "unknown"
        ]
        for dt in dpi_types:
            self.assertIn(dt, ar.REMEDIATION_ACTIONS,
                          "Missing action for DPI type: %s" % dt)


class TestAutoRemediation(unittest.TestCase):
    """Тесты AutoRemediation."""

    def setUp(self):
        self.remediation = ar.AutoRemediation()

    def test_find_best_tunnel_empty(self):
        """Без конфигов — нет туннелей."""
        result = self.remediation._find_best_tunnel()
        self.assertEqual(result, "")

    def test_get_results_empty(self):
        results = self.remediation.get_results()
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
