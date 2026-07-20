# tests/test_dpi_filter.py
"""Unit-тесты для DPI-type фильтрации стратегий (strategy_scanner._filter_by_dpi)."""

import unittest

from core.models import CatalogEntry


def _make_entry(args_str):
    """Создать CatalogEntry с заданными аргументами."""
    return CatalogEntry(section_id="test", name="test", args=args_str)


class TestDpiFilter(unittest.TestCase):
    """Тесты _filter_by_dpi метода StrategyScanner."""

    def _get_scanner(self):
        """Получить scanner без запуска."""
        from core.strategy_scanner import StrategyScanner
        return StrategyScanner()

    def _filter(self, entries, dpi_type):
        scanner = self._get_scanner()
        return scanner._filter_by_dpi(entries, dpi_type)

    def test_tls_dpi_keeps_tls_entries(self):
        entries = [
            _make_entry("--filter-l7=tls --payload=tls_client_hello\n--lua-desync=fake"),
            _make_entry("--filter-l7=tls --payload=tls_client_hello\n--lua-desync=multisplit"),
        ]
        result = self._filter(entries, "tls_dpi")
        self.assertEqual(len(result), 2)

    def test_tls_dpi_removes_quic_entries(self):
        entries = [
            _make_entry("--filter-l7=tls --payload=tls_client_hello\n--lua-desync=fake"),
            _make_entry("--filter-l7=quic --payload=quic_initial\n--lua-desync=udplen"),
        ]
        result = self._filter(entries, "tls_dpi")
        self.assertEqual(len(result), 1)
        self.assertIn("tls", result[0].args)

    def test_quic_block_keeps_quic_entries(self):
        entries = [
            _make_entry("--filter-l7=quic --payload=quic_initial\n--lua-desync=fake"),
            _make_entry("--filter-l7=tls --payload=tls_client_hello\n--lua-desync=split"),
        ]
        result = self._filter(entries, "quic_block")
        self.assertEqual(len(result), 1)
        self.assertIn("quic", result[0].args)

    def test_quic_block_removes_tls_entries(self):
        entries = [
            _make_entry("--filter-l7=quic --payload=quic_initial\n--lua-desync=udplen"),
            _make_entry("--filter-l7=tls --payload=tls_client_hello\n--lua-desync=fake"),
        ]
        result = self._filter(entries, "quic_block")
        self.assertEqual(len(result), 1)
        self.assertIn("quic", result[0].args)

    def test_dns_fake_skips_all(self):
        entries = [_make_entry("--filter-l7=tls\n--lua-desync=fake")]
        result = self._filter(entries, "dns_fake")
        self.assertEqual(len(result), 0)

    def test_ip_block_skips_all(self):
        entries = [_make_entry("--filter-l7=tls\n--lua-desync=fake")]
        result = self._filter(entries, "ip_block")
        self.assertEqual(len(result), 0)

    def test_full_block_skips_all(self):
        entries = [_make_entry("--filter-l7=tls\n--lua-desync=fake")]
        result = self._filter(entries, "full_block")
        self.assertEqual(len(result), 0)

    def test_unknown_type_keeps_all(self):
        entries = [_make_entry("--filter-l7=tls\n--lua-desync=fake")]
        result = self._filter(entries, "unknown_type")
        self.assertEqual(len(result), 1)

    def test_empty_dpi_type_keeps_all(self):
        entries = [_make_entry("--filter-l7=tls\n--lua-desync=fake")]
        result = self._filter(entries, "")
        self.assertEqual(len(result), 1)

    def test_clienthello_dpi_keeps_multisplit(self):
        entries = [
            _make_entry("--filter-l7=tls\n--lua-desync=multisplit:pos=1"),
            _make_entry("--filter-l7=tls\n--lua-desync=split:pos=2"),
            _make_entry("--filter-l7=quic\n--lua-desync=fake"),
        ]
        result = self._filter(entries, "clienthello_dpi")
        # Should keep TLS entries (must_have filter)
        self.assertGreater(len(result), 0)
        for e in result:
            self.assertIn("tls", e.args)


if __name__ == "__main__":
    unittest.main()
