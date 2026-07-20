# tests/test_tunnel_monitor.py
"""Unit-тесты для core/tunnel_monitor.py."""

import unittest
import time

from core import tunnel_monitor as tm


class TestTunnelMonitor(unittest.TestCase):
    """Тесты TunnelMonitor."""

    def setUp(self):
        self.monitor = tm.TunnelMonitor()

    def test_initial_status(self):
        status = self.monitor.get_status()
        self.assertFalse(status["running"])
        self.assertEqual(status["interfaces"], 0)

    def test_read_counters_missing_iface(self):
        rx, tx = self.monitor._read_counters("nonexistent_iface_xyz")
        self.assertIsNone(rx)
        self.assertIsNone(tx)

    def test_read_counters_special_nfqws(self):
        """nfqws2 читает из /proc."""
        rx, tx = self.monitor._read_counters("__nfqws2__")
        self.assertIsInstance(rx, int)
        self.assertIsInstance(tx, int)

    def test_get_metrics_empty(self):
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics, [])

    def test_metrics_structure(self):
        """Проверяем что get_metrics возвращает корректную структуру."""
        metrics = self.monitor.get_metrics()
        self.assertIsInstance(metrics, list)


if __name__ == "__main__":
    unittest.main()
