# tests/test_tunnel_optimizer.py
"""Unit-тесты для core/tunnel_optimizer.py."""

import unittest
from unittest import mock
import os

from core import tunnel_optimizer as to


class TestOptimizeIface(unittest.TestCase):
    """Тесты optimize_iface."""

    @mock.patch("subprocess.run")
    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("builtins.open", mock.mock_open())
    def test_optimize_balanced(self, mock_isdir, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = to.optimize_iface("opkgtun0", "balanced")
        self.assertTrue(r["ok"])
        self.assertIn("mtu", r["applied"])

    def test_empty_iface(self):
        r = to.optimize_iface("", "balanced")
        self.assertFalse(r["ok"])

    def test_optimize_iface_rejects_invalid_iface(self):
        r = to.optimize_iface("../../tcp_rmem_max", "balanced")
        self.assertFalse(r["ok"])
        self.assertIn("Недопустимое имя интерфейса", r["error"])

    @mock.patch("subprocess.run")
    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("builtins.open", mock.mock_open())
    def test_optimize_low_latency(self, mock_isdir, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = to.optimize_iface("awg0", "low_latency")
        self.assertTrue(r["ok"])
        self.assertIn("mtu", r["applied"])

    @mock.patch("core.tunnel_optimizer.optimize_iface")
    def test_optimize_nested_tunnel_calculates_inner_mtu(self, mock_optimize_iface):
        mock_optimize_iface.side_effect = [
            {"ok": True, "mtu": 1420, "applied": ["mtu"], "errors": []},
            {"ok": True, "mtu": 1340, "applied": ["mtu"], "errors": []},
        ]
        res = to.optimize_nested_tunnel("opkgtun0", "warp", "awg0", "awg", "balanced")
        self.assertTrue(res["ok"])
        self.assertEqual(res["inner"]["mtu"], 1350)
        self.assertGreaterEqual(res["inner"]["mtu"], 576)

    @mock.patch("core.tunnel_optimizer.optimize_iface")
    def test_nested_tunnel_mtu_never_below_576(self, mock_optimize_iface):
        mock_optimize_iface.side_effect = [
            {"ok": True, "mtu": 600, "applied": ["mtu"], "errors": []},
            {"ok": True, "mtu": 576, "applied": ["mtu"], "errors": []},
        ]
        res = to.optimize_nested_tunnel("opkgtun0", "warp", "awg0", "awg", "low_latency")
        self.assertTrue(res["ok"])
        self.assertEqual(res["inner"]["mtu"], 576)


class TestOptimizeMtu(unittest.TestCase):
    """Тесты _optimize_mtu."""

    @mock.patch("subprocess.run")
    def test_mtu_balanced(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = to._optimize_mtu("opkgtun0", "balanced")
        self.assertTrue(r["ok"])
        self.assertEqual(r["mtu"], 1420)

    @mock.patch("subprocess.run")
    def test_mtu_low_latency(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = to._optimize_mtu("opkgtun0", "low_latency")
        self.assertEqual(r["mtu"], 1280)

    @mock.patch("subprocess.run")
    def test_mtu_throughput(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        r = to._optimize_mtu("opkgtun0", "throughput")
        self.assertEqual(r["mtu"], 1500)


class TestOptimizeCongestion(unittest.TestCase):
    """Тесты _optimize_congestion."""

    def test_returns_dict(self):
        """Проверяем что возвращает словарь (реальные /proc файлы не доступны)."""
        r = to._optimize_congestion()
        self.assertIsInstance(r, dict)
        self.assertIn("ok", r)


class TestGetOptimizationStatus(unittest.TestCase):
    """Тесты get_optimization_status."""

    def test_returns_dict(self):
        status = to.get_optimization_status()
        self.assertIsInstance(status, dict)


if __name__ == "__main__":
    unittest.main()
