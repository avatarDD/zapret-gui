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
        self.assertFalse(res["ok"])
        self.assertIsNone(res["inner"]["mtu"])


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
        self.assertEqual(r["mtu"], 1420)


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


class TestPmtuProbe(unittest.TestCase):
    @mock.patch("core.tunnel_optimizer._which", return_value=True)
    @mock.patch("core.tunnel_optimizer.subprocess.run")
    def test_probe_pmtu_binary_searches_dataplane(self, run, _which):
        def result(cmd, **_kwargs):
            payload = int(cmd[cmd.index("-s") + 1])
            # IPv4 payload + 28 bytes succeeds through MTU 1400.
            return mock.Mock(returncode=0 if payload + 28 <= 1400 else 1,
                             stdout="", stderr="")
        run.side_effect = result
        res = to.probe_pmtu("opkgtun0", "1.1.1.1", 1280, 1500)
        self.assertTrue(res["ok"])
        self.assertEqual(res["pmtu"], 1400)
        self.assertTrue(res["ipv6_safe"])

    def test_probe_pmtu_rejects_hostname(self):
        res = to.probe_pmtu("opkgtun0", "example.com")
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
