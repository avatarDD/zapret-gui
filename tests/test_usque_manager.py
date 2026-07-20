"""Regression tests for usque lifecycle and supported CLI flags."""

import os
import unittest
from unittest import mock

from core.usque_manager import UsqueManager


class TestUsqueManager(unittest.TestCase):
    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_check_iface_up", side_effect=[False, True])
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_auto_falls_back_from_h3_to_h2_once(
        self, _sleep, _makedirs, _isfile, popen, _iface_up, _binary
    ):
        failed = mock.Mock(pid=111, stderr=None)
        failed.poll.return_value = 2
        failed.wait.return_value = 2
        healthy = mock.Mock(pid=222, stderr=None)
        healthy.poll.return_value = None
        popen.side_effect = [failed, healthy]

        result = UsqueManager().start(
            "opkgtun0", "/tmp/warp.conf", transport_profile="auto")

        self.assertTrue(result["ok"])
        self.assertEqual(result["fallback_from"], "performance")
        self.assertNotIn("--http2", popen.call_args_list[0].args[0])
        self.assertIn("--http2", popen.call_args_list[1].args[0])

    @mock.patch("core.usque_manager.os.path.exists", return_value=False)
    @mock.patch("core.usque_manager.os.listdir", return_value=["lo", "opkgtun0"])
    def test_allocate_iface_avoids_existing_and_reserved(self, _listdir, _exists):
        mgr = UsqueManager()
        self.assertEqual(mgr.allocate_iface("opkgtun", {"opkgtun1"}), "opkgtun2")

    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_check_iface_up", return_value=True)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_uses_supported_keepalive_flag_and_does_not_deadlock(
        self, _sleep, _makedirs, _isfile, popen, _iface_up, _binary
    ):
        proc = mock.Mock()
        proc.pid = 1234
        proc.poll.return_value = None
        popen.return_value = proc

        mgr = UsqueManager()
        result = mgr.start("opkgtun0", "/tmp/warp.conf", low_latency=True)

        self.assertTrue(result["ok"])
        argv = popen.call_args.args[0]
        self.assertIn("--keepalive-period", argv)
        self.assertIn("10s", argv)
        self.assertNotIn("--tcp-nodelay", argv)
        self.assertNotIn("--keepalive", argv)

    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_check_iface_up", return_value=False)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_rejects_process_that_dies_before_interface(
        self, _sleep, _makedirs, _isfile, popen, _iface_up, _binary
    ):
        proc = mock.Mock()
        proc.pid = 1234
        proc.poll.return_value = 2
        popen.return_value = proc

        mgr = UsqueManager()
        result = mgr.start("opkgtun0", "/tmp/warp.conf")

        self.assertFalse(result["ok"])
        self.assertNotIn("opkgtun0", mgr._processes)


if __name__ == "__main__":
    unittest.main()
