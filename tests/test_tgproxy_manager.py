"""Unit-тесты для core/tgproxy_manager.py."""

import unittest
from unittest import mock

from core import tgproxy_manager as tm


class TestTgWsProxyManager(unittest.TestCase):

    def setUp(self):
        self.mgr = tm.TgWsProxyManager()

    @mock.patch("core.tgproxy_manager._read_kv_conf")
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_save_preserves_existing_secret_and_masks_result(
        self, _chmod, _makedirs, write_conf, read_conf
    ):
        secret = "0123456789abcdef0123456789abcdef"
        read_conf.return_value = {"SECRET": secret}
        result = self.mgr.save_config(mode="direct")
        self.assertTrue(result["ok"])
        self.assertNotIn("secret", result)
        self.assertTrue(result["secret_configured"])
        secret_values = write_conf.call_args_list[1].args[1]
        self.assertEqual(secret_values["SECRET"], secret)

    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_hybrid_and_resource_profile_generate_validated_flags(
        self, _chmod, _makedirs, write_conf, _read_conf
    ):
        result = self.mgr.save_config(
            mode="hybrid", pool_size=1, max_conns=32, buf_kb=32)
        self.assertTrue(result["ok"])
        values = write_conf.call_args_list[0].args[1]
        self.assertIn("--cfproxy-priority=false", values["EXTRA_ARGS"])
        self.assertIn("--pool-size=1", values["EXTRA_ARGS"])
        self.assertIn("--max-conns=32", values["EXTRA_ARGS"])

    def test_extra_args_uses_strict_whitelist(self):
        result = self.mgr.save_config(extra_args="--secret=bad")
        self.assertFalse(result["ok"])
        self.assertIn("Недопустимый", result["error"])

    @mock.patch("core.tgproxy_manager._find_tgwsproxy_initd", return_value="/opt/etc/init.d/S99tg-ws-proxy")
    @mock.patch("core.tgproxy_manager._pkg_version", return_value="0.9.2")
    def test_detect_prefers_package_and_initd(self, mock_pkg_version, mock_find_initd):
        det = self.mgr.detect()
        self.assertTrue(det["installed"])
        self.assertEqual(det["path"], "/opt/etc/init.d/S99tg-ws-proxy")
        self.assertEqual(det["package"], "tg-ws-proxy")
        self.assertEqual(det["version"], "0.9.2")

    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("os.makedirs")
    def test_tgwsproxy_default_host_is_not_silent_0000(self, mock_makedirs, mock_write):
        self.mgr.save_config()
        args, kwargs = mock_write.call_args_list[0]
        values = args[1]
        self.assertEqual(values["HOST"], "127.0.0.1")
        self.assertNotEqual(values["HOST"], "0.0.0.0")

    @mock.patch("core.tgproxy_manager._lan_ip", return_value="192.168.1.1")
    @mock.patch.object(tm.TgWsProxyManager, "get_config", return_value={
        "host": "0.0.0.0",
        "port": 1443,
        "secret": "0123456789abcdef0123456789abcdef",
        "fake_tls_domain": "",
    })
    def test_connect_info_uses_lan_ip_fallback(self, mock_get_config, mock_lan_ip):
        info = self.mgr.get_connect_info()
        self.assertEqual(info["host"], "192.168.1.1")
        self.assertIn("tg://proxy?server=192.168.1.1", info["link"])

    @mock.patch("core.tgproxy_manager._find_tgwsproxy_initd", return_value="/opt/etc/init.d/S99tg-ws-proxy")
    @mock.patch("core.tgproxy_manager.subprocess.run")
    @mock.patch.object(tm.TgWsProxyManager, "detect", return_value={
        "installed": True,
        "path": "/opt/etc/init.d/S99tg-ws-proxy",
        "config_exists": True,
    })
    @mock.patch.object(tm.TgWsProxyManager, "_status_locked", return_value={"running": True})
    @mock.patch("time.sleep", return_value=None)
    def test_start_stop_use_discovered_initd(
        self, mock_sleep, mock_status_locked, mock_detect, mock_run, mock_find_initd
    ):
        mock_run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
        start = self.mgr.start()
        stop = self.mgr.stop()
        self.assertTrue(start["ok"])
        self.assertTrue(stop["ok"])
        self.assertEqual(mock_run.call_args_list[0].args[0][0], "/opt/etc/init.d/S99tg-ws-proxy")
        self.assertEqual(mock_run.call_args_list[1].args[0][0], "/opt/etc/init.d/S99tg-ws-proxy")


class TestMtProxyClientManager(unittest.TestCase):

    def setUp(self):
        self.mgr = tm.MtProxyClientManager()

    @mock.patch("core.tgproxy_manager._find_mtproxy_binary", return_value="/opt/usr/bin/tg-mtproxy-client")
    def test_mtproto_requires_explicit_relay(self, mock_find_bin):
        res = self.mgr.start(relay="")
        self.assertFalse(res["ok"])
        self.assertIn("relay обязателен", res["error"])

    @mock.patch("core.tgproxy_manager._find_mtproxy_binary", return_value="/opt/usr/bin/tg-mtproxy-client")
    @mock.patch("core.tgproxy_manager.subprocess.Popen")
    @mock.patch("time.sleep", return_value=None)
    def test_mtproto_start_with_relay_succeeds(self, mock_sleep, mock_popen, mock_find_bin):
        proc = mock.Mock()
        proc.poll.return_value = None
        mock_popen.return_value = proc
        res = self.mgr.start(relay="wss://example.invalid/ws")
        self.assertTrue(res["ok"])
        self.assertEqual(res["port"], tm.MTPROXY_LOCAL_PORT)
        self.assertTrue(self.mgr.get_status()["running"])


if __name__ == "__main__":
    unittest.main()
