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


    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_user_extra_args_are_stored_apart_from_generated_ones(
        self, _chmod, _makedirs, write_conf, _read_conf
    ):
        """get_config()['extra_args'] должен приниматься save_config()
        обратно: раньше туда попадала смесь с --no-cfproxy/--pool-size,
        и round-trip GET→PUT падал на whitelist."""
        result = self.mgr.save_config(mode="direct", extra_args="--v=3")
        self.assertTrue(result["ok"])
        values = write_conf.call_args_list[0].args[1]
        self.assertEqual(values["X_EXTRA_ARGS"], "--v=3")
        self.assertIn("--no-cfproxy", values["EXTRA_ARGS"])
        self.assertIn("--v=3", values["EXTRA_ARGS"])

        with mock.patch("core.tgproxy_manager._read_kv_conf",
                        return_value=values):
            cfg = self.mgr.get_config()
        self.assertEqual(cfg["extra_args"], "--v=3")
        self.assertIn("--no-cfproxy", cfg["extra_args_effective"])
        self.assertTrue(
            self.mgr.save_config(mode="direct",
                                 extra_args=cfg["extra_args"])["ok"])

    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_verbose_goes_into_extra_args_not_into_dead_log_level(
        self, _chmod, _makedirs, write_conf, _read_conf
    ):
        """init.d апстрима LOG_LEVEL не читает, а лог-файл включает по
        `case " $EXTRA_ARGS " in *" -v "*` — то есть по `-v` с ОДНИМ
        дефисом."""
        self.assertTrue(self.mgr.save_config(mode="direct", log_level="2")["ok"])
        values = write_conf.call_args_list[0].args[1]
        self.assertIn(" -v ", " %s " % values["EXTRA_ARGS"])

        write_conf.reset_mock()
        self.assertTrue(self.mgr.save_config(mode="direct", log_level="0")["ok"])
        quiet = write_conf.call_args_list[0].args[1]
        self.assertNotIn(" -v ", " %s " % quiet["EXTRA_ARGS"])

    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_worker_domain_written_to_upstream_config_key(
        self, _chmod, _makedirs, write_conf, _read_conf
    ):
        """CFPROXY_WORKER_DOMAINS — родной ключ config.conf апстрима."""
        self.assertTrue(self.mgr.save_config(
            mode="cfdomain", cf_worker_domain="my.workers.dev")["ok"])
        values = write_conf.call_args_list[0].args[1]
        self.assertEqual(values["CFPROXY_WORKER_DOMAINS"], "my.workers.dev")
        self.assertIn("--cfproxy-worker-domain=my.workers.dev",
                      values["EXTRA_ARGS"])

    def test_get_config_infers_mode_for_legacy_config_without_x_mode(self):
        legacy = {"HOST": "0.0.0.0", "PORT": "1443",
                  "X_CF_DOMAIN": "proxy.example.com"}
        with mock.patch("core.tgproxy_manager._read_kv_conf",
                        return_value=legacy):
            cfg = self.mgr.get_config()
        self.assertEqual(cfg["mode"], "cfdomain")

    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_cf_domain_nfqws_route_has_stable_id(
        self, _chmod, _makedirs, _write_conf, _read_conf
    ):
        """Иначе каждое сохранение плодило новый маршрут в едином слое."""
        saved = []
        fake_unified = mock.Mock()
        fake_unified.save_route.side_effect = (
            lambda data, apply=True: saved.append(data) or {"ok": True})
        with mock.patch.dict(
            "sys.modules", {"core.unified": mock.Mock(manager=fake_unified)}
        ):
            self.mgr.save_config(mode="cfdomain", cf_domain="a.example.com")
            self.mgr.save_config(mode="cfdomain", cf_domain="a.example.com")
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[0]["id"], saved[1]["id"])
        self.assertEqual(saved[0]["id"], tm._CF_DOMAIN_ROUTE_ID)

    @mock.patch("core.tgproxy_manager._read_kv_conf", return_value={})
    @mock.patch("core.tgproxy_manager._write_kv_conf")
    @mock.patch("core.tgproxy_manager.os.makedirs")
    @mock.patch("core.tgproxy_manager.os.chmod")
    def test_clearing_cf_domain_removes_auto_route(
        self, _chmod, _makedirs, _write_conf, _read_conf
    ):
        fake_unified = mock.Mock()
        fake_unified.get_route.return_value = {"id": tm._CF_DOMAIN_ROUTE_ID}
        fake_unified.delete_route.return_value = {"ok": True}
        with mock.patch.dict(
            "sys.modules", {"core.unified": mock.Mock(manager=fake_unified)}
        ):
            self.mgr.save_config(mode="direct")
        fake_unified.delete_route.assert_called_once_with(
            tm._CF_DOMAIN_ROUTE_ID)

    def test_telegram_dc_cidrs_match_project_ipset_list(self):
        """CIDR датацентров берутся из core.telegram.org/resources/cidr.txt —
        тот же источник, что у import/lists/ipset-telegram.txt."""
        import os
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "import", "lists",
            "ipset-telegram.txt")
        expected = set()
        with open(path) as f:
            for line in f:
                line = line.strip()
                # IPv6 сознательно не маршрутизируем (см. комментарий
                # у TELEGRAM_DC_CIDRS).
                if line and not line.startswith("#") and ":" not in line:
                    expected.add(line)
        self.assertEqual(expected - set(tm.TELEGRAM_DC_CIDRS), set())

    def test_route_via_tunnel_rejects_bogus_iface(self):
        res = tm.route_telegram_dc_via_tunnel("awg", "awg0; reboot")
        self.assertFalse(res["ok"])
        self.assertIn("Некорректное имя интерфейса", res["error"])

    def test_available_tunnels_use_iface_not_config_name(self):
        """`awg0-opkgtun0.conf` живёт на интерфейсе opkgtun0 — маршрут
        должен строиться по нему, иначе ip rule вешается в никуда."""
        awg = mock.Mock()
        awg.list_configs.return_value = [
            {"name": "awg0-opkgtun0", "iface": "opkgtun0", "active": True}]
        awg.is_running.return_value = True
        with mock.patch.dict("sys.modules", {
            "core.awg_manager": mock.Mock(get_awg_manager=lambda: awg),
            "core.usque_manager": mock.Mock(
                get_usque_manager=lambda: mock.Mock(list_configs=lambda: [])),
        }):
            tunnels = tm.list_available_warp_tunnels()
        awg_entries = [t for t in tunnels if t["kind"] == "awg"]
        self.assertEqual(len(awg_entries), 1)
        self.assertEqual(awg_entries[0]["iface"], "opkgtun0")
        self.assertTrue(awg_entries[0]["running"])


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

    @mock.patch("core.tgproxy_manager._find_mtproxy_binary", return_value="/opt/usr/bin/tg-mtproxy-client")
    def test_mtproto_rejects_non_url_relay(self, mock_find_bin):
        res = self.mgr.start(relay="relay.example.org")
        self.assertFalse(res["ok"])
        self.assertIn("ws://", res["error"])

    @mock.patch("core.tgproxy_manager._find_mtproxy_binary", return_value="/opt/usr/bin/tg-mtproxy-client")
    @mock.patch("core.tgproxy_manager._lan_ip", return_value="192.168.1.1")
    @mock.patch("core.tgproxy_manager.subprocess.Popen")
    @mock.patch("time.sleep", return_value=None)
    def test_mtproto_listens_on_the_address_it_advertises(
        self, mock_sleep, mock_popen, mock_lan_ip, mock_find_bin
    ):
        """Раньше процесс слушал 127.0.0.1, а ссылка вела на LAN-адрес —
        подключиться с телефона по ней было невозможно."""
        proc = mock.Mock()
        proc.poll.return_value = None
        mock_popen.return_value = proc
        res = self.mgr.start(relay="wss://example.invalid/ws")
        self.assertTrue(res["ok"])
        args = mock_popen.call_args.args[0]
        listen = args[args.index("--listen") + 1]
        self.assertEqual(listen, "192.168.1.1:%d" % tm.MTPROXY_LOCAL_PORT)
        info = self.mgr.get_connect_info()
        self.assertEqual(info["host"], "192.168.1.1")
        self.assertIn("tg://proxy?server=192.168.1.1", info["link"])


if __name__ == "__main__":
    unittest.main()
