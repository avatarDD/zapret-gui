"""Regression tests for usque lifecycle and supported CLI flags.

Факты о поведении бинарника, которые здесь закреплены, сверены с реальным
usque v4.2.0 (собран из тега апстрима Diniboy1123/usque) и с его исходником
cmd/nativetun_linux.go. Подробности — .claude/skills/masque-usque/SKILL.md.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from core.usque_manager import UsqueManager


class TestUsqueManager(unittest.TestCase):
    @mock.patch.object(UsqueManager, "_configure_iface",
                       return_value={"ok": True, "ipv4": "172.16.0.2"})
    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_iface_exists", side_effect=[False, True])
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_auto_falls_back_from_h3_to_h2_once(
        self, _sleep, _makedirs, _isfile, popen, _exists, _binary, _configure
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

    @mock.patch.object(UsqueManager, "_configure_iface",
                       return_value={"ok": True, "ipv4": "172.16.0.2"})
    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_iface_exists", return_value=True)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_uses_supported_keepalive_flag_and_does_not_deadlock(
        self, _sleep, _makedirs, _isfile, popen, _exists, _binary, _configure
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

    @mock.patch.object(UsqueManager, "_configure_iface",
                       return_value={"ok": True})
    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_iface_exists", return_value=False)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_rejects_process_that_dies_before_interface(
        self, _sleep, _makedirs, _isfile, popen, _exists, _binary, _configure
    ):
        proc = mock.Mock()
        proc.pid = 1234
        proc.poll.return_value = 2
        popen.return_value = proc

        mgr = UsqueManager()
        result = mgr.start("opkgtun0", "/tmp/warp.conf")

        self.assertFalse(result["ok"])
        self.assertNotIn("opkgtun0", mgr._processes)

    # ─────── готовность интерфейса ───────

    @mock.patch.object(UsqueManager, "_configure_iface",
                       return_value={"ok": True, "ipv4": "172.16.0.2"})
    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_check_iface_up", return_value=False)
    @mock.patch.object(UsqueManager, "_iface_exists", return_value=True)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_does_not_require_operstate_up(
        self, _sleep, _makedirs, _isfile, popen, _exists, _up, _binary, _conf
    ):
        """С --no-iproute2 usque не поднимает link: operstate остаётся down.

        Ожидание operstate ∈ {up, unknown} убивало каждый рабочий туннель
        через 5 с с «usque не создал интерфейс».
        """
        proc = mock.Mock(pid=4242, stderr=None)
        proc.poll.return_value = None
        popen.return_value = proc

        result = UsqueManager().start("opkgtun0", "/tmp/warp.conf")

        self.assertTrue(result["ok"], result.get("error"))

    @mock.patch.object(UsqueManager, "_find_binary", return_value="/usr/bin/usque")
    @mock.patch.object(UsqueManager, "_iface_exists", return_value=True)
    @mock.patch("core.usque_manager.subprocess.Popen")
    @mock.patch("core.usque_manager.os.path.isfile", return_value=True)
    @mock.patch("core.usque_manager.os.makedirs")
    @mock.patch("core.usque_manager.time.sleep")
    def test_start_fails_when_iface_cannot_be_configured(
        self, _sleep, _makedirs, _isfile, popen, _exists, _binary
    ):
        """Ненастроенный интерфейс — не «запущенный туннель»."""
        proc = mock.Mock(pid=4242, stderr=None)
        proc.poll.return_value = None
        popen.return_value = proc

        mgr = UsqueManager()
        with mock.patch.object(mgr, "_configure_iface",
                               return_value={"ok": False, "error": "no ip"}):
            result = mgr.start("opkgtun0", "/tmp/warp.conf")

        self.assertFalse(result["ok"])
        self.assertNotIn("opkgtun0", mgr._processes)

    # ─────── настройка интерфейса ───────

    def test_configure_iface_assigns_addresses_and_brings_link_up(self):
        """Порядок и префиксы повторяют cmd/nativetun_linux.go: /32 и /128."""
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            json.dump({"private_key": "k", "access_token": "t", "id": "i",
                       "ipv4": "172.16.0.2",
                       "ipv6": "2606:4700:110::1"}, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)

        calls = []

        def fake_run(args, timeout=10):
            calls.append(args)
            return 0, "", ""

        with mock.patch("core.usque_manager._run", side_effect=fake_run):
            res = UsqueManager()._configure_iface("opkgtun0", path)

        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(res["ipv4"], "172.16.0.2")
        joined = [" ".join(c) for c in calls]
        self.assertIn("ip link set dev opkgtun0 mtu 1280", joined)
        self.assertIn("ip -4 address add 172.16.0.2/32 dev opkgtun0", joined)
        self.assertIn("ip -6 address add 2606:4700:110::1/128 dev opkgtun0",
                      joined)
        self.assertIn("ip link set dev opkgtun0 up", joined)
        self.assertLess(joined.index("ip -4 address add 172.16.0.2/32"
                                     " dev opkgtun0"),
                        joined.index("ip link set dev opkgtun0 up"))

    def test_configure_iface_survives_missing_ipv6(self):
        """Хост без IPv6 не должен ронять рабочий v4-туннель."""
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            json.dump({"ipv4": "172.16.0.2", "ipv6": "2606:4700:110::1"}, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)

        def fake_run(args, timeout=10):
            if "-6" in args:
                return 1, "", "RTNETLINK answers: Operation not supported"
            return 0, "", ""

        with mock.patch("core.usque_manager._run", side_effect=fake_run):
            res = UsqueManager()._configure_iface("opkgtun0", path)

        self.assertTrue(res["ok"], res.get("error"))

    def test_configure_iface_reports_ipv4_failure(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            json.dump({"ipv4": "172.16.0.2"}, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)

        def fake_run(args, timeout=10):
            if "-4" in args:
                return 2, "", "RTNETLINK answers: Permission denied"
            return 0, "", ""

        with mock.patch("core.usque_manager._run", side_effect=fake_run):
            res = UsqueManager()._configure_iface("opkgtun0", path)

        self.assertFalse(res["ok"])
        self.assertIn("Permission denied", res["error"])

    def test_configure_iface_tolerates_already_assigned_address(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf",
                                         delete=False) as fh:
            json.dump({"ipv4": "172.16.0.2"}, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)

        def fake_run(args, timeout=10):
            if "-4" in args:
                return 2, "", "RTNETLINK answers: File exists"
            return 0, "", ""

        with mock.patch("core.usque_manager._run", side_effect=fake_run):
            res = UsqueManager()._configure_iface("opkgtun0", path)

        self.assertTrue(res["ok"], res.get("error"))

    # ─────── версия ───────

    def test_version_uses_version_subcommand_not_unknown_flag(self):
        """`usque --version` не существует — cobra падает с rc=1.

        Настоящий вывод `usque version` (stdout):
            usque version: 4.2.0
            Commit: ...
            Build Date: ...
        stderr при этом содержит жалобу на отсутствующий config.json.
        """
        captured = {}

        def fake_run(args, **kw):
            captured["argv"] = args
            return mock.Mock(
                returncode=0,
                stdout="usque version: 4.2.0\nCommit: abc\nBuild Date: x\n",
                stderr="Config file not found: open config.json: no such file\n")

        with mock.patch("core.usque_manager.subprocess.run",
                        side_effect=fake_run):
            version = UsqueManager()._get_version("/usr/bin/usque")

        self.assertEqual(version, "4.2.0")
        self.assertIn("version", captured["argv"])
        self.assertNotIn("--version", captured["argv"])

    def test_version_handles_dev_builds(self):
        """Сборка без -ldflags печатает `dev` — это не повод отдавать мусор."""
        with mock.patch("core.usque_manager.subprocess.run",
                        return_value=mock.Mock(
                            returncode=0,
                            stdout="usque version: dev\nCommit: none\n",
                            stderr="")):
            self.assertEqual(
                UsqueManager()._get_version("/usr/bin/usque"), "dev")

    def test_version_never_returns_usage_text(self):
        """Регрессия: раньше в поле версии уезжал текст ошибки cobra."""
        with mock.patch("core.usque_manager.subprocess.run",
                        return_value=mock.Mock(
                            returncode=1,
                            stdout="",
                            stderr="Error: unknown flag: --version\nUsage:\n")):
            self.assertEqual(
                UsqueManager()._get_version("/usr/bin/usque"), "")

    # ─────── формат конфига ───────

    def test_real_register_config_has_no_unknown_fields(self):
        """Набор полей — из настоящего config.json, выданного usque 4.2.0."""
        real = {
            "private_key": "k", "endpoint_v4": "162.159.198.2",
            "endpoint_v6": "2606:4700:103::2",
            "endpoint_h2_v4": "162.159.198.2", "endpoint_h2_v6": "",
            "endpoint_pub_key": "pem", "id": "uuid", "access_token": "uuid",
            "ipv4": "172.16.0.2", "ipv6": "2606:4700:110::1",
        }
        unknown = [k for k in real if k not in UsqueManager._USQUE_KNOWN]
        self.assertEqual(unknown, [])

    def test_license_is_not_required(self):
        """Бесплатная регистрация не выдаёт license — требовать его нельзя."""
        self.assertNotIn("license", UsqueManager._USQUE_REQUIRED)


if __name__ == "__main__":
    unittest.main()
