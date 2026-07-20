# tests/test_cli.py
"""Unit-тесты для core/cli.py (парсер и диспетчеризация)."""

import unittest
from unittest import mock

from core import cli


class TestParser(unittest.TestCase):

    def test_status(self):
        args = cli.build_parser().parse_args(["status"])
        self.assertEqual(args.command, "status")

    def test_nfqws_actions(self):
        for a in ("start", "stop", "restart", "status"):
            args = cli.build_parser().parse_args(["nfqws", a])
            self.assertEqual(args.action, a)

    def test_nfqws_bad_action(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["nfqws", "frobnicate"])

    def test_strategy_apply_with_id(self):
        args = cli.build_parser().parse_args(["strategy", "apply", "foo"])
        self.assertEqual(args.action, "apply")
        self.assertEqual(args.id, "foo")

    def test_singbox_up_with_name(self):
        args = cli.build_parser().parse_args(["singbox", "up", "vpn"])
        self.assertEqual(args.action, "up")
        self.assertEqual(args.name, "vpn")

    def test_no_command_errors(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args([])


class TestDispatchCoverage(unittest.TestCase):

    def test_all_commands_have_handlers(self):
        for c in cli.COMMANDS:
            self.assertIn(c, cli._DISPATCH)


class TestRun(unittest.TestCase):

    def test_run_status(self):
        # init_config мокаем, чтобы не трогать ФС; менеджеры внутри
        # status обёрнуты в try/except и вернут 0 при любой ошибке.
        with mock.patch("core.config_manager.init_config"):
            rc = cli.run(["status"])
        self.assertEqual(rc, 0)

    def test_run_singbox_up_without_name(self):
        with mock.patch("core.config_manager.init_config"):
            rc = cli.run(["singbox", "up"])
        self.assertEqual(rc, 2)

    def test_run_singbox_up_dispatches_manager(self):
        fake = mock.Mock()
        fake.up.return_value = {"ok": True}
        with mock.patch("core.config_manager.init_config"), \
             mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=fake):
            rc = cli.run(["singbox", "up", "vpn"])
        self.assertEqual(rc, 0)
        fake.up.assert_called_once_with("vpn")

    def test_run_tgproxy_status(self):
        fake = mock.Mock()
        fake.get_status.return_value = {"running": False, "engine": "tgwsproxy"}
        with mock.patch("core.config_manager.init_config"), \
             mock.patch("core.tgproxy_manager.get_tgwsproxy_manager",
                        return_value=fake):
            rc = cli.run(["tgproxy", "status"])
        self.assertEqual(rc, 0)
        fake.get_status.assert_called_once()

    def test_run_dns_routing_list(self):
        fake = mock.Mock()
        fake.get_rules.return_value = [{"domain": "example.com", "dns": "cloudflare", "description": ""}]
        with mock.patch("core.config_manager.init_config"), \
             mock.patch("core.dns_routing.get_dns_routing_manager",
                        return_value=fake):
            rc = cli.run(["dns-routing", "list"])
        self.assertEqual(rc, 0)
        fake.get_rules.assert_called_once()

    def test_run_updates(self):
        fake = mock.Mock()
        fake.return_value = None
        with mock.patch("core.config_manager.init_config"), \
             mock.patch("core.update_checker.check_all",
                        return_value={"results": [{"name": "gui", "current": "1.0", "latest": "1.1", "has_update": True}]}):
            rc = cli.run(["updates"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
