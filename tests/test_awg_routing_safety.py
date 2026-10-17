# tests/test_awg_routing_safety.py
"""
Сторожа по итогам код-ревью AWG и маршрутизации.

Каждый класс — один найденный дефект, который уже ломал (или ломал бы)
туннель у пользователя:

* I1..I5 из нескольких тегов (`<r 32><t>`, `<b 0x..><r 16>`) портились
  при разборе и рендере — демон получал мусор;
* поиск PID демона по подстроке: `amneziawg-go warp` находил демон
  `warp2`, и `down warp` убивал соседний туннель;
* рестарт снимал правила маршрутизации и blackhole kill-switch'а — на
  время рестарта (а при неудачном `up` навсегда) трафик утекал мимо
  туннеля;
* нет исключения для собственного Endpoint — правило, накрывшее его,
  заворачивало UDP демона в этот же туннель (петля);
* watchdog перезапускал (то есть удалял) чужие интерфейсы;
* WARP-in-WARP с одинаковым Endpoint у outer и inner — петля outer'а;
* CIDR `0.0.0.0/0` уводил в туннель ответы роутера клиентам LAN;
* неудачный update_rule выкидывал рабочее правило из storage;
* любой «Invalid argument» от ядра навсегда выключал маску fwmark.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from core import awg_config, awg_manager


# ─────────────────────── I1..I5: теги ────────────────────────────────

class TestSignatureTags(unittest.TestCase):

    def _i1(self, value):
        cfg = awg_config.parse_conf(
            "[Interface]\nPrivateKey = x\nI1 = %s\n" % value)
        setconf = [l for l in awg_config.render_setconf(cfg).splitlines()
                   if l.startswith("I1")]
        return cfg["interface"]["I1"], setconf

    def test_tag_sequences_are_kept_verbatim(self):
        for value in ("<r 32><t>", "<b 0xabcd><r 16>", "<rc 8><b 0x0102>",
                      "<rd 4>"):
            stored, setconf = self._i1(value)
            self.assertEqual(stored, value)
            self.assertEqual(setconf, ["I1 = %s" % value])

    def test_single_b_tag_still_normalised_to_hex(self):
        stored, setconf = self._i1("<b 0xab cd>")
        self.assertEqual(stored, "abcd")
        self.assertEqual(setconf, ["I1 = <b 0xabcd>"])

    def test_multiline_b_still_joined(self):
        cfg = awg_config.parse_conf(
            "[Interface]\nPrivateKey = x\nI1 = <b\n0xabcd\nef01\n>\n")
        self.assertEqual(cfg["interface"]["I1"], "abcdef01")

    def test_round_trip_through_render_conf(self):
        cfg = awg_config.parse_conf(
            "[Interface]\nPrivateKey = x\nI1 = <b 0xab><r 16>\n"
            "I2 = <r 32><t>\n")
        again = awg_config.parse_conf(awg_config.render_conf(cfg))
        self.assertEqual(again["interface"]["I1"], "<b 0xab><r 16>")
        self.assertEqual(again["interface"]["I2"], "<r 32><t>")

    def test_i1_lengths_skips_tagged_value(self):
        self.assertIsNone(awg_manager._compute_i1_lengths(
            {"interface": {"I1": "<r 32><t>"}}, "i1: <r 32><t>"))


# ─────────────────────── PID демона ──────────────────────────────────

class TestDaemonPid(unittest.TestCase):

    def test_argv_match_is_per_token(self):
        has = awg_manager._argv_has_seq
        self.assertTrue(has(["/opt/usr/sbin/amneziawg-go", "warp"],
                            ["amneziawg-go", "warp"]))
        self.assertTrue(has(["/opt/usr/sbin/amneziawg-go", "warp"],
                            ["/opt/usr/sbin/amneziawg-go", "warp"]))
        # Главное: префикс имени соседнего туннеля — НЕ совпадение.
        self.assertFalse(has(["/opt/usr/sbin/amneziawg-go", "warp2"],
                             ["amneziawg-go", "warp"]))

    def test_pgrep_first_does_not_pick_neighbour(self):
        argvs = {"100": ["/opt/usr/sbin/amneziawg-go", "warp2"],
                 "200": ["/opt/usr/sbin/amneziawg-go", "warp"]}
        with mock.patch.object(awg_manager.os, "listdir",
                               return_value=list(argvs) + ["self"]), \
             mock.patch.object(awg_manager, "_pid_argv",
                               side_effect=lambda pid: argvs.get(str(pid),
                                                                 [])):
            self.assertEqual(
                awg_manager._pgrep_first(["amneziawg-go", "warp"]), 200)

    def test_daemon_of_other_iface_is_not_ours(self):
        with mock.patch.object(awg_manager, "_pid_alive", return_value=True), \
             mock.patch.object(awg_manager, "_pid_cmdline",
                               return_value="/opt/usr/sbin/amneziawg-go warp2"):
            self.assertFalse(awg_manager._pid_is_our_daemon(4242, "warp"))
            self.assertTrue(awg_manager._pid_is_our_daemon(4242, "warp2"))


# ─────────────────────── рестарт и kill-switch ───────────────────────

class _MgrBase(unittest.TestCase):

    def setUp(self):
        from tests.test_awg_manager_lifecycle import FakePlatform, SAMPLE_CONF
        self.tmpdir = tempfile.mkdtemp(prefix="awg-safety-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = awg_manager.AwgManager()
        self.calls = []

        def fake_run(args, timeout=15, input_text=None, env=None):
            self.calls.append(list(args))
            return 0, "", ""

        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_config_dir",
                              return_value=self.platform.config_dir),
            mock.patch.object(self.mgr, "_run_dir",
                              return_value=self.platform.run_dir),
            mock.patch.object(self.mgr, "_scan_dirs",
                              return_value=[self.platform.config_dir]),
            mock.patch.object(self.mgr, "_awg_bin", return_value="/fake/awg"),
            mock.patch.object(self.mgr, "_table_id_for", return_value=321),
            mock.patch.object(awg_manager, "_run", side_effect=fake_run),
            mock.patch.object(awg_manager, "_is_native_ndms_iface",
                              return_value=False),
        ]
        for p in self._patches:
            p.start()
        with open(os.path.join(self.platform.config_dir, "awg0.conf"),
                  "w") as f:
            f.write(SAMPLE_CONF)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestRestartKeepsRouting(_MgrBase):

    def _restart(self, killswitch_on):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                               return_value=["awg0"]), \
             mock.patch.object(self.mgr, "_do_up",
                               return_value={"ok": True}), \
             mock.patch("core.routing.applier.remove_all_on_interface_down"
                        ) as remove_all, \
             mock.patch("core.routing.killswitch.enabled",
                        return_value=killswitch_on), \
             mock.patch("core.routing.killswitch.present",
                        return_value=False), \
             mock.patch("core.routing.dnsmasq_integration"
                        ".DnsmasqIntegration"):
            res = self.mgr.restart("awg0")
        self.assertTrue(res["ok"])
        return remove_all

    def test_restart_does_not_remove_routing_rules(self):
        # С kill-switch'ем правила переживают рестарт — без утечки.
        self._restart(killswitch_on=True).assert_not_called()

    def test_restart_without_killswitch_is_full_down_up(self):
        # Без kill-switch'а — прежний полный down + up (как до 13.10):
        # держать правила незачем, таблица между down и up всё равно пуста.
        self._restart(killswitch_on=False).assert_called_once_with("awg0")

    def test_explicit_down_still_removes_rules(self):
        with mock.patch.object(self.mgr, "_wg_interfaces", return_value=[]), \
             mock.patch("core.routing.applier.remove_all_on_interface_down"
                        ) as remove_all, \
             mock.patch("core.routing.dnsmasq_integration"
                        ".DnsmasqIntegration"):
            self.mgr.down("awg0")
        remove_all.assert_called_once_with("awg0")

    def test_restart_returns_blackhole_after_flush(self):
        with mock.patch("core.routing.killswitch.present",
                        side_effect=lambda t, fam: fam == "-4"), \
             mock.patch("core.routing.killswitch.ensure") as ensure:
            self.mgr._remove_added_routes("awg0", keep_killswitch=True)
        flushes = [c for c in self.calls if "flush" in c]
        self.assertEqual(len(flushes), 2)
        ensure.assert_called_once_with(321, families=["v4"])

    def test_flush_even_without_routes_json(self):
        self.mgr._remove_added_routes("awg0")
        self.assertTrue(any("flush" in c for c in self.calls))

    def test_restart_refuses_foreign_iface(self):
        with mock.patch.object(self.mgr, "_wg_interfaces",
                               return_value=["wg9"]), \
             mock.patch.object(self.mgr, "_do_down") as do_down:
            res = self.mgr.restart("wg9")
        self.assertFalse(res["ok"])
        do_down.assert_not_called()


class TestEndpointBypass(_MgrBase):

    def test_rule_is_router_only_and_before_ours(self):
        entries = self.mgr._add_endpoint_bypass(["162.159.192.1", "2606::1"])
        adds = [c for c in self.calls if c[3:4] == ["add"]]
        self.assertEqual(len(adds), 2)
        self.assertEqual(adds[0][:2], ["ip", "-4"])
        self.assertIn("162.159.192.1/32", adds[0])
        self.assertIn("2606::1/128", adds[1])
        for argv in adds:
            self.assertEqual(argv[argv.index("iif") + 1], "lo")
            self.assertEqual(argv[argv.index("lookup") + 1], "main")
            prio = int(argv[argv.index("priority") + 1])
            self.assertLess(prio, 10000)
        self.assertEqual([e["bypass"] for e in entries],
                         ["162.159.192.1/32", "2606::1/128"])

    def test_can_be_disabled(self):
        with mock.patch.object(self.mgr, "_endpoint_bypass_enabled",
                               return_value=False):
            self.assertEqual(self.mgr._add_endpoint_bypass(["1.2.3.4"]), [])
        self.assertEqual(self.calls, [])

    def test_down_removes_bypass_from_routes_json(self):
        with open(self.mgr._routes_path("awg0"), "w") as f:
            json.dump([{"family": "-4", "bypass": "1.2.3.4/32"}], f)
        self.mgr._remove_added_routes("awg0")
        dels = [c for c in self.calls if c[3:4] == ["del"]]
        self.assertTrue(any("1.2.3.4/32" in c and "iif" in c for c in dels))

    def test_up_installs_bypass_before_setconf(self):
        order = []
        go = os.path.join(self.platform.binary_dir, "amneziawg-go")
        with open(go, "w") as fh:
            fh.write("#!/bin/true\n")
        with mock.patch.object(self.mgr, "_amneziawg_go", return_value=go), \
             mock.patch.object(self.mgr, "_wg_interfaces", return_value=[]), \
             mock.patch.object(self.mgr, "_probe_binary",
                               return_value={"broken": False, "detail": ""}), \
             mock.patch.object(awg_manager, "_pgrep_first", return_value=None), \
             mock.patch.object(awg_manager, "_resolve_endpoint_ip",
                               return_value=("162.159.192.1", False)), \
             mock.patch.object(self.mgr, "_add_endpoint_bypass",
                               side_effect=lambda ips: order.append(
                                   ("bypass", list(ips))) or []), \
             mock.patch.object(self.mgr, "_apply_setconf",
                               side_effect=lambda *a: order.append(
                                   ("setconf",)) or {"ok": True}), \
             mock.patch("core.routing.applier.apply_all_on_interface_up"):
            res = self.mgr.up("awg0")
        self.assertTrue(res["ok"], res)
        self.assertEqual(order[0], ("bypass", ["162.159.192.1"]))
        self.assertEqual(order[1], ("setconf",))

    def test_up_fails_when_link_does_not_come_up(self):
        go = os.path.join(self.platform.binary_dir, "amneziawg-go")
        with open(go, "w") as fh:
            fh.write("#!/bin/true\n")

        def fake_run(args, timeout=15, input_text=None, env=None):
            self.calls.append(list(args))
            if args[:3] == ["ip", "link", "set"] and args[-1] == "up":
                return 2, "", "Cannot find device"
            return 0, "", ""

        with mock.patch.object(awg_manager, "_run", side_effect=fake_run), \
             mock.patch.object(self.mgr, "_amneziawg_go", return_value=go), \
             mock.patch.object(self.mgr, "_wg_interfaces", return_value=[]), \
             mock.patch.object(self.mgr, "_probe_binary",
                               return_value={"broken": False, "detail": ""}), \
             mock.patch.object(awg_manager, "_pgrep_first", return_value=None), \
             mock.patch.object(awg_manager, "_resolve_endpoint_ip",
                               return_value=("162.159.192.1", False)), \
             mock.patch.object(self.mgr, "_apply_setconf",
                               return_value={"ok": True}), \
             mock.patch("core.routing.applier.apply_all_on_interface_up"
                        ) as apply_all:
            res = self.mgr.up("awg0")
        self.assertFalse(res["ok"])
        apply_all.assert_not_called()


# ─────────────────────── watchdog ────────────────────────────────────

class TestWatchdogForeignIface(unittest.TestCase):

    def test_foreign_iface_is_not_restarted(self):
        from core import awg_watchdog
        wd = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        mgr.list_interfaces.return_value = [
            {"name": "wg9", "active": True, "peers": []},
            {"name": "awg0", "active": True, "peers": []},
        ]
        mgr.has_config_for.side_effect = lambda name: name == "awg0"
        settings = {"enabled": True, "check_interval_sec": 30}
        with mock.patch.object(awg_watchdog, "_get_settings",
                               return_value=settings), \
             mock.patch("core.awg_manager.get_awg_manager", return_value=mgr), \
             mock.patch.object(wd, "_maybe_restart") as maybe, \
             mock.patch.object(wd, "_resurrect_down_autostart"):
            wd._tick()
        self.assertEqual([c.args[1] for c in maybe.call_args_list], ["awg0"])


# ─────────────────────── WARP-in-WARP ────────────────────────────────

class TestWiwSameEndpoint(unittest.TestCase):

    def test_same_endpoint_is_refused_before_anything_is_up(self):
        from core import awg_warp_in_warp as wiw
        mgr = mock.MagicMock()
        mgr.get_config.return_value = {"errors": []}
        with mock.patch.object(wiw, "_state", return_value={"active": False}), \
             mock.patch.object(wiw, "get_awg_manager", return_value=mgr), \
             mock.patch.object(wiw, "_read_inner_endpoint",
                               return_value=("engage.cloudflareclient.com",
                                             "2408")), \
             mock.patch.object(wiw, "_resolve_endpoint",
                               return_value=("162.159.192.1", None)), \
             mock.patch.object(wiw, "_endpoint_ips_of",
                               return_value={"162.159.192.1"}):
            res = wiw._do_setup("warp_out", "warp_in")
        self.assertFalse(res["ok"])
        self.assertIn("162.159.192.1", res["error"])
        mgr.up.assert_not_called()


# ─────────────────────── RoutingManager ──────────────────────────────

class TestRoutingManagerSafety(unittest.TestCase):

    def setUp(self):
        from core.routing import manager
        self.manager = manager
        self.mgr = manager.RoutingManager()

    def test_whole_internet_cidr_is_rejected(self):
        from core.routing.rules import CidrRoutingRule
        for cidr in ("0.0.0.0/0", "::/0"):
            rule = CidrRoutingRule(target_iface="awg0", cidrs=[cidr])
            with mock.patch.object(self.manager.storage, "add_rule") as add:
                res = self.mgr.add_rule(rule)
            self.assertFalse(res["ok"])
            self.assertIn("устройства", res["error"])
            add.assert_not_called()

    def test_failed_update_restores_previous_rule(self):
        from core.routing.rules import CidrRoutingRule
        old = CidrRoutingRule(target_iface="awg0", cidrs=["1.2.3.0/24"],
                              rule_id="cidr-x")
        new = CidrRoutingRule(target_iface="awg0", cidrs=["5.6.7.0/24"],
                              rule_id="cidr-x")
        applied = []
        with mock.patch.object(self.manager.storage, "get_rule",
                               return_value=old), \
             mock.patch.object(self.manager.storage, "update_rule") as upd, \
             mock.patch.object(self.manager.storage, "remove_rule") as rm, \
             mock.patch.object(self.mgr, "_remove"), \
             mock.patch.object(self.mgr, "_apply",
                               side_effect=lambda r: applied.append(
                                   r.cidrs[0]) or {"ok": r is old}):
            res = self.mgr.update_rule(new)
        self.assertFalse(res["ok"])
        rm.assert_not_called()
        self.assertIs(upd.call_args_list[-1].args[0], old)
        self.assertEqual(applied, ["5.6.7.0/24", "1.2.3.0/24"])

    def test_failed_add_releases_mark_slot(self):
        from core.routing.rules import CidrRoutingRule
        rule = CidrRoutingRule(target_iface="awg0", cidrs=["1.2.3.0/24"])
        with mock.patch.object(self.manager.storage, "add_rule"), \
             mock.patch.object(self.manager.storage, "remove_rule"), \
             mock.patch.object(self.mgr, "_remove"), \
             mock.patch.object(self.mgr, "_apply",
                               return_value={"ok": False, "error": "x"}), \
             mock.patch.object(self.manager, "_release_mark") as release:
            self.mgr.add_rule(rule)
        release.assert_called_once_with(rule.id)


class TestMaskHeuristic(unittest.TestCase):

    def tearDown(self):
        from core.routing import marks
        marks._mask_unsupported = False

    def test_kernel_einval_does_not_disable_mask(self):
        from core.routing import marks
        with mock.patch.object(marks, "_ip", side_effect=lambda a, timeout=5:
                               (2, "", "RTNETLINK answers: Invalid argument")
                               if a[3] == "add" else (2, "", "")):
            res = marks.ip_rule_add(0x10000, 150)
        self.assertFalse(res["ok"])
        self.assertFalse(marks._mask_unsupported)


# ─────────────────────── sweeper ─────────────────────────────────────

class TestSweeperKeepsBlackhole(unittest.TestCase):

    def _sweep(self, table_dump, killswitch_on=True):
        from core.routing import sweeper
        calls = []

        def fake_run(args, timeout=10):
            calls.append(list(args))
            if "show" in args:
                return 0, table_dump if args[1] == "-4" else "", ""
            return 0, "", ""

        expected = {"marks": set(), "devices": set(), "cidrs": set(),
                    "sets": set(), "tables": {321}}
        with mock.patch.object(sweeper, "collect_expected",
                               return_value=expected), \
             mock.patch.object(sweeper, "_table_map",
                               return_value={"awg0": 321}), \
             mock.patch.object(sweeper, "_parse_ip_rules", return_value=[]), \
             mock.patch.object(sweeper, "_list_ipsets", return_value=[]), \
             mock.patch.object(sweeper, "_list_nftsets", return_value=[]), \
             mock.patch.object(sweeper, "_iface_exists", return_value=False), \
             mock.patch.object(sweeper, "_run", side_effect=fake_run), \
             mock.patch("core.routing.killswitch.enabled",
                        return_value=killswitch_on), \
             mock.patch("core.routing.killswitch.present",
                        return_value=True), \
             mock.patch("core.routing.killswitch.ensure") as ensure:
            res = sweeper.sweep()
        return res, calls, ensure

    def test_lone_blackhole_of_live_rules_survives(self):
        res, calls, _e = self._sweep(
            "blackhole default metric 4294967294\n")
        self.assertEqual(res["tables"], [])
        self.assertFalse(any("flush" in c for c in calls))

    def test_blackhole_returned_after_flushing_leftovers(self):
        res, _c, ensure = self._sweep(
            "blackhole default metric 4294967294\n"
            "10.0.0.0/8 dev awg0 scope link\n")
        self.assertEqual(len(res["tables"]), 1)
        ensure.assert_called_once()

    def test_without_killswitch_table_is_swept(self):
        res, calls, ensure = self._sweep(
            "blackhole default metric 4294967294\n", killswitch_on=False)
        self.assertEqual(len(res["tables"]), 1)
        ensure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
