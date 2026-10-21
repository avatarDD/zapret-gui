# tests/test_route_bypass_ports.py
"""Wi-Fi Calling и порт торрент-клиента мимо туннеля (приём Tachyon)."""

import unittest
from unittest import mock

from core.routing import device_rule
from core.routing.rules import (DeviceRoutingRule, normalize_bypass_ports,
                                rule_from_dict)
from core.unified.model import UnifiedRoute


class TestModel(unittest.TestCase):

    def _route(self, bypass, strict=True):
        return UnifiedRoute.from_dict(
            {"name": "tv", "method": "awg:awg0",
             "devices": [{"ip": "192.168.1.50"}], "bypass": bypass},
            strict_devices=strict)

    def test_presets_expand_to_ports(self):
        r = self._route({"wifi_calling": True,
                         "torrent_ports": "51413, 6881-6889"})
        self.assertEqual(r.bypass_ports(), [
            "udp:dport:500", "udp:dport:4500",
            "tcp:sport:51413", "udp:sport:51413",
            "tcp:sport:6881-6889", "udp:sport:6881-6889"])
        self.assertEqual(r.to_dict()["bypass"],
                         {"wifi_calling": True,
                          "torrent_ports": "51413,6881-6889"})

    def test_spaces_inside_range(self):
        r = self._route({"torrent_ports": "6881 - 6889; 51413"})
        self.assertEqual(r.bypass["torrent_ports"], "6881-6889,51413")

    def test_empty_by_default(self):
        self.assertEqual(self._route(None).bypass_ports(), [])

    def test_bad_port_rejected_from_gui_but_tolerated_from_disk(self):
        with self.assertRaises(ValueError):
            self._route({"torrent_ports": "70000"})
        self.assertEqual(self._route({"torrent_ports": "abc"},
                                     strict=False).bypass_ports(), [])


class TestRule(unittest.TestCase):

    def test_normalize(self):
        self.assertEqual(normalize_bypass_ports(
            ["UDP:dport:500", "udp:dport:500", "tcp:sport:7-7",
             "icmp:dport:1", "udp:to:5", "udp:dport:0", "udp:dport:9-3"]),
            ["udp:dport:500", "tcp:sport:7"])

    def test_roundtrip(self):
        rule = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2",
                                 bypass_ports=["udp:dport:4500"])
        again = rule_from_dict(rule.to_dict())
        self.assertEqual(again.bypass_ports, ["udp:dport:4500"])
        plain = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2")
        self.assertNotIn("bypass_ports", plain.to_dict())

    def test_apply_puts_exemptions_before_device_rule(self):
        calls = []

        def fake_run(argv, timeout=5):
            calls.append(argv)
            return 0, "", ""

        rule = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2",
                                 bypass_ports=["udp:dport:500"])
        with mock.patch.object(device_rule, "_run", side_effect=fake_run), \
                mock.patch.object(device_rule, "_iface_exists",
                                  return_value=True), \
                mock.patch.object(device_rule, "_ensure_table_default",
                                  return_value=True), \
                mock.patch("core.routing.masquerade.ensure_for_iface",
                           return_value={"ok": True}), \
                mock.patch("core.routing.killswitch.ensure",
                           return_value={"skipped": True}):
            res = device_rule.apply_device_rule(rule)
        self.assertTrue(res["ok"])
        self.assertEqual(res["bypass_ports"], ["udp:dport:500"])
        added = [" ".join(c) for c in calls if "add" in c]
        self.assertIn("ip -4 rule add from 10.0.0.2/32 ipproto udp dport 500 "
                      "lookup main priority %d"
                      % device_rule.PORT_EXEMPT_PRIORITY, added)
        self.assertLess(device_rule.PORT_EXEMPT_PRIORITY,
                        device_rule.DEVICE_PRIORITY)

    def test_old_kernel_keeps_device_rule(self):
        def fake_run(argv, timeout=5):
            if "ipproto" in argv and "add" in argv:
                return 2, "", "Error: argument \"ipproto\" is wrong"
            return 0, "", ""

        rule = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2",
                                 bypass_ports=["udp:dport:500"])
        with mock.patch.object(device_rule, "_run", side_effect=fake_run), \
                mock.patch.object(device_rule, "_iface_exists",
                                  return_value=True), \
                mock.patch.object(device_rule, "_ensure_table_default",
                                  return_value=True), \
                mock.patch("core.routing.masquerade.ensure_for_iface",
                           return_value={"ok": True}), \
                mock.patch("core.routing.killswitch.ensure",
                           return_value={"skipped": True}):
            res = device_rule.apply_device_rule(rule)
        self.assertTrue(res["ok"])
        self.assertEqual(res["bypass_ports"], [])
        self.assertTrue(res["bypass_ports_errors"])

    def test_remove_drops_exemptions(self):
        calls = []

        def fake_run(argv, timeout=5):
            calls.append(" ".join(argv))
            return (1 if "ipproto" in argv else 0), "", ""

        rule = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2",
                                 bypass_ports=["tcp:sport:51413"])
        with mock.patch.object(device_rule, "_run", side_effect=fake_run), \
                mock.patch("core.routing.masquerade.remove_if_unused"):
            device_rule.remove_device_rule(rule)
        self.assertIn("ip -4 rule del from 10.0.0.2/32 ipproto tcp sport 51413 "
                      "lookup main", calls)

    def test_ndms_skipped_when_ports_present(self):
        from core.routing.manager import RoutingManager
        rule = DeviceRoutingRule(target_iface="awg0", source_ip="10.0.0.2",
                                 mac="aa:bb:cc:dd:ee:ff",
                                 bypass_ports=["udp:dport:500"])
        mgr = RoutingManager.__new__(RoutingManager)
        with mock.patch("core.routing.ndms_backend.can_handle_device_rule",
                        return_value=True), \
                mock.patch("core.routing.ndms_backend.apply_device_rule") \
                as ndms, \
                mock.patch("core.routing.device_rule.apply_device_rule",
                           return_value={"ok": True}) as plain:
            mgr._apply(rule)
        ndms.assert_not_called()
        plain.assert_called_once()


if __name__ == "__main__":
    unittest.main()
