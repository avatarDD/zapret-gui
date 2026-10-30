# tests/test_iface_external.py
"""
Пометка внешнего (WAN) интерфейса в /api/interfaces: сопоставление
устройств с логическими сетями OpenWrt и флаг external, по которому
настройки показывают, какой интерфейс смотрит в сторону провайдера.
"""

import json
import unittest
from unittest import mock

from api import status


_UBUS_DUMP = {
    "interface": [
        {"interface": "lan", "up": True, "device": "br-lan",
         "l3_device": "br-lan"},
        {"interface": "wan", "up": True, "device": "eth1",
         "l3_device": "pppoe-wan"},
        {"interface": "wan6", "up": True, "device": "eth1",
         "l3_device": "pppoe-wan"},
        {"interface": "loopback", "up": True, "device": "lo",
         "l3_device": "lo"},
        {"interface": "vpn", "up": True, "l3_device": "wg0"},
    ]
}


def _fake_cmd(ubus=None, uci=None):
    def run(args, timeout=5):
        if args[0] == "ubus":
            return (0, json.dumps(ubus)) if ubus is not None else (-1, "")
        if args[0] == "uci":
            return (0, uci) if uci is not None else (1, "")
        return -1, ""
    return run


def _ifaces(*names):
    return [{"name": n, "state": "up"} for n in names]


class OpenwrtNetworksTest(unittest.TestCase):

    def test_ubus_maps_l3_and_lower_device(self):
        with mock.patch.object(status, "_run_cmd", _fake_cmd(ubus=_UBUS_DUMP)):
            nets = status._openwrt_networks()
        self.assertEqual(nets["pppoe-wan"], ["wan", "wan6"])
        self.assertEqual(nets["eth1"], ["wan", "wan6"])
        self.assertEqual(nets["br-lan"], ["lan"])
        self.assertEqual(nets["wg0"], ["vpn"])
        self.assertNotIn("lo", nets)

    def test_uci_fallback(self):
        uci = ("network.loopback=interface\n"
               "network.loopback.device='lo'\n"
               "network.lan=interface\n"
               "network.lan.device='br-lan'\n"
               "network.wan=interface\n"
               "network.wan.device='eth0.2'\n"
               "network.old=interface\n"
               "network.old.ifname='eth2 eth3'\n")
        with mock.patch.object(status, "_run_cmd", _fake_cmd(uci=uci)):
            nets = status._openwrt_networks()
        self.assertEqual(nets["eth0.2"], ["wan"])
        self.assertEqual(nets["br-lan"], ["lan"])
        self.assertEqual(nets["eth2"], ["old"])
        self.assertNotIn("lo", nets)

    def test_not_openwrt(self):
        with mock.patch.object(status, "_run_cmd", _fake_cmd()):
            self.assertEqual(status._openwrt_networks(), {})

    def test_bad_json(self):
        def run(args, timeout=5):
            return (0, "not json") if args[0] == "ubus" else (1, "")
        with mock.patch.object(status, "_run_cmd", run):
            self.assertEqual(status._openwrt_networks(), {})


class AnnotateExternalTest(unittest.TestCase):

    def test_openwrt_wan_wins_over_vpn_default_route(self):
        # Маршрут по умолчанию через VPN — туннель не становится внешним.
        ifaces = _ifaces("br-lan", "eth1", "pppoe-wan", "wg0")
        nets = {"br-lan": ["lan"], "eth1": ["wan"],
                "pppoe-wan": ["wan"], "wg0": ["vpn"]}
        status._annotate_external(ifaces, ({"wg0"}, set()), nets)
        ext = {i["name"]: i["external"] for i in ifaces}
        self.assertEqual(ext, {"br-lan": False, "eth1": True,
                               "pppoe-wan": True, "wg0": False})
        wg = ifaces[3]
        self.assertEqual(wg["default_route"], ["ipv4"])
        self.assertEqual(wg["networks"], ["vpn"])

    def test_default_route_without_openwrt(self):
        ifaces = _ifaces("eth0", "br0")
        status._annotate_external(ifaces, ({"eth0"}, {"eth0"}), {})
        self.assertTrue(ifaces[0]["external"])
        self.assertEqual(ifaces[0]["default_route"], ["ipv4", "ipv6"])
        self.assertEqual(ifaces[0]["networks"], [])
        self.assertFalse(ifaces[1]["external"])

    def test_nothing_external(self):
        ifaces = _ifaces("eth0")
        status._annotate_external(ifaces, (set(), set()), {})
        self.assertFalse(ifaces[0]["external"])
        self.assertEqual(ifaces[0]["default_route"], [])


class DetectRolesTest(unittest.TestCase):

    def test_uses_given_routes(self):
        ifaces = _ifaces("eth1", "br-lan")
        addr = {"br-lan": [{"family": "ipv4", "address": "192.168.1.1"}]}
        got = status._detect_interface_roles(ifaces, addr,
                                             ({"eth1"}, set()))
        self.assertEqual(got, {"wan": "eth1", "wan6": "eth1",
                               "lan": "br-lan"})


if __name__ == "__main__":
    unittest.main()
