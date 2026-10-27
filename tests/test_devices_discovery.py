# tests/test_devices_discovery.py
"""Тесты извлечения hostname из NDM-структуры (RCI/CLI) и склейки
источников в list_devices()."""

import unittest
from unittest import mock

from core import devices_discovery as dd
from core.devices_discovery import _extract_ndm_hosts


class TestExtractNdmHosts(unittest.TestCase):

    def test_host_list_with_names(self):
        data = {"host": [
            {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10",
             "name": "Galaxy-S21"},
            {"mac": "11:22:33:44:55:66", "ip": "192.168.1.11",
             "hostname": "macbook"},
        ]}
        out = _extract_ndm_hosts(data)
        self.assertEqual(len(out), 2)
        names = {h["ip"]: h["hostname"] for h in out}
        self.assertEqual(names["192.168.1.10"], "Galaxy-S21")
        self.assertEqual(names["192.168.1.11"], "macbook")
        self.assertTrue(all(h["source"] == "ndm" for h in out))

    def test_name_preferred_over_hostname(self):
        data = {"host": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1",
                          "name": "AdminName", "hostname": "client-sent"}]}
        self.assertEqual(_extract_ndm_hosts(data)[0]["hostname"], "AdminName")

    def test_single_host_dict(self):
        data = {"host": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.2",
                         "name": "solo"}}
        out = _extract_ndm_hosts(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["hostname"], "solo")

    def test_bare_array(self):
        data = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.3", "name": "x"}]
        self.assertEqual(len(_extract_ndm_hosts(data)), 1)

    def test_skips_without_ip_or_mac(self):
        data = {"host": [{"name": "nothing"}]}
        self.assertEqual(_extract_ndm_hosts(data), [])

    def test_empty_and_garbage(self):
        self.assertEqual(_extract_ndm_hosts({}), [])
        self.assertEqual(_extract_ndm_hosts({"host": None}), [])
        self.assertEqual(_extract_ndm_hosts("not a dict"), [])
        self.assertEqual(_extract_ndm_hosts(None), [])


def _dev(ip, mac, name="", src="arp", iface="br0"):
    return {"ip": ip, "mac": mac, "hostname": name, "source": src,
            "expires_at": 0, "iface": iface}


class TestListDevicesMerge(unittest.TestCase):
    """Скриншот из треда: «i3» на 0.0.0.0 вместо кормушки, роутер в списке."""

    def _run(self, ndm=(), leases=(), arp=(), side=(set(), set(), set()),
             **kw):
        with mock.patch.object(dd, "_read_ndm_hosts", return_value=list(ndm)), \
             mock.patch.object(dd, "_read_leases", return_value=list(leases)), \
             mock.patch.object(dd, "_read_arp", return_value=list(arp)), \
             mock.patch.object(dd, "_router_side", return_value=side), \
             mock.patch.object(dd, "_reverse_lookup", return_value=""):
            return dd.list_devices(**kw)

    def test_ndm_zero_ip_is_no_ip(self):
        out = _extract_ndm_hosts({"host": [
            {"mac": "08:00:27:53:59:60", "ip": "0.0.0.0", "name": "i3"}]})
        self.assertEqual(out[0]["ip"], "")
        self.assertEqual(out[0]["mac"], "08:00:27:53:59:60")

    def test_offline_hosts_do_not_collide_on_zero_ip(self):
        ndm = _extract_ndm_hosts({"host": [
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "0.0.0.0", "name": "Кормушка"},
            {"mac": "08:00:27:53:59:60", "ip": "0.0.0.0", "name": "i3"}]})
        self.assertEqual(self._run(ndm=ndm), [])
        off = self._run(ndm=ndm, include_offline=True)
        self.assertEqual({(d["mac"], d["hostname"]) for d in off},
                         {("aa:aa:aa:aa:aa:01", "Кормушка"),
                          ("08:00:27:53:59:60", "i3")})
        self.assertTrue(all(d["ip"] == "" and d["offline"] for d in off))

    def test_offline_ndm_name_follows_mac_to_live_ip(self):
        """NDM ещё не знает адрес, а ARP уже видит устройство — склейка по MAC."""
        ndm = _extract_ndm_hosts({"host": [
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "0.0.0.0", "name": "Кормушка"}]})
        out = self._run(ndm=ndm,
                        arp=[_dev("192.168.1.77", "aa:aa:aa:aa:aa:01")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "192.168.1.77")
        self.assertEqual(out[0]["hostname"], "Кормушка")
        self.assertEqual(out[0]["source"], "arp+ndm")

    def test_ip_match_with_other_mac_does_not_steal_name(self):
        """Адрес переехал к другому устройству — имя старого не приписываем."""
        ndm = _extract_ndm_hosts({"host": [
            {"mac": "aa:aa:aa:aa:aa:01", "ip": "192.168.1.77",
             "name": "Кормушка"}]})
        out = self._run(ndm=ndm,
                        arp=[_dev("192.168.1.77", "bb:bb:bb:bb:bb:02")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["mac"], "bb:bb:bb:bb:bb:02")
        self.assertNotEqual(out[0]["hostname"], "Кормушка")

    def test_router_and_gateway_excluded(self):
        arp = [_dev("100.12.12.1", "24:21:24:7f:ef:81", iface="eth3"),
               _dev("192.168.1.1", "4c:5e:0c:00:00:01"),
               _dev("192.168.1.117", "f4:26:79:ed:ae:2c")]
        out = self._run(arp=arp, side=({"192.168.1.1", "100.12.12.5"},
                                       {"100.12.12.1"}, {"eth3"}))
        self.assertEqual([d["ip"] for d in out], ["192.168.1.117"])

    def test_wan_neighbours_excluded_but_not_when_wan_is_lan(self):
        arp = [_dev("100.12.12.9", "24:21:24:7f:ef:82", iface="eth3"),
               _dev("192.168.1.117", "f4:26:79:ed:ae:2c")]
        out = self._run(arp=arp, side=(set(), set(), {"eth3"}))
        self.assertEqual([d["ip"] for d in out], ["192.168.1.117"])
        # Все устройства со стороны WAN — значит, это и есть LAN.
        out = self._run(arp=arp[:1], side=(set(), set(), {"eth3"}))
        self.assertEqual([d["ip"] for d in out], ["100.12.12.9"])

    def test_router_side_parsing(self):
        addr = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
                "3: br0    inet 192.168.1.1/24 brd 192.168.1.255 scope global br0\n"
                "5: eth3    inet 100.12.12.5/24 brd 100.12.12.255 scope global eth3\n")
        route = "default via 100.12.12.1 dev eth3 \n"

        def run(args, timeout=5):
            return 0, (addr if "addr" in args else route), ""
        with mock.patch.object(dd, "_run", side_effect=run):
            own, gws, wan = dd._router_side()
        self.assertIn("192.168.1.1", own)
        self.assertEqual(gws, {"100.12.12.1"})
        self.assertEqual(wan, {"eth3"})
        # Точка доступа: маршрут по умолчанию через br0 — это LAN, не WAN.
        route = "default via 192.168.1.254 dev br0\n"
        with mock.patch.object(dd, "_run", side_effect=run):
            _own, gws, wan = dd._router_side()
        self.assertEqual(gws, {"192.168.1.254"})
        self.assertEqual(wan, set())

    def test_zero_ip_not_valid_device(self):
        for ip in ("0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"):
            self.assertFalse(dd._is_host_ip(ip), ip)
        self.assertTrue(dd._is_host_ip("192.168.1.5"))


class TestRouteDeviceValidation(unittest.TestCase):

    def test_zero_ip_rejected_on_save_dropped_on_load(self):
        from core.unified.model import UnifiedRoute
        data = {"name": "x", "method": "awg:awg0",
                "destination": {"domains": ["a.com"]},
                "devices": [{"ip": "0.0.0.0"}, {"ip": "192.168.1.5"}]}
        with self.assertRaises(ValueError) as ctx:
            UnifiedRoute.from_dict(data, strict_devices=True)
        self.assertIn("0.0.0.0", str(ctx.exception))
        route = UnifiedRoute.from_dict(data)
        self.assertEqual([d["ip"] for d in route.devices], ["192.168.1.5"])

    def test_subnet_still_allowed(self):
        from core.unified.model import UnifiedRoute
        route = UnifiedRoute.from_dict(
            {"name": "x", "method": "awg:awg0",
             "devices": [{"ip": "192.168.1.0/24"}]}, strict_devices=True)
        self.assertEqual(route.devices[0]["ip"], "192.168.1.0/24")

    def test_router_address_rejected_on_save(self):
        from core.unified import manager
        with mock.patch("core.devices_discovery.router_addresses",
                        return_value={"192.168.1.1", "100.12.12.1"}), \
             mock.patch.object(manager.storage, "add_route") as add:
            r = manager.save_route(
                {"name": "x", "method": "awg:awg0",
                 "devices": [{"ip": "100.12.12.1"}]},
                apply=False, validate=True)
        self.assertFalse(r["ok"])
        self.assertIn("100.12.12.1", r["error"])
        add.assert_not_called()


if __name__ == "__main__":
    unittest.main()
