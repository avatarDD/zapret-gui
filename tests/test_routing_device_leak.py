# tests/test_routing_device_leak.py
"""Регрессия: «весь трафик с устройства через AWG» молча уходил мимо.

Три разных способа получить одно и то же — на 2ip адрес провайдера при
полностью настроенном на вид маршруте:

  1. метод маршрута не туннельный (direct/nfqws2). Устройства и DSCP
     работают ТОЛЬКО с туннелем, applier их пропускает — но узнать об
     этом было неоткуда: маршрут выглядел рабочим, в логе INFO «маршрут
     = direct», а `метод: direct — производных правил не требует` в
     диагностике выдавалось как успех;

  2. пустой `method` в запросе молча превращался в `direct` — маршрут
     сохранялся как рабочий, не делая ничего;

  3. туннель перезапускается (watchdog): ядро выкидывает его маршруты,
     таблица пустеет, policy-db идёт дальше до main — и трафик уходит
     через провайдера. Это лечит kill-switch (blackhole в таблице).

Здесь проверяем каждый из трёх.
"""

import unittest
from unittest import mock

from core.routing import doctor, killswitch
from core.routing.rules import DeviceRoutingRule
from core.unified.model import UnifiedRoute


class TestBlankMethodRejected(unittest.TestCase):

    def test_empty_method_is_an_error_not_direct(self):
        with self.assertRaises(ValueError) as ctx:
            UnifiedRoute.from_dict({"name": "devices", "method": "",
                                    "devices": [{"ip": "192.168.1.149"}]})
        self.assertIn("метод", str(ctx.exception).lower())

    def test_missing_method_still_defaults(self):
        """Старые payload'ы без поля method должны продолжать работать."""
        route = UnifiedRoute.from_dict({"name": "x",
                                        "destination": {"domains": ["a.com"]}})
        self.assertEqual(route.method, "direct")


class TestApplierWarnsOnIgnoredDevices(unittest.TestCase):

    def _route(self, method):
        return UnifiedRoute(name="devices", method=method,
                            devices=[{"ip": "192.168.1.149"}])

    def test_direct_with_devices_logs_warning(self):
        from core.unified import applier
        with mock.patch.object(applier, "_remove_routing_rules"), \
             mock.patch.object(applier, "_remove_hostlist"), \
             mock.patch.object(applier, "_remove_geo"), \
             mock.patch.object(applier, "_rebuild_nfqws_aggregate"), \
             mock.patch.object(applier.log, "warning") as warn:
            res = applier.apply_route(self._route("direct"), method="direct")
        self.assertTrue(res["ok"])
        self.assertTrue(res["skipped_selectors"])
        warn.assert_called_once()
        self.assertIn("устройства", warn.call_args[0][0].lower())


class TestDoctorFlagsIgnoredSelectors(unittest.TestCase):

    def _report_for(self, route):
        with mock.patch("core.routing.storage.load_rules", return_value=[]), \
             mock.patch("core.unified.storage.load_routes",
                        return_value=[route]), \
             mock.patch("core.routing.domain_rule._sets_state_load",
                        return_value={}), \
             mock.patch("core.routing.domain_rule._iproute_state_load",
                        return_value={}), \
             mock.patch.object(doctor, "_run", return_value=(0, "", "")), \
             mock.patch.object(doctor, "_probe_xt_set",
                               return_value=(True, "")):
            return doctor.diagnose()

    def test_direct_with_devices_is_a_failure(self):
        route = UnifiedRoute(name="devices", method="direct",
                             devices=[{"ip": "192.168.1.149"}])
        report = self._report_for(route)
        checks = report["unified"][0]["checks"]
        bad = [c for c in checks if not c["ok"]]
        self.assertTrue(bad, checks)
        self.assertIn("устройства", bad[0]["details"].lower())

    def test_direct_without_devices_is_fine(self):
        route = UnifiedRoute(name="dom", method="direct",
                             destination={"domains": ["a.com"]})
        report = self._report_for(route)
        checks = report["unified"][0]["checks"]
        self.assertTrue(all(c["ok"] for c in checks), checks)

    def test_warp_route_is_diagnosed_not_skipped(self):
        """`warp:` (usque/MASQUE) applier раскладывает как туннель —
        доктор обязан проверять его производные правила, а не объявлять
        «производных правил не требует»."""
        route = UnifiedRoute(name="w", method="warp:usque0",
                             devices=[{"ip": "192.168.1.84"}])
        report = self._report_for(route)
        names = [c["name"] for c in report["unified"][0]["checks"]]
        self.assertTrue(any("device-правило" in n for n in names), names)


class TestDoctorDeviceChain(unittest.TestCase):
    """Device-правило проверяется целиком, а не только «ip rule есть»."""

    def _rule(self):
        return DeviceRoutingRule(target_iface="WARPv2_83",
                                 source_ip="192.168.1.149",
                                 rule_id="uni-r-dev-1")

    def _checks(self, **over):
        rules = over.get("ip_rules", [
            "0:\tfrom all lookup local",
            "10200:\tfrom 192.168.1.149 lookup 354",
            "32766:\tfrom all lookup main",
        ])
        with mock.patch("core.routing.device_rule._table_id_for",
                        return_value=354), \
             mock.patch.object(doctor, "_ip_rule_lines", return_value=rules), \
             mock.patch.object(doctor, "_table_default_iface",
                               return_value=over.get("dev", "WARPv2_83")), \
             mock.patch.object(doctor, "_masquerade_present",
                               return_value=over.get("masq", True)), \
             mock.patch.object(doctor, "_forward_accept_present",
                               return_value=over.get("fwd", True)), \
             mock.patch.object(doctor, "_route_get_from",
                               return_value=over.get("via", "WARPv2_83")), \
             mock.patch.object(killswitch, "status",
                               return_value={"enabled": False,
                                             "present": False}):
            return doctor._diagnose_device_rule(self._rule())

    def _failed(self, checks):
        return [c["name"] for c in checks if not c["ok"]]

    def test_healthy_device_rule(self):
        self.assertEqual(self._failed(self._checks()), [])

    def test_empty_table_is_reported(self):
        bad = self._failed(self._checks(dev=""))
        self.assertTrue(any("default-route" in n for n in bad), bad)

    def test_missing_masquerade_is_reported(self):
        bad = self._failed(self._checks(masq=False))
        self.assertTrue(any("masquerade" in n for n in bad), bad)

    def test_missing_forward_accept_is_reported(self):
        bad = self._failed(self._checks(fwd=False))
        self.assertTrue(any("форвард" in n for n in bad), bad)

    def test_firmware_rule_above_ours_is_reported(self):
        """Правило прошивки с меньшим приоритетом перехватывает раньше."""
        rules = [
            "0:\tfrom all lookup local",
            "1152:\tfrom all lookup 16385",
            "10200:\tfrom 192.168.1.149 lookup 354",
            "32766:\tfrom all lookup main",
        ]
        bad = self._failed(self._checks(ip_rules=rules))
        self.assertTrue(any("выше" in n for n in bad), bad)

    def test_packet_leaving_through_wan_is_reported(self):
        bad = self._failed(self._checks(via="eth2.4"))
        self.assertTrue(any("уходит" in n for n in bad), bad)


class TestKillSwitch(unittest.TestCase):

    def test_disabled_removes_instead_of_adding(self):
        with mock.patch.object(killswitch, "enabled", return_value=False), \
             mock.patch.object(killswitch, "_run",
                               return_value=(0, "", "")) as run:
            res = killswitch.ensure(354, families=("v4",))
        self.assertTrue(res["skipped"])
        # Ни одного `route add` — только уборка прежнего blackhole.
        self.assertTrue(all("add" not in c.args[0]
                            for c in run.call_args_list), run.call_args_list)

    def test_enabled_adds_blackhole_with_high_metric(self):
        with mock.patch.object(killswitch, "enabled", return_value=True), \
             mock.patch.object(killswitch, "present", return_value=False), \
             mock.patch.object(killswitch, "_run",
                               return_value=(0, "", "")) as run:
            res = killswitch.ensure(354, families=("v4",))
        self.assertTrue(res["ok"])
        argv = run.call_args_list[0].args[0]
        self.assertIn("blackhole", argv)
        self.assertIn("354", argv)
        self.assertIn(str(killswitch.KILLSWITCH_METRIC), argv)

    def test_idempotent_when_already_present(self):
        with mock.patch.object(killswitch, "enabled", return_value=True), \
             mock.patch.object(killswitch, "present", return_value=True), \
             mock.patch.object(killswitch, "_run",
                               return_value=(0, "", "")) as run:
            killswitch.ensure(354, families=("v4",))
        run.assert_not_called()

    def test_device_rule_survives_iface_down(self):
        """Снятие правил при уходе интерфейса вниз НЕ трогает blackhole:
        он и держит трафик, пока туннель перезапускается."""
        from core.routing import device_rule
        rule = DeviceRoutingRule(target_iface="WARPv2_83",
                                 source_ip="192.168.1.149",
                                 rule_id="uni-r-dev-1")
        with mock.patch.object(device_rule, "_run",
                               return_value=(0, "", "")), \
             mock.patch("core.routing.device_rule._table_id_for",
                        return_value=354), \
             mock.patch("core.routing.masquerade.remove_if_unused"), \
             mock.patch.object(killswitch, "remove") as ks_remove:
            device_rule.remove_device_rule(rule)
        ks_remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
