"""
Расписание обхода по устройствам (issue #381): разбор правил, окна
времени (в т.ч. через полночь), MAC → адреса по таблице соседей и
команды firewall. Сам iptables/nft не вызывается — подменяем запуск.
"""

import calendar
import unittest
from unittest import mock

from core import device_schedule as ds


def _ts(y, mo, d, h, mi):
    """UTC-время → timestamp (для local_now со сдвигом)."""
    return calendar.timegm((y, mo, d, h, mi, 0, 0, 0, 0))


class TestParsing(unittest.TestCase):

    def test_hhmm(self):
        self.assertEqual(ds.parse_hhmm("8:05"), 485)
        self.assertEqual(ds.parse_hhmm("23:59"), 1439)
        for bad in ("24:00", "9", "ab", "", None, "12:60"):
            self.assertIsNone(ds.parse_hhmm(bad), bad)

    def test_tz_offset(self):
        self.assertIsNone(ds.parse_tz_offset(""))
        self.assertEqual(ds.parse_tz_offset("+03:00"), 180)
        self.assertEqual(ds.parse_tz_offset("-5"), -300)
        self.assertEqual(ds.parse_tz_offset("+0530"), 330)
        for bad in ("3", "+15:00", "UTC+3", "+03:99"):
            with self.assertRaises(ValueError):
                ds.parse_tz_offset(bad)

    def test_devices(self):
        self.assertEqual(ds.normalize_device("192.168.1.5"),
                         ("ip", "192.168.1.5"))
        self.assertEqual(ds.normalize_device("192.168.1.7/24"),
                         ("ip", "192.168.1.0/24"))
        self.assertEqual(ds.normalize_device("AA-BB-CC-DD-EE-FF"),
                         ("mac", "aa:bb:cc:dd:ee:ff"))
        self.assertEqual(ds.normalize_device("2001:db8::1"),
                         ("ip", "2001:db8::1"))
        with self.assertRaises(ValueError):
            ds.normalize_device("tv.local")

    def test_rule(self):
        r = ds.normalize_rule({"name": " Дети ", "devices": "192.168.1.5, "
                               "aa:bb:cc:dd:ee:ff 192.168.1.5",
                               "days": ["5", 1, 1], "from": "9:00",
                               "to": "19:30"})
        self.assertEqual(r, {"name": "Дети", "enabled": True,
                             "devices": ["192.168.1.5", "aa:bb:cc:dd:ee:ff"],
                             "days": [1, 5], "from": "09:00", "to": "19:30"})

    def test_rule_errors(self):
        base = {"devices": ["192.168.1.5"], "from": "09:00", "to": "19:00"}
        for patch in ({"devices": []}, {"from": "9"}, {"days": [8]},
                      {"days": "пн"}, {"devices": ["нет"]}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                ds.normalize_rule(dict(base, **patch))

    def test_settings_limits(self):
        rule = {"devices": ["10.0.0.1"], "from": "09:00", "to": "10:00"}
        with self.assertRaises(ValueError):
            ds.normalize_settings({"rules": [rule] * (ds.MAX_RULES + 1)})
        with self.assertRaises(ValueError):
            ds.normalize_settings({"rules": [], "tz_offset": "мск"})
        out = ds.normalize_settings({"enabled": 1, "rules": [rule]})
        self.assertTrue(out["enabled"])
        self.assertEqual(out["tz_offset"], "")


class TestWindows(unittest.TestCase):

    def rule(self, start, end, days=None, enabled=True):
        return {"enabled": enabled, "devices": ["10.0.0.1"],
                "days": days or [], "from": start, "to": end}

    def test_daytime(self):
        r = self.rule("09:00", "19:00", days=[1, 2, 3, 4, 5])
        self.assertTrue(ds.rule_active(r, 1, 9 * 60))
        self.assertTrue(ds.rule_active(r, 5, 18 * 60 + 59))
        self.assertFalse(ds.rule_active(r, 5, 19 * 60))      # конец не включён
        self.assertFalse(ds.rule_active(r, 1, 8 * 60 + 59))
        self.assertFalse(ds.rule_active(r, 6, 12 * 60))      # суббота

    def test_overnight_belongs_to_start_day(self):
        r = self.rule("22:00", "07:00", days=[5])            # ночь с пятницы
        self.assertTrue(ds.rule_active(r, 5, 23 * 60))
        self.assertTrue(ds.rule_active(r, 6, 6 * 60))        # утро субботы
        self.assertFalse(ds.rule_active(r, 6, 23 * 60))
        self.assertFalse(ds.rule_active(r, 5, 6 * 60))       # утро пятницы

    def test_overnight_sunday_to_monday(self):
        r = self.rule("23:00", "01:00", days=[7])
        self.assertTrue(ds.rule_active(r, 1, 30))

    def test_whole_day_and_every_day(self):
        self.assertTrue(ds.rule_active(self.rule("00:00", "00:00"), 3, 0))
        self.assertTrue(ds.rule_active(self.rule("10:00", "10:00", [2]), 2,
                                       1439))
        self.assertFalse(ds.rule_active(self.rule("09:00", "19:00",
                                                  enabled=False), 1, 600))

    def test_active_devices_dedup(self):
        a = self.rule("09:00", "19:00")
        b = dict(self.rule("08:00", "20:00"), devices=["10.0.0.1", "10.0.0.2"])
        self.assertEqual(ds.active_devices([a, b], 1, 600),
                         ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(ds.active_devices([a, b], 1, 19 * 60 + 30),
                         ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(ds.active_devices([a], 1, 20 * 60), [])

    def test_local_now_with_offset(self):
        # Пятница 2026-10-09 22:30 UTC = суббота 01:30 по +03:00.
        ts = _ts(2026, 10, 9, 22, 30)
        self.assertEqual(ds.local_now("+03:00", ts), (6, 90))
        self.assertEqual(ds.local_now("+00:00", ts), (5, 22 * 60 + 30))


class TestResolve(unittest.TestCase):

    NEIGH = (
        "192.168.1.5 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.9 dev br0  FAILED\n"
        "2001:db8::5 dev br0 lladdr AA:BB:CC:DD:EE:FF STALE\n"
        "fe80::1 dev br0 lladdr aa:bb:cc:dd:ee:ff router STALE\n"
        "10.0.0.2 dev br0 lladdr 11:22:33:44:55:66 DELAY\n"
    )

    def test_parse_neigh(self):
        pairs = ds.parse_ip_neigh(self.NEIGH)
        self.assertIn(("192.168.1.5", "aa:bb:cc:dd:ee:ff"), pairs)
        self.assertIn(("2001:db8::5", "aa:bb:cc:dd:ee:ff"), pairs)
        self.assertNotIn("192.168.1.9", [p[0] for p in pairs])

    def test_mac_gives_v4_and_v6_without_link_local(self):
        pairs = ds.parse_ip_neigh(self.NEIGH)
        got = ds.resolve_addresses(["aa:bb:cc:dd:ee:ff", "192.168.2.0/24"],
                                   pairs, [("192.168.1.6",
                                            "aa:bb:cc:dd:ee:ff")])
        self.assertEqual(got, {"4": ["192.168.1.5", "192.168.1.6",
                                     "192.168.2.0/24"],
                               "6": ["2001:db8::5"]})

    def test_unknown_mac_resolves_to_nothing(self):
        self.assertEqual(ds.resolve_addresses(["de:ad:be:ef:00:01"], []),
                         {"4": [], "6": []})


class TestNeighborsAndSettings(unittest.TestCase):

    def test_proc_arp_fallback(self):
        text = ("IP address  HW type  Flags  HW address  Mask  Device\n"
                "192.168.1.5 0x1 0x2 aa:bb:cc:dd:ee:ff * br0\n"
                "192.168.1.6 0x1 0x0 00:00:00:00:00:00 * br0\n")
        self.assertEqual(ds.parse_proc_arp(text),
                         [("192.168.1.5", "aa:bb:cc:dd:ee:ff")])

    def test_bad_rule_does_not_hide_the_others(self):
        good = {"name": "ok", "devices": ["10.0.0.1"], "from": "09:00",
                "to": "10:00"}
        bad = {"name": "битое", "devices": ["tv-livingroom"],
               "from": "09:00", "to": "10:00"}
        work, form, errors = ds.load_settings(
            {"enabled": True, "tz_offset": "мск", "rules": [bad, good]})
        self.assertTrue(work["enabled"])
        self.assertEqual([r["name"] for r in work["rules"]], ["ok"])
        self.assertEqual(work["tz_offset"], "")
        # Форма получает оба правила по порядку, битое — с причиной.
        self.assertEqual([r["name"] for r in form], ["битое", "ok"])
        self.assertIn("tv-livingroom", form[0]["error"])
        self.assertEqual(len(errors), 2)

    def test_garbage_settings(self):
        work, form, errors = ds.load_settings("мусор")
        self.assertEqual(work, {"enabled": False, "tz_offset": "",
                                "rules": []})
        self.assertEqual(form, [])


class TestFirewallCommands(unittest.TestCase):

    def test_ipt_rule(self):
        self.assertEqual(ds.ipt_rule_args("10.0.0.5", "0x20000000"),
                         ["-s", "10.0.0.5", "-j", "CONNMARK", "--set-xmark",
                          "0x20000000/0x20000000"])

    def test_nft_script(self):
        text = ds.nft_script({"4": ["10.0.0.5", "10.0.1.0/24"],
                              "6": ["2001:db8::5"]}, "0x20000000")
        self.assertIn("delete table inet zgui_sched", text)
        self.assertIn("priority -160", text)
        self.assertIn("ip saddr { 10.0.0.5, 10.0.1.0/24 } ct mark set "
                      "ct mark or 0x20000000", text)
        self.assertIn("ip6 saddr { 2001:db8::5 }", text)
        text4 = ds.nft_script({"4": ["10.0.0.5"], "6": []}, "0x20000000")
        self.assertNotIn("ip6 saddr", text4)


class TestScheduler(unittest.TestCase):
    """tick(): применяет при входе в окно, снимает на выходе, чинит пропажу."""

    def setUp(self):
        self.sched = ds.DeviceScheduler()
        self.settings = {"enabled": True, "tz_offset": "+00:00", "rules": [
            {"name": "Дети", "enabled": True, "devices": ["10.0.0.5"],
             "days": [], "from": "09:00", "to": "19:00"}]}
        self.calls = []
        self.present = True
        self.chain_exists = False
        self.fail_add = False
        self._p = [
            mock.patch.object(ds.DeviceScheduler, "settings",
                              side_effect=lambda: self.settings),
            mock.patch.object(ds.DeviceScheduler, "_mark",
                              return_value="0x20000000"),
            mock.patch.object(ds.DeviceScheduler, "_fw_type",
                              return_value="iptables"),
            mock.patch.object(ds.shutil, "which",
                              side_effect=lambda b: b == "iptables"),
            mock.patch.object(ds, "_ipt", side_effect=self._fake_ipt),
            mock.patch.object(ds, "read_neighbors", return_value=[]),
        ]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()

    def _fake_ipt(self, cmd, quiet=False):
        self.calls.append(cmd)
        if "-C" in cmd:
            return self.present
        if "-S" in cmd:                 # есть ли цепочка
            return self.chain_exists
        if "-A" in cmd and self.fail_add:
            return False
        if "-X" in cmd:
            self.chain_exists = False
        if "-N" in cmd:
            self.chain_exists = True
        return True

    def _at(self, hour):
        return mock.patch.object(ds.time, "time",
                                 return_value=_ts(2026, 10, 7, hour, 0))

    def test_enter_and_leave_window(self):
        with self._at(10):
            self.sched.tick()
        self.assertEqual(self.sched._applied, {"4": ["10.0.0.5"], "6": []})
        self.assertIn(["iptables", "-t", "mangle", "-A", ds.CHAIN,
                       "-s", "10.0.0.5", "-j", "CONNMARK", "--set-xmark",
                       "0x20000000/0x20000000"], self.calls)
        # Тот же тик, правила на месте — ничего не пересобираем.
        self.calls.clear()
        with self._at(11):
            self.sched.tick()
        self.assertFalse([c for c in self.calls if "-A" in c])
        # Окно закончилось — цепочка снята.
        self.calls.clear()
        with self._at(20):
            self.sched.tick()
        self.assertIsNone(self.sched._applied)
        self.assertIn(["iptables", "-t", "mangle", "-X", ds.CHAIN],
                      self.calls)

    def test_restores_rules_after_firmware_flush(self):
        with self._at(10):
            self.sched.tick()
        self.calls.clear()
        self.present = False      # прошивка сбросила netfilter
        with self._at(10):
            self.sched.tick()
        self.assertTrue([c for c in self.calls if "-A" in c and ds.CHAIN in c])

    def test_disabled_clears(self):
        with self._at(10):
            self.sched.tick()
        self.settings = dict(self.settings, enabled=False)
        with self._at(10):
            self.sched.tick()
        self.assertIsNone(self.sched._applied)

    def test_leftover_from_previous_process_is_removed(self):
        # GUI перезапустили посреди окна, поднялся уже после него: в
        # системе цепочка прошлого процесса, в памяти — ничего.
        self.chain_exists = True
        with self._at(20):
            self.sched.tick()
        self.assertIn(["iptables", "-t", "mangle", "-X", ds.CHAIN],
                      self.calls)
        self.assertFalse(self.sched._maybe_installed)
        # Дальше вне окна — никаких команд.
        self.calls.clear()
        with self._at(21):
            self.sched.tick()
        self.assertEqual(self.calls, [])

    def test_partial_failure_is_removed_after_window(self):
        self.fail_add = True
        with self._at(10):
            self.sched.tick()
        self.assertIsNone(self.sched._applied)
        self.assertTrue(self.sched.status()["error"])
        self.fail_add = False
        with self._at(20):
            self.sched.tick()
        self.assertIn(["iptables", "-t", "mangle", "-X", ds.CHAIN],
                      self.calls)

    def test_late_tick_does_not_reapply_after_disable(self):
        stop = ds.threading.Event()
        real_desired = ds.DeviceScheduler.desired

        def desired_then_disable(sched, st=None, now=None):
            out = real_desired(sched, st, now)
            # Пока тик считал адреса, пользователь выключил расписание.
            self.settings = dict(self.settings, enabled=False)
            return out
        with self._at(10), mock.patch.object(
                ds.DeviceScheduler, "desired", desired_then_disable):
            self.sched.tick(stop)
        self.assertFalse([c for c in self.calls if "-A" in c])

    def test_stopped_thread_tick_is_a_noop(self):
        stop = ds.threading.Event()
        stop.set()
        with self._at(10):
            self.sched.tick(stop)
        self.assertEqual(self.calls, [])

    def test_status_reports_window(self):
        with self._at(10):
            self.sched.tick()
            st = self.sched.status()
        self.assertEqual(st["router_time"], "Ср 10:00")
        self.assertEqual(st["active_rules"], ["Дети"])
        self.assertEqual(st["excluded"], ["10.0.0.5"])


if __name__ == "__main__":
    unittest.main()



class TestApi(unittest.TestCase):
    """POST /api/device-schedule: тело без JSON не стирает расписание."""

    def setUp(self):
        from core.bottle_vendor import ensure_bottle
        ensure_bottle()
        import bottle
        from api import device_schedule as api_mod
        from tests._wsgi_client import WSGIClient
        app = bottle.Bottle()
        api_mod.register(app)
        self.client = WSGIClient(app)
        self.cfg = mock.Mock()
        self.cfg.save.return_value = True
        self.sched = mock.Mock()
        self.sched.form_settings.return_value = {"rules": []}
        self.sched.status.return_value = {}
        self._p = [
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.cfg),
            mock.patch("core.device_schedule.get_device_scheduler",
                       return_value=self.sched),
        ]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()

    def test_body_without_json_type_is_rejected_not_saved(self):
        for body, ctype in ((b"enabled=1", "application/x-www-form-urlencoded"),
                            (b"", ""), (b"[]", "application/json"),
                            (b"{}", "application/json")):
            with self.subTest(body=body):
                status, _, data = self.client.request(
                    "POST", "/api/device-schedule", body=body,
                    content_type=ctype)
                self.assertEqual(status, 400, data)
        self.cfg.set.assert_not_called()

    def test_json_without_content_type_is_accepted(self):
        body = (b'{"enabled": true, "rules": [{"devices": ["10.0.0.5"], '
                b'"from": "09:00", "to": "19:00"}]}')
        status, _, data = self.client.request(
            "POST", "/api/device-schedule", body=body, content_type="")
        self.assertEqual(status, 200, data)
        saved = self.cfg.set.call_args[0][-1]
        self.assertEqual(saved["rules"][0]["devices"], ["10.0.0.5"])
        self.sched.reconfigure.assert_called_once_with(apply_now=True)

    def test_invalid_rule_is_400(self):
        status, _, data = self.client.request(
            "POST", "/api/device-schedule",
            body={"enabled": True, "rules": [{"devices": ["нет"],
                                              "from": "9:00", "to": "10:00"}]})
        self.assertEqual(status, 400)
        self.assertIn("нет", data["error"])
        self.cfg.set.assert_not_called()
