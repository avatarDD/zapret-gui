# tests/test_device_quota.py
"""
Дневные квоты времени устройств (core/device_quota): проверка правил,
счёт активных минут по счётчикам firewall, блок по исчерпании, сброс в
полночь, «добавить минут», разбор вывода iptables-save и nft.
"""

import calendar
import json
import time
import unittest
from unittest import mock

from core import device_quota as dq


def ts(day, hh, mm=0):
    """UTC-время 2026-10-<day> hh:mm (tz_offset «+00:00»)."""
    return calendar.timegm((2026, 10, day, hh, mm, 0, 0, 0, 0))


class TestNormalize(unittest.TestCase):
    def test_rule(self):
        r = dq.normalize_rule({"name": "Дети", "devices": "AA-BB-CC-DD-EE-FF, 192.168.1.5/32",
                               "minutes": "90", "days": [6, 7, 9]})
        self.assertEqual(r["devices"], ["aa:bb:cc:dd:ee:ff", "192.168.1.5"])
        self.assertEqual(r["minutes"], 90)
        self.assertEqual(r["days"], [6, 7])

    def test_bad(self):
        for bad in ({"devices": ["1.2.3.4"], "minutes": 0},
                    {"devices": [], "minutes": 10},
                    {"devices": ["junk"], "minutes": 10},
                    {"devices": ["1.2.3.4"], "minutes": "x"}):
            with self.assertRaises(ValueError):
                dq.normalize_rule(bad)

    def test_duplicate_device_sets_rejected(self):
        with self.assertRaises(ValueError):
            dq.normalize_settings({"rules": [
                {"devices": ["1.1.1.1", "2.2.2.2"], "minutes": 5},
                {"devices": ["2.2.2.2", "1.1.1.1"], "minutes": 9}]})

    def test_load_settings_skips_broken(self):
        work, form, errors = dq.load_settings({"enabled": True, "rules": [
            {"devices": ["1.1.1.1"], "minutes": 5}, {"minutes": 5}]})
        self.assertEqual(len(work["rules"]), 1)
        self.assertEqual(len(errors), 1)
        # Битое правило остаётся в форме, чтобы сохранение его не стёрло.
        self.assertEqual(len(form), 2)
        self.assertIn("error", form[1])


class TestPure(unittest.TestCase):
    def test_count_minute(self):
        self.assertTrue(dq.count_minute({"a": 10}, {"a": 50}, ["a"], 30))
        self.assertFalse(dq.count_minute({"a": 10}, {"a": 20}, ["a"], 30))
        # Без прежнего значения — не считаем накопленное.
        self.assertFalse(dq.count_minute({}, {"a": 10 ** 6}, ["a"], 30))
        # Несколько адресов складываются.
        self.assertTrue(dq.count_minute({"a": 0, "b": 0},
                                        {"a": 20, "b": 15}, ["a", "b"], 30))

    def test_left(self):
        r = {"minutes": 60}
        self.assertEqual(dq.left_minutes(r, 50, 0), 10)
        self.assertEqual(dq.left_minutes(r, 70, 15), 5)
        self.assertEqual(dq.left_minutes(r, 90, 0), 0)

    def test_local_date_with_offset(self):
        self.assertEqual(dq.local_date("+03:00", ts(21, 22))[0],
                         "2026-10-22")
        self.assertEqual(dq.local_date("+00:00", ts(21, 22)),
                         ("2026-10-21", 3))

    def test_parse_ipt_list(self):
        v4 = """Chain zgui_quota (2 references)
    pkts      bytes target     prot opt in     out     source               destination
       4      300 RETURN     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpts:67:68
      12     3400 REJECT     all  --  *      *       192.168.1.5          0.0.0.0/0            reject-with icmp-port-unreachable
       0        0 DROP       all  --  *      *       0.0.0.0/0            192.168.1.5
      77     9000            all  --  *      *       192.168.1.7          0.0.0.0/0
"""
        v6 = """Chain zgui_quota (2 references)
    pkts      bytes target     prot opt in     out     source               destination
       5      100            all      *      *       fd00::7/128          ::/0
"""
        self.assertEqual(dq.parse_ipt_list(v4), {"192.168.1.7": 77})
        self.assertEqual(dq.parse_ipt_list(v6), {"fd00::7": 5})

    def test_parse_nft(self):
        text = """table inet zgui_quota {
	chain forward {
		type filter hook forward priority -5; policy accept;
		ip saddr 192.168.1.5 reject
		ip daddr 192.168.1.5 drop
		ip saddr 192.168.1.7 counter packets 42 bytes 900
		ip6 saddr fd00::7 counter packets 3 bytes 10
	}
	chain input {
		ip saddr 192.168.1.7 counter packets 8 bytes 90
	}
}"""
        # forward и input складываются: transparent-режим идёт в INPUT.
        self.assertEqual(dq.parse_nft(text),
                         {"192.168.1.7": 50, "fd00::7": 3})

    def test_nft_script_blocks_before_counting(self):
        s = dq.nft_script({"4": ["1.1.1.1", "2.2.2.2"], "6": []},
                          {"4": ["1.1.1.1"], "6": []})
        self.assertLess(s.index("saddr 1.1.1.1 reject"),
                        s.index("saddr 1.1.1.1 counter"))
        self.assertIn("daddr 1.1.1.1 drop", s)
        self.assertNotIn("2.2.2.2 reject", s)
        self.assertIn("chain input", s)
        # DHCP и DNS роутера заблокированному остаются.
        self.assertLess(s.index("udp dport 67-68 return"),
                        s.index("saddr 1.1.1.1 reject"))

    def test_ipt_rules(self):
        self.assertEqual(dq.ipt_rules(["1.1.1.1"], [])[0], ["-s", "1.1.1.1"])
        self.assertEqual(dq.ipt_rules(["1.1.1.1"], ["1.1.1.1"])[3:], [
            ["-s", "1.1.1.1", "-j", "REJECT"],
            ["-d", "1.1.1.1", "-j", "DROP"],
            ["-s", "1.1.1.1"]])


class TestTick(unittest.TestCase):
    def setUp(self):
        self.settings = {"enabled": True, "tz_offset": "+00:00",
                         "active_packets": 30, "rules": [
                             {"name": "Дети", "enabled": True,
                              "devices": ["192.168.1.7"], "names": {},
                              "minutes": 2, "days": []}]}
        self.states = []
        patches = [
            mock.patch.object(dq, "_read_state", return_value={}),
            mock.patch.object(dq, "_write_state",
                              side_effect=self.states.append),
            mock.patch.object(dq.DeviceQuota, "settings",
                              lambda _s: self.settings),
            mock.patch.object(dq, "read_neighbors", return_value=[]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.q = dq.DeviceQuota()
        self.counter = 0
        self.installed = []
        self.q._read_counters = lambda: ({"192.168.1.7": self.counter}
                                         if self.q._installed else {})

        def install(count, block):
            self.installed.append((count, block))
            if (count, block) != self.q._installed:
                # Как в настоящем _install: новая цепочка считает с нуля.
                self.q._prev = {x: 0 for x in count["4"] + count["6"]}
                self.counter = 0
            self.q._installed = (count, block)

        self.q._install = install
        self.q._remove = lambda every_backend=False: True
        self.q.notify_calls = []
        self.q._notify = lambda r: self.q.notify_calls.append(r["name"])

    def run_minutes(self, n, start, pkts=100):
        t = start
        for _ in range(n):
            self.counter += pkts
            self.q.tick(now=t, count=True)
            t += 60
        return t

    def test_active_minutes_block_and_midnight(self):
        t = self.run_minutes(4, ts(21, 10))
        # Первый тик ставит счётчик, второй — точка отсчёта, дальше счёт.
        st = self.q.status(now=t)["rules"][0]
        self.assertEqual(st["used"], 2)
        self.assertTrue(st["blocked"])
        self.assertEqual(self.installed[-1][1]["4"], ["192.168.1.7"])
        self.assertEqual(self.q.notify_calls, ["Дети"])
        self.assertTrue(self.states)        # блок сохраняется сразу
        # После полуночи — новый день, блок снят.
        self.q.tick(now=ts(22, 0, 1))
        st = self.q.status(now=ts(22, 0, 1))["rules"][0]
        self.assertEqual((st["used"], st["blocked"]), (0, False))
        self.assertEqual(self.installed[-1][1]["4"], [])

    def test_idle_device_spends_nothing(self):
        t = self.run_minutes(10, ts(21, 10), pkts=3)
        self.assertEqual(self.q.status(now=t)["rules"][0]["used"], 0)

    def test_extra_ticks_do_not_count(self):
        self.settings["rules"][0]["minutes"] = 100
        t = self.run_minutes(3, ts(21, 10))         # used = 2
        for _ in range(5):                          # сохранения формы
            self.counter += 500
            self.q.tick(now=t)
        self.assertEqual(self.q.status(now=t)["rules"][0]["used"], 2)

    def test_grant_unblocks(self):
        self.q._thread = mock.Mock()            # процесс GUI с потоком квот
        t = self.run_minutes(4, ts(21, 10))
        r = self.q.grant("Дети", 15, now=t)
        self.assertTrue(r["ok"])
        self.assertEqual(r["left"], 15)
        self.assertFalse(self.q.status(now=t)["rules"][0]["blocked"])
        self.assertEqual(self.installed[-1][1]["4"], [])
        self.assertFalse(self.q.grant("нет такого", 5, now=t)["ok"])
        self.assertFalse(self.q.grant("Дети", 0, now=t)["ok"])

    def test_rule_not_today(self):
        self.settings["rules"][0]["days"] = [1]       # только понедельник
        t = self.run_minutes(5, ts(21, 10))           # среда
        st = self.q.status(now=t)["rules"][0]
        self.assertEqual((st["today"], st["used"], st["blocked"]),
                         (False, 0, False))

    def test_disabled_removes(self):
        self.run_minutes(2, ts(21, 10))
        self.settings["enabled"] = False
        removed = []
        self.q._remove = lambda every_backend=False: removed.append(1) or True
        self.assertEqual(self.q.tick(now=ts(21, 11), count=True)["action"],
                         "off")
        self.assertTrue(removed)


class TestMcp(unittest.TestCase):
    def test_grant_tool(self):
        from core.mcp.tools import firewall as fw
        q = mock.Mock()
        q.grant.return_value = {"ok": True, "left": 30}
        with mock.patch("core.device_quota.get_device_quota",
                        return_value=q):
            r = fw.device_quota_grant({"rule": "Дети", "minutes": 30})
        q.grant.assert_called_once_with("Дети", 30)
        self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main()



class TestCrossProcess(TestTick):
    """device_quota_grant из другого процесса (MCP через stdio, CLI) пишет
    файл; GUI подхватывает его на своём тике и не затирает."""

    def test_grant_from_other_process_is_picked_up(self):
        disk = {}
        sig = [0]

        def write(data):
            disk.clear()
            disk.update(json.loads(json.dumps(data)))
            sig[0] += 1

        with mock.patch.object(dq, "_write_state", side_effect=write), \
                mock.patch.object(dq, "_read_state",
                                  side_effect=lambda: json.loads(
                                      json.dumps(disk))), \
                mock.patch.object(dq, "_state_sig",
                                  side_effect=lambda: sig[0]):
            self.q._own_sig = sig[0]
            t = self.run_minutes(4, ts(21, 10))
            self.assertTrue(self.q.status(now=t)["rules"][0]["blocked"])
            other = dq.DeviceQuota()            # «другой процесс»
            self.assertTrue(other.grant("Дети", 30, now=t)["ok"])
            self.q.tick(now=t + 60, count=True)
            st = self.q.status(now=t + 60)["rules"][0]
            self.assertEqual(st["extra"], 30)
            self.assertFalse(st["blocked"])
            self.q._save(t + 60)
            self.assertEqual(list(disk["extra"].values()), [30])

    def test_rebuild_does_not_lose_a_minute(self):
        self.settings["rules"][0]["minutes"] = 100
        t = self.run_minutes(3, ts(21, 10))     # used = 2
        # Адреса сменились — цепочка пересобрана, счётчики с нуля.
        self.q._install({"4": ["192.168.1.7", "192.168.1.8"], "6": []},
                        {"4": [], "6": []})
        self.run_minutes(1, t)
        self.assertEqual(self.q.status(now=t)["rules"][0]["used"], 3)
