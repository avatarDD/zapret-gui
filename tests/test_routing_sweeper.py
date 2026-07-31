# tests/test_routing_sweeper.py
"""
Сброс «левых» артефактов маршрутизации (core/routing/sweeper).

Причина появления: `ip rule`/ipset/таблицы переживают удаление правила и
переподъём туннеля, поэтому в ядре копятся записи, которых нет в GUI —
трафик заворачивается «в никуда», а пользователь видит правильные
маршруты и не понимает, почему не работает. Здесь проверяем, что sweep
снимает ровно осиротевшее и не трогает ни чужое, ни живое.
"""

import unittest
from unittest import mock

from core.routing import sweeper
from core.routing.rules import (CidrRoutingRule, DeviceRoutingRule,
                                DomainRoutingRule)


# ip -4 rule show на роутере с одним живым доменным правилом (mark
# 0x10abc → table 123), одним осиротевшим device-правилом и мусором,
# который трогать нельзя.
IP4_RULES = """\
0:	from all lookup local
10000:	from all to 104.16.0.0/12 lookup 123
10100:	from all fwmark 0x10abc lookup 123
10100:	from all fwmark 0x1dead lookup 123
10200:	from 192.168.1.5 lookup 123
10200:	from 192.168.1.9 lookup 123
10050:	from all to 8.8.8.0/24 lookup 250
10000:	from all iif br0 lookup 123
32766:	from all lookup main
"""


class _Rules:
    """Заглушка storage: набор правил + доступ по id."""

    def __init__(self, rules):
        self._rules = rules

    def load_rules(self):
        return list(self._rules)

    def get_rule(self, rule_id):
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None


class TestParseIpRules(unittest.TestCase):

    def test_parses_selectors_and_marks_foreign(self):
        with mock.patch.object(sweeper, "_run",
                               return_value=(0, IP4_RULES, "")):
            parsed = sweeper._parse_ip_rules("-4")
        by_prio = {}
        for e in parsed:
            by_prio.setdefault(e["priority"], []).append(e)

        cidr = by_prio[10000][0]
        self.assertEqual(cidr["dst"], "104.16.0.0/12")
        self.assertEqual(cidr["table"], "123")
        self.assertFalse(cidr["foreign"])

        fwmark = by_prio[10100][0]
        self.assertEqual(fwmark["fwmark"], 0x10ABC)

        dev = by_prio[10200][0]
        self.assertEqual(dev["src"], "192.168.1.5")

        # `iif br0` — селектор, которого мы не ставим: помечаем чужим.
        self.assertTrue(by_prio[10000][1]["foreign"])
        # main/local — таблицы по имени, без числового id
        self.assertEqual(by_prio[32766][0]["table"], "main")

    def test_del_argv_is_precise(self):
        entry = {"family": "-4", "priority": 10200, "src": "192.168.1.9",
                 "dst": "", "fwmark": None, "table": "123", "foreign": False}
        self.assertEqual(
            sweeper._del_argv(entry),
            ["ip", "-4", "rule", "del", "priority", "10200",
             "from", "192.168.1.9", "lookup", "123"])


class TestIsOrphanRule(unittest.TestCase):

    def setUp(self):
        self.expected = {
            "marks":   {0x10ABC},
            "devices": {("192.168.1.5", 123)},
            "cidrs":   {("104.16.0.0/12", 123)},
            "sets":    set(),
            "tables":  {123},
        }
        self.our_tables = {123}

    def _entries(self):
        with mock.patch.object(sweeper, "_run",
                               return_value=(0, IP4_RULES, "")):
            return sweeper._parse_ip_rules("-4")

    def test_only_orphans_match(self):
        orphans = [sweeper._describe(e) for e in self._entries()
                   if sweeper._is_orphan_rule(e, self.expected,
                                              self.our_tables)]
        # осиротели: fwmark 0x1dead и device 192.168.1.9
        self.assertEqual(len(orphans), 2)
        self.assertTrue(any("0x1dead" in o for o in orphans))
        self.assertTrue(any("192.168.1.9" in o for o in orphans))

    def test_foreign_table_untouched(self):
        """`lookup 250` — не наша таблица, даже с нашим приоритетом."""
        entry = {"family": "-4", "priority": 10050, "src": "", "dst":
                 "8.8.8.0/24", "fwmark": None, "table": "250",
                 "foreign": False}
        self.assertFalse(sweeper._is_orphan_rule(entry, self.expected,
                                                 self.our_tables))

    def test_priority_outside_band_untouched(self):
        entry = {"family": "-4", "priority": 500, "src": "", "dst":
                 "1.2.3.0/24", "fwmark": None, "table": "123",
                 "foreign": False}
        self.assertFalse(sweeper._is_orphan_rule(entry, self.expected,
                                                 self.our_tables))

    def test_alien_fwmark_untouched(self):
        """Чужая марка (не наш диапазон и не id таблицы) — не наша."""
        entry = {"family": "-4", "priority": 10100, "src": "", "dst": "",
                 "fwmark": 0x40000000, "table": "123", "foreign": False}
        self.assertFalse(sweeper._is_orphan_rule(entry, self.expected,
                                                 self.our_tables))

    def test_dscp_mark_equal_to_table_is_ours(self):
        """DSCP-правило метит пакеты меткой = id таблицы."""
        entry = {"family": "-4", "priority": 10150, "src": "", "dst": "",
                 "fwmark": 123, "table": "123", "foreign": False}
        self.assertTrue(sweeper._is_orphan_rule(entry, self.expected,
                                                self.our_tables))
        self.expected["marks"].add(123)
        self.assertFalse(sweeper._is_orphan_rule(entry, self.expected,
                                                 self.our_tables))


class TestCollectExpected(unittest.TestCase):

    def _collect(self, rules, iproute_state=None):
        from core.routing import domain_rule
        stub = _Rules(rules)
        with mock.patch("core.routing.storage.load_rules", stub.load_rules), \
             mock.patch("core.routing.storage.get_rule", stub.get_rule), \
             mock.patch("core.routing.manager.table_id_for",
                        return_value=123), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value=iproute_state or {}):
            return sweeper.collect_expected()

    def test_live_rules_are_protected(self):
        from core.routing import domain_rule
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r1-dom")
        cidr = CidrRoutingRule(target_iface="awg0", cidrs=["1.2.3.0/24"],
                               rule_id="uni-r1-cidr")
        dev = DeviceRoutingRule(target_iface="awg0", source_ip="192.168.1.5",
                                rule_id="uni-r1-dev-aa")
        exp = self._collect([dom, cidr, dev])
        self.assertIn(domain_rule._mark_for("uni-r1-dom"), exp["marks"])
        self.assertIn(("1.2.3.0/24", 123), exp["cidrs"])
        self.assertIn(("192.168.1.5", 123), exp["devices"])
        self.assertIn(123, exp["tables"])
        # оба бэкенда + v6-вариант
        self.assertTrue(any(n.endswith("6") for n in exp["sets"]))

    def test_disabled_rule_keeps_sets_but_drops_ip_rules(self):
        from core.routing import domain_rule
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r2-dom", enabled=False)
        exp = self._collect([dom])
        self.assertNotIn(domain_rule._mark_for("uni-r2-dom"), exp["marks"])
        self.assertTrue(exp["sets"])

    def test_iproute_fallback_entries_are_protected(self):
        """Динамические «to <ip>/32» доменного фолбэка — не сироты."""
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r3-dom")
        exp = self._collect([dom], iproute_state={
            "uni-r3-dom": [["93.184.216.34/32", "-4"]],
            "uni-gone-dom": [["1.1.1.1/32", "-4"]],
        })
        self.assertIn(("93.184.216.34/32", 123), exp["cidrs"])
        self.assertNotIn(("1.1.1.1/32", 123), exp["cidrs"])


class TestSweep(unittest.TestCase):

    def _sweep(self, dry_run=False, ip_rules=IP4_RULES, ipsets=(),
               nftsets=(), table_map=None, ifaces=()):
        calls = []

        def fake_run(args, timeout=10):
            calls.append(list(args))
            if args[:2] == ["ip", "-4"] and args[2:4] == ["rule", "show"]:
                return 0, ip_rules, ""
            if args[2:4] == ["rule", "show"]:
                return 0, "", ""
            if args[1:3] == ["link", "show"]:
                return (0 if args[-1] in ifaces else 1), "", ""
            if args[2:4] == ["route", "show"]:
                return 0, "default dev awg0\n", ""
            return 0, "", ""

        expected = {"marks": {0x10ABC}, "devices": {("192.168.1.5", 123)},
                    "cidrs": {("104.16.0.0/12", 123)},
                    "sets": {"awgr_uni_r1_dom"}, "tables": {123}}
        with mock.patch.object(sweeper, "_run", side_effect=fake_run), \
             mock.patch.object(sweeper, "collect_expected",
                               return_value=expected), \
             mock.patch.object(sweeper, "_table_map",
                               return_value=table_map or {"awg0": 123}), \
             mock.patch.object(sweeper, "_list_ipsets",
                               return_value=list(ipsets)), \
             mock.patch.object(sweeper, "_list_nftsets",
                               return_value=list(nftsets)), \
             mock.patch.object(sweeper, "_drop_ipset_refs"), \
             mock.patch("core.routing.ipset_backend.destroy_set",
                        return_value={"ok": True}):
            res = sweeper.sweep(dry_run=dry_run)
        return res, calls

    def test_dry_run_changes_nothing(self):
        res, calls = self._sweep(dry_run=True, ipsets=["awgr_stale"],
                                 ifaces=("awg0",))
        self.assertEqual(len(res["ip_rules"]), 2)
        self.assertEqual(res["sets"], ["ipset awgr_stale"])
        self.assertTrue(res["dry_run"])
        self.assertFalse([c for c in calls if "del" in c or "flush" in c])

    def test_removes_orphan_ip_rules(self):
        res, calls = self._sweep(ifaces=("awg0",))
        self.assertTrue(res["ok"], res)
        dels = [c for c in calls if c[3:4] == ["del"]]
        self.assertEqual(len(dels), 2)
        joined = [" ".join(c) for c in dels]
        self.assertTrue(any("fwmark %d" % 0x1DEAD in j for j in joined))
        self.assertTrue(any("from 192.168.1.9" in j for j in joined))
        # живые правила остались нетронутыми
        self.assertFalse(any("192.168.1.5" in j for j in joined))
        self.assertFalse(any("104.16.0.0/12" in j for j in joined))

    def test_keeps_expected_set(self):
        res, _calls = self._sweep(ipsets=["awgr_uni_r1_dom", "awgr_stale"],
                                  ifaces=("awg0",))
        self.assertEqual(res["sets"], ["ipset awgr_stale"])

    def test_flushes_table_of_vanished_iface(self):
        """Интерфейса нет, а таблица не пуста — это остатки прошлой сессии."""
        res, calls = self._sweep(ifaces=())
        self.assertEqual(res["tables"], ["table 123 (awg0)"])
        flushes = [c for c in calls if c[2:4] == ["route", "flush"]]
        self.assertEqual(len(flushes), 2)          # v4 + v6

    def test_live_iface_table_untouched(self):
        res, calls = self._sweep(ifaces=("awg0",))
        self.assertEqual(res["tables"], [])
        self.assertFalse([c for c in calls if c[2:4] == ["route", "flush"]])


if __name__ == "__main__":
    unittest.main()
