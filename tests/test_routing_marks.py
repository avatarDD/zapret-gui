"""Метки маршрутов (core/routing/marks.py) и цепочки маркировки ipset-пути.

Сторожат: метка маршрута — только своё поле бит (чужие метки пакета —
пробы, песочница, nfqws2, политика NDMS — не затираются), два правила
не получают одну метку, цепочки переписываются целиком и с conntrack-
правилами, старые метки распознаются как свои.
"""

import struct
import subprocess
import unittest
from unittest import mock

from core.routing import ipset_backend, marks


class FakeStore:
    def __init__(self, data=None):
        self.data = dict(data or {})

    def load(self):
        return dict(self.data)

    def save(self, slots):
        self.data = dict(slots)


class TestSlots(unittest.TestCase):

    def setUp(self):
        self.store = FakeStore()
        for name, fn in (("_load", self.store.load), ("_save", self.store.save)):
            p = mock.patch.object(marks, name, side_effect=fn)
            p.start()
            self.addCleanup(p.stop)

    def test_distinct_keys_never_share_a_slot(self):
        seen = {marks.mark_for("dom:r%d" % i) for i in range(50)}
        self.assertEqual(len(seen), 50)

    def test_slot_is_stable_and_released(self):
        a = marks.mark_for("dom:a")
        self.assertEqual(marks.mark_for("dom:a"), a)
        marks.release("dom:a")
        self.assertNotIn("dom:a", self.store.data)

    def test_mark_lives_only_in_its_field(self):
        mark = marks.mark_for("dom:x")
        self.assertEqual(mark & ~marks.MASK, 0)
        self.assertTrue(mark & marks.MASK)
        # Наши метки обхода (пробы, EXCLUDE, nfqws2, песочница) и
        # пользовательские младшие 16 бит не задеты.
        for other in (0x10000000, 0x20000000, 0x40000000, 0x80000000,
                      0xFFFF):
            self.assertEqual(marks.MASK & other, 0)

    def test_ndms_all_ones_slot_is_never_given(self):
        self.assertEqual(marks.pick_free(range(1, marks.SLOT_MAX + 1)), 0)
        # 0xffffaaa (политика NDMS) несёт в поле все единицы.
        self.assertEqual((0x0ffffaaa & marks.MASK) >> marks.SHIFT, 0xFFF)
        self.assertGreater(0xFFF, marks.SLOT_MAX)


class TestForms(unittest.TestCase):

    def test_spec_and_nft(self):
        self.assertEqual(marks.spec(0x20000), "0x20000/0xfff0000")
        self.assertEqual(marks.nft_set_expr(0x20000),
                         "meta mark set meta mark and 0xf000ffff or "
                         "0x00020000")

    def test_parse(self):
        self.assertEqual(marks.parse("0x10000/0xfff0000"),
                         (0x10000, 0xFFF0000))
        self.assertEqual(marks.parse("65536"), (0x10000, 0xFFFFFFFF))
        self.assertIsNone(marks.parse("junk"))

    def test_is_ours(self):
        self.assertTrue(marks.is_ours(0x10000, marks.MASK))
        self.assertTrue(marks.is_ours(0x1ABCD, marks.FULL))     # старая
        self.assertTrue(marks.is_ours(0x30000, marks.FULL))     # BusyBox
        self.assertFalse(marks.is_ours(0x0ffffaaa, marks.FULL))  # NDMS
        self.assertFalse(marks.is_ours(0x40000000, 0x40000000))


class TestIpRule(unittest.TestCase):

    def tearDown(self):
        marks._mask_unsupported = False

    def test_busybox_without_mask_falls_back_once(self):
        calls = []

        def fake(args, timeout=5):
            calls.append(args)
            if args[3] == "add" and "/" in args[5]:
                return 1, "", 'ip: invalid argument "0x10000/0xfff0000"'
            return (0, "", "") if args[3] == "add" else (2, "", "")
        with mock.patch.object(marks, "_ip", side_effect=fake):
            res = marks.ip_rule_add(0x10000, 150)
            self.assertTrue(res["ok"])
            self.assertFalse(res["masked"])
            calls.clear()
            marks.ip_rule_add(0x20000, 151)
        adds = [c for c in calls if c[3] == "add"]
        self.assertEqual(len(adds), 1)
        self.assertEqual(adds[0][5], str(0x20000))

    def test_other_errors_are_not_mistaken_for_busybox(self):
        with mock.patch.object(marks, "_ip", side_effect=lambda a, timeout=5:
                               (2, "", "RTNETLINK answers: No such table")
                               if a[3] == "add" else (2, "", "")):
            res = marks.ip_rule_add(0x10000, 150)
        self.assertFalse(res["ok"])
        self.assertFalse(marks._mask_unsupported)


class TestMarkChains(unittest.TestCase):

    DUMP = (
        "-N AWG_ROUTING_PRE\n"
        "-A AWG_ROUTING_PRE -m conntrack --ctdir REPLY -j RETURN\n"
        "-A AWG_ROUTING_PRE -m connmark --mark 0x10000/0xfff0000 "
        "-j MARK --set-xmark 0x10000/0xfff0000\n"
        "-A AWG_ROUTING_PRE -m set --match-set awgr_a dst "
        "-j MARK --set-xmark 0x10000/0xfff0000\n"
        "-A AWG_ROUTING_PRE -m set --match-set awgr_a dst "
        "-j CONNMARK --set-xmark 0x10000/0xfff0000\n"
        # прошлая версия: метка целиком
        "-A AWG_ROUTING_PRE -m set --match-set awgr_old dst "
        "-j MARK --set-xmark 0x1abcd/0xffffffff\n")

    def test_parse_entries(self):
        self.assertEqual(ipset_backend.parse_chain_entries(self.DUMP),
                         [("awgr_a", 0x10000, 0xFFF0000),
                          ("awgr_old", 0x1ABCD, 0xFFFFFFFF)])

    def test_render_has_reply_guard_and_connmark(self):
        text = ipset_backend.render_restore([("s", 0x10000, marks.MASK)])
        lines = text.splitlines()
        self.assertEqual(lines[0], "*mangle")
        self.assertIn(":AWG_ROUTING_PRE - [0:0]", lines)
        self.assertEqual(lines[-1], "COMMIT")
        pre = [ln for ln in lines if ln.startswith("-A AWG_ROUTING_PRE")]
        self.assertIn("--ctdir REPLY -j RETURN", pre[0])
        self.assertIn("-m connmark --mark 0x10000/0xfff0000", pre[1])
        self.assertIn("-j MARK --set-xmark 0x10000/0xfff0000", pre[2])
        self.assertIn("-j CONNMARK --set-xmark 0x10000/0xfff0000", pre[3])
        self.assertNotIn("--set-mark", text)

    def test_empty_render_flushes_chains(self):
        text = ipset_backend.render_restore([])
        self.assertNotIn("-A ", text)
        self.assertIn(":AWG_ROUTING_OUT - [0:0]", text)

    def _setup(self, func, *args):
        restored = []

        def fake_run(args, timeout=10):
            if args[1:4] == ["-t", "mangle", "-S"]:
                return 0, self.DUMP, ""
            return 0, "", ""

        def fake_sub(argv, input=None, **kw):
            restored.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(ipset_backend, "_run", side_effect=fake_run), \
                mock.patch.object(ipset_backend.subprocess, "run",
                                  side_effect=fake_sub):
            res = func(*args)
        return res, restored

    def test_setup_replaces_only_its_entry_atomically(self):
        res, restored = self._setup(ipset_backend.setup_mark_rule,
                                    "awgr_old", 0x20000, "v4")
        self.assertTrue(res["ok"])
        self.assertEqual(len(restored), 1)
        argv, text = restored[0]
        self.assertEqual(argv, ["iptables-restore", "--noflush"])
        self.assertIn("--match-set awgr_a dst -j MARK", text)
        self.assertIn("--match-set awgr_old dst -j MARK --set-xmark "
                      "0x20000/0xfff0000", text)
        self.assertNotIn("0x1abcd", text)

    def test_teardown_and_v6(self):
        res, restored = self._setup(ipset_backend.teardown_mark_rule,
                                    "awgr_a", 0, "v6")
        self.assertTrue(res["ok"])
        argv, text = restored[0]
        self.assertEqual(argv[0], "ip6tables-restore")
        self.assertNotIn("awgr_a", text)
        self.assertIn("awgr_old", text)


class TestAddEntry(unittest.TestCase):

    def test_ipset_timeout(self):
        self.assertEqual(ipset_backend.add_entry_argv("s", "1.2.3.4", 3900),
                         ["ipset", "add", "s", "1.2.3.4", "timeout", "3900",
                          "-exist"])
        self.assertEqual(ipset_backend.add_entry_argv("s", "1.2.3.4"),
                         ["ipset", "add", "s", "1.2.3.4", "-exist"])

    def test_nft_timeout_and_fallback(self):
        from core.routing import nftset_backend
        self.assertEqual(nftset_backend.add_entry_argv("s", "1.2.3.4", 90)[-1],
                         "{ 1.2.3.4 timeout 90s }")
        runs = [(1, "", "Error: set does not support timeout"),
                (0, "", "")]
        with mock.patch.object(nftset_backend, "_run", side_effect=runs) as r:
            self.assertTrue(nftset_backend.add_entry("s", "1.2.3.4", 90))
        self.assertEqual(r.call_args_list[1][0][0][-1], "{ 1.2.3.4 }")


class TestSweeperMasked(unittest.TestCase):

    def test_masked_rule_is_parsed_and_judged(self):
        from core.routing import sweeper
        text = ("0:\tfrom all lookup local\n"
                "10100:\tfrom all fwmark 0x10000/0xfff0000 lookup 123\n"
                "10100:\tfrom all fwmark 0x20000/0xfff0000 lookup 123\n")
        with mock.patch.object(sweeper, "_run", return_value=(0, text, "")):
            rules = sweeper._parse_ip_rules("-4")
        masked = [r for r in rules if r["fwmark"] is not None]
        self.assertEqual(len(masked), 2)
        exp = {"marks": {0x10000}, "devices": set(), "cidrs": set()}
        self.assertFalse(sweeper._is_orphan_rule(masked[0], exp, {123}))
        self.assertTrue(sweeper._is_orphan_rule(masked[1], exp, {123}))
        self.assertIn("fwmark 0x20000/0xfff0000",
                      " ".join(sweeper._del_argv(masked[1])))

    def test_ndms_policy_rule_is_never_ours(self):
        from core.routing import sweeper
        entry = {"priority": 10100, "family": "-4", "src": "", "dst": "",
                 "fwmark": 0x0ffffaaa, "fwmask": marks.FULL,
                 "table": "123", "foreign": False}
        exp = {"marks": set(), "devices": set(), "cidrs": set()}
        self.assertFalse(sweeper._is_orphan_rule(entry, exp, {123}))


if __name__ == "__main__":
    unittest.main()
