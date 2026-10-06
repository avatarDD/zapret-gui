# tests/test_nftset_backend.py
"""
Unit-тесты для core/routing/nftset_backend.py.

Большая часть функций backend'а вызывает `nft` через subprocess —
монкипатчим `_run` чтобы тестировать без реального nftables.
"""

import unittest
from unittest import mock

from core.routing import nftset_backend


class TestSetNameFor(unittest.TestCase):
    def test_basic(self):
        self.assertTrue(
            nftset_backend.set_name_for("domain-abc123").startswith("awgr_"))

    def test_dashes_to_underscores(self):
        name = nftset_backend.set_name_for("domain-abc-def")
        self.assertNotIn("-", name)
        self.assertIn("_", name)

    def test_length_capped(self):
        long_id = "domain-" + ("x" * 200)
        name = nftset_backend.set_name_for(long_id)
        self.assertLessEqual(len(name), 63)


class TestOutputChainTypeWrong(unittest.TestCase):
    """Парсер для определения старой type=filter цепочки output."""

    def test_old_filter_type(self):
        listing = """
        table inet awg_routing {
            chain output {
                type filter hook output priority mangle; policy accept;
            }
        }
        """
        self.assertTrue(nftset_backend._output_chain_type_wrong(listing))

    def test_new_route_type(self):
        listing = """
        table inet awg_routing {
            chain output {
                type route hook output priority mangle; policy accept;
            }
        }
        """
        self.assertFalse(nftset_backend._output_chain_type_wrong(listing))

    def test_empty_string(self):
        self.assertFalse(nftset_backend._output_chain_type_wrong(""))


class TestAvailable(unittest.TestCase):
    """Детект доступности nft."""

    def test_available_true(self):
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(0, "", "")):
            self.assertTrue(nftset_backend.available())

    def test_available_false(self):
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(127, "", "command not found")):
            self.assertFalse(nftset_backend.available())


class TestCreateSet(unittest.TestCase):
    """Создание set'а — мокаем _run."""

    def test_creates_when_missing(self):
        # Первый _run (list set) → not found, второй (add set) → ok
        with mock.patch.object(nftset_backend, "_run",
                               side_effect=[
                                   (1, "", "no such set"),    # list
                                   (0, "", ""),               # add table
                                   (0, "", ""),               # add chain prerouting
                                   (0, "", ""),               # add chain output
                                   (0, "", ""),               # add chain postrouting
                                   (0, "", ""),               # add chain forward
                                   (1, "", "no such set"),    # list set (in create)
                                   (0, "", ""),               # add set
                               ]):
            r = nftset_backend.create_set("test_set", family="v4")
            self.assertTrue(r["ok"])

    def test_idempotent_when_exists(self):
        # _ensure_table_and_chains возвращает быстро через "table уже есть"
        # list set → существует
        runs = [
            # _ensure_table_and_chains
            (0, "table inet awg_routing {\n"
                "  chain prerouting { type filter hook prerouting priority mangle; policy accept; }\n"
                "  chain output { type route hook output priority mangle; policy accept; }\n"
                "  chain postrouting { type nat hook postrouting priority srcnat; policy accept; }\n"
                "  chain forward { type filter hook forward priority -1; policy accept; }\n"
                "}", ""),
            # create_set's own list set
            (0, "set test_set { ... }", ""),
        ]
        with mock.patch.object(nftset_backend, "_run", side_effect=runs):
            r = nftset_backend.create_set("test_set", family="v4")
            self.assertTrue(r["ok"])
            self.assertFalse(r["created"])


class TestEntryHandles(unittest.TestCase):
    """_entry_handles находит правила записи: наши (по комментарию) и
    старого формата (`@set … meta mark set`), чужие не трогает."""

    LISTING = (
        "chain prerouting { # handle 1\n"
        '  ct direction original ip daddr @set1 meta mark set meta mark & '
        '0xf001ffff | 0x00010000 comment "awgr:set1" # handle 7\n'
        "  ip daddr @set1 meta mark set 0x0000abcd # handle 8\n"
        "  ip daddr @set2 meta mark set 0x0000abce # handle 9\n"
        "  ip dscp ef meta mark set 0x00000395 # handle 10\n"
        "}")

    def test_finds_new_and_legacy_rules_of_the_set(self):
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(0, self.LISTING, "")):
            self.assertEqual(
                nftset_backend._entry_handles("prerouting", "set1"),
                ["7", "8"])

    def test_entry_rules_keep_foreign_bits(self):
        rules = nftset_backend.entry_rules("s", 0x10000, "v4")
        self.assertEqual(len(rules), 3)
        self.assertTrue(all('comment "awgr:s"' in r for r in rules))
        self.assertTrue(all("ct direction original" in r for r in rules))
        self.assertIn("meta mark set meta mark and 0xf000ffff or "
                      "0x00010000", rules[1])
        self.assertIn("ct mark set ct mark and 0xf000ffff or 0x00010000",
                      rules[2])
        self.assertIn("ip6 daddr @s6", nftset_backend.entry_rules(
            "s6", 0x10000, "v6")[1])


class TestEnsureIfaceMasquerade(unittest.TestCase):
    """oifname masquerade — обрабатываем обе формы (с кавычками и без)."""

    def test_already_present_with_quotes(self):
        chain_listing = ('chain postrouting {\n'
                         '  oifname "awg0" masquerade\n'
                         '}')
        runs = [
            # _ensure_table_and_chains — таблица уже OK
            (0, ("table inet awg_routing {\n"
                 "  chain prerouting { type filter hook prerouting priority mangle; }\n"
                 "  chain output { type route hook output priority mangle; }\n"
                 "  chain postrouting { type nat hook postrouting priority srcnat; }\n"
                 "  chain forward { type filter hook forward priority -1; }\n"
                 "}"), ""),
            (0, chain_listing, ""),
        ]
        with mock.patch.object(nftset_backend, "_run", side_effect=runs):
            r = nftset_backend.ensure_iface_masquerade("awg0")
            self.assertTrue(r["ok"])
            self.assertFalse(r["added"])

    def test_already_present_without_quotes(self):
        chain_listing = "chain postrouting {\n  oifname awg0 masquerade\n}"
        runs = [
            (0, ("table inet awg_routing {\n"
                 "  chain prerouting { type filter hook prerouting priority mangle; }\n"
                 "  chain output { type route hook output priority mangle; }\n"
                 "  chain postrouting { type nat hook postrouting priority srcnat; }\n"
                 "  chain forward { type filter hook forward priority -1; }\n"
                 "}"), ""),
            (0, chain_listing, ""),
        ]
        with mock.patch.object(nftset_backend, "_run", side_effect=runs):
            r = nftset_backend.ensure_iface_masquerade("awg0")
            self.assertTrue(r["ok"])
            self.assertFalse(r["added"])

    def test_adds_when_missing(self):
        empty_chain = "chain postrouting {\n}"
        runs = [
            (0, ("table inet awg_routing {\n"
                 "  chain prerouting { type filter hook prerouting priority mangle; }\n"
                 "  chain output { type route hook output priority mangle; }\n"
                 "  chain postrouting { type nat hook postrouting priority srcnat; }\n"
                 "  chain forward { type filter hook forward priority -1; }\n"
                 "}"), ""),
            (0, empty_chain, ""),
            (0, "", ""),    # add rule succeeds
        ]
        with mock.patch.object(nftset_backend, "_run", side_effect=runs):
            r = nftset_backend.ensure_iface_masquerade("awg0")
            self.assertTrue(r["ok"])
            self.assertTrue(r["added"])


if __name__ == "__main__":
    unittest.main()
