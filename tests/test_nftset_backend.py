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


class TestRuleExists(unittest.TestCase):
    """_rule_exists ищет нужный паттерн в выводе nft list chain."""

    def test_match_v4(self):
        listing = "chain prerouting {\n  ip daddr @set1 meta mark set 0xabcd\n}"
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(0, listing, "")):
            self.assertTrue(
                nftset_backend._rule_exists(
                    "prerouting", "set1", 0xabcd, "v4"))

    def test_match_v6(self):
        listing = "chain output {\n  ip6 daddr @set2 meta mark set 0x42\n}"
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(0, listing, "")):
            self.assertTrue(
                nftset_backend._rule_exists(
                    "output", "set2", 0x42, "v6"))

    def test_no_match(self):
        listing = "chain prerouting {\n  meta mark set 0x9999\n}"
        with mock.patch.object(nftset_backend, "_run",
                               return_value=(0, listing, "")):
            self.assertFalse(
                nftset_backend._rule_exists(
                    "prerouting", "set1", 0xabcd, "v4"))


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
