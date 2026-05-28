# tests/test_ipset_backend.py
"""
Unit-тесты для core/routing/ipset_backend.py с моком `_run`.
Аналогично test_nftset_backend.py.
"""

import unittest
from unittest import mock

from core.routing import ipset_backend


class TestSetNameFor(unittest.TestCase):

    def test_basic(self):
        name = ipset_backend.set_name_for("domain-abc")
        self.assertTrue(name.startswith("awgr_"))
        self.assertIn("abc", name)

    def test_dashes_replaced(self):
        self.assertNotIn("-", ipset_backend.set_name_for("a-b-c"))

    def test_length_31_chars(self):
        # ipset имеет лимит на длину имени; проверяем что усекаем.
        long_id = "x" * 100
        self.assertLessEqual(len(ipset_backend.set_name_for(long_id)), 31)


class TestAvailable(unittest.TestCase):

    def test_available_true(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(0, "", "")):
            self.assertTrue(ipset_backend.available())

    def test_available_false(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(127, "", "command not found")):
            self.assertFalse(ipset_backend.available())


class TestCreateSet(unittest.TestCase):

    def test_already_exists(self):
        # list -name → set уже в выводе
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(0, "awgr_test\nother_set\n", "")):
            r = ipset_backend.create_set("awgr_test", family="v4")
            self.assertTrue(r["ok"])
            self.assertFalse(r["created"])

    def test_creates_new(self):
        runs = [
            (0, "", ""),         # list -name (нашего нет)
            (0, "", ""),         # create
        ]
        with mock.patch.object(ipset_backend, "_run", side_effect=runs):
            r = ipset_backend.create_set("awgr_new", family="v4")
            self.assertTrue(r["ok"])
            self.assertTrue(r["created"])

    def test_creates_v6_family(self):
        # Проверяем что для v6 используется inet6
        runs = [(0, "", ""), (0, "", "")]
        with mock.patch.object(ipset_backend, "_run",
                               side_effect=runs) as m:
            ipset_backend.create_set("awgr_v6", family="v6")
            # Второй вызов — create. Проверяем что в args есть inet6.
            create_args = m.call_args_list[1][0][0]
            self.assertIn("inet6", create_args)

    def test_race_already_exists_during_create(self):
        # Кто-то параллельно создал — stderr содержит «already exists»
        runs = [
            (0, "", ""),                         # list -name (наш отсутствует)
            (1, "", "set with the given name already exists"),  # create
        ]
        with mock.patch.object(ipset_backend, "_run", side_effect=runs):
            r = ipset_backend.create_set("awgr_race", family="v4")
            self.assertTrue(r["ok"])


class TestDestroySet(unittest.TestCase):

    def test_destroys(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(0, "", "")):
            r = ipset_backend.destroy_set("awgr_x")
            self.assertTrue(r["ok"])

    def test_not_exists_treated_as_ok(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(1, "",
                                "The set with the given name does not exist")):
            r = ipset_backend.destroy_set("awgr_missing")
            self.assertTrue(r["ok"])


class TestFlushSet(unittest.TestCase):

    def test_flush_ok(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(0, "", "")):
            self.assertTrue(ipset_backend.flush_set("awgr_x")["ok"])


class TestAddDelIpRuleFwmark(unittest.TestCase):
    """add_ip_rule_fwmark/del_ip_rule_fwmark — обёртки вокруг `ip rule`."""

    def test_add_returns_ok(self):
        # Сначала del (best-effort), потом add.
        runs = [(2, "", ""), (0, "", "")]
        with mock.patch.object(ipset_backend, "_run", side_effect=runs):
            r = ipset_backend.add_ip_rule_fwmark(0x100, 200, family="v4")
            self.assertTrue(r["ok"])

    def test_del_returns_ok(self):
        with mock.patch.object(ipset_backend, "_run",
                               return_value=(0, "", "")):
            r = ipset_backend.del_ip_rule_fwmark(0x100, 200, family="v4")
            self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main()
