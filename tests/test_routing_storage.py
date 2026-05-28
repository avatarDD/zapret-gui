# tests/test_routing_storage.py
"""
Unit-тесты для core/routing/storage.py.

Storage использует ConfigManager.get/set/save — мокаем сам менеджер
через in-memory dict, чтобы тесты не трогали файловую систему.
"""

import unittest
from unittest import mock

from core.routing import storage
from core.routing.rules import CidrRoutingRule, DomainRoutingRule


class FakeConfigManager:
    """In-memory заглушка для ConfigManager."""

    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value

    def save(self):
        return True


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._patch = mock.patch(
            "core.routing.storage.get_config_manager",
            return_value=self.fake,
        )
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_empty_load(self):
        self.assertEqual(storage.load_rules(), [])

    def test_add_rule(self):
        r = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                            rule_id="cidr-1")
        storage.add_rule(r)
        loaded = storage.load_rules()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].id, "cidr-1")
        self.assertEqual(loaded[0].cidrs, ["10.0.0.0/24"])

    def test_add_replaces_same_id(self):
        # add_rule с тем же id должен ЗАМЕНИТЬ старое правило,
        # а не дублировать (см. реализацию storage.add_rule).
        r1 = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                             rule_id="r1")
        r2 = CidrRoutingRule(target_iface="awg1", cidrs=["10.0.0.0/24"],
                             rule_id="r1")
        storage.add_rule(r1)
        storage.add_rule(r2)
        loaded = storage.load_rules()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].target_iface, "awg1")

    def test_add_multiple(self):
        r1 = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                             rule_id="r1")
        r2 = DomainRoutingRule(target_iface="awg0",
                               domains=["youtube.com"],
                               rule_id="r2")
        storage.add_rule(r1)
        storage.add_rule(r2)
        loaded = storage.load_rules()
        self.assertEqual(len(loaded), 2)
        types = sorted(type(r).__name__ for r in loaded)
        self.assertEqual(types, ["CidrRoutingRule", "DomainRoutingRule"])

    def test_get_rule(self):
        r = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                            rule_id="my-rule")
        storage.add_rule(r)
        got = storage.get_rule("my-rule")
        self.assertIsNotNone(got)
        self.assertEqual(got.id, "my-rule")

    def test_get_rule_missing(self):
        self.assertIsNone(storage.get_rule("nope"))

    def test_remove_rule(self):
        r = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                            rule_id="r1")
        storage.add_rule(r)
        self.assertTrue(storage.remove_rule("r1"))
        self.assertEqual(storage.load_rules(), [])

    def test_remove_missing_returns_false(self):
        self.assertFalse(storage.remove_rule("nope"))

    def test_update_rule(self):
        r = CidrRoutingRule(target_iface="awg0", cidrs=["10.0.0.0/24"],
                            rule_id="r1")
        storage.add_rule(r)
        r_updated = CidrRoutingRule(target_iface="awg1",
                                    cidrs=["192.168.0.0/16"],
                                    rule_id="r1")
        storage.update_rule(r_updated)
        loaded = storage.load_rules()[0]
        self.assertEqual(loaded.target_iface, "awg1")
        self.assertEqual(loaded.cidrs, ["192.168.0.0/16"])

    def test_save_rules_full_replace(self):
        r1 = CidrRoutingRule(target_iface="awg0", cidrs=["1.0.0.0/8"],
                             rule_id="r1")
        r2 = CidrRoutingRule(target_iface="awg0", cidrs=["2.0.0.0/8"],
                             rule_id="r2")
        storage.save_rules([r1, r2])
        self.assertEqual(len(storage.load_rules()), 2)

    def test_corrupted_rule_skipped_not_crashed(self):
        # В settings лежит мусор — load_rules не должен падать,
        # просто пропустит битое правило.
        self.fake.set("routing", {"rules": [
            {"type": "cidr", "target_iface": "awg0",
             "cidrs": ["10.0.0.0/24"], "id": "good"},
            {"type": "wireguard"},   # неизвестный type
            "not-a-dict",
        ]})
        loaded = storage.load_rules()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].id, "good")


if __name__ == "__main__":
    unittest.main()
