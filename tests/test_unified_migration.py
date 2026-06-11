# tests/test_unified_migration.py
"""
Unit-тесты для core/unified/migration.py — перенос legacy-правил
selective routing (routing.rules) в единый слой (unified_routes).

Side-effect'ы в ядре (ip rule/ipset/применение) мокаются: проверяем
ТОЛЬКО трансформацию хранилищ и идемпотентность.
"""

import unittest
from unittest import mock

from core.routing.manager import RoutingManager
from core.unified import migration


class FakeConfigManager:
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def save(self):
        return True


LEGACY_RULES = [
    {"id": "cidr-11111111", "type": "cidr", "target_iface": "awg0",
     "cidrs": ["1.2.3.0/24"], "ip_version": "auto",
     "description": "Telegram CIDR", "enabled": True,
     "priority": 0, "created_at": 1700000000},
    {"id": "domain-22222222", "type": "domain", "target_iface": "tun0",
     "domains": ["youtube.com", "googlevideo.com"],
     "description": "", "enabled": True,
     "priority": 0, "created_at": 1700000001},
    {"id": "device-33333333", "type": "device", "target_iface": "awg0",
     "source_ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff",
     "hostname": "tv", "description": "", "enabled": False,
     "priority": 0, "created_at": 1700000002},
    {"id": "dscp-44444444", "type": "dscp", "target_iface": "awg0",
     "dscp": 46, "proxy_self": True, "description": "realtime",
     "enabled": True, "priority": 0, "created_at": 1700000003},
    # Производное правило единого слоя — мигрировать НЕЛЬЗЯ.
    {"id": "uni-route-aaaa-dom", "type": "domain", "target_iface": "awg0",
     "domains": ["x.com"], "description": "unified:x", "enabled": True,
     "priority": 0, "created_at": 1700000004},
]


class TestMigration(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self.fake.data["routing"] = {"rules": [dict(r) for r in LEGACY_RULES]}
        patches = [
            mock.patch("core.routing.storage.get_config_manager",
                       return_value=self.fake),
            mock.patch("core.unified.storage.get_config_manager",
                       return_value=self.fake),
            # Снятие kernel-артефактов legacy-правил — no-op.
            mock.patch.object(RoutingManager, "_remove",
                              return_value={"ok": True}),
            # Применение мигрированных маршрутов — no-op.
            mock.patch("core.unified.applier.apply_route",
                       return_value={"ok": True}),
            mock.patch("core.unified.migration._singbox_tun_ifaces",
                       return_value={"tun0"}),
        ]
        self._patches = patches
        for p in patches:
            p.start()
        # Монитор не трогаем.
        self._pm = mock.patch("core.unified.monitor.autostart_if_needed")
        self._pm.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._pm.stop()

    def _routing_ids(self):
        return [r.get("id")
                for r in self.fake.data.get("routing", {}).get("rules", [])]

    def _unified_by_id(self):
        return {r.get("id"): r
                for r in self.fake.data.get("unified_routes", [])}

    def test_legacy_rules_lists_only_non_uni(self):
        ids = [r["id"] for r in migration.legacy_rules()]
        self.assertEqual(len(ids), 4)
        self.assertNotIn("uni-route-aaaa-dom", ids)

    def test_migrate_moves_all_legacy(self):
        res = migration.migrate(apply=True)
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(res["migrated"]), 4)
        self.assertEqual(res["errors"], [])

        # В routing.rules осталось только производное uni-правило.
        self.assertEqual(self._routing_ids(), ["uni-route-aaaa-dom"])

        routes = self._unified_by_id()
        # CIDR: описание стало именем, метод awg:<iface>.
        cidr = routes["mig-cidr-11111111"]
        self.assertEqual(cidr["name"], "Telegram CIDR")
        self.assertEqual(cidr["method"], "awg:awg0")
        self.assertEqual(cidr["destination"]["cidrs"], ["1.2.3.0/24"])
        self.assertEqual(cidr["created_at"], 1700000000)
        # Domain: tun0 распознан как sing-box.
        dom = routes["mig-domain-22222222"]
        self.assertEqual(dom["method"], "singbox:tun0")
        self.assertEqual(dom["destination"]["domains"],
                         ["youtube.com", "googlevideo.com"])
        # Device: ip/mac/hostname сохранены, выключенность сохранена,
        # имя — из hostname.
        dev = routes["mig-device-33333333"]
        self.assertEqual(dev["devices"], [{
            "ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "tv"}])
        self.assertFalse(dev["enabled"])
        self.assertEqual(dev["name"], "tv → awg0")
        # DSCP: значение и proxy_self.
        q = routes["mig-dscp-44444444"]
        self.assertEqual(q["dscp"], 46)
        self.assertTrue(q["dscp_self"])
        self.assertEqual(q["name"], "realtime")

    def test_migrate_applies_only_enabled(self):
        with mock.patch("core.unified.applier.apply_route",
                        return_value={"ok": True}) as ap:
            migration.migrate(apply=True)
        applied_ids = [c.args[0].id for c in ap.call_args_list]
        self.assertIn("mig-cidr-11111111", applied_ids)
        # device-правило было enabled=False — не применяется.
        self.assertNotIn("mig-device-33333333", applied_ids)

    def test_migrate_idempotent(self):
        migration.migrate(apply=True)
        res2 = migration.migrate(apply=True)
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["migrated"], [])
        self.assertEqual(len(self._unified_by_id()), 4)

    def test_broken_device_rule_reported_not_lost(self):
        self.fake.data["routing"]["rules"].append(
            {"id": "device-broken", "type": "device", "target_iface": "awg0",
             "source_ip": "", "enabled": True})
        res = migration.migrate(apply=True)
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["errors"]), 1)
        self.assertIn("device-broken", res["errors"][0])
        # Битое правило осталось в routing.rules (не потеряли).
        self.assertIn("device-broken", self._routing_ids())

    def test_method_for_iface(self):
        self.assertEqual(
            migration.method_for_iface("tun0", {"tun0"}), "singbox:tun0")
        self.assertEqual(
            migration.method_for_iface("Wireguard0", {"tun0"}),
            "awg:Wireguard0")
        self.assertEqual(
            migration.method_for_iface("awg0", set()), "awg:awg0")


if __name__ == "__main__":
    unittest.main()
