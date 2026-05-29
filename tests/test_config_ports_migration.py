# tests/test_config_ports_migration.py
"""Тесты миграции портов: расширяем только нетронутые узкие дефолты."""

import json
import os
import tempfile
import unittest

from core.config_manager import ConfigManager


def _load_with(saved: dict):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "settings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(saved, f)
    cm = ConfigManager(config_dir=d)
    cm.load()
    return cm


class TestPortsMigration(unittest.TestCase):

    def test_old_default_tcp_widened(self):
        cm = _load_with({"nfqws": {"ports_tcp": "80,443", "ports_udp": "443"}})
        self.assertNotEqual(cm.get("nfqws", "ports_tcp"), "80,443")
        self.assertIn("5222", cm.get("nfqws", "ports_tcp"))
        self.assertIn("49152:65535", cm.get("nfqws", "ports_udp"))

    def test_custom_tcp_preserved(self):
        cm = _load_with({"nfqws": {"ports_tcp": "80,443,9999",
                                   "ports_udp": "443,1234"}})
        self.assertEqual(cm.get("nfqws", "ports_tcp"), "80,443,9999")
        self.assertEqual(cm.get("nfqws", "ports_udp"), "443,1234")

    def test_fresh_install_has_wide_defaults(self):
        d = tempfile.mkdtemp()
        cm = ConfigManager(config_dir=d)
        cm.load()
        self.assertIn("8443", cm.get("nfqws", "ports_tcp"))
        self.assertIn("3478:3481", cm.get("nfqws", "ports_udp"))


if __name__ == "__main__":
    unittest.main()
