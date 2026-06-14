# tests/test_phase3_fixes.py
"""Тесты оптимизаций Фазы 3 (поведение сохраняется)."""

import unittest
from unittest import mock


# ════════════════════════════════════════════════════════════
# server_pool.refresh_pool — параллельный фетч, поведение сохранено
# ════════════════════════════════════════════════════════════

class TestServerPoolConcurrentRefresh(unittest.TestCase):

    def test_aggregate_and_source_order(self):
        from core import server_pool as sp

        sources = [
            {"id": "a", "name": "A", "url": "http://a", "enabled": True},
            {"id": "b", "name": "B", "url": "http://b", "enabled": True},
            {"id": "c", "name": "C", "url": "http://c", "enabled": True},
        ]

        def fake_fetch(url, fmt, transport=""):
            sid = url[-1]
            n = {"a": 1, "b": 2, "c": 1}[sid]
            obs = [{"tag": "%s%d" % (sid, i), "type": "vless",
                    "server": "10.0.%d.%d" % (ord(sid), i),
                    "server_port": 443}
                   for i in range(n)]
            return {"outbounds": obs, "error": ""}

        settings = {"cap": 100, "health_filter": False, "group": "urltest",
                    "target": "cloudflare", "transport": ""}
        built = {}

        with mock.patch.object(sp, "list_sources", return_value=sources), \
             mock.patch.object(sp, "get_settings", return_value=settings), \
             mock.patch("core.subscription_manager.fetch_outbounds",
                        side_effect=fake_fetch), \
             mock.patch.object(sp, "_load_cache", return_value={}), \
             mock.patch.object(sp, "_save_cache"), \
             mock.patch.object(sp, "_record"), \
             mock.patch.object(sp, "_build_and_save",
                               side_effect=lambda agg, grp: built.update(
                                   {"n": len(agg)})):
            res = sp.refresh_pool()

        self.assertTrue(res.get("ok"), res)
        self.assertEqual(res["count"], 4)            # 1+2+1
        # per_source — в порядке источников, несмотря на параллельный фетч.
        self.assertEqual([s["id"] for s in res["sources"]], ["a", "b", "c"])
        self.assertEqual([s["count"] for s in res["sources"]], [1, 2, 1])
        self.assertEqual(built.get("n"), 4)

    def test_empty_source_uses_cache(self):
        from core import server_pool as sp
        sources = [{"id": "a", "name": "A", "url": "http://a",
                    "enabled": True}]
        settings = {"cap": 100, "health_filter": False, "group": "urltest",
                    "target": "cloudflare", "transport": ""}
        cache = {"a": {"outbounds": [{"tag": "old", "type": "vless",
                                      "server": "1.2.3.4",
                                      "server_port": 443}]}}

        with mock.patch.object(sp, "list_sources", return_value=sources), \
             mock.patch.object(sp, "get_settings", return_value=settings), \
             mock.patch("core.subscription_manager.fetch_outbounds",
                        return_value={"outbounds": [], "error": "fail"}), \
             mock.patch.object(sp, "_load_cache", return_value=cache), \
             mock.patch.object(sp, "_save_cache"), \
             mock.patch.object(sp, "_record"), \
             mock.patch.object(sp, "_build_and_save"):
            res = sp.refresh_pool()

        self.assertTrue(res.get("ok"), res)
        self.assertTrue(res["sources"][0]["used_cache"])


# ════════════════════════════════════════════════════════════
# warp_importer — предвычисленные сети
# ════════════════════════════════════════════════════════════

class TestWarpRange(unittest.TestCase):

    def test_v4_in_range(self):
        from core.warp_importer import _is_in_warp_range
        self.assertTrue(_is_in_warp_range("162.159.192.5"))
        self.assertFalse(_is_in_warp_range("8.8.8.8"))

    def test_v6_in_range(self):
        from core.warp_importer import _is_in_warp_range
        self.assertTrue(_is_in_warp_range("2606:4700:d0::1"))

    def test_domain_branch(self):
        from core.warp_importer import _is_in_warp_range
        self.assertTrue(_is_in_warp_range("engage.cloudflareclient.com"))


# ════════════════════════════════════════════════════════════
# firewall.get_status — один вызов get_rules вместо двух
# ════════════════════════════════════════════════════════════

class TestFirewallStatusSingleCall(unittest.TestCase):

    def test_get_rules_called_once(self):
        from core.firewall import FirewallManager, NFT_TABLE
        fw = FirewallManager()
        calls = []

        def fake_rules():
            calls.append(1)
            return ["add rule inet %s postrouting ..." % NFT_TABLE]

        with mock.patch.object(fw, "detect_fw_type", return_value="nftables"), \
             mock.patch.object(fw, "get_rules", side_effect=fake_rules):
            st = fw.get_status()
        self.assertEqual(len(calls), 1)
        self.assertTrue(st["applied"])
        self.assertEqual(st["rules_count"], 1)


if __name__ == "__main__":
    unittest.main()
