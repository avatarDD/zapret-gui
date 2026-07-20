# tests/test_dns_providers.py
"""Unit-тесты для core/dns_providers.py."""

import unittest

from core import dns_providers as dp


class TestDohProviders(unittest.TestCase):
    """Тесты DoH провайдеров."""

    def test_has_required_providers(self):
        required = ["google", "cloudflare", "adguard", "yandex",
                     "quad9", "comss", "geohide", "geohide-h3"]
        ids = [p["id"] for p in dp.DOH_PROVIDERS]
        for rid in required:
            self.assertIn(rid, ids, "Missing DoH provider: %s" % rid)

    def test_all_have_url(self):
        for p in dp.DOH_PROVIDERS:
            self.assertIn("url", p, "Provider %s missing url" % p["id"])
            self.assertTrue(p["url"], "Provider %s has empty url" % p["id"])

    def test_all_have_ips(self):
        for p in dp.DOH_PROVIDERS:
            self.assertIn("ips", p, "Provider %s missing ips" % p["id"])
            self.assertGreater(len(p["ips"]), 0,
                               "Provider %s has empty ips" % p["id"])

    def test_geohide_doh(self):
        gh = next(p for p in dp.DOH_PROVIDERS if p["id"] == "geohide")
        self.assertIn("geohide.ru", gh["url"])
        self.assertIn("45.155.204.190", gh["ips"])

    def test_geohide_h3(self):
        gh = next(p for p in dp.DOH_PROVIDERS if p["id"] == "geohide-h3")
        self.assertTrue(gh["url"].startswith("h3://"))


class TestDotProviders(unittest.TestCase):
    """Тесты DoT провайдеров."""

    def test_has_geohide_dot(self):
        ids = [p["id"] for p in dp.DOT_PROVIDERS]
        self.assertIn("geohide-dot", ids)

    def test_geohide_dot_config(self):
        gh = next(p for p in dp.DOT_PROVIDERS if p["id"] == "geohide-dot")
        self.assertEqual(gh["host"], "dns.geohide.ru")
        self.assertEqual(gh["port"], 853)
        self.assertIn("45.155.204.190", gh["ips"])


class TestListProviders(unittest.TestCase):
    """Тесты list_providers."""

    def test_returns_all(self):
        all_providers = dp.list_providers()
        doh_count = len(dp.DOH_PROVIDERS)
        dot_count = len(dp.DOT_PROVIDERS)
        self.assertEqual(len(all_providers), doh_count + dot_count)

    def test_list_doh(self):
        self.assertEqual(len(dp.list_doh()), len(dp.DOH_PROVIDERS))

    def test_list_dot(self):
        self.assertEqual(len(dp.list_dot()), len(dp.DOT_PROVIDERS))


class TestGetProvider(unittest.TestCase):
    """Тесты get_provider."""

    def test_get_existing(self):
        p = dp.get_provider("cloudflare")
        self.assertEqual(p["id"], "cloudflare")

    def test_get_geohide(self):
        p = dp.get_provider("geohide")
        self.assertIn("geohide.ru", p.get("url", ""))

    def test_get_nonexistent(self):
        p = dp.get_provider("nonexistent")
        self.assertEqual(p, {})


if __name__ == "__main__":
    unittest.main()
