# tests/test_named_lists.py
"""Unit-тесты для core/named_lists.py."""

import unittest
from unittest import mock

from core import named_lists as nl


class FakeConfigManager:
    def __init__(self):
        self.data = {}
    def get(self, key, default=None):
        return self.data.get(key, default)
    def set(self, key, value):
        self.data[key] = value
    def save(self):
        return True


class TestClassify(unittest.TestCase):

    def test_domain(self):
        self.assertEqual(nl.classify_entry("Example.COM"), ("domain", "example.com"))
        self.assertEqual(nl.classify_entry("sub.youtube.com")[0], "domain")

    def test_domain_strip_url(self):
        self.assertEqual(nl.classify_entry("https://example.com/path"),
                         ("domain", "example.com"))

    def test_ip_to_cidr(self):
        self.assertEqual(nl.classify_entry("1.2.3.4"), ("cidr", "1.2.3.4/32"))

    def test_cidr(self):
        self.assertEqual(nl.classify_entry("10.0.0.0/8"), ("cidr", "10.0.0.0/8"))

    def test_v6(self):
        k, v = nl.classify_entry("2001:db8::1")
        self.assertEqual(k, "cidr")
        self.assertTrue(v.endswith("/128"))

    def test_comment_and_empty(self):
        self.assertEqual(nl.classify_entry("# comment"), (None, ""))
        self.assertEqual(nl.classify_entry("   "), (None, ""))

    def test_garbage(self):
        self.assertEqual(nl.classify_entry("not a domain!!")[0], None)


class TestParseEntries(unittest.TestCase):

    def test_mixed(self):
        r = nl.parse_entries("example.com, 1.2.3.0/24\n10.0.0.1\n# c\nfoo.bar")
        self.assertIn("example.com", r["domains"])
        self.assertIn("foo.bar", r["domains"])
        self.assertIn("1.2.3.0/24", r["cidrs"])
        self.assertIn("10.0.0.1/32", r["cidrs"])

    def test_dedup(self):
        r = nl.parse_entries("a.com a.com a.com")
        self.assertEqual(r["domains"], ["a.com"])

    def test_list_input(self):
        r = nl.parse_entries(["a.com", "1.1.1.1"])
        self.assertEqual(r["domains"], ["a.com"])
        self.assertEqual(r["cidrs"], ["1.1.1.1/32"])


class TestStorageCrud(unittest.TestCase):

    def setUp(self):
        self.fake = FakeConfigManager()
        self._p = mock.patch("core.named_lists.get_config_manager",
                             return_value=self.fake)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_create_and_get(self):
        r = nl.create("My List", entries="example.com\n1.2.3.0/24")
        self.assertTrue(r["ok"])
        lid = r["list"]["id"]
        got = nl.get(lid)
        self.assertEqual(got["name"], "My List")
        self.assertEqual(got["domains"], ["example.com"])
        self.assertEqual(got["cidrs"], ["1.2.3.0/24"])

    def test_create_duplicate_name(self):
        nl.create("Dup")
        r = nl.create("Dup")
        self.assertFalse(r["ok"])

    def test_create_empty_name(self):
        self.assertFalse(nl.create("")["ok"])

    def test_list_all_counts(self):
        nl.create("L1", entries="a.com b.com 1.1.1.1")
        items = nl.list_all()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["domain_count"], 2)
        self.assertEqual(items[0]["cidr_count"], 1)

    def test_update_replace(self):
        lid = nl.create("L", entries="a.com")["list"]["id"]
        nl.update(lid, entries="b.com c.com", replace=True)
        self.assertEqual(nl.get(lid)["domains"], ["b.com", "c.com"])

    def test_update_append(self):
        lid = nl.create("L", entries="a.com")["list"]["id"]
        nl.update(lid, entries="b.com a.com", replace=False)
        self.assertEqual(nl.get(lid)["domains"], ["a.com", "b.com"])

    def test_resolve(self):
        lid = nl.create("L", entries="a.com 1.2.3.0/24")["list"]["id"]
        r = nl.resolve(lid)
        self.assertEqual(r["domains"], ["a.com"])
        self.assertEqual(r["cidrs"], ["1.2.3.0/24"])

    def test_delete(self):
        lid = nl.create("L")["list"]["id"]
        self.assertTrue(nl.delete(lid)["ok"])
        self.assertIsNone(nl.get(lid))
        self.assertFalse(nl.delete(lid)["ok"])


if __name__ == "__main__":
    unittest.main()
