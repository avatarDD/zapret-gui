# tests/test_alias_resolver.py
"""
Unit-тесты для core/routing/alias_resolver.py.

Сетевые вызовы (resolve_alias → fetch) монкипатчим через `_http_get_text`.
"""

import unittest
from unittest import mock

from core.routing import alias_resolver


class TestParseAlias(unittest.TestCase):

    def test_basic(self):
        kind, name = alias_resolver.parse_alias("geosite:youtube")
        self.assertEqual(kind, "geosite")
        self.assertEqual(name, "youtube")

    def test_uppercase_normalizes(self):
        kind, name = alias_resolver.parse_alias("GEOIP:RU")
        self.assertEqual(kind, "geoip")
        self.assertEqual(name, "ru")

    def test_not_alias(self):
        kind, name = alias_resolver.parse_alias("youtube.com")
        self.assertIsNone(kind)
        self.assertIsNone(name)

    def test_is_alias(self):
        self.assertTrue(alias_resolver.is_alias("geosite:netflix"))
        self.assertFalse(alias_resolver.is_alias("netflix.com"))
        self.assertFalse(alias_resolver.is_alias(""))


class TestParseGeositeBody(unittest.TestCase):

    def test_plain_domains(self):
        text = "youtube.com\nytimg.com\ngoogle.com\n"
        result = alias_resolver._parse_geosite_body(text)
        self.assertEqual(result, ["youtube.com", "ytimg.com", "google.com"])

    def test_prefixes_stripped(self):
        text = "full:example.com\ndomain:foo.bar\nbaz.com\n"
        result = alias_resolver._parse_geosite_body(text)
        self.assertEqual(result, ["example.com", "foo.bar", "baz.com"])

    def test_excludes_regexp_include_keyword(self):
        text = """youtube.com
regexp:^.*youtube.*\\.com$
include:other-list
keyword:youtube
ytimg.com"""
        result = alias_resolver._parse_geosite_body(text)
        self.assertEqual(result, ["youtube.com", "ytimg.com"])

    def test_tags_stripped(self):
        text = "youtube.com @cn\nnetflix.com\n"
        result = alias_resolver._parse_geosite_body(text)
        self.assertEqual(result, ["youtube.com", "netflix.com"])

    def test_comments_ignored(self):
        text = "# header\nyoutube.com\n# section 2\nnetflix.com\n"
        result = alias_resolver._parse_geosite_body(text)
        self.assertEqual(result, ["youtube.com", "netflix.com"])


class TestParseGeoipBody(unittest.TestCase):

    def test_simple(self):
        text = "10.0.0.0/24\n192.168.1.0/24\n2001:db8::/32\n"
        result = alias_resolver._parse_geoip_body(text)
        self.assertEqual(result,
                         ["10.0.0.0/24", "192.168.1.0/24", "2001:db8::/32"])

    def test_drops_garbage(self):
        text = "10.0.0.0/24\nnot-a-cidr-line\n8.8.8.8\n"
        result = alias_resolver._parse_geoip_body(text)
        self.assertEqual(result, ["10.0.0.0/24", "8.8.8.8"])


class TestExpandDomains(unittest.TestCase):

    def test_pure_domains_and_cidrs(self):
        items = ["youtube.com", "10.0.0.0/24", "8.8.8.8"]
        # Не должно лезть в сеть — все элементы не алиасы.
        with mock.patch.object(alias_resolver, "resolve_alias") as m:
            m.side_effect = AssertionError("не должен вызываться")
            res = alias_resolver.expand_domains(items)
        self.assertEqual(res["domains"], ["youtube.com"])
        self.assertEqual(sorted(res["cidrs"]), ["10.0.0.0/24", "8.8.8.8"])
        self.assertEqual(res["aliases_resolved"], [])
        self.assertEqual(res["aliases_failed"], [])

    def test_alias_expanded(self):
        with mock.patch.object(alias_resolver, "resolve_alias",
                               return_value=["ytimg.com", "youtube.com"]):
            res = alias_resolver.expand_domains(["geosite:youtube"])
        self.assertIn("ytimg.com", res["domains"])
        self.assertIn("youtube.com", res["domains"])
        self.assertEqual(res["aliases_resolved"],
                         [{"kind": "geosite", "name": "youtube", "count": 2}])

    def test_alias_failed(self):
        with mock.patch.object(alias_resolver, "resolve_alias",
                               return_value=[]):
            res = alias_resolver.expand_domains(["geosite:nope"])
        self.assertEqual(res["domains"], [])
        self.assertEqual(res["aliases_failed"],
                         [{"kind": "geosite", "name": "nope"}])

    def test_dedup(self):
        # И raw, и из алиаса — дубль не уйдёт в финал.
        with mock.patch.object(alias_resolver, "resolve_alias",
                               return_value=["youtube.com"]):
            res = alias_resolver.expand_domains(
                ["youtube.com", "geosite:youtube"])
        self.assertEqual(res["domains"].count("youtube.com"), 1)


class TestResolveAlias(unittest.TestCase):
    """resolve_alias — мок _http_get_text, проверяем парсинг и кэш."""

    def test_geosite_success(self):
        body = "youtube.com\nytimg.com\n"
        with mock.patch.object(alias_resolver, "_http_get_text",
                               return_value=body):
            with mock.patch.object(alias_resolver, "_read_cache",
                                   return_value=None):
                with mock.patch.object(alias_resolver,
                                       "_write_cache") as mw:
                    items = alias_resolver.resolve_alias(
                        "geosite", "youtube", force_refresh=True)
            self.assertEqual(items, ["youtube.com", "ytimg.com"])
            mw.assert_called_once()

    def test_uses_stale_cache_on_network_failure(self):
        stale = {"items": ["old.example.com"], "fetched_at": 1}
        with mock.patch.object(alias_resolver, "_http_get_text",
                               return_value=""):
            with mock.patch.object(alias_resolver, "_read_cache",
                                   return_value=stale):
                items = alias_resolver.resolve_alias(
                    "geosite", "youtube", force_refresh=True)
        # Сеть вернула пусто, но stale-кэш должен спасти.
        self.assertEqual(items, ["old.example.com"])

    def test_invalid_kind(self):
        items = alias_resolver.resolve_alias("nonsense", "foo")
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
