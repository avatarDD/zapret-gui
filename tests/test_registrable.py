# tests/test_registrable.py
"""Регистрируемый домен по Public Suffix List (core/registrable)."""

import unittest

from unittest import mock

from core import registrable as rg
from core.registrable import parse_rules, registrable


class TestRegistrable(unittest.TestCase):

    def test_real_list(self):
        cases = {
            "api.example.co.uk": "example.co.uk",
            "www.youtube.com": "youtube.com",
            "rr5---sn-abc.googlevideo.com": "googlevideo.com",
            "user.github.io": "user.github.io",
            "a.b.github.io": "b.github.io",
            "sub.example.com.ru": "example.com.ru",
            "Example.COM.": "example.com",
            "co.uk": "",
            "com": "",
            "": "",
        }
        for domain, want in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(registrable(domain), want)

    def test_wildcard_and_exception(self):
        rules = parse_rules(["// комментарий", "jp", "*.kawasaki.jp",
                             "!city.kawasaki.jp", "com"])
        self.assertEqual(registrable("a.b.kawasaki.jp", rules),
                         "a.b.kawasaki.jp")
        self.assertEqual(registrable("x.city.kawasaki.jp", rules),
                         "city.kawasaki.jp")
        # Без правила — суффикс последняя метка («*»).
        self.assertEqual(registrable("a.b.unknowntld", rules), "b.unknowntld")


if __name__ == "__main__":
    unittest.main()


class TestNoSnapshot(unittest.TestCase):
    def test_missing_psl_returns_exact_name(self):
        # Снимок не прочитался: не «co.uk», а само имя.
        with mock.patch.object(rg, "_load", return_value=(set(), set(),
                                                          set())):
            self.assertEqual(rg.registrable("api.example.co.uk"),
                             "api.example.co.uk")
