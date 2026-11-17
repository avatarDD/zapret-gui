# tests/test_list_lint.py
"""Проверка хостлистов: мусор, повторы, конфликты (core/list_lint)."""

import unittest

from core import list_lint as ll
from core.hostlist_manager import HostlistManager

NORM = HostlistManager().normalize_domain


class TestLintEntries(unittest.TestCase):

    def test_clean_list(self):
        r = ll.lint_entries(["example.com", "ya.ru"], normalize=NORM)
        self.assertEqual(r["issues"], {})
        self.assertEqual(r["fixable"], 0)

    def test_wildcard_and_url(self):
        r = ll.lint_entries(["*.example.com", "https://Ya.RU/path",
                             "www.rutracker.org"], normalize=NORM)
        self.assertEqual(r["issues"][ll.CODE_WILDCARD]["samples"][0]["fix"],
                         "example.com")
        self.assertEqual(r["issues"][ll.CODE_NOT_NORMAL]["count"], 2)

    def test_duplicate_and_covered(self):
        r = ll.lint_entries(["example.com", "EXAMPLE.com", "a.example.com",
                             "^b.example.com"], normalize=NORM)
        self.assertEqual(r["issues"][ll.CODE_DUPLICATE]["count"], 1)
        # строгая запись поддоменом не считается — она точная
        self.assertEqual(r["issues"][ll.CODE_COVERED]["count"], 1)
        self.assertEqual(r["issues"][ll.CODE_COVERED]["samples"][0]["fix"],
                         "example.com")

    def test_local_exemption(self):
        # zapret2 1.0.7: «!» — исключение внутри списка, «com» + «!vk.com».
        # Не мусор и не «покрыто родителем»: под родителем оно и нужно.
        r = ll.lint_entries(["com", "!vk.com", "!^ok.com"], normalize=NORM)
        self.assertEqual(r["issues"], {})
        self.assertEqual(ll.fix_entries(["com", "!vk.com", "a.com"],
                                        normalize=NORM), ["com", "!vk.com"])
        # исключение в списке обхода — не обход и с exclude не конфликтует
        cc = ll.cross_check({"other": ["!vk.com"], "netrogat": ["vk.com"]},
                            excludes={"netrogat"}, normalize=NORM)
        self.assertEqual(cc["conflicts"], [])

    def test_prefix_normalization(self):
        self.assertEqual(NORM("!vk.com"), "!vk.com")
        self.assertEqual(NORM("^!vk.com"), "!^vk.com")
        self.assertEqual(NORM("!^vk.com"), "!^vk.com")
        self.assertEqual(NORM("!*.vk.com"), "!vk.com")
        self.assertEqual(NORM("!https://www.vk.com/feed"), "!vk.com")
        self.assertIsNone(NORM("!"))

    def test_invalid_is_reported_not_fixed(self):
        r = ll.lint_entries(["not a domain!"], normalize=NORM)
        self.assertEqual(r["issues"][ll.CODE_INVALID]["count"], 1)
        self.assertEqual(r["fixable"], 0)

    def test_comments_skipped(self):
        r = ll.lint_entries(["# comment", "", "ya.ru"], normalize=NORM)
        self.assertEqual(r["issues"], {})


class TestFixEntries(unittest.TestCase):

    def test_fix(self):
        out = ll.fix_entries(["*.example.com", "a.example.com", "Ya.ru",
                              "ya.ru", "junk entry!", "^x.example.com"],
                             normalize=NORM)
        self.assertEqual(out, ["example.com", "ya.ru", "junk entry!",
                               "^x.example.com"])

    def test_fix_is_idempotent(self):
        once = ll.fix_entries(["*.a.com", "b.a.com", "c.com"], normalize=NORM)
        self.assertEqual(ll.fix_entries(once, normalize=NORM), once)


class TestCrossCheck(unittest.TestCase):

    def test_duplicates(self):
        r = ll.cross_check({"other": ["ya.ru"], "my": ["ya.ru", "x.com"]},
                           normalize=NORM)
        self.assertEqual(r["duplicates"],
                         [{"entry": "ya.ru", "lists": ["my", "other"]}])

    def test_conflict_by_parent(self):
        r = ll.cross_check({"other": ["video.example.com"],
                            "netrogat": ["example.com"]},
                           excludes=["netrogat"], normalize=NORM)
        self.assertEqual(len(r["conflicts"]), 1)
        c = r["conflicts"][0]
        self.assertEqual(c["entry"], "video.example.com")
        self.assertEqual(c["exclude_entry"], "example.com")
        self.assertEqual(c["bypass"], ["other"])

    def test_strict_exclude_only_exact(self):
        r = ll.cross_check({"other": ["a.example.com", "example.com"],
                            "netrogat": ["^example.com"]},
                           excludes=["netrogat"], normalize=NORM)
        self.assertEqual([c["entry"] for c in r["conflicts"]],
                         ["example.com"])

    def test_no_conflict_without_excludes(self):
        r = ll.cross_check({"other": ["ya.ru"], "netrogat": ["ya.ru"]},
                           normalize=NORM)
        self.assertEqual(r["conflicts"], [])


class TestReviewFixes(unittest.TestCase):

    def test_tld_exclude_covers(self):
        r = ll.cross_check({"other": ["xn--80ak6aa92e.xn--p1ai"],
                            "netrogat": ["xn--p1ai"]},
                           excludes=["netrogat"], normalize=NORM)
        self.assertEqual(len(r["conflicts"]), 1)

    def test_unread_list_does_not_conflict(self):
        r = ll.cross_check({"other": ["ya.ru"], "other2": ["sber.ru"],
                            "netrogat": ["ya.ru", "sber.ru"]},
                           excludes=["netrogat"], bypass=["other"],
                           normalize=NORM)
        self.assertEqual([c["entry"] for c in r["conflicts"]], ["ya.ru"])

    def test_fixable_counts_lines_once(self):
        r = ll.lint_entries(["example.com", "*.example.com"], normalize=NORM)
        self.assertEqual(r["fixable"], 1)
        self.assertEqual(len(ll.fix_entries(["example.com", "*.example.com"],
                                            normalize=NORM)), 1)

    def test_fix_lines_keeps_comments(self):
        out = ll.fix_lines(["# банки", "*.sber.ru", "", "# видео",
                            "a.sber.ru", "YouTube.com"], normalize=NORM)
        self.assertEqual(out, ["# банки", "sber.ru", "", "# видео",
                               "youtube.com"])

    def test_fix_list_on_disk(self):
        import os
        import tempfile
        from unittest import mock
        from core import hostlist_manager as hlm
        with tempfile.TemporaryDirectory() as d:
            hm = hlm.HostlistManager()
            path = os.path.join(d, "my.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("# мой\n*.ya.ru\nya.ru\n")
            with mock.patch.object(hlm.HostlistManager, "lists_path",
                                   new=property(lambda self: d)), \
                 mock.patch.object(hlm, "get_hostlist_manager",
                                   return_value=hm), \
                 mock.patch.object(hm, "list_names", return_value=["my"]):
                res = ll.fix_list("my")
            with open(path, encoding="utf-8") as f:
                text = f.read()
        self.assertTrue(res["changed"])
        self.assertEqual((res["before"], res["after"]), (2, 1))
        self.assertEqual(text, "# мой\nya.ru\n")


class TestUsage(unittest.TestCase):

    def test_usage_from_argv(self):
        u = ll.strategy_list_usage([
            "--hostlist=/opt/zapret2/lists/other.txt,/opt/zapret2/lists/my.txt",
            "--hostlist-exclude=/opt/zapret2/lists/netrogat.txt",
            "--new", "--hostlist=/opt/zapret2/lists/netrogat.txt"])
        self.assertEqual(u, {"other": "bypass", "my": "bypass",
                             "netrogat": "exclude"})


if __name__ == "__main__":
    unittest.main()
