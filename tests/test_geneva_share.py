"""Обмен найденными стратегиями geneva (core/geneva_share)."""

import json
import os
import tempfile
import unittest

from core import geneva_share as sh

TCP = "[TCP:flags:PA]-fragment{tcp:-1:False}-| \\/"
UDP = "[UDP:sport:*]-duplicate(tamper{UDP:load:corrupt},)-| \\/"


class TestExport(unittest.TestCase):

    def test_only_strategies_and_names(self):
        doc = sh.build_export([
            {"strategy": TCP, "fitness": 396,
             "services": [{"key": "port:udp:192.168.1.10:6881",
                           "name": "youtube.com"}],
             "targets": ["rutor.info"]},
            {"strategy": UDP, "services": []},
            {"strategy": ""}], now=0)
        self.assertEqual(doc["format"], sh.FORMAT)
        self.assertEqual(doc["exported_at"], "1970-01-01T00:00:00Z")
        self.assertEqual(len(doc["items"]), 2)
        self.assertEqual(doc["items"][0]["services"],
                         ["youtube.com", "rutor.info"])
        self.assertEqual(doc["items"][1]["transport"], "udp")
        self.assertNotIn("192.168.1.10", json.dumps(doc))


class TestImport(unittest.TestCase):

    def test_round_trip(self):
        doc = sh.build_export([{"strategy": TCP,
                                "services": [{"name": "a.ru"}]}])
        rows, errors = sh.parse_import(json.dumps(doc))
        self.assertEqual(errors, [])
        self.assertEqual(rows, [{"strategy": TCP, "services": ["a.ru"]}])
        rows, _ = sh.parse_import(doc)
        self.assertEqual(rows[0]["strategy"], TCP)

    def test_plain_text_and_errors(self):
        rows, errors = sh.parse_import(
            "# мой список\n%s\n\n%s\nне стратегия\n%s\n" % (TCP, UDP, TCP))
        self.assertEqual([r["strategy"] for r in rows], [TCP, UDP])
        self.assertEqual(len(errors), 1)

    def test_rejects(self):
        self.assertEqual(sh.parse_import('{"format": "other"}')[0], [])
        self.assertEqual(sh.parse_import("{bad json")[0], [])
        self.assertEqual(sh.parse_import("x" * (sh.MAX_BYTES + 1))[0], [])
        self.assertEqual(sh.parse_import(42)[0], [])


class TestStore(unittest.TestCase):

    def test_add_merge_remove(self):
        with tempfile.TemporaryDirectory() as d:
            st = sh.ImportStore(os.path.join(d, "auto", "imported.json"),
                                clock=lambda: 5.0)
            self.assertEqual(st.load(), [])
            self.assertEqual(st.add([{"strategy": TCP, "services": ["a"]}]),
                             {"added": 1, "total": 1})
            self.assertEqual(st.add([{"strategy": TCP, "services": ["b"]},
                                     {"strategy": UDP, "services": []}]),
                             {"added": 1, "total": 2})
            self.assertEqual(st.load()[0]["services"], ["a", "b"])
            self.assertTrue(st.remove(TCP))
            self.assertFalse(st.remove(TCP))
            self.assertEqual([i["strategy"] for i in st.load()], [UDP])


if __name__ == "__main__":
    unittest.main()
