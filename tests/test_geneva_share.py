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


DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data",
                    "geneva")
X = "[TCP:flags:PA]-xfake{blob=z2_tls_clienthello_vk_com;ttl=3}-| \\/"


class TestVersion2(unittest.TestCase):
    """Версия 2 — x-стратегии geneva_c 2.0 (договор с Zapret2_AutoTuner)."""

    def test_export_marks_x_strategies(self):
        doc = sh.build_export([{"strategy": X, "services": ["vk.com"]},
                               {"strategy": TCP}], now=0)
        self.assertEqual(doc["version"], 2)
        x, plain = doc["items"]
        self.assertIs(x["ext"], True)
        self.assertEqual(x["blobs"], ["z2_tls_clienthello_vk_com"])
        self.assertNotIn("ext", plain)
        self.assertNotIn("blobs", plain)

    def test_golden_v2_round_trip(self):
        with open(os.path.join(DATA, "share-v2.json"), encoding="utf-8") as f:
            text = f.read()
        rows, errors = sh.parse_import(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 4)
        self.assertTrue(rows[0]["ext"])
        self.assertEqual(rows[0]["blobs"], ["z2_tls_clienthello_vk_com"])
        self.assertTrue(rows[2]["ext"])
        self.assertNotIn("blobs", rows[2])
        self.assertNotIn("ext", rows[3])
        # экспорт тех же строк даёт тот же файл
        doc = sh.build_export([{"strategy": r["strategy"],
                                "services": r["services"],
                                "fitness": i.get("fitness")}
                               for r, i in zip(rows,
                                               json.loads(text)["items"])],
                              now=1794979200)
        self.assertEqual(doc, json.loads(text))

    def test_old_v1_export_still_imports(self):
        with open(os.path.join(DATA, "share-v1.json"), encoding="utf-8") as f:
            rows, errors = sh.parse_import(f.read())
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["services"], ["youtube.com",
                                               "googlevideo.com"])
        self.assertFalse(any(r.get("ext") for r in rows))

    def test_autotuner_export_imports(self):
        """Файл, записанный Zapret2_AutoTuner (GenevaShare.Build)."""
        with open(os.path.join(DATA, "autotuner-export-v2.json"),
                  encoding="utf-8") as f:
            rows, errors = sh.parse_import(f.read())
        self.assertEqual(errors, [])
        self.assertTrue(any(r.get("blobs") for r in rows))

    def test_fields_are_recomputed(self):
        """ext и blobs из файла не доверяются: считаются по стратегии."""
        rows, _ = sh.parse_import(json.dumps({
            "format": sh.FORMAT, "version": 2,
            "items": [{"strategy": TCP, "ext": True, "blobs": ["z2_x"]}]}))
        self.assertEqual(rows, [{"strategy": TCP, "services": []}])


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
