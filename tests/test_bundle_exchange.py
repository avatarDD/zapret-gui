"""
Обмен стратегиями zapret-gui ⇄ Zapret2_AutoTuner на эталонных файлах.

Эталоны в tests/data/autotuner/ и tests/data/geneva/ записаны самим
AutoTuner (его tests/testdata) — копии один в один. Здесь проверяется:

* бандл AutoTuner проходит наш импорт бандла;
* наш экспорт бандлом из тех же файлов даёт тот же бандл (обратный путь),
  и он снова проходит наш импорт;
* tests/data/autotuner/zapret-gui-bundle.json — то, что пишет наш экспорт;
  его же читает AutoTuner (копия у него в testdata/export/from-zapret-gui);
* обмен стратегиями geneva: наш экспорт совпадает с эталоном, который
  AutoTuner держит как «записанный zapret-gui».
"""

import base64
import json
import os
import unittest

from core import bundle_export as be
from core import bundle_import as bi

DATA = os.path.join(os.path.dirname(__file__), "data")


def _load(*parts):
    with open(os.path.join(DATA, *parts), encoding="utf-8") as f:
        return json.load(f)


def _from_bundle(bundle):
    """Доступ к файлам «роутера», на котором лежит содержимое бандла."""
    hl = {h["name"]: h["domains"] for h in bundle.get("hostlists") or []}
    ips = {i["name"]: i["cidrs"] for i in bundle.get("ipsets") or []}
    bl = {b["name"]: base64.b64decode(b["base64"])
          for b in bundle.get("blobs") or []}
    lua = {l["name"][:-4]: l["text"] for l in bundle.get("lua") or []}
    return dict(hostlists=hl.get, ipsets=ips.get, blobs=bl.get, lua=lua.get)


def sample_strategy():
    return {
        "id": "my.yt-2026", "name": "Моя: YouTube", "is_builtin": False,
        "description": "с роутера", "version": 1, "type": "combined",
        "_filepath": "/opt/x.json",
        "profiles": [
            {"id": "p1", "name": "TLS", "enabled": True,
             "args": "--lua-init=@lua/my-twice.lua --filter-tcp=443 "
                     "--hostlist=lists/my-yt.txt --hostlist=lists/other.txt "
                     "--lua-desync=fake:blob=my_tls:tcp_md5 "
                     "--lua-desync=my_twice:count=2"},
            {"id": "p2", "name": "QUIC", "enabled": False,
             "args": "--filter-udp=443 --ipset=lists/ipset-yt.txt "
                     "--lua-desync=fake:blob=fake_default_quic:repeats=6"},
            {"id": "p3", "name": "GUI", "enabled": True,
             "args": "--filter-tcp=80 --lua-desync=fakemultisplit:pos=1:"
                     "blob=tls_google --lua-desync=multisplit:pos=2:"
                     "seqovl=5:seqovl_pattern=tls_rnd"},
        ]}


SAMPLE_FILES = dict(
    hostlists={"my-yt": ["youtube.com", "googlevideo.com"]}.get,
    ipsets={"ipset-yt": ["142.250.0.0/15"]}.get,
    blobs={"my_tls": b"\x16\x03\x01\x00\x05hello",
           "tls_google": b"\x16\x03\x01google"}.get,
    lua={"my-twice": "function my_twice(ctx, desync) end\n",
         "fakemultisplit": "function fakemultisplit(ctx, desync) end\n",
         "init_vars": "tls_rnd = fake_default_tls\n"}.get)


class TestAutoTunerBundleIn(unittest.TestCase):

    def test_autotuner_bundles_pass_our_import(self):
        for f in ("bundle.json", "bundle-lua.json"):
            errors, _ = bi.validate_bundle(_load("autotuner", f))
            self.assertEqual(errors, [], f)

    def test_same_bundle_back(self):
        for f in ("bundle.json", "bundle-lua.json"):
            src = _load("autotuner", f)
            out, warnings = be.build_bundle(src["strategy"],
                                            **_from_bundle(src))
            self.assertEqual(warnings, [], f)
            for key in ("format", "format_version", "zapret2_compat",
                        "strategy", "hostlists", "ipsets", "blobs", "lua"):
                self.assertEqual(out[key], src.get(key, []), (f, key))
            self.assertEqual(bi.validate_bundle(out)[0], [], f)


class TestOurBundleOut(unittest.TestCase):

    def test_references(self):
        refs = be.references(sample_strategy())
        self.assertEqual(refs["lists"], [("hostlist", "my-yt"),
                                         ("hostlist", "other"),
                                         ("ipset", "ipset-yt")])
        self.assertEqual(refs["blobs"], ["my_tls", "fake_default_quic",
                                         "tls_google"])
        self.assertEqual(refs["patterns"], ["tls_rnd"])
        # свой скрипт и те, что GUI подключает сам: fakemultisplit по
        # функции, init_vars по паттерну tls_rnd; zapret-lib/antidpi — нет
        self.assertEqual(refs["lua"], ["my-twice", "init_vars",
                                       "fakemultisplit"])

    def test_bundle_matches_golden_and_imports(self):
        out, warnings = be.build_bundle(sample_strategy(), version="test",
                                        **SAMPLE_FILES)
        self.assertEqual(warnings, ["hostlist other не входит в бандл "
                                    "(встроенный или его нет)"])
        self.assertEqual([b["name"] for b in out["blobs"]],
                         ["my_tls", "tls_google"])     # tls_rnd — init_vars
        self.assertEqual([x["name"] for x in out["lua"]],
                         ["my-twice.lua", "init_vars.lua",
                          "fakemultisplit.lua"])
        self.assertEqual(out["strategy"]["id"], "my_yt-2026")
        self.assertNotIn("_filepath", out["strategy"])
        self.assertEqual(bi.validate_bundle(out)[0], [])
        self.assertEqual(out, _load("autotuner", "zapret-gui-bundle.json"))


class TestGenevaShareGolden(unittest.TestCase):
    """Эталон AutoTuner «записан zapret-gui»: наш экспорт его повторяет."""

    def test_export_matches_autotuner_golden(self):
        from core import geneva_share as gsh
        for f in ("zapret-gui-export-v2.json", "zapret-gui-export.json"):
            doc = _load("geneva", f)
            rows, errors = gsh.parse_import(doc)
            self.assertEqual(errors, [], f)
            fit = {i["strategy"]: i.get("fitness") for i in doc["items"]}
            out = gsh.build_export([dict(r, fitness=fit.get(r["strategy"]))
                                    for r in rows])
            self.assertEqual(out["format"], doc["format"])
            if f.endswith("v2.json"):
                self.assertEqual(out["version"], doc["version"])
            self.assertEqual(out["items"], doc["items"], f)



class TestApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_export_bundle(self):
        from unittest import mock

        class SM:
            def get_strategy(self, sid):
                return sample_strategy() if sid == "my.yt-2026" else None
        with mock.patch("core.strategy_builder.get_strategy_manager",
                        return_value=SM()), \
                mock.patch.object(be, "export_strategy",
                                  lambda s: be.build_bundle(
                                      s, version="test", **SAMPLE_FILES)):
            r = self.client.get_json(
                "/api/strategies/my.yt-2026/export-bundle")
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["filename"], "my_yt-2026.bundle.json")
            self.assertEqual(r["bundle"]["blobs"][0]["name"], "my_tls")
            self.assertEqual(len(r["warnings"]), 1)
            r = self.client.get_json("/api/strategies/nope/export-bundle")
            self.assertEqual(r["_status"], 404)

    def test_export_strategy_reads_router_files(self):
        """Настоящие менеджеры на пустом роутере: ничего не падает,
        отсутствующее — в warnings."""
        out, warnings = be.export_strategy(sample_strategy())
        self.assertEqual(out["strategy"]["id"], "my_yt-2026")
        self.assertEqual(bi.validate_bundle(out)[0], [])
        self.assertTrue(any("my_tls" in w for w in warnings))

    def test_missing_lua_and_big_blob_are_warned(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-init=@lua/gone.lua "
                                 "--lua-desync=fake:blob=huge"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs={"huge": b"x" * (bi.MAX_BLOB + 1)}.get,
            lua=lambda n: None)
        self.assertEqual(out["blobs"], [])
        self.assertEqual(out["lua"], [])
        self.assertEqual(len(warnings), 2)

    def test_invalid_strategy_is_not_exported(self):
        from unittest import mock

        class SM:
            def get_strategy(self, sid):
                return {"id": "x", "name": "x", "profiles": []}
        with mock.patch("core.strategy_builder.get_strategy_manager",
                        return_value=SM()):
            r = self.client.get_json("/api/strategies/x/export-bundle")
        self.assertEqual(r["_status"], 400)


if __name__ == "__main__":
    unittest.main()
