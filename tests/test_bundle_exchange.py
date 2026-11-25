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
             "args": "--blob=my_hex:0x1603010000 --filter-tcp=80 "
                     "--lua-desync=fakemultisplit:pos=1:blob=fake_tls_1 "
                     "--lua-desync=multisplit:pos=2:seqovl=5:"
                     "seqovl_pattern=my_hex"},
        ]}


SAMPLE_FILES = dict(
    hostlists={"my-yt": ["youtube.com", "googlevideo.com"]}.get,
    ipsets={"ipset-yt": ["142.250.0.0/15"]}.get,
    blobs={"my_tls": b"\x16\x03\x01\x00\x05hello",
           "fake_tls_1": b"\x16\x03\x01google",
           "tls_google": b"\x16\x03\x01catalog"}.get,
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
                                         "my_hex", "fake_tls_1"])
        self.assertEqual(refs["patterns"], ["my_hex"])
        self.assertEqual(refs["declared"], {"my_hex": "0x1603010000"})
        # скрипты, что GUI подключает сам (fakemultisplit по функции), —
        # раньше своего, как при запуске; zapret-lib/antidpi — нет
        self.assertEqual(refs["lua"], ["fakemultisplit", "my-twice"])

    def test_bundle_matches_golden_and_imports(self):
        out, warnings = be.build_bundle(sample_strategy(), version="test",
                                        **SAMPLE_FILES)
        self.assertEqual(warnings, ["hostlist other не входит в бандл "
                                    "(встроенный или его нет)"])
        # fake_tls_1 — блоб каталога: едет байтами файла, на который его
        # ведёт реестр (AutoTuner без них стратегию не проверит)
        self.assertEqual([b["name"] for b in out["blobs"]],
                         ["fake_tls_1", "my_tls"])
        # объявленный в args блоб остаётся объявлением (hex), не дублем
        self.assertIn("--blob=my_hex:0x1603010000",
                      out["strategy"]["profiles"][2]["args"])
        self.assertEqual([x["name"] for x in out["lua"]],
                         ["fakemultisplit.lua", "my-twice.lua"])
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
            self.assertEqual(r["bundle"]["blobs"][1]["name"], "my_tls")
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

    def test_offset_declaration_reads_from_offset(self):
        import tempfile
        from unittest import mock
        from core import blob_registry as br
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * (bi.MAX_BLOB + 100) + b"\x07" * 10)
        self.addCleanup(os.unlink, f.name)
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--blob=b:+%d@bin/big.bin "
                                 "--lua-desync=fake:blob=b"
                                 % (bi.MAX_BLOB + 100)}]}
        with mock.patch.object(br, "_blob_file_path", lambda v: f.name), \
                mock.patch.object(be, "_export_roots",
                                  lambda: [os.path.dirname(f.name)]):
            out, _ = be.export_strategy(st)
        self.assertIn("--blob=b:0x" + "07" * 10,
                      out["strategy"]["profiles"][0]["args"])

    def test_declaration_outside_managed_roots_keeps_path_not_bytes(self):
        """Абсолютный ``@путь`` — например, оставшийся от импортированного
        чужого бандла — экспорт не вычитывает: декларация остаётся с
        путём, а байты файла в бандл не попадают."""
        import tempfile
        payload = b"\x16\x03\x01topsecret"
        with tempfile.TemporaryDirectory() as d:
            secret = os.path.join(d, "secret.bin")
            with open(secret, "wb") as f:
                f.write(payload)
            st = {"id": "x", "name": "x", "profiles": [
                {"id": "p1", "args": "--blob=leak:@%s "
                                     "--lua-desync=fake:blob=leak" % secret}]}
            out, warnings = be.export_strategy(st)
        args = out["strategy"]["profiles"][0]["args"]
        self.assertIn("--blob=leak:@", args)
        self.assertNotIn("0x" + payload.hex(), args)
        self.assertNotIn(base64.b64encode(payload).decode(),
                         json.dumps(out))
        self.assertTrue(any("вне управляемых" in w for w in warnings),
                        warnings)

    def test_init_vars_pattern_without_file_and_empty_name(self):
        st = {"id": "x", "name": "", "profiles": [
            {"id": "p1", "args": "--lua-desync=multisplit:pos=2:seqovl=5:"
                                 "seqovl_pattern=tls_rnd "
                                 "--lua-init=@/opt/etc/my.lua"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs=lambda n: None, lua={"init_vars": "x"}.get)
        self.assertEqual(out["strategy"]["name"], "x")
        self.assertEqual(out["blobs"], [])
        self.assertTrue(any("tls_rnd" in w and "init_vars" in w
                            for w in warnings), warnings)
        self.assertTrue(any("/opt/etc/my.lua" in w for w in warnings))
        self.assertEqual(bi.validate_bundle(out)[0], [])

    def test_init_vars_name_is_not_taken_from_catalog_file(self):
        """tls_google и паттерном, и блобом: по ссылке запуск подключает
        init_vars.lua, и тот присваивает имя заново (поверх --blob) —
        файл каталога в бандл не идёт, скрипт идёт."""
        for args in ("--lua-desync=multisplit:pos=2:seqovl=5:"
                     "seqovl_pattern=tls_google",
                     "--lua-desync=fake:blob=tls_google"):
            st = {"id": "x", "name": "x", "profiles": [
                {"id": "p1", "args": args}]}
            out, warnings = be.build_bundle(st, **SAMPLE_FILES)
            self.assertEqual(out["blobs"], [], args)
            self.assertEqual([x["name"] for x in out["lua"]],
                             ["init_vars.lua"])
            self.assertTrue(any("tls_google" in w and "init_vars" in w
                                for w in warnings), warnings)

    def test_init_vars_name_in_fallback_ships_registry_bytes(self):
        """fallback= init_vars.lua не подключает: tls_google там —
        файл реестра, и он едет в бандле."""
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-desync=tls_client_hello_clone:"
                                 "blob=ch:fallback=tls_google "
                                 "--lua-desync=fake:blob=ch"}]}
        out, warnings = be.build_bundle(st, **SAMPLE_FILES)
        self.assertEqual([b["name"] for b in out["blobs"]], ["tls_google"])
        self.assertEqual(out["lua"], [])
        self.assertEqual(warnings, [])

    def test_gui_registry_fake_default_goes_as_declaration(self):
        """fake_default_udp — имя реестра GUI, не nfqws2: едет
        объявлением в начале первого включённого профиля (до первого
        --new); встроенный fake_default_quic не берётся."""
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p0", "enabled": False,
             "args": "--lua-desync=fake:blob=fake_default_udp"},
            {"id": "tcp", "args": "--filter-tcp=443 "
                                  "--lua-desync=multisplit:pos=1"},
            {"id": "p1", "args": "--filter-udp=443 "
                                 "--lua-desync=fake:blob=fake_default_udp:"
                                 "repeats=6 --lua-desync=fake:"
                                 "blob=fake_default_quic"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs={"fake_default_udp": b"\x00" * 16}.get,
            lua=lambda n: None)
        self.assertEqual(warnings, [])
        self.assertEqual(out["blobs"], [])
        self.assertEqual(out["strategy"]["profiles"][0]["args"],
                         st["profiles"][0]["args"])
        self.assertTrue(out["strategy"]["profiles"][1]["args"].startswith(
            "--blob=fake_default_udp:0x" + "00" * 16 + " --filter-tcp=443"))
        self.assertNotIn("--blob=", out["strategy"]["profiles"][2]["args"])
        self.assertEqual(bi.validate_bundle(out)[0], [])

    def test_fallback_init_vars_name_when_script_is_loaded(self):
        """Другой профиль подключает init_vars.lua — и тот задаёт
        tls_google и в fallback=: байтов в бандле нет."""
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-desync=tls_client_hello_clone:"
                                 "blob=ch:fallback=tls_google"},
            {"id": "p2", "args": "--lua-desync=fake:blob=tls_vk"}]}
        out, warnings = be.build_bundle(st, **SAMPLE_FILES)
        self.assertEqual(out["blobs"], [])
        self.assertTrue(any(w.startswith("tls_google") for w in warnings))

    def test_declaration_only_in_disabled_profile(self):
        """Объявление в выключенном профиле: запуск берёт имя из реестра
        — его байты нужны и бандлу (импорт AutoTuner выключенные
        профили отбрасывает)."""
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "enabled": False,
             "args": "--blob=quic_google:@bin/q.bin --filter-tcp=443 "
                     "--lua-desync=fake:blob=quic_google"},
            {"id": "p2", "args": "--filter-udp=443 "
                                 "--lua-desync=fake:blob=quic_google"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs={"quic_google": b"\x0c\x0d"}.get, lua=lambda n: None,
            blob_file={"@bin/q.bin": b"\x0a\x0b"}.get)
        self.assertEqual(warnings, [])
        self.assertEqual(out["blobs"], [{"name": "quic_google",
                                         "base64": "DA0="}])
        self.assertIn("--blob=quic_google:0x0a0b",
                      out["strategy"]["profiles"][0]["args"])
        self.assertEqual(bi.validate_bundle(out)[0], [])

    def test_lua_of_disabled_profiles_stays_out(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--filter-tcp=443 "
                                 "--lua-desync=fake:blob=fake_default_tls"},
            {"id": "p2", "enabled": False,
             "args": "--lua-init=@lua/mine.lua --filter-tcp=80 "
                     "--lua-desync=fakemultisplit:pos=1"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs=lambda n: None, lua=lambda n: "x")
        self.assertEqual(out["lua"], [])
        self.assertTrue(any("mine.lua" in w for w in warnings), warnings)

    def test_each_declaration_keeps_its_own_bytes(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "old", "enabled": False,
             "args": "--blob=myfake:@bin/old.bin --lua-desync=fake:blob=myfake"},
            {"id": "new", "args": "--blob=myfake:@bin/new.bin "
                                  "--lua-desync=fake:blob=myfake"}]}
        out, _ = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs=lambda n: None, lua=lambda n: None,
            blob_file={"@bin/old.bin": b"OLD", "@bin/new.bin": b"NEW"}.get)
        args = [p["args"] for p in out["strategy"]["profiles"]]
        self.assertIn("--blob=myfake:0x" + b"OLD".hex(), args[0])
        self.assertIn("--blob=myfake:0x" + b"NEW".hex(), args[1])

    def test_registry_declaration_does_not_load_init_vars(self):
        from core.nfqws_manager import _NAMED_PATTERN_RE
        self.assertEqual(_NAMED_PATTERN_RE.findall(
            "--blob=tls_google:@bin/x.bin --lua-desync=tls_client_hello_clone:"
            "blob=ch:fallback=tls_google --lua-desync=fake:fake_blob=tls_vk"),
            ["ch", "tls_vk"])

    def test_crlf_script_is_same(self):
        from unittest import mock

        class LM:
            def get_script(self, n):
                return "a\nb\n"
        b = {"lua": [{"name": "x.lua", "text": "a\r\nb\r\n"}]}
        with mock.patch("core.lua_manager.get_lua_manager",
                        return_value=LM()):
            same = bi._same_here(b, {"hostlists": set(), "ipsets": set(),
                                     "lua": {"x"}})
        self.assertEqual(same, {("lua", "x")})

    def test_clone_variable_and_fallback(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-desync=tls_client_hello_clone:"
                                 "blob=cl:fallback=my_tls "
                                 "--lua-desync=fake:blob=cl "
                                 "--lua-desync=multisplit_tls:fallback=pass"},
            # другой профиль: cl здесь — настоящий блоб
            {"id": "p2", "args": "--lua-desync=fake:blob=cl"}]}
        refs = be.references(st)
        self.assertEqual(refs["blobs"], ["my_tls", "cl"])

    def test_lists_only_from_lists_dir_and_quoted_declaration(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--hostlist=/opt/etc/my.txt "
                                 "--hostlist=/opt/etc/lists/yt.txt "
                                 "--hostlist=/opt/zapret2/lists/yt.txt "
                                 "--lua-init=@/opt/zapret2/lua/my.lua "
                                 '--blob=q:@"/opt/my blobs/q.bin" '
                                 "--blob=o:+2@bin/o.bin "
                                 "--lua-desync=fake:blob=q:blob=o"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: ["a"], ipsets=lambda n: None,
            blobs=lambda n: None, lua=lambda n: "x",
            blob_file={'@"/opt/my blobs/q.bin"': b"\x01",
                       "+2@bin/o.bin": b"\x02"}.get,
            roots={"lists": ["/opt/zapret2/lists/"],
                   "lua": ["/opt/zapret2/lua"]})
        self.assertEqual(out["hostlists"], [{"name": "yt",
                                             "domains": ["a"]}])
        # не каталог менеджера — не берётся, даже если путь .../lists/
        self.assertTrue(any("/opt/etc/my.txt" in w for w in warnings))
        self.assertTrue(any("/opt/etc/lists/yt.txt" in w for w in warnings))
        # пути роутера — в переносимые, объявления — hex (+N — со смещения)
        self.assertEqual(out["strategy"]["profiles"][0]["args"],
                         "--hostlist=/opt/etc/my.txt "
                         "--hostlist=/opt/etc/lists/yt.txt "
                         "--hostlist=lists/yt.txt --lua-init=@lua/my.lua "
                         "--blob=q:0x01 --blob=o:0x02 "
                         "--lua-desync=fake:blob=q:blob=o")

    def test_builtin_trick_gets_launch_filter(self):
        st = {"id": "x", "name": "x", "is_builtin": True, "protocol": "tcp",
              "family": "", "profiles": [
                  {"id": "p1", "args": "--payload=tls_client_hello "
                                       "--lua-desync=fake:blob=my_tls"},
                  {"id": "p2", "args": "--filter-tcp=80 "
                                       "--lua-desync=fake"}]}
        got = be._as_launched(st)["profiles"]
        self.assertTrue(got[0]["args"].startswith("--filter-tcp=443 "),
                        got[0]["args"])
        self.assertTrue(got[0]["args"].endswith(st["profiles"][0]["args"]))
        self.assertEqual(got[1]["args"], st["profiles"][1]["args"])
        # своя стратегия: фильтр по однозначному --payload — тоже
        user = dict(st, is_builtin=False)
        self.assertTrue(be._as_launched(user)["profiles"][0]["args"]
                        .startswith("--filter-tcp=443 "))
        bare = {"id": "y", "profiles": [{"id": "p", "args": "--lua-desync=fake"}]}
        self.assertIs(be._as_launched(bare), bare)

    def test_blob_over_autotuner_limit_is_warned_not_dropped(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-desync=fake:blob=mid"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs={"mid": b"x" * 20000}.get, lua=lambda n: None)
        self.assertEqual([b["name"] for b in out["blobs"]], ["mid"])
        self.assertTrue(any("AutoTuner" in w for w in warnings))

    def test_identical_files_are_not_written_on_import(self):
        out, _ = be.build_bundle(sample_strategy(), version="test",
                                 **SAMPLE_FILES)
        existing = {"hostlists": set(), "ipsets": set(), "blobs": set(),
                    "lua": {"my-twice", "fakemultisplit"},
                    "strategies": set(), "builtin_strategies": set(),
                    "same": {("lua", "fakemultisplit"),
                             ("blob", "fake_tls_1")}}
        plan = bi.plan_bundle(out, existing)
        # отличающийся свой my-twice — конфликт, решает человек
        self.assertEqual(plan["conflicts"],
                         [{"kind": "lua", "name": "my-twice"}])
        self.assertEqual(sorted(x["name"] for x in plan["skipped"]),
                         ["fake_tls_1", "fakemultisplit"])

    def test_same_here_compares_content(self):
        from unittest import mock
        out, _ = be.build_bundle(sample_strategy(), version="test",
                                 **SAMPLE_FILES)

        class LM:
            def get_script(self, n):
                return {"my-twice": "function my_twice(ctx, desync) end\n",
                        "fakemultisplit": "-- другой\n"}.get(n, "")

        class HM:
            def get_hostlist(self, n):
                return ["youtube.com", "googlevideo.com"]
        names = {"hostlists": {"my-yt"}, "ipsets": set(),
                 "lua": {"my-twice", "fakemultisplit"}}
        with mock.patch("core.lua_manager.get_lua_manager",
                        return_value=LM()), \
                mock.patch("core.hostlist_manager.get_hostlist_manager",
                           return_value=HM()), \
                mock.patch.object(bi, "_blob_here",
                                  lambda n: b"\x16\x03\x01google"
                                  if n == "fake_tls_1" else None):
            same = bi._same_here(out, names)
        self.assertEqual(same, {("lua", "my-twice"), ("hostlist", "my-yt"),
                                ("blob", "fake_tls_1")})

    def test_gui_blob_args_declared_path_enabled_and_inline_lua(self):
        st = {"id": "x", "name": "x", "profiles": [
            {"id": "p1", "args": "--lua-init=fake_default_tls=1 "
                                 "--blob=over:@bin/over.bin "
                                 "--lua-desync=fakemultidisorder:pos=1:"
                                 "fake_blob=my_fake:x=over "
                                 "--lua-desync=fake:blob=tls_rnd"},
            {"id": "p2", "enabled": None, "args": "--lua-desync=fake"}]}
        out, warnings = be.build_bundle(
            st, hostlists=lambda n: None, ipsets=lambda n: None,
            blobs={"my_fake": b"\x01\x02"}.get, lua=lambda n: "x",
            blob_file={"@bin/over.bin": b"\xab\xcd"}.get)
        self.assertEqual([b["name"] for b in out["blobs"]], ["my_fake"])
        self.assertIn("--blob=over:0xabcd",
                      out["strategy"]["profiles"][0]["args"])
        self.assertIs(out["strategy"]["profiles"][1]["enabled"], False)
        # инлайн-lua — не файл; blob=tls_rnd — init_vars, а не «нет блоба»
        self.assertFalse(any("lua-init" in w for w in warnings), warnings)
        self.assertTrue(any("tls_rnd" in w and "init_vars" in w
                            for w in warnings), warnings)

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
