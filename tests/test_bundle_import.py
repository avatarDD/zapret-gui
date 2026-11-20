# tests/test_bundle_import.py
"""Импорт бандла Zapret2_AutoTuner (core/bundle_import): проверка,
план, переименование со ссылками, запись через менеджеры."""

import base64
import unittest
from unittest import mock

from core import bundle_import as bi


def bundle(**over):
    b = {
        "format": bi.FORMAT, "format_version": 1, "zapret2_compat": 6,
        "strategy": {"id": "zt_youtube_2026_10_18", "name": "AutoTuner",
                     "profiles": [{
                         "id": "p1", "name": "youtube",
                         "args": "--filter-tcp=443 "
                                 "--hostlist=lists/zt-youtube.txt "
                                 "--ipset=lists/zt-yt-ipset.txt "
                                 "--lua-init=@lua/my.lua "
                                 "--lua-desync=fake:blob=tls1:repeats=2 "
                                 "--lua-desync=multisplit:"
                                 "seqovl_pattern=tls1:pos=1"}]},
        "hostlists": [{"name": "zt-youtube", "domains": ["youtube.com"]}],
        "ipsets": [{"name": "zt-yt-ipset", "cidrs": ["1.2.3.0/24"]}],
        "blobs": [{"name": "tls1",
                   "base64": base64.b64encode(b"\x16\x03\x01").decode()}],
        "lua": [{"name": "my.lua", "text": "-- x"}],
    }
    b.update(over)
    return b


NOTHING = {"hostlists": set(), "ipsets": set(), "blobs": set(), "lua": set(),
           "strategies": set(), "builtin_strategies": set()}


class TestValidate(unittest.TestCase):

    def test_ok(self):
        self.assertEqual(bi.validate_bundle(bundle()), ([], []))

    def test_not_a_bundle(self):
        self.assertTrue(bi.validate_bundle({"format": "x"})[0])
        self.assertTrue(bi.validate_bundle([])[0])

    def test_newer_version(self):
        errs, _ = bi.validate_bundle(bundle(format_version=2))
        self.assertTrue(any("новее" in e for e in errs))

    def test_compat_warns(self):
        errs, warns = bi.validate_bundle(bundle(zapret2_compat=5))
        self.assertEqual(errs, [])
        self.assertTrue(warns)

    def test_bad_names_and_sizes(self):
        b = bundle(
            hostlists=[{"name": "other", "domains": []}],
            ipsets=[{"name": "noprefix", "cidrs": []}],
            blobs=[{"name": "fake_default_tls", "base64": "AA=="},
                   {"name": "big", "base64": base64.b64encode(
                       b"x" * (bi.MAX_BLOB + 1)).decode()},
                   {"name": "bad-name", "base64": "AA=="},
                   {"name": "nob64", "base64": "!!"}],
            lua=[{"name": "..", "text": ""}])
        errs, _ = bi.validate_bundle(b)
        self.assertEqual(len(errs), 7, errs)

    def test_profile_rules(self):
        for args in ("--lua-desync=fake --new --lua-desync=fake",
                     "--dpi-desync=fake"):
            b = bundle()
            b["strategy"]["profiles"][0]["args"] = args
            self.assertTrue(bi.validate_bundle(b)[0], args)

    def test_pins_warn(self):
        _, warns = bi.validate_bundle(bundle(hosts_pins=[{"host": "a"}]))
        self.assertTrue(any("hosts_pins" in w for w in warns))


class TestPlanAndRename(unittest.TestCase):

    def test_plan_conflicts(self):
        existing = dict(NOTHING, blobs={"tls1"}, lua={"my"})
        plan = bi.plan_bundle(bundle(), existing)
        self.assertEqual(len(plan["items"]), 5)
        self.assertEqual({(c["kind"], c["name"]) for c in plan["conflicts"]},
                         {("blob", "tls1"), ("lua", "my")})
        self.assertFalse(plan["builtin_strategy"])

    def test_rename_rewrites_every_reference(self):
        existing = dict(NOTHING, hostlists={"zt-youtube"},
                        ipsets={"zt-yt-ipset"}, blobs={"tls1"}, lua={"my"})
        plan = bi.plan_bundle(bundle(), existing)
        renames = bi.rename_map(plan, existing)
        self.assertEqual(renames["blob"], {"tls1": "tls1_2"})
        self.assertEqual(renames["ipset"], {"zt-yt-ipset": "zt-yt-ipset-2"})
        from core.ipset_manager import IPSET_NAMESPACE_RE
        self.assertTrue(IPSET_NAMESPACE_RE.match("zt-yt-ipset-2"))
        args = bi.rewrite_args(
            bundle()["strategy"]["profiles"][0]["args"], renames)
        self.assertIn("--hostlist=lists/zt-youtube-2.txt", args)
        self.assertIn("--ipset=lists/zt-yt-ipset-2.txt", args)
        self.assertIn("--lua-init=@lua/my-2.lua", args)
        self.assertIn("fake:blob=tls1_2:repeats=2", args)
        self.assertIn("seqovl_pattern=tls1_2:pos=1", args)

    def test_gui_scripts_kept_catalog_blobs_only_under_new_names(self):
        b = bundle(blobs=bundle()["blobs"] + [
            {"name": "tls_google",
             "base64": base64.b64encode(b"other").decode()}])
        existing = dict(NOTHING, lua={"my"}, gui_lua={"my"},
                        catalog_blobs={"tls_google", "tls_google_2"})
        plan = bi.plan_bundle(b, existing)
        # скрипт GUI не пишется вовсе: остаётся здешний, с предупреждением
        self.assertEqual(plan["kept"], [{"kind": "lua", "name": "my"}])
        self.assertTrue(any("my.lua" in w for w in plan["warnings"]))
        # блоб каталога — только «переименовать»
        self.assertEqual([(c["kind"], c["name"]) for c in plan["conflicts"]
                          if c.get("rename_only")], [("blob", "tls_google")])
        self.assertTrue(plan["rename_only"])
        renames = bi.rename_map(plan, existing)
        # новое имя — не снова имя каталога
        self.assertEqual(renames["blob"], {"tls_google": "tls_google_3"})

    def test_init_vars_names_when_script_is_loaded(self):
        b = bundle()
        b["strategy"]["profiles"][0]["args"] = (
            "--lua-desync=tls_client_hello_clone:blob=ch:fallback=tls_rnd")
        self.assertEqual(bi._init_vars_refs(b), set())
        # seqovl_pattern=tls_google подключит init_vars.lua — и тот задаст
        # и tls_rnd из fallback=
        b["strategy"]["profiles"].append({
            "id": "p2", "args": "--lua-desync=multisplit:seqovl=5:"
                                "seqovl_pattern=tls_google"})
        self.assertEqual(bi._init_vars_refs(b), {"tls_google", "tls_rnd"})

    def test_quoted_and_absolute_refs_are_renamed(self):
        args = bi.rewrite_args(
            '--lua-desync="fake:blob=b1:repeats=2" --lua-desync=fake:blob=b1 '
            "--lua-init=@/opt/zapret2/lua/my.lua "
            "--hostlist=/opt/zapret2/lists/zt-youtube.txt",
            {"blob": {"b1": "b1_2"}, "lua": {"my": "my-2"},
             "hostlist": {"zt-youtube": "zt-youtube-2"}})
        self.assertEqual(
            args, '--lua-desync="fake:blob=b1_2:repeats=2" '
                  "--lua-desync=fake:blob=b1_2 "
                  "--lua-init=@/opt/zapret2/lua/my-2.lua "
                  "--hostlist=/opt/zapret2/lists/zt-youtube-2.txt")

    def test_rename_keeps_clone_variable(self):
        args = bi.rewrite_args(
            "--lua-desync=tls_client_hello_clone:blob=ch:fallback=fb "
            "--lua-desync=fake:blob=ch", {"blob": {"ch": "ch_2", "fb": "fb_2"}})
        self.assertEqual(args, "--lua-desync=tls_client_hello_clone:blob=ch:"
                               "fallback=fb_2 --lua-desync=fake:blob=ch")
        # в другом профиле ch — настоящий блоб
        self.assertEqual(bi.rewrite_args("--lua-desync=fake:blob=ch",
                                         {"blob": {"ch": "ch_2"}}),
                         "--lua-desync=fake:blob=ch_2")

    def test_init_vars_name_in_fallback_is_a_plain_blob(self):
        b = bundle()
        b["strategy"]["profiles"][0]["args"] = (
            "--lua-desync=tls_client_hello_clone:blob=ch:fallback=tls_google "
            "--lua-desync=ippxor:dataxor=tls_vk")
        self.assertEqual(bi._init_vars_refs(b), set())

    def test_gui_registry_fake_default_is_a_valid_blob(self):
        b = bundle(blobs=[{"name": "fake_default_udp",
                           "base64": base64.b64encode(bytes(16)).decode()}])
        self.assertEqual(bi.validate_bundle(b)[0], [])
        b = bundle(blobs=[{"name": "fake_default_tls", "base64": "AQ=="}])
        self.assertTrue(bi.validate_bundle(b)[0])

    def test_fake_default_blob_renamed_out_of_builtin_prefix(self):
        b = bundle(blobs=[{"name": "fake_default_udp",
                           "base64": base64.b64encode(b"\x01" * 16).decode()}])
        plan = bi.plan_bundle(b, NOTHING)
        self.assertEqual(plan["conflicts"], [
            {"kind": "blob", "name": "fake_default_udp", "rename_only": True}])
        self.assertEqual(bi.rename_map(plan, NOTHING, b)["blob"],
                         {"fake_default_udp": "my_fake_default_udp_2"})

    def test_init_vars_in_disabled_profile_is_not_loaded(self):
        b = bundle()
        b["strategy"]["profiles"][0].update(
            enabled=False, args="--lua-desync=fake:blob=tls_google")
        self.assertEqual(bi._init_vars_refs(b), set())

    def test_new_name_is_free_in_bundle_and_fits(self):
        b = bundle(blobs=[{"name": n, "base64": "AQ=="}
                          for n in ("a", "a_2", "b" * 64)])
        existing = dict(NOTHING, blobs={"a", "b" * 64})
        plan = bi.plan_bundle(b, existing)
        renames = bi.rename_map(plan, existing, b)
        self.assertEqual(renames["blob"]["a"], "a_3")
        long = renames["blob"]["b" * 64]
        self.assertEqual((len(long), long[-2:]), (64, "_2"))

    def test_fallback_is_a_blob_only_for_clone(self):
        renames = {"blob": {"pass": "pass_2", "fb": "fb_2", "cl": "cl_2"}}
        # blob= у клона — имя переменной desync, а не блоба
        args = bi.rewrite_args(
            "--lua-desync=multisplit_tls:fallback=pass "
            "--lua-desync=tls_client_hello_clone:blob=cl:fallback=fb "
            "--lua-desync=fake:blob=cl", renames)
        self.assertIn("multisplit_tls:fallback=pass ", args)
        self.assertIn("tls_client_hello_clone:blob=cl:fallback=fb_2", args)
        self.assertEqual(
            bi.desync_blob_refs("tls_client_hello_clone:blob=cl:fallback=fb"),
            ([("fallback", "fb")], ["cl"]))
        self.assertEqual(bi.desync_blob_refs("multisplit_tls:fallback=pass"),
                         ([], []))

    def test_rename_leaves_other_names(self):
        args = bi.rewrite_args("--lua-desync=fake:blob=tls10 --blob=tls1:@bin/a",
                               {"blob": {"tls1": "tls1_2"}})
        self.assertIn("blob=tls10", args)
        self.assertIn("--blob=tls1_2:@bin/a", args)


class _Mgr:
    def __init__(self):
        self.saved = {}

    def save_hostlist(self, name, items):
        self.saved[name] = items
        return True

    save_ipset = save_hostlist

    def list_names(self):
        return []

    def create_ipset(self, name):
        return True, ""

    def save_blob(self, name, data):
        self.saved[name] = data
        return True, None

    def save_script(self, name, text):
        self.saved[name] = text
        return True, None

    def save_user_strategy(self, data):
        self.saved[data["id"]] = data
        return data


class TestApply(unittest.TestCase):

    def setUp(self):
        self.m = _Mgr()
        self.patches = [mock.patch(p, return_value=self.m) for p in (
            "core.hostlist_manager.get_hostlist_manager",
            "core.ipset_manager.get_ipset_manager",
            "core.blob_manager.get_blob_manager",
            "core.lua_manager.get_lua_manager",
            "core.strategy_builder.get_strategy_manager")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_saves_everything(self):
        r = bi.apply_bundle(bundle(), existing=NOTHING)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.m.saved["tls1"], b"\x16\x03\x01")
        self.assertEqual(self.m.saved["my"], "-- x")
        self.assertIn("zt_youtube_2026_10_18", self.m.saved)
        self.assertEqual(len(r["saved"]), 5)

    def test_conflict_writes_nothing(self):
        r = bi.apply_bundle(bundle(), existing=dict(NOTHING, blobs={"tls1"}))
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_code"], "conflict")
        self.assertEqual(self.m.saved, {})

    def test_builtin_strategy_needs_rename(self):
        sid = "zt_youtube_2026_10_18"
        existing = dict(NOTHING, strategies={sid}, builtin_strategies={sid})
        self.assertEqual(bi.apply_bundle(bundle(), on_conflict="replace",
                                         existing=existing)["error_code"],
                         "conflict")
        r = bi.apply_bundle(bundle(), on_conflict="rename", existing=existing)
        self.assertTrue(r["ok"])
        self.assertEqual(r["strategy_id"], sid + "_2")

    def test_rename_saves_rewritten_args(self):
        existing = dict(NOTHING, blobs={"tls1"})
        r = bi.apply_bundle(bundle(), on_conflict="rename", existing=existing)
        self.assertIn("tls1_2", self.m.saved)
        args = self.m.saved["zt_youtube_2026_10_18"]["profiles"][0]["args"]
        self.assertIn("blob=tls1_2", args)
        self.assertEqual(r["renamed"], {"blob": {"tls1": "tls1_2"}})

    def test_same_and_gui_script_are_not_written(self):
        existing = dict(NOTHING, hostlists={"zt-youtube"}, blobs={"tls1"},
                        ipsets={"zt-yt-ipset"}, lua={"my"}, gui_lua={"my"},
                        same={("hostlist", "zt-youtube"),
                              ("ipset", "zt-yt-ipset")})
        r = bi.apply_bundle(bundle(), on_conflict="replace",
                            existing=existing)
        self.assertTrue(r["ok"], r)
        self.assertEqual(set(self.m.saved), {"tls1", "zt_youtube_2026_10_18"})
        self.assertEqual(sorted(r["skipped"]),
                         ["hostlist zt-youtube", "ipset zt-yt-ipset"])
        self.assertEqual(r["kept"], ["lua my"])
        self.assertTrue(any("my.lua" in w for w in r["warnings"]))
        # ссылка в args осталась на здешний скрипт
        self.assertIn("--lua-init=@lua/my.lua", self.m.saved[
            "zt_youtube_2026_10_18"]["profiles"][0]["args"])

    def test_init_vars_pattern_blob_is_never_same(self):
        b = bundle(blobs=[{"name": "tls_google",
                           "base64": base64.b64encode(b"cat").decode()}])
        b["strategy"]["profiles"][0]["args"] = (
            "--lua-desync=multisplit:seqovl=5:seqovl_pattern=tls_google "
            "--lua-desync=fake:blob=tls_youtube")
        self.assertEqual(bi._init_vars_refs(b), {"tls_google", "tls_youtube"})
        with mock.patch.object(bi, "_blob_here", lambda n: b"cat"):
            same = bi._same_here(b, {"hostlists": set(), "ipsets": set(),
                                     "lua": set()})
        self.assertNotIn(("blob", "tls_google"), same)

    def test_invalid(self):
        r = bi.apply_bundle({"format": bi.FORMAT}, existing=NOTHING)
        self.assertEqual(r["error_code"], "invalid")


class TestApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def post(self, body):
        return self.client.post_json("/api/strategies/import-bundle", body)

    def test_invalid_is_400(self):
        r = self.post({"bundle": {"format": "x"}})
        self.assertEqual(r["_status"], 400)

    def test_dry_run_by_default_writes_nothing(self):
        with mock.patch("core.bundle_import.existing_names",
                        return_value=dict(NOTHING, blobs={"tls1"})), \
             mock.patch("core.bundle_import.apply_bundle") as apply:
            r = self.post({"bundle": bundle()})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["plan"]["conflicts"],
                         [{"kind": "blob", "name": "tls1"}])
        apply.assert_not_called()

    def test_conflict_is_409(self):
        with mock.patch("core.bundle_import.apply_bundle",
                        return_value={"ok": False,
                                      "error_code": "conflict"}) as apply:
            r = self.post({"bundle": bundle(), "dry_run": False})
        self.assertEqual(r["_status"], 409)
        apply.assert_called_once()

    def test_bad_on_conflict(self):
        r = self.post({"bundle": bundle(), "dry_run": False,
                       "on_conflict": "merge"})
        self.assertEqual(r["_status"], 400)
