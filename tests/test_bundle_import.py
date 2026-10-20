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
