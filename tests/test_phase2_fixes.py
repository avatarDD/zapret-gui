# tests/test_phase2_fixes.py
"""Тесты MEDIUM-фиксов Фазы 2 (парсинг, бэкенды, ресурсы)."""

import os
import shutil
import tempfile
import unittest
from unittest import mock


# ════════════════════════════════════════════════════════════
# #22 — clash YAML: # внутри кавычек не режется
# ════════════════════════════════════════════════════════════

class TestStripYamlComment(unittest.TestCase):

    def test_comment_after_space_stripped(self):
        from core.clash_yaml import _strip_yaml_comment
        self.assertEqual(_strip_yaml_comment("key: ab # note").rstrip(),
                         "key: ab")

    def test_hash_in_quotes_kept(self):
        from core.clash_yaml import _strip_yaml_comment
        self.assertEqual(_strip_yaml_comment('password: "ab #cd"'),
                         'password: "ab #cd"')
        self.assertEqual(_strip_yaml_comment("password: 'p #1'"),
                         "password: 'p #1'")

    def test_hash_without_space_not_comment(self):
        from core.clash_yaml import _strip_yaml_comment
        self.assertEqual(_strip_yaml_comment("key: ab#cd"), "key: ab#cd")

    def test_full_line_comment(self):
        from core.clash_yaml import _strip_yaml_comment
        self.assertEqual(_strip_yaml_comment("# whole line").strip(), "")


# ════════════════════════════════════════════════════════════
# #23 — reality short-id: ведущий ноль восстанавливается
# ════════════════════════════════════════════════════════════

class TestRealityShortId(unittest.TestCase):

    def _short_id(self, sid):
        from core import clash_yaml
        ob = clash_yaml._conv_vless({
            "name": "s", "server": "h", "port": 443, "uuid": "u",
            "tls": True, "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "pk", "short-id": sid},
        })
        return ob["tls"]["reality"]["short_id"]

    def test_int_leading_zero_recovered(self):
        self.assertEqual(self._short_id(1), "01")
        self.assertEqual(self._short_id(8), "08")

    def test_int_even_length_kept(self):
        self.assertEqual(self._short_id(10), "10")

    def test_string_passthrough(self):
        self.assertEqual(self._short_id("1a2b"), "1a2b")


# ════════════════════════════════════════════════════════════
# #24 — hysteria2 insecure: нормализация регистра
# ════════════════════════════════════════════════════════════

class TestHysteria2Insecure(unittest.TestCase):

    def test_case_insensitive_insecure(self):
        from core.singbox_subscription import hysteria2_to_outbound
        up = hysteria2_to_outbound("hysteria2://pw@h.example:443?insecure=TRUE#t")
        lo = hysteria2_to_outbound("hysteria2://pw@h.example:443?insecure=true#t")
        no = hysteria2_to_outbound("hysteria2://pw@h.example:443#t")
        self.assertTrue(up["ok"] and lo["ok"] and no["ok"])
        # TRUE должно трактоваться как true.
        self.assertEqual(up["outbound"], lo["outbound"])
        # И отличаться от варианта без insecure (флаг реально применён).
        self.assertNotEqual(up["outbound"], no["outbound"])


# ════════════════════════════════════════════════════════════
# #26 — dscp backend: nft-compat shim → нативный nft
# ════════════════════════════════════════════════════════════

class TestDscpBackend(unittest.TestCase):

    def _patch_run(self, ipt_out, nft_ok=True):
        from core.routing import dscp_rule

        def fake_run(args, timeout=10):
            if args[:2] == ["iptables", "-V"]:
                return (0, ipt_out, "")
            if args[:1] == ["nft"]:
                return (0, "nftables v1.0", "") if nft_ok else (1, "", "no")
            return (1, "", "")
        return mock.patch.object(dscp_rule, "_run", side_effect=fake_run)

    def test_nft_compat_prefers_nft(self):
        from core.routing import dscp_rule
        with self._patch_run("iptables v1.8.7 (nf_tables)"):
            self.assertEqual(dscp_rule._backend(), "nftables")

    def test_legacy_iptables(self):
        from core.routing import dscp_rule
        with self._patch_run("iptables v1.8.7 (legacy)"):
            self.assertEqual(dscp_rule._backend(), "iptables")

    def test_nft_compat_without_nft_falls_back(self):
        from core.routing import dscp_rule
        with self._patch_run("iptables v1.8.7 (nf_tables)", nft_ok=False):
            self.assertEqual(dscp_rule._backend(), "iptables")


# ════════════════════════════════════════════════════════════
# #27 — dnsmasq ipset-директива содержит и v4, и v6 set
# ════════════════════════════════════════════════════════════

class TestDnsmasqIpsetV6(unittest.TestCase):

    def test_ipset_directive_has_both_sets(self):
        from core.routing import dnsmasq_integration as di
        mgr = di.DnsmasqIntegration()
        tmp = tempfile.mkdtemp()
        try:
            managed = os.path.join(tmp, "managed.conf")
            with mock.patch.object(mgr, "managed_file_path",
                                   return_value=managed):
                res = mgr.write_managed_file([{
                    "rule_id": "r1", "set_kind": "ipset",
                    "set_name": "awg_r1", "domains": ["example.com"],
                }])
            self.assertTrue(res.get("ok"), res)
            text = open(managed, encoding="utf-8").read()
            self.assertIn("ipset=/example.com/awg_r1,awg_r16", text)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ════════════════════════════════════════════════════════════
# #29 — find_confdir выбирает существующую/записываемую директорию
# ════════════════════════════════════════════════════════════

class TestFindConfdir(unittest.TestCase):

    def test_returns_existing_candidate(self):
        from core.routing import dnsmasq_integration as di
        mgr = di.DnsmasqIntegration()
        mgr.CONFDIR_CANDIDATES = ("/nonexistent/zzz/dnsmasq.d", "/tmp")
        self.assertEqual(mgr.find_confdir(""), "/tmp")

    def test_falls_back_to_writable_parent(self):
        from core.routing import dnsmasq_integration as di
        mgr = di.DnsmasqIntegration()
        mgr.CONFDIR_CANDIDATES = ("/nonexistent/a/dnsmasq.d",
                                  "/tmp/zg-newconfdir")
        self.assertEqual(mgr.find_confdir(""), "/tmp/zg-newconfdir")


# ════════════════════════════════════════════════════════════
# #30 — blob save/delete не трогают системную директорию
# ════════════════════════════════════════════════════════════

class TestBlobSystemProtection(unittest.TestCase):

    def setUp(self):
        from core.blob_manager import BlobManager
        self.tmp = tempfile.mkdtemp()
        self.mgr = BlobManager()
        self.mgr.blobs_dir = os.path.join(self.tmp, "blobs")
        self.mgr.system_blobs_dir = os.path.join(self.tmp, "files", "fake")
        os.makedirs(self.mgr.blobs_dir, exist_ok=True)
        os.makedirs(self.mgr.system_blobs_dir, exist_ok=True)
        self.sys_file = os.path.join(self.mgr.system_blobs_dir, "tls_sys.bin")
        with open(self.sys_file, "wb") as f:
            f.write(b"SYSTEM")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_does_not_overwrite_system(self):
        ok, err = self.mgr.save_blob("tls_sys.bin", b"USERDATA")
        self.assertTrue(ok, err)
        # Системный файл не тронут, юзерский — в blobs/.
        with open(self.sys_file, "rb") as f:
            self.assertEqual(f.read(), b"SYSTEM")
        self.assertTrue(os.path.isfile(
            os.path.join(self.mgr.blobs_dir, "tls_sys.bin")))

    def test_delete_refuses_system_blob(self):
        ok, err = self.mgr.delete_blob("tls_sys.bin")
        self.assertFalse(ok)
        self.assertIn("систем", (err or "").lower())
        self.assertTrue(os.path.isfile(self.sys_file))

    def test_delete_user_blob_ok(self):
        with open(os.path.join(self.mgr.blobs_dir, "userblob.bin"), "wb") as f:
            f.write(b"x")
        ok, err = self.mgr.delete_blob("userblob.bin")
        self.assertTrue(ok, err)


if __name__ == "__main__":
    unittest.main()
