# tests/test_profile_import.py
"""Импорт чужого профиля (core/profile_import): разбор конфигов, перенос
путей, выброс опций движка."""

import unittest

from core import profile_import as pi

HAVE = {"/l/lua/zapret-antidpi.lua", "/l/fake/tls_google.bin",
        "/l/lists/other.txt"}
ENV = {"lua_path": "/l/lua", "bin_path": "/l/fake",
       "lists_path": "/l/lists", "ipset_path": "/l/ipset",
       "exists": lambda p: p in HAVE,
       "iface_exists": lambda i: i == "eth3"}


def conv(text):
    return pi.convert(text, ENV)


ZAPRET2 = '''
# zapret2 config
FWTYPE=nftables
IFACE_WAN="ppp0"
NFQWS2_OPT="
--blob=tls_google:@/opt/zapret2/files/fake/tls_google.bin
--filter-tcp=443 --filter-l7=tls <HOSTLIST> --lua-desync=fake:blob=tls_google --new
--filter-udp=443 <HOSTLIST_NOAUTO> --lua-desync=fake:blob=fake_default_quic:repeats=6
"
'''

KEENETIC = '''
ISP_INTERFACE="eth3"
NFQWS_BASE_ARGS="--qnum=200 --user=nobody"
NFQWS_ARGS="--filter-tcp=443 --lua-desync=multisplit:pos=1 --lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua"
NFQWS_ARGS_QUIC="--filter-udp=443 --lua-desync=fake:blob=fake_default_quic"
NFQWS_EXTRA_ARGS="--hostlist=/opt/etc/nfqws2/user.list --hostlist-exclude=/opt/etc/nfqws2/other.txt"
'''


class TestDetect(unittest.TestCase):

    def test_kinds(self):
        self.assertEqual(pi.detect(ZAPRET2), "zapret2")
        self.assertEqual(pi.detect(KEENETIC), "keenetic")
        self.assertEqual(pi.detect('NFQWS_OPT="--dpi-desync=fake"'),
                         "zapret1")
        self.assertEqual(pi.detect("nfqws2 --lua-desync=fake"), "args")
        self.assertEqual(pi.detect("привет"), "unknown")


class TestZapret2(unittest.TestCase):

    def test_profiles_and_paths(self):
        r = conv(ZAPRET2)
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["profiles"]), 2)
        first = r["profiles"][0]["args"]
        self.assertIn("--blob=tls_google:@bin/tls_google.bin", first)
        self.assertNotIn("<HOSTLIST>", first)
        self.assertEqual(r["profiles"][1]["name"], "UDP 443")
        self.assertTrue(any("<HOSTLIST>" in w for w in r["warnings"]))
        self.assertTrue(any("ppp0" in w for w in r["warnings"]))

    def test_globals_carry_to_first_profile(self):
        r = conv('NFQWS2_OPT="--blob=x:@/a/b/x.bin --new '
                 '--filter-tcp=443 --lua-desync=fake:blob=x"')
        self.assertEqual(len(r["profiles"]), 1)
        self.assertTrue(r["profiles"][0]["args"].startswith(
            "--blob=x:@bin/x.bin"))
        self.assertTrue(any("x.bin" in w for w in r["warnings"]))


class TestKeenetic(unittest.TestCase):

    def test_extra_lists_go_to_each_profile(self):
        r = conv(KEENETIC)
        self.assertEqual(r["kind"], "keenetic")
        self.assertEqual(len(r["profiles"]), 2)
        for p in r["profiles"]:
            self.assertIn("--hostlist=lists/user.list", p["args"])
            self.assertIn("--hostlist-exclude=lists/other.txt", p["args"])
        self.assertIn("--lua-init=@lua/zapret-antidpi.lua",
                      r["profiles"][0]["args"])
        # user.list у нас нет, other.txt и интерфейс eth3 — есть.
        self.assertTrue(any("user.list" in w for w in r["warnings"]))
        self.assertFalse(any("other.txt" in w for w in r["warnings"]))
        self.assertFalse(any("eth3" in w for w in r["warnings"]))

    def test_engine_options_dropped(self):
        r = conv(KEENETIC)
        self.assertIn("--qnum=200", r["dropped"])
        joined = " ".join(p["args"] for p in r["profiles"])
        self.assertNotIn("--qnum", joined)
        self.assertNotIn("--user", joined)


class TestArgs(unittest.TestCase):

    def test_command_line(self):
        r = conv("/opt/zapret2/nfq2/nfqws2 --qnum 200 --pidfile=/x "
                 "--filter-tcp=443 --lua-desync=multisplit")
        self.assertEqual(r["profiles"][0]["args"],
                         "--filter-tcp=443 --lua-desync=multisplit")
        self.assertIn("--qnum", r["dropped"])

    def test_ipset_maps_to_lists(self):
        r = conv("--filter-tcp=443 --ipset=/opt/zapret2/ipset/cf.txt "
                 "--lua-desync=fake")
        self.assertIn("--ipset=lists/cf.txt", r["profiles"][0]["args"])
        self.assertTrue(any("cf.txt" in w for w in r["warnings"]))

    def test_v1_warned_not_imported(self):
        r = conv('NFQWS_OPT="--filter-tcp=443 --dpi-desync=fake,split2"')
        self.assertFalse(r["ok"])
        self.assertIn("v1", r["warnings"][0])
        self.assertIn("zapret v1", r["error"])

    def test_repeated_payload_kept_in_order(self):
        args = ("--filter-tcp=443 --payload=tls_client_hello "
                "--lua-desync=fake --payload=http_req --lua-desync=multisplit "
                "--payload=tls_client_hello --lua-desync=multidisorder")
        r = conv(args)
        self.assertEqual(r["profiles"][0]["args"], args)

    def test_globals_mixed_with_engine_options_carried(self):
        r = conv('NFQWS_BASE_ARGS="--qnum=200 --lua-init=@/opt/x/zapret-lib.lua"\n'
                 'NFQWS_ARGS="--filter-tcp=443 --lua-desync=fake"')
        self.assertTrue(r["profiles"][0]["args"].startswith(
            "--lua-init=@lua/zapret-lib.lua"))
        self.assertFalse(any("пропущена" in w for w in r["warnings"]))

    def test_trailing_blob_moved_to_first_profile(self):
        r = conv('NFQWS2_OPT="--filter-tcp=443 --lua-desync=fake:blob=y '
                 '--new --blob=y:@/a/y.bin"')
        self.assertTrue(r["profiles"][0]["args"].startswith(
            "--blob=y:@bin/y.bin"))

    def test_line_continuation_in_value(self):
        r = conv('NFQWS2_OPT="--filter-tcp=443 \\\n --lua-desync=fake"')
        self.assertEqual(r["profiles"][0]["args"],
                         "--filter-tcp=443 --lua-desync=fake")

    def test_two_token_path(self):
        r = conv("nfqws2 --hostlist /opt/x/l.txt --filter-tcp=443 "
                 "--lua-desync=fake")
        self.assertIn("--hostlist=lists/l.txt", r["profiles"][0]["args"])

    def test_inline_comment(self):
        r = conv("nfqws2 --filter-tcp=443 --lua-desync=fake  # рабочая")
        self.assertEqual(r["profiles"][0]["args"],
                         "--filter-tcp=443 --lua-desync=fake")

    def test_builder_resolves_imported_paths(self):
        from core.catalog_loader import CatalogManager
        r = conv(ZAPRET2)
        from core.models import tokenize_args
        out = CatalogManager.resolve_paths_in_args(
            tokenize_args(r["profiles"][0]["args"]),
            lua_path="/L", lists_path="/LS", bin_path="/B", ipset_path="/I")
        self.assertIn("--blob=tls_google:@/B/tls_google.bin", out)


if __name__ == "__main__":
    unittest.main()


class TestMissingFiles(unittest.TestCase):

    def test_lists_files_to_create(self):
        r = conv(ZAPRET2.replace("tls_google.bin", "tls_x.bin").replace(
            "<HOSTLIST> --lua-desync",
            "--hostlist=/opt/zapret2/lists/zt-yt.txt "
            "--ipset=/opt/zapret2/ipset/zt-x-ipset.txt --lua-desync"))
        self.assertIn({"kind": "blob", "name": "tls_x.bin"},
                      r["missing_files"])
        self.assertIn({"kind": "hostlist", "name": "zt-yt.txt"},
                      r["missing_files"])
        self.assertIn({"kind": "ipset", "name": "zt-x-ipset.txt"},
                      r["missing_files"])

    def test_present_files_not_listed(self):
        r = conv(KEENETIC)
        names = [m["name"] for m in r["missing_files"]]
        self.assertNotIn("zapret-antidpi.lua", names)
        self.assertNotIn("other.txt", names)
        self.assertIn("user.list", names)
        self.assertEqual(len(names), len(set(names)))
