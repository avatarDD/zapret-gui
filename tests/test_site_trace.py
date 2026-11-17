# tests/test_site_trace.py
"""«Куда пойдёт сайт» (core/site_trace): разбор профилей nfqws2 и выбор
профиля для потока — чистые функции, плюс граница trace()."""

import unittest
from unittest import mock

from core import site_trace as st

HTTPS = ("https", "tcp", 443, "tls")
QUIC = ("quic", "udp", 443, "quic")
HTTP = ("http", "tcp", 80, "http")


def reader(lists):
    return lambda path: set(lists.get(path, ()))


class TestPorts(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(st.parse_ports("80,443,1000-2000"),
                         [(80, 80, False), (443, 443, False),
                          (1000, 2000, False)])
        self.assertEqual(st.parse_ports("~80"), [(80, 80, True)])
        self.assertEqual(st.parse_ports("*"), [(0, 65535, False)])
        self.assertEqual(st.parse_ports("50000:50100,x"),
                         [(50000, 50100, False)])

    def test_port_in(self):
        self.assertTrue(st.port_in(st.parse_ports("80,443"), 443))
        self.assertFalse(st.port_in(st.parse_ports("80"), 443))
        self.assertTrue(st.port_in(st.parse_ports("~80"), 443))
        self.assertFalse(st.port_in(st.parse_ports("~80"), 80))


class TestMatch(unittest.TestCase):

    def test_domain_hit(self):
        self.assertEqual(st.domain_hit("a.youtube.com", ["youtube.com"]),
                         "youtube.com")
        self.assertEqual(st.domain_hit("youtube.com", ["youtube.com"]),
                         "youtube.com")
        self.assertEqual(st.domain_hit("a.youtube.com", ["^youtube.com"]),
                         "")
        self.assertEqual(st.domain_hit("youtube.com", ["^youtube.com"]),
                         "^youtube.com")
        self.assertEqual(st.domain_hit("notyoutube.com", ["youtube.com"]),
                         "")

    def test_domain_hit_local_exemption(self):
        # zapret2 1.0.7: «com» + «!vk.com» — всё *.com, кроме vk.com
        lst = ["com", "!vk.com"]
        self.assertEqual(st.domain_hit("ya.com", lst), "com")
        self.assertEqual(st.domain_hit("vk.com", lst), "")
        self.assertEqual(st.domain_hit("m.vk.com", lst), "")
        # самая длинная запись решает: a.vk.com в списке явно
        self.assertEqual(st.domain_hit("a.vk.com", lst + ["a.vk.com"]),
                         "a.vk.com")
        # строгое исключение — только сам домен, поддомены снова под «com»
        for strict in ("!^vk.com", "^!vk.com"):
            self.assertEqual(st.domain_hit("vk.com", ["com", strict]), "")
            self.assertEqual(st.domain_hit("m.vk.com", ["com", strict]),
                             "com")

    def test_ip_hit(self):
        self.assertIn("10.0.0.0/8", st.ip_hit(["10.1.2.3"], ["10.0.0.0/8"]))
        self.assertEqual(st.ip_hit(["1.1.1.1"], ["10.0.0.0/8", "bad"]), "")
        self.assertEqual(st.ip_hit(["::1"], ["0.0.0.0/0"]), "")


class TestProfiles(unittest.TestCase):

    def pick(self, profiles, flow=HTTPS, domain="youtube.com",
             ips=("1.2.3.4",), lists=None):
        return st.pick_profile(profiles, flow, domain, list(ips),
                               reader(lists or {}))

    def test_parse_profile(self):
        p = st.parse_profile([
            "--filter-tcp=443", "--filter-l7=tls,quic",
            "--hostlist=/l/a.txt", "--hostlist-domains=X.com",
            "--lua-desync=fake:blob=tls", "--lua-desync=multisplit"])
        self.assertEqual(p["tcp"], [(443, 443, False)])
        self.assertEqual(p["l7"], {"tls", "quic"})
        self.assertEqual(p["hostlist_domains"], ["x.com"])
        self.assertEqual(p["actions"], ["fake", "multisplit"])

    def test_first_matching_profile_wins(self):
        r = self.pick([
            ["--filter-udp=443", "--lua-desync=fake"],
            ["--filter-tcp=443", "--hostlist=/l/yt.txt",
             "--lua-desync=multisplit"],
            ["--filter-tcp=443", "--lua-desync=fake"],
        ], lists={"/l/yt.txt": ["youtube.com"]})
        self.assertEqual(r["profile"], 2)
        self.assertEqual(r["actions"], ["multisplit"])
        self.assertEqual(r["skipped"][0]["reason"],
                         "фильтр только по UDP")
        self.assertIn("yt.txt", r["reason"])

    def test_exclude_beats_include(self):
        r = self.pick([["--filter-tcp=443", "--hostlist-domains=youtube.com",
                        "--hostlist-exclude=/l/ex.txt"]],
                      lists={"/l/ex.txt": ["youtube.com"]})
        self.assertIsNone(r["profile"])
        self.assertIn("исключён", r["skipped"][0]["reason"])

    def test_l7_filter(self):
        prof = [["--filter-l7=http", "--lua-desync=fake"]]
        self.assertIsNone(self.pick(prof)["profile"])
        self.assertEqual(self.pick(prof, flow=HTTP)["profile"], 1)

    def test_l3_multi_value(self):
        prof = [["--filter-l3=ipv4,ipv6", "--lua-desync=fake"]]
        self.assertEqual(self.pick(prof)["profile"], 1)
        self.assertIsNone(self.pick([["--filter-l3=ipv6"]])["profile"])

    def test_no_lists_takes_all(self):
        r = self.pick([["--filter-udp=443", "--lua-desync=fake"]], flow=QUIC)
        self.assertEqual(r["profile"], 1)

    def test_ipset_and_hostlist_both_required(self):
        prof = [["--ipset-ip=10.0.0.0/8", "--hostlist-domains=youtube.com"]]
        self.assertIsNone(self.pick(prof)["profile"])
        self.assertEqual(self.pick(prof, ips=["10.1.1.1"])["profile"], 1)
        r = self.pick([["--ipset-ip=10.0.0.0/8"]], ips=[])
        self.assertIn("не узнаны", r["skipped"][0]["reason"])

    def test_autohostlist_note(self):
        r = self.pick([["--hostlist-auto=/l/auto.txt"]])
        self.assertIn("автохостлист", r["skipped"][0]["reason"])
        r = self.pick([["--hostlist-auto=/l/auto.txt"]],
                      lists={"/l/auto.txt": ["youtube.com"]})
        self.assertEqual(r["profile"], 1)

    def test_nothing_matches(self):
        r = self.pick([["--hostlist-domains=example.com"]])
        self.assertIsNone(r["profile"])
        self.assertIn("без обхода", r["reason"])


class TestTrace(unittest.TestCase):

    def test_bad_domain(self):
        self.assertFalse(st.trace("localhost")["ok"])

    def test_normalize(self):
        self.assertEqual(st.normalize("https://WWW.YouTube.com/watch?v=1"),
                         "www.youtube.com")

    def test_layer_errors_do_not_break(self):
        boom = mock.Mock(side_effect=RuntimeError("x"))
        with mock.patch.object(st, "_hosts_layer", boom), \
                mock.patch.object(st, "_dns_layer", lambda d: []), \
                mock.patch.object(st, "_unified_layer", lambda d: []), \
                mock.patch.object(st, "_lists_layer", lambda d, r=None: {}), \
                mock.patch("core.list_lint._strategy_argv", lambda: []):
            r = st.trace("youtube.com", resolve=False)
        self.assertTrue(r["ok"])
        self.assertIn("hosts", r["errors"])
        self.assertTrue(r["nfqws"]["no_strategy"])
        self.assertIsInstance(r["summary"], list)

    def test_unified_hostlist_goes_into_first_profile(self):
        # compose_command ставит hostlist единого слоя ДО профилей.
        argv = ["--filter-tcp=443", "--lua-desync=fake", "--new",
                "--filter-tcp=443", "--lua-desync=multisplit"]
        with mock.patch.object(st, "_hosts_layer", lambda d: []), \
                mock.patch.object(st, "_dns_layer", lambda d: []), \
                mock.patch.object(st, "_unified_layer", lambda d: []), \
                mock.patch.object(st, "_lists_layer", lambda d, r=None: {}), \
                mock.patch.object(st, "_list_reader",
                                  lambda: reader({"/u.txt": ["a.com"]})), \
                mock.patch.object(st, "_firewall_ports", lambda: {
                    "tcp": st.parse_ports("80,443"),
                    "udp": st.parse_ports("443")}), \
                mock.patch("core.list_lint._strategy_argv", lambda: argv), \
                mock.patch("core.unified.nfqws_hostlist.compose_extra_args",
                           lambda: ["--hostlist=/u.txt"]):
            r = st.trace("youtube.com", resolve=False)
        https = r["nfqws"]["flows"]["https"]
        self.assertEqual(https["profile"], 2)
        self.assertEqual(https["actions"], ["multisplit"])


class TestSummary(unittest.TestCase):

    def test_blocked_by_hosts(self):
        lines = st.summarize({"hosts": [{"ip": "0.0.0.0", "system": False}],
                              "blocked": True})
        self.assertIn("в никуда", lines[-1])

    def test_several_tunnels_not_definite(self):
        routes = [{"id": "1", "name": "a", "method": "awg:wg0",
                   "match": "x", "tunnel": True, "maybe": False},
                  {"id": "2", "name": "b", "method": "singbox:tun0",
                   "match": "x", "tunnel": True, "maybe": False}]
        lines = st.summarize({"routes": routes})
        self.assertIn("один из туннелей", lines[-1])

    def test_device_scoped_tunnel_keeps_nfqws_part(self):
        routes = [{"id": "1", "name": "a", "method": "awg:wg0",
                   "match": "x", "tunnel": True, "maybe": False,
                   "devices": ["tv"]}]
        lines = st.summarize({"routes": routes, "nfqws": {
            "running": False}})
        self.assertTrue(any("nfqws2 не запущен" in x for x in lines))

    def test_block_ip(self):
        self.assertTrue(st._is_block_ip("0.0.0.0"))
        self.assertTrue(st._is_block_ip("127.0.0.1"))
        self.assertFalse(st._is_block_ip("1.2.3.4"))


class TestReader(unittest.TestCase):

    def test_gzip_list(self):
        import gzip
        import os
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "l.txt.gz")
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write("# c\nYouTube.com\n")
        with mock.patch("core.config_manager.get_config_manager") as g:
            g.return_value.get.return_value = d
            read = st._list_reader()
            self.assertEqual(read(path), {"youtube.com"})


if __name__ == "__main__":
    unittest.main()
