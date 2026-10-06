"""DNS-перехват: CNAME-цепочки, TTL записей, вырезание AAAA, TCP, PKTINFO,
шаблоны wildcard/regex (приёмы MagiTrickle).
"""

import socket
import struct
import threading
import time
import unittest
from unittest import mock

from core.routing import dns_intercept, domain_match, set_ttl
from core.routing.dns_intercept import (DnsIntercept, parse_dns_message,
                                        strip_answers)


def _name(n: str) -> bytes:
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _query(qname: str, qtype: int = 1) -> bytes:
    return (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + _name(qname) + struct.pack("!HH", qtype, 1))


def _response(qname: str, answers, qtype: int = 1) -> bytes:
    """answers: [(owner, rtype, ttl, rdata_bytes)]."""
    body = _name(qname) + struct.pack("!HH", qtype, 1)
    for owner, rtype, ttl, rdata in answers:
        body += _name(owner) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
        body += rdata
    head = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(answers), 0, 0)
    return head + body


def _a(ip):
    return socket.inet_aton(ip)


class TestParse(unittest.TestCase):

    def test_cname_chain_names_and_ttl(self):
        resp = _response("www.apple.com", [
            ("www.apple.com", 5, 300, _name("www.apple.com.edgekey.net")),
            ("www.apple.com.edgekey.net", 5, 60, _name("e6858.dsce9.akamaiedge.net")),
            ("e6858.dsce9.akamaiedge.net", 1, 20, _a("23.1.2.3")),
        ])
        msg = parse_dns_message(resp)
        self.assertEqual(msg["qname"], "www.apple.com")
        self.assertIn("e6858.dsce9.akamaiedge.net", msg["names"])
        self.assertIn("www.apple.com.edgekey.net", msg["names"])
        self.assertEqual(msg["ips"], [("23.1.2.3", "v4", 20)])

    def test_garbage_is_empty(self):
        self.assertEqual(parse_dns_message(b"\x00" * 5), {})
        self.assertEqual(parse_dns_message(_query("a.com")), {})

    def test_strip_answers_keeps_question(self):
        resp = _response("v6.example.com",
                         [("v6.example.com", 28, 60, b"\x20\x01" + b"\x00" * 14)],
                         qtype=28)
        msg = parse_dns_message(resp)
        out = strip_answers(resp, msg["qend"])
        hdr = struct.unpack("!HHHHHH", out[:12])
        self.assertEqual(hdr[2:], (1, 0, 0, 0))
        self.assertEqual(parse_dns_message(out)["qname"], "v6.example.com")
        self.assertEqual(parse_dns_message(out)["ips"], [])


class TestMatcher(unittest.TestCase):

    def test_kinds(self):
        self.assertEqual(domain_match.kind_of("*.a.com"), "domain")
        self.assertEqual(domain_match.kind_of("cdn*.a.com"), "wildcard")
        self.assertEqual(domain_match.kind_of("regexp:^a"), "regex")
        self.assertEqual(domain_match.plain_domains(
            ["*.A.com.", "cdn*.b.com", "regexp:x", "c.org"]), ["a.com", "c.org"])

    def test_match(self):
        m = domain_match.Matcher(["googlevideo.com", "r?---sn-*.example.net",
                                  "regexp:^api[0-9]+\\.foo\\.org$"])
        self.assertTrue(m.match("RR3---SN-x.GoogleVideo.com."))     # 0x20
        self.assertFalse(m.match("evilgooglevideo.com"))
        self.assertTrue(m.match("r3---sn-abc.example.net"))
        self.assertFalse(m.match("rr3---sn-abc.example.net"))
        self.assertTrue(m.match("api12.foo.org"))
        self.assertFalse(m.match("api.foo.org"))
        self.assertTrue(m.match_any(["x.com", "a.googlevideo.com"]))

    def test_validate(self):
        self.assertEqual(domain_match.validate_entry("youtube.com"), "")
        self.assertEqual(domain_match.validate_entry("*.youtube.com"), "")
        self.assertEqual(domain_match.validate_entry("cdn*.yt.com"), "")
        self.assertTrue(domain_match.validate_entry("youtube,com"))
        self.assertTrue(domain_match.validate_entry("https://x.com/a"))
        self.assertTrue(domain_match.validate_entry("regexp:(unclosed"))
        self.assertEqual(domain_match.validate_entry("regexp:^a\\.b$"), "")

    def test_alias_resolver_keeps_patterns_out_of_domains(self):
        from core.routing.alias_resolver import expand_domains
        out = expand_domains(["*.A.com", "cdn*.b.com", "regexp:^c/d"])
        self.assertEqual(out["domains"], ["a.com"])
        self.assertEqual(out["cidrs"], [])
        self.assertEqual(out["patterns"], ["cdn*.b.com", "regexp:^c/d"])


class TestSetTtl(unittest.TestCase):

    def test_timeout_for(self):
        on = {"enabled": True, "extra_sec": 3600, "min_sec": 300}
        self.assertEqual(set_ttl.timeout_for(20, on), 3900)      # min 300
        self.assertEqual(set_ttl.timeout_for(7200, on), 10800)
        self.assertEqual(set_ttl.timeout_for(None, on), 3900)
        self.assertEqual(set_ttl.timeout_for(20, {"enabled": False}), 0)


class _Entry:
    @staticmethod
    def make(kind="ipset", **kw):
        e = {"id": "r1", "kind": kind, "iface": "awg0", "table": 100,
             "set_v4": "awgr_r1", "set_v6": "awgr_r16",
             "matcher": domain_match.Matcher(kw.pop("domains",
                                                    ["akamaiedge.net"]))}
        e.update(kw)
        return e


class TestHarvest(unittest.TestCase):

    def _di(self, entry):
        di = DnsIntercept()
        di._rules_cache = [entry]
        di._rules_at = time.time() + 3600
        return di

    def test_rule_on_cname_target_catches_the_answer(self):
        di = self._di(_Entry.make())
        added = []
        with mock.patch("core.routing.ipset_backend.add_entry",
                        side_effect=lambda s, ip, t: added.append((s, ip, t))
                        or True), \
                mock.patch.object(set_ttl, "_settings", return_value={}):
            matched = di._harvest(["www.apple.com",
                                   "e6858.dsce9.akamaiedge.net"],
                                  [("23.1.2.3", "v4", 20)])
        self.assertTrue(matched)
        self.assertEqual(added, [("awgr_r1", "23.1.2.3", 3900)])

    def test_fresh_entry_is_not_readded_but_expiring_is(self):
        di = self._di(_Entry.make())
        calls = []
        with mock.patch("core.routing.ipset_backend.add_entry",
                        side_effect=lambda *a: calls.append(a) or True), \
                mock.patch.object(set_ttl, "_settings", return_value={}):
            di._harvest(["a.akamaiedge.net"], [("1.1.1.1", "v4", 60)])
            di._harvest(["a.akamaiedge.net"], [("1.1.1.1", "v4", 60)])
            self.assertEqual(len(calls), 1)
            di._seen[("r1", "1.1.1.1")] = time.time() + 10   # почти истекла
            di._harvest(["a.akamaiedge.net"], [("1.1.1.1", "v4", 60)])
        self.assertEqual(len(calls), 2)

    def test_seen_is_bounded(self):
        di = self._di(_Entry.make())
        now = time.time()
        with mock.patch.object(dns_intercept, "_SEEN_MAX", 10):
            for i in range(25):
                di._remember(("r1", "10.0.0.%d" % i), now + 100, now)
        self.assertLessEqual(len(di._seen), 10)


class TestProcess(unittest.TestCase):

    def _di(self, domains):
        di = DnsIntercept()
        di._rules_cache = [_Entry.make(domains=domains)]
        di._rules_at = time.time() + 3600
        return di

    def test_aaaa_of_routed_domain_is_stripped(self):
        resp = _response("yt.com", [("yt.com", 28, 60,
                                     b"\x20\x01" + b"\x00" * 14)], qtype=28)
        di = self._di(["yt.com"])
        with mock.patch("core.routing.ipset_backend.add_entry",
                        return_value=True), \
                mock.patch.object(dns_intercept, "_settings",
                                  return_value={}):
            out = di._process(_query("yt.com", 28), lambda q: resp)
        self.assertEqual(struct.unpack("!H", out[6:8])[0], 0)
        self.assertEqual(di.stats["aaaa_dropped"], 1)
        with mock.patch("core.routing.ipset_backend.add_entry",
                        return_value=True), \
                mock.patch.object(dns_intercept, "_settings",
                                  return_value={"drop_aaaa": "off"}):
            self.assertEqual(di._process(_query("yt.com", 28),
                                         lambda q: resp), resp)

    def test_foreign_domain_untouched(self):
        resp = _response("other.org", [("other.org", 28, 60,
                                        b"\x20\x01" + b"\x00" * 14)], qtype=28)
        di = self._di(["yt.com"])
        with mock.patch.object(dns_intercept, "_settings", return_value={}):
            self.assertEqual(di._process(_query("other.org", 28),
                                         lambda q: resp), resp)

    def test_harvest_failure_still_answers(self):
        resp = _response("yt.com", [("yt.com", 1, 60, _a("1.2.3.4"))])
        di = self._di(["yt.com"])
        with mock.patch.object(di, "_harvest", side_effect=RuntimeError):
            self.assertEqual(di._process(_query("yt.com"), lambda q: resp),
                             resp)

    def test_upstream_failure_returns_none(self):
        di = self._di(["yt.com"])

        def boom(_q):
            raise OSError("timeout")
        self.assertIsNone(di._process(_query("yt.com"), boom))


class TestPktinfo(unittest.TestCase):

    def test_dst_from_ancillary(self):
        data = struct.pack("=i4s4s", 3, socket.inet_aton("0.0.0.0"),
                           socket.inet_aton("192.168.1.1"))
        anc = [(socket.IPPROTO_IP, dns_intercept._IP_PKTINFO, data)]
        self.assertEqual(dns_intercept._pktinfo_dst(anc), "192.168.1.1")
        self.assertIsNone(dns_intercept._pktinfo_dst([]))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestTcpLoopback(unittest.TestCase):
    """Живой прогон по TCP: клиент → прокси → фейковый TCP-upstream."""

    def test_tcp_query_is_proxied_and_harvested(self):
        up_port = _free_port()
        resp = _response("cdn.example.com",
                         [("cdn.example.com", 1, 60, _a("9.9.9.9"))])
        up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        up.bind(("127.0.0.1", up_port))
        up.listen(1)
        up.settimeout(5)

        def upstream():
            try:
                conn, _ = up.accept()
                with conn:
                    q = dns_intercept._recv_framed(conn)
                    if q:
                        conn.sendall(struct.pack("!H", len(resp)) + resp)
            except OSError:
                pass
        threading.Thread(target=upstream, daemon=True).start()

        di = DnsIntercept()
        di._rules_cache = [_Entry.make(domains=["example.com"])]
        di._rules_at = time.time() + 3600
        di._running = True
        added = []
        a, b = socket.socketpair()
        try:
            with mock.patch.object(dns_intercept, "_settings",
                                   return_value={"upstream":
                                                 "127.0.0.1:%d" % up_port}), \
                    mock.patch("core.routing.ipset_backend.add_entry",
                               side_effect=lambda *x: added.append(x) or True):
                di._tcp_slots.acquire()
                t = threading.Thread(target=di._tcp_client, args=(b,),
                                     daemon=True)
                t.start()
                q = _query("cdn.example.com")
                a.sendall(struct.pack("!H", len(q)) + q)
                a.settimeout(5)
                got = dns_intercept._recv_framed(a)
                a.close()
                t.join(5)
        finally:
            up.close()
        self.assertEqual(got, resp)
        self.assertEqual(added[0][:2], ("awgr_r1", "9.9.9.9"))
        self.assertEqual(di.stats["tcp"], 1)


class TestRedirectRules(unittest.TestCase):

    def test_nft_rule_is_ipv4_only_and_covers_tcp(self):
        calls = []
        with mock.patch.object(dns_intercept, "_run",
                               side_effect=lambda a, **k:
                               (calls.append(a), (0, "", ""))[1]):
            res = DnsIntercept()._ensure_redirect_nft(15353, ("udp", "tcp"))
        self.assertTrue(res["ok"])
        rules = [" ".join(c) for c in calls if c[1:3] == ["add", "rule"]]
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertIn("meta nfproto ipv4", r)
        self.assertTrue(any(" tcp dport 53 " in r for r in rules))

    def test_ipt_rules_for_both_protocols(self):
        calls = []
        with mock.patch.object(dns_intercept, "_run",
                               side_effect=lambda a, **k:
                               (calls.append(a), (0, "", ""))[1]):
            DnsIntercept()._ensure_redirect_ipt(15353, ("udp", "tcp"))
        protos = [c[c.index("-p") + 1] for c in calls if "-p" in c]
        self.assertEqual(protos, ["udp", "tcp"])


if __name__ == "__main__":
    unittest.main()
