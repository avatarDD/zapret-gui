# tests/test_geneva_auto_xcands.py
"""
Методы zapret2 (x-действия geneva_c 2.0) в подборе «Авто»
(AutoCandidates.XFor / BlobCandidates / Fits Zapret2_AutoTuner 1.4).
"""

import os
import subprocess
import unittest

from core import geneva_auto as ga
from core.geneva_ext import needs_ext

GENEVA = os.environ.get("GENEVA_BIN", "")


def svc(**kw):
    base = dict(key="k", name="site.example.org", kind=ga.WEB,
                transport="tcp", ports=[443],
                addresses=[{"ip": "93.184.216.1", "seen": 1}])
    base.update(kw)
    return ga.Service(**base)


ALL = (ga.X_TCP + ga.X_QUIC + ga.X_TCP_WIDE + ga.X_HTTP + ga.X_QUIC_WIDE +
       ga.X_UDP + ga.X_DHT + ga.X_TCP_ANY)


class TestXFor(unittest.TestCase):

    def test_all_need_ext(self):
        self.assertTrue(all(needs_ext(x) for x in ALL))
        self.assertEqual(len(set(ALL)), len(ALL) - 1)   # xoob{urp=b} дважды

    def test_no_ext_no_methods(self):
        self.assertEqual(ga.x_for(svc(), False), [])

    def test_site(self):
        xs = ga.x_for(svc(), True, wide=False)
        self.assertEqual(xs, list(ga.X_TCP))
        wide = ga.x_for(svc(), True)
        self.assertEqual(wide, list(ga.X_TCP) + list(ga.X_TCP_WIDE))
        http = ga.x_for(svc(ports=[80]), True, wide=False)
        self.assertEqual(http[:len(ga.X_HTTP)], list(ga.X_HTTP))
        both = ga.x_for(svc(ports=[80, 443]), True, wide=False)
        self.assertNotIn(ga.X_HTTP[0], both)
        self.assertIn(ga.X_HTTP[0], ga.x_for(svc(ports=[80, 443]), True))

    def test_other_protocols(self):
        self.assertEqual(ga.x_for(svc(kind=ga.QUIC, transport="udp"), True,
                                  wide=False), list(ga.X_QUIC))
        self.assertEqual(ga.x_for(svc(kind=ga.DNS, transport="udp",
                                      ports=[53]), True), [])
        self.assertEqual(ga.x_for(svc(kind=ga.ENDPOINT, transport="udp",
                                      app="dht"), True), list(ga.X_DHT))
        self.assertEqual(ga.x_for(svc(kind=ga.ENDPOINT, transport="udp",
                                      app="wireguard"), True),
                         list(ga.X_UDP))
        self.assertEqual(ga.x_for(svc(kind=ga.ENDPOINT, transport="tcp",
                                      app=""), True), list(ga.X_TCP_ANY))

    def test_fakes_by_kind_and_rounds(self):
        blobs = ["z2_tls_clienthello_%02d" % i for i in range(6)] + \
            ["z2_quic_initial_a", "z2_http_iana_org", "z2_zero_256",
             "z2_wireguard_initiation", "z2_dht_find_node"]
        site = ga.blob_candidates(svc(), blobs)
        # по два на ClientHello и seqovl с первым
        self.assertEqual(len(site), 13)
        self.assertIn("seqovl_pattern=z2_tls_clienthello_00", site[-1])
        q = ga.blob_candidates(svc(kind=ga.QUIC, transport="udp"), blobs)
        self.assertEqual(len(q), 1)
        wg = ga.blob_candidates(svc(kind=ga.ENDPOINT, transport="udp",
                                    app="wireguard"), blobs)
        self.assertEqual(len(wg), 2)          # wireguard + zero
        r0 = ga.x_for(svc(), True, blobs=blobs, rnd=0)[-8:]
        r1 = ga.x_for(svc(), True, blobs=blobs, rnd=1)[-8:]
        self.assertNotEqual(r0, r1)
        self.assertEqual(set(ga.slice_round(site, 8, 0)) |
                         set(ga.slice_round(site, 8, 1)), set(site))

    def test_blob_kind(self):
        self.assertEqual(ga.blob_kind("z2_quic2_x"), "quic_initial")
        self.assertEqual(ga.blob_kind("z2_tls_alert"), "tcp_other")
        self.assertEqual(ga.blob_kind("z2_stun"), "udp_other")


class TestFitsAndRounds(unittest.TestCase):

    def test_flow_triggers_by_actions(self):
        tcp, udp = svc(), svc(kind=ga.QUIC, transport="udp")
        self.assertTrue(ga._fits(tcp, r"[FLOW:n:a]-xoob{urp=b}-| \/"))
        self.assertFalse(ga._fits(udp, r"[FLOW:n:a]-xoob{urp=b}-| \/"))
        self.assertTrue(ga._fits(udp, r"[FLOW:n:a]-xudplen{increment=2}-| \/"))
        self.assertFalse(ga._fits(tcp, r"[FLOW:n:a]-xudplen{increment=2}-| \/"))

    def test_rounds_with_ext(self):
        s = svc()
        plain = ga.candidate_rounds(s)
        with_x = ga.candidate_rounds(s, ext=True)
        rest = with_x[-1]
        self.assertTrue(set(ga.X_TCP) <= set(rest))
        self.assertFalse(any(needs_ext(c) for c in plain[-1]))
        # методы zapret2 — сразу после классики, до библиотеки
        lib = [r"[TCP:flags:PA]-fragment{tcp:4:True}-| \/"]
        rest = ga.candidate_rounds(s, library=lib, ext=True)[-1]
        self.assertLess(rest.index(ga.X_TCP[0]), rest.index(lib[0]))

    def test_found_x_strategy_needs_ext(self):
        s = svc()
        x = ga.X_TCP[0]
        self.assertNotIn(x, sum(ga.candidate_rounds(s, found=[x]), []))
        self.assertEqual(ga.candidate_rounds(s, found=[x], ext=True)[0][0],
                         x)


@unittest.skipUnless(GENEVA and os.path.isfile(GENEVA),
                     "GENEVA_BIN не задан: geneva check не проверяет строки")
class TestGenevaParses(unittest.TestCase):

    def test_every_method_parses(self):
        for x in ALL:
            r = subprocess.run([GENEVA, "check", "--ext", "--json", x],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, x + r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
