"""Общая стратегия из находок blockcheck2 (core/strategy_combine)."""

import unittest

from core.strategy_combine import candidates, combine, family_of

A = "--payload=tls_client_hello --lua-desync=multisplit:pos=2"
B = "--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:tcp_md5:repeats=1"
C = "--lua-desync=multidisorder:pos=1,midsld"
Q = "--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"


def f(dom, test, strat, ok=3, total=3):
    return {"domain": dom, "test": test, "strategy": strat,
            "ok": ok, "total": total, "full": ok >= total}


FOUND = [
    f("a.com", "curl_test_https_tls13", A),
    f("a.com", "curl_test_https_tls13", B),
    f("b.com", "curl_test_https_tls13", B),
    f("c.com", "curl_test_https_tls13", C),
    f("c.com", "curl_test_https_tls13", A, ok=2),
    f("a.com", "curl_test_http3", Q),
]


class TestCombine(unittest.TestCase):

    def test_family(self):
        self.assertEqual(family_of("curl_test_http3"), "quic")
        self.assertEqual(family_of("curl_test_https_tls12"), "tls")
        self.assertEqual(family_of("curl_test_http"), "http")

    def test_grouped_set_cover(self):
        r = combine(FOUND, mode="grouped")
        self.assertTrue(r["ok"])
        v = r["variants"][0]
        tls = [(p["strategy"], p["domains"]) for p in v["profiles"]
               if p["family"] == "tls"]
        # B покрывает a и b одним профилем, c — своим приёмом.
        self.assertEqual(tls, [(B, ["a.com", "b.com"]), (C, ["c.com"])])
        self.assertEqual(v["args"].count(" --new "), 2)
        self.assertTrue(v["args"].startswith(
            "--filter-tcp=443 --filter-l7=tls --hostlist-domains=a.com,b.com "
            + B))
        # Приём без --payload получает payload семейства.
        self.assertIn("--hostlist-domains=c.com --payload=tls_client_hello "
                      + C, v["args"])
        self.assertTrue(v["args"].endswith(
            "--filter-udp=443 --filter-l7=quic --hostlist-domains=a.com " + Q))

    def test_partial_excluded_by_default(self):
        c = candidates(FOUND)
        self.assertEqual(c[("c.com", "tls")], [C])
        c = candidates(FOUND, include_partial=True)
        self.assertEqual(c[("c.com", "tls")], [C, A])

    def test_per_domain(self):
        v = combine(FOUND, mode="per_domain")["variants"][0]
        tls = [(p["strategy"], p["domains"]) for p in v["profiles"]
               if p["family"] == "tls"]
        self.assertEqual(tls, [(A, ["a.com"]), (B, ["b.com"]), (C, ["c.com"])])

    def test_custom(self):
        v = combine(FOUND, mode="custom",
                    choices={"a.com|tls": B, "c.com|tls": "чужое"})["variants"][0]
        tls = {p["strategy"]: p["domains"] for p in v["profiles"]
               if p["family"] == "tls"}
        self.assertEqual(tls, {B: ["a.com", "b.com"], C: ["c.com"]})

    def test_all_combinations_and_limit(self):
        r = combine(FOUND, mode="all")
        self.assertEqual(r["total_combinations"], 2)   # a: A|B, прочие по 1
        self.assertEqual(len(r["variants"]), 2)
        self.assertFalse(r["truncated"])
        many = FOUND + [f("b.com", "curl_test_https_tls13", A)]
        r = combine(many, mode="all", limit=3)
        self.assertEqual(r["total_combinations"], 4)
        self.assertEqual(len(r["variants"]), 3)
        self.assertTrue(r["truncated"])

    def test_tls12_and_13_intersection_first(self):
        found = [
            f("x.org", "curl_test_https_tls12", A),
            f("x.org", "curl_test_https_tls12", B),
            f("x.org", "curl_test_https_tls13", B),
        ]
        self.assertEqual(candidates(found)[("x.org", "tls")], [B, A])

    def test_blob_hoisted_before_first_new(self):
        found = [
            f("h.com", "curl_test_http",
              "--blob=fake_http:@/opt/f.bin --payload=http_req --lua-desync=fake:blob=fake_http"),
            f("h.com", "curl_test_https_tls13", A),
        ]
        v = combine(found, mode="grouped")["variants"][0]
        self.assertEqual(v["globals"], ["--blob=fake_http:@/opt/f.bin"])
        self.assertTrue(v["args"].startswith("--blob=fake_http:@/opt/f.bin --filter-tcp=80"))
        self.assertEqual(v["args"].count("--blob="), 1)

    def test_errors(self):
        self.assertFalse(combine([], mode="grouped")["ok"])
        self.assertFalse(combine(FOUND, mode="magic")["ok"])
        self.assertFalse(combine([f("a.com", "curl_test_http", A, ok=1)])["ok"])


if __name__ == "__main__":
    unittest.main()
