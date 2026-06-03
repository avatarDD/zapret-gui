# tests/test_blockcheck2_found.py
"""Разбор «working strategy found» blockcheck2 в структуру для GUI-бейджей."""

import unittest

from core.blockcheck2 import parse_found_strategy, _classify_test


class TestClassifyTest(unittest.TestCase):

    def test_http(self):
        info = _classify_test("curl_test_http")
        self.assertEqual((info["proto"], info["port"], info["l7"],
                          info["payload"], info["label"]),
                         ("tcp", "80", "http", "http_req", "HTTP"))

    def test_tls13(self):
        info = _classify_test("curl_test_https_tls13")
        self.assertEqual((info["proto"], info["port"], info["l7"],
                          info["payload"], info["label"]),
                         ("tcp", "443", "tls", "tls_client_hello", "TLS1.3"))

    def test_tls12(self):
        info = _classify_test("curl_test_https_tls12")
        self.assertEqual(info["label"], "TLS1.2")
        self.assertEqual(info["proto"], "tcp")

    def test_http3_quic(self):
        info = _classify_test("curl_test_http3")
        self.assertEqual((info["proto"], info["port"], info["l7"],
                          info["payload"], info["label"]),
                         ("udp", "443", "quic", "quic_initial", "QUIC"))


class TestParseFoundStrategy(unittest.TestCase):

    def test_tls13_line(self):
        line = ("curl_test_https_tls13: working strategy found for ipv4 "
                "youtube.com : nfqws2 --payload=tls_client_hello "
                "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid")
        f = parse_found_strategy(line)
        self.assertIsNotNone(f)
        self.assertEqual(f["ipv"], 4)
        self.assertEqual(f["domain"], "youtube.com")
        self.assertEqual(f["engine"], "nfqws2")
        self.assertEqual(f["proto"], "tcp")
        self.assertEqual(f["port"], "443")
        self.assertEqual(f["l7"], "tls")
        self.assertEqual(f["payload"], "tls_client_hello")
        self.assertEqual(f["label"], "TLS1.3")
        # strategy — дословно, без движка
        self.assertEqual(
            f["strategy"],
            "--payload=tls_client_hello "
            "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid")

    def test_http_ipv6(self):
        line = ("curl_test_http: working strategy found for ipv6 example.com "
                ": nfqws --lua-desync=fake:blob=fake_default_http")
        f = parse_found_strategy(line)
        self.assertEqual(f["ipv"], 6)
        self.assertEqual(f["proto"], "tcp")
        self.assertEqual(f["port"], "80")
        self.assertEqual(f["l7"], "http")
        self.assertEqual(f["engine"], "nfqws")

    def test_quic(self):
        line = ("curl_test_http3: working strategy found for ipv4 youtube.com "
                ": nfqws2 --payload=quic_initial --lua-desync=fake")
        f = parse_found_strategy(line)
        self.assertEqual(f["proto"], "udp")
        self.assertEqual(f["l7"], "quic")
        self.assertEqual(f["label"], "QUIC")

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(parse_found_strategy("* SUMMARY"))
        self.assertIsNone(parse_found_strategy("some random log line"))

    def test_line_without_args_returns_none(self):
        line = ("curl_test_http: working strategy found for ipv4 host : nfqws")
        self.assertIsNone(parse_found_strategy(line))


if __name__ == "__main__":
    unittest.main()
