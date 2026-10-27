"""Находки с OpenWrt: остатки dnsmasq после выключения маршрута и проба
curl без несуществующей переменной --write-out ``ssl_version``."""

import unittest
from unittest import mock


class TestDisableRouteSweepsDnsmasq(unittest.TestCase):
    def test_disable_route_sweeps_dnsmasq(self):
        from core.unified import manager
        route = mock.Mock(id="uni-route-z", enabled=False)
        route.has_selectors.return_value = True
        with mock.patch("core.unified.manager.UnifiedRoute.from_dict",
                        return_value=route), \
                mock.patch("core.unified.storage.get_route",
                           return_value=route), \
                mock.patch("core.unified.storage.update_route"), \
                mock.patch("core.unified.applier.remove_route") as rm, \
                mock.patch.object(manager, "_sync_monitor"), \
                mock.patch("core.routing.sweeper.sweep_dnsmasq",
                           return_value=([], [])) as sweep:
            self.assertTrue(manager.save_route({})["ok"])
        rm.assert_called_once_with(route)
        sweep.assert_called_once()


OPENSSL_V = """\
*   Trying 1.2.3.4:443...
* ALPN: curl offers h2,http/1.1
* TLSv1.0 (OUT), TLS header, Certificate Status (22):
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
> GET / HTTP/1.1
< HTTP/1.1 200 OK
"""

MBEDTLS_V = """\
*   Trying 1.2.3.4:443...
* mbedTLS: TLSv1.2 Handshake complete, cipher is TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
< HTTP/1.1 200 OK
"""


class TestCurlProbe(unittest.TestCase):
    def test_tls_version_openssl(self):
        from core.diagnostics import _curl_tls_version
        self.assertEqual(_curl_tls_version(OPENSSL_V), "TLSv1.3")

    def test_tls_version_mbedtls(self):
        from core.diagnostics import _curl_tls_version
        self.assertEqual(_curl_tls_version(MBEDTLS_V), "TLSv1.2")

    def test_tls_version_plain_http(self):
        from core.diagnostics import _curl_tls_version
        self.assertIsNone(_curl_tls_version("* Trying 1.2.3.4:80...\n"))

    def test_error_skips_verbose_log(self):
        from core.diagnostics import _curl_error
        err = OPENSSL_V.split("> GET")[0] + \
            "curl: (28) Operation timed out after 8001 milliseconds\n"
        self.assertEqual(_curl_error(err),
                         "curl: (28) Operation timed out after 8001 "
                         "milliseconds")

    def test_check_http_no_ssl_version_variable(self):
        from core import diagnostics
        calls = []

        def fake_run(cmd, timeout=10):
            calls.append(cmd)
            return 0, "200||0.123", OPENSSL_V

        with mock.patch.object(diagnostics, "_find_binary",
                               return_value="/usr/bin/curl"), \
                mock.patch.object(diagnostics, "_run", side_effect=fake_run):
            res = diagnostics.check_http("https://example.org/",
                                         fresh=True)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("ssl_version", " ".join(calls[0]))
        self.assertTrue(res["ok"])
        self.assertEqual(res["tls_version"], "TLSv1.3")
        self.assertEqual(res["response_time"], 123)
        self.assertIsNone(res["error"])


if __name__ == "__main__":
    unittest.main()
