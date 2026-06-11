# tests/test_download_transport.py
"""
Тесты core/download_transport.py — транспорт скачивания (задача №8):
разбор спеки, обнаружение локальных прокси sing-box/mihomo, резолв
транспорта, сборка urllib-opener'ов и проводка через
binary_installer.download_file.
"""

import io
import socket
import unittest
import urllib.request
from unittest import mock

from core import download_transport as dt


class TestParseTransport(unittest.TestCase):

    def test_direct_variants(self):
        self.assertEqual(dt.parse_transport(""), ("direct", ""))
        self.assertEqual(dt.parse_transport(None), ("direct", ""))
        self.assertEqual(dt.parse_transport("direct"), ("direct", ""))
        self.assertEqual(dt.parse_transport(" Direct "), ("direct", ""))

    def test_awg(self):
        self.assertEqual(dt.parse_transport("awg"), ("awg", ""))
        self.assertEqual(dt.parse_transport("awg:wg0"), ("awg", "wg0"))
        self.assertEqual(dt.parse_transport("wireguard:awg0"),
                         ("awg", "awg0"))

    def test_singbox_mihomo(self):
        self.assertEqual(dt.parse_transport("singbox:proxy"),
                         ("singbox", "proxy"))
        self.assertEqual(dt.parse_transport("sing-box"), ("singbox", ""))
        self.assertEqual(dt.parse_transport("mihomo:main"),
                         ("mihomo", "main"))

    def test_unknown(self):
        kind, _ = dt.parse_transport("tor:9050")
        self.assertEqual(kind, "unknown")


class TestLocalHost(unittest.TestCase):

    def test_wildcards_to_loopback(self):
        for listen in ("", None, "0.0.0.0", "::", "[::]", "127.0.0.1",
                       "localhost"):
            self.assertEqual(dt._local_host(listen), "127.0.0.1")

    def test_concrete_address_kept(self):
        self.assertEqual(dt._local_host("192.168.1.1"), "192.168.1.1")


class TestSingboxLocalProxy(unittest.TestCase):

    def test_mixed_inbound(self):
        cfg = {"inbounds": [
            {"type": "tun", "tag": "tun-in"},
            {"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080},
        ]}
        p = dt.singbox_local_proxy(cfg)
        self.assertEqual(p, {"host": "127.0.0.1", "port": 1080,
                             "type": "mixed"})

    def test_http_inbound_wildcard_listen(self):
        cfg = {"inbounds": [
            {"type": "http", "listen": "0.0.0.0", "listen_port": 8118},
        ]}
        p = dt.singbox_local_proxy(cfg)
        self.assertEqual(p["host"], "127.0.0.1")
        self.assertEqual(p["port"], 8118)

    def test_socks_only_skipped(self):
        cfg = {"inbounds": [
            {"type": "socks", "listen": "127.0.0.1", "listen_port": 1080},
        ]}
        self.assertIsNone(dt.singbox_local_proxy(cfg))

    def test_inbound_with_users_skipped(self):
        cfg = {"inbounds": [
            {"type": "mixed", "listen_port": 1080,
             "users": [{"username": "u", "password": "p"}]},
        ]}
        self.assertIsNone(dt.singbox_local_proxy(cfg))

    def test_bad_port_skipped(self):
        cfg = {"inbounds": [{"type": "mixed", "listen_port": "oops"},
                            {"type": "mixed", "listen_port": 0}]}
        self.assertIsNone(dt.singbox_local_proxy(cfg))

    def test_not_dict(self):
        self.assertIsNone(dt.singbox_local_proxy(None))
        self.assertIsNone(dt.singbox_local_proxy({"inbounds": "x"}))


class TestMihomoLocalProxy(unittest.TestCase):

    def test_mixed_port_preferred(self):
        cfg = {"mixed-port": 7890, "port": 7891}
        p = dt.mihomo_local_proxy(cfg)
        self.assertEqual(p, {"host": "127.0.0.1", "port": 7890,
                             "type": "mixed"})

    def test_http_port_fallback(self):
        p = dt.mihomo_local_proxy({"port": 7891})
        self.assertEqual(p["port"], 7891)
        self.assertEqual(p["type"], "http")

    def test_socks_only_none(self):
        self.assertIsNone(dt.mihomo_local_proxy({"socks-port": 7892}))

    def test_authentication_skipped(self):
        cfg = {"mixed-port": 7890, "authentication": ["user:pass"]}
        self.assertIsNone(dt.mihomo_local_proxy(cfg))


class TestResolveTransport(unittest.TestCase):

    def test_direct(self):
        r = dt.resolve_transport("")
        self.assertTrue(r["ok"])
        self.assertEqual(r["kind"], "direct")

    def test_awg_named_found(self):
        cands = [{"id": "awg:wg0", "kind": "awg", "device": "wg0",
                  "label": "AWG: wg0"}]
        with mock.patch.object(dt, "_awg_candidates", return_value=cands):
            r = dt.resolve_transport("awg:wg0")
        self.assertTrue(r["ok"])
        self.assertEqual(r["device"], "wg0")

    def test_awg_first_when_unnamed(self):
        cands = [{"id": "awg:a0", "kind": "awg", "device": "a0",
                  "label": "AWG: a0"},
                 {"id": "awg:a1", "kind": "awg", "device": "a1",
                  "label": "AWG: a1"}]
        with mock.patch.object(dt, "_awg_candidates", return_value=cands):
            r = dt.resolve_transport("awg")
        self.assertEqual(r["device"], "a0")

    def test_awg_missing_iface_error(self):
        with mock.patch.object(dt, "_awg_candidates", return_value=[]), \
             mock.patch("os.path.isdir", return_value=False):
            r = dt.resolve_transport("awg:nope")
        self.assertFalse(r["ok"])
        self.assertIn("nope", r["error"])

    def test_awg_iface_exists_in_sysfs(self):
        # Не в кандидатах (например, нативный Keenetic WG), но интерфейс
        # существует — разрешаем.
        with mock.patch.object(dt, "_awg_candidates", return_value=[]), \
             mock.patch("os.path.isdir", return_value=True):
            r = dt.resolve_transport("awg:Wireguard0")
        self.assertTrue(r["ok"])
        self.assertEqual(r["device"], "Wireguard0")

    def test_singbox_named(self):
        cands = [{"id": "singbox:a", "kind": "singbox", "name": "a",
                  "proxy": "http://127.0.0.1:1080", "label": "sing-box: a"}]
        with mock.patch.object(dt, "_singbox_candidates",
                               return_value=cands):
            ok = dt.resolve_transport("singbox:a")
            missing = dt.resolve_transport("singbox:b")
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["proxy"], "http://127.0.0.1:1080")
        self.assertFalse(missing["ok"])

    def test_mihomo_none_running(self):
        with mock.patch.object(dt, "_mihomo_candidates", return_value=[]):
            r = dt.resolve_transport("mihomo")
        self.assertFalse(r["ok"])

    def test_unknown_kind(self):
        r = dt.resolve_transport("tor:9050")
        self.assertFalse(r["ok"])


class TestBuildOpener(unittest.TestCase):

    def test_direct_returns_none(self):
        self.assertIsNone(dt.build_opener(""))
        self.assertIsNone(dt.build_opener("direct"))

    def test_unavailable_raises(self):
        with mock.patch.object(dt, "resolve_transport",
                               return_value={"ok": False, "error": "нет"}):
            with self.assertRaises(RuntimeError):
                dt.build_opener("singbox")

    def test_proxy_opener_has_proxies(self):
        res = {"ok": True, "kind": "mihomo",
               "proxy": "http://127.0.0.1:7890"}
        with mock.patch.object(dt, "resolve_transport", return_value=res):
            opener = dt.build_opener("mihomo")
        proxy_handlers = [h for h in opener.handlers
                          if isinstance(h, urllib.request.ProxyHandler)]
        self.assertTrue(proxy_handlers)
        self.assertEqual(proxy_handlers[0].proxies,
                         {"http": "http://127.0.0.1:7890",
                          "https": "http://127.0.0.1:7890"})

    def test_awg_opener_has_bound_handlers(self):
        res = {"ok": True, "kind": "awg", "device": "wg0"}
        with mock.patch.object(dt, "resolve_transport", return_value=res):
            opener = dt.build_opener("awg:wg0")
        https = [h for h in opener.handlers
                 if isinstance(h, dt._BoundHTTPSHandler)]
        http_ = [h for h in opener.handlers
                 if isinstance(h, dt._BoundHTTPHandler)]
        self.assertTrue(https and http_)
        self.assertEqual(https[0]._device, "wg0")


@unittest.skipUnless(hasattr(socket, "SO_BINDTODEVICE"),
                     "SO_BINDTODEVICE есть только на Linux")
class TestBindToDevice(unittest.TestCase):

    def test_setsockopt_called(self):
        sock = mock.Mock()
        dt._bind_to_device(sock, "wg0", socket.AF_INET)
        sock.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wg0\x00")

    def test_fallback_to_source_ip(self):
        # SO_BINDTODEVICE упал (EPERM без root) → bind на IPv4 интерфейса.
        sock = mock.Mock()
        sock.setsockopt.side_effect = OSError("EPERM")
        with mock.patch.object(dt, "_iface_ipv4", return_value="10.0.0.2"):
            dt._bind_to_device(sock, "wg0", socket.AF_INET)
        sock.bind.assert_called_once_with(("10.0.0.2", 0))

    def test_no_fallback_raises(self):
        sock = mock.Mock()
        sock.setsockopt.side_effect = OSError("EPERM")
        with mock.patch.object(dt, "_iface_ipv4", return_value=""):
            with self.assertRaises(OSError):
                dt._bind_to_device(sock, "wg0", socket.AF_INET)


class _FakeResponse:
    """Ответ для подмены opener.open / urlopen в download_file."""

    def __init__(self, data=b"DATA"):
        self._buf = io.BytesIO(data)
        self._len = len(data)

    def getheader(self, name):
        return str(self._len) if name == "Content-Length" else None

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestDownloadFileTransportWiring(unittest.TestCase):
    """download_file(transport=...) использует opener из download_transport."""

    def test_opener_used(self):
        import tempfile
        import os
        from core import binary_installer as bi

        fake_opener = mock.Mock()
        fake_opener.open.return_value = _FakeResponse(b"PAYLOAD")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("core.download_transport.build_opener",
                        return_value=fake_opener) as bo, \
             mock.patch("urllib.request.urlopen") as plain:
            dest = os.path.join(d, "out.bin")
            r = bi.download_file("https://github.com/o/r/x.bin", dest,
                                 transport="singbox:proxy")
            with open(dest, "rb") as f:
                payload = f.read()
        self.assertTrue(r["ok"], r)
        bo.assert_called_once_with("singbox:proxy")
        fake_opener.open.assert_called_once()
        plain.assert_not_called()
        self.assertEqual(payload, b"PAYLOAD")

    def test_unavailable_transport_is_error(self):
        import tempfile
        import os
        from core import binary_installer as bi

        with tempfile.TemporaryDirectory() as d, \
             mock.patch("core.download_transport.build_opener",
                        side_effect=RuntimeError("нет туннеля")):
            r = bi.download_file("https://github.com/o/r/x.bin",
                                 os.path.join(d, "o.bin"),
                                 transport="awg")
        self.assertFalse(r["ok"])
        self.assertIn("нет туннеля", r["error"])

    def test_direct_unaffected(self):
        import tempfile
        import os
        from core import binary_installer as bi

        with tempfile.TemporaryDirectory() as d, \
             mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse(b"X")) as plain, \
             mock.patch("core.download_transport.build_opener") as bo:
            r = bi.download_file("https://github.com/o/r/x.bin",
                                 os.path.join(d, "o.bin"))
        self.assertTrue(r["ok"], r)
        plain.assert_called_once()
        bo.assert_not_called()


class TestUrlopenVia(unittest.TestCase):

    def test_direct_uses_plain_urlopen(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=_FakeResponse()) as plain:
            dt.urlopen_via("https://example.org/x", transport="")
        plain.assert_called_once()

    def test_transport_uses_opener(self):
        fake_opener = mock.Mock()
        fake_opener.open.return_value = _FakeResponse()
        with mock.patch.object(dt, "build_opener",
                               return_value=fake_opener):
            dt.urlopen_via("https://example.org/x", transport="mihomo")
        fake_opener.open.assert_called_once()


class TestListTransports(unittest.TestCase):

    def test_direct_always_first(self):
        with mock.patch.object(dt, "_awg_candidates", return_value=[]), \
             mock.patch.object(dt, "_singbox_candidates", return_value=[]), \
             mock.patch.object(dt, "_mihomo_candidates", return_value=[]):
            r = dt.list_transports()
        self.assertTrue(r["ok"])
        self.assertEqual(r["transports"][0]["id"], "direct")
        self.assertEqual(len(r["transports"]), 1)

    def test_engine_candidates_appended(self):
        awg = [{"id": "awg:wg0", "kind": "awg", "device": "wg0",
                "label": "AWG: wg0"}]
        sb = [{"id": "singbox:a", "kind": "singbox", "name": "a",
               "proxy": "http://127.0.0.1:1080", "label": "sing-box: a"}]
        with mock.patch.object(dt, "_awg_candidates", return_value=awg), \
             mock.patch.object(dt, "_singbox_candidates", return_value=sb), \
             mock.patch.object(dt, "_mihomo_candidates", return_value=[]):
            r = dt.list_transports()
        ids = [t["id"] for t in r["transports"]]
        self.assertEqual(ids, ["direct", "awg:wg0", "singbox:a"])


if __name__ == "__main__":
    unittest.main()
