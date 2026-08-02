"""Тесты временного SOCKS5, привязанного к интерфейсу.

Он нужен там, где обход есть, но локального прокси-порта у него нет:
AWG/WARP — это интерфейсы. Сторонний бинарник (`usque register`) умеет
только HTTPS_PROXY, поэтому мост «socks5 на loopback → SO_BINDTODEVICE»
и закрывает разрыв.
"""

import socket
import struct
import unittest
from unittest import mock

from core.iface_socks import IfaceSocksProxy, iface_supported


def _socks_request(port, host, dst_port=443):
    """Отправить SOCKS5 CONNECT и вернуть код ответа (REP)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return -1
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + struct.pack("!H", dst_port))
        rep = s.recv(10)
        return rep[1] if len(rep) > 1 else -1
    finally:
        s.close()


class TestIfaceSocksGuards(unittest.TestCase):

    def test_missing_iface_is_rejected(self):
        p = IfaceSocksProxy("")
        res = p.start()
        self.assertFalse(res["ok"])
        self.assertFalse(p.ok)

    def test_nonexistent_iface_is_rejected(self):
        p = IfaceSocksProxy("nosuchdev0")
        res = p.start()
        self.assertFalse(res["ok"])
        self.assertIn("nosuchdev0", res["error"])
        p.stop()

    def test_start_fails_when_kernel_cannot_bind(self):
        """Без прав молча уйти мимо туннеля нельзя — только явный отказ."""
        with mock.patch("core.iface_socks.iface_supported",
                        return_value=False):
            p = IfaceSocksProxy("lo")
            res = p.start()
        self.assertFalse(res["ok"])
        self.assertIn("root", res["error"])


@unittest.skipUnless(iface_supported(),
                     "SO_BINDTODEVICE недоступен (нужен root)")
class TestIfaceSocksBehaviour(unittest.TestCase):

    def setUp(self):
        self.proxy = IfaceSocksProxy(
            "lo", allow_hosts=["api.cloudflareclient.com"])
        res = self.proxy.start()
        if not res.get("ok"):
            self.skipTest("не удалось поднять форвардер: %s" % res.get("error"))
        self.addCleanup(self.proxy.stop)

    def test_listens_on_loopback_only(self):
        self.assertTrue(self.proxy.url.startswith("socks5://127.0.0.1:"))

    def test_host_outside_allowlist_is_refused(self):
        # REP=2 — connection not allowed by ruleset.
        self.assertEqual(_socks_request(self.proxy.port, "example.com"), 2)

    def test_allowlist_matching_is_case_insensitive(self):
        # Без сети: сам предикат правила. Живой прогон CONNECT к
        # разрешённому хосту здесь бессмыслен — сокет привязан к lo.
        self.assertTrue(self.proxy._allowed("API.CloudflareClient.com"))
        self.assertFalse(self.proxy._allowed("evil.example"))

    def test_no_allowlist_means_no_restriction(self):
        self.assertTrue(IfaceSocksProxy("lo")._allowed("anything.example"))

    def test_refused_request_is_not_counted_as_connection(self):
        _socks_request(self.proxy.port, "example.com")
        self.assertEqual(self.proxy.connections, 0)

    def test_stop_closes_the_listener(self):
        port = self.proxy.port
        self.proxy.stop()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2)


if __name__ == "__main__":
    unittest.main()
