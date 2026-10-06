"""Метка собственных проб GUI (core/probe_mark.py) — приём d2k.

Главное, что сторожат тесты: помеченная проба либо действительно
помечена и действительно идёт мимо очереди, либо её нет вовсе. Замер
«без обхода», ушедший сквозь обход, — самоподтверждение, а не замер.
"""

import socket
import struct
import unittest
from unittest import mock

from core import probe_mark


class FakeSock:
    def __init__(self, stored=None, fail=False):
        self.stored = stored
        self.fail = fail
        self.closed = False

    def setsockopt(self, level, name, value):
        if self.fail:
            raise PermissionError("нет CAP_NET_ADMIN")
        if isinstance(value, bytes):
            # Как ядро: u32 из буфера (метка уходит упакованной).
            value = struct.unpack("I", value)[0]
        if self.stored is None:
            self.stored = value

    def getsockopt(self, level, name):
        return self.stored or 0

    def close(self):
        self.closed = True


class FakeFirewall:
    def __init__(self, rules):
        self.rules = rules

    def get_rules(self):
        return list(self.rules)


class TestApply(unittest.TestCase):

    def test_readback_must_match(self):
        self.assertTrue(probe_mark.apply(FakeSock(), 0x10000000))
        # setsockopt «прошёл», а метки на сокете другая — не верим.
        self.assertFalse(probe_mark.apply(FakeSock(stored=0x1), 0x10000000))

    def test_permission_error(self):
        self.assertFalse(probe_mark.apply(FakeSock(fail=True), 0x10000000))

    def test_zero_is_off(self):
        self.assertFalse(probe_mark.apply(FakeSock(), 0))

    def test_create_connection_refuses_unmarked(self):
        sock = FakeSock(fail=True)
        with mock.patch.object(probe_mark.socket, "socket",
                               return_value=sock), \
                mock.patch.object(probe_mark.socket, "getaddrinfo",
                                  return_value=[(socket.AF_INET,
                                                 socket.SOCK_STREAM, 6, "",
                                                 ("1.2.3.4", 443))]):
            with self.assertRaises(probe_mark.MarkError):
                probe_mark.create_connection(("1.2.3.4", 443), 1,
                                             mark=0x10000000)
        self.assertTrue(sock.closed)

    def test_create_connection_without_mark_is_plain(self):
        with mock.patch.object(probe_mark.socket, "create_connection",
                               return_value="plain") as plain:
            self.assertEqual(probe_mark.create_connection(("h", 1), 2),
                             "plain")
        plain.assert_called_once_with(("h", 1), timeout=2)


class TestRules(unittest.TestCase):

    def test_iptables_and_nft_forms(self):
        ipt = ["[ip4 mangle/POSTROUTING] 3 0 0 CONNMARK all -- * eth0 "
               "0.0.0.0/0 0.0.0.0/0 mark match 0x10000000/0x10000000 "
               "/* zapret-gui */ CONNMARK xset 0x20000000/0x20000000"]
        nft = ["meta mark & 0x10000000 == 0x10000000 ct mark set ct mark "
               "| 0x20000000"]
        self.assertTrue(probe_mark.rules_carry_mark(ipt, 0x10000000))
        self.assertTrue(probe_mark.rules_carry_mark(nft, 0x10000000))
        self.assertFalse(probe_mark.rules_carry_mark(
            ["NFQUEUE num 300 bypass"], 0x10000000))


class TestBaselineMode(unittest.TestCase):

    def _mode(self, rules, mark=0x10000000, supported=True):
        with mock.patch.object(probe_mark, "configured", return_value=mark), \
                mock.patch.object(probe_mark, "supported",
                                  return_value=supported):
            return probe_mark.baseline_mode(FakeFirewall(rules))

    def test_no_rules_means_direct(self):
        self.assertTrue(self._mode([])["marked"])

    def test_rules_with_exclusion(self):
        rules = ["mark match 0x10000000/0x10000000 CONNMARK xset "
                 "0x20000000/0x20000000", "NFQUEUE num 300"]
        self.assertTrue(self._mode(rules)["marked"])

    def test_old_rules_without_exclusion(self):
        # Правила старого автозапуска: метка ушла бы в очередь.
        mode = self._mode(["NFQUEUE num 300"])
        self.assertFalse(mode["marked"])
        self.assertIn("исключения проб", mode["reason"])

    def test_disabled_or_unsupported(self):
        self.assertFalse(self._mode([], mark=0)["marked"])
        self.assertFalse(self._mode([], supported=False)["marked"])


if __name__ == "__main__":
    unittest.main()
