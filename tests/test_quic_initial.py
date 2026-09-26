# tests/test_quic_initial.py
"""
QUIC Initial с ClientHello: криптография и проба.

Криптография своя (на роутере нет ``cryptography``), поэтому держится на
опубликованных векторах: ошибка в одном бите — и сервер молча выбросит
Initial, а подбор объявит «QUIC заблокирован» на каждой стратегии.

* AES-128 — FIPS-197 Appendix C.1;
* AES-128-GCM — NIST (McGrew & Viega) Test Case 2, 3, 4;
* ключи Initial и маска заголовка — RFC 9001 Appendix A.1/A.2.

Проба — на настоящих UDP-сокетах к фейковому серверу на 127.0.0.1: он
отвечает long header на Source Connection ID клиента, как сделал бы
QUIC-сервер. Совместимость пакета с настоящим стеком проверялась
сервером aioquic (ответ Initial с ServerHello, ALPN h3 согласован); в
тесты он не входит — лишняя зависимость.
"""

import socket
import struct
import threading
import unittest

from core.models import TestStatus as Status
from core.testers import quic_initial as q
from core.testers.quic_tester import test_quic_handshake as quic_handshake


class TestVectors(unittest.TestCase):

    def test_aes128_fips197(self):
        self.assertEqual(q.aes128_ecb_encrypt(
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_gcm_zero_key(self):
        self.assertEqual(
            q.aes128_gcm_encrypt(bytes(16), bytes(12), bytes(16), b"").hex(),
            "0388dace60b6a392f328c2b971b2fe78"
            "ab6e47d42cec13bdf53a67b21257bddf")

    def test_gcm_nist_case_3_and_4(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        out = q.aes128_gcm_encrypt(key, iv, pt, b"")
        self.assertEqual(out[:16].hex(), "42831ec2217774244b7221b784d0d49c")
        self.assertEqual(out[-16:].hex(), "4d5c2af327cd64a62cf35abd2ba6fab4")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        out = q.aes128_gcm_encrypt(key, iv, pt[:60], aad)
        self.assertEqual(out[-16:].hex(), "5bc94fbc3221a5db94fae95ae7121a47")

    def test_rfc9001_initial_keys(self):
        keys = q.client_initial_keys(bytes.fromhex("8394c8f03e515708"))
        self.assertEqual(keys["key"].hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(keys["iv"].hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(keys["hp"].hex(), "9f50449e04a0e810283a1e9933adedd2")

    def test_rfc9001_header_protection_mask(self):
        hp = bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")
        sample = bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b")
        self.assertEqual(q.aes128_ecb_encrypt(hp, sample)[:5].hex(),
                         "437b9aec36")


class TestPacket(unittest.TestCase):

    def test_datagram_is_a_padded_v1_initial(self):
        packet, dcid, scid = q.build_initial("www.youtube.com")
        self.assertEqual(len(packet), q.MIN_DATAGRAM)
        self.assertEqual(packet[0] & 0xB0, 0x80 | 0x00)   # long, Initial
        self.assertEqual(struct.unpack(">I", packet[1:5])[0], q.QUIC_V1)
        self.assertEqual(packet[6:6 + packet[5]], dcid)
        at = 6 + len(dcid)
        self.assertEqual(packet[at + 1:at + 1 + packet[at]], scid)

    def test_client_hello_carries_sni_and_h3(self):
        hello = q.build_client_hello("www.youtube.com", b"12345678")
        self.assertEqual(hello[0], 0x01)                  # ClientHello
        self.assertIn(b"www.youtube.com", hello)
        self.assertIn(b"\x02h3", hello)

    def test_reply_parsing_only_accepts_our_scid(self):
        scid = b"ABCDEFGH"
        ours = bytes([0xC0]) + struct.pack(">I", 1) + b"\x08" + scid
        theirs = bytes([0xC0]) + struct.pack(">I", 1) + b"\x08" + b"x" * 8
        self.assertEqual(q.parse_server_reply(ours + b"\x00" * 8, scid),
                         "initial")
        self.assertEqual(q.parse_server_reply(theirs + b"\x00" * 8, scid), "")
        vn = b"\x80" + bytes(4) + b"\x08" + scid + b"\x00" * 8
        self.assertEqual(q.parse_server_reply(vn, scid),
                         "version_negotiation")


class _FakeQuicServer:
    """UDP-сервер, отвечающий long header на SCID клиента (или чужой)."""

    def __init__(self, echo_scid=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.echo_scid = echo_scid
        self.got = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(5)
        try:
            data, peer = self.sock.recvfrom(4096)
        except OSError:
            return
        self.got.append(data)
        at = 6 + data[5]
        scid = data[at + 1:at + 1 + data[at]] if self.echo_scid \
            else b"z" * 8
        reply = (bytes([0xC0]) + struct.pack(">I", 1) + bytes([len(scid)])
                 + scid + b"\x08" + b"s" * 8 + b"\x00" * 32)
        self.sock.sendto(reply, peer)

    def close(self):
        self.sock.close()


class TestHandshakeProbe(unittest.TestCase):

    def test_reply_to_our_scid_is_success(self):
        server = _FakeQuicServer()
        self.addCleanup(server.close)
        res = quic_handshake("127.0.0.1", port=server.port, timeout=3,
                             retries=1, sni="www.youtube.com")
        self.assertEqual(res.status, Status.SUCCESS.value, res.details)
        # Сервер получил настоящий Initial: SNI в нём зашифрован, но
        # датаграмма — полноразмерная, с версией 1.
        self.assertEqual(len(server.got[0]), q.MIN_DATAGRAM)

    def test_foreign_reply_is_not_success(self):
        server = _FakeQuicServer(echo_scid=False)
        self.addCleanup(server.close)
        res = quic_handshake("127.0.0.1", port=server.port, timeout=2,
                             retries=1)
        self.assertEqual(res.status, Status.TIMEOUT.value)

    def test_missing_family_is_skipped(self):
        res = quic_handshake("127.0.0.1", port=443, timeout=1,
                             ip_family="ipv6")
        self.assertEqual(res.status, Status.SKIPPED.value)


if __name__ == "__main__":
    unittest.main()
