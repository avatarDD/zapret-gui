"""Тесты AF_PACKET fallback в core/block_detector.py."""

import socket
import struct
import unittest
from unittest import mock

from core import block_detector as bd


def _build_dns_packet(domain: str, *, eth_type: int = 0x0800, proto: int = 17,
                      src_port: int = 12345, dst_port: int = 53) -> bytes:
    labels = domain.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    udp_len = 8 + len(dns)
    ip_len = 20 + udp_len
    eth = b"\x00" * 12 + struct.pack("!H", eth_type)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0, 64, proto, 0,
        socket.inet_aton("1.2.3.4"),
        socket.inet_aton("8.8.8.8"),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth + ip + udp + dns


class _FakeSock:
    def __init__(self, packets):
        self._packets = list(packets)
        self.closed = False

    def setblocking(self, _flag):
        return None

    def recv(self, _size):
        if not self._packets:
            raise BlockingIOError
        return self._packets.pop(0)

    def close(self):
        self.closed = True


class TestAfPacketSniffing(unittest.TestCase):

    def setUp(self):
        self.detector = bd.BlockDetector()

    @mock.patch("select.select")
    @mock.patch("socket.socket")
    def test_af_packet_parses_dns_query(self, mock_socket, mock_select):
        fake_sock = _FakeSock([_build_dns_packet("example.com")])
        mock_socket.return_value = fake_sock
        mock_select.side_effect = [([fake_sock], [], []), ([], [], [])]

        domains = self.detector._from_af_packet()
        self.assertIn("example.com", domains)

    @mock.patch("select.select")
    @mock.patch("socket.socket")
    def test_af_packet_ignores_non_dns_packets(self, mock_socket, mock_select):
        fake_sock = _FakeSock([
            _build_dns_packet("example.com", eth_type=0x86DD),  # не IPv4
            _build_dns_packet("example.org", proto=6),          # не UDP
        ])
        mock_socket.return_value = fake_sock
        mock_select.side_effect = [([fake_sock], [], []), ([fake_sock], [], []), ([], [], [])]

        domains = self.detector._from_af_packet()
        self.assertEqual(domains, [])

    @mock.patch("socket.socket", side_effect=PermissionError("raw sockets denied"))
    def test_af_packet_returns_empty_on_permission_error(self, mock_socket):
        domains = self.detector._from_af_packet()
        self.assertEqual(domains, [])

    @mock.patch("select.select")
    @mock.patch("socket.socket")
    def test_af_packet_deduplicates_and_limits_domains(self, mock_socket, mock_select):
        packets = [_build_dns_packet("example.com")] * 3
        packets += [_build_dns_packet("a%d.example.com" % i) for i in range(60)]
        fake_sock = _FakeSock(packets)
        mock_socket.return_value = fake_sock
        mock_select.side_effect = [([fake_sock], [], [])] * 64 + [([], [], [])]

        domains = self.detector._from_af_packet()
        self.assertLessEqual(len(domains), 50)
        self.assertIn("example.com", set(domains))


if __name__ == "__main__":
    unittest.main()
