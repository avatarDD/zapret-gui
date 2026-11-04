"""Сборщик имён серверов (core/name_sniffer): BPF-фильтр, разбор, жизнь."""

import socket
import struct
import time
import unittest

from core import name_sniffer as ns
from core.testers.dpi_differential import build_client_hello


# ── пакеты ──

def ip4(proto, payload, src="192.168.1.10", dst="93.184.216.34", frag=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1,
                      frag, 64, proto, 0, socket.inet_aton(src),
                      socket.inet_aton(dst))
    return hdr + payload


def ip6(nh, payload, src="2001:db8::10", dst="2a00:1450::1"):
    hdr = struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, 64,
                      socket.inet_pton(socket.AF_INET6, src),
                      socket.inet_pton(socket.AF_INET6, dst))
    return hdr + payload


def tcp(dport, data, sport=40000, opts=b""):
    doff = (20 + len(opts)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, doff << 4, 0x18,
                       65535, 0, 0) + opts + data


def udp(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def dns_answer(name, ip, aaaa=False):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + \
        b"\x00"
    qtype = 28 if aaaa else 1
    rdata = socket.inet_pton(socket.AF_INET6 if aaaa else socket.AF_INET, ip)
    return (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q +
            struct.pack("!HH", qtype, 1) + b"\xc0\x0c" +
            struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata)


# ── мини-интерпретатор классического BPF (то, что делает ядро) ──

def run_bpf(prog, pkt):
    a = x = 0
    pc = 0

    def ld(off, size):
        if off + size > len(pkt):
            raise IndexError
        return int.from_bytes(pkt[off:off + size], "big")
    try:
        while True:
            code, jt, jf, k = prog[pc]
            pc += 1
            if code == ns._LDB_ABS:
                a = ld(k, 1)
            elif code == ns._LDH_ABS:
                a = ld(k, 2)
            elif code == ns._LDB_IND:
                a = ld(x + k, 1)
            elif code == ns._LDH_IND:
                a = ld(x + k, 2)
            elif code == ns._LDX_MSH:
                x = 4 * (ld(k, 1) & 0xF)
            elif code == ns._RSH_K:
                a >>= k
            elif code == ns._AND_K:
                a &= k
            elif code == ns._ADD_K:
                a += k
            elif code == ns._ADD_X:
                a += x
            elif code == ns._TAX:
                x = a
            elif code == ns._JA:
                pc += k
            elif code == ns._JEQ_K:
                pc += jt if a == k else jf
            elif code == ns._JSET_K:
                pc += jt if a & k else jf
            elif code == ns._RET_K:
                return k
            else:
                raise AssertionError("неизвестная инструкция %#x" % code)
    except IndexError:
        return 0                       # как в ядре: вылет за пакет — 0


class TestFilter(unittest.TestCase):

    def setUp(self):
        self.prog = ns.bpf_program()
        self.hello = build_client_hello("www.example.org")

    def ok(self, pkt):
        return run_bpf(self.prog, pkt) == ns.SNAPLEN

    def test_accepts_names(self):
        self.assertTrue(self.ok(ip4(6, tcp(443, self.hello))))
        self.assertTrue(self.ok(ip4(6, tcp(443, self.hello,
                                           opts=b"\x01" * 12))))
        self.assertTrue(self.ok(ip4(6, tcp(80, b"GET / HTTP/1.1\r\n"))))
        self.assertTrue(self.ok(ip4(17, udp(53, 5353,
                                            dns_answer("a.ru", "1.2.3.4")))))
        self.assertTrue(self.ok(ip6(6, tcp(443, self.hello))))
        self.assertTrue(self.ok(ip6(17, udp(53, 5353, b"x" * 20))))

    def test_drops_the_rest(self):
        self.assertFalse(self.ok(ip4(6, tcp(443, b"\x17\x03\x03data"))))
        self.assertFalse(self.ok(ip4(6, tcp(443, b""))))       # голый ACK
        self.assertFalse(self.ok(ip4(6, tcp(8443, self.hello))))
        self.assertFalse(self.ok(ip4(17, udp(5353, 53, b"query"))))
        self.assertFalse(self.ok(ip4(17, udp(443, 443, b"\xc0quic"))))
        self.assertFalse(self.ok(ip4(1, b"\x08\x00" + b"\x00" * 30)))
        self.assertFalse(self.ok(ip4(6, tcp(443, self.hello), frag=8)))
        self.assertFalse(self.ok(b"\x11\x00\x00\x10" + b"\x00" * 40))
        self.assertFalse(self.ok(b""))

    def test_jumps_fit(self):
        for _c, jt, jf, _k in self.prog:
            self.assertLessEqual(max(jt, jf), 255)


class TestParse(unittest.TestCase):

    def test_tls_sni_and_server_address(self):
        pkt = ip4(6, tcp(443, build_client_hello("WWW.Example.org")))
        self.assertEqual(ns.parse_packet(pkt),
                         [("93.184.216.34", "www.example.org")])
        pkt6 = ip6(6, tcp(443, build_client_hello("v6.example.org")))
        self.assertEqual(ns.parse_packet(pkt6),
                         [("2a00:1450::1", "v6.example.org")])

    def test_http_host_without_port(self):
        pkt = ip4(6, tcp(80, b"GET / HTTP/1.1\r\nHost: Site.example:8080"
                             b"\r\n\r\n"))
        self.assertEqual(ns.parse_packet(pkt),
                         [("93.184.216.34", "site.example")])

    def test_dns_answers(self):
        pkt = ip4(17, udp(53, 40000, dns_answer("api.example.com",
                                                "203.0.113.7")),
                  src="1.1.1.1", dst="192.168.1.10")
        self.assertEqual(ns.parse_packet(pkt),
                         [("203.0.113.7", "api.example.com")])
        pkt6 = ip6(17, udp(53, 40000, dns_answer("v6.example.com",
                                                 "2001:db8::7", aaaa=True)))
        self.assertEqual(ns.parse_packet(pkt6),
                         [("2001:db8::7", "v6.example.com")])

    def test_junk_is_empty(self):
        for pkt in (b"", b"\x45" * 10, ip4(6, tcp(443, b"\x16\x03\x01")),
                    ip4(6, tcp(80, b"POST / HTTP/1.1\r\nHost: 1.2.3.4\r\n")),
                    ip4(6, tcp(80, b"GET / HTTP/1.1\r\nHost: bad host\r\n")),
                    ip4(17, udp(53, 1, b"\x00" * 12)),
                    ip4(6, tcp(443, build_client_hello("x.org")), frag=8)):
            self.assertEqual(ns.parse_packet(pkt), [], pkt[:30])


class FakeSock:
    def __init__(self, packets):
        self.packets = list(packets)
        self.closed = False

    def recv(self, n):
        if self.packets:
            return self.packets.pop(0)
        time.sleep(0.01)
        raise socket.timeout()

    def close(self):
        self.closed = True


class TestSniffer(unittest.TestCase):

    def test_collects_and_stops_with_last_owner(self):
        got = []
        pkts = [ip4(6, tcp(443, build_client_hello("a.example.org"))),
                ip4(6, tcp(443, b"\x17"))]
        sock = FakeSock(pkts)
        s = ns.NameSniffer(remember=lambda p: (got.extend(p), len(p))[1],
                           opener=lambda: sock)
        self.assertTrue(s.start("geneva-auto"))
        self.assertTrue(s.start("other"))
        deadline = time.time() + 2
        while s.stats["packets"] < 2 and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(got, [("93.184.216.34", "a.example.org")])
        self.assertEqual(s.stats["names"], 1)
        s.stop("geneva-auto")
        self.assertTrue(s.running)              # второй владелец остался
        s.stop("other")
        self.assertFalse(s.running)
        self.assertTrue(sock.closed)

    def test_no_rights_is_not_fatal(self):
        def opener():
            raise PermissionError(1, "Operation not permitted")
        s = ns.NameSniffer(opener=opener)
        self.assertFalse(s.start())
        self.assertIn("not permitted", s.stats["error"])
        s.stop()
        self.assertFalse(s.running)


class TestObserverRunsSniffer(unittest.TestCase):

    def test_started_with_accounting_and_stopped_on_restore(self):
        import tempfile
        from core import geneva_auto_observer as ob

        class Fake:
            def __init__(self):
                self.calls = []

            def start(self, owner):
                self.calls.append(("start", owner))
                return True

            def stop(self, owner):
                self.calls.append(("stop", owner))

        fake = Fake()
        with tempfile.TemporaryDirectory() as d:
            o = ob.Observer(reader=lambda: [], sysctl_dir=d, sniffer=fake)
            self.assertTrue(o.enable_accounting()["names"])
            o.restore()
        self.assertEqual(fake.calls, [("start", "geneva-auto"),
                                      ("stop", "geneva-auto")])


@unittest.skipUnless(hasattr(socket, "AF_PACKET"), "Linux only")
class TestRealFilterAttaches(unittest.TestCase):
    """Ядро принимает программу (нужен CAP_NET_RAW, иначе пропуск)."""

    def test_attach(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                                 socket.htons(ns.ETH_P_ALL))
        except OSError:
            self.skipTest("нет прав на AF_PACKET")
        try:
            ns.attach_filter(sock, ns.bpf_program())
        finally:
            sock.close()


if __name__ == "__main__":
    unittest.main()
