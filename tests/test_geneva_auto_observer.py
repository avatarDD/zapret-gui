# tests/test_geneva_auto_observer.py
"""
Наблюдение режима «Авто» geneva (core/geneva_auto_observer.py).

Строки conntrack — в форматах, которые дают роутеры:

* OpenWrt (ядро 5.15/6.6, nft): ``ipv4 2 tcp 6 … zone=0 delta-time=…``,
  флаги ``[OFFLOAD]``/``[HW_OFFLOAD]`` при flow offloading;
* Keenetic (ядро 4.9, Entware): ``/proc/net/nf_conntrack`` без ``zone=``
  и ``delta-time=``, без учёта пакетов, пока не включён
  ``nf_conntrack_acct``;
* ``conntrack -L -o extended`` (conntrack-tools) и старый
  ``/proc/net/ip_conntrack`` без префикса семейства.

Ни root, ни сети: всё через подменяемые reader/names/local/capture.
"""

import os
import socket
import struct
import tempfile
import unittest
from unittest import mock

from core import block_detector as bd
from core import geneva_auto as ga
from core import geneva_auto_observer as ob
from core import pcap_reader

LAN = "192.168.1.10"
WAN = "81.200.10.5"


def tcp(state, dst, dport=443, src=LAN, sport=50432, op=None, ob_=None,
        rp=None, rb=None, flags="[ASSURED]", tail="mark=0 zone=0 use=2",
        delta=None, unreplied=False, rsrc=None, rdst=WAN):
    cnt_o = "" if op is None else " packets=%d bytes=%d" % (op, ob_)
    cnt_r = "" if rp is None else " packets=%d bytes=%d" % (rp, rb)
    unr = " [UNREPLIED]" if unreplied else ""
    d = "" if delta is None else " delta-time=%d" % delta
    return ("ipv4     2 tcp      6 299 %s src=%s dst=%s sport=%d dport=%d%s"
            "%s src=%s dst=%s sport=%d dport=%d%s %s %s%s"
            % (state, src, dst, sport, dport, cnt_o, unr, rsrc or dst, rdst,
               dport, sport, cnt_r, flags, tail, d))


def udp(dst, dport, src=LAN, sport=40000, op=None, ob_=None, rp=None,
        rb=None, unreplied=False, delta=None, rdst=WAN,
        tail="mark=0 zone=0 use=2"):
    cnt_o = "" if op is None else " packets=%d bytes=%d" % (op, ob_)
    cnt_r = "" if rp is None else " packets=%d bytes=%d" % (rp, rb)
    unr = " [UNREPLIED]" if unreplied else ""
    d = "" if delta is None else " delta-time=%d" % delta
    return ("ipv4     2 udp      17 25 src=%s dst=%s sport=%d dport=%d%s%s "
            "src=%s dst=%s sport=%d dport=%d%s %s%s"
            % (src, dst, sport, dport, cnt_o, unr, dst, rdst, dport, sport,
               cnt_r, tail, d))


# Реальные формы строк (адреса заменены: документационные диапазоны не «интернет»).
OPENWRT = (
    "ipv4     2 tcp      6 7438 ESTABLISHED src=192.168.1.149 "
    "dst=93.184.216.7 sport=52944 dport=443 packets=23 bytes=2779 "
    "src=93.184.216.7 dst=81.200.10.5 sport=443 dport=52944 packets=30 "
    "bytes=285130 [ASSURED] mark=0 zone=0 delta-time=41 use=2")
OPENWRT_OFFLOAD = (
    "ipv4     2 tcp      6 src=192.168.1.149 dst=93.184.216.8 sport=52950 "
    "dport=443 packets=5 bytes=900 src=93.184.216.8 dst=81.200.10.5 "
    "sport=443 dport=52950 packets=3 bytes=160 [OFFLOAD] mark=0 zone=0 "
    "use=3")
KEENETIC = (
    "ipv4     2 tcp      6 118 SYN_SENT src=192.168.1.33 dst=93.184.216.9 "
    "sport=61022 dport=443 [UNREPLIED] src=93.184.216.9 dst=81.200.10.5 "
    "sport=443 dport=61022 mark=0 use=2")
KEENETIC_UDP = (
    "ipv4     2 udp      17 29 src=192.168.1.33 dst=93.184.216.20 "
    "sport=51820 dport=51820 packets=3 bytes=444 [UNREPLIED] "
    "src=93.184.216.20 dst=81.200.10.5 sport=51820 dport=51820 packets=0 "
    "bytes=0 mark=0 use=2")
CONNTRACK_TOOL = (
    "ipv6     10 tcp      6 431999 ESTABLISHED src=2a02:6b8:1::10 "
    "dst=2a00:1450:4001::65 sport=40112 dport=443 packets=12 bytes=1800 "
    "src=2a00:1450:4001::65 dst=2a02:6b8:1::10 sport=443 dport=40112 "
    "packets=14 bytes=9800 [ASSURED] mark=0 secctx=system_u use=1")
IP_CONNTRACK = (
    "tcp      6 117 SYN_SENT src=10.0.0.5 dst=93.184.216.30 sport=1234 "
    "dport=80 [UNREPLIED] src=93.184.216.30 dst=10.0.0.1 sport=80 "
    "dport=1234 use=1")


def local():
    return ob.Local(own={WAN, "192.168.1.1"},
                    nets=[__import__("ipaddress").ip_network(
                        "2a02:6b8:1::/64")])


class TestParse(unittest.TestCase):

    def test_openwrt(self):
        c = ob.parse_line(OPENWRT)
        self.assertEqual((c.proto, c.state, c.src, c.dst, c.sport, c.dport),
                         ("tcp", "ESTABLISHED", "192.168.1.149",
                          "93.184.216.7", 52944, 443))
        self.assertEqual((c.opackets, c.obytes, c.rpackets, c.rbytes),
                         (23, 2779, 30, 285130))
        self.assertEqual((c.rsrc, c.rdst), ("93.184.216.7", WAN))
        self.assertTrue(c.assured)
        self.assertEqual(c.delta, 41.0)
        self.assertEqual(c.timeout, 7438)

    def test_offload_without_state_timeout(self):
        c = ob.parse_line(OPENWRT_OFFLOAD)
        self.assertTrue(c.offload)
        self.assertEqual(c.state, "")

    def test_keenetic_without_counters(self):
        c = ob.parse_line(KEENETIC)
        self.assertEqual(c.state, "SYN_SENT")
        self.assertTrue(c.unreplied)
        self.assertFalse(c.counted)
        self.assertIsNone(c.delta)
        self.assertEqual(c.zone, 0)

    def test_keenetic_udp(self):
        c = ob.parse_line(KEENETIC_UDP)
        self.assertEqual((c.proto, c.opackets, c.rpackets), ("udp", 3, 0))
        self.assertTrue(c.unreplied)

    def test_conntrack_tool_ipv6(self):
        c = ob.parse_line(CONNTRACK_TOOL)
        self.assertEqual(c.family, 6)
        self.assertEqual(c.dst, "2a00:1450:4001::65")
        self.assertEqual(c.rbytes, 9800)

    def test_old_ip_conntrack(self):
        c = ob.parse_line(IP_CONNTRACK)
        self.assertEqual((c.proto, c.state, c.dport), ("tcp", "SYN_SENT", 80))

    def test_garbage_and_icmp(self):
        self.assertIsNone(ob.parse_line(""))
        self.assertIsNone(ob.parse_line("hello world"))
        self.assertIsNone(ob.parse_line(
            "ipv4 2 icmp 1 29 src=1.1.1.1 dst=8.8.8.8 type=8 code=0 id=1 "
            "src=8.8.8.8 dst=1.1.1.1 type=0 code=0 id=1 mark=0 use=2"))
        self.assertIsNone(ob.parse_line("ipv4 2 tcp 6 10 ESTABLISHED src=x"))

    def test_mark_hex(self):
        c = ob.parse_line(tcp("ESTABLISHED", "93.184.216.7",
                              tail="mark=536870912 zone=0 use=2"))
        self.assertEqual(c.mark, 0x20000000)


class TestFilter(unittest.TestCase):

    def test_internet(self):
        for ip in ("10.0.0.1", "192.168.0.1", "100.64.1.1", "127.0.0.1",
                   "224.0.0.251", "169.254.1.1", "fe80::1", "ff02::1"):
            self.assertFalse(ob.is_internet(ip), ip)
        self.assertTrue(ob.is_internet("8.8.8.8"))
        self.assertTrue(ob.is_internet("2a00:1450:4001::65"))

    def skip(self, line, loc=None):
        return ob.skip_reason(ob.parse_line(line), loc or local())

    def test_kept(self):
        self.assertEqual(self.skip(OPENWRT), "")
        self.assertEqual(self.skip(CONNTRACK_TOOL), "")   # IPv6 из LAN

    def test_lan_and_inbound(self):
        self.assertEqual(self.skip(tcp("ESTABLISHED", "192.168.1.1")),
                         "not_internet")
        self.assertEqual(self.skip(tcp("ESTABLISHED", WAN,
                                       src="93.184.216.50")), "inbound")

    def test_router_itself(self):
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       src=WAN)), "")

    def test_own_marks_and_probe_ports(self):
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       tail="mark=0x20000000 use=2")),
                         "own_mark")
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       tail="mark=268435456 use=2")),
                         "own_mark")
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       src=WAN, sport=30010)), "probe_port")
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       sport=30600)), "")

    def test_redirect_and_tunnel(self):
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       rsrc="192.168.1.1",
                                       rdst=LAN)), "redirected")
        loc = local()
        loc.tunnel.add("172.16.0.2")
        self.assertEqual(self.skip(tcp("ESTABLISHED", "93.184.216.7",
                                       rdst="172.16.0.2"), loc), "tunnel")
        loc.exclude.add("162.159.192.1")
        self.assertEqual(self.skip(udp("162.159.192.1", 2408, src=WAN),
                                   loc), "excluded")

    def test_tunnel_servers_observed_and_labelled(self):
        """Сервер AWG/WG zapret-gui: подключение роутера к нему — тоже
        сервис «Авто» (geneva поможет, если его блокируют)."""
        loc = local()
        loc.servers.add("162.159.192.1")
        line = udp("162.159.192.1", 2408, src=WAN, op=3, ob_=444, rp=0,
                   rb=0, unreplied=True, delta=6)
        self.assertEqual(self.skip(line, loc), "")
        got = ob.build_samples(ob.parse_table([line]), 100.0, {}, local=loc)
        self.assertEqual(got[0].health, ga.FAILED)
        self.assertTrue(got[0].name.startswith("Туннель: "))

    def test_help_tunnels_off_excludes_servers(self):
        loc = local()
        loc.servers.add("162.159.192.1")
        o = ob.Observer(reader=lambda: [], local=lambda: loc)
        self.assertNotIn("162.159.192.1", o.local().exclude)
        o.help_tunnels = False
        self.assertIn("162.159.192.1", o.local().exclude)


class TestJudge(unittest.TestCase):

    def j(self, line, age, kind="", hung=False):
        return ob.judge(ob.parse_line(line), age, kind, hung)

    def test_syn_without_answer(self):
        line = tcp("SYN_SENT", "93.184.216.7", op=2, ob_=120, rp=0, rb=0,
                   unreplied=True, flags="")
        self.assertIsNone(self.j(line, 2))
        self.assertEqual(self.j(line, 3)[0], ga.NO_CONNECTION)
        one = tcp("SYN_SENT", "93.184.216.7", op=1, ob_=60, rp=0, rb=0,
                  unreplied=True, flags="")
        self.assertIsNone(self.j(one, 10))      # SYN ещё не повторён
        self.assertEqual(self.j(KEENETIC, 5)[0], ga.NO_CONNECTION)

    def test_established_no_data(self):
        # SYN, ACK, ClientHello и его повторы — ответ только SYN-ACK
        line = tcp("ESTABLISHED", "93.184.216.7", op=5, ob_=2300, rp=1,
                   rb=60)
        self.assertIsNone(self.j(line, 4))
        self.assertEqual(self.j(line, 6),
                         (ga.FAILED, "соединение есть, данных нет"))

    def test_quiet_non_web_server_is_not_stalled(self):
        # не веб, клиент не повторял: долгий опрос, а не DPI
        line = tcp("ESTABLISHED", "93.184.216.7", dport=5222, op=3,
                   ob_=300, rp=2, rb=104)
        self.assertIsNone(self.j(line, 30))

    def test_success(self):
        self.assertEqual(self.j(OPENWRT, 41), (ga.OK, ""))
        small = tcp("ESTABLISHED", "93.184.216.7", op=4, ob_=600, rp=4,
                    rb=900)
        self.assertEqual(self.j(small, 6), (ga.OK, ""))

    def test_reset(self):
        line = tcp("CLOSE", "93.184.216.7", op=3, ob_=700, rp=2, rb=100)
        self.assertEqual(self.j(line, 1),
                         (ga.FAILED, "сброс соединения (RST)"))
        refused = tcp("CLOSE", "93.184.216.7", op=1, ob_=60, rp=1, rb=40)
        self.assertIsNone(self.j(refused, 1))   # порт закрыт: не DPI

    def test_cutoff_16k(self):
        line = tcp("ESTABLISHED", "93.184.216.7", op=20, ob_=2000, rp=14,
                   rb=16000)
        self.assertIsNone(self.j(line, 10))
        self.assertEqual(self.j(line, 10, hung=True),
                         (ga.FAILED, "обрыв на 16 КБ"))

    def test_offload_hides_counters(self):
        self.assertIsNone(self.j(OPENWRT_OFFLOAD, 30))
        big = OPENWRT_OFFLOAD.replace("packets=3 bytes=160",
                                      "packets=40 bytes=60000")
        self.assertEqual(self.j(big, 30), (ga.OK, ""))

    def test_fin_states(self):
        line = tcp("TIME_WAIT", "93.184.216.7", op=6, ob_=800, rp=5,
                   rb=1200)
        self.assertEqual(self.j(line, 20), (ga.OK, ""))

    def test_udp(self):
        self.assertEqual(self.j(KEENETIC_UDP, 6),
                         (ga.FAILED, "запросы без ответа"))
        self.assertIsNone(self.j(KEENETIC_UDP, 3))
        once = udp("93.184.216.20", 51820, op=1, ob_=176, rp=0, rb=0,
                   unreplied=True)
        self.assertIsNone(self.j(once, 10))     # клиент спросил один раз
        dns = udp("93.184.216.53", 53, op=1, ob_=60, rp=0, rb=0,
                  unreplied=True)
        self.assertEqual(self.j(dns, 6, ga.DNS)[0], ga.FAILED)
        answered = udp("93.184.216.53", 53, op=1, ob_=60, rp=1, rb=120)
        self.assertEqual(self.j(answered, 0, ga.DNS), (ga.OK, ""))

    def test_udp_without_counters(self):
        line = udp("93.184.216.53", 53, unreplied=True)
        self.assertEqual(self.j(line, 6, ga.DNS)[0], ga.FAILED)
        self.assertEqual(self.j(udp("93.184.216.53", 53), 1)[0], ga.OK)


class TestClassify(unittest.TestCase):

    def cl(self, line, **kw):
        return ob.classify(ob.parse_line(line), **kw)

    def test_web(self):
        kind, key, shown, app = self.cl(OPENWRT, name="rr3.cdn.youtube.com")
        self.assertEqual((kind, key, shown, app),
                         (ga.WEB, "web:youtube.com", "youtube.com", "tls"))

    def test_quic(self):
        kind, key, _s, app = self.cl(udp("93.184.216.7", 443),
                                     name="www.example.co.uk")
        self.assertEqual((kind, key, app),
                         (ga.QUIC, "quic:example.co.uk", "quic"))

    def test_dns(self):
        kind, key, _s, _a = self.cl(udp("93.184.216.53", 53))
        self.assertEqual((kind, key), (ga.DNS, "dns:93.184.216.53"))

    def test_endpoint(self):
        kind, key, shown, app = self.cl(KEENETIC_UDP)
        self.assertEqual((kind, key, app),
                         (ga.ENDPOINT, "ep:udp:udp:93.184.216.20:51820",
                          "udp"))
        kind, key, shown, _ = self.cl(KEENETIC_UDP, app="wireguard",
                                      name="vpn.example.net")
        self.assertEqual(key, "ep:wireguard:udp:93.184.216.20:51820")
        self.assertIn("WireGuard vpn.example.net", shown)
        # TCP 443 без имени — сервер по адресу
        self.assertEqual(self.cl(tcp("ESTABLISHED", "93.184.216.7"))[0],
                         ga.ENDPOINT)

    def test_ipv6_endpoint(self):
        _k, key, _s, _a = self.cl(CONNTRACK_TOOL)
        self.assertEqual(key, "ep:tcp:tcp:[2a00:1450:4001::65]:443")

    def test_dht_and_p2p(self):
        kind, key, shown, app = self.cl(udp("93.184.216.9", 6881,
                                            sport=6881), p2p=True)
        self.assertEqual((kind, key, app),
                         (ga.LOCAL_PORT, "port:udp:%s:6881" % LAN, "p2p"))
        self.assertEqual(self.cl(udp("93.184.216.9", 6881, sport=6881),
                                 app="dht")[3], "dht")

    def test_fanout(self):
        conns = [ob.parse_line(udp("93.184.216.%d" % i, 6881, sport=6881))
                 for i in range(1, ob.P2P_FANOUT + 1)]
        conns.append(ob.parse_line(udp("93.184.216.200", 443, sport=5000)))
        self.assertEqual(ob.fanout_ports(conns), {(LAN, 6881)})
        self.assertEqual(ob.fanout_ports(conns[:-2]), set())


def _qname(name):
    return b"".join(bytes([len(x)]) + x.encode()
                    for x in name.split(".")) + b"\0"


class TestFirstPacket(unittest.TestCase):

    def test_openvpn(self):
        udp_reset = bytes([7 << 3]) + os.urandom(8) + b"\0" * 5
        self.assertTrue(ob.is_openvpn(udp_reset, False))
        self.assertEqual(ob.detect_app(udp_reset, "udp"), "openvpn")
        tcp_reset = struct.pack(">H", 14) + bytes([10 << 3]) + b"\1" * 13
        self.assertTrue(ob.is_openvpn(tcp_reset, True))
        self.assertFalse(ob.is_openvpn(bytes([7 << 3 | 1]) + b"\0" * 13,
                                       False))

    def test_dht(self):
        q = b"d1:ad2:id20:" + b"a" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"
        self.assertTrue(ob.is_dht(q))
        self.assertEqual(ob.detect_app(q, "udp"), "dht")
        self.assertFalse(ob.is_dht(b"d1:x1:ye"))

    def test_wireguard_stun_dns_quic(self):
        self.assertEqual(ob.detect_app(b"\x01\0\0\0" + b"\0" * 144, "udp"),
                         "wireguard")
        stun = struct.pack(">HHI", 1, 0, 0x2112A442) + os.urandom(12)
        self.assertEqual(ob.detect_app(stun, "udp"), "stun")
        self.assertFalse(ob.is_ice_check(stun))
        ice = struct.pack(">HHI", 1, 8, 0x2112A442) + os.urandom(12) + \
            struct.pack(">HH", 6, 4) + b"user"
        self.assertTrue(ob.is_ice_check(ice))
        self.assertFalse(ob.can_replay("stun", [ice]))
        self.assertTrue(ob.can_replay("stun", [stun]))
        dns = struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + \
            _qname("example.com") + b"\0\1\0\1"
        self.assertEqual(ob.detect_app(dns, "udp"), "dns")
        quic = bytes([0xC3]) + struct.pack(">I", 1) + os.urandom(1195)
        self.assertEqual(ob.detect_app(quic, "udp"), "quic")
        self.assertEqual(ob.detect_app(b"\0" * 10, "udp"), "")

    def test_tcp(self):
        self.assertEqual(ob.detect_app(b"GET / HTTP/1.1\r\nHost: a\r\n",
                                       "tcp"), "http")
        self.assertEqual(ob.detect_app(_client_hello("x.example"), "tcp"),
                         "tls")

    def test_replayable_only(self):
        self.assertFalse(ob.can_replay("wireguard", [b"x"]))
        self.assertFalse(ob.can_replay("http", [b"GET"]))
        self.assertTrue(ob.can_replay("openvpn", [b"x"]))


def _client_hello(sni):
    name = sni.encode()
    ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0,
                      len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\0" + b"\x00\x02\x13\x01" + \
        b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _ip4_udp(src, dst, sport, dport, payload):
    udp_h = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), 0, 0, 64,
                     17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + udp_h + payload


def _ip4_tcp(src, dst, sport, dport, seq, flags, payload=b""):
    tcp_h = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                        65535, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64,
                     6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp_h + payload


def _pcap(frames, linktype=101):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for k, f in enumerate(frames):
        out += struct.pack("<IIII", 1000 + k, 0, len(f), len(f)) + f
    return out


class TestCapture(unittest.TestCase):

    def test_pcap_payloads(self):
        rep = pcap_reader.read_bytes(_pcap([_ip4_udp(LAN, "93.184.216.1",
                                                     1, 2, b"abc")]),
                                     payloads=True)
        self.assertEqual(rep["packets"][0]["payload"], b"abc")
        rep = pcap_reader.read_bytes(_pcap([_ip4_udp(LAN, "93.184.216.1",
                                                     1, 2, b"abc")]))
        self.assertNotIn("payload", rep["packets"][0])

    def test_openvpn_replay_deduplicates_nat_copies(self):
        reset = bytes([7 << 3]) + b"\x11" * 13
        srv = "93.184.216.40"
        frames = [_ip4_udp(LAN, srv, 5000, 1194, reset),     # LAN-сторона
                  _ip4_udp(WAN, srv, 5000, 1194, reset),     # после NAT
                  _ip4_udp(srv, WAN, 1194, 5000, b"answer")]
        pk = pcap_reader.read_bytes(_pcap(frames), payloads=True)["packets"]
        res = ob.analyze_capture(pk, srv, 1194, "udp")
        self.assertEqual(res["app"], "openvpn")
        self.assertEqual(res["replay"], [reset])
        self.assertEqual(res["src"], LAN)

    def test_wireguard_not_replayed(self):
        init = b"\x01\0\0\0" + os.urandom(144)
        srv = "93.184.216.41"
        pk = pcap_reader.read_bytes(_pcap([_ip4_udp(LAN, srv, 5001, 51820,
                                                    init)]),
                                    payloads=True)["packets"]
        res = ob.analyze_capture(pk, srv, 51820, "udp")
        self.assertEqual((res["app"], res["replay"]), ("wireguard", []))

    def test_tls_sni_and_replay(self):
        srv = "93.184.216.42"
        hello = _client_hello("blocked.example.org")
        frames = [_ip4_tcp(LAN, srv, 6000, 8443, 1, 0x02),
                  _ip4_tcp(LAN, srv, 6000, 8443, 2, 0x18, hello[:40]),
                  _ip4_tcp(WAN, srv, 6000, 8443, 2, 0x18, hello[:40]),
                  _ip4_tcp(LAN, srv, 6000, 8443, 42, 0x18, hello[40:]),
                  # Finished и данные сессии в повтор не идут
                  _ip4_tcp(LAN, srv, 6000, 8443, 42 + len(hello) - 40, 0x18,
                           b"\x14\x03\x03\x00\x01\x01")]
        pk = pcap_reader.read_bytes(_pcap(frames), payloads=True)["packets"]
        res = ob.analyze_capture(pk, srv, 8443, "tcp")
        self.assertEqual(res["app"], "tls")
        self.assertEqual(res["host"], "blocked.example.org")
        self.assertEqual(res["replay"], [hello])

    def test_dht_by_local_port(self):
        q = b"d1:ad2:id20:" + b"a" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"
        frames = [_ip4_udp(LAN, "93.184.216.%d" % i, 6881, 6881, q)
                  for i in (1, 2)]
        pk = pcap_reader.read_bytes(_pcap(frames), payloads=True)["packets"]
        res = ob.analyze_capture(pk, "", 0, "udp", local_port=6881)
        self.assertEqual((res["app"], res["replay"]), ("dht", []))


class TestBuildSamples(unittest.TestCase):

    def run_slice(self, lines, now, tracks, **kw):
        return ob.build_samples(ob.parse_table(lines), now, tracks,
                                local=local(), **kw)

    def test_one_verdict_per_tcp_connection(self):
        tracks = {}
        syn = tcp("SYN_SENT", "93.184.216.7", op=2, ob_=120, rp=0, rb=0,
                  unreplied=True, flags="", delta=4)
        s1 = self.run_slice([syn], 100.0, tracks,
                            names={"93.184.216.7": "www.blocked.example"})
        self.assertEqual(len(s1), 1)
        self.assertEqual((s1[0].key, s1[0].health, s1[0].time),
                         ("web:blocked.example", ga.NO_CONNECTION, 96.0))
        self.assertEqual(s1[0].host, "www.blocked.example")
        # тот же SYN в следующем срезе — не второй провал
        self.assertEqual(self.run_slice([syn], 115.0, tracks), [])
        # соединение ушло из таблицы — память чистится
        self.run_slice([], 130.0, tracks)
        self.assertEqual(tracks, {})

    def test_failure_then_success_corrects(self):
        tracks = {}
        stall = tcp("ESTABLISHED", "93.184.216.7", op=5, ob_=2300, rp=1,
                    rb=60, delta=6)
        self.assertEqual(self.run_slice([stall], 100.0, tracks)[0].health,
                         ga.FAILED)
        ok = tcp("ESTABLISHED", "93.184.216.7", op=9, ob_=2600, rp=12,
                 rb=40000, delta=21)
        got = self.run_slice([ok], 115.0, tracks)
        self.assertEqual([s.health for s in got], [ga.OK])
        self.assertEqual(self.run_slice([ok], 130.0, tracks), [])

    def test_cutoff_detected_across_slices(self):
        tracks = {}
        a = tcp("ESTABLISHED", "93.184.216.7", op=20, ob_=2000, rp=14,
                rb=16000, delta=5)
        self.assertEqual(self.run_slice([a], 100.0, tracks), [])
        b = tcp("ESTABLISHED", "93.184.216.7", op=26, ob_=2400, rp=14,
                rb=16000, delta=20)
        got = self.run_slice([b], 115.0, tracks)
        self.assertEqual([(s.health, s.why) for s in got],
                         [(ga.FAILED, "обрыв на 16 КБ")])

    def test_long_udp_judged_per_slice(self):
        tracks = {}
        srv = "93.184.216.20"
        first = udp(srv, 51820, op=3, ob_=444, rp=2, rb=200, delta=1)
        self.assertEqual(self.run_slice([first], 100.0, tracks)[0].health,
                         ga.OK)
        # за срез клиент послал 5, ответа нет — провал со временем среза
        dead = udp(srv, 51820, op=8, ob_=1200, rp=2, rb=200, delta=16)
        got = self.run_slice([dead], 115.0, tracks)
        self.assertEqual([(s.health, s.time) for s in got],
                         [(ga.FAILED, 115.0)])
        self.assertEqual(got[0].key, "ep:udp:udp:93.184.216.20:51820")

    def test_age_without_delta_time(self):
        tracks = {}
        line = udp("93.184.216.53", 53, op=1, ob_=60, rp=0, rb=0,
                   unreplied=True)
        self.assertEqual(self.run_slice([line], 100.0, tracks), [])
        got = self.run_slice([line], 115.0, tracks)
        self.assertEqual([(s.key, s.health) for s in got],
                         [("dns:93.184.216.53", ga.FAILED)])

    def test_skips_counted(self):
        stats = {}
        self.run_slice([tcp("ESTABLISHED", "192.168.1.1"),
                        tcp("ESTABLISHED", "93.184.216.7",
                            tail="mark=0x20000000 use=1"), OPENWRT],
                       100.0, {}, stats=stats)
        self.assertEqual(stats["connections"], 3)
        self.assertEqual(stats["observed"], 1)
        self.assertEqual(stats["skipped"],
                         {"not_internet": 1, "own_mark": 1})

    def test_sticky_endpoint_key(self):
        tracks, sticky = {}, {}
        line = udp("93.184.216.20", 51820, op=3, ob_=444, rp=0, rb=0,
                   unreplied=True, delta=6)
        s1 = self.run_slice([line], 100.0, tracks, sticky=sticky)
        line2 = udp("93.184.216.20", 51820, sport=40001, op=3, ob_=444,
                    rp=0, rb=0, unreplied=True, delta=6)
        s2 = self.run_slice([line2], 115.0, tracks, sticky=sticky,
                            learned={("udp", "93.184.216.20", 51820):
                                     ("wireguard", "")})
        self.assertEqual(s1[0].key, s2[0].key)
        self.assertEqual(s2[0].app, "wireguard")

    def test_book_reaches_suspicion(self):
        """Срезы conntrack доводят заблокированный резолвер до подозрения."""
        tracks = {}
        book = ga.Book()
        lines = [udp("93.184.216.53", 53, sport=41000 + i, op=1, ob_=60,
                     rp=0, rb=0, unreplied=True, delta=6) for i in range(3)]
        book.feed(self.run_slice(lines, 100.0, tracks), 100.0)
        book.evaluate(100.0)
        s = book.find("dns:93.184.216.53")
        self.assertEqual(s.status, ga.SUSPECTED)


class TestObserverIO(unittest.TestCase):

    def test_check_custom_and_missing(self):
        o = ob.Observer(reader=lambda: [])
        self.assertEqual(o.check()["source"], "custom")
        with tempfile.TemporaryDirectory() as d:
            o = ob.Observer(sysctl_dir=d)
            with mock.patch.object(ob, "CONNTRACK_FILES",
                                            (os.path.join(d, "none"),)), \
                    mock.patch.object(ob.Observer,
                                               "_conntrack_binary",
                                               staticmethod(lambda: "")):
                with self.assertRaises(ob.ObserverError) as e:
                    o.check()
                self.assertEqual(e.exception.code, "conntrack_unsupported")
                open(os.path.join(d, "nf_conntrack_max"), "w").close()
                with self.assertRaises(ob.ObserverError) as e:
                    o.check()
                self.assertEqual(e.exception.code, "conntrack_tool_missing")
                self.assertIn("conntrack", e.exception.hint)

    def test_accounting_enabled_and_restored(self):
        with tempfile.TemporaryDirectory() as d:
            for name, val in (("nf_conntrack_acct", "0"),
                              ("nf_conntrack_timestamp", "1")):
                with open(os.path.join(d, name), "w") as f:
                    f.write(val + "\n")
            o = ob.Observer(reader=lambda: [], sysctl_dir=d)
            self.assertEqual(o.enable_accounting(),
                             {"nf_conntrack_acct": True,
                              "nf_conntrack_timestamp": True})
            self.assertEqual(open(os.path.join(d, "nf_conntrack_acct"))
                             .read(), "1")
            self.assertEqual(o.saved_sysctls, {"nf_conntrack_acct": "0"})
            o.restore()
            self.assertEqual(open(os.path.join(d, "nf_conntrack_acct"))
                             .read(), "0")
            self.assertEqual(open(os.path.join(d, "nf_conntrack_timestamp"))
                             .read().strip(), "1")
            self.assertEqual(o.saved_sysctls, {})

    def test_slice_and_identify(self):
        srv = "93.184.216.40"
        reset = bytes([7 << 3]) + b"\x11" * 13
        frames = [_ip4_udp(LAN, srv, 5000, 1194, reset)]
        pk = pcap_reader.read_bytes(_pcap(frames), payloads=True)["packets"]
        lines = [udp(srv, 1194, sport=5000, op=3, ob_=200, rp=0, rb=0,
                     unreplied=True, delta=8)]
        o = ob.Observer(reader=lambda: lines, names=lambda: {},
                        local=local, clock=lambda: 100.0,
                        capture=lambda h, p, t: {"packets": pk})
        o.check()
        got = o.slice()
        self.assertEqual(got[0].key, "ep:udp:udp:93.184.216.40:1194")
        self.assertEqual(o.last_stats["samples"], 1)
        res = o.identify(srv, 1194, "udp")
        self.assertEqual((res["app"], res["replay"]), ("openvpn", [reset]))
        # следующий срез: протокол узнан, ключ прежний
        lines[0] = udp(srv, 1194, sport=5001, op=3, ob_=200, rp=0, rb=0,
                       unreplied=True, delta=8)
        got = o.slice(115.0)
        self.assertEqual((got[0].key, got[0].app),
                         ("ep:udp:udp:93.184.216.40:1194", "openvpn"))

    def test_identify_dht_learns_port(self):
        q = b"d1:ad2:id20:" + b"a" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"
        pk = pcap_reader.read_bytes(_pcap([_ip4_udp(LAN, "93.184.216.9",
                                                    6881, 6881, q)]),
                                    payloads=True)["packets"]
        lines = [udp("93.184.216.%d" % i, 7000 + i, sport=6881, op=2,
                     ob_=200, rp=0, rb=0, unreplied=True, delta=8)
                 for i in (1, 2)]
        o = ob.Observer(reader=lambda: lines, names=lambda: {},
                        local=local, capture=lambda h, p, t: {"packets": pk})
        res = o.identify("93.184.216.9", 6881, "udp")
        self.assertEqual(res["app"], "dht")
        keys = {s.key for s in o.slice(100.0)}
        self.assertEqual(keys, {"port:udp:%s:6881" % LAN})

    def test_conntrack_tool_reads_both_families(self):
        calls = []

        def fake_run(argv, timeout=10):
            calls.append(argv)
            return 0, OPENWRT if "ipv6" not in argv else CONNTRACK_TOOL

        o = ob.Observer(local=local, names=lambda: {})
        o.source = "/usr/sbin/conntrack"
        with mock.patch.object(ob, "_run", fake_run):
            lines = o._lines()
        self.assertEqual(len(lines), 2)
        self.assertIn(["/usr/sbin/conntrack", "-L", "-f", "ipv6", "-o",
                       "extended"], calls)

    def test_seed_keys(self):
        o = ob.Observer(reader=lambda: [])
        o.seed_keys(["ep:wireguard:udp:93.184.216.20:51820",
                     "ep:tcp:tcp:[2a00:1450:4001::65]:443", "web:x.com"])
        self.assertEqual(o._sticky[("udp", "93.184.216.20", 51820)],
                         "ep:wireguard:udp:93.184.216.20:51820")
        self.assertIn(("tcp", "2a00:1450:4001::65", 443), o._sticky)

    def test_parse_ip_addr_and_endpoints(self):
        text = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\ ...\n"
            "5: br0    inet 192.168.1.1/24 brd 192.168.1.255 scope global\n"
            "5: br0    inet6 2a02:6b8:1::1/64 scope global\n"
            "7: ppp0    inet 81.200.10.5 peer 10.0.0.1/32 scope global\n"
            "7: ppp0    inet6 2a02:6b8:ffff::5/64 scope global\n"
            "9: awg0    inet 172.16.0.2/32 scope global awg0\n"
            "10: nwg1    inet6 2606:4700:110::2/128 scope global\n")
        loc = ob.parse_ip_addr(text, wan=["ppp0"])
        self.assertIn("192.168.1.1", loc.own)
        self.assertEqual(loc.tunnel, {"172.16.0.2", "2606:4700:110::2"})
        self.assertEqual([str(n) for n in loc.nets], ["2a02:6b8:1::/64"])
        self.assertTrue(ob.is_local_client("2a02:6b8:1::77", loc))
        self.assertFalse(ob.is_local_client("2a02:6b8:ffff::77", loc))
        eps = ob.parse_wg_endpoints(
            "awg0\tpk1=\t162.159.192.1:2408\n"
            "awg1\tpk2=\t[2606:4700:d0::a29f:c001]:500\n"
            "awg2\tpk3=\t(none)\n")
        self.assertEqual(eps, {"162.159.192.1", "2606:4700:d0::a29f:c001"})


class TestDnsNames(unittest.TestCase):

    def setUp(self):
        bd.forget_names()

    def tearDown(self):
        bd.forget_names()

    def test_dnsmasq_cname_chain(self):
        lines = [
            "Nov  3 query[A] www.example.com from 192.168.1.10",
            "Nov  3 reply www.example.com is <CNAME>",
            "Nov  3 reply cdn.example.net is 93.184.216.7",
            "Nov  3 query[A] other.org from 192.168.1.10",
            "Nov  3 reply other.org is 93.184.216.8",
        ]
        self.assertEqual(bd.parse_dnsmasq_replies(lines),
                         [("93.184.216.7", "www.example.com"),
                          ("93.184.216.8", "other.org")])

    def test_dns_answers(self):
        q = _qname("www.example.com")
        msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 2, 0, 0) + q + \
            b"\0\1\0\1" + \
            b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + \
            socket.inet_aton("93.184.216.7") + \
            b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 60, 16) + \
            socket.inet_pton(socket.AF_INET6, "2001:db8::7")
        self.assertEqual(bd.parse_dns_answers(msg),
                         [("93.184.216.7", "www.example.com"),
                          ("2001:db8::7", "www.example.com")])
        self.assertEqual(bd.parse_dns_answers(msg[:20]), [])
        query = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + q
        self.assertEqual(bd.parse_dns_answers(query), [])

    def test_name_map(self):
        bd.remember_names([("93.184.216.7", "WWW.Example.COM."),
                           ("bad", "x.com"), ("93.184.216.8", "nas.lan")],
                          now=1000.0)
        self.assertEqual(bd.ip_names(now=1000.0),
                         {"93.184.216.7": "www.example.com"})
        self.assertEqual(bd.ip_names(now=1000.0 + bd.NAMES_LIFE + 1), {})

    def test_refresh_names_uses_detector_source(self):
        det = bd.BlockDetector()
        calls = []

        def collect():
            calls.append(1)
            bd.remember_names([("93.184.216.9", "a.example.org")])
            return []

        det._collect_dns_queries = collect
        det._get_dns_source = lambda: "dnsmasq_log"
        self.assertEqual(det.refresh_names(), {"93.184.216.9": "a.example.org"})
        det.refresh_names()                     # чаще min_interval — кеш
        self.assertEqual(len(calls), 1)

    def test_refresh_names_without_af_packet_is_quiet(self):
        det = bd.BlockDetector()
        det._get_dns_source = lambda: "af_packet"
        det._af_packet_available = lambda: False
        det._collect_dns_queries = lambda: self.fail("сбор без AF_PACKET")
        self.assertEqual(det.refresh_names(), {})

    def test_dnsmasq_cached(self):
        self.assertEqual(bd.parse_dnsmasq_replies(
            ["Nov  3 cached x.example.org is 93.184.216.7"]),
            [("93.184.216.7", "x.example.org")])


if __name__ == "__main__":
    unittest.main()


class TestOffload(unittest.TestCase):

    def test_openwrt_config(self):
        on = ("config defaults\n\toption syn_flood '1'\n"
              "\toption flow_offloading '1'\n\nconfig zone\n"
              "\toption name 'lan'\n")
        self.assertTrue(ob.openwrt_offload(on))
        self.assertTrue(ob.openwrt_offload(
            "config defaults\n\toption flow_offloading_hw \"1\"\n"))
        self.assertFalse(ob.openwrt_offload(
            "config defaults\n\toption flow_offloading '0'\n"))
        # чужая секция — не offload роутера
        self.assertFalse(ob.openwrt_offload(
            "config zone\n\toption flow_offloading '1'\n"))
        self.assertFalse(ob.openwrt_offload(""))

    def test_from_slice_or_file(self):
        import tempfile
        self.assertTrue(ob.offload_enabled({"offload": 3}, path="/nonexistent"))
        self.assertFalse(ob.offload_enabled({"offload": 0},
                                            path="/nonexistent"))
        with tempfile.NamedTemporaryFile("w", suffix=".cfg") as f:
            f.write("config defaults\n\toption flow_offloading '1'\n")
            f.flush()
            self.assertTrue(ob.offload_enabled({}, path=f.name))
