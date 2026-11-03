# tests/test_geneva_auto_probes.py
"""
Пробы режима «Авто» geneva (core/geneva_auto_probes.py).

Сеть не нужна: настоящие сокеты против серверов на 127.0.0.1 (HTTP,
эхо UDP/TCP, сброс, молчание, обрыв), вердикты и fitness — чистыми
функциями, класс AutoProbes — с подменёнными пробами.
"""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from core import geneva_auto as ga
from core import geneva_auto_probes as pr


class _Server:
    """TCP-сервер на 127.0.0.1 с заданным поведением на соединение."""

    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.peers = []
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                return
            self.peers.append(addr)
            threading.Thread(target=self._one, args=(conn,),
                             daemon=True).start()

    def _one(self, conn):
        try:
            self.handler(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        self.sock.close()


def _read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _http(body, headers="Content-Length: %d\r\n"):
    def handler(conn):
        _read_request(conn)
        h = headers % len(body) if "%d" in headers else headers
        conn.sendall(b"HTTP/1.1 200 OK\r\n" + h.encode() + b"\r\n" + body)
    return handler


def _reset(conn):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestBodyParser(unittest.TestCase):

    def test_content_length(self):
        b = pr._Body()
        b.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")
        self.assertEqual((b.status, b.body, b.complete), (200, 2, False))
        b.feed(b"cde")
        self.assertTrue(b.complete)

    def test_chunked(self):
        b = pr._Body()
        b.feed(b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked"
               b"\r\n\r\n3\r\nab")
        b.feed(b"c\r\n10;x=1\r\n" + b"z" * 16 + b"\r\n0\r\n\r\n")
        self.assertEqual((b.status, b.body, b.complete), (404, 19, True))

    def test_eof_without_length_and_no_body(self):
        b = pr._Body()
        b.feed(b"HTTP/1.0 200 OK\r\n\r\nhello")
        self.assertFalse(b.complete)
        b.eof()
        self.assertTrue(b.complete)
        b = pr._Body()
        b.feed(b"HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n")
        self.assertTrue(b.complete)
        b = pr._Body()
        b.feed(b"HTTP/1.1 304 Not Modified\r\n\r\n")
        self.assertTrue(b.complete)

    def test_not_http(self):
        b = pr._Body()
        b.feed(b"\x15\x03\x03\x00\x02\x02\x28")
        self.assertTrue(b.bad)


class TestVerdicts(unittest.TestCase):

    def test_page_confirm_and_fitness(self):
        ok = pr.PageResult(tls=False, connect_ok=True, status=200, body=10,
                           complete=True)
        self.assertEqual(pr.page_confirm(ok), ga.C_NOT_BLOCKED)
        self.assertEqual(pr.page_fitness(ok), (400, "ok"))
        # 4xx — тоже ответ сервера
        self.assertTrue(pr.PageResult(tls=False, connect_ok=True,
                                      status=403, complete=True).passes())
        cases = {
            pr.P_CONNECT_TIMEOUT: (ga.C_IP_BLOCKED, -400, "connect_timeout"),
            pr.P_UNREACHABLE: (ga.C_IP_BLOCKED, -400, "connect_timeout"),
            pr.P_CONNECT_REFUSED: (ga.C_BLOCKED, -360, "reset"),
            pr.P_TLS_RESET: (ga.C_BLOCKED, -360, "reset"),
            pr.P_TLS_TIMEOUT: (ga.C_BLOCKED, -480, "timeout"),
            pr.P_STALLED: (ga.C_BLOCKED, -480, "timeout"),
            pr.P_TRUNCATED: (ga.C_BLOCKED, -480, "broken"),
            pr.P_TLS_CLOSED: (ga.C_BLOCKED, -480, "broken"),
        }
        for err, (confirm, fit, outcome) in cases.items():
            r = pr.PageResult(error=err, connect_ok=err not in (
                pr.P_CONNECT_TIMEOUT, pr.P_UNREACHABLE,
                pr.P_CONNECT_REFUSED))
            self.assertEqual(pr.page_confirm(r), confirm, err)
            self.assertEqual(pr.page_fitness(r), (fit, outcome), err)

    def test_stall_and_foreign_cert(self):
        r = pr.PageResult(tls=False, connect_ok=True, status=200, body=16000,
                          stalled_at=16000, error=pr.P_STALLED)
        self.assertFalse(r.passes())
        self.assertIn("16000", r.text())
        cert = pr.PageResult(connect_ok=True, tls_ok=True, cert_valid=False)
        self.assertEqual(pr.page_confirm(cert), ga.C_BLOCKED)
        self.assertEqual(pr.page_fitness(cert), (-360, "injected"))

    def test_probe_itself_failed_is_unknown(self):
        self.assertEqual(pr.page_confirm(pr.PageResult(error=pr.P_OTHER)),
                         ga.C_UNKNOWN)

    def test_replay(self):
        ok = pr.ReplayResult(ok=True, bytes_in=5)
        self.assertEqual(pr.replay_fitness(ok), (400, "ok: answer"))
        self.assertEqual(pr.replay_fitness(pr.ReplayResult(error=pr.R_RESET)),
                         (-360, "reset"))
        self.assertEqual(pr.replay_fitness(
            pr.ReplayResult(error=pr.R_NO_CONNECTION)),
            (-400, "connect_timeout"))
        self.assertEqual(pr.replay_fitness(
            pr.ReplayResult(error=pr.R_NO_ANSWER)), (-400, "timeout: no answer"))
        self.assertEqual(pr.replay_fitness(pr.ReplayResult(error=pr.R_CLOSED)),
                         (-480, "broken: closed"))
        fail = pr.ReplayResult(error=pr.R_NO_ANSWER)
        conn = pr.ReplayResult(error=pr.R_NO_CONNECTION)
        self.assertEqual(pr.replay_confirm([fail, ok]), ga.C_NOT_BLOCKED)
        self.assertEqual(pr.replay_confirm([fail, conn]), ga.C_IP_BLOCKED)
        self.assertEqual(pr.replay_confirm([conn, fail]), ga.C_BLOCKED)
        self.assertEqual(pr.replay_confirm([]), ga.C_UNKNOWN)
        self.assertEqual(pr.replay_confirm(
            [pr.ReplayResult(error=pr.R_NOTHING)]), ga.C_UNKNOWN)

    def test_port_unavailable(self):
        r = pr.ReplayResult(error=pr.R_SOCKET,
                            detail="local port unavailable: 30001 busy")
        self.assertTrue(r.port_unavailable)
        self.assertFalse(pr.ReplayResult(error=pr.R_SOCKET).port_unavailable)


class TestPlans(unittest.TestCase):

    def svc(self, **kw):
        base = dict(key="k", addresses=[{"ip": "93.184.216.1", "seen": 1}])
        base.update(kw)
        return ga.Service(**base)

    def test_replay_plan(self):
        s = self.svc(kind=ga.ENDPOINT, transport="udp", app="openvpn",
                     replay=ga.to_base64([b"\x38abc"]))
        self.assertEqual(pr.replay_plan(s), ([b"\x38abc"], True, ""))
        self.assertEqual(pr.replay_plan(self.svc(kind=ga.ENDPOINT,
                                                 transport="udp",
                                                 app="stun")),
                         ([], True, "stun"))
        self.assertEqual(pr.replay_plan(self.svc(kind=ga.DNS,
                                                 transport="udp")),
                         ([], True, "dns"))
        self.assertIsNone(pr.replay_plan(self.svc(kind=ga.ENDPOINT,
                                                  transport="udp",
                                                  app="wireguard")))
        # не повторяемый протокол: replay не используется, даже если есть
        self.assertIsNone(pr.replay_plan(self.svc(
            kind=ga.ENDPOINT, app="http", replay=ga.to_base64([b"GET"]))))

    def test_requests(self):
        q = pr.dns_query("example.com")
        self.assertEqual(q[2:4], b"\x01\x00")
        self.assertTrue(q.endswith(b"\x07example\x03com\x00\x00\x01\x00\x01"))
        tq = pr.dns_query("example.com", tcp=True)
        self.assertEqual(struct.unpack(">H", tq[:2])[0], len(tq) - 2)
        stun = pr.stun_binding_request()
        self.assertEqual(len(stun), 20)
        self.assertNotEqual(stun[8:], pr.stun_binding_request()[8:])
        req = pr.build_request("a.example.org")
        self.assertIn(b"Host: a.example.org\r\n", req)
        self.assertTrue(req.endswith(b"\r\n\r\n"))


class TestPageProbe(unittest.TestCase):

    def run_page(self, handler, **kw):
        srv = _Server(handler)
        try:
            return pr.probe_page("127.0.0.1", srv.port, "site.example.org",
                                 tls=False, **kw), srv
        finally:
            srv.close()

    def test_full_page(self):
        r, _ = self.run_page(_http(b"x" * 1000))
        self.assertTrue(r.passes(), r)
        self.assertEqual((r.status, r.body), (200, 1000))

    def test_big_page_stops_at_min_bytes(self):
        r, _ = self.run_page(_http(b"y" * 200000), min_bytes=65536)
        self.assertTrue(r.passes())
        self.assertGreaterEqual(r.body, 65536)

    def test_stalled(self):
        def handler(conn):
            _read_request(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n"
                         + b"z" * 500)
            time.sleep(2)
        r, _ = self.run_page(handler, stall=0.5)
        self.assertEqual((r.error, r.stalled_at), (pr.P_STALLED, 500))
        self.assertEqual(pr.page_confirm(r), ga.C_BLOCKED)

    def test_no_answer_and_reset(self):
        def silent(conn):
            _read_request(conn)
            time.sleep(2)
        r, _ = self.run_page(silent, stall=0.5)
        self.assertEqual(r.error, pr.P_HTTP_TIMEOUT)

        def reset(conn):
            _read_request(conn)
            _reset(conn)
        r, _ = self.run_page(reset)
        self.assertEqual(r.error, pr.P_HTTP_RESET)
        self.assertEqual(pr.page_fitness(r), (-360, "reset"))

    def test_truncated(self):
        def handler(conn):
            _read_request(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"
                         + b"z" * 100)
        r, _ = self.run_page(handler)
        self.assertEqual(r.error, pr.P_TRUNCATED)

    def test_refused(self):
        r = pr.probe_page("127.0.0.1", _free_port(), "x.example.org",
                          tls=False)
        self.assertEqual(r.error, pr.P_CONNECT_REFUSED)
        self.assertEqual(pr.page_confirm(r), ga.C_BLOCKED)

    def test_ports_block(self):
        r, srv = self.run_page(_http(b"ok"), ports=(39100, 39163))
        self.assertTrue(r.passes())
        self.assertTrue(39100 <= srv.peers[0][1] <= 39163, srv.peers)

    def test_exact_local_port_busy(self):
        busy = socket.socket()
        busy.bind(("0.0.0.0", 0))
        busy.listen(1)
        try:
            r, _ = self.run_page(_http(b"ok"),
                                 local_port=busy.getsockname()[1])
        finally:
            busy.close()
        self.assertTrue(r.port_unavailable)


@unittest.skipUnless(shutil.which("openssl"), "нет openssl для сертификата")
class TestTlsPage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.cert = os.path.join(cls.dir, "c.pem")
        cls.key = os.path.join(cls.dir, "k.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=site.example.org",
             "-addext", "subjectAltName=DNS:site.example.org",
             "-keyout", cls.key, "-out", cls.cert],
            check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def tls_server(self, inner):
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(self.cert, self.key)

        def handler(conn):
            with sctx.wrap_socket(conn, server_side=True) as t:
                inner(t)
        return _Server(handler)

    def client_ctx(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        return ctx

    def test_full_tls_page(self):
        srv = self.tls_server(_http(b"t" * 3000))
        try:
            r = pr.probe_page("127.0.0.1", srv.port, "site.example.org",
                              ctx=self.client_ctx())
        finally:
            srv.close()
        self.assertTrue(r.passes(), r)
        self.assertTrue(r.tls_ok and r.cert_valid)

    def test_foreign_certificate(self):
        srv = self.tls_server(_http(b"t"))
        try:
            r = pr.probe_page("127.0.0.1", srv.port, "other.example.org",
                              ctx=self.client_ctx())
        finally:
            srv.close()
        self.assertEqual((r.tls_ok, r.cert_valid), (True, False))
        self.assertEqual(pr.page_fitness(r), (-360, "injected"))
        self.assertEqual(pr.page_confirm(r), ga.C_BLOCKED)

    def test_reset_on_client_hello(self):
        def handler(conn):
            conn.recv(4096)
            _reset(conn)
        srv = _Server(handler)
        try:
            r = pr.probe_page("127.0.0.1", srv.port, "site.example.org",
                              ctx=self.client_ctx())
        finally:
            srv.close()
        self.assertEqual(r.error, pr.P_TLS_RESET)

    def test_silence_after_client_hello(self):
        def handler(conn):
            conn.recv(4096)
            time.sleep(2)
        srv = _Server(handler)
        try:
            r = pr.probe_page("127.0.0.1", srv.port, "site.example.org",
                              ctx=self.client_ctx(), stall=0.3)
        finally:
            srv.close()
        self.assertEqual(r.error, pr.P_TLS_TIMEOUT)
        self.assertEqual(pr.page_fitness(r), (-480, "timeout"))


class TestReplayProbe(unittest.TestCase):

    def udp_server(self, answer=True):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        got = []

        def loop():
            while True:
                try:
                    data, addr = s.recvfrom(65536)
                except OSError:
                    return
                got.append(data)
                if answer:
                    s.sendto(b"pong:" + data[:4], addr)
        threading.Thread(target=loop, daemon=True).start()
        return s, got

    def test_udp_answer(self):
        s, got = self.udp_server()
        try:
            r = pr.probe_replay("127.0.0.1", s.getsockname()[1],
                                [b"\x38hello"], udp=True)
        finally:
            s.close()
        self.assertTrue(r.ok, r)
        self.assertEqual(got[0], b"\x38hello")

    def test_udp_silence(self):
        s, got = self.udp_server(answer=False)
        try:
            r = pr.probe_replay("127.0.0.1", s.getsockname()[1], [b"q"],
                                udp=True, timeout=0.6)
        finally:
            s.close()
        self.assertEqual(r.error, pr.R_NO_ANSWER)
        self.assertGreaterEqual(r.sent, 2)          # раунды повторов

    def test_udp_fresh_stun(self):
        s, got = self.udp_server()
        try:
            r = pr.probe_replay("127.0.0.1", s.getsockname()[1], [],
                                udp=True, fresh="stun")
        finally:
            s.close()
        self.assertTrue(r.ok)
        self.assertEqual(got[0][4:8], b"\x21\x12\xa4\x42")

    def test_tcp_answer_close_reset(self):
        def echo(conn):
            conn.sendall(conn.recv(100))
        srv = _Server(echo)
        try:
            r = pr.probe_replay("127.0.0.1", srv.port, [b"\x16\x03\x01hi"],
                                udp=False)
        finally:
            srv.close()
        self.assertTrue(r.ok)

        srv = _Server(lambda conn: conn.recv(100))
        try:
            r = pr.probe_replay("127.0.0.1", srv.port, [b"x"], udp=False)
        finally:
            srv.close()
        self.assertEqual(r.error, pr.R_CLOSED)

        def reset(conn):
            conn.recv(100)
            _reset(conn)
        srv = _Server(reset)
        try:
            r = pr.probe_replay("127.0.0.1", srv.port, [b"x"], udp=False)
        finally:
            srv.close()
        self.assertEqual(r.error, pr.R_RESET)

    def test_tcp_no_connection(self):
        r = pr.probe_replay("127.0.0.1", _free_port(), [b"x"], udp=False)
        self.assertEqual(r.error, pr.R_NO_CONNECTION)
        self.assertEqual(pr.replay_confirm([r, r]), ga.C_IP_BLOCKED)

    def test_nothing_to_send(self):
        self.assertEqual(pr.probe_replay("127.0.0.1", 1, [], udp=True).error,
                         pr.R_NOTHING)

    def test_fresh_dns_over_tcp(self):
        seen = []

        def handler(conn):
            data = conn.recv(512)
            seen.append(data)
            conn.sendall(data)
        srv = _Server(handler)
        try:
            r = pr.probe_replay("127.0.0.1", srv.port, [], udp=False,
                                fresh="dns")
        finally:
            srv.close()
        self.assertTrue(r.ok)
        self.assertEqual(struct.unpack(">H", seen[0][:2])[0],
                         len(seen[0]) - 2)


class TestAutoProbes(unittest.TestCase):

    def svc(self, **kw):
        base = dict(key="k", name="site.example.org",
                    addresses=[{"ip": "93.184.216.1", "seen": 5},
                               {"ip": "93.184.216.2", "seen": 9}])
        base.update(kw)
        return ga.Service(**base)

    def test_web_baseline_uses_newest_address_and_host(self):
        calls = []

        def page(ip, port, host, **kw):
            calls.append((ip, port, host, kw))
            return pr.PageResult(error=pr.P_CONNECT_TIMEOUT)

        p = pr.AutoProbes(page=page, mark=lambda: 0, ports=(1, 2))
        s = self.svc(kind=ga.WEB, host="www.site.example.org", ports=[443])
        confirm, text = p.check(s)
        self.assertEqual(confirm, ga.C_IP_BLOCKED)
        self.assertEqual(calls[0][:3], ("93.184.216.2", 443,
                                        "www.site.example.org"))
        self.assertEqual(calls[0][3], {"tls": True, "ports": (1, 2)})
        self.assertIn("соединение", text)

    def test_replay_two_tries(self):
        calls = []

        def replay(ip, port, payloads, **kw):
            calls.append(kw)
            return pr.ReplayResult(error=pr.R_NO_ANSWER)

        p = pr.AutoProbes(replay=replay, mark=lambda: 0)
        s = self.svc(kind=ga.ENDPOINT, transport="udp", app="quic",
                     replay=ga.to_base64([b"\xc3x"]), ports=[443])
        self.assertEqual(p.check(s)[0], ga.C_BLOCKED)
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0]["udp"])

    def test_unknown_for_unreplayable_and_no_address(self):
        p = pr.AutoProbes(mark=lambda: 0)
        wg = self.svc(kind=ga.ENDPOINT, transport="udp", app="wireguard",
                      ports=[51820])
        self.assertEqual(p.check(wg)[0], ga.C_UNKNOWN)
        self.assertEqual(p.check(ga.Service(key="x", kind=ga.WEB))[0],
                         ga.C_UNKNOWN)
        self.assertIsNone(p.judge(wg))

    def test_mark_failure_is_unknown(self):
        from core import probe_mark

        def page(*a, **kw):
            raise probe_mark.MarkError("нет CAP_NET_ADMIN")

        p = pr.AutoProbes(page=page, mark=lambda: 0)
        self.assertEqual(p.check(self.svc(kind=ga.WEB))[0], ga.C_UNKNOWN)

    def test_judge_from_local_port(self):
        calls = []

        def replay(ip, port, payloads, **kw):
            calls.append(kw["local_port"])
            if kw["local_port"] == 30001:
                return pr.ReplayResult(
                    error=pr.R_SOCKET,
                    detail="local port unavailable: 30001")
            return pr.ReplayResult(ok=True, bytes_in=3)

        p = pr.AutoProbes(replay=replay, mark=lambda: 0)
        s = self.svc(kind=ga.DNS, transport="udp", ports=[53])
        run = p.judge(s)
        self.assertEqual(run(30000), (400, "ok: answer", False))
        self.assertTrue(run(30001)[2])
        self.assertEqual(calls, [30000, 30001])

    def test_judge_web(self):
        def page(ip, port, host, **kw):
            return pr.PageResult(error=pr.P_TLS_RESET, connect_ok=True)

        p = pr.AutoProbes(page=page, mark=lambda: 0)
        run = p.judge(self.svc(kind=ga.WEB))
        self.assertEqual(run(30005), (-360, "reset", False))

    def test_through_bypass_has_no_mark(self):
        marks = []
        p = pr.AutoProbes(page=lambda *a, **k: pr.PageResult(
            tls=False, connect_ok=True, status=200, complete=True),
            mark=lambda: marks.append(1) or 0x20000000)
        self.assertEqual(p.check(self.svc(kind=ga.WEB), through_bypass=True)
                         [0], ga.C_NOT_BLOCKED)
        self.assertEqual(marks, [])

    def test_baseline_mark_includes_geneva(self):
        self.assertTrue(pr.baseline_mark() & pr.GENEVA_MARK)


class TestObserverSkipsProbePorts(unittest.TestCase):

    def test_ports(self):
        from core import geneva_auto_observer as ob
        lo, hi = ob.AUTO_PROBE_PORTS
        self.assertEqual((lo, hi), (30512, 30575))
        self.assertTrue(ob.is_probe_port(lo) and ob.is_probe_port(hi))
        self.assertFalse(ob.is_probe_port(hi + 1))


if __name__ == "__main__":
    unittest.main()
