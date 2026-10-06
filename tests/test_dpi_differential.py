"""Дифференциальный классификатор DPI (приём d2k): разбор, дерево, сеть.

Сеть — локальный «DPI-сервер» на петле: рвёт соединение, если в
ПЕРВОМ прочитанном куске есть запрещённое имя (префиксный матчер без
сборки потока), иначе отвечает записью ServerHello. Ровно то, что
отличает prefix от opaque.
"""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from core.testers import dpi_differential as dd


def record(kind, payload):
    return bytes([kind, 3, 3]) + struct.pack(">H", len(payload)) + payload


def hs(msg, body=b""):
    return bytes([msg]) + len(body).to_bytes(3, "big") + body


SERVER_HELLO = record(0x16, hs(2, b"\x03\x03" + b"\x00" * 34))
TLS12_FLIGHT = record(0x16, hs(2, b"\x03\x03" + b"\x00" * 34)
                      + hs(11, b"\x00" * 10) + hs(14))
ALERT = record(0x15, b"\x02\x70")


class TestParse(unittest.TestCase):

    def test_server_hello(self):
        f = dd.parse_server_flight(SERVER_HELLO)
        self.assertTrue(f["server_hello"])
        self.assertTrue(f["tls"])
        self.assertTrue(dd.trigger_passed(f))
        self.assertFalse(dd.trigger_passed(f, tls12=True))

    def test_tls12_complete_flight(self):
        f = dd.parse_server_flight(TLS12_FLIGHT)
        self.assertTrue(f["certificate"] and f["hello_done"])
        self.assertTrue(dd.trigger_passed(f, tls12=True))

    def test_cut_certificate(self):
        f = dd.parse_server_flight(TLS12_FLIGHT[:30])
        self.assertTrue(f["server_hello"])
        self.assertFalse(f["hello_done"])

    def test_alert_is_not_a_pass_for_trigger(self):
        # Инжектированный алерт — ответ коробки, а не сервера.
        f = dd.parse_server_flight(ALERT)
        self.assertFalse(dd.trigger_passed(f))
        self.assertTrue(dd.control_passed(f))
        self.assertTrue(f["alert"])

    def test_garbage(self):
        f = dd.parse_server_flight(b"HTTP/1.1 302 Found\r\n")
        self.assertFalse(f["tls"])
        self.assertFalse(dd.control_passed(f))
        self.assertFalse(dd.parse_server_flight(b"")["tls"])


class TestDecide(unittest.TestCase):

    def test_tree(self):
        T, F = True, False
        cases = [
            ({"connect": [F, F], "base": [F, F]}, dd.UNREACHABLE),
            ({"connect": [T, T], "base": [T, T]}, dd.CLEAR),
            ({"connect": [T, T], "base": [T, F]}, dd.FLAKY),
            ({"connect": [T, T], "base": [F, F], "split": [T, T]},
             dd.PREFIX),
            ({"connect": [T, T], "base": [F, F], "split": [F, F],
              "control": [T, T]}, dd.OPAQUE),
            ({"connect": [T, T], "base": [F, F], "split": [F, F],
              "control": [F, F]}, dd.ADDRESS),
            ({"connect": [T, T], "base": [F, F], "split": [F, F],
              "control": [T, F]}, dd.FLAKY),
            ({"connect": [T, T], "base": [T, T],
              "tls12": {"server_hello": T, "complete": [F, F]}},
             dd.RESPONSE),
            ({"connect": [T, T], "base": [T, T],
              "tls12": {"server_hello": T, "complete": [T, F]}},
             dd.CLEAR),
        ]
        for steps, want in cases:
            with self.subTest(steps=steps):
                self.assertEqual(dd.decide(steps)[0], want)

    def test_unmarked_clear_is_not_accepted(self):
        verdict, reason = dd.decide({"connect": [True], "base": [True]},
                                    marked=False)
        self.assertEqual(verdict, dd.INCONCLUSIVE)
        self.assertIn("самоподтверждением", reason)

    def test_prefix_names_the_gap(self):
        _, reason = dd.decide({"connect": [True], "base": [False],
                               "split": [True]}, split_gap_ms=20)
        self.assertIn("20 мс", reason)

    def test_mapping_covers_every_verdict(self):
        self.assertEqual(set(dd.VERDICTS), set(dd.DPI_BY_VERDICT))


class FakeDpiServer:
    """TCP-сервер на петле: префиксный DPI + ответ «сервера»."""

    def __init__(self, blocked=b"blocked.test", reply=SERVER_HELLO,
                 kill_all=False, control_reply=ALERT):
        self.blocked = blocked
        self.reply = reply
        self.kill_all = kill_all
        self.control_reply = control_reply
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _rst(self, conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        conn.close()

    def _loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(2)
                first = conn.recv(4096)
                if self.kill_all or (self.blocked and self.blocked in first):
                    self._rst(conn)
                    continue
                data = first
                while len(data) < 5 or len(data) < 5 + int.from_bytes(
                        data[3:5], "big"):
                    more = conn.recv(4096)
                    if not more:
                        break
                    data += more
                if b"example.com" in data:
                    conn.sendall(self.control_reply)
                else:
                    conn.sendall(self.reply)
                conn.close()
            except OSError:
                conn.close()

    def close(self):
        self.stop = True
        self.sock.close()


class TestNetwork(unittest.TestCase):

    def run_classify(self, server, domain):
        self.addCleanup(server.close)
        with mock.patch.object(dd, "_pick_ip",
                               return_value=(["127.0.0.1"], False)):
            return dd.classify(domain, port=server.port, timeout=2,
                               repeats=2, mark=0, check_tls12=False)

    def test_clear(self):
        result = self.run_classify(FakeDpiServer(), "open.test")
        self.assertEqual(result["verdict"], dd.CLEAR, result)
        self.assertEqual(result["remediation"], "none")

    def test_prefix(self):
        result = self.run_classify(FakeDpiServer(), "blocked.test")
        self.assertEqual(result["verdict"], dd.PREFIX, result)
        self.assertEqual(result["remediation"], "zapret")

    def test_opaque(self):
        # Матчер видит имя в любом куске: разрез не помогает, контроль —
        # проходит.
        server = FakeDpiServer(blocked=None)
        server.reply = b""        # «сервер» молчит на настоящее имя
        result = self.run_classify(server, "blocked.test")
        self.assertEqual(result["verdict"], dd.OPAQUE, result)
        self.assertEqual(result["steps"]["control"][0]["alert"], True)

    def test_address(self):
        result = self.run_classify(FakeDpiServer(kill_all=True),
                                   "blocked.test")
        self.assertEqual(result["verdict"], dd.ADDRESS, result)
        self.assertEqual(result["remediation"], "tunnel")

    def test_unreachable(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with mock.patch.object(dd, "_pick_ip",
                               return_value=(["127.0.0.1"], False)):
            result = dd.classify("x.test", port=port, timeout=1,
                                 repeats=1, mark=0)
        self.assertEqual(result["verdict"], dd.UNREACHABLE, result)

    def test_local_address(self):
        with mock.patch.object(dd, "_pick_ip",
                               return_value=(["10.171.171.171"], True)):
            result = dd.classify("rutracker.org", mark=0)
        self.assertEqual(result["verdict"], dd.LOCAL_ADDRESS)
        self.assertEqual(result["remediation"], "dns")


@unittest.skipUnless(shutil.which("openssl"), "нет openssl")
class TestRealTls(unittest.TestCase):
    """Настоящий TLS-сервер Python: ServerHello и полный ответ TLS 1.2."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="dpi-diff-")
        cls.cert = os.path.join(cls.dir, "c.pem")
        cls.key = os.path.join(cls.dir, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", cls.key, "-out", cls.cert,
                        "-days", "1", "-subj", "/CN=open.test"],
                       capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _server(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        self.addCleanup(sock.close)

        def loop():
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(2)
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        threading.Thread(target=loop, daemon=True).start()
        return sock.getsockname()[1]

    def test_tls13_and_tls12_flights(self):
        port = self._server()
        hello = dd.build_client_hello("open.test")
        res = dd.exchange("127.0.0.1", port, hello, 2,
                          until=dd.trigger_passed)
        self.assertTrue(res["flight"]["server_hello"], res)
        res12 = dd.exchange("127.0.0.1", port,
                            dd.build_client_hello("open.test", tls12=True),
                            2, until=lambda f: f["hello_done"])
        self.assertTrue(res12["flight"]["hello_done"], res12)

    def test_classify_clear_with_tls12_check(self):
        port = self._server()
        with mock.patch.object(dd, "_pick_ip",
                               return_value=(["127.0.0.1"], False)):
            result = dd.classify("open.test", port=port, timeout=2,
                                 repeats=1, mark=0)
        self.assertEqual(result["verdict"], dd.CLEAR, result)
        self.assertNotIn("не проверялся", result["reason"])


if __name__ == "__main__":
    unittest.main()


class TestBlockcheckIntegration(unittest.TestCase):
    """blockcheck уточняет симптом ответом классификатора."""

    def _report(self):
        from core.models import BlockcheckReport, TargetResult
        report = BlockcheckReport()
        report.targets = [
            TargetResult(domain="blocked.example",
                         dpi_classification="ip_block",
                         dpi_detail="TCP connect не проходит"),
            TargetResult(domain="open.example", dpi_classification="none"),
            TargetResult(domain="TCP 16-20KB",
                         dpi_classification="tls_dpi"),
        ]
        return report

    def test_refines_and_skips(self):
        from core.blockcheck import BlockcheckRunner
        runner = BlockcheckRunner()
        report = self._report()
        asked = []

        def fake(domain, **kw):
            asked.append(domain)
            return {"verdict": dd.OPAQUE,
                    "verdict_text": dd.VERDICTS[dd.OPAQUE],
                    "reason": "тест", "dpi_classification": "tls_dpi"}

        with mock.patch.object(dd, "classify", side_effect=fake):
            runner._run_differential(report, 5)
        # Спрашиваем только цели с непрошедшим TLS и настоящими именами.
        self.assertEqual(asked, ["blocked.example"])
        target = report.targets[0]
        self.assertEqual(target.dpi_classification, "tls_dpi")
        self.assertIn("уточнено", target.dpi_detail)
        self.assertEqual(target.to_dict()["remediation"], "zapret")
        self.assertEqual(target.to_dict()["differential"]["verdict"],
                         dd.OPAQUE)

    def test_inconclusive_only_annotates(self):
        from core.blockcheck import BlockcheckRunner
        report = self._report()
        with mock.patch.object(dd, "classify", return_value={
                "verdict": dd.FLAKY, "verdict_text": "x", "reason": "y",
                "dpi_classification": "unknown"}):
            BlockcheckRunner()._run_differential(report, 5)
        self.assertEqual(report.targets[0].dpi_classification, "ip_block")
        self.assertIn("вопросы к DPI", report.targets[0].dpi_detail)
