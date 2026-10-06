"""TX-лестница (исходящий объём, приём d2k): вердикт и сеть на петле."""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest

from core import models
from core.models import TargetResult, SingleTestResult
from core.testers import tcp_test


class TestVerdict(unittest.TestCase):

    def test_all_answered(self):
        self.assertEqual(tcp_test.tx_verdict(tcp_test.TX_REQUESTS, 0, "")[0],
                         "ok")

    def test_cut_in_window(self):
        status, details = tcp_test.tx_verdict(6, 12500, "reset")
        self.assertEqual(status, "cut")
        self.assertIn("12500", details)

    def test_first_request_is_not_volume(self):
        self.assertEqual(tcp_test.tx_verdict(1, 2100, "reset")[0],
                         "inconclusive")

    def test_server_close_is_not_a_block(self):
        self.assertEqual(tcp_test.tx_verdict(4, 6000, "server_close")[0],
                         "inconclusive")

    def test_outside_window(self):
        self.assertEqual(tcp_test.tx_verdict(3, 4000, "reset")[0],
                         "inconclusive")


class TestClassifyTarget(unittest.TestCase):

    def test_rx_and_tx_named_separately(self):
        from core.blockcheck import BlockcheckRunner
        tr = TargetResult(domain="TCP 16-20KB")
        tr.results = [
            SingleTestResult(target="a", test_type=models.TestType.TCP_16_20.value,
                             status=models.TestStatus.SUCCESS.value),
            SingleTestResult(target="a", test_type=models.TestType.TCP_16_20.value,
                             status=models.TestStatus.FAILED.value,
                             error="TCP_16_20",
                             raw_data={"direction": "tx"}),
        ]
        BlockcheckRunner._classify_tcp_target(tr)
        self.assertEqual(tr.dpi_classification, "tcp_16_20")
        self.assertIn("отправки", tr.dpi_detail)
        self.assertNotIn("приёма", tr.dpi_detail)


@unittest.skipUnless(shutil.which("openssl"), "нет openssl")
class TestLadderOnLoopback(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="tx-ladder-")
        cls.cert = os.path.join(cls.dir, "c.pem")
        cls.key = os.path.join(cls.dir, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", cls.key, "-out", cls.cert,
                        "-days", "1", "-subj", "/CN=localhost"],
                       capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _server(self, cut_after=None):
        """Keep-alive HEAD-сервер; ``cut_after`` — RST после N байт."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        self.addCleanup(sock.close)

        def serve(conn):
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.settimeout(3)
                got, buf = 0, b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        return
                    got += len(chunk)
                    if cut_after and got > cut_after:
                        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                        struct.pack("ii", 1, 0))
                        conn.close()
                        return
                    buf += chunk
                    while b"\r\n\r\n" in buf:
                        _, _, buf = buf.partition(b"\r\n\r\n")
                        tls.sendall(b"HTTP/1.1 200 OK\r\n"
                                    b"Content-Length: 0\r\n\r\n")
            except (OSError, ssl.SSLError):
                pass

        def loop():
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                threading.Thread(target=serve, args=(conn,),
                                 daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return "https://127.0.0.1:%d/" % sock.getsockname()[1]

    def test_clean_line(self):
        result = tcp_test.check_tcp_tx_volume(self._server(), timeout=3)
        self.assertEqual(result.status, models.TestStatus.SUCCESS.value,
                         result.details)
        self.assertEqual(result.raw_data["direction"], "tx")

    def test_cut_line(self):
        result = tcp_test.check_tcp_tx_volume(self._server(cut_after=12000),
                                              timeout=3)
        self.assertEqual(result.status, models.TestStatus.FAILED.value,
                         result.details)
        self.assertEqual(result.error, "TCP_16_20")
        self.assertIn("исходящий", result.details)


if __name__ == "__main__":
    unittest.main()
