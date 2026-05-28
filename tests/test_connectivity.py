# tests/test_connectivity.py
"""Unit-тесты для core/connectivity/matrix.py и traffic.py."""

import time
import unittest
from unittest import mock

from core.connectivity import matrix
from core.connectivity import traffic


class TestClassifyLatency(unittest.TestCase):

    def test_good_lt_100(self):
        self.assertEqual(matrix.classify_latency(50), "good")
        self.assertEqual(matrix.classify_latency(99.9), "good")

    def test_ok_lt_250(self):
        self.assertEqual(matrix.classify_latency(100), "ok")
        self.assertEqual(matrix.classify_latency(249), "ok")

    def test_slow(self):
        self.assertEqual(matrix.classify_latency(250), "slow")
        self.assertEqual(matrix.classify_latency(999), "slow")

    def test_failed(self):
        self.assertEqual(matrix.classify_latency(None), "failed")


class TestParseFirstLatency(unittest.TestCase):

    def test_iputils_format(self):
        out = ("PING 8.8.8.8 (8.8.8.8): 56 data bytes\n"
               "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms\n")
        self.assertAlmostEqual(matrix._parse_first_latency(out), 12.3,
                                places=2)

    def test_busybox_format(self):
        out = "64 bytes from 1.1.1.1: seq=0 ttl=58 time=4.5 ms"
        self.assertAlmostEqual(matrix._parse_first_latency(out), 4.5,
                                places=2)

    def test_time_lt(self):
        # iputils иногда выдаёт `time<0.001 ms` — тоже должно парситься.
        out = "64 bytes from 127.0.0.1: time<0.001 ms"
        v = matrix._parse_first_latency(out)
        self.assertIsNotNone(v)

    def test_no_match(self):
        self.assertIsNone(matrix._parse_first_latency("100% packet loss"))
        self.assertIsNone(matrix._parse_first_latency(""))


class TestMatrixTargets(unittest.TestCase):

    def test_default_targets_have_required_fields(self):
        self.assertGreater(len(matrix.DEFAULT_TARGETS), 0)
        for t in matrix.DEFAULT_TARGETS:
            self.assertIn("name", t)
            self.assertIn("host", t)

    def test_set_targets_normalizes(self):
        mgr = matrix.ConnectivityMatrix()
        mgr.set_targets([
            {"name": "X", "host": "1.2.3.4"},
            "8.8.8.8",
            {"host": ""},          # пустой host — игнорируется
            {"name": "Y"},          # без host — игнорируется
        ])
        ts = mgr.get_targets()
        self.assertEqual(len(ts), 2)
        self.assertEqual(ts[0]["host"], "1.2.3.4")
        self.assertEqual(ts[1]["host"], "8.8.8.8")
        # Без name — host используется как name
        self.assertEqual(ts[1]["name"], "8.8.8.8")

    def test_set_empty_returns_to_defaults(self):
        mgr = matrix.ConnectivityMatrix()
        mgr.set_targets([{"host": "1.1.1.1"}])
        mgr.set_targets([])
        self.assertEqual(mgr.get_targets(), list(matrix.DEFAULT_TARGETS))


class TestSnapshotEmpty(unittest.TestCase):

    def test_empty_snapshot(self):
        mgr = matrix.ConnectivityMatrix()
        snap = mgr.get_snapshot()
        self.assertEqual(snap["cells"], [])
        self.assertFalse(snap["fresh"])


class TestTrafficBuffer(unittest.TestCase):

    def test_ring_wraps(self):
        # Размер 4 — после 6 add'ов остаются последние 4.
        buf = traffic._RingBuffer(4)
        for i in range(6):
            buf.append(1000 + i, i * 100, i * 50)
        samples = list(buf.iter_chronological())
        # Должны быть только последние 4
        self.assertEqual(len(samples), 4)
        # Самый старый — i=2; новый — i=5
        self.assertEqual(samples[0][0], 1002)
        self.assertEqual(samples[-1][0], 1005)

    def test_iter_empty(self):
        buf = traffic._RingBuffer(8)
        self.assertEqual(list(buf.iter_chronological()), [])

    def test_iface_and_peer_buffer_aliases(self):
        # Заглушка-конструкторы возвращают _RingBuffer нужного размера.
        b1 = traffic._IfaceBuffer()
        b2 = traffic._PeerBuffer()
        self.assertIsInstance(b1, traffic._RingBuffer)
        self.assertIsInstance(b2, traffic._RingBuffer)


class TestSeriesFromSamples(unittest.TestCase):

    def test_constant_rate(self):
        # Сэмплы по 1000 байт/тик с интервалом 30с
        now = int(time.time())
        raw = [(now - 60 + i * 30, i * 30000, i * 15000)
               for i in range(3)]
        s = traffic._series_from_samples(raw, window_sec=60, points=2)
        # Точки должны быть; bps ≈ 1000
        self.assertGreater(len(s), 0)
        for p in s:
            self.assertGreater(p["rx_bps"], 0)
            self.assertGreater(p["tx_bps"], 0)

    def test_counter_reset_clamped_zero(self):
        # rx убывает (рестарт счётчика) — bps не должен быть отрицательным.
        now = int(time.time())
        raw = [(now - 60, 100000, 50000), (now - 30, 0, 0)]
        s = traffic._series_from_samples(raw, window_sec=60, points=1)
        for p in s:
            self.assertGreaterEqual(p["rx_bps"], 0)
            self.assertGreaterEqual(p["tx_bps"], 0)

    def test_insufficient_data(self):
        self.assertEqual(traffic._series_from_samples([], 60, 5), [])
        # Один сэмпл — bps вычислить нельзя.
        self.assertEqual(
            traffic._series_from_samples([(1, 100, 50)], 60, 5), [])


class TestReadPeers(unittest.TestCase):
    """awg show <iface> dump parser."""

    def test_parses_dump_lines(self):
        # Первая строка — Interface section, дальше peer'ы.
        dump = "PRIV\tPUB-IFACE\t51820\t(none)\n" \
               "PUB1\t(none)\tendp:1\t10.0.0.0/24\t1700000000\t12345\t67890\toff\n" \
               "PUB2\t(none)\tendp:2\t10.0.1.0/24\t1700000001\t11\t22\t25\n"
        with mock.patch.object(
                traffic, "_run", return_value=(0, dump, "")):
            peers = traffic._read_peers("awg0")
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0], ("PUB1", 12345, 67890))
        self.assertEqual(peers[1], ("PUB2", 11, 22))

    def test_command_failure(self):
        with mock.patch.object(
                traffic, "_run", return_value=(1, "", "error")):
            self.assertEqual(traffic._read_peers("awg0"), [])


if __name__ == "__main__":
    unittest.main()
