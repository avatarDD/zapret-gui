# tests/test_log_buffer.py
"""Unit-тесты для core/log_buffer.py (RAM-буфер логов)."""

import time
import unittest

from core.log_buffer import LogBuffer, LogEntry


class TestLogEntry(unittest.TestCase):

    def test_to_dict(self):
        e = LogEntry("INFO", "hello", "src")
        d = e.to_dict()
        self.assertEqual(d["level"], "INFO")
        self.assertEqual(d["message"], "hello")
        self.assertEqual(d["source"], "src")
        self.assertIn("color", d)

    def test_format_line(self):
        e = LogEntry("ERROR", "boom", "x")
        self.assertIn("boom", e.format_line())


class TestLogBuffer(unittest.TestCase):

    def setUp(self):
        # file_enabled off — не пишем на диск в тестах.
        self.buf = LogBuffer(max_entries=5, file_path="/tmp/_t_logbuf.log")
        self.buf._file_enabled = False

    def test_add_and_get_last(self):
        for i in range(3):
            self.buf.add("INFO", "m%d" % i)
        last = self.buf.get_last(10)
        self.assertEqual(len(last), 3)
        self.assertEqual(last[-1]["message"], "m2")

    def test_ring_overflow(self):
        for i in range(10):
            self.buf.add("INFO", "m%d" % i)
        # maxlen=5 — остаются последние 5.
        self.assertEqual(self.buf.get_count(), 5)
        msgs = [e["message"] for e in self.buf.get_last(10)]
        self.assertEqual(msgs, ["m5", "m6", "m7", "m8", "m9"])

    def test_counter_monotonic(self):
        self.buf.add("INFO", "a")
        self.buf.add("INFO", "b")
        self.assertEqual(self.buf.get_counter(), 2)
        self.buf.clear()
        self.assertEqual(self.buf.get_counter(), 0)
        self.assertEqual(self.buf.get_count(), 0)

    def test_get_since(self):
        self.buf.add("INFO", "old")
        t = time.time()
        time.sleep(0.01)
        self.buf.add("INFO", "new")
        res = self.buf.get_since(t)
        self.assertEqual([e["message"] for e in res], ["new"])

    def test_filter_by_level(self):
        self.buf.add("INFO", "i")
        self.buf.add("ERROR", "e")
        self.buf.add("WARNING", "w")
        errs = self.buf.get_filtered(level="ERROR")
        msgs = [e["message"] for e in errs]
        self.assertIn("e", msgs)
        self.assertNotIn("i", msgs)

    def test_filter_by_search(self):
        self.buf.add("INFO", "alpha")
        self.buf.add("INFO", "beta")
        res = self.buf.get_filtered(search="alph")
        self.assertEqual([e["message"] for e in res], ["alpha"])

    def test_listeners(self):
        got = []
        cb = lambda e: got.append(e.message)
        self.buf.add_listener(cb)
        self.buf.add("INFO", "x")
        self.assertEqual(got, ["x"])
        self.buf.remove_listener(cb)
        self.buf.add("INFO", "y")
        self.assertEqual(got, ["x"])

    def test_broken_listener_removed(self):
        def boom(_e):
            raise RuntimeError("bad")
        self.buf.add_listener(boom)
        self.buf.add("INFO", "z")   # не должно бросать
        # сломанный слушатель удалён
        self.assertEqual(self.buf._listeners, [])


if __name__ == "__main__":
    unittest.main()
