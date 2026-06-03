# tests/test_nfqws_debug_stream.py
"""Регрессия: вывод nfqws2 (stdout+stderr, в т.ч. пер-пакетный --debug) читается
из PTY-мастера построчно и попадает в лог-буфер.

Подоплёка бага: nfqws2 пишет debug-лог (DLOG) в STDOUT, а раньше stdout уходил
в DEVNULL — поэтому при включённой отладке «в логах было пусто». Теперь
stdout+stderr объединяются и читаются через _read_output_stream (PTY-путь —
os.read из мастер-дескриптора, построчно, со срезом CR от CRLF).
"""

import os
import unittest

from core.nfqws_manager import NFQWSManager


class _FakeProc:
    """Заглушка Popen (в PTY-ветке сам proc не используется для чтения)."""
    stdout = None


class TestReadOutputStreamPTY(unittest.TestCase):

    def _run(self, payload: bytes):
        mgr = NFQWSManager()
        captured = []
        mgr._log_nfqws_line = lambda line: captured.append(line)  # type: ignore

        read_fd, write_fd = os.pipe()
        # Пишем нарезкой, чтобы границы строк попадали в середину чанка.
        for i in range(0, len(payload), 5):
            os.write(write_fd, payload[i:i + 5])
        os.close(write_fd)

        mgr._read_output_stream(_FakeProc(), read_fd)
        # _read_output_stream сам закрывает fd; повторно не закрываем.
        return captured

    def test_crlf_chunked_lines(self):
        payload = (b"loading lua zapret-lib.lua\r\n"
                   b"blob fake_default_tls declared\r\n"
                   b"packet matched hostlist youtube.com\r\n"
                   b"tail-no-newline")
        lines = self._run(payload)
        self.assertIn("loading lua zapret-lib.lua", lines)
        self.assertIn("blob fake_default_tls declared", lines)
        self.assertIn("packet matched hostlist youtube.com", lines)
        self.assertIn("tail-no-newline", lines)  # хвост без \n тоже учтён
        self.assertFalse(any("\r" in l for l in lines), "CR должен быть срезан")

    def test_out_fd_closed_after_read(self):
        lines = self._run(b"one line\n")
        self.assertEqual(lines, ["one line"])


if __name__ == "__main__":
    unittest.main()
