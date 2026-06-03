# tests/test_blockcheck2_stream.py
"""Регрессия: потоковое чтение вывода blockcheck2 через файловый дескриптор
(PTY-путь) разбирает строки построчно, корректно склеивает чанки на границе
строк, срезает CR от CRLF (PTY) и наполняет found/highlights В РЕАЛЬНОМ
ВРЕМЕНИ (по мере поступления, а не в конце).

Подоплёка: раньше вывод шёл через обычный pipe, libc в скрипте и его детях
переключалась на блочную буферизацию, и «working strategy found» доходило
только в конце. Теперь вывод идёт через PTY (isatty==true → построчно), а
читаем мы из мастер-дескриптора через _read_from_fd / _handle_line.
"""

import os
import unittest

from core.blockcheck2 import Blockcheck2Runner


class TestHandleLine(unittest.TestCase):

    def test_handle_line_collects_found_and_highlight(self):
        r = Blockcheck2Runner()
        r._handle_line("[attempt 1] UNAVAILABLE code=28")
        r._handle_line(
            "curl_test_https_tls13: working strategy found for ipv4 "
            "youtube.com : nfqws2 --payload=tls_client_hello "
            "--lua-desync=fake:blob=fake_default_tls")
        # шумовая строка не попадает в highlights/found
        self.assertEqual(len(r._highlights), 1)
        self.assertEqual(len(r._found), 1)
        self.assertEqual(r._found[0]["domain"], "youtube.com")
        self.assertEqual(r._found[0]["label"], "TLS1.3")
        # но в общий буфер строк попадает всё
        self.assertEqual(len(r._lines), 2)


class TestReadFromFd(unittest.TestCase):

    def test_chunked_crlf_split_across_boundaries(self):
        r = Blockcheck2Runner()
        read_fd, write_fd = os.pipe()

        strat = ("curl_test_http: working strategy found for ipv6 "
                 "rutracker.org : nfqws2 --filter-tcp=80 --lua-desync=fake")
        # CRLF как от PTY; строку стратегии намеренно режем по разным чанкам.
        payload = ("line one\r\n" + strat + "\r\n" + "tail without newline")
        data = payload.encode("utf-8")

        # Пишем нарезкой по 7 байт, чтобы границы строк попали в середину чанка.
        for i in range(0, len(data), 7):
            os.write(write_fd, data[i:i + 7])
        os.close(write_fd)

        r._read_from_fd(read_fd)
        os.close(read_fd)

        # CR срезан, строки целые, последняя без \n тоже учтена.
        self.assertIn("line one", r._lines)
        self.assertIn(strat, r._lines)
        self.assertIn("tail without newline", r._lines)
        self.assertFalse(any("\r" in l for l in r._lines),
                         "CR от CRLF должен быть срезан")
        # Найденная стратегия разобрана инкрементально.
        self.assertEqual(len(r._found), 1)
        self.assertEqual(r._found[0]["ipv"], 6)
        self.assertEqual(r._found[0]["domain"], "rutracker.org")


if __name__ == "__main__":
    unittest.main()
