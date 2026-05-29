# tests/test_catalog_loader.py
"""Unit-тесты для чистых хелперов core/catalog_loader.py."""

import unittest

from core import catalog_loader as cl


class TestGuessProtocol(unittest.TestCase):

    def test_udp_keywords(self):
        for n in ("udp.txt", "discord_voice.txt", "stun.txt", "quic.txt"):
            self.assertEqual(cl._guess_protocol(n), "udp", n)

    def test_tcp_keywords(self):
        for n in ("tcp.txt", "http80.txt", "tls.txt"):
            self.assertEqual(cl._guess_protocol(n), "tcp", n)

    def test_default_tcp(self):
        self.assertEqual(cl._guess_protocol("mystery.txt"), "tcp")


class TestWindivertArg(unittest.TestCase):

    def test_detects_windivert(self):
        # Берём реальные префиксы из модуля, чтобы тест не расходился.
        for prefix in cl._WINDIVERT_PREFIXES:
            self.assertTrue(cl._is_windivert_arg(prefix + "something"))

    def test_non_windivert(self):
        self.assertFalse(cl._is_windivert_arg("--dpi-desync=fake"))


class TestParseCatalogContent(unittest.TestCase):

    def test_parses_sections(self):
        content = (
            "# comment\n"
            "[strat1]\n"
            "name = Strategy One\n"
            "description = desc\n"
            "--dpi-desync=fake\n"
            "--dpi-desync-ttl=5\n"
            "\n"
            "[strat2]\n"
            "--dpi-desync=split2\n"
        )
        entries = cl._parse_catalog_content(content, "basic_tcp.txt",
                                            protocol="tcp", level="basic")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].section_id, "strat1")
        self.assertEqual(entries[0].name, "Strategy One")
        self.assertEqual(entries[0].protocol, "tcp")
        self.assertIn("--dpi-desync=fake", entries[0].args)

    def test_section_without_args_skipped(self):
        content = "[empty]\nname = X\ndescription = only meta\n"
        entries = cl._parse_catalog_content(content, "x.txt", protocol="tcp")
        self.assertEqual(entries, [])

    def test_skips_comments_and_blanks(self):
        content = "# only comment\n\n   \n"
        entries = cl._parse_catalog_content(content, "x.txt", protocol="tcp")
        self.assertEqual(entries, [])


if __name__ == "__main__":
    unittest.main()
