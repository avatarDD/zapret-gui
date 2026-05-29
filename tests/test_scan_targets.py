# tests/test_scan_targets.py
"""Unit-тесты для core/scan_targets.py (detect_target)."""

import unittest

from core.scan_targets import detect_target, ScanTarget


class TestDetectTarget(unittest.TestCase):

    def test_known_youtube(self):
        t = detect_target("youtube.com")
        self.assertEqual(t.key, "youtube")
        self.assertEqual(t.primary_host, "youtube.com")

    def test_youtube_alias_googlevideo(self):
        t = detect_target("rr1---sn-x.googlevideo.com")
        self.assertEqual(t.key, "youtube")
        # нестандартный домен попадает в primary + hostlist
        self.assertEqual(t.primary_host, "rr1---sn-x.googlevideo.com")
        self.assertIn("rr1---sn-x.googlevideo.com", t.hostlist_domains)

    def test_discord(self):
        self.assertEqual(detect_target("discord.com").key, "discord")

    def test_generic_unknown(self):
        t = detect_target("example.org")
        self.assertEqual(t.key, "generic")
        self.assertEqual(t.primary_host, "example.org")
        self.assertEqual(t.hostlist_domains, ["example.org"])

    def test_empty_defaults_to_youtube(self):
        t = detect_target("")
        self.assertEqual(t.primary_host, "youtube.com")

    def test_case_insensitive(self):
        self.assertEqual(detect_target("YouTube.COM").key, "youtube")

    def test_defaults_present(self):
        t = detect_target("foo.bar")
        self.assertEqual(t.tcp_ports, "443")
        self.assertEqual(t.udp_l7, "quic")
        self.assertIsInstance(t, ScanTarget)


if __name__ == "__main__":
    unittest.main()
