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


class TestHintsMatchByLabel(unittest.TestCase):
    """Профиль — по границам меток домена, а не по подстроке.

    `x.com` сидит внутри `netflix.com`, `t.me` — внутри `bit.media.ru`:
    раньше такие цели получали профиль twitter/telegram, и в пробы уходили
    чужие хосты.
    """

    def test_substring_lookalikes_are_generic(self):
        for host in ("netflix.com", "dropbox.com", "xbox.com",
                     "bit.media.ru", "notdiscord.com", "mygoogleblog.ru"):
            with self.subTest(host=host):
                self.assertEqual(detect_target(host).key, "generic")

    def test_real_members_keep_their_profile(self):
        for host, key in (("x.com", "twitter"), ("api.x.com", "twitter"),
                          ("pbs.twimg.com", "twitter"),
                          ("t.me", "telegram"),
                          ("web.telegram.org", "telegram"),
                          ("youtu.be", "youtube"),
                          ("rr1.googlevideo.com", "youtube"),
                          ("www.youtube-nocookie.com", "youtube"),
                          ("cdn.discordapp.com", "discord"),
                          ("scontent.fbcdn.net", "facebook")):
            with self.subTest(host=host):
                self.assertEqual(detect_target(host).key, key)


class TestProviderTargets(unittest.TestCase):
    """Cloudflare и крупные хостинги: основные цели разблокировки."""

    def test_cloudflare_profile(self):
        for host in ("one.one.one.one", "cloudflare.com",
                     "speed.cloudflare.com"):
            with self.subTest(host=host):
                self.assertEqual(detect_target(host).key, "cloudflare")
        t = detect_target("one.one.one.one")
        # Тело — со speed.cloudflare.com: корневая страница 1.1.1.1 мала
        # для пробы 64 КБ.
        self.assertIn("speed.cloudflare.com", t.get_probe_url())

    def test_hosting_profile_has_no_hostlist(self):
        t = detect_target("hel1-speed.hetzner.com")
        self.assertEqual(t.key, "hosting")
        # Блок по сети провайдера: стратегия для всего трафика.
        self.assertEqual(t.all_hostlist_domains(), [])
        for host in t.test_hosts:
            with self.subTest(host=host):
                url = t.get_probe_url(host)
                self.assertTrue(url.startswith("https://%s/" % host), url)
                self.assertNotEqual(url, "https://%s/" % host)

    def test_custom_host_inside_hosting_uses_its_own_url(self):
        t = detect_target("proof.ovh.net")
        self.assertEqual(t.key, "hosting")
        self.assertEqual(t.get_probe_url(),
                         "https://proof.ovh.net/files/1Mb.dat")
        self.assertTrue(t.no_hostlist)

    def test_youtube_probe_downloads_a_body(self):
        # generate_204 — ответ без тела: обрыв на 16-20 КБ не виден.
        self.assertNotIn("generate_204",
                         detect_target("youtube.com").get_probe_url())


if __name__ == "__main__":
    unittest.main()
