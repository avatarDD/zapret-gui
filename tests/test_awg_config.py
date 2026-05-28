# tests/test_awg_config.py
"""
Unit-тесты для core/awg_config.py — парсер .conf-файлов.
"""

import unittest

from core.awg_config import parse_conf, validate, render_conf


SIMPLE_CONF = """[Interface]
PrivateKey = qK4xn2cV7g7H4ICm3w4f5G9k2vRl0pZ8H8Y0OqWQS3w=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = B5dN1RoG3Jp1A7vWcDjI5xqRsX9cQYTuVE2KAFAVqXk=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

AWG_CONF = """[Interface]
PrivateKey = aP1xJU3a3lYwTzZyB7hN4mE8oQ2rWcKfIvCdEh6gXyo=
Address = 10.66.66.2/32
Jc = 3
Jmin = 50
Jmax = 1000

[Peer]
PublicKey = X4iC8z2qOaP3nE5gF7hM6kL9pR1tWcVbI0oUyA3sJdM=
Endpoint = awg.example.com:5000
AllowedIPs = 0.0.0.0/0
"""


class TestParseConfBasic(unittest.TestCase):

    def test_simple_wg(self):
        cfg = parse_conf(SIMPLE_CONF)
        self.assertEqual(cfg["interface"]["PrivateKey"],
                         "qK4xn2cV7g7H4ICm3w4f5G9k2vRl0pZ8H8Y0OqWQS3w=")
        self.assertEqual(cfg["interface"]["Address"], "10.0.0.2/32")
        self.assertEqual(len(cfg["peers"]), 1)
        peer = cfg["peers"][0]
        self.assertEqual(peer["Endpoint"], "vpn.example.com:51820")
        # AllowedIPs парсер собирает в list при разделении запятой
        # (см. _set_field в awg_config.py).
        self.assertIn(peer["AllowedIPs"],
                      ("0.0.0.0/0, ::/0",
                       ["0.0.0.0/0", "::/0"]))

    def test_awg_extra_fields(self):
        cfg = parse_conf(AWG_CONF)
        self.assertEqual(cfg["interface"]["Jc"],   "3")
        self.assertEqual(cfg["interface"]["Jmin"], "50")
        self.assertEqual(cfg["interface"]["Jmax"], "1000")

    def test_empty_input(self):
        cfg = parse_conf("")
        self.assertEqual(cfg["interface"], {})
        self.assertEqual(cfg["peers"], [])

    def test_comments_ignored(self):
        text = """# header comment
[Interface]
; semicolon comment
PrivateKey = abc
# inline
"""
        cfg = parse_conf(text)
        self.assertEqual(cfg["interface"]["PrivateKey"], "abc")

    def test_multiple_peers(self):
        text = """[Interface]
PrivateKey = a

[Peer]
PublicKey = p1
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = p2
AllowedIPs = 10.0.1.0/24
"""
        cfg = parse_conf(text)
        self.assertEqual(len(cfg["peers"]), 2)
        self.assertEqual(cfg["peers"][0]["PublicKey"], "p1")
        self.assertEqual(cfg["peers"][1]["PublicKey"], "p2")


class TestValidate(unittest.TestCase):

    def test_complete_valid(self):
        cfg = parse_conf(SIMPLE_CONF)
        errors = validate(cfg)
        # PrivateKey + Address + хотя бы один [Peer] с PublicKey и
        # Endpoint должны проходить.
        self.assertEqual(errors, [],
                         msg="Простой valid-conf не должен давать ошибок: %s"
                             % errors)

    def test_missing_interface_section(self):
        errors = validate({"interface": {}, "peers": []})
        self.assertGreater(len(errors), 0)

    def test_peer_without_public_key(self):
        cfg = {
            "interface": {"PrivateKey": "abc", "Address": "10.0.0.2/32"},
            "peers":     [{"Endpoint": "host:1234"}],
        }
        errors = validate(cfg)
        self.assertTrue(any("PublicKey" in e for e in errors))


class TestRender(unittest.TestCase):

    def test_render_roundtrip(self):
        cfg = parse_conf(SIMPLE_CONF)
        rendered = render_conf(cfg)
        # Roundtrip — содержание сохраняется (текстуально может
        # отличаться форматирование, но ключевые поля все на месте).
        cfg2 = parse_conf(rendered)
        self.assertEqual(cfg2["interface"]["PrivateKey"],
                         cfg["interface"]["PrivateKey"])
        self.assertEqual(cfg2["peers"][0]["PublicKey"],
                         cfg["peers"][0]["PublicKey"])
        self.assertEqual(cfg2["peers"][0]["Endpoint"],
                         cfg["peers"][0]["Endpoint"])


if __name__ == "__main__":
    unittest.main()
