# tests/test_awg_config.py
"""
Unit-тесты для core/awg_config.py — парсер .conf-файлов.
"""

import unittest

from core.awg_config import (parse_conf, validate, render_conf, render_setconf,
                             ensure_persistent_keepalive)


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


class TestAwgObfuscationFields(unittest.TestCase):
    """Регрессия: голого поля `I` в AmneziaWG НЕТ — есть только I1..I5.

    amneziawg-tools (src/config.c) в [Interface] матчит лишь "I1".."I5";
    строка `I = ...` для `awg setconf` — неизвестный ключ, и тулза
    отбросила бы весь конфиг (туннель не поднимется). Поэтому
    render_setconf не должен выводить голое `I`, а validate — не считать
    его числовым параметром обфускации.
    """

    CONF = """[Interface]
PrivateKey = aP1xJU3a3lYwTzZyB7hN4mE8oQ2rWcKfIvCdEh6gXyo=
Address = 10.66.66.2/32
Jc = 4
S1 = 30
H1 = 5
I = oops
I1 = <b 0xf6ab34c1>

[Peer]
PublicKey = X4iC8z2qOaP3nE5gF7hM6kL9pR1tWcVbI0oUyA3sJdM=
Endpoint = awg.example.com:5000
AllowedIPs = 0.0.0.0/0
"""

    def test_bare_I_not_sent_to_setconf(self):
        setconf = render_setconf(parse_conf(self.CONF))
        lines = [ln.strip() for ln in setconf.splitlines()]
        # голое `I` НЕ уходит в `awg setconf`
        self.assertNotIn("I = oops", setconf)
        self.assertFalse(
            any(ln.startswith("I =") for ln in lines),
            msg="голое поле I не должно попадать в setconf: %r" % setconf)
        # реальные параметры обфускации — уходят
        self.assertIn("Jc = 4", setconf)
        self.assertIn("S1 = 30", setconf)
        self.assertIn("H1 = 5", setconf)
        # signature-пакет I1 уходит в нативной обёртке <b 0x..>
        self.assertIn("I1 = <b 0xf6ab34c1>", setconf)

    def test_bare_I_not_validated_as_number(self):
        errors = validate(parse_conf(self.CONF))
        self.assertFalse(
            any(e.startswith("[Interface] I ") for e in errors),
            msg="голое I не должно валидироваться как число: %s" % errors)


class TestAwgHeaderRange(unittest.TestCase):
    """H1..H4: одиночный uint (1.0) ИЛИ диапазон `N-M` (AmneziaWG 2.0).

    Раньше validate() проверял H1..H4 как строгий int и зря отклонял
    валидный 2.0-конфиг с `H1 = 5-100`. Остальные числовые поля
    обфускации (Jc/Jmin/Jmax/S1..S4/Itime) остаются строгими int.
    """

    TMPL = ("[Interface]\n"
            "PrivateKey = aP1xJU3a3lYwTzZyB7hN4mE8oQ2rWcKfIvCdEh6gXyo=\n"
            "Address = 10.66.66.2/32\n"
            "%s\n\n"
            "[Peer]\n"
            "PublicKey = X4iC8z2qOaP3nE5gF7hM6kL9pR1tWcVbI0oUyA3sJdM=\n"
            "Endpoint = awg.example.com:5000\n"
            "AllowedIPs = 0.0.0.0/0\n")

    def _errors_for(self, line, needle):
        return [e for e in validate(parse_conf(self.TMPL % line)) if needle in e]

    def test_single_uint_ok(self):
        self.assertEqual(self._errors_for("H1 = 1234567", "H1"), [])

    def test_range_ok(self):
        # ключевая регрессия: диапазон N-M больше не считается ошибкой
        self.assertEqual(self._errors_for("H1 = 5-100", "H1"), [])
        self.assertEqual(self._errors_for("H4 = 0-4294967295", "H4"), [])

    def test_garbage_rejected(self):
        self.assertTrue(self._errors_for("H2 = abc", "H2"))

    def test_inverted_range_rejected(self):
        self.assertTrue(self._errors_for("H3 = 100-5", "H3"))

    def test_other_numeric_fields_still_strict(self):
        # range-синтаксис — только у H*; у прочих полей по-прежнему строгий int
        self.assertTrue(self._errors_for("Jmin = abc", "Jmin"))
        self.assertTrue(self._errors_for("S1 = 1-2", "S1"))


class TestSetconfZeroObfuscation(unittest.TestCase):
    """
    render_setconf не должен отдавать в `awg setconf` нулевую junk-
    обфускацию (Jc/Jmin/Jmax) и нулевые заголовки (H1..H4): amneziawg-go
    требует jc/jmin/jmax > 0 ("jc must be a positive value") и падает с
    "Unable to modify interface: Invalid argument", а H*=0 ломает тип
    сообщения. Семантика «все нули = обычный WireGuard» (docs.amnezia.org)
    реализуется именно пропуском этих полей.
    """

    PRIV = "aP1xJU3a3lYwTzZyB7hN4mE8oQ2rWcKfIvCdEh6gXyo="

    def _setconf(self, iface_extra):
        cfg = {"interface": dict({"PrivateKey": self.PRIV}, **iface_extra),
               "peers": []}
        return render_setconf(cfg)

    def test_all_zero_vanilla_omits_junk_and_headers(self):
        sc = self._setconf({"Jc": 0, "Jmin": 0, "Jmax": 0,
                            "S1": 0, "S2": 0,
                            "H1": 0, "H2": 0, "H3": 0, "H4": 0})
        low = sc.lower()
        for k in ("jc", "jmin", "jmax", "h1", "h2", "h3", "h4"):
            self.assertNotIn(k + " =", low,
                             msg="%s=0 не должно уходить в setconf: %r" % (k, sc))
        # S1/S2 = 0 корректны для демона (нулевой паддинг) — остаются
        self.assertIn("s1 = 0", low)

    def test_valid_junk_and_std_headers_preserved(self):
        sc = self._setconf({"Jc": 4, "Jmin": 40, "Jmax": 70,
                            "S1": 0, "S2": 0,
                            "H1": 1, "H2": 2, "H3": 3, "H4": 4})
        self.assertIn("Jc = 4", sc)
        self.assertIn("Jmin = 40", sc)
        self.assertIn("Jmax = 70", sc)
        self.assertIn("H1 = 1", sc)
        self.assertIn("H4 = 4", sc)

    def test_partial_junk_dropped_atomically(self):
        # неполный junk (jmax=0) невалиден для демона → группа целиком
        # не уходит, чтобы setconf не упал на jmax=0.
        sc = self._setconf({"Jc": 4, "Jmin": 40, "Jmax": 0})
        low = sc.lower()
        self.assertNotIn("jc =", low)
        self.assertNotIn("jmin =", low)
        self.assertNotIn("jmax =", low)


class TestEnsurePersistentKeepalive(unittest.TestCase):
    """При создании/импорте конфигов проставляем PersistentKeepalive=25
    каждому peer'у без него; явное значение (в т.ч. 0) не трогаем."""

    def _peer(self, **extra):
        p = {"PublicKey": "B5dN1RoG3Jp1A7vWcDjI5xqRsX9cQYTuVE2KAFAVqXk=",
             "Endpoint": "vpn.example.com:51820", "AllowedIPs": "0.0.0.0/0"}
        p.update(extra)
        return {"interface": {"PrivateKey": "x"}, "peers": [p]}

    def test_adds_when_missing(self):
        cfg = self._peer()
        self.assertTrue(ensure_persistent_keepalive(cfg))
        self.assertEqual(cfg["peers"][0]["PersistentKeepalive"], 25)

    def test_preserves_existing(self):
        cfg = self._peer(PersistentKeepalive=15)
        self.assertFalse(ensure_persistent_keepalive(cfg))
        self.assertEqual(cfg["peers"][0]["PersistentKeepalive"], 15)

    def test_does_not_override_explicit_zero(self):
        # 0 = keepalive выключен пользователем — уважаем.
        cfg = self._peer(PersistentKeepalive=0)
        self.assertFalse(ensure_persistent_keepalive(cfg))
        self.assertEqual(cfg["peers"][0]["PersistentKeepalive"], 0)

    def test_multiple_peers(self):
        cfg = self._peer()
        cfg["peers"].append({"PublicKey": "k", "Endpoint": "h:1",
                             "AllowedIPs": "::/0", "PersistentKeepalive": 10})
        self.assertTrue(ensure_persistent_keepalive(cfg))
        self.assertEqual(cfg["peers"][0]["PersistentKeepalive"], 25)
        self.assertEqual(cfg["peers"][1]["PersistentKeepalive"], 10)

    def test_rendered_conf_contains_line(self):
        cfg = self._peer()
        ensure_persistent_keepalive(cfg)
        self.assertIn("PersistentKeepalive = 25", render_conf(cfg))


class TestFieldsUnsupportedByTools(unittest.TestCase):
    """`J1..J3`/`Itime` не должны попадать в `awg setconf`.

    Документация протокола AmneziaWG 2.0 их описывает, но парсер
    amneziawg-tools (`key_match` в src/config.c) их не знает — проверено на
    релизах v1.0.20260618-2 и v3.0.20260730. На неизвестном ключе config.c
    делает `goto error`: печатает `Line unrecognized` и отбрасывает
    **весь** конфиг, то есть интерфейс не поднимается вообще, а в логе
    видно лишь невнятное «Unable to modify interface».

    При этом терять поля нельзя: пользователь импортирует .conf из клиента
    Amnezia, и round-trip обязан их сохранять.
    """

    CONF = (
        "[Interface]\n"
        "PrivateKey = aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTI=\n"
        "ListenPort = 51820\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 15\nS2 = 30\n"
        "I1 = <b 0xdeadbeef>\n"
        "J1 = <b 0xcafebabe>\n"
        "J2 = <b 0xfeedface>\n"
        "Itime = 30\n"
        "\n[Peer]\n"
        "PublicKey = aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTI=\n"
        "Endpoint = 1.2.3.4:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )

    def setUp(self):
        self.cfg = parse_conf(self.CONF)

    def test_setconf_omits_unsupported_fields(self):
        setconf = render_setconf(self.cfg)
        for field in ("J1", "J2", "J3", "Itime"):
            self.assertNotIn(
                field + " ", setconf,
                "%s ушло в setconf — amneziawg-tools отвергнет весь конфиг "
                "с «Line unrecognized»" % field)

    def test_setconf_keeps_fields_tools_do_support(self):
        """Соседние поля обфускации при этом остаются на месте."""
        setconf = render_setconf(self.cfg)
        for field in ("Jc", "Jmin", "Jmax", "S1", "S2", "I1"):
            self.assertIn(field, setconf,
                          "%s поддерживается tools и должно уходить в "
                          "setconf" % field)

    def test_round_trip_preserves_unsupported_fields(self):
        """В самом .conf поля сохраняются — иначе потеряем при импорте."""
        text = render_conf(self.cfg)
        for field in ("J1", "J2", "Itime"):
            self.assertIn(field, text,
                          "%s потерялось при round-trip" % field)
        again = parse_conf(text)
        self.assertEqual(again["interface"].get("Itime"),
                         self.cfg["interface"].get("Itime"))

    def test_unsupported_list_matches_declaration(self):
        """Список не разъехался с тем, что реально пропускается."""
        from core.awg_config import (AWG_FIELDS_UNSUPPORTED_BY_TOOLS,
                                     WG_INTERFACE_FIELDS)
        for field in AWG_FIELDS_UNSUPPORTED_BY_TOOLS:
            self.assertIn(
                field, WG_INTERFACE_FIELDS,
                "%s должно оставаться известным полем (иначе validate "
                "заругается на легитимный конфиг Amnezia)" % field)


class TestAwg3Fields(unittest.TestCase):
    """Поколение AWG 3+ (ветка amneziawg-go v3.x).

    Ключи принимаются парсером amneziawg-tools (key_match в src/config.c
    v3.0.20260730), значит обязаны доходить до `awg setconf`. Раньше их не
    было в WG_INTERFACE_FIELDS: демон поднимался без защиты заголовка, а
    пир, который её ждёт, дропал data-пакеты — «92 B in / 20 KB out».
    """

    CONF = (
        "[Interface]\n"
        "PrivateKey = QFvE7YbLQZ7Nn3+ZL1kmFCPRE1BpBcDGcs+2c0T1YXQ=\n"
        "Address = 10.2.0.2/32\n"
        "S1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\n"
        "HeaderProtectionKey = mNk1PLcYbHRTPd0h2FzC9YZ0kSHqVvBv6mR6l7Kx0nA=\n"
        "ContentPaddingAddition = 10-40\n"
        "RekeyAfterTime = 120\n"
        "RekeyTimeout = 5\n"
        "RejectAfterTime = 180\n"
        "KeepaliveTimeout = (off)\n"
        "MaxHandshakeAttempts = 5\n"
        "\n"
        "[Peer]\n"
        "PublicKey = jNRPY62L5FXVfKQ6Yl8t2vT0/DiC2h3sB0YlxLKGZk4=\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )

    def test_valid_awg3_config_has_no_errors(self):
        self.assertEqual(validate(parse_conf(self.CONF)), [])

    def test_awg3_fields_reach_setconf(self):
        from core.awg_config import AWG3_INTERFACE_FIELDS
        text = render_setconf(parse_conf(self.CONF))
        for field in AWG3_INTERFACE_FIELDS:
            self.assertIn(field, text,
                          "%s обязано доходить до демона" % field)

    def test_awg3_fields_survive_roundtrip(self):
        cfg = parse_conf(render_conf(parse_conf(self.CONF)))
        self.assertEqual(cfg["interface"]["ContentPaddingAddition"], "10-40")
        self.assertEqual(cfg["interface"]["KeepaliveTimeout"], "(off)")

    def test_timings_accept_range_and_off(self):
        for value in ("120", "60-180", "(off)"):
            cfg = parse_conf(self.CONF.replace("RekeyAfterTime = 120",
                                               "RekeyAfterTime = %s" % value))
            self.assertEqual(validate(cfg), [], "RekeyAfterTime = %s" % value)

    def test_timings_reject_garbage(self):
        cfg = parse_conf(self.CONF.replace("RekeyAfterTime = 120",
                                           "RekeyAfterTime = abc"))
        self.assertTrue(any("RekeyAfterTime" in e for e in validate(cfg)))

    def test_header_protection_key_must_be_a_key(self):
        cfg = parse_conf(self.CONF.replace(
            "HeaderProtectionKey = mNk1PLcYbHRTPd0h2FzC9YZ0kSHqVvBv6mR6l7Kx0nA=",
            "HeaderProtectionKey = not-a-key"))
        self.assertTrue(any("HeaderProtectionKey" in e for e in validate(cfg)))

    def test_header_protection_requires_padding_at_least_12(self):
        """README: «Header protection requires S1-S4 value to be 12 at least»."""
        cfg = parse_conf(self.CONF.replace("S3 = 16", "S3 = 4"))
        errs = validate(cfg)
        self.assertTrue(any("не меньше 12" in e for e in errs), errs)

    def test_header_protection_without_padding_is_flagged(self):
        text = self.CONF
        for k in ("S1", "S2", "S3", "S4"):
            text = text.replace("%s = 16\n" % k, "")
        self.assertTrue(any("не меньше 12" in e for e in validate(parse_conf(text))))


class TestAwg31Fields(unittest.TestCase):
    """Поколение AWG 3.1 (amneziawg-go v3.1.20260814 + tools v3.1.20260812).

    Два булевых ключа устройства: RandomTrailers (случайный хвост у
    служебных пакетов, СИММЕТРИЧНЫЙ — приёмник допускает пакет больше
    ожидаемого только с этим флагом) и DisableCookies (не отвечать
    cookie-reply). В README апстрима их нет, источник — device/uapi.go и
    key_match в src/config.c.
    """

    CONF = (
        "[Interface]\n"
        "PrivateKey = QFvE7YbLQZ7Nn3+ZL1kmFCPRE1BpBcDGcs+2c0T1YXQ=\n"
        "Address = 10.2.0.2/32\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "RandomTrailers = on\n"
        "DisableCookies = off\n"
        "\n"
        "[Peer]\n"
        "PublicKey = jNRPY62L5FXVfKQ6Yl8t2vT0/DiC2h3sB0YlxLKGZk4=\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )

    def test_valid_config_has_no_errors(self):
        self.assertEqual(validate(parse_conf(self.CONF)), [])

    def test_fields_reach_setconf(self):
        from core.awg_config import AWG31_INTERFACE_FIELDS
        text = render_setconf(parse_conf(self.CONF))
        for field in AWG31_INTERFACE_FIELDS:
            self.assertIn(field, text,
                          "%s обязано доходить до демона" % field)

    def test_fields_survive_roundtrip(self):
        cfg = parse_conf(render_conf(parse_conf(self.CONF)))
        self.assertEqual(cfg["interface"]["RandomTrailers"], "on")
        self.assertEqual(cfg["interface"]["DisableCookies"], "off")

    def test_accepts_on_off_and_digits(self):
        for value in ("on", "off", "ON", "0", "1"):
            cfg = parse_conf(self.CONF.replace("RandomTrailers = on",
                                               "RandomTrailers = %s" % value))
            self.assertEqual(validate(cfg), [], "RandomTrailers = %s" % value)

    def test_rejects_true_false(self):
        # parse_bool в src/config.c знает только on/off и число; на true он
        # отбрасывает ВЕСЬ конфиг — ловим на импорте, пока видно виновника.
        for value in ("true", "false", "yes"):
            cfg = parse_conf(self.CONF.replace("RandomTrailers = on",
                                               "RandomTrailers = %s" % value))
            errs = validate(cfg)
            self.assertTrue(any("RandomTrailers" in e for e in errs),
                            "RandomTrailers = %s должно ругаться" % value)

    def test_bumps_generation_to_31_not_30(self):
        # Движок v3.0.x на этих UAPI-ключах отвечает EINVAL, поэтому
        # подсказка «нужен 3.0» увела бы пользователя не туда.
        from core.awg_config import required_generation
        need = required_generation(parse_conf(self.CONF))
        self.assertEqual(need["generation"], "3.1")
        self.assertIn("RandomTrailers", need["fields"])

    def test_config_without_them_stays_on_lower_generation(self):
        from core.awg_config import required_generation
        text = self.CONF.replace("RandomTrailers = on\n", "") \
                        .replace("DisableCookies = off\n", "")
        self.assertEqual(
            required_generation(parse_conf(text))["generation"], "1.0")


class TestPeerAdvancedSecurity(unittest.TestCase):
    """`AdvancedSecurity` есть в key_match секции [Peer] у amneziawg-tools."""

    CONF = (
        "[Interface]\n"
        "PrivateKey = QFvE7YbLQZ7Nn3+ZL1kmFCPRE1BpBcDGcs+2c0T1YXQ=\n"
        "\n"
        "[Peer]\n"
        "PublicKey = jNRPY62L5FXVfKQ6Yl8t2vT0/DiC2h3sB0YlxLKGZk4=\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "AdvancedSecurity = on\n"
    )

    def test_reaches_setconf(self):
        self.assertIn("AdvancedSecurity", render_setconf(parse_conf(self.CONF)))

    def test_config_is_valid(self):
        self.assertEqual(validate(parse_conf(self.CONF)), [])


class TestPersistentKeepaliveRange(unittest.TestCase):
    """AWG 3+ разрешает `PersistentKeepalive = 22-30` (тип range)."""

    def _conf(self, value):
        return (
            "[Interface]\n"
            "PrivateKey = QFvE7YbLQZ7Nn3+ZL1kmFCPRE1BpBcDGcs+2c0T1YXQ=\n"
            "\n"
            "[Peer]\n"
            "PublicKey = jNRPY62L5FXVfKQ6Yl8t2vT0/DiC2h3sB0YlxLKGZk4=\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = %s\n" % value
        )

    def test_accepts_plain_int_range_and_off(self):
        for value in ("25", "22-30", "(off)"):
            self.assertEqual(validate(parse_conf(self._conf(value))), [],
                             "PersistentKeepalive = %s" % value)

    def test_rejects_reversed_range(self):
        errs = validate(parse_conf(self._conf("30-22")))
        self.assertTrue(any("PersistentKeepalive" in e for e in errs))

    def test_rejects_out_of_bounds(self):
        errs = validate(parse_conf(self._conf("70000")))
        self.assertTrue(any("PersistentKeepalive" in e for e in errs))



if __name__ == "__main__":
    unittest.main()
