# tests/test_awg_config_bom.py
"""Регрессия issue #319: конфиг из приложения Amnezia не добавлялся.

Десктопный AmneziaVPN сохраняет .conf в UTF-8 **с сигнатурой** (BOM).
Первая строка приезжала как `﻿[Interface]`, регулярка секции её не
узнавала — и на совершенно корректном конфиге пользователь получал
«Отсутствует секция [Interface]». Браузер BOM тоже не убирает:
`FileReader.readAsText()` отдаёт его в тексте как есть, поэтому чистить
нужно на разборе — через него проходят и загрузка файлом, и вставка
текстом, и импорт подписок.

Заодно проверяем, что конфиг из issue разбирается целиком: H1..H4 там
заданы ДИАПАЗОНАМИ (AmneziaWG 2.0), а `I1` пустой.
"""

import unittest

from core import awg_config as ac


BODY = """[Interface]
PrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=
Address = 10.9.9.4/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = 3
Jmin = 38
Jmax = 70
S1 = 63
S2 = 44
S3 = 47
S4 = 5
H1 = 479794990-486422101
H2 = 640533341-1040087653
H3 = 1205678824-1325594526
H4 = 1554356161-1607052731
I1 =

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 31.76.70.86:443
AllowedIPs = 0.0.0.0/0, ::/0
"""


class TestBom(unittest.TestCase):

    def _ok(self, text, label):
        cfg = ac.parse_conf(text)
        self.assertTrue(cfg["interface"], "%s: секция [Interface] потеряна" % label)
        self.assertEqual(ac.validate(cfg), [], label)
        return cfg

    def test_utf8_bom(self):
        self._ok("﻿" + BODY, "BOM")

    def test_utf8_bom_with_crlf(self):
        self._ok("﻿" + BODY.replace("\n", "\r\n"), "BOM+CRLF")

    def test_bom_decoded_as_latin1(self):
        """Пересылка конфига через мессенджер даёт «ï»¿» вместо BOM."""
        self._ok("ï»¿" + BODY, "mojibake BOM")

    def test_plain_still_parses(self):
        self._ok(BODY, "без BOM")

    def test_bom_does_not_leak_into_first_field(self):
        cfg = ac.parse_conf("﻿" + BODY)
        self.assertNotIn("﻿", "".join(cfg["interface"].keys()))
        self.assertTrue(cfg["interface"]["PrivateKey"].startswith("QMPTZ5"))


class TestIssue319Config(unittest.TestCase):
    """Сам конфиг из issue должен проходить весь путь сохранения."""

    def test_header_ranges_and_empty_i1(self):
        cfg = ac.parse_conf(BODY)
        self.assertEqual(cfg["interface"]["H1"], "479794990-486422101")
        self.assertEqual(cfg["interface"]["I1"], "")
        self.assertEqual(ac.validate(cfg), [])

    def test_save_pipeline_render_and_revalidate(self):
        cfg = ac.parse_conf("﻿" + BODY)
        ac.ensure_persistent_keepalive(cfg)
        text = ac.render_conf(cfg)
        self.assertIn("[Interface]", text.splitlines()[0])
        self.assertEqual(ac.validate(ac.parse_conf(text)), [])
        # Пустой I1 не должен уезжать в setconf пустой строкой.
        self.assertNotIn("I1 =", ac.render_setconf(cfg))


class TestRequiredGeneration(unittest.TestCase):
    """`awg setconf … Unable to modify interface: Invalid argument`.

    Это EINVAL от ДЕМОНА: тулза ключ разобрала и передала дальше, а
    amneziawg-go значение не принял. Практически всегда — разрыв
    поколений: профиль из свежего клиента Amnezia приносит поля AWG 2.0
    (S3/S4, диапазоны H1..H4), а на роутере движок постарше. Снаружи
    видно только «Invalid argument», поэтому поколение конфига считаем
    сами и пишем в сообщение.
    """

    def test_issue_config_needs_2_0(self):
        need = ac.required_generation(ac.parse_conf(BODY))
        self.assertEqual(need["generation"], "2.0")
        self.assertIn("S3", need["fields"])
        self.assertIn("H1 (диапазон)", need["fields"])

    def test_plain_v1_config_needs_nothing(self):
        cfg = ac.parse_conf(
            "[Interface]\nPrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=\n"
            "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\n"
            "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n")
        self.assertEqual(ac.required_generation(cfg)["generation"], "1.0")

    def test_zero_s3_s4_do_not_raise_the_bar(self):
        """S3/S4 = 0 — это «выключено», движку 2.0 для такого не нужен."""
        cfg = ac.parse_conf(
            "[Interface]\nPrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=\n"
            "S3 = 0\nS4 = 0\nH1 = 5\n")
        self.assertEqual(ac.required_generation(cfg)["generation"], "1.0")

    def test_signature_packets_need_1_5(self):
        cfg = ac.parse_conf(
            "[Interface]\nPrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=\n"
            "I1 = <b 0xdeadbeef>\n")
        self.assertEqual(ac.required_generation(cfg)["generation"], "1.5")

    def test_awg3_fields_need_3_0(self):
        cfg = ac.parse_conf(
            "[Interface]\nPrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=\n"
            "RekeyAfterTime = 120\n")
        self.assertEqual(ac.required_generation(cfg)["generation"], "3.0")


class TestSetconfFailureHint(unittest.TestCase):

    def _hint(self, err, conf_text=BODY):
        from unittest import mock
        from core.awg_manager import get_awg_manager
        mgr = get_awg_manager()
        setconf = ac.render_setconf(ac.parse_conf(conf_text))
        with mock.patch("core.awg_manager._run",
                        return_value=(0, "amneziawg-go v0.2.19", "")):
            return mgr._setconf_failure_hint(err, setconf)

    def test_invalid_argument_explains_generation(self):
        hint = self._hint("Unable to modify interface: Invalid argument")
        self.assertIn("2.0", hint)
        self.assertIn("S3", hint)
        self.assertIn("amneziawg-go v0.2.19", hint)

    def test_line_unrecognized_also_explained(self):
        self.assertIn("2.0", self._hint("Line unrecognized: 'S3 = 47'"))

    def test_unrelated_error_gets_no_hint(self):
        self.assertEqual(self._hint("Unable to access interface: No such device"), "")

    def test_plain_v1_config_gets_no_hint(self):
        conf = ("[Interface]\n"
                "PrivateKey = QMPTZ5Dj5TLuwGO/hOSJAWkAgwWZ1lXgLbTNOxKWM10=\n"
                "Jc = 4\nJmin = 40\nJmax = 70\nH1 = 1\n\n"
                "[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n"
                "AllowedIPs = 0.0.0.0/0\n")
        self.assertEqual(
            self._hint("Unable to modify interface: Invalid argument", conf), "")


if __name__ == "__main__":
    unittest.main()
