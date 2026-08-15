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


if __name__ == "__main__":
    unittest.main()
