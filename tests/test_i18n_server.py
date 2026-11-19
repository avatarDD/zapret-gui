"""Английские сообщения сервера: tools/i18n_extract_server.py и
web/js/i18n/en.server.js (docs/i18n.md)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "i18n_extract_server.py")
if not os.path.exists(TOOL):
    # На роутер tools/ не ставится: самодиагностика пропускает модуль.
    raise unittest.SkipTest("нет tools/i18n_extract_server.py")
sys.path.insert(0, os.path.join(ROOT, "tools"))

import i18n_extract_server as ex  # noqa: E402


def keys(src):
    return set(ex.extract_source(src))


class ExtractTest(unittest.TestCase):
    def test_literal_and_formats(self):
        got = keys(
            'log.info("Конфиг сохранён")\n'
            'log.info("Ошибка записи %s: %s" % (a, b))\n'
            'log.info(f"Запущен {name} (pid {pid})")\n'
            'log.info("Найдено: {}".format(n))\n'
            'raise ValueError("Порт " + str(p) + " занят")\n'
        )
        self.assertIn("Конфиг сохранён", got)
        self.assertIn("Ошибка записи {0}: {1}", got)
        self.assertIn("Запущен {0} (pid {1})", got)
        self.assertIn("Найдено: {0}", got)
        self.assertIn("Порт {0} занят", got)

    def test_skips_docstrings_compares_and_code(self):
        got = keys(
            'def f():\n'
            '    """Документация функции."""\n'
            '    if x == "сравнение":\n'
            '        pass\n'
            '    re.compile("регулярка")\n'
            '    s = "# комментарий конфига"\n'
            '    t = "if [ -x $(cmd) ]; then echo да; fi"\n'
        )
        self.assertEqual(got, set())

    def test_nonliteral_operand_gets_own_key(self):
        got = keys(
            "m = 'Нет стратегий' + ('' if p else ' (только прошедшие)')\n"
            "n = 'Порт ' + str(p) + ': ' + ('ошибка %s' % e)\n"
        )
        self.assertIn("Нет стратегий{0}", got)
        self.assertIn("(только прошедшие)", got)
        self.assertIn("Порт {0}: {1}", got)
        self.assertIn("ошибка {0}", got)

    def test_percent_in_plain_text_is_not_placeholder(self):
        self.assertIn("Прогресс: 50% done", keys('log("Прогресс: 50% done")'))

    def test_replacement_and_fstring_parts_collected(self):
        got = keys(
            'a = text.replace(value, "«скрыто»")\n'
            'b = "Статус: " + f"{\'включён\' if on else \'выключен\'}"\n'
            'c = re.sub("шаблон", "замена", s)\n'
            'd = "Нет подключения по wi-fi"\n'
        )
        self.assertTrue({"«скрыто»", "Статус: {0}", "включён", "выключен",
                         "замена", "Нет подключения по wi-fi"} <= got)
        self.assertNotIn("шаблон", got)

    def test_single_letters_skipped(self):
        self.assertEqual(keys("T = {'а': 'a', 'б': 'b'}"), set())

    def test_placeholders(self):
        self.assertEqual(ex.placeholders("a {1} b {0} {1}"),
                         ex.placeholders("{0} {1} x {1}"))


class DictTest(unittest.TestCase):
    def test_every_server_message_translated(self):
        d = ex.load_dict()
        missing = [k for k in ex.extract_all() if not d.get(k)]
        self.assertEqual(missing[:20], [],
                         "%d без перевода: python3 tools/i18n_extract_server.py "
                         "--missing" % len(missing))

    def test_values_are_english_with_same_placeholders(self):
        bad = [k for k, v in ex.load_dict().items()
               if ex.CYR.search(v) or ex.placeholders(k) != ex.placeholders(v)]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
