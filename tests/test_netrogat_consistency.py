# tests/test_netrogat_consistency.py
"""netrogat: единый источник истины для дефолтных исключений.

Три представления должны совпадать байт-в-домен:
  * core.hostlist_manager.DEFAULT_NETROGAT  (runtime: reset / авто-создание);
  * import/lists/netrogat.base.txt          (бандл-база, деплоится на роутер);
  * import/lists/netrogat.txt               (итоговый = base + user, user пуст).

Без этого теста «Сбросить к дефолтам» давал бы 20 доменов, а свежая установка —
другой (полный) набор из бандла (issue #166: слияние netrogat + list-exclude).
"""

import os
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
LISTS_DIR = os.path.join(HERE, "..", "import", "lists")


def _read_domains(path):
    """Домены из txt: непустые строки без комментариев, в порядке файла."""
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


class TestNetrogatConsistency(unittest.TestCase):

    def setUp(self):
        from core.hostlist_manager import DEFAULT_NETROGAT
        self.defaults = list(DEFAULT_NETROGAT)
        self.base = _read_domains(os.path.join(LISTS_DIR, "netrogat.base.txt"))
        self.final = _read_domains(os.path.join(LISTS_DIR, "netrogat.txt"))
        self.user_path = os.path.join(LISTS_DIR, "netrogat.user.txt")

    def test_no_duplicates_in_defaults(self):
        seen = [d for d in self.defaults if self.defaults.count(d) > 1]
        self.assertEqual(seen, [], "дубликаты в DEFAULT_NETROGAT: %s" % set(seen))

    def test_defaults_match_base(self):
        # Порядок тоже важен — это один и тот же канонический список.
        self.assertEqual(self.defaults, self.base,
                         "DEFAULT_NETROGAT разошёлся с netrogat.base.txt")

    def test_final_equals_base_plus_user(self):
        user = _read_domains(self.user_path) if os.path.isfile(self.user_path) else []
        self.assertEqual(self.final, self.base + user,
                         "netrogat.txt != base + user")

    def test_merge_166_additions_present(self):
        # Домены из issue #166 (запрошенные пользователем) обязаны быть.
        for d in ("taxcom.ru", "1c-edo.ru", "1c.ru", "crpt.ru",
                  "egais.ru", "gov.ru", "atol.ru"):
            self.assertIn(d, self.final, "%s отсутствует в netrogat" % d)

    def test_merge_list_exclude_present(self):
        # Ключевые домены из влитого list-exclude.txt.
        for d in ("twitch.tv", "donationalerts.com", "citilink.ru",
                  "dns-shop.ru", "2ip.ru"):
            self.assertIn(d, self.final,
                          "%s (из list-exclude) отсутствует" % d)

    def test_list_exclude_removed(self):
        # Файл-сирота удалён (влит в netrogat).
        self.assertFalse(
            os.path.isfile(os.path.join(LISTS_DIR, "list-exclude.txt")),
            "list-exclude.txt должен быть удалён (влит в netrogat)")


if __name__ == "__main__":
    unittest.main()
