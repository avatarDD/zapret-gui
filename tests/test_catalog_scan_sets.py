# tests/test_catalog_scan_sets.py
"""
Наборы подбора из каталогов: под трафик цели, разнообразные, без повторов.

Раньше быстрый набор брал первые 30 записей с меткой ``recommended`` по
алфавиту файлов: для TLS-цели это были 30 HTTP-приёмов из http80_*, для
QUIC — 27 приёмов голоса Discord. А одноимённые записи с разными
аргументами прятали друг друга: QUIC-версии ``fake_2_n2`` и соседей не
видел ни подбор, ни список стратегий.

Проверяется на настоящих каталогах из поставки.
"""

import collections
import os
import tempfile
import unittest

from core.catalog_loader import (CatalogManager, catalog_family,
                                 get_catalog_manager, technique_key)
from core.scan_targets import detect_target, traffic_family


class TestFamilies(unittest.TestCase):

    def test_family_by_file(self):
        for name, fam in (("http80_zapret2_advanced.txt", "http"),
                          ("tcp_zapret2_basic.txt", "tls"),
                          ("udp_z2k_advanced.txt", "quic"),
                          ("discord_voice_zapret2_basic.txt", "voice"),
                          ("voice.txt", "voice"),
                          ("winws2_presets.txt", "")):
            with self.subTest(name=name):
                self.assertEqual(catalog_family(name), fam)

    def test_family_of_targets(self):
        self.assertEqual(traffic_family(detect_target("youtube.com"), "tcp"),
                         "tls")
        self.assertEqual(traffic_family(detect_target("youtube.com"), "udp"),
                         "quic")
        self.assertEqual(traffic_family(detect_target("discord.com"), "udp"),
                         "voice")


class TestScanSets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cm = get_catalog_manager()
        cls.cm.reload()

    def _check(self, protocol, family):
        for getter in (self.cm.get_quick_set, self.cm.get_standard_set,
                       self.cm.get_full_set):
            entries = getter(protocol=protocol, family=family)
            with self.subTest(set=getter.__name__, family=family):
                self.assertTrue(entries)
                fams = {catalog_family(e.source_file) for e in entries}
                self.assertLessEqual(fams, {"", family})
                args = collections.Counter(" ".join(e.get_args_list())
                                           for e in entries)
                self.assertEqual([a for a, n in args.items() if n > 1], [])

    def test_sets_match_target_traffic(self):
        for protocol, family in (("tcp", "tls"), ("tcp", "http"),
                                 ("udp", "quic"), ("udp", "voice")):
            self._check(protocol, family)

    def test_quick_set_is_diverse(self):
        quick = self.cm.get_quick_set(protocol="tcp", family="tls")
        self.assertEqual(len(quick), 30)
        # Не 30 вариаций одного приёма, а разные техники.
        self.assertGreaterEqual(len({technique_key(e) for e in quick}), 20)

    def test_quic_variants_are_not_hidden(self):
        full = self.cm.get_full_set(protocol="udp", family="quic")
        self.assertGreaterEqual(len(full), 50)


class TestDisambiguateIds(unittest.TestCase):
    """Одноимённые записи с разными аргументами получают разные id."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="catalogs-")
        os.makedirs(os.path.join(self.dir, "basic"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))

    def _write(self, name, body):
        with open(os.path.join(self.dir, "basic", name), "w",
                  encoding="utf-8") as f:
            f.write(body)

    def test_second_variant_is_renamed_and_visible(self):
        self._write("discord_voice_x.txt",
                    "[fake_2]\nname = fake 2\n--lua-desync=fake:blob=a\n")
        self._write("udp_x.txt",
                    "[fake_2]\nname = fake 2\n--lua-desync=fake:blob=b\n"
                    "[same]\nname = same\n--lua-desync=fake\n")
        self._write("voice_y.txt",
                    "[same]\nname = same\n--lua-desync=fake\n")
        cm = CatalogManager(catalogs_dir=self.dir)
        entries = cm.get_all_for_protocol("udp")
        ids = sorted(e.section_id for e in entries)
        self.assertIn("fake_2", ids)
        renamed = [e for e in entries if e.section_id.startswith("fake_2__")]
        self.assertEqual(len(renamed), 1)
        self.assertIn("QUIC", renamed[0].name)
        # Одинаковые аргументы под одним id — не «вариант», а повтор.
        self.assertEqual(ids.count("same"), 1)
        self.assertFalse(any(i.startswith("same__") for i in ids))


if __name__ == "__main__":
    unittest.main()
