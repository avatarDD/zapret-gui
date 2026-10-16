# tests/test_nfqws_menu_catalog.py
"""
Стратегии rndnaame/nfqws-menu: блобы, init_vars и повторы.

Проверяется на настоящих каталогах из поставки:

* каждый блоб, на который ссылаются ``nfqws_menu``-каталоги, известен
  реестру и лежит файлом в ``import/bin`` (иначе fake уходит пустым);
* ``seqovl_pattern=``/``pattern=`` не зовут имя из init_vars.lua без
  ``blob=`` того же имени: у nfqws-menu ``tls_google`` — файл 681 байт,
  а голое имя у нас — переменная init_vars (fake_default_tls с другим
  размером), и seqovl=681 перекрывал бы чужим узором;
* приёмы не повторяют аргументы приёмов того же семейства из других
  каталогов — импорт брал только новое.
"""

import glob
import os
import re
import unittest

from core import blob_registry
from core.catalog_loader import catalog_family, parse_catalog_file
from core.nfqws_manager import _INIT_VARS_NAMES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOGS = os.path.join(ROOT, "catalogs")
MENU_FILES = sorted(
    glob.glob(os.path.join(CATALOGS, "builtin", "nfqws_menu.txt"))
    + glob.glob(os.path.join(CATALOGS, "advanced", "*_nfqws_menu.txt")))

_REF_RE = re.compile(
    r"(?<![A-Za-z0-9_])(blob|seqovl_pattern|pattern)=([A-Za-z_][A-Za-z0-9_]*)")


def _entries(path):
    return parse_catalog_file(path)


def _desync(entry):
    return tuple(a for a in entry.get_args_list()
                 if a.startswith("--lua-desync="))


class TestNfqwsMenuCatalog(unittest.TestCase):

    def test_files_present(self):
        self.assertEqual(len(MENU_FILES), 5, MENU_FILES)
        presets = _entries(os.path.join(CATALOGS, "builtin", "nfqws_menu.txt"))
        self.assertEqual(len(presets), 27)

    def test_blobs_resolve_to_files(self):
        for path in MENU_FILES:
            for e in _entries(path):
                for kind, name in _REF_RE.findall(" ".join(e.get_args_list())):
                    if name in blob_registry.BUILTIN_BLOB_NAMES:
                        continue
                    if kind != "blob" and name in _INIT_VARS_NAMES:
                        continue      # отдельная проверка ниже
                    value = blob_registry.get_blob_value(name)
                    self.assertTrue(value, "%s: блоб %s не в реестре"
                                    % (e.section_id, name))
                    if value.startswith("0x"):
                        continue      # инлайновый hex (fake_default_udp)
                    fn = os.path.basename(value.lstrip("@"))
                    self.assertTrue(
                        os.path.exists(os.path.join(ROOT, "import", "bin", fn)),
                        "%s: нет файла %s" % (e.section_id, fn))

    def test_patterns_not_init_vars(self):
        for path in MENU_FILES:
            for e in _entries(path):
                refs = _REF_RE.findall(" ".join(e.get_args_list()))
                blobs = {n for k, n in refs if k == "blob"}
                for kind, name in refs:
                    if kind == "blob" or name in blobs:
                        continue
                    self.assertNotIn(name, _INIT_VARS_NAMES,
                                     "%s: %s=%s — это переменная init_vars, "
                                     "а не файл" % (e.section_id, kind, name))

    def test_onetrust_not_max(self):
        # «tls_max» nfqws-menu — 664 байта ClientHello www.onetrust.com;
        # наш tls_max — max.ru, и seqovl=664 с ним не сходится.
        for path in MENU_FILES:
            for e in _entries(path):
                for a in e.get_args_list():
                    self.assertNotRegex(a, r"(?<![a-z_])(blob|seqovl_pattern)=tls_max\b",
                                        e.section_id)

    def test_tricks_are_new(self):
        seen = {}
        for path in glob.glob(os.path.join(CATALOGS, "*", "*.txt")):
            if path in MENU_FILES or "/builtin/" in path:
                continue
            fam = catalog_family(path)
            for e in _entries(path):
                seen.setdefault((fam, _desync(e)), e.section_id)
        for path in MENU_FILES:
            if "/builtin/" in path:
                continue
            fam = catalog_family(path)
            own = set()
            for e in _entries(path):
                key = (fam, _desync(e))
                self.assertNotIn(key, seen, "%s повторяет %s"
                                 % (e.section_id, seen.get(key)))
                self.assertNotIn(key, own, e.section_id)
                own.add(key)


if __name__ == "__main__":
    unittest.main()
