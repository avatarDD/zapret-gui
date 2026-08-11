# tests/test_catalog_merge.py
"""Merge и конвертация INI-каталогов стратегий (`core/catalog_merge`).

Раньше эта машинерия проверялась заодно с загрузчиком каталогов
(`tests/test_catalog_updater.py`). Загрузчик убран вместе с исчезнувшим
источником, а merge остался — им пользуется `core/asset_importer` при
импорте bundled-каталогов на установке и обновлении GUI. Ошибка здесь
тихо съедает пользовательские стратегии, поэтому покрытие переехало
сюда.
"""

import unittest

from core import catalog_merge as cm


class TestParseIniSections(unittest.TestCase):

    def test_header_and_sections_split(self):
        header, sections = cm._parse_ini_sections(
            "# шапка\n"
            "\n"
            "[alpha]\n"
            "--lua-desync=fake\n"
            "\n"
            "[beta]\n"
            "--lua-desync=multisplit\n"
        )
        self.assertIn("# шапка", header)
        self.assertEqual(list(sections), ["alpha", "beta"])
        self.assertIn("--lua-desync=fake", sections["alpha"])

    def test_duplicate_ids_collapse_to_last(self):
        _, sections = cm._parse_ini_sections(
            "[dup]\n--first\n"
            "[dup]\n--second\n"
        )
        self.assertEqual(list(sections), ["dup"])
        self.assertIn("--second", sections["dup"])
        self.assertNotIn("--first", sections["dup"])

    def test_empty_content(self):
        header, sections = cm._parse_ini_sections("")
        self.assertEqual(header, [])
        self.assertEqual(list(sections), [])


class TestMergeContent(unittest.TestCase):

    def test_remote_wins_local_survives(self):
        local = "[common]\n--old\n\n[mine]\n--custom\n"
        remote = "[common]\n--new\n\n[fresh]\n--brand-new\n"

        merged, added, updated, preserved = cm._merge_content(local, remote)

        self.assertEqual((added, updated, preserved), (1, 1, 1))
        # Апстрим победил на коллизии...
        self.assertIn("--new", merged)
        self.assertNotIn("--old", merged)
        # ...новая секция приехала, а локальная не потерялась.
        self.assertIn("[fresh]", merged)
        self.assertIn("[mine]", merged)
        self.assertIn("--custom", merged)

    def test_no_duplicate_section_ids(self):
        merged, _, _, _ = cm._merge_content(
            "[a]\n--x\n[b]\n--y\n", "[a]\n--z\n")
        _, sections = cm._parse_ini_sections(merged)
        self.assertEqual(sorted(sections), ["a", "b"])
        self.assertEqual(merged.count("[a]"), 1)

    def test_merge_is_idempotent(self):
        remote = "[a]\n--x\n\n[b]\n--y\n"
        once, _, _, _ = cm._merge_content("", remote)
        twice, added, _, preserved = cm._merge_content(once, remote)
        self.assertEqual(once, twice)
        self.assertEqual((added, preserved), (0, 0))

    def test_empty_local_takes_everything(self):
        merged, added, updated, preserved = cm._merge_content(
            "", "[a]\n--x\n")
        self.assertEqual((added, updated, preserved), (1, 0, 0))
        self.assertIn("[a]", merged)

    def test_empty_remote_keeps_local(self):
        merged, added, updated, preserved = cm._merge_content(
            "[mine]\n--custom\n", "")
        self.assertEqual((added, updated, preserved), (0, 0, 1))
        self.assertIn("--custom", merged)


class TestPresetConversion(unittest.TestCase):

    def test_windows_only_flags_are_stripped(self):
        result = cm._convert_preset(
            "Discord.txt",
            "--wf-tcp=443\n--lua-desync=fake\n",
        )
        self.assertIsNotNone(result)
        _, text = result
        self.assertNotIn("--wf-tcp", text)
        self.assertIn("--lua-desync=fake", text)

    def test_section_id_carries_winws2_prefix(self):
        result = cm._convert_preset("Discord.txt", "--lua-desync=fake\n")
        sid, text = result
        self.assertTrue(sid.startswith(cm.WINWS2_PREFIX),
                        "section_id без префикса столкнётся с direct-каталогом")
        self.assertIn("[%s]" % sid, text)

    def test_build_presets_ini_dedups_and_parses(self):
        ini = cm._build_presets_ini({
            "Alpha.txt": "--lua-desync=fake\n",
            "Beta.txt": "--lua-desync=multisplit\n",
        })
        _, sections = cm._parse_ini_sections(ini)
        self.assertEqual(len(sections), 2)
        for sid in sections:
            self.assertTrue(sid.startswith(cm.WINWS2_PREFIX))


class TestNoDownloaderLeftBehind(unittest.TestCase):
    """Загрузчик убран — модуль больше не ходит в сеть."""

    def test_module_has_no_network_imports(self):
        import inspect
        src = inspect.getsource(cm)
        for needle in ("urlopen", "urllib", "api.github.com", "tarfile"):
            self.assertNotIn(needle, src,
                             "в catalog_merge вернулась сетевая логика: %s"
                             % needle)


if __name__ == "__main__":
    unittest.main()
