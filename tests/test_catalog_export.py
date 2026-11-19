# tests/test_catalog_export.py
"""
Экспорт находки в формат каталога: секция обязана читаться НАШИМ парсером.

Почему это главное требование. Формат INI каталогов мягкий: строка, не
начинающаяся с ``--``, читается как метаданные, а перевод строки в
описании разрезает секцию пополам — и то и другое происходит молча. То
есть неверный экспорт выглядит как успешный, а замечает его тот, кто
через месяц не понимает, почему в каталоге стратегия из двух половинок.

Поэтому экспорт проверяет себя round-trip'ом (``core/catalog_loader``),
а этот файл стережёт, что проверка не формальная: на каждый способ
испортить секцию должен быть отказ с объяснением.

Второе требование — **ничего не записывать**. `catalogs/` перезаписывает
установщик GUI; локальная правка там потерялась бы при обновлении, и
именно поэтому экспорт отдаёт текст, а не пишет файл.
"""

import os
import unittest

from core import catalog_export as export
from core.catalog_loader import _VALID_LABELS, _parse_catalog_content


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestGuesses(unittest.TestCase):
    """Уровень и протокол выводятся из argv, а не спрашиваются."""

    def test_single_trick_is_direct(self):
        self.assertEqual(
            export.guess_level(["--lua-desync=multisplit:pos=1"]), "direct")

    def test_filters_and_new_make_it_a_full_config(self):
        # Граница та же, что в catalogs/README.md: секция с фильтрами —
        # это готовая конфигурация, а не приём для сканера.
        self.assertEqual(export.guess_level(["--filter-tcp=443",
                                             "--lua-desync=fake"]),
                         "builtin")
        self.assertEqual(export.guess_level(["--lua-desync=fake", "--new"]),
                         "builtin")

    def test_udp_is_recognised_by_quic_and_filters(self):
        self.assertEqual(export.guess_protocol(
            ["--filter-udp=443", "--lua-desync=fake:blob=quic_google"]),
            "udp")

    def test_mixed_argv_falls_back_to_tcp(self):
        # Не «угадать поточнее», а не соврать: tcp-файл терпит и то и
        # другое, udp-каталог собирает ровно udp-приёмы.
        self.assertEqual(export.guess_protocol(
            ["--filter-tcp=443", "--filter-udp=443"]), "tcp")

    def test_blobs_are_collected_but_literals_are_not(self):
        args = ["--lua-desync=fake:blob=fake_default_tls",
                "--lua-desync=fakemultisplit:fake_blob=tls_google",
                "--lua-desync=fake:blob=0x00"]
        self.assertEqual(export.guess_blobs(args),
                         ["fake_default_tls", "tls_google"])

    def test_cyrillic_name_becomes_a_usable_section_id(self):
        # Иначе секция называлась бы «_____» и все находки слиплись бы.
        self.assertEqual(export.slugify("Мой фейк + сплит"),
                         "moy_feyk_split")
        self.assertEqual(export.slugify(""), "strategy")


class TestRendering(unittest.TestCase):

    def export(self, args, **kw):
        return export.export(args, **kw)

    def test_section_reads_back_as_the_same_argv(self):
        args = ["--lua-desync=fake:blob=fake_default_tls",
                "--lua-desync=multisplit:pos=1,midsld"]
        result = self.export(args, name="Fake + split", author="tester",
                             label="stable", description="Найдено тестом")
        entries = _parse_catalog_content(result["text"], protocol="tcp",
                                         level="direct")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get_args_list(), args)
        self.assertEqual(entries[0].name, "Fake + split")
        self.assertEqual(entries[0].author, "tester")
        self.assertEqual(entries[0].label, "stable")
        self.assertEqual(entries[0].blobs, ["fake_default_tls"])

    def test_it_points_at_the_right_file(self):
        direct = self.export(["--lua-desync=fake:blob=quic_google"])
        self.assertEqual(direct["file"], "catalogs/direct/udp.txt")
        full = self.export(["--filter-tcp=443", "--lua-desync=fake"])
        self.assertEqual(full["file"],
                         "catalogs/builtin/zapret_gui_defaults.txt")
        self.assertTrue(any("builtin" in w for w in full["warnings"]))

    def test_multiline_description_does_not_split_the_section(self):
        result = self.export(["--lua-desync=fake"],
                             description="первая строка\nвторая строка")
        entries = _parse_catalog_content(result["text"], protocol="tcp",
                                         level="direct")
        self.assertEqual(len(entries), 1)
        self.assertNotIn("\n", entries[0].description)

    def test_leading_hash_in_metadata_is_not_a_comment(self):
        result = self.export(["--lua-desync=fake"], name="# не комментарий")
        entries = _parse_catalog_content(result["text"], protocol="tcp",
                                         level="direct")
        self.assertEqual(entries[0].name, "не комментарий")

    def test_windivert_args_are_dropped(self):
        result = self.export(["--wf-tcp=443", "--lua-desync=fake"])
        self.assertEqual(result["args"], ["--lua-desync=fake"])


class TestRefusals(unittest.TestCase):
    """Отказ с объяснением лучше секции, которая читается не так."""

    def test_argument_without_dashes(self):
        with self.assertRaises(export.ExportError) as caught:
            export.export(["lua-desync=fake"])
        self.assertIn("--", str(caught.exception))

    def test_argument_with_a_newline(self):
        with self.assertRaises(export.ExportError):
            export.export(["--lua-desync=fake\nname = чужое"])

    def test_nothing_to_export(self):
        with self.assertRaises(export.ExportError):
            export.export([])

    def test_unknown_label_is_refused_not_silently_dropped(self):
        # Загрузчик выбрасывает неизвестную метку молча, и находка
        # уехала бы в каталог без пометки.
        with self.assertRaises(export.ExportError):
            export.export(["--lua-desync=fake"], label="супер")

    def test_bad_section_id(self):
        with self.assertRaises(export.ExportError):
            export.render_section("Не Секция", ["--lua-desync=fake"])

    def test_labels_match_the_loader(self):
        # Разошлись — и экспорт начнёт принимать метку, которую
        # загрузчик выкинет.
        self.assertEqual(set(export.LABELS), set(_VALID_LABELS))


class TestNothingIsWritten(unittest.TestCase):
    """Экспорт не трогает catalogs/ — там поставка GUI."""

    def test_catalog_files_are_untouched(self):
        directory = os.path.join(REPO, "catalogs", "direct")
        before = {name: os.path.getmtime(os.path.join(directory, name))
                  for name in os.listdir(directory)}
        export.export(["--lua-desync=fake"], name="Проба пера")
        after = {name: os.path.getmtime(os.path.join(directory, name))
                 for name in os.listdir(directory)}
        self.assertEqual(before, after)


class TestTool(unittest.TestCase):
    """Тот же экспорт инструментом MCP."""

    def setUp(self):
        from core.mcp import registry
        registry.load_tools()
        self.registry = registry

    def call(self, args, perms=None):
        return self.registry.call(
            "strategy_export_catalog", args,
            {"strategies_write": True} if perms is None else perms
        )["structuredContent"]

    def test_argv_in_section_out(self):
        answer = self.call({"args": ["--lua-desync=multisplit:pos=1"],
                            "name": "Сплит", "author": "tester"})
        self.assertTrue(answer["ok"])
        self.assertIn("[split]", answer["text"])
        self.assertIn("catalogs/direct/tcp.txt", answer["hint"])

    def test_needs_strategies_write(self):
        # Разрешение здесь не про «мы пишем», а про то, что собранное
        # предназначено для записи — как у strategy_compose.
        answer = self.call({"args": ["--lua-desync=fake"]}, perms={})
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["permission"], "strategies_write")

    def test_nothing_to_export_says_where_to_take_argv(self):
        answer = self.call({})
        self.assertFalse(answer["ok"])
        self.assertIn("strategy_experiment_result", answer["hint"])

    def test_unknown_strategy_id(self):
        answer = self.call({"strategy_id": "нет-такой"})
        self.assertFalse(answer["ok"])
        self.assertIn("strategy_list", answer["hint"])

    def test_broken_argv_explains_the_format(self):
        answer = self.call({"args": ["просто текст"]})
        self.assertFalse(answer["ok"])
        self.assertIn("--", answer["error"])


if __name__ == "__main__":
    unittest.main()


class TestCleanStartNotExported(unittest.TestCase):
    """Локальная «начинать без обхода» в экспорт каталога не попадает."""

    def test_tool_builds_without_clean_start(self):
        from unittest import mock
        from core.mcp import registry
        registry.load_tools()
        seen = {}

        class SM:
            def get_strategy(self, sid):
                return {"id": sid, "name": "C", "profiles": []}

            def build_nfqws_args(self, strategy, clean_start=None):
                seen["clean_start"] = clean_start
                return ["--lua-desync=multisplit:pos=1"]
        with mock.patch("core.strategy_builder.get_strategy_manager",
                        return_value=SM()):
            answer = registry.call("strategy_export_catalog",
                                   {"strategy_id": "c"},
                                   {"strategies_write": True})
        self.assertTrue(answer["structuredContent"]["ok"], answer)
        self.assertIs(seen["clean_start"], False)
