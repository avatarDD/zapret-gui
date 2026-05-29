# tests/test_strategy_generator.py
"""Тесты генератора стратегий на лету (core/strategy_generator.py)."""

import unittest

from core import strategy_generator as gen


class TestComplexityKey(unittest.TestCase):
    """Ранжирование по простоте (заимствовано из blockcheckw/rank.rs)."""

    def test_single_action_simplest(self):
        self.assertEqual(
            gen.complexity_key(["--lua-desync=multisplit:pos=1"]),
            (1, 0, 0),
        )

    def test_repeats_counted(self):
        # Достаём max repeats из аргументов.
        self.assertEqual(
            gen.complexity_key(["--lua-desync=fake:repeats=11"]),
            (1, 11, 0),
        )

    def test_multistage_marked(self):
        # send + --new + fake → action_count=2, multi_stage=1.
        key = gen.complexity_key([
            "--lua-desync=send:repeats=2",
            "--new",
            "--lua-desync=fake:repeats=6",
        ])
        self.assertEqual(key, (2, 6, 1))

    def test_simpler_sorts_first(self):
        # Один lua-desync без repeats < два с repeats.
        a = gen.complexity_key(["--lua-desync=multisplit:pos=1"])
        b = gen.complexity_key([
            "--lua-desync=fake:repeats=11",
            "--lua-desync=multisplit:pos=1",
        ])
        self.assertLess(a, b)


class TestGenerate(unittest.TestCase):

    def test_tcp_quick_has_items(self):
        items = gen.generate("tcp", "quick", dedup_against_catalog=False)
        self.assertGreater(len(items), 0)

    def test_levels_monotonic(self):
        q = len(gen.generate("tcp", "quick", dedup_against_catalog=False))
        s = len(gen.generate("tcp", "standard", dedup_against_catalog=False))
        f = len(gen.generate("tcp", "full", dedup_against_catalog=False))
        self.assertLessEqual(q, s)
        self.assertLessEqual(s, f)

    def test_udp_has_quic_fake(self):
        items = gen.generate("udp", "standard", dedup_against_catalog=False)
        self.assertTrue(any(
            "fake_default_quic" in " ".join(e.get_args_list()) for e in items
        ))

    def test_sorted_by_complexity(self):
        items = gen.generate("tcp", "standard", dedup_against_catalog=False)
        keys = [gen.complexity_key(e.get_args_list()) for e in items]
        self.assertEqual(keys, sorted(keys))

    def test_dedup_inside_generation(self):
        items = gen.generate("tcp", "full", dedup_against_catalog=False)
        seen = set()
        for e in items:
            k = gen._norm_args(e.get_args_list())
            self.assertNotIn(k, seen, "Duplicate args in generated set: %s" % k)
            seen.add(k)

    def test_entry_format_compatible_with_scanner(self):
        # Сгенерированные записи — «приёмы» (bare desync), не «full preset».
        from core.strategy_scanner import _is_full_preset_args
        for e in gen.generate("tcp", "quick", dedup_against_catalog=False):
            self.assertFalse(
                _is_full_preset_args(e.get_args_list()),
                "Generated entry must be a 'trick' (no --filter-*/--new): %s"
                % e.args,
            )

    def test_protocol_field_set(self):
        for e in gen.generate("tcp", "quick", dedup_against_catalog=False):
            self.assertEqual(e.protocol, "tcp")
        for e in gen.generate("udp", "quick", dedup_against_catalog=False):
            self.assertEqual(e.protocol, "udp")

    def test_section_ids_unique(self):
        items = gen.generate("tcp", "full", dedup_against_catalog=False)
        ids = [e.section_id for e in items]
        self.assertEqual(len(ids), len(set(ids)))


class TestTcpsegOobIncluded(unittest.TestCase):
    """Новые методы из blockcheckw присутствуют в генерации."""

    def test_tcpseg_present(self):
        items = gen.generate("tcp", "standard", dedup_against_catalog=False)
        self.assertTrue(any(
            "lua-desync=tcpseg" in " ".join(e.get_args_list()) for e in items
        ))

    def test_oob_present(self):
        items = gen.generate("tcp", "standard", dedup_against_catalog=False)
        self.assertTrue(any(
            "lua-desync=oob" in " ".join(e.get_args_list()) for e in items
        ))


if __name__ == "__main__":
    unittest.main()
