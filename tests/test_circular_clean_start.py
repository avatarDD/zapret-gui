# tests/test_circular_clean_start.py
"""«Авто»-стратегии без обхода на первом шаге (filter.circular_clean_start).

circular начинает каждый хост с strategy=1, поэтому приём №1 бил по всем
сайтам. Опция ставит первым шагом pass и сдвигает остальные номера.
"""

import os
import re
import unittest

from core.config_manager import get_config_manager
from core.strategy_builder import circular_pass_first, get_strategy_manager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROFILE = [
    "--filter-tcp=443", "--filter-l7=tls",
    "--lua-desync=circular:fails=3:hostkey=z2k_nohost_key",
    "--in-range=x", "--payload=tls_client_hello",
    "--lua-desync=fake:blob=fake_default_tls:strategy=1",
    "--lua-desync=multisplit:pos=1:strategy=2",
    "--lua-desync=fake:blob=fake_default_tls:strategy=3",
    "--lua-desync=multisplit:pos=1,midsld:strategy=3:final",
]


def _nums(args):
    out = []
    for a in args:
        m = re.search(r":strategy=(\d+)(?::|$)", a)
        if m:
            out.append(int(m.group(1)))
    return out


class TestTransform(unittest.TestCase):

    def test_pass_inserted_and_steps_shifted(self):
        out = circular_pass_first(PROFILE, 2)
        ci = out.index(next(a for a in out if a.startswith(
            "--lua-desync=circular")))
        self.assertEqual(out[ci + 1], "--lua-desync=pass:strategy=1")
        self.assertEqual(_nums(out), [1, 2, 3, 4, 4])
        # final едет вместе со своим шагом
        self.assertIn("--lua-desync=multisplit:pos=1,midsld:strategy=4:final",
                      out)
        # остальное не тронуто
        self.assertEqual(out[:2], PROFILE[:2])
        self.assertEqual(len(out), len(PROFILE) + 1)

    def test_own_state_key(self):
        out = circular_pass_first(PROFILE, 2)
        circ = next(a for a in out if a.startswith("--lua-desync=circular"))
        # первый --lua-desync в профиле → номер 1, профиль 2
        self.assertTrue(circ.endswith(":key=circular_2_1_pass"), circ)
        self.assertIn("fails=3", circ)

    def test_existing_key_gets_suffix(self):
        prof = ["--lua-desync=circular:key=yt_tcp:fails=2",
                "--lua-desync=fake:blob=x:strategy=1"]
        out = circular_pass_first(prof)
        self.assertEqual(out[0], "--lua-desync=circular:key=yt_tcp_pass:fails=2")
        self.assertEqual(out[1], "--lua-desync=pass:strategy=1")
        self.assertEqual(out[2], "--lua-desync=fake:blob=x:strategy=2")

    def test_bare_circular(self):
        prof = ["--lua-desync=circular", "--lua-desync=fake:strategy=1"]
        out = circular_pass_first(prof, 1)
        self.assertEqual(out[0], "--lua-desync=circular:key=circular_1_1_pass")

    def test_unchanged_cases(self):
        cases = [
            ["--filter-tcp=443", "--lua-desync=multisplit:pos=1"],
            # два circular
            ["--lua-desync=circular", "--lua-desync=fake:strategy=1",
             "--lua-desync=circular", "--lua-desync=fake:strategy=1"],
            # pass уже первым шагом
            ["--lua-desync=circular", "--lua-desync=pass:strategy=1",
             "--lua-desync=fake:strategy=2"],
            # нечисловой номер
            ["--lua-desync=circular", "--lua-desync=fake:strategy=x"],
            # нет шагов
            ["--lua-desync=circular"],
        ]
        for prof in cases:
            self.assertEqual(circular_pass_first(prof), prof, prof)

    def test_not_confused_by_similar_names(self):
        prof = ["--lua-desync=circular_with_preload",
                "--lua-desync=fake:strategy=1"]
        self.assertEqual(circular_pass_first(prof), prof)
        prof = ["--lua-desync=circular",
                "--lua-desync=fake:strategy=1:blob=fake_strategy=9"]
        out = circular_pass_first(prof)
        self.assertEqual(out[2], "--lua-desync=fake:strategy=2:blob=fake_strategy=9")

    def test_all_builtin_circular_presets(self):
        # Каждый каталожный circular-профиль после сдвига: номера с 1 подряд
        # (иначе circular падает: «gaps are not allowed»), первым — pass.
        sm = get_strategy_manager()
        seen = 0
        for strat in sm.get_strategies():
            for prof in strat.get("profiles") or []:
                toks = sm._parse_profile_args(prof.get("args", ""))
                out = circular_pass_first(toks)
                if out is toks:
                    continue
                seen += 1
                nums = sorted(set(_nums(out)))
                self.assertEqual(nums, list(range(1, len(nums) + 1)),
                                 strat.get("id"))
                self.assertIn("--lua-desync=pass:strategy=1", out)
        self.assertGreater(seen, 0)


class TestBuildArgs(unittest.TestCase):

    def setUp(self):
        self.cfg = get_config_manager()
        self.cfg.load()
        self._mode = self.cfg.get("filter", "mode", default="none")
        self._clean = self.cfg.get("filter", "circular_clean_start",
                                   default=False)
        self.cfg.set("filter", "mode", "none")
        self.sm = get_strategy_manager()
        self.strategy = {"id": "t", "name": "t", "profiles": [
            {"id": "p1", "enabled": True,
             "args": "--filter-udp=443 --lua-desync=fake:blob=quic1"},
            {"id": "p2", "enabled": True, "args": " ".join(PROFILE)},
        ]}

    def tearDown(self):
        self.cfg.set("filter", "mode", self._mode)
        self.cfg.set("filter", "circular_clean_start", self._clean)

    def test_off_by_default(self):
        self.cfg.set("filter", "circular_clean_start", False)
        args = self.sm.build_nfqws_args(self.strategy)
        self.assertNotIn("--lua-desync=pass:strategy=1", args)

    def test_on(self):
        self.cfg.set("filter", "circular_clean_start", True)
        args = self.sm.build_nfqws_args(self.strategy)
        self.assertIn("--lua-desync=pass:strategy=1", args)
        # ключ — по id профиля: не едет при отключении соседних профилей
        self.assertTrue(any(a.endswith(":key=circular_p2_1_pass")
                            for a in args), args)
        # профиль без circular не тронут
        self.assertIn("--lua-desync=fake:blob=quic1", args)

    def test_key_stable_when_neighbour_disabled(self):
        self.cfg.set("filter", "circular_clean_start", True)
        self.strategy["profiles"][0]["enabled"] = False
        args = self.sm.build_nfqws_args(self.strategy)
        self.assertTrue(any(a.endswith(":key=circular_p2_1_pass")
                            for a in args), args)

    def test_explicit_false_overrides_setting(self):
        self.cfg.set("filter", "circular_clean_start", True)
        args = self.sm.build_nfqws_args(self.strategy, clean_start=False)
        self.assertNotIn("--lua-desync=pass:strategy=1", args)

    def test_experiment_probes_without_clean_start(self):
        # Проба стратегии должна сразу бить приёмом, а не начинать с pass.
        from core import strategy_experiment as se
        self.cfg.set("filter", "circular_clean_start", True)
        argv, _src = se._variant_args({"profiles": [
            {"id": "p2", "enabled": True, "args": " ".join(PROFILE)}]})
        self.assertNotIn("--lua-desync=pass:strategy=1", argv)


class TestStateReset(unittest.TestCase):
    """Сброс хоста healthcheck'ом у circular с первым шагом pass."""

    def setUp(self):
        import tempfile
        from unittest.mock import patch
        from core import strategy_state as ss
        self.ss = ss
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "state.tsv")
        with open(self.path, "w") as f:
            f.write("# h\n"
                    "rkn_tcp_pass\ta.com\t4\t1\n"
                    "rkn_tcp_pass\tb.com\t1\t1\n"
                    "rkn_tcp\ta.com\t3\t1\n"
                    "rkn_tcp_pass\tc.com\t5\t1\n")
        self.p = patch.object(ss, "_candidate_files",
                              return_value=[self.path])
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def _rows(self):
        return {(e["key"], e["host"]): e["strategy"]
                for e in self.ss._read_one(self.path)}

    def test_first_trick_reset(self):
        self.ss.clear_hosts(["a.com", "b.com"], first_trick=True)
        rows = self._rows()
        self.assertEqual(rows[("rkn_tcp_pass", "a.com")], 2)  # → 1-й приём
        self.assertNotIn(("rkn_tcp_pass", "b.com"), rows)     # был pass
        self.assertNotIn(("rkn_tcp", "a.com"), rows)          # обычный ключ
        self.assertEqual(rows[("rkn_tcp_pass", "c.com")], 5)  # не трогали

    def test_plain_clear_forgets(self):
        # Кнопка «забыть» в UI: хост удаляется под любым ключом.
        self.ss.clear_host("a.com")
        self.assertNotIn(("rkn_tcp_pass", "a.com"), self._rows())


if __name__ == "__main__":
    unittest.main()
