# tests/test_blockcheck2_highlights.py
"""Регрессия: в «примороженные» итоги blockcheck2 попадают ТОЛЬКО найденные
рабочие стратегии, а не шум AVAILABLE/UNAVAILABLE.

Старый фильтр ловил `UNAVAILABLE code=28` (т.к. "AVAILABLE" — подстрока
"UNAVAILABLE") и каждую попытку `!!!!! AVAILABLE !!!!!`. Новый — только строки
`working strategy found …` и заголовки секций `* SUMMARY` / `* COMMON`.
"""

import unittest

from core import blockcheck2
from core.blockcheck2 import Blockcheck2Runner, _HIGHLIGHT_RE


class TestHighlightRegex(unittest.TestCase):

    def test_matches_found_strategy_and_sections(self):
        self.assertTrue(_HIGHLIGHT_RE.search(
            "!!!!! curl_test_http: working strategy found for ipv4 "
            "rutracker.org : nfqws2 --filter-tcp=443 --lua-desync=fake !!!!!"))
        self.assertTrue(_HIGHLIGHT_RE.search("* SUMMARY"))
        self.assertTrue(_HIGHLIGHT_RE.search("  * COMMON"))
        # zapret2 1.0.6: секция покрытия после COMMON.
        self.assertTrue(_HIGHLIGHT_RE.search("* COVERAGE"))

    def test_ignores_noise(self):
        for noise in (
            "[attempt 1] UNAVAILABLE code=28",
            "UNAVAILABLE code=7",
            "!!!!! AVAILABLE !!!!!",
            "* AVAILABLE",
            # строка секции COVERAGE (1.0.6) — не находка, заголовка хватает
            "2/3 : nfqws2 --payload=tls_client_hello --lua-desync=fake",
        ):
            self.assertIsNone(_HIGHLIGHT_RE.search(noise),
                              "ложное срабатывание на: %r" % noise)


class TestScanlevel(unittest.TestCase):
    """SCANLEVEL доходит до скрипта; veryquick (zapret2 1.0.6) — допустим."""

    def _env_for(self, level):
        from unittest import mock
        r = Blockcheck2Runner()
        with mock.patch.object(Blockcheck2Runner, "find_script",
                               staticmethod(lambda: "/nonexistent/bc2.sh")), \
                mock.patch("core.blockcheck2.subprocess.Popen",
                           side_effect=OSError("stub")) as popen:
            res = r.start(scanlevel=level)
        return res, popen

    def test_veryquick_passed_to_env(self):
        res, popen = self._env_for("VeryQuick")
        self.assertFalse(res["ok"])          # Popen-заглушка
        self.assertEqual(popen.call_args.kwargs["env"]["SCANLEVEL"],
                         "veryquick")

    def test_unknown_level_rejected(self):
        res, popen = self._env_for("deep")
        self.assertFalse(res["ok"])
        self.assertIn("veryquick", res["error"])
        popen.assert_not_called()


class _FakeProc:
    """Минимальный двойник Popen для _read_output."""
    def __init__(self, lines):
        self.stdout = iter([l + "\n" for l in lines])
        self._rc = 0

    def wait(self):
        return self._rc


class TestReadOutputHighlights(unittest.TestCase):

    def test_only_strategies_pinned_and_deduped(self):
        runner = Blockcheck2Runner()
        strat = ("!!!!! curl_test_https_tls13: working strategy found for "
                 "ipv4 rutracker.org : nfqws2 --filter-tcp=443 !!!!!")
        lines = [
            "[attempt 1] UNAVAILABLE code=28",
            "!!!!! AVAILABLE !!!!!",
            strat,                       # найдена стратегия
            "[attempt 2] UNAVAILABLE code=28",
            "* SUMMARY",
            strat,                       # повтор той же стратегии в сводке
        ]
        runner._read_output(_FakeProc(lines))

        hl = runner._highlights
        # Шум не попал.
        self.assertFalse(any("UNAVAILABLE" in h for h in hl))
        self.assertFalse(any(h == "AVAILABLE" for h in hl))
        # Стратегия попала ровно один раз (дедуп) и без декоративных "!".
        strat_hits = [h for h in hl if "working strategy found" in h]
        self.assertEqual(len(strat_hits), 1)
        self.assertFalse(strat_hits[0].startswith("!"))
        self.assertFalse(strat_hits[0].endswith("!"))
        # Заголовок секции примораживается.
        self.assertIn("* SUMMARY", hl)


if __name__ == "__main__":
    unittest.main()
