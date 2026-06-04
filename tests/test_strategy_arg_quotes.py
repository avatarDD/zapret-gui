# tests/test_strategy_arg_quotes.py
"""Парсинг args профиля сохраняет кавычки (важно для inline-Lua в --lua-init).

Регрессия: стратегии из blockcheck2 содержат lua-литералы вида
``tls_mod(fake_default_tls,'rnd')``. Раньше _parse_profile_args вырезал
одинарные кавычки → nfqws2 получал ``tls_mod(...,rnd)`` и Lua падал с
«bad argument #2 to 'tls_mod' (string expected, got nil)». Кавычки должны
доходить до nfqws2 дословно (argv передаётся subprocess списком, без shell).
"""

import unittest

from core.strategy_builder import StrategyManager


class TestParseProfileArgsQuotes(unittest.TestCase):

    def setUp(self):
        # _parse_profile_args не использует состояние экземпляра —
        # создаём объект без тяжёлого __init__.
        self.sm = StrategyManager.__new__(StrategyManager)

    def test_lua_init_single_quotes_preserved(self):
        # Кейс из бейджа blockcheck2: одинарные кавычки — это Lua-строка.
        s = ("--filter-tcp=443 --filter-l7=tls --hostlist-domains=youtube.com "
             "--lua-init=fake_default_tls=tls_mod(fake_default_tls,'rnd') "
             "--lua-desync=wssize:wsize=1:scale=6 --payload=tls_client_hello")
        out = self.sm._parse_profile_args(s)
        self.assertEqual(out, [
            "--filter-tcp=443",
            "--filter-l7=tls",
            "--hostlist-domains=youtube.com",
            "--lua-init=fake_default_tls=tls_mod(fake_default_tls,'rnd')",
            "--lua-desync=wssize:wsize=1:scale=6",
            "--payload=tls_client_hello",
        ])

    def test_double_quotes_preserved(self):
        out = self.sm._parse_profile_args('--lua-init=x=f("rnd")')
        self.assertEqual(out, ['--lua-init=x=f("rnd")'])

    def test_space_inside_quotes_groups_and_keeps_quotes(self):
        # Пробел внутри кавычек не разрывает токен; кавычки сохраняются.
        out = self.sm._parse_profile_args('--foo="a b" --bar=x')
        self.assertEqual(out, ['--foo="a b"', '--bar=x'])

    def test_plain_args_unchanged(self):
        out = self.sm._parse_profile_args(
            "--filter-tcp=443 --lua-desync=multisplit")
        self.assertEqual(out, ["--filter-tcp=443", "--lua-desync=multisplit"])

    def test_extra_spaces_collapsed(self):
        out = self.sm._parse_profile_args("  --filter-tcp=443    --payload=tls_client_hello ")
        self.assertEqual(out, ["--filter-tcp=443", "--payload=tls_client_hello"])

    def test_empty(self):
        self.assertEqual(self.sm._parse_profile_args(""), [])
        self.assertEqual(self.sm._parse_profile_args(None), [])


if __name__ == "__main__":
    unittest.main()
