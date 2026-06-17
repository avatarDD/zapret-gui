# tests/test_catalog_argv_tokenize.py
"""Каталожные строки с несколькими флагами токенизируются в отдельные argv.

Регрессия (найдено прогоном всех стратегий через nfqws2 --intercept=0 на
реальном бинарнике v1.0.2): конвертированные winws2-пресеты и z2k-пресеты
кладут НЕСКОЛЬКО флагов в одну строку каталога, напр.:

    --filter-tcp=80,443 --filter-l7=tls,http --ipcache-hostname=1 ...
    --lua-desync=send:...:strategy=1 --lua-desync=syndata:...:strategy=1

Раньше CatalogManager.build_nfqws_args_from_entry возвращал каждую СТРОКУ как
один argv-токен (split только по '\\n'). В результате nfqws2 получал, напр.,
``--filter-tcp=80,443 --filter-l7=...`` ОДНИМ токеном → hard-ошибка
«Invalid port filter» (z2k_all_in_one/z2k_tls_circular_smart), а цепочки
``--lua-desync=...:strategy=N`` тихо схлопывались (значение strategy=
затягивало остаток строки) — тихий 0% у ~47 строк winws2-пресетов.

Чинит core.models.tokenize_args (quote-aware), которым теперь пользуются и
build_nfqws_args_from_entry, и strategy_builder._parse_profile_args.
"""

import unittest

from core.models import CatalogEntry, tokenize_args
from core.catalog_loader import CatalogManager, get_catalog_manager
from core.config_manager import init_config


class TestTokenizeArgs(unittest.TestCase):

    def test_multi_flag_line_split(self):
        self.assertEqual(
            tokenize_args("--filter-tcp=80,443 --filter-l7=tls,http "
                          "--ipcache-hostname=1"),
            ["--filter-tcp=80,443", "--filter-l7=tls,http",
             "--ipcache-hostname=1"],
        )

    def test_lua_desync_chain_split(self):
        self.assertEqual(
            tokenize_args("--lua-desync=send:repeats=2:strategy=1 "
                          "--lua-desync=syndata:blob=stun_pat:strategy=1"),
            ["--lua-desync=send:repeats=2:strategy=1",
             "--lua-desync=syndata:blob=stun_pat:strategy=1"],
        )

    def test_quoted_inline_lua_kept_as_one_token(self):
        # Пробел внутри кавычек НЕ разрывает токен — иначе Lua-литерал ломается.
        self.assertEqual(
            tokenize_args("--lua-desync=luaexec:code='desync.x = brandom(3)'"),
            ["--lua-desync=luaexec:code='desync.x = brandom(3)'"],
        )

    def test_empty(self):
        self.assertEqual(tokenize_args(""), [])
        self.assertEqual(tokenize_args(None), [])


class TestBuildNfqwsArgsFromEntry(unittest.TestCase):

    def test_entry_multiflag_line_is_tokenized(self):
        e = CatalogEntry(
            section_id="x",
            args="--filter-tcp=80,443 --filter-l7=tls,http\n"
                 "--lua-desync=fake:strategy=1 --lua-desync=multisplit:strategy=1",
        )
        out = CatalogManager.build_nfqws_args_from_entry(e)
        self.assertEqual(out, [
            "--filter-tcp=80,443",
            "--filter-l7=tls,http",
            "--lua-desync=fake:strategy=1",
            "--lua-desync=multisplit:strategy=1",
        ])


class TestAllCatalogsTokenizedAtomic(unittest.TestCase):
    """Инвариант по ВСЕМ каталогам: каждый argv-токен — атомарный.

    Атомарность = повторная токенизация токена возвращает его же. Это ловит
    любую «склейку» несколько-флагов-в-токене (в т.ч. с --filter-tcp, где
    nfqws2 падает hard-ошибкой) для всего каталога разом, без бинарника.
    """

    @classmethod
    def setUpClass(cls):
        init_config()
        cls.cache = get_catalog_manager().load_all()

    def test_no_multiflag_token_in_any_entry(self):
        offenders = []
        for key in self.cache:
            for e in self.cache[key]:
                for tok in CatalogManager.build_nfqws_args_from_entry(e):
                    if tokenize_args(tok) != [tok]:
                        offenders.append((key, e.section_id, tok[:80]))
        self.assertEqual(offenders, [], "не-атомарные токены: %r" % offenders[:5])

    def test_filter_port_tokens_have_no_space(self):
        # --filter-tcp=/--filter-udp= значение не должно содержать пробел
        # (иначе nfqws2: «Invalid port filter»).
        bad = []
        for key in self.cache:
            for e in self.cache[key]:
                for tok in CatalogManager.build_nfqws_args_from_entry(e):
                    if (tok.startswith("--filter-tcp=")
                            or tok.startswith("--filter-udp=")):
                        if " " in tok:
                            bad.append((key, e.section_id, tok[:80]))
        self.assertEqual(bad, [], "port-фильтр с пробелом: %r" % bad[:5])


if __name__ == "__main__":
    unittest.main()
