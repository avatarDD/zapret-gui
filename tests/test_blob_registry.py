# tests/test_blob_registry.py
"""Тесты реестра именованных blob'ов (core/blob_registry.py)."""

import unittest

from core import blob_registry as br


class TestReferencedBlobNames(unittest.TestCase):

    def test_extracts_from_lua_desync(self):
        args = ["--lua-desync=fake:blob=tls_google:repeats=6"]
        self.assertEqual(br.referenced_blob_names(args), ["tls_google"])

    def test_unique_in_order(self):
        args = [
            "--lua-desync=fake:blob=tls7",
            "--lua-desync=multisplit:seqovl_pattern=tls7",
            "--lua-desync=fake:blob=tls_max",
        ]
        # seqovl_pattern=tls7 не содержит blob=, поэтому только blob= ссылки
        self.assertEqual(br.referenced_blob_names(args), ["tls7", "tls_max"])

    def test_empty(self):
        self.assertEqual(br.referenced_blob_names(["--lua-desync=multisplit"]), [])


class TestBuildBlobDeclarations(unittest.TestCase):

    def test_known_name_declared(self):
        decls = br.build_blob_declarations(["--lua-desync=fake:blob=tls_google"])
        self.assertEqual(
            decls,
            ["--blob=tls_google:@bin/tls_clienthello_www_google_com.bin"],
        )

    def test_builtin_skipped(self):
        self.assertEqual(
            br.build_blob_declarations(["--lua-desync=fake:blob=fake_default_tls"]),
            [],
        )

    def test_inline_hex_skipped(self):
        self.assertEqual(
            br.build_blob_declarations(["--lua-desync=fake:blob=0x00000000"]),
            [],
        )

    def test_already_declared_not_duplicated(self):
        args = [
            "--blob=tls7:@bin/tls_clienthello_7.bin",
            "--lua-desync=fake:blob=tls7",
        ]
        self.assertEqual(br.build_blob_declarations(args), [])

    def test_unknown_name_skipped(self):
        self.assertEqual(
            br.build_blob_declarations(["--lua-desync=fake:blob=does_not_exist_xyz"]),
            [],
        )

    def test_multiple_names(self):
        args = [
            "--lua-desync=fake:blob=tls_google",
            "--new",
            "--lua-desync=fake:blob=quic_google",
        ]
        decls = br.build_blob_declarations(args)
        self.assertEqual(len(decls), 2)
        self.assertTrue(any("tls_google" in d for d in decls))
        self.assertTrue(any("quic_google" in d for d in decls))


class TestRegistryContent(unittest.TestCase):

    def test_fallback_aliases_present(self):
        # Реестр должен содержать ключевые имена даже без каталогов.
        for name in ("tls_google", "tls7", "quic_google", "stun_pat", "dtls_w3"):
            self.assertIsNotNone(br.get_blob_value(name), name)

    def test_reload_does_not_crash(self):
        br.reload_registry()
        self.assertIsNotNone(br.get_blob_value("tls_google"))


class TestStrategyBuilderIntegration(unittest.TestCase):

    def test_basic_strategy_gets_blob_declaration(self):
        from core.strategy_builder import get_strategy_manager
        sm = get_strategy_manager()
        sm.load_strategies()
        s = sm.get_strategy("censorliber_tls_google_syndata_tcpack_fake")
        if s is None:
            self.skipTest("каталог basic недоступен в тестовой среде")
        args = sm.build_nfqws_args(s, hostlist_path=None)
        # Должна появиться декларация blob'а tls_google (с резолвом @bin/).
        blob_decls = [a for a in args if a.startswith("--blob=tls_google:")]
        self.assertEqual(len(blob_decls), 1)
        self.assertIn("tls_clienthello_www_google_com.bin", blob_decls[0])
        # И декларация должна идти ДО ссылки на неё.
        decl_idx = args.index(blob_decls[0])
        ref_idx = next(i for i, a in enumerate(args) if "blob=tls_google" in a
                       and not a.startswith("--blob="))
        self.assertLess(decl_idx, ref_idx)


if __name__ == "__main__":
    unittest.main()
