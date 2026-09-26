# tests/test_strategy_autowrap.py
"""Авто-ограничение «голого приёма» фильтром (SKILL.md §1/§2/§3).

Приём вида `--lua-desync=fake:...` без --filter-* десинхронизирует весь
трафик очереди. autowrap_bare_trick() оборачивает его фильтром, выведенным
из --payload (или дефолт-профиля ScanTarget), но НЕ трогает профили, у
которых фильтр уже есть.
"""

import unittest

from core.strategy_builder import autowrap_bare_trick


class TestAutowrapBareTrick(unittest.TestCase):

    def test_no_desync_untouched(self):
        args = ["--filter-tcp=443", "--payload=tls_client_hello"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_existing_filter_untouched(self):
        args = ["--filter-tcp=443", "--filter-l7=tls",
                "--lua-desync=fake:blob=fake_default_tls"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_existing_udp_filter_untouched(self):
        args = ["--filter-udp=443", "--lua-desync=fake"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_l7_only_filter_untouched(self):
        args = ["--filter-l7=quic", "--lua-desync=fake"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_tls_payload_derives_tcp443_tls(self):
        args = ["--payload=tls_client_hello",
                "--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd"]
        out = autowrap_bare_trick(list(args))
        self.assertEqual(
            out[:2], ["--filter-tcp=443", "--filter-l7=tls"])
        # payload уже был — не дублируем
        self.assertEqual(out.count("--payload=tls_client_hello"), 1)
        # исходные args сохранены в хвосте
        self.assertEqual(out[2:], args)

    def test_http_payload_derives_tcp80_http(self):
        args = ["--payload=http_req", "--lua-desync=fake:blob=fake_default_http"]
        out = autowrap_bare_trick(list(args))
        self.assertEqual(out[:2], ["--filter-tcp=80", "--filter-l7=http"])

    def test_quic_payload_derives_udp443_quic(self):
        args = ["--payload=quic_initial", "--lua-desync=fake"]
        out = autowrap_bare_trick(list(args))
        self.assertEqual(out[:2], ["--filter-udp=443", "--filter-l7=quic"])

    def test_no_payload_left_untouched(self):
        # Без --payload протокол неоднозначен — не трогаем (как было раньше).
        args = ["--lua-desync=fake:blob=fake_default_tls"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_payload_all_left_untouched(self):
        # Каталожные QUIC-приёмы: --payload=all + blob=quic_* — не мис-скоупим.
        args = ["--payload=all",
                "--lua-desync=fake:blob=quic_google:repeats=6"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)

    def test_unknown_payload_left_untouched(self):
        args = ["--payload=dns_query", "--lua-desync=fake"]
        self.assertEqual(autowrap_bare_trick(list(args)), args)


class TestAutowrapByProtocol(unittest.TestCase):
    """Каталожный приём без --payload — ограничивается своим протоколом.

    Профиль без --filter-tcp/udp подходит к любому L4: TCP-приём с
    TLS-фейком срабатывал на QUIC-пакетах, UDP-приём — на TCP.
    """

    def test_tls_trick_gets_tcp_ports_and_l7(self):
        args = ["--lua-desync=fake:blob=tls_google"]
        out = autowrap_bare_trick(list(args), protocol="tcp", family="tls",
                                  ports="80,443")
        self.assertEqual(out, ["--filter-tcp=80,443", "--filter-l7=tls"]
                         + args)

    def test_voice_trick_gets_udp_ports_without_l7(self):
        args = ["--lua-desync=fake:blob=0x00"]
        out = autowrap_bare_trick(list(args), protocol="udp", family="voice",
                                  ports="443,50000-65535")
        self.assertEqual(out, ["--filter-udp=443,50000-65535"] + args)

    def test_payload_all_quic_trick_is_scoped_too(self):
        args = ["--payload=all", "--lua-desync=fake:blob=quic_google"]
        out = autowrap_bare_trick(list(args), protocol="udp", family="quic",
                                  ports="443")
        self.assertEqual(out[:2], ["--filter-udp=443", "--filter-l7=quic"])

    def test_filtered_profile_still_untouched(self):
        args = ["--filter-tcp=443", "--lua-desync=fake"]
        self.assertEqual(autowrap_bare_trick(list(args), protocol="tcp",
                                             family="tls", ports="443"), args)

    def test_catalog_strategy_through_manager(self):
        from core.strategy_builder import StrategyManager, _nfqws_ports
        self.assertEqual(_nfqws_ports("443,3478:3481, 5349"),
                         "443,3478-3481,5349")
        scope = StrategyManager._autowrap_scope(
            {"protocol": "tcp", "family": "tls", "is_builtin": True})
        self.assertEqual(scope["protocol"], "tcp")
        self.assertEqual(scope["family"], "tls")
        self.assertTrue(scope["ports"])
        # Пользовательская стратегия без протокола — как раньше.
        self.assertEqual(StrategyManager._autowrap_scope(
            {"profiles": [], "is_builtin": False}), {})


if __name__ == "__main__":
    unittest.main()
