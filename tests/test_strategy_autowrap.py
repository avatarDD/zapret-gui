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


if __name__ == "__main__":
    unittest.main()
