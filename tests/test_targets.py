# tests/test_targets.py
"""
Тесты общего каталога целей core/targets.py.

Каталог «популярных сервисов» был описан дважды — в core/diagnostics
(карточки-светофоры) и в core/blockcheck (домены теста доступности), — и
списки успели разъехаться. Эти тесты фиксируют, что источник один.
"""

import unittest

from core import targets


class TestCatalogShape(unittest.TestCase):

    def test_services_not_empty(self):
        self.assertGreater(len(targets.SERVICES), 5)

    def test_every_service_has_required_fields(self):
        for key, svc in targets.SERVICES.items():
            with self.subTest(service=key):
                self.assertTrue(svc.get("name"), "нет имени")
                self.assertTrue(svc.get("icon"), "нет иконки")
                self.assertTrue(svc.get("hosts"), "нет хостов")
                for host in svc["hosts"]:
                    self.assertNotIn("/", host, "host, а не URL")
                for url in svc.get("urls", []):
                    self.assertTrue(url.startswith("http"))

    def test_service_hosts_deduplicated(self):
        hosts = targets.service_hosts()
        self.assertEqual(len(hosts), len(set(hosts)))

    def test_default_domains_cover_services_and_reference(self):
        domains = targets.default_check_domains()
        for host in targets.service_hosts():
            self.assertIn(host, domains)
        for host in targets.REFERENCE_HOSTS:
            self.assertIn(host, domains)
        self.assertEqual(len(domains), len(set(domains)))

    def test_available_services_is_a_copy(self):
        # API-представление не должно давать править каталог по ссылке.
        api = targets.available_services()
        api["youtube"]["hosts"].append("evil.example")
        self.assertNotIn("evil.example", targets.SERVICES["youtube"]["hosts"])


class TestSingleSourceOfTruth(unittest.TestCase):

    def test_diagnostics_uses_shared_catalog(self):
        from core import diagnostics
        self.assertIs(diagnostics.SERVICES, targets.SERVICES)

    def test_diagnostics_api_lists_all_services(self):
        from core.diagnostics import get_available_services
        self.assertEqual(set(get_available_services()), set(targets.SERVICES))

    def test_blockcheck_defaults_come_from_catalog(self):
        from core import blockcheck
        self.assertEqual(blockcheck._DEFAULT_DOMAINS,
                         targets.default_check_domains())

    def test_unknown_service_rejected(self):
        # check_service ищет цель в общем каталоге — всё, чего там нет,
        # отсекается до сетевых проверок.
        from core.diagnostics import check_service
        self.assertEqual(check_service("нет-такого").get("error"),
                         "Неизвестный сервис")


if __name__ == "__main__":
    unittest.main()
