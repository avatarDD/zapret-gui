# tests/test_mcp_writable_paths.py
"""
Сторож границы записи настроек через MCP.

Каждый ключ `DEFAULT_CONFIG` обязан быть отнесён к одной из двух сторон
**осознанно**. Без этого теста новая настройка попадает в разрешённое
поддерево молча — и модель получает на запись то, о чём никто не решал.
Работает это в обе стороны: пропавший из списка путь тоже ломает тест,
потому что кто-то мог случайно сузить перехват или отладку.

Починка при падении: посмотреть на новый путь и либо добавить его в
`WRITABLE` здесь (если запись обратима и не отбирает управление
роутером), либо закрыть его в `core/mcp/permissions.py`
(`DENY_PATHS`/`DENY_KEY_RE`) и оставить вне списка.

Саму запись делает S6 — она обязана спрашивать `is_writable()` и
ничего не решать сама.
"""

import unittest

from core.config_manager import DEFAULT_CONFIG
from core.mcp import permissions as perms


# Полный список листьев settings.json, открытых на запись из MCP.
# Отсортирован; пополняется руками и осознанно.
WRITABLE = {
    "block_detector.auto_add_enabled",
    "block_detector.auto_add_list_id", "block_detector.dns_source",
    "block_detector.enabled", "block_detector.interval_sec",
    "block_detector.probe_timeout", "block_detector.whitelist",
    "blockcheck.default_mode", "blockcheck.max_workers",
    "blockcheck.probe_timeout", "dns_routing.rules", "filter.mode",
    "filter.protect_excluded", "healthcheck.auto_reset",
    "healthcheck.consecutive_failures", "healthcheck.control_domain",
    "healthcheck.custom_domains", "healthcheck.enabled",
    "healthcheck.history_size", "healthcheck.interval_min",
    "healthcheck.outage_guard", "healthcheck.services",
    "logging.file_enabled", "logging.level", "logging.max_entries",
    "logging.persist_critical", "logging.persist_min_level",
    "nfqws.debug", "nfqws.disable_ipv6", "nfqws.ports_tcp",
    "nfqws.ports_udp", "nfqws.tcp_pkt_in", "nfqws.tcp_pkt_out",
    "nfqws.udp_pkt_in", "nfqws.udp_pkt_out", "scan.confirm_repeats",
    "scan.confirm_top", "scan.default_mode",
    "scan.default_protocol", "scan.probe_timeout",
    "scan.stabilization_delay", "scan.use_generated",
    "strategy.current_id", "strategy.current_name",
    "strategy.favorites",
}


def leaves(node, prefix=""):
    """Все листья конфига как точечные пути."""
    for key, value in node.items():
        path = "%s.%s" % (prefix, key) if prefix else key
        if isinstance(value, dict) and value:
            for item in leaves(value, path):
                yield item
        else:
            yield path


class TestWritableSnapshot(unittest.TestCase):

    def test_list_matches_the_model(self):
        computed = {item["path"] for item in perms.writable_paths()}
        self.assertEqual(
            computed, WRITABLE,
            "список writable-путей разошёлся с моделью: лишние %s, "
            "недостающие %s" % (sorted(computed - WRITABLE),
                                sorted(WRITABLE - computed)))

    def test_every_config_key_is_classified(self):
        unknown = []
        for path in leaves(DEFAULT_CONFIG):
            if perms.is_writable(path):
                if path not in WRITABLE:
                    unknown.append(path)
            elif not perms.why_not_writable(path):
                unknown.append(path)
        self.assertEqual(unknown, [],
                         "ключи без явного решения writable/не-writable: %s"
                         % unknown)

    def test_closed_keys_have_a_reason(self):
        for path in leaves(DEFAULT_CONFIG):
            if path in WRITABLE:
                continue
            with self.subTest(path=path):
                self.assertTrue(perms.why_not_writable(path),
                                "нет объяснения, почему %s закрыт" % path)


class TestInvariants(unittest.TestCase):
    """Проверки, не зависящие от списка: их нельзя «починить» правкой."""

    def test_no_writable_path_leaves_the_whitelist(self):
        for path in WRITABLE:
            section = path.split(".")[0]
            self.assertIn(section, perms.WRITABLE_SECTIONS, path)

    def test_no_writable_path_looks_like_a_secret_or_a_location(self):
        # Расположение файла и секрет не принимаются на запись даже
        # внутри разрешённого поддерева — запреты сильнее разрешений.
        for path in WRITABLE:
            for segment in path.split(".")[1:]:
                with self.subTest(path=path):
                    self.assertFalse(perms.DENY_KEY_RE.search(segment), path)

    def test_whole_sections_are_never_writable(self):
        for section in DEFAULT_CONFIG:
            self.assertFalse(perms.is_writable(section), section)

    def test_permission_and_access_settings_are_closed(self):
        # Модель не расширяет собственные права и не роняет управление.
        # `agent.` здесь по той же причине, что `mcp.` (S18): это
        # настройки ПОВОДКА — адрес сервера модели, потолок шагов,
        # набор инструментов. Право их править означает право сменить
        # себе модель и снять с себя ограничения.
        for path in leaves(DEFAULT_CONFIG):
            if path.startswith(("mcp.", "agent.", "gui.", "install.",
                                "autostart.")):
                with self.subTest(path=path):
                    self.assertFalse(perms.is_writable(path), path)

    def test_enums_point_at_real_paths(self):
        for path in perms.ENUMS:
            with self.subTest(path=path):
                self.assertIn(path, WRITABLE,
                              "подсказка для %s описывает путь, которого "
                              "нет среди writable" % path)


if __name__ == "__main__":
    unittest.main()
