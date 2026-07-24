# tests/test_dev_merge_regressions.py
"""
Регресс-тесты для фиксов, внесённых при подготовке мержа Development → main.

Каждый тест соответствует реальному дефекту, найденному при ревью ветки
Development и не покрытому существующими тестами.
"""

import unittest
from unittest import mock


class TestGeositeEnumFix(unittest.TestCase):
    """geosite_importer: правильная нумерация v2ray Domain.Type enum.

    Было: typ in (1,3,4) — держал Regex(1), отбрасывал Domain(2, ~99% записей).
    Стало: typ in (0,2,3) — Plain/Domain/Full, без Regex(1).
    """

    @staticmethod
    def _entry(typ: int, domain: str) -> bytes:
        def enc(fn, wt):
            return bytes([(fn << 3) | wt])

        def varint(n):
            o = b""
            while True:
                b = n & 0x7F
                n >>= 7
                o += bytes([b | 0x80]) if n else bytes([b])
                if not n:
                    break
            return o
        return (enc(1, 0) + varint(typ)
                + enc(2, 2) + varint(len(domain)) + domain.encode())

    def test_domain_type_kept(self):
        from core.geosite_importer import _parse_domain_entry
        # type 2 = Domain (RootDomain) — основной тип
        self.assertEqual(_parse_domain_entry(self._entry(2, "example.com")),
                         "example.com")

    def test_plain_and_full_kept(self):
        from core.geosite_importer import _parse_domain_entry
        self.assertEqual(_parse_domain_entry(self._entry(0, "plain.com")),
                         "plain.com")
        self.assertEqual(_parse_domain_entry(self._entry(3, "full.com")),
                         "full.com")

    def test_regex_excluded(self):
        from core.geosite_importer import _parse_domain_entry
        # type 1 = Regex — НЕ домен, должен отбрасываться
        self.assertEqual(_parse_domain_entry(self._entry(1, "re.*x")), "")


class TestAutoRemediationOperaRemoved(unittest.TestCase):
    """auto_remediation: opera убран (не метод unified-слоя → ValueError)."""

    def test_opera_not_in_default_priority(self):
        from core.auto_remediation import get_auto_remediation
        rem = get_auto_remediation()
        # дефолтный приоритет не должен содержать opera
        target = rem._find_best_tunnel()  # без активных туннелей вернёт ""
        self.assertNotIn("opera", target)

    def test_detect_tunnel_opera_returns_empty(self):
        from core.auto_remediation import get_auto_remediation
        rem = get_auto_remediation()
        self.assertEqual(rem._detect_tunnel("opera"), "")

    def test_config_default_priority_has_no_opera(self):
        from core.config_manager import DEFAULT_CONFIG
        pr = DEFAULT_CONFIG["auto_remediation"]["tunnel_priority"]
        self.assertNotIn("opera", pr)


class TestUpdateCheckerSymbols(unittest.TestCase):
    """update_checker._check_tgproto использует существующие символы."""

    def test_check_tgproto_no_import_error(self):
        from core.update_checker import _check_tgproto
        res = _check_tgproto()
        # раньше падало ImportError (get_tgproxy_manager не существует) →
        # error заполнялся текстом исключения
        self.assertNotIn("cannot import name", str(res.get("error") or ""))

    def test_check_now_and_status_checking(self):
        from core.update_checker import get_update_checker
        c = get_update_checker()
        self.assertTrue(hasattr(c, "check_now"))
        self.assertIn("checking", c.get_status())


class TestTgproxyManagerSymbols(unittest.TestCase):
    """Символы, на которые теперь ссылаются update_checker и tunnel_monitor."""

    def test_symbols_exist(self):
        import core.tgproxy_manager as tg
        self.assertTrue(hasattr(tg, "get_mtproxy_client_manager"))
        self.assertTrue(hasattr(tg, "get_active_engine_status"))

    def test_active_engine_status_shape(self):
        from core.tgproxy_manager import get_active_engine_status
        st = get_active_engine_status()
        self.assertIn("any_running", st)


class TestTunnelOptimizerBBRNotFatal(unittest.TestCase):
    """optimize_all_tunnels: отсутствие BBR не делает всю операцию ошибкой."""

    def test_ok_when_buffers_ok_bbr_fails(self):
        import core.tunnel_optimizer as topt
        # get_tunnel_monitor импортируется внутри функции — патчим в источнике
        with mock.patch("core.tunnel_monitor.get_tunnel_monitor") as gm, \
             mock.patch.object(topt, "ensure_global_tcp_tuning",
                               return_value={"ok": True}), \
             mock.patch.object(topt, "_optimize_congestion",
                               return_value={"ok": False,
                                             "error": "BBR модуль недоступен"}), \
             mock.patch.object(topt, "_detect_egress_iface", return_value="eth0"):
            gm.return_value.discover_interfaces.return_value = []
            res = topt.optimize_all_tunnels("balanced")
        # нет туннелей + буферы применены + BBR недоступен → это НЕ ошибка
        self.assertTrue(res["ok"])


class TestConcurrentFuturesFallback(unittest.TestCase):
    """Watchdog'и mihomo/singbox работают без concurrent.futures (python3-light)."""

    def _run_tick_without_cf(self, module_name):
        import importlib
        mod = importlib.import_module(module_name)
        wd = mod.get_watchdog()
        calls = []

        fake_mgr = mock.Mock()
        fake_mgr.list_configs.return_value = [{"name": "a"}, {"name": "b"}]
        fake_mgr.is_running.side_effect = lambda n: calls.append(n) or False

        real_import = __import__

        def blocked_import(name, *a, **k):
            if name == "concurrent.futures" or name.startswith("concurrent.futures"):
                raise ImportError("No module named 'logging'")
            return real_import(name, *a, **k)

        with mock.patch.object(mod, "_get_settings",
                               return_value={"enabled": True}), \
             mock.patch("builtins.__import__", side_effect=blocked_import):
            # менеджер импортируется внутри _tick — подменяем его геттер
            mgr_getter = ("core.mihomo_manager.get_mihomo_manager"
                          if "mihomo" in module_name
                          else "core.singbox_manager.get_singbox_manager")
            with mock.patch(mgr_getter, return_value=fake_mgr):
                wd._tick()
        # оба конфига проверены последовательно, без падения
        self.assertEqual(set(calls), {"a", "b"})

    def test_mihomo_watchdog_sequential_fallback(self):
        self._run_tick_without_cf("core.mihomo_watchdog")

    def test_singbox_watchdog_sequential_fallback(self):
        self._run_tick_without_cf("core.singbox_watchdog")


if __name__ == "__main__":
    unittest.main()
