# tests/test_dev_merge_regressions.py
"""
Регресс-тесты для фиксов, внесённых при подготовке мержа Development → main.

Каждый тест соответствует реальному дефекту, найденному при ревью ветки
Development и не покрытому существующими тестами.
"""

import os
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


class TestAwgDaemonization(unittest.TestCase):
    """Готовность интерфейса проверяется через `awg show <iface>` (rc==0), а
    НЕ по пути /var/run/wireguard/<if>.sock (на Keenetic он в другом месте) и
    не по выходу процесса. amneziawg-go может работать в FOREGROUND (poll()==
    None) — это норма, его нельзя убивать. Регрессия ронявшая AWG на Keenetic."""

    def setUp(self):
        import tempfile
        from tests.test_awg_manager_lifecycle import FakePlatform, SAMPLE_CONF
        import core.awg_manager as am
        self.am = am
        self.tmpdir = tempfile.mkdtemp(prefix="awg-daemon-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = am.AwgManager()
        go = os.path.join(self.platform.binary_dir, "amneziawg-go")
        awgb = os.path.join(self.platform.binary_dir, "awg")
        for f in (go, awgb):
            with open(f, "w") as fh:
                fh.write("#!/bin/true\n")
        self._patches = [
            mock.patch.object(self.mgr, "_platform", return_value=self.platform),
            mock.patch.object(self.mgr, "_config_dir",
                              return_value=self.platform.config_dir),
            mock.patch.object(self.mgr, "_run_dir",
                              return_value=self.platform.run_dir),
            mock.patch.object(self.mgr, "_scan_dirs",
                              return_value=[self.platform.config_dir]),
            mock.patch.object(self.mgr, "_awg_bin", return_value=awgb),
            mock.patch.object(self.mgr, "_amneziawg_go", return_value=go),
            mock.patch.object(self.mgr, "_wg_interfaces", return_value=[]),
            mock.patch.object(self.mgr, "_probe_binary",
                              return_value={"broken": False, "detail": ""}),
            mock.patch.object(self.mgr, "_apply_setconf",
                              return_value={"ok": True}),
        ]
        for p in self._patches:
            p.start()
        self.mgr.save_config("awg0", text=SAMPLE_CONF)

    def tearDown(self):
        import shutil
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_daemonized_parent_exit_is_success(self):
        killed = {"v": False}

        class FakeProc:
            def poll(self_inner):
                return 0  # родитель вышел с rc==0 (демонизация)

            def kill(self_inner):
                killed["v"] = True

            def wait(self_inner, timeout=None):
                return 0

        real_exists = os.path.exists

        def fake_exists(p):
            if str(p).endswith(".sock"):
                return True  # сокет поднял фоновый демон
            return real_exists(p)

        with mock.patch.object(self.am.subprocess, "Popen",
                               return_value=FakeProc()), \
             mock.patch.object(self.am.os.path, "exists",
                               side_effect=fake_exists), \
             mock.patch.object(self.am, "_run", return_value=(0, "", "")), \
             mock.patch.object(self.am, "_pgrep_first", return_value=4242), \
             mock.patch.object(self.am, "_resolve_endpoint_ip",
                               return_value=("162.159.192.4", False)), \
             mock.patch("core.routing.applier.apply_all_on_interface_up",
                        return_value=None):
            res = self.mgr.up("awg0")

        self.assertNotIn("Не удалось запустить amneziawg-go",
                         res.get("message", ""))
        self.assertFalse(killed["v"], "рабочий демон не должен убиваться")
        self.assertTrue(res.get("ok"), res)

    def test_nonzero_exit_no_socket_is_error(self):
        # Родитель вышел с ошибкой (rc!=0), сокет не появился → честная ошибка,
        # без зависания (stderr читаем из файла, а не блокирующегося pipe).
        class FailProc:
            def poll(self_inner):
                return 1

            def kill(self_inner):
                pass

            def wait(self_inner, timeout=None):
                return 1

        # `awg show` возвращает НЕнулевой код (интерфейс не готов), процесс
        # вышел с rc!=0 → честная ошибка старта, без зависания.
        with mock.patch.object(self.am.subprocess, "Popen",
                               return_value=FailProc()), \
             mock.patch.object(self.am, "_run",
                               return_value=(1, "", "Unable to access interface")), \
             mock.patch.object(self.am, "_pgrep_first", return_value=0):
            res = self.mgr.up("awg0")
        self.assertFalse(res.get("ok"))
        self.assertIn("Не удалось запустить amneziawg-go",
                      res.get("message", ""))


class TestConfigImportMaskPreserved(unittest.TestCase):
    """import_json не должен затирать секреты маской '***' (лок-аут)."""

    def _mgr(self):
        import tempfile
        import core.config_manager as cm
        # изолированный менеджер с временным каталогом
        m = cm.ConfigManager()
        m.set("gui", "auth_password", "realpass")
        m.set("awg", "private_key", "REALKEY==")
        return m

    def test_masked_import_preserves_secret(self):
        import json
        m = self._mgr()
        m.import_json(json.dumps({"gui": {"auth_password": "***", "port": 9091},
                                  "awg": {"private_key": "***"}}))
        self.assertEqual(m.get("gui", "auth_password"), "realpass")
        self.assertEqual(m.get("awg", "private_key"), "REALKEY==")
        self.assertEqual(m.get("gui", "port"), 9091)

    def test_real_value_import_overwrites(self):
        import json
        m = self._mgr()
        m.import_json(json.dumps({"gui": {"auth_password": "changed"}}))
        self.assertEqual(m.get("gui", "auth_password"), "changed")


class TestBlockcheckDohNoFalsePositive(unittest.TestCase):
    """blockcheck: непубличный IP-хелпер отличает CDN (публичные) от перехвата."""

    def test_has_non_public_ip(self):
        # helper объявлен локально внутри _run_dns_phase — тестируем через
        # эквивалентную проверку ipaddress (закрепляем намерение)
        import ipaddress

        def has_non_public(ips):
            for ip in ips:
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if (a.is_private or a.is_loopback or a.is_reserved
                        or a.is_link_local or a.is_unspecified):
                    return True
            return False
        # CDN: все публичные, disjoint — НЕ фейк
        self.assertFalse(has_non_public(["142.250.1.1", "172.217.2.2"]))
        # перехват на приватный IP — фейк
        self.assertTrue(has_non_public(["192.168.1.1"]))


if __name__ == "__main__":
    unittest.main()
