# tests/test_awg_watchdog_clock_budget.py
"""
Watchdog AWG и таблицы маршрутизации: сторожа по разбору зависаний
Keenetic (октябрь 2026).

* Скачок часов после загрузки: handshake до синхронизации NTP получал
  метку из прошлого, и watchdog видел «handshake 1032687с назад» —
  перезапуск живого туннеля.
* Ручной `down` после неудачного рестарта: туннель числился «опущенным
  watchdog'ом» и поднимался обратно вопреки остановке.
* Лимит рестартов в час считался по интерфейсу, подъёмов — по конфигу:
  при разных именах бюджет удваивался.
* Хэш имени мог выдать системную таблицу 253/254/255 — её flush на down
  отрезал бы роутер от сети.
"""

import time
import unittest
from unittest import mock

from core import awg_watchdog


class TestEffectiveHandshakeAge(unittest.TestCase):

    def test_plausible_age_is_trusted(self):
        age, seen = awg_watchdog.effective_handshake_age(
            1000, 30, 3600.0, None, 50.0)
        self.assertEqual((age, seen), (30, None))

    def test_no_uptime_trusts_age(self):
        age, seen = awg_watchdog.effective_handshake_age(
            1000, 10 ** 6, None, None, 50.0)
        self.assertEqual((age, seen), (10 ** 6, None))

    def test_age_older_than_boot_counts_from_first_sight(self):
        # 1032687 с при аптайме в час — метка до синхронизации часов.
        age, seen = awg_watchdog.effective_handshake_age(
            1000, 1032687, 3600.0, None, 50.0)
        self.assertEqual(age, 0)
        self.assertEqual(seen, (1000, 50.0))
        # Та же метка через 200 с — туннель и правда молчит.
        age, seen = awg_watchdog.effective_handshake_age(
            1000, 1032887, 3800.0, seen, 250.0)
        self.assertEqual(age, 200)
        # Новая (и уже достоверная) метка — поправка больше не нужна.
        age, seen = awg_watchdog.effective_handshake_age(
            2000, 5, 3810.0, seen, 260.0)
        self.assertEqual((age, seen), (5, None))

    def test_handshake_in_future_is_not_trusted(self):
        age, seen = awg_watchdog.effective_handshake_age(
            1000, -500, 3600.0, None, 10.0)
        self.assertEqual(age, 0)
        self.assertIsNotNone(seen)

    def test_clock_jump_does_not_restart(self):
        wd = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        mgr._config_for_name.return_value = "WARPv1_30"
        now = int(time.time())
        status = {"peers": [{"latest_handshake": now - 1032687}]}
        settings = {"handshake_timeout_sec": 180, "check_interval_sec": 30,
                    "cooldown_sec": 300, "max_restarts_per_hour": 6,
                    "enabled": True}
        with mock.patch.object(awg_watchdog, "_uptime_sec",
                               return_value=5400.0):
            wd._maybe_restart(mgr, "WARPv1_30", status, settings, now)
        mgr.restart.assert_not_called()


class TestUserDownForgetsTookDown(unittest.TestCase):

    def test_forget_took_down(self):
        wd = awg_watchdog.AwgWatchdog()
        wd._took_down.update({"warp-opkgtun0", "other"})
        with mock.patch.object(awg_watchdog, "_watchdog", wd):
            awg_watchdog.forget_took_down("warp-opkgtun0", "opkgtun0")
        self.assertEqual(wd._took_down, {"other"})

    def test_forget_without_watchdog_is_noop(self):
        with mock.patch.object(awg_watchdog, "_watchdog", None):
            awg_watchdog.forget_took_down("x")   # не падает и не создаёт

    def test_manager_down_calls_forget(self):
        from core import awg_manager
        mgr = awg_manager.AwgManager.__new__(awg_manager.AwgManager)
        mgr._lock = mock.MagicMock()
        with mock.patch.object(mgr, "_do_down", return_value={"ok": True},
                               create=True), \
             mock.patch.object(mgr, "_config_for_name",
                               return_value="warp-opkgtun0", create=True), \
             mock.patch.object(awg_watchdog, "forget_took_down") as forget:
            mgr.down("opkgtun0")
        forget.assert_called_once_with("warp-opkgtun0", "opkgtun0")


class TestSingleRestartBudget(unittest.TestCase):

    def test_budget_keyed_by_config_name(self):
        # Подъёмы воскрешением исчерпали лимит конфига — рестарт по имени
        # интерфейса тоже не идёт (раньше у него был свой бюджет).
        wd = awg_watchdog.AwgWatchdog()
        mgr = mock.MagicMock()
        mgr._config_for_name.return_value = "warp-opkgtun0"
        now = time.time()
        wd._restart_log["warp-opkgtun0"] = [now - i * 100 for i in range(6)]
        status = {"peers": [{"latest_handshake": int(now) - 1000}]}
        settings = {"handshake_timeout_sec": 180, "check_interval_sec": 30,
                    "cooldown_sec": 300, "max_restarts_per_hour": 6,
                    "enabled": True}
        with mock.patch.object(awg_watchdog, "_uptime_sec",
                               return_value=None):
            wd._maybe_restart(mgr, "opkgtun0", status, settings, now)
        mgr.restart.assert_not_called()

    def test_inactive_iface_forgets_detector_state(self):
        wd = awg_watchdog.AwgWatchdog()
        wd._zero_state["awg0"] = {"since": 1.0, "tx": 10}
        wd._rx_state["awg0"] = {"rx": 0}
        mgr = mock.MagicMock()
        mgr.list_interfaces.return_value = [{"name": "awg0",
                                             "active": False}]
        settings = {"enabled": True, "check_interval_sec": 30}
        with mock.patch.object(awg_watchdog, "_get_settings",
                               return_value=settings), \
             mock.patch("core.awg_manager.get_awg_manager",
                        return_value=mgr), \
             mock.patch.object(wd, "_resurrect_down_autostart"):
            wd._tick()
        self.assertNotIn("awg0", wd._zero_state)
        self.assertNotIn("awg0", wd._rx_state)


class TestReservedTables(unittest.TestCase):

    def _table_id(self, name, table_map=None):
        from core.routing import manager
        cm = mock.MagicMock()
        cm.get.return_value = dict(table_map or {})
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm):
            return manager.table_id_for(name), cm

    def test_hash_never_gives_system_table(self):
        # opkgtun67/68/69 по хэшу попадали ровно на 253/254/255.
        for name in ("opkgtun67", "opkgtun68", "opkgtun69"):
            tid, _cm = self._table_id(name)
            self.assertNotIn(tid, (253, 254, 255), name)
            self.assertTrue(100 <= tid <= 999)

    def test_stored_system_table_is_reallocated(self):
        tid, cm = self._table_id("awg9", {"awg9": 254, "awg1": 100})
        self.assertNotIn(tid, (100, 253, 254, 255))
        saved = cm.set.call_args.args[2]
        self.assertEqual(saved["awg9"], tid)
        self.assertEqual(saved["awg1"], 100)

    def test_valid_stored_table_kept(self):
        tid, cm = self._table_id("WARPv1_30", {"WARPv1_30": 105})
        self.assertEqual(tid, 105)
        cm.set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
