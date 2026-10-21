# tests/test_warp_in_warp_deadlock.py
"""Issue #416: stop() WARP-in-WARP не должен ждать сам себя.

Цепочка была такая: stop() под self._lock → usque stop() →
restore_system_defaults(only_if_idle=True) → tunnel_monitor обходит
туннели → WarpInWarpManager.get_status() → `with self._lock` в том же
потоке. Обычный Lock — поток вставал навсегда, исключения не было.
"""

import threading
import unittest
from unittest import mock

from core import usque_manager as um
from core import warp_in_warp as wiw

_RUNTIME = {
    "mode": "masque_masque",
    "outer_iface": "usque1",
    "inner_iface": "usque0",
    "owned_awg_outer": False,
    "owned_awg_inner": False,
    "pinned_routes": [["162.159.198.2", "usque1", False, ""]],
}


def _call_with_timeout(fn, timeout=5.0):
    """Запустить fn в отдельном потоке; None — если не уложилась."""
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", fn()),
                         daemon=True)
    t.start()
    t.join(timeout)
    return None if t.is_alive() else box.get("r")


class _StatusPollingMonitor:
    """tunnel_monitor, который, как настоящий, спрашивает WARP-in-WARP."""

    def __init__(self, mgr):
        self.mgr = mgr
        self.calls = 0

    def discover_interfaces(self):
        self.calls += 1
        self.mgr.get_status()
        return ["usque9"]   # «есть активный туннель» — defaults не трогаем


class TestStopAfterGuiRestart(unittest.TestCase):

    def _patches(self, m, usque_mgr, monitor):
        # runtime-блок пережил рестарт GUI; stop() его стирает
        store = {"runtime": dict(_RUNTIME)}
        return [
            mock.patch.object(wiw, "_load_runtime",
                              side_effect=lambda: dict(store["runtime"])),
            mock.patch.object(wiw, "_clear_runtime",
                              side_effect=lambda: store.update(runtime={})),
            mock.patch.object(wiw, "_clear_last_start"),
            mock.patch.object(wiw, "_restore_route"),
            mock.patch.object(wiw, "_route_get", return_value=""),
            mock.patch("core.usque_manager.get_usque_manager",
                       return_value=usque_mgr),
            mock.patch("core.warp_in_warp.get_warp_in_warp_manager",
                       return_value=m),
            mock.patch("core.tunnel_monitor.get_tunnel_monitor",
                       return_value=monitor),
        ]

    def _run_stop(self, m, usque_mgr, monitor):
        patches = self._patches(m, usque_mgr, monitor)
        for p in patches:
            p.start()
        try:
            return _call_with_timeout(m.stop)
        finally:
            for p in patches:
                p.stop()

    def test_stop_with_real_usque_stop_returns(self):
        """Настоящий UsqueManager.stop(): пид-файла нет, процесса нет."""
        m = wiw.WarpInWarpManager()
        monitor = _StatusPollingMonitor(m)
        usque = um.UsqueManager()
        with mock.patch.object(usque, "_pid_path",
                               return_value="/nonexistent/usque.pid"), \
             mock.patch.object(usque, "_run_files_for_iface",
                               return_value=[]):
            r = self._run_stop(m, usque, monitor)
        self.assertEqual(r, {"ok": True})
        self.assertEqual(m._mode, "")
        # defaults проверяются один раз — самим stop() после замка,
        # а не каждым usque stop() под замком
        self.assertEqual(monitor.calls, 1)

    def test_usque_stop_called_without_restore(self):
        m = wiw.WarpInWarpManager()
        usque = mock.Mock()
        usque.stop.return_value = {"ok": True}
        r = self._run_stop(m, usque, _StatusPollingMonitor(m))
        self.assertEqual(r, {"ok": True})
        self.assertEqual(
            usque.stop.call_args_list,
            [mock.call("usque0", restore_defaults=False),
             mock.call("usque1", restore_defaults=False)])

    def test_reentrant_status_under_lock_does_not_hang(self):
        """Страховка: кто-то снова позовёт get_status() из-под замка."""
        m = wiw.WarpInWarpManager()
        monitor = _StatusPollingMonitor(m)
        usque = mock.Mock()

        def stop(iface, restore_defaults=True):
            monitor.discover_interfaces()    # игнорирует restore_defaults
            return {"ok": True}

        usque.stop.side_effect = stop
        r = self._run_stop(m, usque, monitor)
        self.assertEqual(r, {"ok": True})


class TestUsqueStopRestoreFlag(unittest.TestCase):

    def _stop(self, **kw):
        usque = um.UsqueManager()
        with mock.patch.object(usque, "_pid_path",
                               return_value="/nonexistent/usque.pid"), \
             mock.patch.object(usque, "_run_files_for_iface",
                               return_value=[]), \
             mock.patch("core.tunnel_optimizer.restore_system_defaults") as rsd:
            self.assertEqual(usque.stop("usque0", **kw), {"ok": True})
        return rsd

    def test_default_restores(self):
        self._stop().assert_called_once_with(only_if_idle=True)

    def test_flag_skips_restore(self):
        self._stop(restore_defaults=False).assert_not_called()


if __name__ == "__main__":
    unittest.main()
