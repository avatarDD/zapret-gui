"""Тесты перезапуска демона и перезагрузки устройства.

Обе операции рвут текущее HTTP-соединение, поэтому выполняются
отложенно и в отвязанном процессе — иначе ответ до браузера не доедет,
а `S99zapret-gui restart` убил бы собственного родителя.
"""

import unittest
from unittest import mock

from core import system_control
from tests._wsgi_client import WSGIClient, build_test_app


class TestCommandSelection(unittest.TestCase):

    def test_entware_init_wins(self):
        with mock.patch("core.system_control.os.path.isfile",
                        side_effect=lambda p: p == "/opt/etc/init.d/S99zapret-gui"):
            self.assertEqual(system_control.restart_command(),
                             "/opt/etc/init.d/S99zapret-gui restart")

    def test_openwrt_init_used_when_no_entware(self):
        with mock.patch("core.system_control.os.path.isfile",
                        side_effect=lambda p: p == "/etc/init.d/zapret-gui"):
            self.assertEqual(system_control.restart_command(),
                             "/etc/init.d/zapret-gui restart")

    def test_systemd_fallback(self):
        with mock.patch("core.system_control.os.path.isfile",
                        return_value=False), \
             mock.patch("core.system_control.shutil.which",
                        return_value="/bin/systemctl"), \
             mock.patch("core.system_control.os.path.isdir",
                        return_value=True):
            self.assertEqual(system_control.restart_command(),
                             "systemctl restart zapret-gui")

    def test_no_restart_method_reports_empty(self):
        with mock.patch("core.system_control.os.path.isfile",
                        return_value=False), \
             mock.patch("core.system_control.shutil.which",
                        return_value=None):
            self.assertEqual(system_control.restart_command(), "")

    def test_keenetic_reboot_prefers_ndmc(self):
        """На Keenetic ndmc гасит сервисы и размонтирует USB штатно."""
        with mock.patch("core.system_control.shutil.which",
                        side_effect=lambda b: "/opt/bin/ndmc" if b == "ndmc" else None):
            self.assertEqual(system_control.reboot_command(),
                             'ndmc -c "system reboot"')

    def test_reboot_falls_back_to_plain_binary(self):
        with mock.patch("core.system_control.shutil.which",
                        return_value=None), \
             mock.patch("core.system_control.os.path.isfile",
                        side_effect=lambda p: p == "/sbin/reboot"):
            self.assertEqual(system_control.reboot_command(), "/sbin/reboot")


class TestDetachedExecution(unittest.TestCase):

    def test_restart_is_delayed_and_detached(self):
        with mock.patch("core.system_control.restart_command",
                        return_value="/opt/etc/init.d/S99zapret-gui restart"), \
             mock.patch("core.system_control.subprocess.Popen") as popen:
            res = system_control.restart_gui()

        self.assertTrue(res["ok"])
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:2], ["/bin/sh", "-c"])
        # Пауза нужна, чтобы bottle успел отдать ответ до смерти процесса.
        self.assertIn("sleep", argv[2])
        self.assertIn("S99zapret-gui restart", argv[2])
        # Без новой сессии restart убил бы и сам перезапускающий процесс.
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_reboot_is_delayed_and_detached(self):
        with mock.patch("core.system_control.reboot_command",
                        return_value='ndmc -c "system reboot"'), \
             mock.patch("core.system_control.subprocess.Popen") as popen:
            res = system_control.reboot_device()

        self.assertTrue(res["ok"])
        self.assertIn("system reboot", popen.call_args.args[0][2])

    def test_missing_method_does_not_spawn_anything(self):
        with mock.patch("core.system_control.restart_command",
                        return_value=""), \
             mock.patch("core.system_control.subprocess.Popen") as popen:
            res = system_control.restart_gui()
        self.assertFalse(res["ok"])
        popen.assert_not_called()


class TestSystemControlApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_capabilities_shape(self):
        r = self.client.get_json("/api/system/control")
        self.assertTrue(r["ok"])
        for key in ("restart_gui", "reboot", "restart_command",
                    "reboot_command"):
            self.assertIn(key, r)

    def test_reboot_requires_confirmation(self):
        """Случайный POST не должен ронять роутер."""
        with mock.patch("core.system_control.reboot_device") as reboot:
            r = self.client.post_json("/api/system/reboot", {})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])
        reboot.assert_not_called()

    def test_reboot_with_confirmation_calls_through(self):
        with mock.patch("core.system_control.reboot_device",
                        return_value={"ok": True}) as reboot:
            r = self.client.post_json("/api/system/reboot", {"confirm": True})
        self.assertTrue(r["ok"])
        reboot.assert_called_once()

    def test_restart_reports_501_when_unsupported(self):
        with mock.patch("core.system_control.restart_gui",
                        return_value={"ok": False, "error": "нечем"}):
            r = self.client.post_json("/api/system/restart-gui", {})
        self.assertEqual(r["_status"], 501)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
