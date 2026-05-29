# tests/test_firewall_persistence.py
"""Тесты персистентности firewall-правил (ndm/hotplug-хуки + reapply)."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from core import firewall_persistence as fp


def _sh_ok(text):
    sh = shutil.which("sh")
    if not sh:
        return True  # нет sh — пропускаем проверку
    return subprocess.run([sh, "-n"], input=text, text=True,
                          capture_output=True).returncode == 0


class TestGeneratedScripts(unittest.TestCase):

    def test_reapply_script_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_reapply_script()))

    def test_ndm_hook_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_ndm_hook()))

    def test_hotplug_hook_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_hotplug_hook()))

    def test_shared_funcs_valid_shell(self):
        # Функции должны быть валидны при заданных переменных.
        prelude = (
            'QUEUE_NUM=300\nPORTS_TCP="80,443"\nPORTS_UDP="443"\n'
            'MAX_PKT_OUT=20\nMAX_PKT_OUT_UDP=5\n'
            'MARK_PROCESSED="0x40000000/0x40000000"\n'
            'MARK_EXCLUDE="0x20000000/0x20000000"\n'
            'IPV6_ENABLED=0\nWAN_IFACES="eth0"\n'
        )
        self.assertTrue(_sh_ok(prelude + fp.FIREWALL_SH_FUNCTIONS))

    def test_ndm_hook_filters_table(self):
        body = fp.build_ndm_hook()
        self.assertIn("mangle", body)
        self.assertIn("nat", body)
        self.assertIn("reapply", body)

    def test_hooks_check_pidfiles(self):
        for body in (fp.build_ndm_hook(), fp.build_hotplug_hook()):
            self.assertIn(fp.AUTOSTART_PID_FILE, body)
            self.assertIn(fp.GUI_PID_FILE, body)


class TestRunConf(unittest.TestCase):

    def test_render_contains_all_keys(self):
        conf = fp.render_run_conf({
            "queue_num": 300, "ports_tcp": "80,443", "ports_udp": "443",
            "tcp_pkt_out": 20, "udp_pkt_out": 5, "pkt_in": 15,
            "mark_processed": "0x40000000/0x40000000",
            "mark_exclude": "0x20000000/0x20000000",
            "ipv6_enabled": "0", "wan_ifaces": "eth0",
        })
        for key in ("QUEUE_NUM", "PORTS_TCP", "PORTS_UDP", "MAX_PKT_OUT",
                    "MARK_PROCESSED", "MARK_EXCLUDE", "WAN_IFACES"):
            self.assertIn(key + "=", conf)


class TestInstallRemove(unittest.TestCase):

    def test_install_and_remove_in_tempdirs(self):
        with tempfile.TemporaryDirectory() as d:
            ndm = os.path.join(d, "ndm", "100-zapret-gui.sh")
            hot = os.path.join(d, "hotplug", "90-zapret-gui")
            with mock.patch.object(fp, "NDM_HOOK_PATH", ndm), \
                 mock.patch.object(fp, "HOTPLUG_HOOK_PATH", hot), \
                 mock.patch.object(fp, "is_keenetic", return_value=True), \
                 mock.patch.object(fp, "is_openwrt_hotplug", return_value=True):
                res = fp.install_hooks()
                self.assertTrue(res["ndm"])
                self.assertTrue(res["hotplug"])
                self.assertTrue(os.path.isfile(ndm))
                self.assertTrue(os.path.isfile(hot))
                # Исполняемый бит выставлен.
                self.assertTrue(os.access(ndm, os.X_OK))

                rem = fp.remove_hooks()
                self.assertIn(ndm, rem["removed"])
                self.assertFalse(os.path.isfile(ndm))

    def test_install_noop_when_not_router(self):
        with mock.patch.object(fp, "is_keenetic", return_value=False), \
             mock.patch.object(fp, "is_openwrt_hotplug", return_value=False):
            res = fp.install_hooks()
            self.assertEqual(res["installed"], [])


if __name__ == "__main__":
    unittest.main()
