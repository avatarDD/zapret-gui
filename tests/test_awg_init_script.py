# tests/test_awg_init_script.py
"""
Unit-тесты для core/awg_init_script.py — генератор init-скриптов
для Entware / OpenWrt-procd / systemd.
"""

import unittest

from core.awg_init_script import (
    render_init_script, _entware_init, _openwrt_procd, _systemd_unit,
)
from core.awg_platform import (
    KeeneticPlatform, OpenWrtPlatform, GenericLinuxPlatform,
)


class TestRenderInitScript(unittest.TestCase):

    def test_keenetic_returns_entware(self):
        s = render_init_script(KeeneticPlatform(), "/opt/bin/python3",
                                "/opt/zapret-gui/app.py")
        # Заголовок Entware-init
        self.assertIn("#!/bin/sh", s)
        # Содержит путь к app.py
        self.assertIn("/opt/zapret-gui/app.py", s)

    def test_openwrt_returns_procd(self):
        s = render_init_script(OpenWrtPlatform(), "/usr/bin/python3",
                                "/usr/lib/zapret-gui/app.py")
        # procd-стиль использует USE_PROCD
        self.assertIn("USE_PROCD", s)
        self.assertIn("/usr/lib/zapret-gui/app.py", s)

    def test_linux_returns_systemd(self):
        s = render_init_script(GenericLinuxPlatform(), "/usr/bin/python3",
                                "/opt/zapret-gui/app.py")
        # systemd
        self.assertIn("[Unit]", s)
        self.assertIn("ExecStart", s)
        self.assertIn("/opt/zapret-gui/app.py", s)


class TestEntwareInit(unittest.TestCase):

    def test_has_start_stop(self):
        s = _entware_init("/opt/bin/python3", "/opt/zapret-gui/app.py")
        self.assertIn("start", s)
        self.assertIn("stop", s)
        self.assertIn("/opt/bin/python3", s)

    def test_start_stop_restart_cases(self):
        s = _entware_init("/opt/bin/python3", "/opt/zapret-gui/app.py")
        # BusyBox-init: case "$1" в start/stop/restart
        for case in ("start)", "stop)", "restart)"):
            self.assertIn(case, s)


class TestOpenwrtProcd(unittest.TestCase):

    def test_procd_block(self):
        s = _openwrt_procd("/usr/bin/python3", "/usr/lib/app.py")
        self.assertIn("procd_open_instance", s)
        self.assertIn("procd_set_param", s)
        self.assertIn("procd_close_instance", s)


class TestSystemdUnit(unittest.TestCase):

    def test_systemd_sections(self):
        s = _systemd_unit("/usr/bin/python3", "/opt/app.py")
        self.assertIn("[Unit]", s)
        self.assertIn("[Service]", s)
        self.assertIn("[Install]", s)
        self.assertIn("/usr/bin/python3", s)
        self.assertIn("/opt/app.py", s)
        # ExecStart обязательная директива
        self.assertIn("ExecStart", s)


if __name__ == "__main__":
    unittest.main()
