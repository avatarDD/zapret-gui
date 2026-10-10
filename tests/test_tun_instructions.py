"""
TUN общий для всех движков: инструкция «как включить» должна приходить
с сервера под конкретную платформу (а не отсылкой «см. AmneziaWG»), а
запуск конфига с TUN на хосте без /dev/net/tun — отказывать понятной
ошибкой до старта бинаря (issue #386).
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import awg_platform
from core.awg_platform import (
    AwgPlatform, GenericLinuxPlatform, KeeneticPlatform, OpenWrtPlatform,
    tun_missing_error, tun_status,
)


class TestTunInstructions(unittest.TestCase):

    def test_every_platform_has_instructions(self):
        for p in (AwgPlatform(), OpenWrtPlatform(), GenericLinuxPlatform(),
                  KeeneticPlatform("5.0.1"), KeeneticPlatform("4.3.6"),
                  KeeneticPlatform("")):
            text = p.tun_instructions()
            self.assertTrue(text.strip(), type(p).__name__)
            # Старое имя — тот же текст.
            self.assertEqual(p.opkg_tun_instructions(), text)

    def test_keenetic_branches_by_version(self):
        self.assertIn("OpkgTun", KeeneticPlatform("5.0.1").tun_instructions())
        self.assertIn("kmod-tun", KeeneticPlatform("4.3.6").tun_instructions())

    def test_openwrt_mentions_package(self):
        self.assertIn("kmod-tun", OpenWrtPlatform().tun_instructions())

    def test_linux_mentions_modprobe(self):
        self.assertIn("modprobe tun", GenericLinuxPlatform().tun_instructions())

    def test_not_awg_specific(self):
        # Текст показывают страницы sing-box/mihomo/usque.
        for p in (KeeneticPlatform("5.0.1"), KeeneticPlatform("4.3.6")):
            self.assertNotIn("для работы AmneziaWG", p.tun_instructions())

    def test_as_dict_carries_instructions_only_without_tun(self):
        p = OpenWrtPlatform()
        with mock.patch.object(OpenWrtPlatform, "tun_available",
                               return_value=False), \
             mock.patch.object(OpenWrtPlatform, "get_firewall_backend",
                               return_value="nftables"), \
             mock.patch.object(OpenWrtPlatform, "supports_iptables_marks",
                               return_value=False):
            d = p.as_dict()
        self.assertEqual(d["tun_instructions"], p.tun_instructions())
        self.assertEqual(d["opkg_tun_instructions"], d["tun_instructions"])
        with mock.patch.object(OpenWrtPlatform, "tun_available",
                               return_value=True), \
             mock.patch.object(OpenWrtPlatform, "get_firewall_backend",
                               return_value="nftables"), \
             mock.patch.object(OpenWrtPlatform, "supports_iptables_marks",
                               return_value=False):
            self.assertNotIn("tun_instructions", p.as_dict())


class TestTunStatus(unittest.TestCase):

    def _det(self, platform):
        det = mock.Mock()
        det.detect_platform.return_value = platform
        return det

    def test_available(self):
        with mock.patch.object(awg_platform.os.path, "exists",
                               return_value=True):
            st = tun_status()
        self.assertEqual(st, {"device": True, "available": True,
                              "instructions": ""})

    def test_missing_gives_platform_text(self):
        with mock.patch.object(awg_platform.os.path, "exists",
                               return_value=False), \
             mock.patch("core.awg_detector.get_awg_detector",
                        return_value=self._det(KeeneticPlatform("5.1"))):
            st = tun_status()
        self.assertFalse(st["available"])
        self.assertIn("OpkgTun", st["instructions"])

    def test_detector_failure_falls_back(self):
        with mock.patch.object(awg_platform.os.path, "exists",
                               return_value=False), \
             mock.patch("core.awg_detector.get_awg_detector",
                        side_effect=RuntimeError("boom")):
            st = tun_status()
        self.assertEqual(st["instructions"], AwgPlatform().tun_instructions())

    def test_singbox_and_mihomo_detectors_use_it(self):
        from core.mihomo_detector import MihomoDetector
        from core.singbox_detector import SingboxDetector
        fake = {"device": False, "available": False, "instructions": "X"}
        with mock.patch("core.awg_platform.tun_status", return_value=fake):
            self.assertEqual(SingboxDetector().detect_tun(), fake)
            self.assertEqual(MihomoDetector().detect_tun(), fake)

    def test_missing_error_shape(self):
        with mock.patch("core.awg_platform.tun_status",
                        return_value={"instructions": "do it"}):
            r = tun_missing_error("sing-box", "sing-box → Установка")
        self.assertFalse(r["ok"])
        self.assertTrue(r["tun_missing"])
        self.assertIn("/dev/net/tun", r["error"])
        self.assertIn("sing-box → Установка", r["error"])
        self.assertEqual(r["tun_instructions"], "do it")


class TestSingboxUpWithoutTun(unittest.TestCase):

    def setUp(self):
        from core import singbox_manager
        self.tmp = tempfile.mkdtemp(prefix="sb-tun-")
        self.mgr = singbox_manager.SingboxManager()
        self.platform = mock.Mock()
        self.platform.config_path.side_effect = (
            lambda n: os.path.join(self.tmp, n + ".json"))
        self.platform.tun_available.return_value = False
        self._p = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary", return_value="/bin/false"),
            mock.patch.object(self.mgr, "is_running", return_value=False),
            mock.patch.object(singbox_manager, "_run",
                              side_effect=AssertionError("не должен звать")),
        ]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, cfg):
        with open(os.path.join(self.tmp, "vpn.json"), "w") as f:
            json.dump(cfg, f)

    def test_tun_inbound_refused_before_start(self):
        self._write({"inbounds": [{"type": "tun",
                                   "interface_name": "singbox-tun"}]})
        r = self.mgr._do_up("vpn")
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("tun_missing"))

    def test_no_tun_inbound_not_refused_for_tun(self):
        self._write({"inbounds": [{"type": "mixed", "listen_port": 1080}]})
        with self.assertRaises(AssertionError):
            # Дошли до `sing-box check` — TUN-проверка не помешала.
            self.mgr._do_up("vpn")


class TestMihomoWantsTun(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mh-tun-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cfg(self, text):
        path = os.path.join(self.tmp, "c.yaml")
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_detects_enabled_tun(self):
        from core.mihomo_manager import MihomoManager
        self.assertTrue(MihomoManager._config_wants_tun(
            self._cfg("tun:\n  enable: true\n  stack: gvisor\nproxies: []\n")))
        self.assertFalse(MihomoManager._config_wants_tun(
            self._cfg("tun:\n  enable: false\nproxies: []\n")))
        self.assertFalse(MihomoManager._config_wants_tun(
            self._cfg("mixed-port: 7890\nproxies: []\n")))
        self.assertFalse(MihomoManager._config_wants_tun(
            os.path.join(self.tmp, "missing.yaml")))
        self.assertTrue(MihomoManager._config_wants_tun(
            self._cfg("listeners:\n  - name: t\n    type: tun\n"
                      "proxies: []\n")))


if __name__ == "__main__":
    unittest.main()
