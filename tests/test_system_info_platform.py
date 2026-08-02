# tests/test_system_info_platform.py
"""
Тесты лёгкого детекта платформы core/system_info.platform_kind().

Он питает карточку «Системная информация» в разделе «Диагностика»,
дашборд и решение kmod_manager «можно ли ставить модули ядра». Прежняя
версия опознавала Keenetic по одному `/tmp/ndnproxy_acl` (файл ndnproxy),
и на роутерах, где DNS отдан dnsmasq/AdGuard, платформа определялась как
OpenWrt — у KeenOS есть /etc/openwrt_release.

Файловую систему и PATH мокаем целиком: тесты должны давать один и тот же
результат и на роутере, и на CI.
"""

import unittest
from unittest import mock

from core import system_info


def _fake_env(paths=(), dirs=(), which=(), files=None):
    """Контекст с подменённой ФС: exists/isdir/which/чтение файлов."""
    paths = set(paths) | set(dirs)
    dirs = set(dirs)
    which = set(which)
    files = files or {}

    return (
        mock.patch.object(system_info.os.path, "exists",
                          side_effect=lambda p: p in paths),
        mock.patch.object(system_info.os.path, "isdir",
                          side_effect=lambda p: p in dirs),
        mock.patch.object(system_info.shutil, "which",
                          side_effect=lambda n: ("/opt/bin/%s" % n)
                          if n in which else None),
        mock.patch.object(system_info, "_read_file",
                          side_effect=lambda p, default="": files.get(p, default)),
    )


class _EnvCase(unittest.TestCase):
    """База: self.env(...) поднимает моки на время блока."""

    def env(self, **kw):
        patches = _fake_env(**kw)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class TestKeeneticMarkers(_EnvCase):

    def test_ndm_hooks_dir(self):
        self.env(dirs=["/opt/etc/ndm"])
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_ndmc_in_path(self):
        self.env(which=["ndmc"])
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_ndmq_in_path(self):
        self.env(which=["ndmq"])
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_proc_version(self):
        self.env(files={"/proc/version": "Linux version 4.9 (Keenetic 4.1.5)"})
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_legacy_ndnproxy_marker_still_works(self):
        self.env(paths=["/tmp/ndnproxy_acl"])
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_openwrt_release_mentioning_keenetic(self):
        self.env(paths=["/etc/openwrt_release"],
                 files={"/etc/openwrt_release":
                        'DISTRIB_DESCRIPTION="Keenetic 4.1.5"'})
        self.assertEqual(system_info.platform_kind(), "keenetic")

    def test_keenetic_without_ndnproxy_is_not_openwrt(self):
        # Регрессия: DNS отдан dnsmasq → /tmp/ndnproxy_acl нет, а
        # /etc/openwrt_release и Entware есть. Раньше выходил «OpenWrt».
        self.env(paths=["/etc/openwrt_release", "/opt/etc/entware_release",
                        "/opt/bin/opkg"],
                 dirs=["/opt/etc/ndm"],
                 files={"/etc/openwrt_release": "DISTRIB_RELEASE='19.07.7'"})
        self.assertEqual(system_info.platform_kind(), "keenetic")


class TestOtherPlatforms(_EnvCase):

    def test_openwrt(self):
        self.env(paths=["/etc/openwrt_release"],
                 files={"/etc/openwrt_release": "DISTRIB_RELEASE='23.05.2'"})
        self.assertEqual(system_info.platform_kind(), "openwrt")

    def test_openwrt_by_version_file(self):
        self.env(paths=["/etc/openwrt_version"])
        self.assertEqual(system_info.platform_kind(), "openwrt")

    def test_entware_by_release(self):
        self.env(paths=["/opt/etc/entware_release"])
        self.assertEqual(system_info.platform_kind(), "entware")

    def test_entware_by_opkg(self):
        # Entware на прошивке без openwrt_release (Padavan/ASUS и пр.).
        self.env(paths=["/opt/bin/opkg"])
        self.assertEqual(system_info.platform_kind(), "entware")

    def test_plain_linux(self):
        self.env()
        self.assertEqual(system_info.platform_kind(), "linux")


class TestHumanLabel(_EnvCase):

    def test_keenetic_with_version_and_entware(self):
        self.env(dirs=["/opt/etc/ndm"], paths=["/opt/bin/opkg"],
                 files={"/proc/version": "Linux version 4.9-ndm (Keenetic 4.1.5)"})
        self.assertEqual(system_info._get_platform(),
                         "Keenetic 4.1.5 (NDMS) + Entware")

    def test_keenetic_without_version(self):
        self.env(dirs=["/opt/etc/ndm"])
        self.assertEqual(system_info._get_platform(), "Keenetic (NDMS)")

    def test_keenetic_version_from_openwrt_release(self):
        self.env(paths=["/etc/openwrt_release"],
                 files={"/etc/openwrt_release":
                        'DISTRIB_DESCRIPTION="Keenetic 5.0.3 rc"'})
        self.assertEqual(system_info._get_platform(), "Keenetic 5.0.3 (NDMS)")

    def test_openwrt_with_release(self):
        self.env(paths=["/etc/openwrt_release"],
                 files={"/etc/openwrt_release": "DISTRIB_RELEASE='23.05.2'"})
        self.assertEqual(system_info._get_platform(), "OpenWrt 23.05.2")

    def test_openwrt_with_entware(self):
        self.env(paths=["/etc/openwrt_release", "/opt/etc/entware_release"],
                 files={"/etc/openwrt_release": "DISTRIB_RELEASE='23.05.2'"})
        self.assertEqual(system_info._get_platform(), "OpenWrt 23.05.2 + Entware")

    def test_entware_release_text(self):
        self.env(paths=["/opt/etc/entware_release"],
                 files={"/opt/etc/entware_release": "Entware 2024.05\nmipsel"})
        self.assertEqual(system_info._get_platform(), "Entware (Entware 2024.05)")

    def test_linux(self):
        self.env()
        self.assertEqual(system_info._get_platform(), "Linux")


class TestNoSubprocessProbes(_EnvCase):
    """Детект не должен запускать ndmc/ndmq: их сессии засоряют лог роутера,
    а platform_kind вызывается на каждый опрос дашборда."""

    def test_platform_kind_runs_no_commands(self):
        self.env(dirs=["/opt/etc/ndm"])
        with mock.patch.object(system_info.subprocess, "run") as run:
            system_info.platform_kind()
            system_info._get_platform()
        run.assert_not_called()


class TestSingleSourceOfTruth(unittest.TestCase):
    """Копии детекта в других модулях сведены к общей функции."""

    def test_network_env_delegates(self):
        from core import network_env
        with mock.patch("core.system_info.platform_kind",
                        return_value="keenetic") as pk:
            self.assertEqual(network_env._platform_kind(), "keenetic")
        pk.assert_called_once()

    def test_kmod_manager_delegates(self):
        from core import kmod_manager
        with mock.patch("core.system_info.platform_kind",
                        return_value="openwrt") as pk:
            self.assertEqual(kmod_manager._platform_kind(), "openwrt")
        pk.assert_called_once()


if __name__ == "__main__":
    unittest.main()
