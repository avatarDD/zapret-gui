# tests/test_kmod_manager.py
"""
Unit-тесты core/kmod_manager — установка модулей ядра NFQUEUE из GUI.

Проверяем чистую логику без рута и без реальной установки:
  • детект СИСТЕМНОГО пакетного менеджера (apk на 24.10+, opkg на 23.05,
    игнор Entware'ского /opt/bin/opkg);
  • набор пакетов под iptables/nftables;
  • команды/подкоманды (apk add / opkg install);
  • платформенное гейтирование can_auto_install (OpenWrt да, Keenetic/ПК нет);
  • подсказки nfqueue_fix_hint.
"""

import unittest
from unittest import mock

from core import kmod_manager as k


def _fake_fs(present_files=(), present_dirs=()):
    """Вернуть (exists, isdir) поверх набора «существующих» путей."""
    files = set(present_files)
    dirs = set(present_dirs)

    def exists(p):
        return p in files or p in dirs

    def isdir(p):
        return p in dirs

    return exists, isdir


class TestPkgManagerDetect(unittest.TestCase):

    def _detect(self, present_files=(), present_dirs=(), which=None):
        exists, isdir = _fake_fs(present_files, present_dirs)
        with mock.patch.object(k.os.path, "exists", exists), \
             mock.patch.object(k.os.path, "isdir", isdir):
            return k.detect_pkg_manager()

    def test_apk_based_openwrt(self):
        # 24.10+: есть /usr/bin/apk и БД /etc/apk
        kind, path = self._detect(
            present_files=("/usr/bin/apk",), present_dirs=("/etc/apk",))
        self.assertEqual(kind, "apk")
        self.assertEqual(path, "/usr/bin/apk")

    def test_opkg_openwrt(self):
        kind, path = self._detect(present_files=("/bin/opkg",))
        self.assertEqual(kind, "opkg")
        self.assertEqual(path, "/bin/opkg")

    def test_entware_opkg_ignored(self):
        # Keenetic: системный менеджер — Entware'ский /opt/bin/opkg, который
        # НЕ входит в наши списки. Детект должен вернуть (None, None), а не
        # выбрать Entware (kmod оттуда не ставятся).
        kind, path = self._detect(present_files=("/opt/bin/opkg",))
        self.assertIsNone(kind)
        self.assertIsNone(path)

    def test_both_prefers_real_apk(self):
        # Переходный образ с обоими бинарями, но apk-БД присутствует → apk.
        kind, _ = self._detect(
            present_files=("/usr/bin/apk", "/bin/opkg"),
            present_dirs=("/etc/apk",))
        self.assertEqual(kind, "apk")

    def test_none(self):
        kind, path = self._detect()
        self.assertIsNone(kind)
        self.assertIsNone(path)


class TestRequiredPackages(unittest.TestCase):

    def test_iptables(self):
        pkgs = k.required_packages("iptables")
        self.assertIn(k.PKG_NFNETLINK_QUEUE, pkgs)
        self.assertIn(k.PKG_IPT_NFQUEUE, pkgs)
        self.assertNotIn(k.PKG_NFT_QUEUE, pkgs)

    def test_nftables(self):
        pkgs = k.required_packages("nftables")
        self.assertIn(k.PKG_NFNETLINK_QUEUE, pkgs)
        self.assertIn(k.PKG_NFT_QUEUE, pkgs)
        self.assertNotIn(k.PKG_IPT_NFQUEUE, pkgs)

    def test_module_always_first(self):
        # Модуль nfnetlink_queue — критичный, идёт первым в обеих раскладках.
        self.assertEqual(k.required_packages("iptables")[0], k.PKG_NFNETLINK_QUEUE)
        self.assertEqual(k.required_packages("nftables")[0], k.PKG_NFNETLINK_QUEUE)

    def test_unknown_backend_by_binary(self):
        with mock.patch.object(k.shutil, "which",
                               side_effect=lambda n: "/x" if n == "nft" else None):
            pkgs = k.required_packages(None)
        self.assertIn(k.PKG_NFT_QUEUE, pkgs)
        self.assertNotIn(k.PKG_IPT_NFQUEUE, pkgs)


class TestCommandStrings(unittest.TestCase):

    def test_verbs(self):
        self.assertEqual(k._install_verb("apk"), "add")
        self.assertEqual(k._install_verb("opkg"), "install")

    def test_apk_command(self):
        cmd = k.install_command_str("apk", ["kmod-nfnetlink-queue"])
        self.assertEqual(cmd, "apk update && apk add kmod-nfnetlink-queue")

    def test_opkg_command(self):
        cmd = k.install_command_str("opkg", ["kmod-nfnetlink-queue", "kmod-nft-queue"])
        self.assertEqual(
            cmd, "opkg update && opkg install kmod-nfnetlink-queue kmod-nft-queue")

    def test_empty_when_no_manager(self):
        self.assertEqual(k.install_command_str(None, ["x"]), "")
        self.assertEqual(k.install_command_str("apk", []), "")


class TestFixHint(unittest.TestCase):

    def _hint(self, platform, pkg=("apk", "/usr/bin/apk"), fw="iptables"):
        with mock.patch.object(k, "_platform_kind", return_value=platform), \
             mock.patch.object(k, "detect_pkg_manager", return_value=pkg), \
             mock.patch.object(k, "_detect_fw_type", return_value=fw):
            return k.nfqueue_fix_hint()

    def test_openwrt_auto(self):
        h = self._hint("openwrt")
        self.assertTrue(h["can_auto_install"])
        self.assertIn("apk add", h["command"])
        self.assertIn("apk", h["log_line"])

    def test_keenetic_no_auto(self):
        h = self._hint("keenetic", pkg=(None, None))
        self.assertFalse(h["can_auto_install"])
        self.assertIn("прошивк", h["log_line"].lower())

    def test_linux_modprobe(self):
        h = self._hint("linux", pkg=(None, None))
        self.assertFalse(h["can_auto_install"])
        self.assertIn("modprobe", h["command"])

    def test_openwrt_without_manager_falls_back(self):
        # OpenWrt, но менеджер не найден → не предлагаем авто-установку.
        h = self._hint("openwrt", pkg=(None, None))
        self.assertFalse(h["can_auto_install"])


class TestDepsStatus(unittest.TestCase):

    def _status(self, platform, pkg, fw, nfq_avail, target=True):
        with mock.patch.object(k, "_platform_kind", return_value=platform), \
             mock.patch.object(k, "detect_pkg_manager", return_value=pkg), \
             mock.patch.object(k, "_detect_fw_type", return_value=fw), \
             mock.patch.object(k, "_iptables_target_available", return_value=target), \
             mock.patch("core.diagnostics._check_nfqueue_available",
                        return_value=nfq_avail):
            return k.nfqueue_deps_status()

    def test_openwrt_can_auto(self):
        s = self._status("openwrt", ("apk", "/usr/bin/apk"), "iptables", False)
        self.assertTrue(s["can_auto_install"])
        self.assertEqual(s["pkg_manager"], "apk")
        self.assertFalse(s["nfqueue_available"])
        self.assertIn("apk add", s["install_command"])

    def test_keenetic_cannot_auto(self):
        s = self._status("keenetic", (None, None), "iptables", False)
        self.assertFalse(s["can_auto_install"])
        self.assertTrue(s["reason"])
        self.assertTrue(s["instructions"])

    def test_linux_cannot_auto(self):
        s = self._status("linux", (None, None), "iptables", False)
        self.assertFalse(s["can_auto_install"])

    def test_openwrt_healthy_still_reports(self):
        # Даже когда NFQUEUE доступен, статус отдаётся (UI сам решит показывать
        # блок или нет). can_auto_install остаётся True на OpenWrt.
        s = self._status("openwrt", ("opkg", "/bin/opkg"), "nftables", True)
        self.assertTrue(s["nfqueue_available"])
        self.assertTrue(s["can_auto_install"])


class TestInstallGate(unittest.TestCase):

    def test_install_async_refuses_non_openwrt(self):
        # На неподходящей платформе install_async не должен запускать поток —
        # возвращает ok=False с причиной.
        with mock.patch.object(k, "nfqueue_deps_status", return_value={
                "can_auto_install": False, "reason": "нет",
                "pkg_manager": None, "pkg_manager_path": None, "packages": []}):
            # гарантируем, что не «уже идёт»
            with k._state_lock:
                k._state["running"] = False
            r = k.install_async()
        self.assertFalse(r["ok"])
        self.assertIn("error", r)


if __name__ == "__main__":
    unittest.main()
