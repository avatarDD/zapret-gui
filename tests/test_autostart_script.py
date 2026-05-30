# tests/test_autostart_script.py
"""Тесты генерации init-скрипта автозапуска (S99zapret).

Проверяем главное, что было сломано до портирования из nfqws2-keenetic:
согласованность fwmark / queue-num между firewall-правилами скрипта и
командой запуска nfqws2, наличие PREROUTING/NAT/TCP-flags правил и
валидность shell-синтаксиса.
"""

import shutil
import subprocess
import unittest

from core.autostart_manager import get_autostart_manager
from core.config_manager import get_config_manager


class TestGeneratedScript(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.script = get_autostart_manager()._generate_script()
        cls.cfg = get_config_manager()

    def test_queue_num_matches_config(self):
        qnum = str(self.cfg.get("nfqws", "queue_num", default=300))
        self.assertIn('QUEUE_NUM="%s"' % qnum, self.script)
        # Не остался старый рассинхронизированный дефолт firewall.queue_num=200.
        self.assertNotIn('QUEUE_NUM="200"', self.script)

    def test_mark_matches_config(self):
        mark = self.cfg.get("nfqws", "desync_mark", default="0x40000000")
        self.assertIn("MARK_PROCESSED=\"%s/%s\"" % (mark, mark), self.script)
        # Старый хардкод 0x10000 должен исчезнуть.
        self.assertNotIn("0x10000", self.script)

    def test_has_prerouting_chain(self):
        self.assertIn("nfqws_pre", self.script)
        self.assertIn("PREROUTING", self.script)

    def test_has_nat_masquerade(self):
        self.assertIn("nfqws_nat", self.script)
        self.assertIn("MASQUERADE", self.script)

    def test_has_tcp_flag_rules(self):
        self.assertIn("--tcp-flags syn,ack syn,ack", self.script)
        self.assertIn("--tcp-flags fin fin", self.script)
        self.assertIn("--tcp-flags rst rst", self.script)

    def test_has_conntrack_tuning(self):
        self.assertIn("nf_conntrack_tcp_be_liberal=1", self.script)
        self.assertIn("nf_conntrack_checksum=0", self.script)

    def test_has_reapply_subcommands(self):
        # Нужны для ndm/hotplug-хуков переустановки правил.
        for cmd in ("firewall_iptables", "firewall_ip6tables",
                    "firewall_stop", "reapply"):
            self.assertIn(cmd, self.script)

    def test_no_unsubstituted_placeholders(self):
        self.assertNotIn("@", self.script.split("NFQWS_ARGS=")[0])

    def test_shell_syntax_valid(self):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("sh недоступен")
        proc = subprocess.run(
            [sh, "-n"], input=self.script,
            text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestAutostartModel(unittest.TestCase):
    """Issue #107: на systemd (Debian) Entware-каталог /opt/etc/init.d
    может существовать, но init.d-скрипты НЕ исполняются при загрузке.
    Модель автозапуска должна отдавать приоритет systemd, а boot-apply
    GUI — НЕ пропускать запуск nfqws2 из-за наличия мёртвого S99zapret."""

    def _patch(self, *, systemd, entware, openwrt=False, script=True):
        from unittest import mock
        import core.autostart_manager as am
        return [
            mock.patch.object(am, "_is_systemd", return_value=systemd),
            mock.patch.object(am, "_is_entware", return_value=entware),
            mock.patch.object(am, "_is_openwrt_procd", return_value=openwrt),
            mock.patch("os.path.isfile", return_value=script),
        ]

    def _run(self, **kw):
        import core.autostart_manager as am
        patches = self._patch(**kw)
        for p in patches:
            p.start()
        try:
            return am._autostart_model(), am.external_boot_starts_nfqws()
        finally:
            for p in patches:
                p.stop()

    def test_debian_systemd_with_entware_dir(self):
        # /opt/etc/init.d есть + systemd → модель systemd, GUI стартует сам.
        model, external = self._run(systemd=True, entware=True)
        self.assertEqual(model, "systemd")
        self.assertFalse(external)

    def test_keenetic_entware(self):
        # Entware без systemd + скрипт есть → init.d сам поднимает nfqws2.
        model, external = self._run(systemd=False, entware=True, script=True)
        self.assertEqual(model, "entware")
        self.assertTrue(external)

    def test_entware_without_script(self):
        # Entware, но скрипт ещё не установлен → GUI должен поднять сам.
        model, external = self._run(systemd=False, entware=True, script=False)
        self.assertEqual(model, "entware")
        self.assertFalse(external)

    def test_openwrt_procd(self):
        model, external = self._run(systemd=False, entware=False, openwrt=True)
        self.assertEqual(model, "openwrt")
        self.assertFalse(external)

    def test_plain_linux_none(self):
        model, external = self._run(systemd=False, entware=False, openwrt=False)
        self.assertEqual(model, "none")
        self.assertFalse(external)


if __name__ == "__main__":
    unittest.main()
