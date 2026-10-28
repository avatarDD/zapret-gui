# tests/test_dnsmasq_line_limit.py
"""
Лимит длины строки в конфиге dnsmasq (issue #332).

dnsmasq читает конфиг через `fgets(buff, MAXDNAME, f)`, MAXDNAME = 1025:
строка длиннее 1024 байт разрывается, хвост разбирается как отдельная
директива, и dnsmasq падает с «bad option at line N» — вместе с ним на
роутере ложатся DHCP и DNS. Длинный список доменов обязан разъезжаться
по нескольким директивам.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    mock = None

from core.routing import dnsmasq_integration as di


# Жёсткий предел самого dnsmasq (MAXDNAME - 1), в байтах, с «\n».
DNSMASQ_HARD_LIMIT = 1024


class TestSplitDomainDirectives(unittest.TestCase):

    def test_short_list_stays_one_line(self):
        lines = di.split_domain_directives(
            "nftset=/", ["google.com", "youtube.com"],
            "/4#inet#awg_routing#awgr_a,6#inet#awg_routing#awgr_a6")
        self.assertEqual(len(lines), 1)
        self.assertEqual(
            lines[0],
            "nftset=/google.com/youtube.com/"
            "4#inet#awg_routing#awgr_a,6#inet#awg_routing#awgr_a6")

    def test_long_list_is_split_and_every_line_fits(self):
        doms = ["sub%03d.example-domain-name.com" % i for i in range(300)]
        suffix = "/4#inet#awg_routing#awgr_abcd1234,6#inet#awg_routing#awgr_abcd12346"
        lines = di.split_domain_directives("nftset=/", doms, suffix)
        self.assertGreater(len(lines), 1)
        for ln in lines:
            self.assertLessEqual(len(ln.encode("utf-8")) + 1,
                                 DNSMASQ_HARD_LIMIT, ln)
            self.assertTrue(ln.startswith("nftset=/"))
            self.assertTrue(ln.endswith(suffix))

    def test_no_domain_is_lost_or_duplicated(self):
        doms = ["d%d.example.com" % i for i in range(500)]
        suffix = "/awgr_x,awgr_x6"
        lines = di.split_domain_directives("ipset=/", doms, suffix)
        got = []
        for ln in lines:
            body = ln[len("ipset=/"):-len(suffix)]
            got.extend(body.split("/"))
        self.assertEqual(got, doms)

    def test_single_oversized_domain_is_kept_on_its_own_line(self):
        """Резать доменное имя нельзя — оно уезжает отдельной строкой."""
        huge = "a" * 1200 + ".example.com"
        lines = di.split_domain_directives(
            "ipset=/", ["short.com", huge, "other.com"], "/awgr_x,awgr_x6")
        self.assertEqual(len(lines), 3)
        self.assertIn(huge, lines[1])

    def test_unicode_domains_counted_in_bytes(self):
        """Лимит у dnsmasq в байтах: кириллический домен «весит» вдвое."""
        doms = ["домен-%02d.рф" % i for i in range(200)]
        suffix = "/awgr_x,awgr_x6"
        lines = di.split_domain_directives("ipset=/", doms, suffix)
        for ln in lines:
            self.assertLessEqual(len(ln.encode("utf-8")) + 1,
                                 DNSMASQ_HARD_LIMIT, ln)

    def test_empty_list_gives_no_lines(self):
        self.assertEqual(
            di.split_domain_directives("ipset=/", [], "/awgr_x,awgr_x6"), [])


@unittest.skipIf(mock is None, "нет unittest.mock")
class TestManagedFileLines(unittest.TestCase):
    """Тот же инвариант, но на выходе write_managed_file()."""

    def _write(self, blocks):
        dn = di.DnsmasqIntegration()
        tmp_dir = tempfile.mkdtemp()
        main_conf = os.path.join(tmp_dir, "dnsmasq.conf")
        managed = os.path.join(tmp_dir, "managed.conf")
        with mock.patch.object(dn, "find_main_config", return_value=main_conf), \
             mock.patch.object(dn, "managed_file_path", return_value=managed):
            res = dn.write_managed_file(blocks)
        self.assertTrue(res["ok"], res)
        with open(managed, "r", encoding="utf-8") as f:
            return f.read()

    def _assert_all_lines_fit(self, text):
        for ln in text.splitlines():
            self.assertLessEqual(len(ln.encode("utf-8")) + 1,
                                 DNSMASQ_HARD_LIMIT, ln[:80] + "...")

    def test_nftset_block_with_many_domains(self):
        text = self._write([{
            "rule_id": "r1",
            "set_kind": "nftset",
            "set_name": "awgr_deadbeef",
            "nft_table": "awg_routing",
            "nft_family": "inet",
            "domains": ["host%04d.streaming-service.example" % i
                        for i in range(400)],
        }])
        self._assert_all_lines_fit(text)
        self.assertGreater(
            sum(1 for ln in text.splitlines() if ln.startswith("nftset=/")), 1)
        # Оба set'а (v4 и v6) остались в КАЖДОЙ директиве.
        for ln in text.splitlines():
            if ln.startswith("nftset=/"):
                self.assertTrue(ln.endswith("4#inet#awg_routing#awgr_deadbeef,"
                                            "6#inet#awg_routing#awgr_deadbeef6"))

    def test_ipset_block_with_many_domains(self):
        text = self._write([{
            "rule_id": "r2",
            "set_kind": "ipset",
            "set_name": "awgr_cafe",
            "domains": ["host%04d.streaming-service.example" % i
                        for i in range(400)],
        }])
        self._assert_all_lines_fit(text)
        for ln in text.splitlines():
            if ln.startswith("ipset=/"):
                self.assertTrue(ln.endswith("awgr_cafe,awgr_cafe6"))


@unittest.skipIf(mock is None, "нет unittest.mock")
class TestRemoveInclude(unittest.TestCase):
    """Снятие include симметрично ensure_include() (issue #332)."""

    def test_include_and_managed_file_are_removed(self):
        dn = di.DnsmasqIntegration()
        tmp_dir = tempfile.mkdtemp()
        main_conf = os.path.join(tmp_dir, "dnsmasq.conf")
        managed = os.path.join(tmp_dir, "zapret-gui-awg-routing.conf")
        with open(main_conf, "w") as f:
            f.write("port=53\n%s\nconf-file=%s\nlog-queries\n"
                    % (di.INCLUDE_MARKER, managed))
        with open(managed, "w") as f:
            f.write("# managed\n")

        with mock.patch.object(dn, "find_main_config", return_value=main_conf), \
             mock.patch.object(dn, "managed_file_path", return_value=managed):
            res = dn.remove_include()

        self.assertTrue(res["ok"], res)
        self.assertFalse(os.path.exists(managed))
        with open(main_conf) as f:
            text = f.read()
        self.assertNotIn(di.INCLUDE_MARKER, text)
        self.assertNotIn("conf-file=", text)
        # Чужие строки не тронуты.
        self.assertIn("port=53", text)
        self.assertIn("log-queries", text)

    def test_foreign_conf_file_lines_are_kept(self):
        dn = di.DnsmasqIntegration()
        tmp_dir = tempfile.mkdtemp()
        main_conf = os.path.join(tmp_dir, "dnsmasq.conf")
        managed = os.path.join(tmp_dir, "zapret-gui-awg-routing.conf")
        with open(main_conf, "w") as f:
            f.write("conf-file=/etc/dnsmasq.d/other.conf\n")

        with mock.patch.object(dn, "find_main_config", return_value=main_conf), \
             mock.patch.object(dn, "managed_file_path", return_value=managed):
            res = dn.remove_include()

        self.assertTrue(res["ok"], res)
        with open(main_conf) as f:
            self.assertIn("conf-file=/etc/dnsmasq.d/other.conf", f.read())

    def test_idempotent_when_nothing_to_remove(self):
        dn = di.DnsmasqIntegration()
        tmp_dir = tempfile.mkdtemp()
        main_conf = os.path.join(tmp_dir, "dnsmasq.conf")
        managed = os.path.join(tmp_dir, "zapret-gui-awg-routing.conf")
        with open(main_conf, "w") as f:
            f.write("port=53\n")
        with mock.patch.object(dn, "find_main_config", return_value=main_conf), \
             mock.patch.object(dn, "managed_file_path", return_value=managed):
            res = dn.remove_include()
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["removed_include"])
        self.assertFalse(res["removed_file"])


if __name__ == "__main__":
    unittest.main()
