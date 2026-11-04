"""Сторож маршрутизации (core/routing/guardian.py): хук netfilter.d,
восстановление правил после перезаписи netfilter, разбор netlink."""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from core.routing import guardian, marks
from core.routing.rules import (CidrRoutingRule, DomainRoutingRule,
                                DscpRoutingRule)


def _sh_ok(text: str) -> bool:
    sh = shutil.which("sh")
    if not sh:
        return True
    r = subprocess.run([sh, "-n"], input=text, capture_output=True,
                       text=True)
    return r.returncode == 0


class TestHook(unittest.TestCase):

    def test_hooks_are_valid_shell(self):
        self.assertTrue(_sh_ok(guardian.build_hook(ndm=True)))
        self.assertTrue(_sh_ok(guardian.build_hook(ndm=False)))

    def test_hook_checks_process_before_signalling(self):
        body = guardian.build_hook()
        self.assertIn("kill -USR2", body)
        self.assertIn("/proc/$pid/cmdline", body)
        self.assertIn('"$table" = "filter"', body)
        self.assertLess(body.index("cmdline"), body.index("kill -USR2"))

    def test_hook_signals_only_our_process(self):
        """Живой прогон хука: PID-файл указывает на процесс без app.py в
        cmdline — сигнала нет; на «наш» — есть."""
        sh = shutil.which("sh")
        if not sh or not os.path.isdir("/proc/self"):
            self.skipTest("нет sh или /proc")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        flag = os.path.join(tmp, "got")
        # «Чужой» процесс: обычный sleep.
        foreign = subprocess.Popen(["sleep", "30"])
        self.addCleanup(foreign.kill)
        pf = os.path.join(tmp, "pid")
        with open(pf, "w") as f:
            f.write(str(foreign.pid))
        hook = guardian.build_hook(pid_files=(pf,), ndm=True)
        subprocess.run([sh, "-c", hook], env={"table": "mangle",
                                               "PATH": os.environ["PATH"]},
                       timeout=10)
        self.assertIsNone(foreign.poll(), "чужой процесс получил сигнал")
        # «Наш»: в cmdline есть zapret-gui, ловит USR2 и пишет флаг.
        ours = subprocess.Popen(
            [sh, "-c", "trap 'echo ok > %s; exit 0' USR2; "
                       "while :; do sleep 0.1; done" % flag,
             "zapret-gui"])
        self.addCleanup(ours.kill)
        with open(pf, "w") as f:
            f.write(str(ours.pid))
        import time
        time.sleep(0.3)
        subprocess.run([sh, "-c", hook], env={"table": "nat",
                                               "PATH": os.environ["PATH"]},
                       timeout=10)
        ours.wait(5)
        self.assertTrue(os.path.exists(flag))

    def test_install_writes_only_where_mechanism_exists(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        ndm = os.path.join(tmp, "ndm", "netfilter.d", "101-x.sh")
        os.makedirs(os.path.dirname(ndm))
        with mock.patch.object(guardian, "NDM_HOOK_PATH", ndm), \
                mock.patch.object(guardian, "HOTPLUG_HOOK_PATH",
                                  os.path.join(tmp, "none", "91-x")), \
                mock.patch.object(guardian.os.path, "isdir",
                                  side_effect=lambda p: p == os.path.dirname(ndm)):
            done = guardian.install_hooks()
        self.assertEqual(done, [ndm])
        self.assertTrue(os.access(ndm, os.X_OK))


class TestRestore(unittest.TestCase):

    def test_mark_entries_only_for_existing_sets(self):
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r1-dom")
        with mock.patch("core.routing.domain_rule._mark_for",
                        return_value=0x30000):
            entries = guardian.mark_entries_for(
                [dom], {"awgr_uni_r1_dom"})
        self.assertEqual(entries["v4"],
                         [("awgr_uni_r1_dom", 0x30000, marks.MASK)])
        self.assertEqual(entries["v6"], [])

    def test_restore_firewall_rebuilds_everything(self):
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r1-dom")
        cidr = CidrRoutingRule(target_iface="Wireguard0",
                               cidrs=["1.0.0.0/8"], rule_id="c1")
        dscp = DscpRoutingRule(target_iface="awg0", dscp=46, rule_id="d1")
        synced, masq, dscp_applied = [], [], []
        fake_di = mock.Mock()
        fake_di.reassert.return_value = {"ok": True, "backend": "iptables"}
        with mock.patch.object(guardian, "_enabled_rules",
                               return_value=[dom, cidr, dscp]), \
                mock.patch.object(guardian, "_existing_ipsets",
                                  return_value={"awgr_uni_r1_dom"}), \
                mock.patch.object(guardian, "_iface_exists",
                                  return_value=True), \
                mock.patch("core.routing.ipset_backend.available",
                           return_value=True), \
                mock.patch("core.routing.ipset_backend.sync_mark_entries",
                           side_effect=lambda e, f: synced.append((f, e))
                           or {"ok": True, "errors": []}), \
                mock.patch("core.routing.domain_rule._mark_for",
                           return_value=0x10000), \
                mock.patch("core.routing.masquerade.ensure_for_iface",
                           side_effect=lambda i: masq.append(i)
                           or {"ok": True}), \
                mock.patch("core.routing.manager._is_ndms_native_iface",
                           side_effect=lambda i: i.startswith("Wireguard")), \
                mock.patch("core.routing.dscp_rule.apply_dscp_rule",
                           side_effect=lambda r: dscp_applied.append(r.id)), \
                mock.patch("core.routing.ipset_backend.marks_in_place",
                           return_value=False), \
                mock.patch("core.routing.dscp_rule.is_hooked",
                           return_value=False), \
                mock.patch("core.routing.dns_intercept.get_dns_intercept",
                           return_value=fake_di):
            res = guardian.restore_firewall()
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["changed"])
        self.assertEqual(res["restored"]["marks"], 1)
        self.assertEqual(res["restored"]["dscp"], 1)
        self.assertEqual(synced, [("v4", [("awgr_uni_r1_dom", 0x10000,
                                           marks.MASK)])])
        # нативный интерфейс Keenetic NDMS ведёт сам — без нашего NAT
        self.assertEqual(masq, ["awg0"])
        self.assertEqual(dscp_applied, ["d1"])
        self.assertTrue(res["dns"])


class TestRestoreWhenNothingIsMissing(unittest.TestCase):
    """Хук зовут и без перезаписи (Keenetic — раз в 5 минут): тогда
    правила не переписываются, и в журнале нет «правила возвращены»."""

    def _restore(self, *, in_place=True, added=False, hooked=True,
                 dns_noop=True):
        dom = DomainRoutingRule(target_iface="awg0", domains=["a.com"],
                                rule_id="uni-r1-dom")
        dscp = DscpRoutingRule(target_iface="awg0", dscp=46, rule_id="d1")
        fake_di = mock.Mock()
        fake_di.reassert.return_value = (
            {"ok": True, "noop": True} if dns_noop else {"ok": True})
        synced = []
        with mock.patch.object(guardian, "_enabled_rules",
                               return_value=[dom, dscp]), \
                mock.patch.object(guardian, "_existing_ipsets",
                                  return_value={"awgr_uni_r1_dom"}), \
                mock.patch.object(guardian, "_iface_exists",
                                  return_value=True), \
                mock.patch("core.routing.ipset_backend.available",
                           return_value=True), \
                mock.patch("core.routing.ipset_backend.marks_in_place",
                           return_value=in_place), \
                mock.patch("core.routing.ipset_backend.sync_mark_entries",
                           side_effect=lambda e, f: synced.append(f)
                           or {"ok": True, "errors": []}), \
                mock.patch("core.routing.domain_rule._mark_for",
                           return_value=0x10000), \
                mock.patch("core.routing.masquerade.ensure_for_iface",
                           return_value={"ok": True, "added": added}), \
                mock.patch("core.routing.manager._is_ndms_native_iface",
                           return_value=False), \
                mock.patch("core.routing.dscp_rule.is_hooked",
                           return_value=hooked), \
                mock.patch("core.routing.dscp_rule.apply_dscp_rule"), \
                mock.patch("core.routing.dns_intercept.get_dns_intercept",
                           return_value=fake_di):
            return guardian.restore_firewall(), synced

    def test_all_in_place_is_not_a_restore(self):
        res, synced = self._restore()
        self.assertTrue(res["ok"])
        self.assertFalse(res["changed"])
        self.assertEqual(synced, [])          # цепочки не переписывали
        self.assertEqual(guardian.restore_summary(res), "")

    def test_lost_masquerade_is_reported(self):
        res, _ = self._restore(added=True)
        self.assertTrue(res["changed"])
        self.assertEqual(guardian.restore_summary(res), "masquerade: awg0")

    def test_lost_marks_are_resynced(self):
        res, synced = self._restore(in_place=False)
        self.assertEqual(synced, ["v4"])
        self.assertIn("маркировка доменов: 1", guardian.restore_summary(res))


class TestRestoreLog(unittest.TestCase):

    def setUp(self):
        guardian._last_restore.update(text="", at=0.0, repeats=0)
        self.p = mock.patch.object(guardian, "log")
        self.log = self.p.start()

    def tearDown(self):
        self.p.stop()

    @staticmethod
    def _res(changed=True, errors=None):
        return {"changed": changed, "errors": errors or [], "dns": False,
                "restored": {"marks": 0, "ifaces": ["awg0"] if changed
                             else [], "dscp": 0}}

    def test_nothing_missing_is_debug_only(self):
        for i in range(5):
            guardian._log_restore(self._res(changed=False), now=300.0 * i)
        self.log.info.assert_not_called()
        self.log.warning.assert_not_called()

    def test_same_restore_is_collapsed_for_an_hour(self):
        for i in range(12):                      # раз в 5 минут, час
            guardian._log_restore(self._res(), now=1000.0 + 300 * i)
        self.assertEqual(self.log.info.call_count, 1)
        guardian._log_restore(self._res(), now=1000.0 + 3600)
        self.assertEqual(self.log.info.call_count, 2)
        self.assertIn("ещё 11 раз", self.log.info.call_args[0][0])

    def test_errors_are_warnings(self):
        guardian._log_restore(self._res(changed=False,
                                        errors=["masquerade awg0: x"]))
        self.log.warning.assert_called_once()


def _nlmsg(mtype, body):
    return struct.pack("=IHHII", 16 + len(body), mtype, 0, 0, 0) + body


def _link(mtype, index, name, up):
    ifname = name.encode() + b"\0"
    attr = struct.pack("=HH", 4 + len(ifname), guardian.IFLA_IFNAME) + ifname
    attr += b"\0" * ((4 - len(attr) % 4) % 4)
    body = struct.pack("=BBHiII", 0, 0, 1, index,
                       guardian.IFF_UP if up else 0, 0) + attr
    return _nlmsg(mtype, body)


class TestNetlink(unittest.TestCase):

    def test_parse_link_and_addr(self):
        data = (_link(guardian.RTM_NEWLINK, 7, "awg0", True)
                + _link(guardian.RTM_DELLINK, 8, "tun1", False)
                + _nlmsg(guardian.RTM_NEWADDR,
                         struct.pack("=BBBBi", 2, 24, 0, 0, 7)))
        self.assertEqual(guardian.parse_netlink(data), [
            ("link", 7, "awg0", True),
            ("gone", 8, "tun1", False),
            ("addr", 7, "", True),
        ])

    def test_parse_garbage(self):
        self.assertEqual(guardian.parse_netlink(b"\x01\x02"), [])
        self.assertEqual(guardian.parse_netlink(
            struct.pack("=IHHII", 9999, 16, 0, 0, 0)), [])

    def test_up_of_managed_iface_is_scheduled_once(self):
        class Sock:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def recv(self, _n):
                if not self.chunks:
                    raise OSError("closed")
                return self.chunks.pop(0)
        sock = Sock([_link(guardian.RTM_NEWLINK, 7, "awg0", True),
                     _link(guardian.RTM_NEWLINK, 7, "awg0", True),
                     _link(guardian.RTM_NEWLINK, 9, "eth9", True)])
        guardian._pending_links.clear()
        with mock.patch.object(guardian, "_managed_ifaces",
                               return_value={"awg0"}):
            guardian._netlink_loop(sock)
        self.assertEqual(list(guardian._pending_links), ["awg0"])
        guardian._pending_links.clear()


if __name__ == "__main__":
    unittest.main()


class TestMarksInPlace(unittest.TestCase):

    def _check(self, chain_dump, pre, out):
        from core.routing import ipset_backend as ib
        dumps = {ib.PREROUTING_CHAIN: chain_dump, "PREROUTING": pre,
                 "OUTPUT": out}

        def fake_run(args, timeout=10):
            return 0, dumps.get(args[-1], ""), ""
        with mock.patch.object(ib, "_run", side_effect=fake_run):
            return ib.marks_in_place([("awgr_x", 0x10000, marks.MASK)])

    def test_all_hooked(self):
        from core.routing import ipset_backend as ib
        dump = ("-A %s -m set --match-set awgr_x dst -j MARK --set-xmark "
                "0x10000/0x%x" % (ib.PREROUTING_CHAIN, marks.MASK))
        pre = "-A PREROUTING -j %s" % ib.PREROUTING_CHAIN
        out = "-A OUTPUT -j %s" % ib.OUTPUT_CHAIN
        self.assertTrue(self._check(dump, pre, out))
        self.assertFalse(self._check(dump, pre, ""))       # OUTPUT снесли
        self.assertFalse(self._check("", pre, out))        # записей нет


class TestGenevaAutoReassert(unittest.TestCase):
    """Хук netfilter.d (NDMS пересобрал таблицы) будит и geneva «Авто»:
    его цепочки ZGGA_* в mangle сносятся так же."""

    def test_calls_manager_and_swallows_errors(self):
        m = mock.Mock()
        with mock.patch("core.geneva_auto_manager.get_geneva_auto_manager",
                        return_value=m):
            guardian._reassert_geneva_auto()
        m.reassert_rules.assert_called_once_with()
        m.reassert_rules.side_effect = RuntimeError("x")
        with mock.patch("core.geneva_auto_manager.get_geneva_auto_manager",
                        return_value=m):
            guardian._reassert_geneva_auto()       # без исключения
