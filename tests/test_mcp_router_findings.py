# tests/test_mcp_router_findings.py
"""
Находки с живых роутеров (отчёты MCP за октябрь и issue #386).

  * gui_updater сдавался на первом IncompleteRead — ответ на 100 релизов
    (~1.1 МБ) рвался на медленном канале mipsel;
  * строки «Обновлений» без «последней» не говорили почему, а общий флаг
    «проверка удалась» гасился одним удачным запросом;
  * OpenWrt fw4 отклонял форвард LAN → туннель без зоны (issue #386);
  * managed-файл dnsmasq хранил блоки давно удалённых маршрутов;
  * device-правило `from 0.0.0.0` уводило в туннель весь трафик роутера;
  * WAN IP и пробы «напрямую» шли через policy-routing в туннель.
"""

import http.client
import json
import os
import tempfile
import unittest
from unittest import mock


class _Resp:
    def __init__(self, data):
        self._data = data

    def read(self):
        return json.dumps(self._data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestGuiUpdaterRetry(unittest.TestCase):

    def _run(self, side_effect):
        import core.gui_updater as gu
        calls = []

        def fake_urlopen(req, timeout=0):
            calls.append(req.full_url)
            return side_effect(len(calls), req.full_url)

        with mock.patch.object(gu, "urlopen", fake_urlopen), \
                mock.patch.object(gu.time, "sleep"):
            return gu.GuiUpdater()._fetch_github_latest_release(), calls

    def test_incomplete_read_is_retried(self):
        def effect(n, _url):
            if n == 1:
                raise http.client.IncompleteRead(b"x" * 10, 100)
            return _Resp([{"tag_name": "v0.25.24", "draft": False,
                           "prerelease": False}])
        rel, calls = self._run(effect)
        self.assertEqual(rel["tag_name"], "v0.25.24")
        self.assertEqual(len(calls), 2)
        # маленькая страница — меньше шанс обрыва на медленном канале
        self.assertIn("per_page=20", calls[0])

    def test_gives_up_after_attempts_with_reason(self):
        def effect(_n, _url):
            raise http.client.IncompleteRead(b"x", 5)
        import core.gui_updater as gu
        with self.assertRaises(Exception) as cm:
            self._run(effect)
        self.assertIn("оборвался", str(cm.exception))
        self.assertIn("%d попыток" % gu.FETCH_ATTEMPTS, str(cm.exception))

    def test_rate_limit_not_retried(self):
        from urllib.error import HTTPError
        calls = []

        def effect(n, url):
            calls.append(n)
            raise HTTPError(url, 403, "rate", {}, None)
        with self.assertRaises(Exception):
            self._run(effect)
        self.assertEqual(calls, [1])


class TestUpdateRowsTellWhy(unittest.TestCase):

    def test_empty_latest_marked_unknown_with_error(self):
        from core import update_checker as uc
        row = uc._finalize_row({
            "name": "singbox", "installed": True, "current": "1.12.0",
            "latest": "", "has_update": False,
            "error": "Нет доступа к GitHub: [Errno -3]"})
        self.assertEqual(row["latest_source"], "unknown")
        self.assertIn("Errno -3", row["note"])

    def test_own_source_is_kept(self):
        from core import update_checker as uc
        row = uc._finalize_row({"name": "opera", "installed": True,
                                "current": "1.28.0", "latest": "",
                                "latest_source": "upstream", "note": "x"})
        self.assertEqual(row["latest_source"], "upstream")
        self.assertEqual(row["note"], "x")

    def test_installed_without_version_explained(self):
        from core import update_checker as uc
        row = uc._finalize_row({"name": "zapret2", "installed": True,
                                "current": "", "latest": "v1.0.6",
                                "error": ""})
        self.assertNotIn("error", row)
        self.assertIn("установленную версию", row["note"])

    def test_singbox_manifest_failure_reaches_row(self):
        from core import update_checker as uc
        inst = mock.Mock()
        inst.check_for_updates.return_value = {
            "ok": False, "error": "timeout",
            "installed": {"installed": True, "version": "1.12.0"}}
        with mock.patch("core.singbox_installer.get_singbox_installer",
                        return_value=inst):
            row = uc._check_singbox()
        self.assertEqual(row["error"], "timeout")

    def test_incomplete_is_per_row(self):
        from core import update_checker as uc
        rows = [{"name": "opera", "display_name": "opera-proxy",
                 "latest_source": "our"},
                {"name": "mihomo", "display_name": "mihomo",
                 "latest_source": "unknown"}]
        self.assertEqual(uc._incomplete_rows(rows), ["mihomo"])


class TestFw4Forward(unittest.TestCase):

    def setUp(self):
        from core.routing import nftset_backend as nb
        self.nb = nb
        self.tmp = tempfile.mkdtemp()
        self.inc = os.path.join(self.tmp, "chain-pre", "forward_lan",
                                "30-zapret-gui.nft")
        self.calls = []

        def fake_run(args, timeout=10):
            self.calls.append(args)
            if args[:5] == ["nft", "list", "chain", "inet", "fw4"]:
                return 0, "chain forward_lan {}", ""
            return 0, "", ""
        self.patches = [mock.patch.object(nb, "FW4_INCLUDE", self.inc),
                        mock.patch.object(nb, "_run", fake_run)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def _reloads(self):
        return [c for c in self.calls if c[:1] == ["fw4"]]

    def test_add_writes_dropin_and_reloads_once(self):
        self.assertTrue(self.nb.fw4_sync_forward("awg", True)["changed"])
        with open(self.inc) as f:
            self.assertIn('oifname "awg" accept', f.read())
        self.assertEqual(len(self._reloads()), 1)
        # повтор (тик guardian'а) — без пересборки fw4
        self.assertFalse(self.nb.fw4_sync_forward("awg", True)["changed"])
        self.assertEqual(len(self._reloads()), 1)

    def test_remove_last_deletes_file(self):
        self.nb.fw4_sync_forward("awg", True)
        self.nb.fw4_sync_forward("sbtun0", True)
        self.nb.fw4_sync_forward("awg", False)
        self.assertEqual(self.nb._fw4_include_ifaces(), ["sbtun0"])
        self.nb.fw4_sync_forward("sbtun0", False)
        self.assertFalse(os.path.exists(self.inc))

    def test_no_fw4_is_noop(self):
        with mock.patch.object(self.nb, "_run",
                               return_value=(1, "", "No such file")):
            self.assertTrue(self.nb.fw4_sync_forward("awg", True)["skipped"])
        self.assertFalse(os.path.exists(self.inc))

    def test_doctor_flags_unzoned_iface(self):
        from core.routing import doctor
        with mock.patch.object(self.nb, "fw4_present", return_value=True), \
                mock.patch.object(self.nb, "_run",
                                  return_value=(0, 'oifname "eth1"', "")):
            chk = doctor._forward_check("awg")
        self.assertFalse(chk["ok"])
        self.assertIn("зоны fw4", chk["details"])


class TestDeviceRuleRejectsUnspecified(unittest.TestCase):

    def test_zero_address_never_reaches_ip_rule(self):
        from core.routing import device_rule
        from core.routing.rules import DeviceRoutingRule
        for src in ("0.0.0.0", "0.0.0.0/0", "::", "127.0.0.1"):
            rule = DeviceRoutingRule(target_iface="awg0", source_ip=src)
            with mock.patch.object(device_rule, "_run") as run:
                res = device_rule.apply_device_rule(rule)
            self.assertFalse(res["ok"], src)
            self.assertTrue(res.get("skipped"), src)
            run.assert_not_called()

    def test_normal_address_allowed(self):
        from core.routing import device_rule
        self.assertEqual(device_rule._unusable_source("192.168.1.84/32"), "")
        self.assertEqual(device_rule._unusable_source("192.168.1.0/24"), "")


class TestSweepStaleDnsmasq(unittest.TestCase):

    def _reason(self, text, live_ids=(), kind="ipset"):
        from core.routing import dnsmasq_integration, domain_rule, sweeper
        rules = [mock.Mock(id=i) for i in live_ids]
        with mock.patch.object(dnsmasq_integration, "_read_file",
                               return_value=text), \
                mock.patch.object(domain_rule, "_all_domain_rules",
                                  return_value=rules), \
                mock.patch.object(domain_rule, "_choose_set_kind",
                                  return_value=kind):
            return sweeper._stale_dnsmasq_reason()

    FILE = ("# Managed by zapret-gui — do not edit by hand.\n"
            "# rule uni-route-ae11239a-dom\n"
            "nftset=/t.me/inet#awg_routing#awgr_x,inet#awg_routing#awgr_x6\n")

    def test_dead_rule_block(self):
        self.assertIn("uni-route-ae11239a-dom", self._reason(self.FILE))

    def test_nftset_on_iptables_router(self):
        reason = self._reason(self.FILE, live_ids=["uni-route-ae11239a-dom"],
                              kind="ipset")
        self.assertIn("nftset=", reason)

    def test_fresh_file_ok(self):
        self.assertEqual(self._reason(self.FILE,
                                      live_ids=["uni-route-ae11239a-dom"],
                                      kind="nftset"), "")


class TestWanIpFromMain(unittest.TestCase):

    def test_tunnel_does_not_masquerade_as_wan(self):
        from core import system_info

        def fake(args, **_kw):
            if args[:3] == ["ip", "-4", "route"]:
                out = "default via 155.223.128.1 dev eth2.4 metric 1000\n"
            elif args[:3] == ["ip", "-4", "-o"]:
                out = ("5: eth2.4    inet 155.223.167.138/18 brd"
                       " 155.223.191.255 scope global eth2.4\n")
            else:                      # ip route get → в туннель
                out = "8.8.8.8 dev AmneziaWarp-AWG table 527 src 172.16.0.2\n"
            return mock.Mock(returncode=0, stdout=out)
        with mock.patch("subprocess.run", side_effect=fake):
            self.assertEqual(system_info._get_wan_ip(), "155.223.167.138")


class TestDirectProbeBindsWan(unittest.TestCase):

    def test_socket_bound_to_main_default_dev(self):
        from core import reachability as rc
        rc.reset()
        sock = mock.MagicMock()
        with mock.patch.object(rc, "_wan_dev", return_value="eth2.4"), \
                mock.patch.object(rc.socket, "socket", return_value=sock):
            self.assertTrue(rc._tcp_probe(("1.1.1.1", 443)))
        opt = sock.setsockopt.call_args[0]
        self.assertEqual(opt[2], b"eth2.4\0")
        sock.connect.assert_called_once_with(("1.1.1.1", 443))


if __name__ == "__main__":
    unittest.main()


class TestRemoveDomainRuleCleansDnsmasq(unittest.TestCase):
    """Удалённый доменный маршрут не оставляет блок и conf-file= в dnsmasq.

    routing.manager.remove_rule снимает правило ДО удаления из storage, и
    пересборка managed-файла раньше видела его живым — блок `# rule <id>`
    переписывался обратно, а `conf-file=` не снимался.
    """

    def _dn(self):
        dn = mock.Mock()
        dn.remove_include.return_value = {"ok": True, "removed_include": True}
        dn.restart.return_value = {"ok": True}
        dn.reload.return_value = {"ok": True}
        return dn

    def test_rebuild_excludes_rule_being_removed(self):
        from core.routing import domain_rule
        from core.routing.rules import DomainRoutingRule
        rule = DomainRoutingRule(target_iface="awg0", domains=["t.me"],
                                 rule_id="uni-route-ae11239a-dom")
        dn = self._dn()
        with mock.patch.object(domain_rule.dnsmasq_integration,
                               "DnsmasqIntegration", return_value=dn), \
                mock.patch.object(domain_rule, "_choose_set_kind",
                                  return_value="nftset"), \
                mock.patch("core.routing.storage.load_rules",
                           return_value=[rule]):
            res = domain_rule._rebuild_managed_dnsmasq(exclude=rule.id)
        self.assertTrue(res["ok"], res)
        dn.remove_include.assert_called_once()
        dn.write_managed_file.assert_not_called()

    def test_dnsmasq_path_passes_exclude(self):
        from core.routing import domain_rule
        from core.routing.rules import DomainRoutingRule
        rule = DomainRoutingRule(target_iface="awg0", domains=["t.me"],
                                 rule_id="uni-x-dom")
        backend = mock.Mock()
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=False), \
                mock.patch.object(domain_rule, "_iproute_state_load",
                                  return_value={}), \
                mock.patch.object(domain_rule, "_sets_state_load",
                                  return_value={}), \
                mock.patch.object(domain_rule, "_detect_backend",
                                  return_value=(backend, "nftset")), \
                mock.patch.object(domain_rule, "_table_id_for",
                                  return_value=200), \
                mock.patch.object(domain_rule, "_mark_for",
                                  return_value=0x100), \
                mock.patch("core.routing.masquerade.remove_if_unused"), \
                mock.patch.object(domain_rule, "_rebuild_managed_dnsmasq",
                                  return_value={"ok": True}) as rebuild:
            domain_rule.remove_domain_rule(rule)
        rebuild.assert_called_once_with(exclude="uni-x-dom")

    def test_sets_path_drops_old_dnsmasq_block(self):
        from core.routing import domain_rule
        from core.routing.rules import DomainRoutingRule
        rule = DomainRoutingRule(target_iface="awg0", domains=["t.me"],
                                 rule_id="uni-y-dom")
        with mock.patch.object(domain_rule, "_ndms_available",
                               return_value=False), \
                mock.patch.object(domain_rule, "_iproute_state_load",
                                  return_value={}), \
                mock.patch.object(domain_rule, "_sets_state_load",
                                  return_value={rule.id: "ipset"}), \
                mock.patch.object(domain_rule, "_remove_domain_via_sets",
                                  return_value={"ok": True}), \
                mock.patch.object(domain_rule.dnsmasq_integration,
                                  "DnsmasqIntegration",
                                  return_value=self._dn()), \
                mock.patch.object(domain_rule.dnsmasq_integration,
                                  "_read_file",
                                  return_value="# rule uni-y-dom\n"
                                               "ipset=/t.me/x\n"), \
                mock.patch.object(domain_rule, "_rebuild_managed_dnsmasq",
                                  return_value={"ok": True}) as rebuild:
            domain_rule.remove_domain_rule(rule)
        rebuild.assert_called_once_with(exclude="uni-y-dom")

    def test_sweeper_flags_file_without_rules(self):
        from core.routing import dnsmasq_integration, domain_rule, sweeper
        with mock.patch.object(dnsmasq_integration, "_read_file",
                               return_value="# Managed by zapret-gui\n"), \
                mock.patch.object(domain_rule, "_all_domain_rules",
                                  return_value=[]):
            self.assertIn("правил нет", sweeper._stale_dnsmasq_reason())

    def test_delete_route_sweeps_dnsmasq(self):
        from core.unified import manager
        route = mock.Mock(id="uni-route-z")
        with mock.patch("core.unified.storage.get_route",
                        return_value=route), \
                mock.patch("core.unified.storage.remove_route"), \
                mock.patch("core.unified.applier.remove_route"), \
                mock.patch.object(manager, "_sync_monitor"), \
                mock.patch("core.routing.sweeper.sweep_dnsmasq",
                           return_value=([], [])) as sweep:
            self.assertTrue(manager.delete_route("uni-route-z")["ok"])
        sweep.assert_called_once()
