# tests/test_lists_routing_review.py
"""
Сторожа к ревью списков, blob'ов, детектора и маршрутизации.

Каждый тест — одна найденная ошибка, которая вернуться не должна:
  - хостлист: .рф и «^» выпадали при сохранении из GUI, «*.» молча не
    работал, файл писался не атомарно, file:// в импорте;
  - ipset: «:::» и «01.2.3.4» принимались (nfqws2 их отбрасывает),
    «::ffff:1.2.3.4» — нет;
  - blob: созданный в GUI blob не объявлялся для nfqws2, имя с «-»/«.»
    роняло nfqws2 при старте;
  - named-lists: hosts-формат заводил 127.0.0.1 в CIDR, запись по
    устаревшему снимку теряла чужие правки;
  - единый слой: маршрут не переприменялся при смене своего списка,
    «^домен» из хостлиста уезжал в dnsmasq;
  - dnsmasq: мусорный «домен» в managed-файле ронял dnsmasq целиком;
  - DNS-маршрутизация: удаление последнего правила не очищало файл.
"""

import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock


class _Cfg:
    """Минимальный config manager для модулей с get(key, default)."""

    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, *keys, default=None):
        cur = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    def set(self, *args):
        *keys, value = args
        cur = self.data
        for k in keys[:-1]:
            cur = cur.setdefault(k, {})
        cur[keys[-1]] = value

    def save(self):
        return True


# ─────────────────────────── хостлисты ───────────────────────────────

class TestHostlistNormalize(unittest.TestCase):

    def setUp(self):
        from core.hostlist_manager import HostlistManager
        self.hm = HostlistManager()

    def test_punycode_tld_kept(self):
        # Дефолтные исключения .рф выпадали при сохранении списка из GUI.
        from core.hostlist_manager import DEFAULT_NETROGAT
        dropped = [d for d in DEFAULT_NETROGAT if not self.hm.normalize_domain(d)]
        self.assertEqual(dropped, [])

    def test_cyrillic_to_punycode(self):
        self.assertEqual(self.hm.normalize_domain("Пример.РФ"),
                         "xn--e1afmkfd.xn--p1ai")

    def test_wildcard_becomes_plain_domain(self):
        # nfqws2 не знает «*.»: запись сравнивалась буквально и не работала.
        self.assertEqual(self.hm.normalize_domain("*.example.com"), "example.com")
        self.assertEqual(self.hm.normalize_domain(".example.com"), "example.com")

    def test_strict_prefix_kept(self):
        self.assertEqual(self.hm.normalize_domain("^example.com"), "^example.com")
        # www в строгой записи не срезается — имя точное.
        self.assertEqual(self.hm.normalize_domain("^www.example.com"),
                         "^www.example.com")
        self.assertEqual(self.hm.normalize_domain("www.example.com"), "example.com")

    def test_garbage_rejected(self):
        for bad in ("a..b", "-x.com", "bad domain.com", "x_y.com", ""):
            self.assertIsNone(self.hm.normalize_domain(bad), bad)


class TestHostlistFiles(unittest.TestCase):

    def setUp(self):
        from core.hostlist_manager import HostlistManager
        self.tmp = tempfile.mkdtemp()
        self.hm = HostlistManager()
        self._p = [
            mock.patch.object(HostlistManager, "lists_path",
                              new_callable=mock.PropertyMock,
                              return_value=self.tmp),
            mock.patch("core.nfqws_reload.reload_lists"),
        ]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_saved_file_readable_by_nfqws_user(self):
        # nfqws2 перечитывает хостлист уже от --user=nobody: 0600 от
        # mkstemp сделал бы список невидимым после первого сохранения.
        self.assertTrue(self.hm.save_hostlist("mylist", ["a.com"]))
        mode = stat.S_IMODE(os.stat(os.path.join(self.tmp, "mylist.txt")).st_mode)
        self.assertEqual(mode, 0o644)
        # Временных файлов не остаётся.
        self.assertEqual(sorted(os.listdir(self.tmp)), ["mylist.txt"])

    def test_remove_by_url_form(self):
        self.hm.save_hostlist("mylist", ["example.com", "b.com"])
        self.assertEqual(self.hm.remove_domains(
            "mylist", ["https://www.example.com/path"]), 1)
        self.assertEqual(self.hm.get_hostlist("mylist"), ["b.com"])

    def test_import_rejects_non_http_url(self):
        # urllib понимает file:// — это чтение файлов роутера через API.
        with mock.patch("urllib.request.urlopen") as uo:
            self.assertEqual(self.hm.import_from_url(
                "mylist", "file:///etc/passwd"), -1)
            uo.assert_not_called()

    def test_save_notifies_unified(self):
        with mock.patch("core.unified.manager.notify_list_changed") as n:
            self.hm.save_hostlist("mylist", ["a.com"])
            self.hm.save_hostlist("unified_route_x", ["a.com"])
        n.assert_called_once_with("hl:mylist")


# ───────────────────────────── ipset ─────────────────────────────────

class TestIpsetValidate(unittest.TestCase):

    def test_canonical_forms(self):
        from core.ipset_manager import validate_ip_entry as v
        self.assertEqual(v("2001:DB8::/32"), "2001:db8::/32")
        self.assertEqual(v("10.0.0.1/8"), "10.0.0.0/8")
        self.assertEqual(v("1.2.3.4/32"), "1.2.3.4")
        self.assertEqual(v("::ffff:1.2.3.4"), "::ffff:1.2.3.4")

    def test_rejects_what_nfqws2_drops(self):
        # inet_pton в nfq2/ipset.c отбрасывает их молча («bad ip»).
        from core.ipset_manager import validate_ip_entry as v
        for bad in (":::", "01.2.3.4", "1.2.3.4/33", "::1/129",
                    "fe80::1%eth0", "1.2.3.4 x"):
            self.assertIsNone(v(bad), bad)


# ───────────────────────────── blob'ы ────────────────────────────────

class TestUserBlobs(unittest.TestCase):

    def setUp(self):
        from core import blob_registry
        from core.blob_manager import BlobManager
        self.tmp = tempfile.mkdtemp()
        self.cfg = _Cfg({"zapret": {"base_path": self.tmp,
                                    "bin_path": os.path.join(self.tmp, "fake")}})
        self._p = mock.patch("core.config_manager.get_config_manager",
                             return_value=self.cfg)
        self._p.start()
        self.bm = BlobManager()
        self.bm.blobs_dir = os.path.join(self.tmp, "blobs")
        self.bm.system_blobs_dir = os.path.join(self.tmp, "fake")
        os.makedirs(self.bm.blobs_dir, exist_ok=True)
        os.makedirs(self.bm.system_blobs_dir, exist_ok=True)
        self._pbm = mock.patch("core.blob_manager.get_blob_manager",
                               return_value=self.bm)
        self._pbm.start()
        blob_registry.reload_registry()

    def tearDown(self):
        from core import blob_registry
        self._pbm.stop()
        self._p.stop()
        blob_registry.reload_registry()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_name_must_be_identifier(self):
        # nfqws2: item_name() → is_identifier(), иначе «bad identifier»
        # и выход при старте.
        for bad in ("my-fake", "my.bin", "1abc"):
            ok, err = self.bm.save_blob(bad, b"\x16\x03\x01")
            self.assertFalse(ok, bad)
        ok, err = self.bm.save_blob("my_fake", b"\x16\x03\x01")
        self.assertTrue(ok, err)

    def test_user_blob_gets_declaration(self):
        from core.blob_registry import build_blob_declarations, list_blobs
        self.bm.save_blob("my_fake", b"\x16\x03\x01")
        decls = build_blob_declarations(["--lua-desync=fake:blob=my_fake"])
        self.assertEqual(decls, ["--blob=my_fake:@%s"
                                 % os.path.join(self.bm.blobs_dir, "my_fake")])
        kinds = {b["name"]: b["kind"] for b in list_blobs()}
        self.assertEqual(kinds.get("my_fake"), "user")

    def test_catalog_name_wins_over_user_file(self):
        from core.blob_registry import get_blob_value
        self.bm.save_blob("tls_google", b"\x16\x03\x01")
        self.assertTrue(get_blob_value("tls_google").startswith("@bin/"))

    def test_system_file_shows_strategy_name(self):
        # Страница показывала имя файла и советовала писать его в blob=.
        path = os.path.join(self.bm.system_blobs_dir,
                            "tls_clienthello_www_google_com.bin")
        with open(path, "wb") as f:
            f.write(b"\x16\x03\x01")
        rows = {b["name"]: b for b in self.bm.get_blobs()}
        self.assertIn("tls_google",
                      rows["tls_clienthello_www_google_com.bin"]["refs"])

    def test_generate_cyrillic_domain(self):
        data = self.bm.generate_fake_tls("пример.рф")
        self.assertIn(b"xn--e1afmkfd.xn--p1ai", data)


# ─────────────────────────── named-lists ─────────────────────────────

class TestNamedListsReview(unittest.TestCase):

    def setUp(self):
        self.cfg = _Cfg()
        self._p = mock.patch("core.named_lists.get_config_manager",
                             return_value=self.cfg)
        self._p.start()
        self._n = mock.patch("core.unified.manager.notify_list_changed")
        self.notify = self._n.start()

    def tearDown(self):
        self._n.stop()
        self._p.stop()

    def test_hosts_format_does_not_add_loopback(self):
        from core import named_lists as nl
        parsed = nl.parse_entries("0.0.0.0 ads.example.com\n"
                                  "127.0.0.1 tracker.example.org")
        self.assertEqual(parsed["cidrs"], [])
        self.assertEqual(parsed["domains"],
                         ["ads.example.com", "tracker.example.org"])

    def test_wildcard_and_idn(self):
        from core import named_lists as nl
        self.assertEqual(nl.classify_entry("*.example.com"),
                         ("domain", "example.com"))
        self.assertEqual(nl.classify_entry("пример.рф"),
                         ("domain", "xn--e1afmkfd.xn--p1ai"))

    def test_add_entries_and_notify(self):
        from core import named_lists as nl
        lid = nl.create("L", entries="a.com")["list"]["id"]
        self.notify.reset_mock()
        res = nl.add_entries(lid, ["b.com", "a.com"])
        self.assertEqual(res["added"], 1)
        self.assertEqual(nl.get(lid)["domains"], ["a.com", "b.com"])
        self.notify.assert_called_once_with(lid)

    def test_bookkeeping_fields_do_not_notify(self):
        from core import named_lists as nl
        lid = nl.create("L", entries="a.com")["list"]["id"]
        self.notify.reset_mock()
        nl.update_fields(lid, {"last_refresh": 1})
        self.notify.assert_not_called()

    def test_rename_keeps_names_unique(self):
        from core import named_lists as nl
        nl.create("A")
        lid = nl.create("B")["list"]["id"]
        self.assertFalse(nl.update(lid, name="A")["ok"])

    def test_refresh_merges_into_fresh_content(self):
        # Пока шло скачивание, детектор дописал домен: запись по снимку
        # из начала refresh_one его затирала.
        from core import named_lists as nl
        from core import list_updater as lu
        lid = nl.create("L", source_url="https://x/l.lst")["list"]["id"]

        def fetch(url, transport=""):
            nl.add_entries(lid, ["manual.com"])
            return "remote.com\n"

        with mock.patch.object(lu, "_fetch", side_effect=fetch):
            r = lu.refresh_one(lid)
        self.assertTrue(r["ok"], r)
        self.assertEqual(sorted(nl.get(lid)["domains"]),
                         ["manual.com", "remote.com"])


# ─────────────────────────── единый слой ─────────────────────────────

class TestUnifiedReapplyOnListChange(unittest.TestCase):

    def test_only_routes_using_list_are_reapplied(self):
        from core.unified import manager
        from core.unified.model import UnifiedRoute
        r1 = UnifiedRoute(name="a", destination={"list_ids": ["list-1"]},
                          method="awg:wg0")
        r2 = UnifiedRoute(name="b", destination={"list_ids": ["hl:other"]},
                          method="awg:wg0")
        r3 = UnifiedRoute(name="c", destination={"list_ids": ["list-1"]},
                          method="awg:wg0", enabled=False)
        with mock.patch("core.unified.storage.load_routes",
                        return_value=[r1, r2, r3]), \
             mock.patch("core.unified.applier.apply_route",
                        return_value={"ok": True}) as ap:
            res = manager.reapply_routes_for({"list-1"})
        self.assertEqual([c.args[0].id for c in ap.call_args_list], [r1.id])
        self.assertTrue(res["ok"])

    def test_notify_is_debounced(self):
        from core.unified import manager
        with mock.patch.object(manager, "AUTO_REAPPLY", True), \
             mock.patch.object(manager, "REAPPLY_DELAY_SEC", 0.05), \
             mock.patch.object(manager, "reapply_routes_for") as rr:
            manager.notify_list_changed("list-1")
            manager.notify_list_changed("hl:x")
            t = manager._pending_timer
            t.join(2)
        rr.assert_called_once_with({"list-1", "hl:x"})

    def test_hostlist_syntax_stripped_for_routing(self):
        from core.unified.model import Destination
        hm = mock.MagicMock()
        hm.get_hostlist.return_value = ["^exact.com", "*.wild.com",
                                        "plain.com"]
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm):
            res = Destination(list_ids=["hl:x"]).resolve()
        self.assertEqual(res["domains"], ["exact.com", "wild.com", "plain.com"])


# ─────────────────────────── dnsmasq ────────────────────────────────

class TestDnsmasqManagedFile(unittest.TestCase):

    def test_garbage_domains_dropped(self):
        # Одна кривая строка — и dnsmasq не стартует, а с ним DHCP/DNS.
        from core.routing import dnsmasq_integration as di
        tmp = tempfile.mkdtemp()
        try:
            mgr = di.DnsmasqIntegration()
            with mock.patch.object(mgr, "find_main_config", return_value=""), \
                 mock.patch.object(mgr, "managed_file_path",
                                   return_value=os.path.join(tmp, "m.conf")):
                res = mgr.write_managed_file([{
                    "rule_id": "r1", "set_kind": "ipset", "set_name": "s",
                    "domains": ["ok.com", "bad dom.com", "a/b.com",
                                "x.com\nserver=/evil/1.2.3.4", "*.w.com"],
                }])
            self.assertTrue(res["ok"])
            with open(os.path.join(tmp, "m.conf")) as f:
                text = f.read()
            self.assertIn("ipset=/ok.com/w.com/s,s6", text)
            self.assertNotIn("evil", text)
            self.assertNotIn("bad dom", text)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────── DNS-маршрутизация ───────────────────────────

class TestDnsRoutingReview(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = _Cfg({"zapret": {"base_path": self.tmp},
                         "dns_routing": {"rules": [
                             {"domain": "a.com", "dns": "cloudflare",
                              "enabled": True}]}})
        self._p = mock.patch("core.config_manager.get_config_manager",
                             return_value=self.cfg)
        self._p.start()

    def tearDown(self):
        self._p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_last_rule_removal_clears_file(self):
        from core.dns_routing import DnsRoutingManager
        mgr = DnsRoutingManager()
        with mock.patch("core.routing.dnsmasq_integration."
                        "DnsmasqIntegration.find_main_config",
                        return_value=""):
            mgr.apply()
            path = mgr._conf_path()
            with open(path) as f:
                self.assertIn("server=/a.com/1.1.1.1", f.read())
            mgr.remove_rule("a.com")
            mgr.apply()
            with open(path) as f:
                self.assertNotIn("server=", f.read())

    def test_comss_is_not_quad9(self):
        from core.dns_routing import DNS_SERVERS
        self.assertNotEqual(DNS_SERVERS["comss"]["ip"], "9.9.9.10")


class TestDiagnosticsHost(unittest.TestCase):

    def test_leading_dash_rejected(self):
        from api.diagnostics import _validate_host
        self.assertFalse(_validate_host("-f"))
        self.assertTrue(_validate_host("youtube.com"))
        from core.diagnostics import ping_host
        with mock.patch("core.diagnostics._run") as run:
            ping_host("-s65000")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
