# tests/test_dns_bench_leak.py
"""
Замер DNS-серверов и автовыбор (core/dns_bench) и проверка утечек IP и
DNS (core/leak_check): разбор DNS-пакетов, выбор лучшего, подмена,
сервер «auto» в правилах, итог проверки утечек без ложного «всё
хорошо».
"""

import socket
import struct
import unittest
from unittest import mock

from core import dns_bench as db
from core import leak_check as lc


def _answer(qid, ips, rcode=0, compress=True):
    q = db.build_query("example.com", qid)
    head = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(ips), 0, 0)
    body = q[12:]
    for ip in ips:
        name = b"\xc0\x0c" if compress else \
            b"\x07example\x03com\x00"
        body += name + struct.pack(">HHIH", 1, 1, 60, 4) \
            + socket.inet_aton(ip)
    return head + body


class TestWire(unittest.TestCase):
    def test_query_layout(self):
        q = db.build_query("ya.ru", 0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x02ya\x02ru\x00", q)
        self.assertEqual(q[-4:], b"\x00\x01\x00\x01")

    def test_bad_name(self):
        with self.assertRaises(ValueError):
            db.build_query("a" * 64 + ".ru", 1)

    def test_parse_answer_with_and_without_compression(self):
        for comp in (True, False):
            rcode, ips = db.parse_response(
                _answer(7, ["1.2.3.4", "5.6.7.8"], compress=comp), 7)
            self.assertEqual((rcode, ips), (0, ["1.2.3.4", "5.6.7.8"]))

    def test_foreign_id_rejected(self):
        with self.assertRaises(ValueError):
            db.parse_response(_answer(7, ["1.2.3.4"]), 8)

    def test_nxdomain(self):
        self.assertEqual(db.parse_response(_answer(3, [], rcode=3), 3),
                         (3, []))

    def test_truncated(self):
        with self.assertRaises(ValueError):
            db.parse_response(_answer(7, ["1.2.3.4"])[:-6], 7)


class TestPickBest(unittest.TestCase):
    def row(self, sid, ok, ms, spoofed=False, total=6):
        return {"id": sid, "udp": {"ok": ok, "total": total, "ms": ms},
                "spoofed": spoofed}

    def test_fastest_honest_wins(self):
        rows = [self.row("system", 6, 1), self.row("google", 6, 30),
                self.row("cloudflare", 6, 20, spoofed=True),
                self.row("quad9", 6, 25), self.row("yandex", 3, 5)]
        self.assertEqual(db.pick_best(rows), "quad9")

    def test_nothing_eligible(self):
        rows = [self.row("google", 0, None), self.row("adguard", 6, 9,
                                                      spoofed=True)]
        self.assertEqual(db.pick_best(rows), "")

    def test_unchecked_spoof_is_disqualifying(self):
        # Не с чем сравнить — честность не доказана, «auto» не трогаем.
        self.assertEqual(db.pick_best([self.row("google", 6, 9,
                                                spoofed=None)]), "")


class TestSpoof(unittest.TestCase):
    def check(self, answer, reference=("195.82.146.214",)):
        with mock.patch.object(db, "udp_query", return_value=answer):
            return db._spoofed("8.8.8.8", list(reference))

    def test_stub_private(self):
        self.assertTrue(self.check((1, 0, ["10.0.0.1"])))

    def test_nxdomain(self):
        self.assertTrue(self.check((1, 3, [])))

    def test_public_stub(self):
        self.assertTrue(self.check((1, 0, ["93.158.134.3"])))

    def test_honest(self):
        self.assertFalse(self.check((1, 0, ["195.82.146.214"])))

    def test_no_reference(self):
        self.assertIsNone(self.check((1, 0, ["1.1.1.1"]), reference=()))


class TestBenchLock(unittest.TestCase):
    def test_lock_held_until_slow_server_finishes(self):
        gate = __import__("threading").Event()

        def slow(c, ref):
            gate.wait(5)
            return dict(c, udp=None, doh=None, dot=None, spoofed=None)

        with mock.patch.object(db, "candidates", return_value=[
                {"id": "google", "name": "G", "ip": "8.8.8.8", "doh": "",
                 "dot": ""}]), \
                mock.patch.object(db, "_reference", return_value=[]), \
                mock.patch.object(db, "_bench_one", side_effect=slow), \
                mock.patch.object(db, "TIMEOUT", 0), \
                mock.patch.object(db, "DEADLINE_PAD", 0.2), \
                mock.patch.object(db, "ROUNDS", 0):
            r = db.benchmark()
            self.assertEqual(r["rows"][0]["error"], "не успел")
            self.assertFalse(db.benchmark()["ok"])      # ещё занято
            gate.set()
            for _ in range(50):
                if not db._run_lock.locked():
                    break
                __import__("time").sleep(0.05)
        self.assertFalse(db._run_lock.locked())


class TestSystemNameserver(unittest.TestCase):
    def test_first_ipv4(self):
        self.assertEqual(db.system_nameserver(["::1", "127.0.0.1"]),
                         "127.0.0.1")
        self.assertEqual(db.system_nameserver([]), "")


class FakeCfg:
    def __init__(self, data):
        self.data = data
        self.saved = 0

    def get(self, *keys, default=None):
        node = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def set(self, *path):
        *keys, value = path
        node = self.data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value

    def save(self):
        self.saved += 1
        return True


class TestAutoselect(unittest.TestCase):
    def setUp(self):
        self.cfg = FakeCfg({"dns_routing": {"rules": [
            {"domain": "x.com", "dns": "auto", "enabled": True}],
            "auto_server": "google"}})
        p = mock.patch.object(db, "_cfg", return_value=self.cfg)
        p.start()
        self.addCleanup(p.stop)

    def test_change_rebuilds_rules(self):
        mgr = mock.Mock()
        mgr.apply.return_value = {"ok": True}
        with mock.patch.object(db, "benchmark", return_value={
                "ok": True, "best": "quad9", "rows": [1]}), \
                mock.patch("core.dns_routing.get_dns_routing_manager",
                           return_value=mgr):
            r = db.autoselect()
        self.assertTrue(r["ok"] and r["changed"])
        self.assertEqual(r["previous"], "google")
        self.assertEqual(self.cfg.data["dns_routing"]["auto_server"],
                         "quad9")
        mgr.apply.assert_called_once()

    def test_same_best_no_apply(self):
        mgr = mock.Mock()
        with mock.patch.object(db, "benchmark", return_value={
                "ok": True, "best": "google", "rows": [1]}), \
                mock.patch("core.dns_routing.get_dns_routing_manager",
                           return_value=mgr):
            r = db.autoselect()
        self.assertFalse(r["changed"])
        mgr.apply.assert_not_called()

    def test_no_best_keeps_previous(self):
        with mock.patch.object(db, "benchmark", return_value={
                "ok": True, "best": "", "rows": [1], "hint": "нет"}):
            r = db.autoselect()
        self.assertFalse(r["ok"])
        self.assertEqual(self.cfg.data["dns_routing"]["auto_server"],
                         "google")

    def test_tick_only_with_auto_rules_and_when_stale(self):
        with mock.patch.object(db, "autoselect",
                               return_value={"ok": True}) as a, \
                mock.patch("core.reachability.wan_down",
                           return_value=False):
            self.cfg.data["dns_routing"]["auto_server_at"] = 1000
            self.assertEqual(db.tick(now=1000 + 3600)["action"], "fresh")
            self.assertEqual(db.tick(now=1000 + 25 * 3600)["action"],
                             "bench")
            self.cfg.data["dns_routing"]["rules"] = []
            self.assertEqual(db.tick(now=10 ** 9)["action"], "off")
        self.assertEqual(a.call_count, 1)

    def test_failed_bench_waits_before_retry(self):
        db._tried_at = 0.0
        self.addCleanup(setattr, db, "_tried_at", 0.0)
        with mock.patch.object(db, "autoselect",
                               return_value={"ok": False}) as a, \
                mock.patch("core.reachability.wan_down",
                           return_value=False):
            now = 10 ** 9
            self.assertEqual(db.tick(now=now)["action"], "bench")
            self.assertEqual(db.tick(now=now + 600)["action"],
                             "retry_later")
            self.assertEqual(db.tick(now=now + db.RETRY_SEC)["action"],
                             "bench")
        self.assertEqual(a.call_count, 2)

    def test_tick_waits_for_wan(self):
        with mock.patch.object(db, "autoselect") as a, \
                mock.patch("core.reachability.wan_down",
                           return_value=True):
            self.assertEqual(db.tick(now=10 ** 9)["action"], "wan_down")
        a.assert_not_called()


class TestDnsRoutingAuto(unittest.TestCase):
    def test_auto_resolves_to_best_or_fallback(self):
        from core import dns_routing as dr
        mgr = dr.DnsRoutingManager()
        cfg = FakeCfg({"dns_routing": {"auto_server": "quad9"}})
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg):
            self.assertEqual(mgr._resolve_server("auto"), "9.9.9.9")
            cfg.data["dns_routing"]["auto_server"] = "bogus"
            self.assertEqual(mgr._resolve_server("auto"), "1.1.1.1")
            servers = mgr.get_available_servers()
        # «Авто» последним: первый пункт — выбор по умолчанию в GUI.
        self.assertEqual(servers[-1]["id"], "auto")

    def test_auto_accepted_in_rules(self):
        from core import dns_routing as dr
        cfg = FakeCfg({"dns_routing": {"rules": []}})
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cfg):
            r = dr.DnsRoutingManager().add_rule("x.com", "auto")
            b = dr.DnsRoutingManager().add_rules_batch(
                [{"domain": "y.com", "dns": "auto"}])
        self.assertTrue(r["ok"])
        self.assertEqual(b["added"], 1)


class TestLeakParse(unittest.TestCase):
    def test_parse_ip(self):
        self.assertEqual(lc.parse_ip('{"ip":"1.2.3.4"}'), "1.2.3.4")
        self.assertEqual(lc.parse_ip("2001:db8::1\n"), "2001:db8::1")
        self.assertEqual(lc.parse_ip("<html>"), "")

    def test_parse_report(self):
        r = lc.parse_dns_report([
            {"ip": "5.5.5.5", "country_name": "Russia", "asn": "AS1",
             "type": "ip"},
            {"ip": "6.6.6.6", "country_name": "Russia", "asn": "AS1",
             "type": "dns"},
            {"ip": "", "type": "dns"},
            {"type": "conclusion", "ip": "x"}, "мусор"])
        self.assertEqual(r["ip"]["asn"], "AS1")
        self.assertEqual([d["ip"] for d in r["dns"]], ["6.6.6.6"])
        self.assertEqual(lc.parse_dns_report({"x": 1}),
                         {"ip": None, "dns": []})


class TestLeakEvaluate(unittest.TestCase):
    DNS_OK = {"ok": True, "ip": {"asn": "AS1"},
              "dns": [{"ip": "8.8.8.8", "country": "US", "asn": "AS15169"}]}

    def test_all_clean(self):
        r = lc.evaluate({"ok": True, "ip": "5.5.5.5"},
                        [{"id": "awg:wg0", "ok": True, "ip": "9.9.9.1"}],
                        self.DNS_OK)
        self.assertEqual(r["level"], "ok")
        self.assertTrue(r["complete"])

    def test_same_ip_through_tunnel(self):
        r = lc.evaluate({"ok": True, "ip": "5.5.5.5"},
                        [{"id": "awg:wg0", "ok": True, "ip": "5.5.5.5"}],
                        self.DNS_OK)
        self.assertEqual(r["level"], "warn")

    def test_isp_resolver(self):
        dns = {"ok": True, "ip": {"asn": "AS1"},
               "dns": [{"ip": "6.6.6.6", "country": "RU", "asn": "AS1"}]}
        r = lc.evaluate({"ok": True, "ip": "5.5.5.5"}, [], dns)
        self.assertEqual(r["level"], "warn")

    def test_tunnel_without_direct_is_not_clean(self):
        r = lc.evaluate({"ok": False, "error": "x"},
                        [{"id": "awg:wg0", "ok": True, "ip": "9.9.9.1"}],
                        self.DNS_OK)
        self.assertEqual(r["level"], "incomplete")
        self.assertEqual(r["findings"][1]["status"], "unknown")

    def test_partial_is_never_ok(self):
        r = lc.evaluate({"ok": True, "ip": "5.5.5.5"}, [],
                        {"ok": False, "error": "bash.ws недоступен"})
        self.assertEqual(r["level"], "incomplete")
        self.assertFalse(r["complete"])
        r = lc.evaluate({"ok": True, "ip": "5.5.5.5"},
                        [{"id": "awg:wg0", "ok": False, "error": "x"}],
                        self.DNS_OK)
        self.assertEqual(r["level"], "incomplete")


class TestLeakRun(unittest.TestCase):
    def test_run_wires_parts(self):
        ips = {"": "5.5.5.5", "awg:wg0": "7.7.7.7"}
        with mock.patch.object(lc, "_tunnels", return_value=[
                {"id": "awg:wg0", "kind": "awg", "label": "AWG wg0"}]), \
                mock.patch.object(lc, "external_ip",
                                  side_effect=lambda t="": {
                                      "ok": True, "ip": ips[t]}), \
                mock.patch.object(lc, "dns_leak",
                                  return_value=TestLeakEvaluate.DNS_OK):
            r = lc.run()
        self.assertEqual(r["level"], "ok")
        self.assertEqual(lc.last()["ts"], r["ts"])

    def test_dns_leak_resolves_names(self):
        calls = []

        def fake_get(url, transport=""):
            calls.append(url)
            if url.endswith("/id"):
                return "12345\n"
            return '[{"ip":"8.8.8.8","type":"dns","asn":"AS15169"}]'

        with mock.patch.object(lc, "_get", side_effect=fake_get), \
                mock.patch.object(lc, "_resolve") as res:
            r = lc.dns_leak()
        self.assertTrue(r["ok"])
        self.assertEqual(res.call_count, lc.NAMES)
        self.assertIn("1.12345.bash.ws", res.call_args_list[0][0])
        self.assertTrue(calls[-1].endswith("/dnsleak/test/12345?json"))

    def test_dns_leak_bad_id(self):
        with mock.patch.object(lc, "_get", return_value="<html>"):
            self.assertFalse(lc.dns_leak()["ok"])


class TestMcpMask(unittest.TestCase):
    def test_ip_masked_without_secrets(self):
        from core.mcp.tools import diagnostics as d
        with mock.patch.object(d.perms_mod, "granted", return_value=False), \
                mock.patch.object(lc, "run", return_value={
                    "ok": True, "findings": [
                        {"id": "ip_direct", "status": "ok",
                         "detail": "5.6.7.8"},
                        {"id": "ip_tunnel", "status": "warning",
                         "detail": "тот же IP, что напрямую (5.6.7.8)"}],
                    "isp": {"ip": "5.6.7.8", "asn": "AS1"}}):
            r = d.leak_check({})
        self.assertEqual(r["findings"][0]["detail"], "5.6.7.x")
        self.assertIn("5.6.7.x", r["findings"][1]["detail"])
        self.assertEqual(r["isp"]["ip"], "5.6.7.x")

    def test_mask_does_not_leak_into_stored_result(self):
        from core.mcp.tools import diagnostics as d
        lc._last.clear()
        lc._last.update({"ok": True, "ts": 1, "findings": [
            {"id": "ip_direct", "status": "ok", "detail": "5.6.7.8"}]})
        self.addCleanup(lc._last.clear)
        with mock.patch.object(d.perms_mod, "granted", return_value=False):
            d.leak_check({"fresh": False})
        self.assertEqual(lc.last()["findings"][0]["detail"], "5.6.7.8")

    def test_autoselect_without_result_needs_probes(self):
        from core.mcp.tools import diagnostics as d
        with mock.patch.object(d.perms_mod, "granted", return_value=False), \
                mock.patch.object(db, "has_result", return_value=False), \
                mock.patch.object(db, "autoselect") as a:
            r = d.dns_autoselect({"fresh": False})
        self.assertEqual(r.get("permission"), "probes")
        a.assert_not_called()

    def test_autoselect_needs_probes_for_fresh(self):
        from core.mcp.tools import diagnostics as d
        with mock.patch.object(d.perms_mod, "granted", return_value=False):
            r = d.dns_autoselect({})
        self.assertEqual(r.get("permission"), "probes")


if __name__ == "__main__":
    unittest.main()
