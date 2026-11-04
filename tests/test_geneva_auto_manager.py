# tests/test_geneva_auto_manager.py
"""
Менеджер режима «Авто» geneva (core/geneva_auto_manager.py) и его связь
с движками (core/bypass_engine.py, core/geneva_manager.py).

Без root и сети: наблюдение, пробы, подбор и процессы — фейки; Applier
настоящий (над фейками geneva и firewall), чтобы проверить, что
стратегия ложится только на адреса своего сервиса.
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import geneva_auto as ga
from core import geneva_auto_apply as ap
from core import geneva_auto_manager as am
from core import geneva_auto_search as gs
from tests.test_geneva_auto_fw import FakeFW, FakeGM
from tests.test_geneva_manager import _StubCase

DNS_IP = "93.184.216.53"
STRAT = "[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/"


def dns_fail(t, i=0):
    return ga.Sample(key="dns:" + DNS_IP, kind=ga.DNS, transport="udp",
                     name="DNS " + DNS_IP, app="dns", ip=DNS_IP, port=53,
                     local_port=41000 + i, client="192.168.1.10", time=t,
                     health=ga.FAILED, why="запросы без ответа")


def web_ok(t):
    return ga.Sample(key="web:ok.example", kind=ga.WEB, transport="tcp",
                     name="ok.example", app="tls", ip="93.184.216.80",
                     port=443, client="192.168.1.10", time=t,
                     health=ga.OK, host="www.ok.example")


class FakeObserver:
    def __init__(self):
        self.slices = []
        self.last_stats = {}
        self.restored = 0
        self.exclude = None
        self.identify_calls = []
        self.done = []
        self.busy = False

    def check(self):
        return {"source": "fake"}

    def enable_accounting(self):
        return {"nf_conntrack_acct": True, "nf_conntrack_timestamp": True}

    def restore(self):
        self.restored += 1

    def set_exclude(self, ips):
        self.exclude = list(ips)

    def seed_keys(self, keys):
        self.seeded = list(keys)

    def slice(self, now=None):
        samples = self.slices.pop(0) if self.slices else []
        self.last_stats = {"connections": 40, "observed": len(samples)}
        return samples

    def identify_async(self, *a, **kw):
        self.identify_calls.append((a, kw))
        return True

    def identified(self):
        out, self.done = self.done, []
        return out


class FakeProbes:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def check(self, s, through_bypass=False):
        self.calls.append((s.key, through_bypass))
        return self.answers.get(s.key, (ga.C_BLOCKED, "сброс"))


class FakeSearch:
    def __init__(self, outcome=gs.APPLIED, strategy=STRAT):
        self.outcome = outcome
        self.strategy = strategy
        self.started = []
        self._result = None
        self.workers = 0
        self.cancelled = 0

    @property
    def busy(self):
        return False

    def start(self, s, running=()):
        self.started.append((s.key, list(running)))
        self._result = gs.SearchResult(s.key, self.outcome,
                                       strategy=self.strategy, fitness=396)
        return True

    def result(self):
        out, self._result = self._result, None
        return out

    def cancel(self, wait=0):
        self.cancelled += 1

    def progress(self):
        return {}


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        saved = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self.tmp)
        cm_mod._config_manager.load()
        self.addCleanup(setattr, cm_mod, "_config_manager", saved)
        self.cfg = cm_mod._config_manager
        self.cfg.set("bypass", "engine", "geneva")
        self.cfg.save()
        self.path = os.path.join(self.tmp, "auto.json")
        self.obs = FakeObserver()
        self.probes = FakeProbes()
        self.search = FakeSearch()
        self.gmf = FakeGM()
        self.fwf = FakeFW()
        self.applier = ap.Applier(geneva=self.gmf, fw=self.fwf)
        self.gm = mock.Mock()
        self.gm.detect.return_value = {"installed": True, "proto_ok": True}
        self.gm.is_running.return_value = False
        self.clock = [100.0]

    def manager(self):
        return am.GenevaAutoManager(
            observer=self.obs, probes=self.probes, search=self.search,
            applier=self.applier, geneva=self.gm, cfg=self.cfg,
            clock=lambda: self.clock[0], path=self.path)


class TestScenario(_Base):

    def test_blocked_resolver_end_to_end(self):
        m = self.manager()
        m.load()
        self.obs.slices = [[dns_fail(95, i) for i in range(3)] +
                           [web_ok(96)], [], []]
        # срез: подозрение → проба без обхода → блок → подбор
        m.tick(100.0)
        s = m.book.find("dns:" + DNS_IP)
        self.assertEqual(self.probes.calls, [("dns:" + DNS_IP, False)])
        self.assertEqual(s.status, ga.SEARCHING)
        self.assertEqual(self.search.started[0][0], "dns:" + DNS_IP)
        # переход сохранён сразу
        saved = json.load(open(self.path))
        self.assertEqual({x["key"]: x["status"] for x in saved["services"]}
                         ["dns:" + DNS_IP], ga.SEARCHING)

        # следующий срез: итог подбора → применение на адреса резолвера
        m.tick(115.0)
        s = m.book.find("dns:" + DNS_IP)
        self.assertEqual((s.status, s.strategy), (ga.APPLIED, STRAT))
        applied = self.fwf.applied[-1]
        self.assertEqual(len(applied), 1)
        group = list(applied.values())[0]
        self.assertEqual(group.strategy, STRAT)
        self.assertEqual(group.services, ["dns:" + DNS_IP])
        self.assertEqual(group.targets[0].addresses, [DNS_IP])
        self.assertEqual((group.targets[0].tcp_ports,
                          group.targets[0].udp_ports), ("53", "53"))
        self.assertEqual(self.gmf.groups, {340: STRAT})

        # состояние переживает перезапуск
        m2 = self.manager()
        m2.load()
        self.assertEqual(m2.book.find("dns:" + DNS_IP).status, ga.APPLIED)

        # выключение: группы и правила сняты, учёт возвращён
        st = m.status()
        self.assertEqual(st["groups"][0]["strategy"], STRAT)
        self.assertEqual([x["key"] for x in st["services"]],
                         ["dns:" + DNS_IP])          # без «работает»
        self.assertEqual(len(m.status(all_services=True)["services"]), 2)
        m.disable()
        self.assertEqual(self.fwf.removed, 1)
        self.assertTrue(self.gmf.stopped_all)
        self.assertEqual(self.obs.restored, 1)
        self.assertFalse(am.auto_settings(self.cfg)["enabled"])

    def test_found_from_book_and_db_even_when_off(self):
        m = self.manager()
        m.load()
        self.obs.slices = [[dns_fail(95, i) for i in range(3)], []]
        m.tick(100.0)
        m.tick(115.0)                        # применено, сохранено
        self.gm.db_top.return_value = {"ok": True, "items": [
            {"strategy": "[TCP:flags:PA]-fragment{tcp:-1:False}-| \\/",
             "target": "https:rutor.info", "ok": 3}]}
        self.cfg.set("geneva", "strategy", STRAT)
        fresh = self.manager()               # режим не запущен: из файла
        res = fresh.found()
        self.assertTrue(res["ok"])
        self.assertEqual(res["items"][0]["strategy"], STRAT)
        self.assertTrue(res["items"][0]["working"])
        self.assertEqual(res["items"][0]["services"][0]["key"],
                         "dns:" + DNS_IP)
        self.assertEqual(res["items"][1]["targets"], ["rutor.info"])
        self.gm.db_top.assert_called_with("", 50)

    def test_not_blocked_and_ip_blocked(self):
        m = self.manager()
        m.load()
        self.probes.answers = {"dns:" + DNS_IP: (ga.C_IP_BLOCKED, "нет")}
        self.obs.slices = [[dns_fail(95, i) for i in range(2)]]
        m.tick(100.0)
        self.assertEqual(m.book.find("dns:" + DNS_IP).status, ga.IP_BLOCKED)
        self.assertEqual(self.search.started, [])

    def test_not_found_and_busy(self):
        self.search.outcome = gs.NOT_FOUND
        m = self.manager()
        m.load()
        self.obs.slices = [[dns_fail(95, i) for i in range(2)], []]
        m.tick(100.0)
        m.tick(115.0)
        s = m.book.find("dns:" + DNS_IP)
        self.assertEqual(s.status, ga.NOT_FOUND)
        self.assertEqual(s.next_check, 115.0 + ga.HOUR)

        self.search.outcome = gs.BUSY
        m.reset("dns:" + DNS_IP)
        self.obs.slices = [[dns_fail(120, i) for i in range(2)], []]
        m.tick(130.0)
        m.tick(145.0)
        self.assertEqual(m.book.find("dns:" + DNS_IP).status, ga.BLOCKED)
        self.assertGreater(m._search_wait, 145.0)

    def test_unprobed_service_needs_two_slices(self):
        m = self.manager()
        m.load()
        wg = [ga.Sample(key="ep:wireguard:udp:93.184.216.20:51820",
                        kind=ga.ENDPOINT, transport="udp", name="WG",
                        app="wireguard", ip="93.184.216.20", port=51820,
                        time=95 + i, health=ga.FAILED, why="нет ответа")
              for i in range(2)]
        self.obs.slices = [wg, []]
        m.tick(100.0)
        self.assertEqual(m.book.services[0].status, ga.SUSPECTED)
        self.assertEqual(self.probes.calls, [])
        m.tick(100.0 + ga.UNKNOWN_RECHECK + 1)
        self.assertEqual(self.search.started[0][0], wg[0].key)

    def test_identify_unknown_endpoint(self):
        m = self.manager()
        m.load()
        ep = [ga.Sample(key="ep:udp:udp:93.184.216.20:1194",
                        kind=ga.ENDPOINT, transport="udp", name="UDP",
                        app="udp", ip="93.184.216.20", port=1194,
                        time=95 + i, health=ga.FAILED, why="нет ответа")
              for i in range(2)]
        self.obs.slices = [ep, []]
        m.tick(100.0)
        self.assertEqual(len(self.obs.identify_calls), 1)
        args, _kw = self.obs.identify_calls[0]
        self.assertEqual(args[:4], (ep[0].key, "93.184.216.20", 1194, "udp"))
        self.obs.done = [{"key": ep[0].key, "app": "openvpn",
                          "replay": [b"\x38abc"], "host": ""}]
        m.tick(115.0)
        s = m.book.find(ep[0].key)
        self.assertEqual(s.app, "openvpn")
        self.assertTrue(s.can_replay)
        self.assertEqual(len(self.obs.identify_calls), 1)   # не повторяет

    def test_trial_callback_and_ok_since(self):
        m = self.manager()
        m.load()
        self.obs.slices = [[web_ok(96)]]
        m.tick(100.0)
        self.assertTrue(m._ok_since("web:ok.example", 90))
        self.assertFalse(m._ok_since("web:ok.example", 97))
        m.book.feed([dns_fail(98)], 100.0)
        s = m.book.find("dns:" + DNS_IP)
        self.assertTrue(m._trial_cb(s, STRAT))
        group = self.fwf.applied[-1][340]
        self.assertEqual(group.services, ["dns:" + DNS_IP])
        self.assertTrue(m._trial_cb(s, None))
        self.assertEqual(self.fwf.applied[-1], {})

    def test_trial_is_part_of_applied_plan(self):
        m = self.manager()
        m.load()
        m.book.feed([dns_fail(98)], 100.0)
        s = m.book.find("dns:" + DNS_IP)
        self.assertTrue(m._trial_cb(s, STRAT))
        n = len(self.fwf.applied)
        m._apply(101.0)                    # тот же план с пробой — повтора нет
        self.assertEqual(len(self.fwf.applied), n)
        m._trial = None                    # проба снята мимо _trial_cb
        m._apply(102.0)                    # — план другой, применяется сразу
        self.assertEqual(len(self.fwf.applied), n + 1)
        self.assertEqual(self.fwf.applied[-1], {})

    def test_offload_warning(self):
        m = self.manager()
        m.load()
        self.obs.slices = [[web_ok(96)], [web_ok(110)]]
        m.tick(100.0)
        self.assertFalse(m.status()["offload"])
        self.obs.last_stats = {}
        orig = self.obs.slice

        def with_offload(now=None):
            out = orig(now)
            self.obs.last_stats["offload"] = 2
            return out
        self.obs.slice = with_offload
        m.tick(115.0)
        st = m.status()
        self.assertTrue(st["offload"])
        self.assertTrue(any("offloading" in j["text"] for j in m.journal))

    def test_trial_after_disable_does_not_reapply(self):
        m = self.manager()
        m.load()
        m.book.feed([dns_fail(98)], 100.0)
        s = m.book.find("dns:" + DNS_IP)
        m._stop.set()                      # режим выключается
        n = len(self.fwf.applied)
        self.assertFalse(m._trial_cb(s, None))
        self.assertFalse(m._trial_cb(s, STRAT))
        self.assertEqual(len(self.fwf.applied), n)

    def test_firewall_requirements_disable_mode(self):
        self.fwf.ok = False
        m = self.manager()
        m.load()
        m.book = ga.Book([ga.Service(
            key="dns:" + DNS_IP, kind=ga.DNS, transport="udp",
            status=ga.APPLIED, strategy=STRAT, applied_at=1,
            addresses=[{"ip": DNS_IP, "seen": 1}]).to_dict()])
        done = threading.Event()
        with mock.patch.object(m, "disable",
                               side_effect=lambda r: done.set()):
            m.tick(100.0)
            self.assertTrue(done.wait(5))
        self.assertIn("opkg", m.problems[0])

    def test_slice_error_backoff(self):
        m = self.manager()
        m.load()
        self.obs.slice = mock.Mock(side_effect=OSError("conntrack пропал"))
        stop = threading.Event()
        waits = []

        def wait(t):
            waits.append(t)
            if len(waits) >= 6:
                stop.set()
            return stop.is_set()

        stop.wait = wait
        stop.is_set = lambda: len(waits) >= 6
        m._loop(stop)
        self.assertEqual(waits[:6], [15.0, 30.0, 60.0, 120.0, 240.0, 300.0])
        self.assertEqual(m.phase, "error")
        self.assertIn("conntrack пропал", m.problems[0])

    def test_save_throttled(self):
        m = self.manager()
        m.load()
        self.obs.slices = [[web_ok(96)], [web_ok(97)], [web_ok(98)]]
        m.tick(100.0)
        first = os.path.getmtime(self.path)
        os.utime(self.path, (1, 1))
        self.clock[0] = 110.0
        m.tick(110.0)             # статусы те же: раньше минуты не пишем
        self.assertEqual(os.path.getmtime(self.path), 1)
        self.clock[0] = 170.0
        m.tick(170.0)
        self.assertNotEqual(os.path.getmtime(self.path), 1)
        del first

    def test_suspend_resume(self):
        m = self.manager()
        m.load()
        m._thread = mock.Mock(is_alive=lambda: True)
        self.assertTrue(m.suspend("scanner"))
        self.assertEqual(self.fwf.removed, 1)
        self.obs.slices = [[dns_fail(95, i) for i in range(3)]]
        m.tick(100.0)
        self.assertEqual(self.probes.calls, [])     # на паузе не пробует
        self.assertEqual(m.phase, "suspended")
        m.resume("scanner")
        self.assertEqual(m.suspended, "")


class TestEnable(_Base):

    def test_needs_confirm_to_switch_engine(self):
        self.cfg.set("bypass", "engine", "nfqws2")
        m = self.manager()
        with mock.patch("core.bypass_engine._nfqws_busy", return_value={}):
            r = m.enable()
        self.assertFalse(r["ok"])
        self.assertEqual(r["error_code"], "need_confirm")
        self.assertEqual(r["need_confirm"], ["engine"])
        self.assertFalse(m.running)

        def switch(target, start=True):
            self.cfg.set("bypass", "engine", target)
            return {"ok": True}

        with mock.patch("core.bypass_engine._nfqws_busy", return_value={}), \
                mock.patch("core.bypass_engine.switch",
                           side_effect=switch) as sw:
            r = m.enable(confirm=True)
        self.assertTrue(r["ok"], r)
        sw.assert_called_once_with("geneva", start=False)
        self.assertTrue(m.running)
        self.assertTrue(am.auto_settings(self.cfg)["enabled"])
        m.disable()
        self.assertFalse(m.running)

    def test_refused_when_nfqws_busy_or_no_conntrack(self):
        m = self.manager()
        with mock.patch("core.bypass_engine._nfqws_busy",
                        return_value={"reason": "идёт сканер"}):
            r = m.enable(confirm=True)
        self.assertEqual(r["error_code"], "busy")
        from core.geneva_auto_observer import ObserverError
        self.obs.check = mock.Mock(side_effect=ObserverError(
            "conntrack_tool_missing", "нет conntrack", "opkg install "
            "conntrack"))
        with mock.patch("core.bypass_engine._nfqws_busy", return_value={}):
            r = m.enable(confirm=True)
        self.assertEqual(r["error_code"], "conntrack_tool_missing")
        self.assertIn("opkg", r["hint"])
        self.assertFalse(m.running)

    def test_single_geneva_run_needs_confirm(self):
        self.gm.is_running.return_value = True
        m = self.manager()
        with mock.patch("core.bypass_engine._nfqws_busy", return_value={}):
            r = m.enable()
            self.assertEqual(r["need_confirm"], ["geneva_run"])
            r = m.enable(confirm=True)
        self.assertTrue(r["ok"])
        self.gm.stop.assert_called_once()
        m.disable()

    def test_boot(self):
        m = self.manager()
        with mock.patch("core.geneva_auto_fw.remove") as rm:
            m.boot()                       # выключен — снять остатки
        rm.assert_called_once()
        self.gm.auto_stop_all.assert_called_once()
        self.assertFalse(m.running)
        auto = dict(self.cfg.get("geneva", "auto"))
        auto["enabled"] = True
        self.cfg.set("geneva", "auto", auto)
        m.boot()
        self.assertTrue(m.running)
        m.shutdown()
        self.assertFalse(m.running)
        self.assertTrue(am.auto_settings(self.cfg)["enabled"])  # остаётся

    def test_settings_limits(self):
        self.cfg.set("geneva", "auto", {"max_groups": 99, "workers": 0,
                                        "exclude": "x"})
        st = am.auto_settings(self.cfg)
        self.assertEqual((st["max_groups"], st["workers"], st["exclude"]),
                         (8, 1, []))


class TestEngineIntegration(_StubCase):

    def enable_auto(self):
        self.cfg.set("geneva", "auto", {"enabled": True})
        self.cfg.save()

    def test_single_run_and_manual_search_refused(self):
        self.enable_auto()
        self.cfg.set("geneva", "strategy", "[TCP:flags:PA]-drop-| \\/")
        for res in (self.mgr.start(),
                    self.mgr.start_search({"host": "blocked.example"}),
                    self.mgr.start_eval(["[TCP:flags:PA]-drop-| \\/"])):
            self.assertFalse(res["ok"])
            self.assertEqual(res["error_code"], "geneva_auto")
        self.assertFalse(self.mgr.is_running())

    def test_switch_to_nfqws_disables_auto(self):
        from core import bypass_engine as be
        fake = mock.Mock()
        fake.settings.return_value = {"enabled": True}
        with mock.patch.object(be, "_auto", return_value=fake), \
                mock.patch.object(be, "_nfqws_busy", return_value={}), \
                mock.patch.object(be, "_nfqws_running", return_value=False):
            be.switch("nfqws2", start=False)
        fake.disable.assert_called_once()

    def test_hold_suspends_auto(self):
        from core import bypass_engine as be
        fake = mock.Mock(running=True, suspended="")
        fake.suspend.return_value = True
        with mock.patch.object(be, "_auto", return_value=fake):
            self.assertEqual(be.hold_geneva_for("scanner"), "paused")
            fake.suspended = "scanner"
            be.release_geneva_hold("scanner")
        fake.suspend.assert_called_once_with("scanner")
        fake.resume.assert_called_once_with("scanner")

    def test_overview_has_auto(self):
        from core import bypass_engine as be
        fake = mock.Mock()
        fake.summary.return_value = {"enabled": True, "phase": "watching"}
        with mock.patch.object(be, "_auto", return_value=fake), \
                mock.patch("core.geneva_auto_manager."
                           "get_geneva_auto_manager", return_value=fake):
            ov = be.overview()
        self.assertEqual(ov["geneva"]["auto"]["phase"], "watching")


if __name__ == "__main__":
    unittest.main()
