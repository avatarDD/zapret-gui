# tests/test_geneva_auto_priorities.py
"""
Режим «Авто» geneva: важность сервисов, списки пользователя, подборы
рядом (перенос AutoPriorities / AutoBook v1.4 Zapret2_AutoTuner).
"""

import unittest

from core import geneva_auto as ga
from core import geneva_auto_lists as gal


def svc(key, kind=ga.WEB, transport="tcp", status=ga.BLOCKED, ips=(),
        host="", app="tls", ports=(443,), since=0.0, last_seen=0.0):
    s = ga.Service(key=key, kind=kind, transport=transport, status=status,
                   host=host, app=app, ports=list(ports), since=since,
                   last_seen=last_seen,
                   addresses=[{"ip": ip, "seen": 1.0} for ip in ips])
    s.name = key.split(":", 1)[-1]
    return s


def book_with(*services, lists=None):
    b = ga.Book(lists=lists)
    for s in services:
        s.priority = gal.base_priority(s, b.lists)
        b._services[s.key] = s
    return b


class TestNameList(unittest.TestCase):

    def test_domains_zones_patterns_addresses(self):
        nl = gal.NameList(["example.org", "*.ru", ".su", "*google*",
                           "203.0.113.0/24", "2001:db8::1", "# comment"])
        self.assertTrue(nl.matches_name("www.example.org"))
        self.assertTrue(nl.matches_name("example.org."))
        self.assertFalse(nl.matches_name("badexample.org"))
        self.assertTrue(nl.matches_name("ya.ru"))
        self.assertTrue(nl.matches_name("a.b.su"))
        self.assertTrue(nl.matches_name("www.googleapis.com"))
        self.assertTrue(nl.matches_address("203.0.113.77"))
        self.assertTrue(nl.matches_address("2001:db8::1"))
        self.assertTrue(nl.matches_address("::ffff:203.0.113.5"))
        self.assertFalse(nl.matches_address("198.51.100.1"))
        self.assertEqual(nl.plain_domains(), ["example.org"])

    def test_asn_networks_binary_search(self):
        nl = gal.NameList(["AS12389"], {"12389": [
            "10.0.0.0/24", "10.0.1.0/24", "192.0.2.0/25", "2001:db8::/32"]})
        self.assertTrue(nl.matches_address("10.0.1.200"))
        self.assertTrue(nl.matches_address("192.0.2.127"))
        self.assertFalse(nl.matches_address("192.0.2.128"))
        self.assertTrue(nl.matches_address("2001:db8:1::5"))
        self.assertEqual(nl.asns, [12389])
        # AS без сетей пока ничего не находит
        self.assertFalse(gal.NameList(["AS1"]).matches_address("10.0.0.1"))

    def test_problems(self):
        self.assertEqual(gal.problem("example.org"), "")
        self.assertEqual(gal.problem("10.0.0.0/8"), "")
        self.assertNotEqual(gal.problem("*google*"), "")
        self.assertNotEqual(gal.problem("AS12389"), "")
        for ok in ("*google*", "AS12389", "*.ru", ".ru", "a?c.com"):
            self.assertEqual(gal.mask_problem(ok), "", ok)
        for bad in ("x", "a b", "AS", "AS0", "10.0.0.0/33"):
            self.assertNotEqual(gal.mask_problem(bad), "", bad)
        out, errors = gal.clean_entries("AS12389, 10.0.0.1\n10.0.0.1 x",
                                        strict=False)
        self.assertEqual(out, ["as12389", "10.0.0.1"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(gal.asns_of(out), [12389])

    def test_parse_ripe_merges(self):
        payload = {"data": {"prefixes": [
            {"prefix": "10.0.0.0/25"}, {"prefix": "10.0.0.128/25"},
            {"prefix": "bad"}, {"prefix": "2001:db8::/48"}]}}
        self.assertEqual(gal.parse_ripe(payload),
                         ["10.0.0.0/24", "2001:db8::/48"])
        self.assertEqual(gal.parse_ripe("not json"), [])

    def test_stale_asns(self):
        lists = gal.Lists({"important": ["AS1"], "no_search": ["AS2"]})
        self.assertEqual(gal.stale_asns(lists, {"1": 100.0}, 200.0), [2])
        self.assertEqual(gal.stale_asns(
            lists, {"1": 100.0, "2": 100.0}, 100.0 + gal.ASN_REFRESH),
            [1, 2])


class TestPriorities(unittest.TestCase):

    def test_base_priority(self):
        lists = gal.Lists({"important": ["important.example"],
                           "unimportant": ["*.games"]})
        self.assertEqual(gal.base_priority(svc("web:youtube.com"), lists),
                         gal.IMPORTANT)
        self.assertEqual(gal.base_priority(svc("web:googlevideo.com"),
                                           lists), gal.IMPORTANT)
        self.assertEqual(gal.base_priority(
            svc("web:www.important.example"), lists), gal.IMPORTANT)
        self.assertEqual(gal.base_priority(svc("web:x.games"), lists),
                         gal.BACKGROUND)
        self.assertEqual(gal.base_priority(svc("web:a.example"), lists),
                         gal.NORMAL)
        peer = svc("ep:udp:udp:1.2.3.4:51413", kind=ga.ENDPOINT,
                   transport="udp", app="udp", ports=(51413,))
        self.assertEqual(gal.base_priority(peer, lists), gal.BACKGROUND)
        wg = svc("ep:wireguard:udp:1.2.3.4:51820", kind=ga.ENDPOINT,
                 transport="udp", app="wireguard", ports=(51820,))
        self.assertEqual(gal.base_priority(wg, lists), gal.LOW)
        no_known = gal.Lists({"known_important": False})
        self.assertEqual(gal.base_priority(svc("web:youtube.com"),
                                           no_known), gal.NORMAL)
        user = svc("web:a.example")
        user.user_priority = gal.USER_IMPORTANT
        self.assertEqual(gal.base_priority(user, lists), gal.IMPORTANT)

    def test_starvation(self):
        peer = svc("ep:udp:udp:1.2.3.4:51413", kind=ga.ENDPOINT,
                   transport="udp", app="udp", ports=(51413,), since=0.0)
        peer.priority = gal.BACKGROUND
        self.assertEqual(gal.effective(peer, 60.0), gal.BACKGROUND)
        self.assertEqual(gal.effective(peer, gal.STARVATION_STEP), gal.LOW)

    def test_family(self):
        self.assertEqual(gal.family_of("rr3---sn.googlevideo.com"),
                         "YouTube")
        self.assertEqual(gal.family_of("youtube.com (QUIC)"), "YouTube")
        self.assertIsNone(gal.family_of("example.org"))


class TestBookQueue(unittest.TestCase):

    def test_important_first_and_preempting(self):
        site = svc("web:a.example", ips=("1.1.1.1",))
        yt = svc("web:youtube.com", ips=("2.2.2.2",))
        b = book_with(site, yt)
        self.assertEqual(b.next_to_search(0).key, "web:youtube.com")
        b.searching(site.key, 0)
        self.assertEqual(b.preempting(site.key, 0).key, yt.key)
        # фоновый никого не прерывает
        peer = svc("ep:udp:udp:3.3.3.3:51413", kind=ga.ENDPOINT,
                   transport="udp", app="udp", ports=(51413,))
        b2 = book_with(site, peer)
        b2.searching(site.key, 0)
        self.assertIsNone(b2.preempting(site.key, 0))

    def test_allowed_filter_and_overlap(self):
        a = svc("web:a.example", ips=("1.1.1.1",))
        q = svc("quic:a.example", kind=ga.QUIC, transport="udp",
                ips=("9.9.9.9",))
        c = svc("web:c.example", ips=("1.1.1.1",))
        d = svc("web:d.example", ips=("4.4.4.4",))
        self.assertTrue(ga.overlap(a, q))      # один сайт: TCP и QUIC
        self.assertTrue(ga.overlap(a, c))      # общий адрес
        self.assertFalse(ga.overlap(a, d))
        b = book_with(a, q, c, d)
        nxt = b.next_to_search(0, lambda s: not ga.overlap(s, a))
        self.assertEqual(nxt.key, "web:d.example")

    def test_no_search_and_exclude(self):
        lists = gal.Lists({"no_search": ["*.ru"], "exclude": ["vpn.example",
                                                              "5.5.5.5"]})
        b = ga.Book(lists=lists)
        smp = ga.Sample(key="web:ya.ru", kind=ga.WEB, transport="tcp",
                        name="ya.ru", app="tls", ip="7.7.7.7", port=443,
                        time=1.0, health=ga.FAILED)
        vpn = ga.Sample(key="ep:wireguard:udp:5.5.5.5:51820",
                        kind=ga.ENDPOINT, transport="udp", name="wg",
                        app="wireguard", ip="5.5.5.5", port=51820,
                        time=1.0, health=ga.FAILED)
        b.feed([smp, vpn], 1.0)
        self.assertEqual(b.services, [])
        # смена списков убирает уже известные, кроме применённых
        b2 = book_with(svc("web:ya.ru"), svc("web:mail.ru",
                                             status=ga.APPLIED))
        b2.find("web:mail.ru").strategy = "x"
        gone, skipped = b2.set_lists(lists)
        self.assertEqual(skipped, ["ya.ru"])
        self.assertIsNotNone(b2.find("web:mail.ru"))
        self.assertIsNone(b2.next_to_search(0))

    def test_interrupted_no_search_leaves(self):
        s = svc("web:ya.ru", status=ga.SEARCHING)
        b = book_with(s, lists=gal.Lists({"no_search": [".ru"]}))
        b.interrupted("web:ya.ru", 5.0)
        self.assertIsNone(b.find("web:ya.ru"))

    def test_check_now_pin_priority(self):
        s = svc("web:a.example", status=ga.APPLIED, ips=("1.1.1.1",))
        s.strategy = "[TCP:flags:PA]-drop-| \\/"
        s.applied_at = 0.0
        b = book_with(s)
        self.assertIn("проверяю", b.check_now(s.key, 1.0))
        self.assertEqual(s.status, ga.DEGRADED)
        self.assertTrue(b.pin(s.key, True))
        line = b.confirmed(s.key, ga.C_BLOCKED, 2.0)
        self.assertEqual(s.status, ga.APPLIED)
        self.assertIn("закреплена", line)
        self.assertTrue(b.set_user_priority(s.key, "unimportant"))
        self.assertEqual(s.priority, gal.BACKGROUND)
        self.assertFalse(b.pin("web:none", True))
        nf = svc("web:n.example", status=ga.NOT_FOUND)
        b._services[nf.key] = nf
        b.check_now(nf.key, 3.0)
        self.assertEqual(nf.status, ga.BLOCKED)

    def test_pinned_does_not_degrade(self):
        s = svc("web:a.example", status=ga.APPLIED, ips=("1.1.1.1",))
        s.strategy = "x"
        s.applied_at = 0.0
        s.pinned = True
        s.fails = [10.0, 11.0, 12.0]
        b = book_with(s)
        out = b.evaluate(20.0)
        self.assertEqual(s.status, ga.APPLIED)
        self.assertTrue(any("закреплённая" in x for x in out))

    def test_new_cdn_address_failure_is_not_degradation(self):
        s = svc("web:a.example", status=ga.APPLIED, ips=("1.1.1.1",))
        s.strategy = "x"
        s.applied_at = 0.0
        b = book_with(s)
        fails = [ga.Sample(key=s.key, kind=ga.WEB, transport="tcp",
                           name="a.example", app="tls", ip="8.8.8.%d" % i,
                           port=443, time=10.0 + i, health=ga.FAILED)
                 for i in range(5)]
        b.feed(fails, 20.0)
        b.evaluate(20.0)
        self.assertEqual(s.status, ga.APPLIED)
        self.assertEqual(s.fails, [])
        self.assertEqual(len(s.addresses), 6)

    def test_family_strategy(self):
        yt = svc("web:youtube.com", status=ga.APPLIED)
        yt.strategy = "[TCP:flags:PA]-x-| \\/"
        yt.applied_at = 5.0
        gv = svc("web:googlevideo.com")
        b = book_with(yt, gv)
        self.assertEqual(b.family_strategy(gv), yt.strategy)
        self.assertIsNone(b.family_strategy(svc("web:a.example")))

    def test_make_room_keeps_places_for_sites(self):
        b = ga.Book()
        n = ga.MAX_SERVICES - gal.RESERVED_PLACES
        for i in range(n):
            b.feed([ga.Sample(key="ep:udp:udp:10.0.%d.%d:51413"
                              % (i // 250, i % 250), kind=ga.ENDPOINT,
                              transport="udp", name="p", app="udp",
                              ip="10.0.%d.%d" % (i // 250, i % 250),
                              port=51413, time=float(i), health=ga.OK)],
                   float(i))
        self.assertEqual(len(b.services), n)
        b.feed([ga.Sample(key="ep:udp:udp:11.0.0.1:51413", kind=ga.ENDPOINT,
                          transport="udp", name="p", app="udp",
                          ip="11.0.0.1", port=51413, time=999.0,
                          health=ga.OK)], 999.0)
        self.assertEqual(len(b.services), n)       # вытеснил старейшего пира
        self.assertIsNone(b.find("ep:udp:udp:10.0.0.0:51413"))
        b.feed([ga.Sample(key="web:a.example", kind=ga.WEB, transport="tcp",
                          name="a.example", app="tls", ip="1.1.1.1",
                          port=443, time=1000.0, health=ga.OK)], 1000.0)
        self.assertEqual(len(b.services), n + 1)   # сайту место есть

    def test_detector_and_dns_poison(self):
        s = svc("web:a.example", status=ga.WATCHING, host="www.a.example",
                ips=("1.1.1.1",))
        s.oks = [1.0]
        b = book_with(s)
        self.assertEqual(b.detect("host", "cdn.a.example", "THROTTLE", 10.0),
                         ["a.example"])
        self.assertEqual(b.detect("host", "a.example", "THROTTLE", 20.0), [])
        self.assertEqual(len(s.detected), 1)       # одна отметка в минуту
        self.assertEqual(b.detect("ip", "1.1.1.1", "RETRANS", 30.0), [])
        b.evaluate(30.0)
        self.assertEqual(s.status, ga.SUSPECTED)
        self.assertIn("шейпер", s.why)
        self.assertTrue(b.dns_poisoned("www.a.example", 0.0))
        self.assertFalse(b.dns_poisoned("www.a.example.", 10.0))
        self.assertTrue(b.dns_poisoned("www.a.example", ga.HOUR + 1))
        # чужие имена журнал не засоряют
        self.assertFalse(b.dns_poisoned("x.example", 0.0))


class TestPlanTrials(unittest.TestCase):

    def test_several_trials_first(self):
        a = svc("web:a.example", ips=("1.1.1.1",))
        c = svc("web:c.example", ips=("3.3.3.3",))
        d = svc("web:d.example", status=ga.APPLIED, ips=("1.1.1.1",
                                                         "4.4.4.4"))
        d.strategy = "S_D"
        groups = ga.plan_groups([a, c, d], trials=[(a, "S_A"), (c, "S_C")])
        self.assertEqual([g.strategy for g in groups[:2]], ["S_A", "S_C"])
        # адрес 1.1.1.1 достался пробе, у рабочей группы — только свой
        self.assertEqual(groups[2].targets[0].addresses, ["4.4.4.4"])


if __name__ == "__main__":
    unittest.main()


# ───────────────────────── менеджер: подборы рядом и списки ──────────

from tests.test_geneva_auto_manager import _Base, FakeSearch  # noqa: E402
from core import geneva_auto_manager as am  # noqa: E402
from core import geneva_auto_search as gs  # noqa: E402


class SlowSearch(FakeSearch):
    """Подбор, который идёт, пока его не отпустят."""

    def __init__(self, slot):
        super().__init__()
        self.slot = slot
        self.running = False

    @property
    def busy(self):
        return self.running

    def start(self, s, running=(), proven=(), only="", first=()):
        super().start(s, running, proven, only, first)
        self.running = True
        self.key = s.key
        return True

    def finish(self, outcome=gs.APPLIED):
        self.running = False
        self._result = gs.SearchResult(self.key, outcome,
                                       strategy=self.strategy, fitness=396)

    def cancel(self, wait=0):
        self.cancelled += 1
        if self.running:
            self.finish(gs.CANCELLED)


class TestSplitAndLists(_Base):

    def make(self, split=True, workers=8):
        raw = dict(self.cfg.get("geneva", "auto", default={}) or {})
        raw.update(split_workers=split, workers=workers, max_groups=8)
        self.cfg.set("geneva", "auto", raw)
        self.slots = {}

        def factory(slot):
            self.slots[slot] = SlowSearch(slot)
            return self.slots[slot]
        m = am.GenevaAutoManager(
            observer=self.obs, probes=self.probes, search=None,
            applier=self.applier, geneva=self.gm, cfg=self.cfg,
            clock=lambda: self.clock[0], path=self.path,
            search_factory=factory)
        m.load()
        return m

    def blocked(self, m, key, ip, kind=ga.WEB):
        s = svc(key, kind=kind, ips=(ip,))
        s.priority = gal.base_priority(s, m.book.lists)
        m.book._services[key] = s
        return s

    def test_slot_workers(self):
        self.assertEqual(am.slot_workers(8, False), 8)
        self.assertEqual(am.slot_workers(8, True), 2)
        self.assertEqual(am.slot_workers(4, True), 1)
        self.assertEqual(am.slot_workers(3, True), 1)

    def test_several_searches_without_overlap(self):
        m = self.make()
        self.blocked(m, "web:a.example", "1.1.1.1")
        self.blocked(m, "web:b.example", "2.2.2.2")
        self.blocked(m, "web:c.example", "1.1.1.1")     # общий адрес с a
        m._searching(100.0)
        self.assertEqual(sorted(m._works), ["web:a.example",
                                            "web:b.example"])
        self.assertEqual(len({w["slot"] for w in m._works.values()}), 2)
        self.assertTrue(all(x.workers == 2 for x in self.slots.values()))
        self.slots[m._works["web:a.example"]["slot"]].finish()
        m._searching(101.0)
        self.assertEqual(m.book.find("web:a.example").status, ga.APPLIED)
        self.assertIn("web:c.example", m._works)

    def test_one_at_a_time_without_split(self):
        m = self.make(split=False)
        self.blocked(m, "web:a.example", "1.1.1.1")
        self.blocked(m, "web:b.example", "2.2.2.2")
        m._searching(100.0)
        self.assertEqual(len(m._works), 1)
        self.assertEqual(self.slots[0].workers, 8)

    def test_important_preempts_least_important(self):
        m = self.make(split=False)
        self.blocked(m, "web:a.example", "1.1.1.1")
        m._searching(100.0)
        self.assertEqual(list(m._works), ["web:a.example"])
        self.blocked(m, "web:youtube.com", "9.9.9.9")
        m._searching(101.0)
        import time
        for _ in range(50):
            if self.slots[0].cancelled:
                break
            time.sleep(0.01)
        self.assertEqual(self.slots[0].cancelled, 1)
        m._searching(102.0)
        self.assertEqual(m.book.find("web:a.example").status, ga.BLOCKED)
        self.assertIn("web:youtube.com", m._works)

    def test_without_split_only_slot_zero(self):
        m = self.make(split=False)
        self.blocked(m, "web:a.example", "1.1.1.1")
        m.search(0).running = True           # прошлый подбор ещё сворачивается
        self.assertIsNone(m._free_slot())
        m.search(0).running = False
        self.assertEqual(m._free_slot(), 0)

    def test_preempt_once_and_not_for_blocked_custom(self):
        m = self.make(split=False)
        self.blocked(m, "web:a.example", "1.1.1.1")
        m._searching(100.0)
        m._works["web:a.example"]["preempted"] = True
        self.blocked(m, "web:youtube.com", "9.9.9.9")
        m._preempt(101.0)                # прерывание уже идёт — второго нет
        import time
        time.sleep(0.05)
        self.assertEqual(self.slots[0].cancelled, 0)
        # важный с идущей проверкой своей стратегии никого не прерывает
        m._works["web:a.example"].pop("preempted")
        m._works["web:youtube.com"] = {"slot": 1, "split": False,
                                       "custom": "S"}
        m._preempt(102.0)
        time.sleep(0.05)
        self.assertEqual(self.slots[0].cancelled, 0)

    def test_lists_from_settings_apply_to_saved_book(self):
        lists = gal.Lists({"exclude": ["bank.example", "10.0.0.0/8"]})
        saved = [svc("web:bank.example", status=ga.APPLIED).to_dict(),
                 svc("web:cdn.example", status=ga.APPLIED,
                     ips=("1.1.1.1",)).to_dict()]
        b = ga.Book(saved, 0, lists)
        self.assertIsNone(b.find("web:bank.example"))
        # новый адрес CDN в исключённой подсети в набор не идёт
        b.feed([ga.Sample(key="web:cdn.example", kind=ga.WEB,
                          transport="tcp", name="cdn.example", app="tls", ip="10.1.2.3", port=443,
                          time=5.0, health=ga.OK)], 5.0)
        self.assertEqual([a["ip"] for a in b.find("web:cdn.example")
                          .addresses], ["1.1.1.1"])

    def test_lists_update_and_no_search(self):
        m = self.make()
        self.blocked(m, "web:ya.ru", "1.1.1.1")
        bad = m.update_lists({"important": ["x y"], "exclude": ["AS1"]})
        self.assertFalse(bad["ok"])
        self.assertEqual(len(bad["errors"]), 2)
        res = m.no_search_for("web:ya.ru")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entry"], "ya.ru")
        self.assertIsNone(m.book.find("web:ya.ru"))
        view = m.lists_view()
        self.assertEqual(view["no_search"], ["ya.ru"])
        self.assertIn("YouTube", view["families"])

    def test_asn_fetch_on_save(self):
        calls = []

        def fetch(n):
            calls.append(n)
            return ["203.0.113.0/24"]
        m = self.make()
        m._asn_fetch = fetch
        m.update_lists({"unimportant": ["AS64500"]})
        m._asn_thread.join(5)
        self.assertEqual(calls, [64500])
        s = svc("web:a.example", ips=("203.0.113.9",))
        self.assertEqual(gal.base_priority(s, m.lists()), gal.BACKGROUND)
        self.assertEqual(m.lists_view()["asn"]["AS64500"]["prefixes"], 1)

    def test_actions(self):
        m = self.make()
        s = self.blocked(m, "web:a.example", "1.1.1.1")
        s.status = ga.APPLIED
        s.strategy = "[TCP:flags:PA]-drop-| \\/"
        self.assertTrue(m.pin("web:a.example")["ok"])
        self.assertTrue(m.book.find("web:a.example").pinned)
        self.assertTrue(m.set_priority("web:a.example", "important")["ok"])
        self.assertFalse(m.set_priority("web:a.example", "x")["ok"])
        self.assertTrue(m.check_now("web:a.example")["ok"])
        self.assertEqual(m.book.find("web:a.example").status, ga.DEGRADED)
        self.assertEqual(m.check_now("web:none")["error_code"], "not_found")


class TestReview2(TestSplitAndLists):
    """Находки второго код-ревью."""

    def test_split_frozen_while_searching(self):
        m = self.make(split=True)
        self.blocked(m, "web:a.example", "1.1.1.1")
        m._searching(100.0)
        self.assertEqual(self.slots[0].workers, 2)
        raw = dict(self.cfg.get("geneva", "auto", default={}))
        raw["split_workers"] = False
        self.cfg.set("geneva", "auto", raw)
        # идущему подбору деление не меняют, новый слот не выдают
        self.assertEqual(m.search(0).workers, 2)
        self.assertIsNone(m._free_slot())
        self.slots[0].finish()
        m._collect(101.0)
        self.assertEqual(m._free_slot(), 0)
        self.assertEqual(m.search(0).workers, 8)

    def test_confirm_skips_service_in_work(self):
        m = self.make()
        s = self.blocked(m, "web:a.example", "1.1.1.1")
        s.status = ga.DEGRADED
        m._works[s.key] = {"slot": 0, "custom": "X"}
        self.assertIsNone(m.book.next_to_confirm(
            100.0, allowed=lambda x: x.key not in m._works))
        self.assertIs(m.book.next_to_confirm(100.0), s)

    def test_cancelled_custom_is_not_failure(self):
        m = self.make()
        self.blocked(m, "web:a.example", "1.1.1.1")
        m._take(gs.SearchResult("web:a.example", gs.CANCELLED), 100.0,
                custom="X")
        joined = " ".join(e["text"] for e in m.journal)
        self.assertIn("прервана", joined)
        self.assertNotIn("не прошла", joined)


class TestReview2Pure(unittest.TestCase):

    def test_fill_population(self):
        from core.geneva_manager import fill_population
        self.assertEqual(fill_population(["a", "b"], ["c", "a"], 3),
                         ["a", "b", "c"])
        self.assertEqual(fill_population(["a", "b"], [], 5),
                         ["a", "b", "a", "b", "a"])
        self.assertEqual(fill_population(["a"] * 3, ["b"] * 30, 2),
                         ["a", "b"])

    def test_seed_db_makes_dir_without_shared(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auto", "db", "t.jsonl")
            gs.seed_db(os.path.join(d, "nope.jsonl"), path)
            self.assertTrue(os.path.isdir(os.path.dirname(path)))
            self.assertFalse(os.path.exists(path))

    def test_page_verdict_uses_target_size(self):
        from core import geneva_auto_probes as pr
        r = pr.PageResult(tls=True)
        r.connect_ok = r.tls_ok = r.cert_valid = True
        r.status, r.body, r.error = 200, 90 * 1024, pr.P_TRUNCATED
        self.assertEqual(pr.page_confirm(r), ga.C_NOT_BLOCKED)
        self.assertEqual(pr.page_confirm(r, 128 * 1024), ga.C_BLOCKED)
        self.assertEqual(pr.page_fitness(r, 128 * 1024)[1], "broken")


class TestReview3(TestSplitAndLists):
    """Находки третьего код-ревью."""

    def test_settings_do_not_retune_running_search(self):
        m = self.make(split=True)
        self.blocked(m, "web:a.example", "1.1.1.1")
        m._searching(100.0)
        raw = dict(self.cfg.get("geneva", "auto", default={}))
        raw["split_workers"] = False
        self.cfg.set("geneva", "auto", raw)
        with m._lock:
            m._retune_searches()
        self.assertEqual(self.slots[0].workers, 2)

    def test_cancel_during_start_is_kept(self):
        m = self.make()
        s = self.blocked(m, "web:a.example", "1.1.1.1")
        m._works[s.key] = {"slot": 0, "split": True, "custom": "",
                           "starting": True}
        m._collect(100.0)                   # запускающийся не собирается
        self.assertIn(s.key, m._works)
        m._cancel_work(s.key)
        started = []
        self.assertIsNone(m._launch(s.key, 0, lambda: started.append(1)))
        self.assertEqual(started, [])
        self.assertNotIn(s.key, m._works)

    def test_cancel_while_starting_cancels_after(self):
        m = self.make()
        s = self.blocked(m, "web:a.example", "1.1.1.1")
        m._works[s.key] = {"slot": 0, "split": True, "custom": "",
                           "starting": True}

        def start():
            m._cancel_work(s.key)           # пришло во время start()
            return m.search(0).start(s.clone())
        self.assertTrue(m._launch(s.key, 0, start))
        self.assertEqual(self.slots[0].cancelled, 1)
        self.assertNotIn("starting", m._works[s.key])


class TestReview3Pure(unittest.TestCase):

    def test_db_proven_reads_target_dbs(self):
        import os
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "db"))
            open(os.path.join(d, "db", "t.jsonl"), "w").close()
            calls = []

            class GM:
                def db_top(self, target="", limit=10, db=""):
                    calls.append(db)
                    return {"items": [{"strategy": "S" + (db and "t"),
                                       "ok": 2 if db else 1}]}
            x = gs.AutoSearch(geneva=GM(), probes=None)
            with mock.patch.object(x, "_p", return_value={"auto": d}):
                self.assertEqual(x._db_proven(), ["St", "S"])
            self.assertEqual(len(calls), 2)
