# tests/test_geneva_auto_core.py
"""
Чистое ядро режима «Авто» geneva (core/geneva_auto.py): ключи, книга
сервисов и все её переходы, backoff «не найдено», QUIC→TCP fallback,
план групп, кандидаты.

Правила переходов — перенос AutoBook из Zapret2_AutoTuner без изменений
(кроме восстановления ``searching`` → ``blocked`` при загрузке), поэтому
тесты повторяют AutoTests.cs по смыслу. Время передаётся явно — без
ожиданий.
"""

import unittest

from core import geneva_auto as ga


def sample(key="dns:93.184.216.53", kind=ga.DNS, transport="udp",
           health=ga.FAILED, t=100.0, ip="93.184.216.53", port=53, **kw):
    return ga.Sample(key=key, kind=kind, transport=transport, name=key,
                     app=kw.pop("app", "dns"), ip=ip, port=port, time=t,
                     health=health, why="запросы без ответа", **kw)


def web(key="web:blocked.example", health=ga.FAILED, t=100.0,
        ip="93.184.216.7"):
    return ga.Sample(key=key, kind=ga.WEB, transport="tcp", name=key[4:],
                     app="tls", ip=ip, port=443, time=t, health=health,
                     why="соединение есть, данных нет",
                     host="www." + key[4:])


class TestKeys(unittest.TestCase):

    def test_keys(self):
        self.assertEqual(ga.service_key(ga.WEB, "tcp", site="ex.co.uk"),
                         "web:ex.co.uk")
        self.assertEqual(ga.service_key(ga.QUIC, "udp", site="ex.com"),
                         "quic:ex.com")
        self.assertEqual(ga.service_key(ga.DNS, "udp", ip="1.2.3.4"),
                         "dns:1.2.3.4")
        self.assertEqual(ga.service_key(ga.ENDPOINT, "udp", ip="1.2.3.4",
                                        port=51820, app="wireguard"),
                         "ep:wireguard:udp:1.2.3.4:51820")
        self.assertEqual(ga.service_key(ga.ENDPOINT, "tcp", ip="2a00::1",
                                        port=443, app="tls"),
                         "ep:tls:tcp:[2a00::1]:443")
        # отличие от эталона: в порту — IP клиента
        self.assertEqual(ga.service_key(ga.LOCAL_PORT, "udp",
                                        client="192.168.1.10",
                                        local_port=6881),
                         "port:udp:192.168.1.10:6881")

    def test_registrable(self):
        self.assertEqual(ga.registrable("cdn.api.example.co.uk"),
                         "example.co.uk")
        self.assertEqual(ga.registrable("rr3.googlevideo.com."),
                         "googlevideo.com")
        self.assertEqual(ga.registrable("user.github.io"), "user.github.io")

    def test_replay_roundtrip_and_garbage(self):
        text = ga.to_base64([b"\x16\x03", b"abc"])
        self.assertEqual(ga.from_base64(text), [b"\x16\x03", b"abc"])
        self.assertEqual(ga.from_base64("%%%"), [])
        self.assertEqual(ga.from_base64(""), [])

    def test_service_roundtrip(self):
        s = ga.Service(key="dns:1.2.3.4", kind=ga.DNS, transport="udp",
                       addresses=[{"ip": "1.2.3.4", "seen": 5}],
                       ports=[53], status=ga.APPLIED, strategy="S",
                       fitness=396, applied_at=7, fails=[1, 2])
        back = ga.Service.from_dict(s.to_dict())
        self.assertEqual(back.to_dict(), s.to_dict())
        bad = ga.Service.from_dict({"key": "x", "kind": "??",
                                    "status": "??", "addresses": [
                                        {"ip": "nope"}], "ports": [0, 70000]})
        self.assertEqual((bad.kind, bad.status, bad.addresses, bad.ports),
                         (ga.ENDPOINT, ga.WATCHING, [], []))


class TestBookTransitions(unittest.TestCase):

    def suspected_book(self, n=3, kind="tcp"):
        b = ga.Book()
        if kind == "tcp":
            b.feed([web(t=90 + i) for i in range(n)], 100)
        else:
            b.feed([sample(t=90 + i) for i in range(n)], 100)
        b.evaluate(100)
        return b

    def test_thresholds(self):
        b = self.suspected_book(2)                  # TCP: нужно 3
        self.assertEqual(b.services[0].status, ga.WATCHING)
        b = self.suspected_book(3)
        self.assertEqual(b.services[0].status, ga.SUSPECTED)
        b = self.suspected_book(2, kind="udp")      # UDP: 2
        self.assertEqual(b.services[0].status, ga.SUSPECTED)
        b = ga.Book()
        dht = [ga.Sample(key="port:udp:192.168.1.10:6881",
                         kind=ga.LOCAL_PORT, transport="udp", name="DHT",
                         app="dht", local_port=6881, client="192.168.1.10",
                         time=90, health=ga.FAILED) for _ in range(19)]
        b.feed(dht, 100)
        b.evaluate(100)
        self.assertEqual(b.services[0].status, ga.WATCHING)  # DHT: 20
        b.feed(dht[:1], 100)
        b.evaluate(100)
        self.assertEqual(b.services[0].status, ga.SUSPECTED)

    def test_one_success_cancels_suspicion(self):
        b = ga.Book()
        b.feed([web(t=90 + i) for i in range(5)] + [web(health=ga.OK)], 100)
        b.evaluate(100)
        self.assertEqual(b.services[0].status, ga.WATCHING)

    def test_window(self):
        b = ga.Book()
        b.feed([web(t=0), web(t=1), web(t=2)], 0)
        b.evaluate(ga.WINDOW + 10)                  # провалы вне окна
        self.assertEqual(b.services[0].status, ga.WATCHING)

    def test_confirm_branches(self):
        for result, status, pause in (
                (ga.C_NOT_BLOCKED, ga.NOT_BLOCKED, ga.NOT_BLOCKED_PAUSE),
                (ga.C_IP_BLOCKED, ga.IP_BLOCKED, ga.IP_BLOCKED_PAUSE),
                (ga.C_BLOCKED, ga.BLOCKED, None)):
            b = self.suspected_book()
            s = b.next_to_confirm(100)
            self.assertIsNotNone(s)
            self.assertTrue(b.confirmed(s.key, result, 100))
            self.assertEqual(s.status, status)
            self.assertEqual(s.next_check,
                             None if pause is None else 100 + pause)

    def test_unknown_twice_is_blocked(self):
        b = self.suspected_book()
        s = b.services[0]
        self.assertEqual(b.confirmed(s.key, ga.C_UNKNOWN, 100), "")
        self.assertEqual(s.status, ga.SUSPECTED)
        self.assertEqual(s.next_check, 100 + ga.UNKNOWN_RECHECK)
        self.assertIsNone(b.next_to_confirm(110))
        b.feed([web(t=150)], 170)
        b.evaluate(170)                              # подозрение держится
        self.assertEqual(s.suspicions, 2)
        b.confirmed(s.key, ga.C_UNKNOWN, 170)
        self.assertEqual(s.status, ga.BLOCKED)

    def test_not_blocked_pause_then_watch(self):
        b = self.suspected_book()
        s = b.services[0]
        b.confirmed(s.key, ga.C_NOT_BLOCKED, 100)
        b.evaluate(200)                              # пауза идёт
        self.assertEqual(s.status, ga.NOT_BLOCKED)
        b.evaluate(100 + ga.NOT_BLOCKED_PAUSE + ga.WINDOW + 1)
        self.assertEqual(s.status, ga.WATCHING)

    def test_search_applied_degraded_cycle(self):
        b = self.suspected_book()
        s = b.services[0]
        b.confirmed(s.key, ga.C_BLOCKED, 100)
        self.assertIs(b.next_to_search(100), s)
        b.searching(s.key, 100)
        self.assertEqual(s.status, ga.SEARCHING)
        self.assertIsNone(b.next_to_search(100))
        b.applied(s.key, "S", 396, 200)
        self.assertEqual((s.status, s.strategy, s.fails), (ga.APPLIED, "S",
                                                           []))
        self.assertTrue(s.is_active)
        # провалы до применения не считаются
        b.feed([web(t=150 + i) for i in range(3)], 210)
        b.evaluate(210)
        self.assertEqual(s.status, ga.APPLIED)
        # после — ослаб
        b.feed([web(t=220 + i) for i in range(3)], 230)
        b.evaluate(230)
        self.assertEqual(s.status, ga.DEGRADED)
        self.assertTrue(s.is_active)               # стратегия ещё стоит
        self.assertIs(b.next_to_confirm(230), s)    # degraded — первыми
        # проверка с обходом прошла → снова applied
        b.confirmed(s.key, ga.C_NOT_BLOCKED, 240)
        self.assertEqual((s.status, s.applied_at), (ga.APPLIED, 240))
        # ослаб ещё раз и проверка не прошла → новый подбор
        b.feed([web(t=250 + i) for i in range(3)], 260)
        b.evaluate(260)
        b.confirmed(s.key, ga.C_BLOCKED, 260)
        self.assertEqual(s.status, ga.BLOCKED)
        # degraded + unknown → сразу blocked (без второго среза)
        b.applied(s.key, "S", 396, 300)
        b.feed([web(t=310 + i) for i in range(3)], 320)
        b.evaluate(320)
        b.confirmed(s.key, ga.C_UNKNOWN, 320)
        self.assertEqual(s.status, ga.BLOCKED)

    def test_not_found_backoff(self):
        b = self.suspected_book()
        s = b.services[0]
        now = 1000.0
        hours = []
        for _ in range(7):
            b.not_found(s.key, now)
            self.assertEqual(s.status, ga.NOT_FOUND)
            hours.append((s.next_check - now) / ga.HOUR)
            b.evaluate(s.next_check)                 # пора — снова blocked
            self.assertEqual(s.status, ga.BLOCKED)
            now = s.next_check
        self.assertEqual(hours, [1, 2, 4, 8, 16, 24, 24])
        b.applied(s.key, "S", 1, now)
        self.assertEqual(s.attempts, 0)              # успех сбрасывает

    def test_reset_and_interrupted(self):
        b = self.suspected_book()
        s = b.services[0]
        b.confirmed(s.key, ga.C_BLOCKED, 100)
        b.searching(s.key, 100)
        b.interrupted(s.key, 110)
        self.assertEqual(s.status, ga.BLOCKED)
        b.applied(s.key, "S", 1, 120)
        self.assertTrue(b.reset(s.key, 130))
        self.assertEqual((s.status, s.strategy, s.applied_at),
                         (ga.WATCHING, None, None))
        self.assertFalse(b.reset("nope", 130))

    def test_saved_searching_becomes_blocked(self):
        """Исправление эталона: «в подборе» после сбоя питания."""
        s = ga.Service(key="dns:1.2.3.4", kind=ga.DNS, status=ga.SEARCHING,
                       addresses=[{"ip": "1.2.3.4", "seen": 1}])
        b = ga.Book([s.to_dict()], now=500)
        self.assertEqual(b.find("dns:1.2.3.4").status, ga.BLOCKED)
        self.assertIsNotNone(b.next_to_search(500))

    def test_saved_replay_of_unreplayable_dropped(self):
        s = ga.Service(key="ep:http:tcp:1.2.3.4:80", app="http",
                       replay=ga.to_base64([b"GET / HTTP/1.1"]))
        b = ga.Book([s.to_dict()])
        self.assertEqual(b.services[0].replay, "")

    def test_forget_and_address_life(self):
        b = ga.Book()
        b.feed([web(t=0)], 0)
        b.feed([web(t=ga.DAY, ip="93.184.216.8")], ga.DAY)
        s = b.services[0]
        b.evaluate(ga.DAY + ga.ADDRESS_LIFE)
        self.assertEqual([a["ip"] for a in s.addresses], ["93.184.216.8"])
        b.evaluate(ga.DAY + ga.FORGET + 1)
        self.assertEqual(b.services, [])
        # применённый сервис не забывается
        b.feed([web(t=0)], 0)
        b.applied("web:blocked.example", "S", 1, 0)
        b.evaluate(ga.FORGET * 2)
        self.assertEqual(len(b.services), 1)

    def test_eviction_keeps_important(self):
        b = ga.Book()
        for i in range(ga.MAX_SERVICES):
            b.feed([sample(key="dns:10.%d" % i, ip="93.184.%d.%d"
                           % (i // 250, i % 250), health=ga.OK, t=i)], i)
        b.feed([web(t=999)], 1000)
        self.assertEqual(len(b.services), ga.MAX_SERVICES)
        self.assertIsNotNone(b.find("web:blocked.example"))
        self.assertIsNone(b.find("dns:10.0"))         # старейший вытеснен

    def test_search_priority(self):
        b = ga.Book()
        for key, kind, transport in (("quic:a.example", ga.QUIC, "udp"),
                                     ("ep:udp:udp:93.184.216.9:1", ga.ENDPOINT,
                                      "udp"),
                                     ("web:a.example", ga.WEB, "tcp"),
                                     ("dns:93.184.216.53", ga.DNS, "udp")):
            b._services[key] = ga.Service(key=key, kind=kind,
                                          transport=transport,
                                          status=ga.BLOCKED)
        order = []
        while True:
            s = b.next_to_search(0)
            if s is None:
                break
            order.append(s.kind)
            b.searching(s.key, 0)
        self.assertEqual(order, [ga.WEB, ga.DNS, ga.ENDPOINT, ga.QUIC])


class TestQuicFallback(unittest.TestCase):

    def test_quic_with_working_tcp_is_fallback(self):
        b = ga.Book()
        quic = [ga.Sample(key="quic:yt.example", kind=ga.QUIC,
                          transport="udp", name="yt.example (QUIC)",
                          app="quic", ip="93.184.216.7", port=443, time=90 + i,
                          health=ga.FAILED) for i in range(2)]
        b.feed(quic + [web(key="web:yt.example", health=ga.OK)], 100)
        lines = b.evaluate(100)
        q = b.find("quic:yt.example")
        self.assertEqual(q.status, ga.FALLBACK)
        self.assertTrue(any("TCP" in x for x in lines))
        self.assertIsNone(b.next_to_confirm(100))

    def test_quic_without_tcp_is_suspected(self):
        b = ga.Book()
        b.feed([ga.Sample(key="quic:q.example", kind=ga.QUIC,
                          transport="udp", name="q", app="quic",
                          ip="93.184.216.7", port=443, time=90 + i,
                          health=ga.FAILED) for i in range(2)], 100)
        b.evaluate(100)
        self.assertEqual(b.services[0].status, ga.SUSPECTED)


class TestPlan(unittest.TestCase):

    def svc(self, key, kind, strategy, ips, **kw):
        return ga.Service(key=key, kind=kind, status=ga.APPLIED,
                          strategy=strategy,
                          addresses=[{"ip": ip, "seen": 1} for ip in ips],
                          **kw)

    def test_targets(self):
        t = ga.target(self.svc("web:a", ga.WEB, "S", ["1.1.1.1"]))
        self.assertEqual((t.tcp_ports, t.udp_ports), ("443", ""))
        t = ga.target(self.svc("quic:a", ga.QUIC, "S", ["1.1.1.1"]))
        self.assertEqual((t.tcp_ports, t.udp_ports), ("", "443"))
        t = ga.target(self.svc("dns:a", ga.DNS, "S", ["1.1.1.1"]))
        self.assertEqual((t.tcp_ports, t.udp_ports), ("53", "53"))
        t = ga.target(self.svc("ep:x", ga.ENDPOINT, "S", ["1.1.1.1"],
                               transport="udp", ports=[51820]))
        self.assertEqual((t.tcp_ports, t.udp_ports), ("", "51820"))
        t = ga.target(ga.Service(key="port:udp:c:6881", kind=ga.LOCAL_PORT,
                                 transport="udp", client="192.168.1.10",
                                 local_port=6881))
        self.assertTrue(t.by_local_port)
        self.assertEqual((t.client, t.udp_ports), ("192.168.1.10", "6881"))
        self.assertIsNone(ga.target(ga.Service(key="web:x", kind=ga.WEB)))

    def test_format_ports(self):
        self.assertEqual(ga.format_ports([443, 8443, 444, 443]),
                         "443-444,8443")

    def test_groups_by_strategy_trial_first_and_claims(self):
        a = self.svc("web:a", ga.WEB, "SA", ["1.1.1.1", "2.2.2.2"])
        b = self.svc("web:b", ga.WEB, "SB", ["2.2.2.2", "3.3.3.3"])
        c = self.svc("web:c", ga.WEB, "SA", ["4.4.4.4"])
        d = ga.Service(key="dns:d", kind=ga.DNS, status=ga.SEARCHING,
                       addresses=[{"ip": "1.1.1.1", "seen": 1}])
        groups = ga.plan_groups([a, b, c, d], trial=(d, "ST"))
        self.assertEqual([g.strategy for g in groups], ["ST", "SA", "SB"])
        # пробная — только на свой сервис
        self.assertEqual(groups[0].services, ["dns:d"])
        # tcp 1.1.1.1 свободен у пробной (у неё tcp 53), группа SA его
        # получает; 2.2.2.2 по tcp достаётся SA, а не SB
        sb = groups[2]
        self.assertEqual(sb.targets[0].addresses, ["3.3.3.3"])

    def test_searching_not_active_and_max_groups(self):
        s = self.svc("web:a", ga.WEB, "SA", ["1.1.1.1"])
        s.status = ga.SEARCHING
        self.assertEqual(ga.plan_groups([s]), [])
        many = [self.svc("web:%d" % i, ga.WEB, "S%d" % i, ["9.9.9.%d" % i])
                for i in range(10)]
        self.assertEqual(len(ga.plan_groups(many, max_groups=4)), 4)


class TestCandidates(unittest.TestCase):

    def test_every_template_passes_check(self):
        from core.geneva_manager import check_strategy_text
        for s in (ga.AUTO_CANDIDATES_TCP + ga.AUTO_CANDIDATES_UDP +
                  ga.AUTO_CANDIDATES_DNS):
            self.assertEqual(check_strategy_text(s), s)

    def test_order_and_transport(self):
        web_s = ga.Service(key="web:a", kind=ga.WEB, transport="tcp")
        out = ga.candidates_for(web_s, running=[
            "[UDP:sport:*]-drop-| \\/", "[TCP:flags:A]-drop-| \\/"],
            found=["[TCP:flags:S]-drop-| \\/"])
        self.assertEqual(out[:2], ["[TCP:flags:A]-drop-| \\/",
                                   "[TCP:flags:S]-drop-| \\/"])
        self.assertNotIn("[UDP:sport:*]-drop-| \\/", out)
        self.assertLessEqual(len(out), ga.MAX_QUICK_CANDIDATES)
        dns = ga.Service(key="dns:a", kind=ga.DNS, transport="udp")
        self.assertEqual(ga.candidates_for(dns)[0],
                         ga.AUTO_CANDIDATES_DNS[0])
        self.assertEqual(ga.protos_for(dns), "UDP,IP,DNS,DNSQR")
        self.assertEqual(ga.protos_for(web_s), "TCP")

    def test_search_target(self):
        s = ga.Service(key="web:a", kind=ga.WEB, host="www.a.example",
                       name="a.example")
        self.assertEqual(ga.search_target(s), "https:www.a.example")
        r = ga.Service(key="dns:x", kind=ga.DNS,
                       addresses=[{"ip": "1.2.3.4", "seen": 1}])
        self.assertEqual(ga.search_target(r), "replay:1.2.3.4:53")


if __name__ == "__main__":
    unittest.main()
