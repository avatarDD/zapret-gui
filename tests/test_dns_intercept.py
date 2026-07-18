# tests/test_dns_intercept.py
"""
Перехват DNS (:53 → встроенный прокси) для доменной маршрутизации без
dnsmasq — core/routing/dns_intercept. Парсер ответов, suffix-match,
раскладка IP по бэкендам правила и живой UDP-прокси на loopback.
"""

import socket
import struct
import threading
import time
import unittest
from unittest import mock

from core.routing import dns_intercept
from core.routing.dns_intercept import (DnsIntercept, domain_matches,
                                        parse_dns_response)


def _build_query(qname, tid=0x1234):
    out = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for p in qname.split("."):
        out += bytes([len(p)]) + p.encode()
    return out + b"\x00" + struct.pack("!HH", 1, 1)


def _build_response(qname, ips_v4=(), ips_v6=(), tid=0x1234):
    an = len(ips_v4) + len(ips_v6)
    out = struct.pack("!HHHHHH", tid, 0x8180, 1, an, 0, 0)
    for p in qname.split("."):
        out += bytes([len(p)]) + p.encode()
    out += b"\x00" + struct.pack("!HH", 1, 1)
    for ip in ips_v4:
        # имя ответа — компрессионный указатель на qname (offset 12)
        out += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        out += socket.inet_pton(socket.AF_INET, ip)
    for ip in ips_v6:
        out += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16)
        out += socket.inet_pton(socket.AF_INET6, ip)
    return out


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestParser(unittest.TestCase):

    def test_parses_a_and_aaaa_with_compression(self):
        resp = _build_response("rr3---sn-x.googlevideo.com",
                               ips_v4=["173.194.1.2"],
                               ips_v6=["2a00:1450::5"])
        qname, ips = parse_dns_response(resp)
        self.assertEqual(qname, "rr3---sn-x.googlevideo.com")
        self.assertIn(("173.194.1.2", "v4"), ips)
        self.assertIn(("2a00:1450::5", "v6"), ips)

    def test_query_is_ignored(self):
        qname, ips = parse_dns_response(_build_query("example.com"))
        self.assertEqual(ips, [])

    def test_garbage_safe(self):
        for data in (b"", b"\x00" * 5, b"\xff" * 40):
            qname, ips = parse_dns_response(data)
            self.assertEqual(ips, [])

    def test_domain_matches_suffix(self):
        self.assertTrue(domain_matches("googlevideo.com",
                                       "googlevideo.com"))
        self.assertTrue(domain_matches("rr3---sn-x.googlevideo.com",
                                       "googlevideo.com"))
        self.assertFalse(domain_matches("evilgooglevideo.com",
                                        "googlevideo.com"))
        self.assertFalse(domain_matches("googlevideo.com", ""))


class TestHarvest(unittest.TestCase):

    def _fresh(self, entry):
        di = DnsIntercept()
        di._rules_cache = [entry]
        di._rules_at = time.time()
        return di

    def test_ipset_backend_add(self):
        di = self._fresh({"id": "r1", "kind": "ipset", "iface": "awg0",
                          "set_v4": "awgr_r1", "set_v6": "awgr_r16",
                          "table": 100, "domains": ["googlevideo.com"]})
        calls = []
        with mock.patch.object(dns_intercept, "_run",
                               side_effect=lambda a, **kw:
                               (calls.append(a), (0, "", ""))[1]):
            di._harvest("rr3---sn-x.googlevideo.com",
                        [("173.194.1.2", "v4"), ("2a00:1450::5", "v6")])
        self.assertEqual(di.stats["ips_added"], 2)
        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("awgr_r1 173.194.1.2" in j for j in joined))
        self.assertTrue(any("awgr_r16 2a00:1450::5" in j for j in joined))
        # Повторный ответ с тем же IP не дёргает ipset заново.
        n = len(calls)
        with mock.patch.object(dns_intercept, "_run",
                               side_effect=lambda a, **kw:
                               (calls.append(a), (0, "", ""))[1]):
            di._harvest("rr3---sn-x.googlevideo.com",
                        [("173.194.1.2", "v4")])
        self.assertEqual(len(calls), n)

    def test_iproute_backend_adds_rule_and_state(self):
        from core.routing import domain_rule
        di = self._fresh({"id": "r2", "kind": "iproute", "iface": "awg0",
                          "table": 361, "domains": ["example.com"]})
        calls = []
        saved = {}
        with mock.patch.object(dns_intercept, "_run",
                               side_effect=lambda a, **kw:
                               (calls.append(a), (0, "", ""))[1]), \
             mock.patch.object(domain_rule, "_iproute_state_load",
                               return_value={"r2": []}), \
             mock.patch.object(domain_rule, "_iproute_state_save",
                               side_effect=saved.update):
            di._harvest("www.example.com", [("5.6.7.8", "v4")])
        joined = [" ".join(c) for c in calls]
        self.assertTrue(any("rule add to 5.6.7.8/32 lookup 361" in j
                            for j in joined), joined)
        self.assertEqual(saved.get("r2"), [["5.6.7.8/32", "-4"]])

    def test_unmatched_domain_untouched(self):
        di = self._fresh({"id": "r1", "kind": "ipset", "iface": "awg0",
                          "set_v4": "s", "set_v6": "s6", "table": 100,
                          "domains": ["example.com"]})
        with mock.patch.object(dns_intercept, "_run") as run:
            di._harvest("other.org", [("1.1.1.1", "v4")])
        run.assert_not_called()
        self.assertEqual(di.stats["ips_added"], 0)


class TestSetEnabled(unittest.TestCase):

    def test_persists_flag_and_applies_state(self):
        # Регрессия: `from core.config_manager import save_config` падал
        # («cannot import name 'save_config'») — включение перехвата
        # отдавало ошибку в UI. Теперь модульная save_config существует.
        import core.config_manager as cmod
        data = {}
        cm = mock.Mock()
        cm.load.return_value = data
        with mock.patch.object(cmod, "get_config_manager",
                               return_value=cm), \
             mock.patch.object(cmod, "save_config") as save, \
             mock.patch.object(dns_intercept, "apply_enabled_state",
                               return_value={"ok": True}) as apply_state:
            res = dns_intercept.set_enabled(True)
        self.assertTrue(res.get("ok"), res)
        self.assertTrue(data["routing"]["dns_intercept"]["enabled"])
        save.assert_called_once()
        apply_state.assert_called_once()

    def test_module_save_config_exists(self):
        import core.config_manager as cmod
        fake = mock.Mock()
        with mock.patch.object(cmod, "get_config_manager",
                               return_value=fake):
            cmod.save_config()
        fake.save.assert_called_once()


class TestProxyLoopback(unittest.TestCase):
    """Живой прогон: клиент → прокси → фейковый upstream → клиент."""

    def test_forwards_and_harvests(self):
        up_port = _free_udp_port()
        px_port = _free_udp_port()

        # Фейковый upstream: на любой запрос отвечает готовым ответом.
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up_sock.bind(("127.0.0.1", up_port))
        up_sock.settimeout(5)
        resp_bytes = _build_response("cdn.example.com",
                                     ips_v4=["9.9.9.9"])

        def upstream():
            try:
                data, addr = up_sock.recvfrom(4096)
                up_sock.sendto(resp_bytes, addr)
            except OSError:
                pass

        t = threading.Thread(target=upstream, daemon=True)
        t.start()

        di = DnsIntercept()
        di._rules_cache = [{"id": "r1", "kind": "ipset", "iface": "awg0",
                            "set_v4": "s4", "set_v6": "s6", "table": 100,
                            "domains": ["example.com"]}]
        di._rules_at = time.time() + 3600  # кэш «вечно свеж» на время теста

        ipset_calls = []
        patches = [
            mock.patch.object(dns_intercept, "_settings",
                              return_value={"enabled": True,
                                            "port": px_port,
                                            "upstream":
                                                "127.0.0.1:%d" % up_port}),
            mock.patch.object(DnsIntercept, "_ensure_redirect",
                              return_value={"ok": True}),
            mock.patch.object(DnsIntercept, "_remove_redirect",
                              return_value=None),
            mock.patch.object(dns_intercept, "_run",
                              side_effect=lambda a, **kw:
                              (ipset_calls.append(a), (0, "", ""))[1]),
        ]
        for p in patches:
            p.start()
        try:
            res = di.start()
            self.assertTrue(res.get("ok"), res)
            cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cl.settimeout(5)
            cl.sendto(_build_query("cdn.example.com"),
                      ("127.0.0.1", px_port))
            data, _ = cl.recvfrom(4096)
            cl.close()
            self.assertEqual(data, resp_bytes)  # клиент получил ответ as-is
            # harvest успел положить IP в set (дожидаемся воркера)
            deadline = time.time() + 5
            while time.time() < deadline and di.stats["ips_added"] < 1:
                time.sleep(0.05)
            self.assertEqual(di.stats["ips_added"], 1)
            self.assertTrue(any("s4" in " ".join(c) and "9.9.9.9" in
                                " ".join(c) for c in ipset_calls))
        finally:
            di.stop()
            up_sock.close()
            for p in patches:
                p.stop()

    def test_start_rolls_back_when_redirect_fails(self):
        px_port = _free_udp_port()
        with mock.patch.object(dns_intercept, "_settings",
                               return_value={"port": px_port}), \
             mock.patch.object(DnsIntercept, "_ensure_redirect",
                               return_value={"ok": False, "error": "no nat"}), \
             mock.patch.object(DnsIntercept, "_remove_redirect",
                               return_value=None):
            di = DnsIntercept()
            res = di.start()
        self.assertFalse(res.get("ok"))
        self.assertFalse(di._running)


if __name__ == "__main__":
    unittest.main()
