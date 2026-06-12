# tests/test_proxy_export_traffic.py
"""
Тесты для функционала «страницы Прокси» (перенос из Throne):

  - обратный экспорт outbound → share-URI (для копирования, Ctrl+C);
  - clash_api-хелперы (нужны для учёта трафика);
  - дельта-аккумуляция трафика per-outbound (core/proxy_traffic).
"""

import base64
import json
import os
import tempfile
import unittest

from core.singbox_subscription import (
    uri_to_outbound, outbound_to_uri, outbounds_to_links, vless_to_outbound,
)
from core.singbox_config import (
    make_clash_api, ensure_clash_api, clash_api_endpoint, plan_activation,
    is_x25519_key, outbound_key_problem,
)
from core.proxy_tester import test_outbounds
import core.proxy_traffic as ptmod

# валидный 32-байтный x25519-ключ в base64url-без-паддинга (как pbk в ссылках)
GOOD_PBK = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


# ─────── outbound → URI (round-trip) ───────

class TestExportRoundTrip(unittest.TestCase):

    SAMPLES = [
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?type=ws&security=tls&sni=a.com&path=%2Fws&host=a.com&fp=chrome#vlnode",
        "vless://22222222-2222-2222-2222-222222222222@1.2.3.4:443"
        "?type=grpc&security=reality&pbk=" + GOOD_PBK +
        "&sid=ab12&flow=xtls-rprx-vision&sni=ya.ru#re1",
        "trojan://pass123@host.tld:443?sni=host.tld&type=ws&path=%2Ftj#tro",
        "ss://aes-256-gcm:secret@5.6.7.8:8388#ssnode",
        "hysteria2://hpw@h2.host:443?sni=h2.host&insecure=1#hy2node",
        "tuic://33333333-3333-3333-3333-333333333333:tpw@t.host:443?sni=t.host#tuicnode",
    ]

    def test_round_trip_preserves_key_fields(self):
        for uri in self.SAMPLES:
            r1 = uri_to_outbound(uri)
            self.assertTrue(r1.get("ok"), (uri, r1))
            ob = r1["outbound"]
            link = outbound_to_uri(ob)
            self.assertTrue(link, ("пустой экспорт", ob))
            r2 = uri_to_outbound(link)
            self.assertTrue(r2.get("ok"), ("реимпорт упал", link, r2))
            ob2 = r2["outbound"]
            for k in ("type", "server", "server_port", "uuid",
                      "password", "method", "flow"):
                if k in ob:
                    self.assertEqual(ob.get(k), ob2.get(k),
                                     (k, link))

    def test_vmess_round_trip(self):
        uri = ("vmess://" + __import__("base64").b64encode(json.dumps({
            "v": "2", "ps": "vm", "add": "vm.host", "port": "443",
            "id": "44444444-4444-4444-4444-444444444444", "scy": "auto",
            "net": "ws", "tls": "tls", "host": "vm.host", "path": "/vm",
        }).encode()).decode())
        ob = uri_to_outbound(uri)["outbound"]
        link = outbound_to_uri(ob)
        ob2 = uri_to_outbound(link)["outbound"]
        for k in ("type", "server", "server_port", "uuid"):
            self.assertEqual(ob[k], ob2[k])

    def test_service_and_group_skipped(self):
        self.assertEqual(outbound_to_uri({"type": "direct", "tag": "d"}), "")
        self.assertEqual(outbound_to_uri({"type": "block", "tag": "b"}), "")
        self.assertEqual(
            outbound_to_uri({"type": "urltest", "tag": "a", "outbounds": []}), "")
        self.assertEqual(outbound_to_uri({"type": "unknownproto"}), "")
        self.assertEqual(outbound_to_uri("not a dict"), "")

    def test_outbounds_to_links_filters_empties(self):
        obs = [
            {"type": "direct", "tag": "direct"},
            uri_to_outbound("ss://aes-256-gcm:p@1.1.1.1:8388#a")["outbound"],
            {"type": "selector", "tag": "sel", "outbounds": []},
            uri_to_outbound("ss://aes-256-gcm:p@2.2.2.2:8388#b")["outbound"],
        ]
        links = outbounds_to_links(obs)
        self.assertEqual(len(links), 2)
        self.assertTrue(all(l.startswith("ss://") for l in links))

    def test_ipv6_server_bracketed(self):
        ob = {"type": "trojan", "tag": "v6", "server": "2606:4700::1111",
              "server_port": 443, "password": "p",
              "tls": {"enabled": True, "server_name": "x"}}
        link = outbound_to_uri(ob)
        self.assertIn("@[2606:4700::1111]:443", link)


# ─────── clash_api helpers ───────

class TestClashApiHelpers(unittest.TestCase):

    def test_make_clash_api_localhost_only(self):
        block = make_clash_api(9090, "sec")
        self.assertEqual(block["external_controller"], "127.0.0.1:9090")
        self.assertEqual(block["secret"], "sec")

    def test_ensure_is_idempotent(self):
        cfg = {"outbounds": []}
        cfg, changed = ensure_clash_api(cfg, port=9090, secret="s")
        self.assertTrue(changed)
        cfg, changed2 = ensure_clash_api(cfg, port=1234, secret="other")
        self.assertFalse(changed2)
        # существующий не перезаписан
        self.assertEqual(
            cfg["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9090")

    def test_endpoint_roundtrip(self):
        cfg, _ = ensure_clash_api({}, port=9091, secret="abc")
        ep = clash_api_endpoint(cfg)
        self.assertEqual(ep, {"host": "127.0.0.1", "port": 9091, "secret": "abc"})

    def test_endpoint_none_when_absent(self):
        self.assertIsNone(clash_api_endpoint({"outbounds": []}))
        self.assertIsNone(clash_api_endpoint({"experimental": {}}))

    def test_endpoint_wildcard_host_becomes_loopback(self):
        cfg = {"experimental": {"clash_api": {
            "external_controller": "0.0.0.0:9999", "secret": "z"}}}
        ep = clash_api_endpoint(cfg)
        self.assertEqual(ep["host"], "127.0.0.1")
        self.assertEqual(ep["port"], 9999)


# ─────── валидация ключей (битый public_key роняет sing-box) ───────

class TestKeyValidation(unittest.TestCase):

    def test_is_x25519_key_accepts_valid(self):
        self.assertTrue(is_x25519_key(GOOD_PBK))                 # base64url raw
        self.assertTrue(is_x25519_key(bytes(range(32)).hex()))  # hex(64)
        self.assertTrue(is_x25519_key(
            base64.b64encode(bytes(32)).decode()))              # std b64 +pad

    def test_is_x25519_key_rejects_bad(self):
        for bad in ("", "   ", "не-ключ", "AAAA", GOOD_PBK[:-5], None, 123):
            self.assertFalse(is_x25519_key(bad), bad)

    def test_reality_empty_pubkey_flagged(self):
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u",
              "tls": {"enabled": True,
                      "reality": {"enabled": True, "public_key": ""}}}
        self.assertIn("public_key", outbound_key_problem(ob) or "")

    def test_reality_bad_pubkey_flagged(self):
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u",
              "tls": {"enabled": True,
                      "reality": {"enabled": True, "public_key": "garbage"}}}
        self.assertIsNotNone(outbound_key_problem(ob))

    def test_reality_valid_pubkey_ok(self):
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u",
              "tls": {"enabled": True,
                      "reality": {"enabled": True, "public_key": GOOD_PBK}}}
        self.assertIsNone(outbound_key_problem(ob))

    def test_plain_vless_not_flagged(self):
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u"}
        self.assertIsNone(outbound_key_problem(ob))

    def test_wireguard_bad_key_flagged(self):
        ob = {"type": "wireguard", "tag": "wg",
              "peer_public_key": "not-a-key"}
        self.assertIsNotNone(outbound_key_problem(ob))

    def test_vless_legacy_flow_flagged(self):
        # «unsupported flow» роняет sing-box целиком — батч тестера/конфиг.
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u", "flow": "xtls-rprx-direct"}
        self.assertIn("flow", outbound_key_problem(ob) or "")

    def test_vless_vision_udp443_not_flagged(self):
        # Нормализуемый вариант — не проблема: его чинит
        # normalize_vless_flow на этапах импорта/теста.
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u", "flow": "xtls-rprx-vision-udp443"}
        self.assertIsNone(outbound_key_problem(ob))

    def test_vless_vision_flow_ok(self):
        ob = {"type": "vless", "tag": "x", "server": "s", "server_port": 1,
              "uuid": "u", "flow": "xtls-rprx-vision"}
        self.assertIsNone(outbound_key_problem(ob))


class TestRealityImportRejection(unittest.TestCase):

    def test_reality_link_without_pbk_rejected(self):
        uri = "vless://11111111-1111-1111-1111-111111111111@h:443?security=reality&sni=x"
        r = vless_to_outbound(uri)
        self.assertFalse(r.get("ok"))

    def test_reality_link_with_valid_pbk_ok(self):
        uri = ("vless://11111111-1111-1111-1111-111111111111@h:443"
               "?security=reality&sni=x&pbk=%s&sid=ab" % GOOD_PBK)
        r = vless_to_outbound(uri)
        self.assertTrue(r.get("ok"))
        self.assertEqual(
            r["outbound"]["tls"]["reality"]["public_key"], GOOD_PBK)


class TestTesterSkipsBrokenKeys(unittest.TestCase):

    def test_broken_key_marked_invalid_not_sent_to_engine(self):
        good = {"type": "vless", "tag": "good", "server": "s",
                "server_port": 1, "uuid": "u"}
        bad = {"type": "vless", "tag": "bad", "server": "s",
               "server_port": 2, "uuid": "u",
               "tls": {"enabled": True,
                       "reality": {"enabled": True, "public_key": ""}}}
        # binary="" → фаза e2e не запускается; TCP отключаем → детерминизм.
        res = test_outbounds([good, bad], tcp_prefilter_enabled=False,
                             binary="")
        by = {r["tag"]: r for r in res["results"]}
        self.assertTrue(by["bad"].get("invalid"))
        self.assertFalse(by["bad"]["alive"])
        self.assertEqual(by["bad"]["stage"], "config")
        self.assertTrue(by["good"]["alive"])     # годный прошёл пайплайн


# ─────── активация сервера (пустить трафик через) ───────

class TestPlanActivation(unittest.TestCase):

    def _cfg_with_selector(self):
        return {"outbounds": [
            {"type": "selector", "tag": "select",
             "outbounds": ["A", "B"], "default": "A"},
            {"type": "vless", "tag": "A", "server": "a", "server_port": 1, "uuid": "u"},
            {"type": "vless", "tag": "B", "server": "b", "server_port": 1, "uuid": "u"},
            {"type": "vless", "tag": "C", "server": "c", "server_port": 1, "uuid": "u"},
            {"type": "direct", "tag": "direct"},
        ]}

    def test_selector_existing_member(self):
        cfg = self._cfg_with_selector()
        plan = plan_activation(cfg, "B")
        self.assertTrue(plan["ok"])
        self.assertEqual(plan["mode"], "selector")
        self.assertEqual(plan["selector"], "select")
        self.assertTrue(plan["already_member"])
        self.assertEqual(cfg["outbounds"][0]["default"], "B")

    def test_selector_adds_missing_member(self):
        cfg = self._cfg_with_selector()
        plan = plan_activation(cfg, "C")     # C не в selector.outbounds
        self.assertTrue(plan["ok"])
        self.assertFalse(plan["already_member"])
        self.assertIn("C", cfg["outbounds"][0]["outbounds"])
        self.assertEqual(cfg["outbounds"][0]["default"], "C")

    def test_route_final_when_no_selector(self):
        cfg = {"outbounds": [
            {"type": "vless", "tag": "A", "server": "a", "server_port": 1, "uuid": "u"},
            {"type": "urltest", "tag": "auto", "outbounds": ["A"]},
        ], "route": {"final": "auto"}}
        plan = plan_activation(cfg, "A")
        self.assertTrue(plan["ok"])
        self.assertEqual(plan["mode"], "route")
        self.assertEqual(cfg["route"]["final"], "A")

    def test_unknown_tag_rejected(self):
        cfg = self._cfg_with_selector()
        plan = plan_activation(cfg, "NOPE")
        self.assertFalse(plan["ok"])


# ─────── traffic delta accumulation ───────

class TestTrafficTracker(unittest.TestCase):

    def test_pick_tag_skips_service(self):
        self.assertEqual(ptmod._pick_tag(["node", "grp"]), "node")
        self.assertEqual(ptmod._pick_tag(["direct"]), "")
        self.assertEqual(ptmod._pick_tag(["block", "node2"]), "node2")
        self.assertEqual(ptmod._pick_tag([]), "")
        self.assertEqual(ptmod._pick_tag(None), "")

    def _patch(self, bodies):
        """Подменяет discovery + HTTP + путь персиста (изоляция между тестами)."""
        self._saved = (ptmod.running_clash_targets, ptmod._clash_get,
                       ptmod._state_path)
        self._tmp = tempfile.mkdtemp(prefix="pt-test-")
        ptmod._state_path = lambda: os.path.join(self._tmp, "pt.json")
        ptmod.running_clash_targets = lambda: [{
            "host": "127.0.0.1", "port": 9090, "secret": "",
            "config": "c", "tags": ["A", "B"]}]
        it = iter(bodies)

        def fake_get(host, port, secret, path, timeout=2.0):
            try:
                return 200, json.dumps({"connections": next(it)})
            except StopIteration:
                return 200, json.dumps({"connections": []})
        ptmod._clash_get = fake_get

    def tearDown(self):
        if hasattr(self, "_saved"):
            (ptmod.running_clash_targets, ptmod._clash_get,
             ptmod._state_path) = self._saved
        if hasattr(self, "_tmp"):
            import shutil
            shutil.rmtree(self._tmp, ignore_errors=True)

    def test_delta_accumulation_across_polls(self):
        poll1 = [
            {"id": "c1", "upload": 100, "download": 200, "chains": ["A", "grp"]},
            {"id": "c2", "upload": 10, "download": 0, "chains": ["B"]},
            {"id": "c3", "upload": 5, "download": 5, "chains": ["direct"]},
        ]
        poll2 = [
            {"id": "c1", "upload": 150, "download": 260, "chains": ["A", "grp"]},
            {"id": "c2", "upload": 10, "download": 5, "chains": ["B"]},
            {"id": "c4", "upload": 7, "download": 8, "chains": ["A"]},
        ]
        self._patch([poll1, poll2])
        tr = ptmod.TrafficTracker()

        tr._poll_all()
        snap = tr.snapshot()
        self.assertEqual(snap["A"]["up"], 100)
        self.assertEqual(snap["A"]["down"], 200)
        self.assertEqual(snap["B"]["up"], 10)
        self.assertNotIn("direct", snap)        # служебный не считается

        tr._poll_all()
        snap = tr.snapshot()
        # A: 100 + (150-100) + 7(new c4) = 157; down: 200 + 60 + 8 = 268
        self.assertEqual(snap["A"]["up"], 157)
        self.assertEqual(snap["A"]["down"], 268)
        # B: up без изменений (10), down +5
        self.assertEqual(snap["B"]["up"], 10)
        self.assertEqual(snap["B"]["down"], 5)

    def test_counter_reset_treated_as_new(self):
        # Соединение «сбросило» счётчик (id переиспользован) → берём как есть.
        self._patch([
            [{"id": "x", "upload": 500, "download": 0, "chains": ["A"]}],
            [{"id": "x", "upload": 30, "download": 0, "chains": ["A"]}],
        ])
        tr = ptmod.TrafficTracker()
        tr._poll_all()
        tr._poll_all()
        self.assertEqual(tr.snapshot()["A"]["up"], 530)

    def test_snapshot_filter_and_reset(self):
        self._patch([
            [{"id": "c1", "upload": 100, "download": 100, "chains": ["A"]},
             {"id": "c2", "upload": 50, "download": 50, "chains": ["B"]}],
        ])
        tr = ptmod.TrafficTracker()
        tr._poll_all()
        only_a = tr.snapshot(["A"])
        self.assertEqual(set(only_a.keys()), {"A"})
        self.assertEqual(only_a["A"]["up"], 100)

        tr.reset(["A"])
        self.assertEqual(tr.snapshot().get("A", {}).get("up", 0), 0)
        self.assertEqual(tr.snapshot()["B"]["up"], 50)   # B не тронут

        tr.reset()
        self.assertEqual(tr.snapshot(), {})


if __name__ == "__main__":
    unittest.main()
