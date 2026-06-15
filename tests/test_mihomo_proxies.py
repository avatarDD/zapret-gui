# tests/test_mihomo_proxies.py
"""
Тесты прокси-таблицы mihomo (задача №2):
  - YAML-эмиттер clash_yaml.dump_yaml + round-trip;
  - clash-proxy ↔ share-URI (copy/paste);
  - чтение/мутации mihomo_proxies (rows/groups/controller/append/remove);
  - тестер mihomo (TCP-degrade без бинаря/контроллера);
  - режим отладки и лог менеджера mihomo.

Тесты не требуют ни bottle, ни pyyaml (round-trip-операции гейтятся
на has_pyyaml() и проверяются для обоих окружений).
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core.clash_yaml import (
    parse_yaml, dump_yaml, dump_seq, has_pyyaml,
    clash_proxy_to_uri, uri_to_clash_proxy,
)
from core import mihomo_proxies as mp
from core.mihomo_proxy_tester import test_proxies
from core import mihomo_manager
from core.mihomo_manager import _inject_log_level
from core.mihomo_platform import MihomoPlatform


# ─────── YAML emitter ───────

class TestDumpYaml(unittest.TestCase):

    def test_roundtrip_pure_proxies(self):
        cfg = {"proxies": [
            {"name": "a", "type": "ss", "server": "1.2.3.4", "port": 8388,
             "cipher": "aes-128-gcm", "password": "p"},
            {"name": "My Node", "type": "vless", "server": "ex.com",
             "port": 443, "uuid": "u-1"},
        ]}
        text = dump_yaml(cfg)
        back = parse_yaml(text)
        self.assertIn("proxies", back)
        self.assertEqual(len(back["proxies"]), 2)
        self.assertEqual(back["proxies"][0]["name"], "a")
        self.assertEqual(back["proxies"][0]["port"], 8388)
        self.assertEqual(back["proxies"][1]["name"], "My Node")

    def test_quotes_special_values(self):
        # значение с ':' должно быть заквочено и распарситься обратно.
        text = dump_yaml({"external-controller": "127.0.0.1:9090"})
        back = parse_yaml(text)
        self.assertEqual(back["external-controller"], "127.0.0.1:9090")

    def test_dump_seq_indent(self):
        lines = dump_seq([{"name": "x", "type": "ss"}], indent=2)
        self.assertTrue(lines[0].startswith("  - "))


# ─────── clash-proxy ↔ URI ───────

class TestClashUriRoundtrip(unittest.TestCase):

    def _roundtrip(self, proxy):
        uri = clash_proxy_to_uri(proxy)
        self.assertTrue(uri, "пустой URI для %s" % proxy.get("type"))
        r = uri_to_clash_proxy(uri)
        self.assertTrue(r.get("ok"), r)
        return r["proxy"]

    def test_ss(self):
        p = self._roundtrip({
            "name": "ss1", "type": "ss", "server": "1.2.3.4", "port": 8388,
            "cipher": "aes-128-gcm", "password": "pw"})
        self.assertEqual(p["type"], "ss")
        self.assertEqual(p["server"], "1.2.3.4")
        self.assertEqual(p["port"], 8388)
        self.assertEqual(p["cipher"], "aes-128-gcm")
        self.assertEqual(p["password"], "pw")
        self.assertEqual(p["name"], "ss1")

    def test_vless_tls(self):
        p = self._roundtrip({
            "name": "v1", "type": "vless", "server": "ex.com", "port": 443,
            "uuid": "uu", "tls": True, "servername": "sni.com",
            "client-fingerprint": "chrome"})
        self.assertEqual(p["type"], "vless")
        self.assertEqual(p["uuid"], "uu")
        self.assertTrue(p["tls"])
        self.assertEqual(p["servername"], "sni.com")

    def test_vless_reality(self):
        p = self._roundtrip({
            "name": "r1", "type": "vless", "server": "ex.com", "port": 443,
            "uuid": "uu", "tls": True, "servername": "sni.com",
            "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "0" * 64, "short-id": "ab"}})
        self.assertEqual(p["reality-opts"]["public-key"], "0" * 64)
        self.assertEqual(p["reality-opts"]["short-id"], "ab")

    def test_trojan(self):
        p = self._roundtrip({
            "name": "t1", "type": "trojan", "server": "t.com", "port": 443,
            "password": "pp", "sni": "s.com"})
        self.assertEqual(p["type"], "trojan")
        self.assertEqual(p["password"], "pp")
        self.assertEqual(p["sni"], "s.com")

    def test_unsupported_type_empty(self):
        self.assertEqual(clash_proxy_to_uri(
            {"name": "x", "type": "wireguard", "server": "h", "port": 1}), "")


# ─────── чтение конфига ───────

SAMPLE = """\
mixed-port: 7890
proxies:
  - name: A
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: p
  - name: B
    type: trojan
    server: 2.2.2.2
    port: 443
    password: q
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - A
      - B
rules:
  - MATCH,PROXY
"""


class TestReadConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = parse_yaml(SAMPLE)

    def test_proxy_rows(self):
        rows = mp.proxy_rows(self.cfg)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "A")
        self.assertEqual(rows[0]["type"], "ss")
        self.assertEqual(rows[0]["server"], "1.1.1.1")
        self.assertEqual(rows[0]["port"], 8388)

    def test_proxy_names(self):
        self.assertEqual(mp.proxy_names(self.cfg), ["A", "B"])

    def test_select_groups(self):
        self.assertEqual(mp.select_group_names(self.cfg), ["PROXY"])

    def test_external_controller_endpoint(self):
        self.assertIsNone(mp.external_controller_endpoint(self.cfg))
        ep = mp.external_controller_endpoint(
            {"external-controller": "127.0.0.1:9090", "secret": "s"})
        self.assertEqual(ep, {"host": "127.0.0.1", "port": 9090,
                              "secret": "s"})
        ep2 = mp.external_controller_endpoint(
            {"external-controller": "0.0.0.0:9091"})
        self.assertEqual(ep2["host"], "127.0.0.1")
        self.assertEqual(ep2["port"], 9091)


# ─────── controller (live external-controller) ───────

class TestControllerProxies(unittest.TestCase):
    """controller_proxies должен предпочитать пользовательскую группу
    встроенной GLOBAL (иначе переключение узла не влияет на трафик)."""

    EP = {"host": "127.0.0.1", "port": 9090, "secret": ""}

    def _resp(self, payload):
        import json
        return (200, json.dumps(payload))

    def test_prefers_user_group_over_global(self):
        payload = {"proxies": {
            "GLOBAL": {"type": "Selector", "now": "DIRECT",
                       "all": ["PROXY", "srv-1", "DIRECT"]},
            "PROXY":  {"type": "Selector", "now": "srv-1", "all": ["srv-1"]},
            "srv-1":  {"type": "Trojan"},
        }}
        with mock.patch.object(mp, "_request", return_value=self._resp(payload)):
            r = mp.controller_proxies(self.EP)
        self.assertTrue(r["ok"])
        names = [g["name"] for g in r["groups"]]
        self.assertEqual(names, ["PROXY"])        # GLOBAL отфильтрован
        self.assertEqual(r["active"], "srv-1")    # из PROXY, не GLOBAL

    def test_keeps_global_when_only_group(self):
        payload = {"proxies": {
            "GLOBAL": {"type": "Selector", "now": "srv-1", "all": ["srv-1"]},
            "srv-1":  {"type": "Trojan"},
        }}
        with mock.patch.object(mp, "_request", return_value=self._resp(payload)):
            r = mp.controller_proxies(self.EP)
        self.assertEqual([g["name"] for g in r["groups"]], ["GLOBAL"])

    def test_activate_targets_user_group(self):
        payload = {"proxies": {
            "GLOBAL": {"type": "Selector", "now": "DIRECT",
                       "all": ["PROXY", "srv-1", "DIRECT"]},
            "PROXY":  {"type": "Selector", "now": "srv-1", "all": ["srv-1"]},
        }}
        calls = []

        def fake_request(ep, path, method="GET", data=None, timeout=3.0):
            if path == "/proxies":
                return self._resp(payload)
            calls.append((path, data))
            return (204, "")
        with mock.patch.object(mp, "_request", side_effect=fake_request):
            r = mp.controller_activate(self.EP, "srv-1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["group"], "PROXY")     # не GLOBAL
        self.assertIn("/proxies/PROXY", calls[0][0])


# ─────── мутации ───────

class TestMutations(unittest.TestCase):

    def test_remove_proxies_and_clean_groups(self):
        cfg = parse_yaml(SAMPLE)
        mp.remove_proxies(cfg, ["A"])
        self.assertEqual([p["name"] for p in cfg["proxies"]], ["B"])
        # ссылка на A удалена из группы
        grp = cfg["proxy-groups"][0]
        self.assertEqual(grp["proxies"], ["B"])

    def test_append_proxies_text(self):
        new = [{"name": "C", "type": "ss", "server": "3.3.3.3", "port": 9000,
                "cipher": "aes-128-gcm", "password": "z"}]
        out = mp.append_proxies_text(SAMPLE, new)
        back = parse_yaml(out)
        names = [p["name"] for p in back["proxies"]]
        self.assertIn("A", names)
        self.assertIn("C", names)
        # остальные секции (rules) сохранены текстово
        self.assertIn("rules:", out)
        self.assertIn("MATCH,PROXY", out)

    def test_append_no_proxies_section(self):
        out = mp.append_proxies_text("mixed-port: 7890\n", [
            {"name": "C", "type": "ss", "server": "3.3.3.3", "port": 1,
             "cipher": "aes-128-gcm", "password": "z"}])
        back = parse_yaml(out)
        self.assertEqual([p["name"] for p in back["proxies"]], ["C"])

    def test_enable_external_controller_text(self):
        out = mp.enable_external_controller_text(
            "mixed-port: 7890\nproxies:\n  - name: a\n",
            "127.0.0.1", 9090, "sec")
        self.assertTrue(out.startswith("external-controller: 127.0.0.1:9090\n"))
        self.assertIn("secret: sec", out)
        self.assertIn("mixed-port: 7890", out)
        # идемпотентность
        self.assertEqual(
            mp.enable_external_controller_text(out, "127.0.0.1", 1, "x"), out)

    def test_safe_mutate_delete(self):
        r = mp.safe_mutate(SAMPLE, lambda c: mp.remove_proxies(c, ["A"]))
        if has_pyyaml():
            self.assertTrue(r["ok"], r)
            back = parse_yaml(r["text"])
            self.assertEqual([p["name"] for p in back["proxies"]], ["B"])
        else:
            self.assertFalse(r["ok"])
            self.assertTrue(r.get("needs_pyyaml"))


# ─────── тестер ───────

class TestTester(unittest.TestCase):

    def test_empty(self):
        res = test_proxies([], binary=None)
        self.assertTrue(res["ok"])
        self.assertEqual(res["summary"]["total"], 0)

    def test_tcp_only_dead(self):
        # 127.0.0.1:1 — порт закрыт → connection refused (быстро) → мёртв.
        res = test_proxies(
            [{"name": "dead", "type": "ss", "server": "127.0.0.1", "port": 1}],
            controller=None, binary=None)
        self.assertEqual(res["summary"]["total"], 1)
        row = res["results"][0]
        self.assertEqual(row["tag"], "dead")
        self.assertFalse(row["alive"])
        self.assertEqual(row["stage"], "tcp")

    def test_filters_missing_server(self):
        res = test_proxies([{"name": "x", "type": "ss"}], binary=None)
        self.assertEqual(res["summary"]["total"], 0)


# ─────── менеджер: debug / log / dotfiles ───────

class _FakePlatform(MihomoPlatform):
    name = "test"

    def __init__(self, base):
        self.binary_dir = os.path.join(base, "bin")
        self.config_dir = os.path.join(base, "config")
        self.run_dir = os.path.join(base, "run")
        self.log_dir = os.path.join(base, "log")
        for d in (self.binary_dir, self.config_dir, self.run_dir,
                  self.log_dir):
            os.makedirs(d, exist_ok=True)


class _FakeCM:
    def __init__(self):
        self.d = {}

    def get(self, sect, key, default=None):
        return self.d.get((sect, key), default)

    def set(self, sect, key, val):
        self.d[(sect, key)] = val

    def save(self):
        pass


class TestManagerDebug(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mihomo-px-")
        self.platform = _FakePlatform(self.tmp)
        self.mgr = mihomo_manager.MihomoManager()
        self._pp = mock.patch.object(self.mgr, "_platform",
                                     return_value=self.platform)
        self._pp.start()

    def tearDown(self):
        self._pp.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inject_log_level(self):
        out = _inject_log_level(
            "mixed-port: 7890\nlog-level: info\nproxies:\n  - name: a\n",
            "debug")
        self.assertTrue(out.startswith("log-level: debug\n"))
        self.assertNotIn("log-level: info", out)
        self.assertIn("mixed-port: 7890", out)

    def test_get_set_debug(self):
        cm = _FakeCM()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm):
            self.assertFalse(self.mgr.get_debug()["enabled"])
            self.assertTrue(self.mgr.set_debug(True)["enabled"])
            self.assertTrue(self.mgr.get_debug()["enabled"])

    def test_list_configs_skips_dotfiles(self):
        cfg_dir = self.platform.config_dir
        with open(os.path.join(cfg_dir, "vpn.yaml"), "w") as f:
            f.write("proxies:\n  - name: a\n    type: ss\n"
                    "    server: 1.1.1.1\n    port: 1\n")
        with open(os.path.join(cfg_dir, ".run-vpn.yaml"), "w") as f:
            f.write("log-level: debug\nproxies: []\n")
        names = [c["name"] for c in self.mgr.list_configs()]
        self.assertIn("vpn", names)
        self.assertNotIn(".run-vpn", names)

    def test_read_log(self):
        with open(self.platform.log_path("inst"), "w") as f:
            for i in range(300):
                f.write("line %d\n" % i)
        r = self.mgr.read_log("inst", lines=10)
        self.assertTrue(r["ok"])
        self.assertTrue(r["exists"])
        self.assertIn("line 299", r["log"])
        self.assertNotIn("line 100", r["log"])

    def test_read_log_missing(self):
        r = self.mgr.read_log("nope")
        self.assertTrue(r["ok"])
        self.assertFalse(r["exists"])

    def test_read_log_bad_name(self):
        self.assertFalse(self.mgr.read_log("../etc/passwd")["ok"])


if __name__ == "__main__":
    unittest.main()
