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
from core.mihomo_proxy_tester import run_proxy_tests
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

    def test_append_into_pyyaml_col0_block(self):
        # dump_yaml/pyyaml пишет элементы списка БЕЗ отступа (col-0 «- name»).
        # Дозапись должна совпасть по отступу и дать валидный YAML, а не
        # «expected <block end>, but found '-'».
        base = dump_yaml({
            "proxies": [{"name": "A", "type": "ss", "server": "1.1.1.1",
                         "port": 1, "cipher": "aes-128-gcm", "password": "p"}],
            "rules": ["MATCH,DIRECT"]})
        out = mp.append_proxies_text(base, [
            {"name": "B", "type": "ss", "server": "2.2.2.2", "port": 2,
             "cipher": "aes-128-gcm", "password": "q"}])
        back = parse_yaml(out)          # не должно бросить ParserError
        self.assertEqual([p["name"] for p in back["proxies"]], ["A", "B"])
        self.assertEqual(back["rules"], ["MATCH,DIRECT"])   # rules сохранены

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
        res = run_proxy_tests([], binary=None)
        self.assertTrue(res["ok"])
        self.assertEqual(res["summary"]["total"], 0)

    def test_tcp_only_dead(self):
        # 127.0.0.1:1 — порт закрыт → connection refused (быстро) → мёртв.
        res = run_proxy_tests(
            [{"name": "dead", "type": "ss", "server": "127.0.0.1", "port": 1}],
            controller=None, binary=None)
        self.assertEqual(res["summary"]["total"], 1)
        row = res["results"][0]
        self.assertEqual(row["tag"], "dead")
        self.assertFalse(row["alive"])
        self.assertEqual(row["stage"], "tcp")

    def test_filters_missing_server(self):
        res = run_proxy_tests([{"name": "x", "type": "ss"}], binary=None)
        self.assertEqual(res["summary"]["total"], 0)


class TestTesterFreshlyAddedProxies(unittest.TestCase):
    """Только что добавленный узел движок ещё не держит.

    Конфиг на диске меняется без перезапуска, поэтому
    `/proxies/<имя>/delay` у запущенного инстанса отвечает 404. Раньше это
    трактовалось как «сервер мёртв» — ложный вердикт срабатывал ровно на
    свежедобавленных (то есть заведомо живых) ключах.
    """

    EP = {"host": "127.0.0.1", "port": 9090, "secret": ""}
    NEW = {"name": "new", "type": "ss", "server": "1.2.3.4", "port": 443}

    def test_unknown_node_is_not_called_dead(self):
        from core import mihomo_proxy_tester as t
        with mock.patch.object(t, "tcp_prefilter",
                               return_value={"new": (True, 5, "")}), \
             mock.patch.object(t, "controller_known_names",
                               return_value={"old"}), \
             mock.patch.object(t, "_controller_delays") as ctl:
            res = run_proxy_tests([self.NEW], controller=self.EP, binary=None)
        ctl.assert_not_called()          # 404 даже не запрашиваем
        row = res["results"][0]
        self.assertFalse(row["alive"])
        self.assertIn("перезапустите", row["error"])

    def test_unknown_node_goes_to_throwaway_engine(self):
        from core import mihomo_proxy_tester as t
        with mock.patch.object(t, "tcp_prefilter",
                               return_value={"new": (True, 5, "")}), \
             mock.patch.object(t, "controller_known_names",
                               return_value={"old"}), \
             mock.patch.object(t, "_throwaway_delays",
                               return_value={"new": {"ok": True,
                                                     "latency_ms": 42}}) as tw:
            res = run_proxy_tests([self.NEW], controller=self.EP,
                                  binary="/opt/usr/sbin/mihomo")
        tw.assert_called_once()
        row = res["results"][0]
        self.assertTrue(row["alive"])
        self.assertEqual(row["latency_ms"], 42)

    def test_known_node_still_measured_through_controller(self):
        from core import mihomo_proxy_tester as t
        with mock.patch.object(t, "tcp_prefilter",
                               return_value={"new": (True, 5, "")}), \
             mock.patch.object(t, "controller_known_names",
                               return_value={"new"}), \
             mock.patch.object(t, "_controller_delays",
                               return_value={"new": {"ok": True,
                                                     "latency_ms": 7}}) as ctl:
            res = run_proxy_tests([self.NEW], controller=self.EP, binary=None)
        ctl.assert_called_once()
        self.assertTrue(res["results"][0]["alive"])

    def test_controller_404_is_reported_as_needing_restart(self):
        from core import mihomo_proxy_tester as t
        with mock.patch.object(t, "_get", return_value=(404, "{}")):
            out = t._controller_delays(self.EP, ["x"], "http://e", 1000)
        self.assertFalse(out["x"]["ok"])
        self.assertTrue(out["x"]["engine_missing"])


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


# ─────────────────────────────────────────────────────────────────────
# Удаление прокси из таблицы БЕЗ pyyaml. Раньше операция просто
# отказывала («требует модуля PyYAML»), а на роутере его обычно нет.
# ─────────────────────────────────────────────────────────────────────

class TestRemoveProxiesText(unittest.TestCase):

    BLOCK = ("mixed-port: 7890\n"
             "# комментарий пользователя\n"
             "proxies:\n"
             "  - name: A\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n"
             "  - name: B\n    type: vless\n    server: b.io\n    port: 443\n"
             "    ws-opts:\n      path: /x\n      headers:\n"
             "        Host: b.io\n"
             "  - name: C\n    type: http\n    server: 127.0.0.1\n"
             "    port: 18080\n"
             "proxy-groups:\n"
             "  - name: PROXY\n    type: select\n    proxies:\n"
             "      - A\n      - B\n      - C\n"
             "rules:\n  - MATCH,PROXY\n")

    PYYAML_STYLE = ("proxies:\n"
                    "- name: A\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n"
                    "- name: B\n  type: ss\n  server: 5.6.7.8\n  port: 8388\n"
                    "proxy-groups:\n"
                    "- name: PROXY\n  type: select\n  proxies:\n"
                    "  - A\n  - B\n")

    FLOW = ('proxies:\n'
            '  - {name: A, type: ss, server: 1.2.3.4, port: 8388}\n'
            '  - {name: "B 2", type: trojan, server: b.io, port: 443}\n'
            'proxy-groups:\n'
            '  - {name: PROXY, type: select, proxies: [A, "B 2", DIRECT]}\n')

    def test_removes_only_selected(self):
        r = mp.remove_proxies_text(self.BLOCK, ["A", "C"])
        self.assertTrue(r["ok"])
        self.assertEqual(sorted(r["removed"]), ["A", "C"])
        self.assertEqual([p["name"] for p in mp.proxies_from_text(r["text"])],
                         ["B"])

    def test_keeps_comments_and_other_sections(self):
        r = mp.remove_proxies_text(self.BLOCK, ["A"])
        self.assertIn("# комментарий пользователя", r["text"])
        self.assertIn("mixed-port: 7890", r["text"])
        self.assertIn("  - MATCH,PROXY", r["text"])

    def test_nested_options_do_not_confuse_item_bounds(self):
        """`Host: b.io` внутри ws-opts не должен ломать границы элемента."""
        r = mp.remove_proxies_text(self.BLOCK, ["B"])
        self.assertEqual([p["name"] for p in mp.proxies_from_text(r["text"])],
                         ["A", "C"])
        self.assertNotIn("ws-opts", r["text"])

    def test_group_references_are_cleaned(self):
        """Группа со ссылкой на удалённый узел не даст mihomo стартовать."""
        r = mp.remove_proxies_text(self.BLOCK, ["A"])
        self.assertNotIn("      - A\n", r["text"])
        self.assertIn("      - B", r["text"])

    def test_group_refs_cleaned_in_pyyaml_style(self):
        """Стиль pyyaml: `proxies:` и `- A` на одной колонке."""
        r = mp.remove_proxies_text(self.PYYAML_STYLE, ["A"])
        self.assertNotIn("- A\n", r["text"])
        self.assertIn("- B", r["text"])

    def test_flow_items_and_flow_group(self):
        r = mp.remove_proxies_text(self.FLOW, ["A"])
        self.assertEqual([p["name"] for p in mp.proxies_from_text(r["text"])],
                         ["B 2"])
        self.assertIn('proxies: ["B 2", DIRECT]', r["text"])

    def test_emptied_group_is_reported(self):
        r = mp.remove_proxies_text(self.BLOCK, ["A", "B", "C"])
        self.assertEqual(r["emptied_groups"], ["PROXY"])
        # Пустой ключ разбирался бы как null — эмитим честный [].
        self.assertIn("proxies: []", r["text"])

    def test_unknown_name_is_a_noop(self):
        r = mp.remove_proxies_text(self.BLOCK, ["нет-такого"])
        self.assertEqual(r["removed"], [])
        self.assertEqual(r["text"], self.BLOCK)

    def test_inline_block_is_refused_not_corrupted(self):
        r = mp.remove_proxies_text("proxies: *anchor\n", ["A"])
        self.assertFalse(r["ok"])
        self.assertTrue(r["unsupported"])

    def test_works_without_pyyaml(self):
        import builtins
        real = builtins.__import__

        def _no_yaml(name, *a, **k):
            if name == "yaml":
                raise ImportError("no yaml")
            return real(name, *a, **k)

        builtins.__import__ = _no_yaml
        try:
            self.assertFalse(mp.has_pyyaml())
            r = mp.remove_proxies_text(self.BLOCK, ["A"])
        finally:
            builtins.__import__ = real
        self.assertTrue(r["ok"])
        self.assertEqual(r["removed"], ["A"])

    def test_unicode_names(self):
        text = ('proxies:\n'
                '  - name: "🇭🇰 HK 01"\n    type: ss\n'
                '    server: hk.io\n    port: 1\n'
                '  - name: keep\n    type: ss\n    server: k.io\n    port: 2\n'
                'proxy-groups:\n'
                '  - name: PROXY\n    type: select\n    proxies:\n'
                '      - "🇭🇰 HK 01"\n      - keep\n')
        r = mp.remove_proxies_text(text, ["🇭🇰 HK 01"])
        self.assertEqual([p["name"] for p in mp.proxies_from_text(r["text"])],
                         ["keep"])
        self.assertNotIn("HK 01", r["text"])
