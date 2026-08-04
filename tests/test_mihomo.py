# tests/test_mihomo.py
"""
Тесты mihomo-подсистемы: валидация YAML, CRUD-менеджер (с временным
config_dir и моками), детект платформы.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import mihomo_manager
from core.mihomo_manager import validate_yaml
from core.mihomo_platform import (
    MihomoPlatform, detect_mihomo_platform,
)


MINIMAL_YAML = """\
proxies:
  - name: "vpn-1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: secret
"""


class FakePlatform(MihomoPlatform):
    name = "test"

    def __init__(self, tmpdir):
        self.binary_dir = os.path.join(tmpdir, "bin")
        self.config_dir = os.path.join(tmpdir, "config")
        self.run_dir    = os.path.join(tmpdir, "run")
        self.log_dir    = os.path.join(tmpdir, "log")
        self.init_dir   = os.path.join(tmpdir, "init")
        for d in (self.binary_dir, self.config_dir, self.run_dir,
                  self.log_dir, self.init_dir):
            os.makedirs(d, exist_ok=True)


class TestValidateYaml(unittest.TestCase):

    def test_empty(self):
        self.assertTrue(validate_yaml(""))

    def test_minimal_ok(self):
        self.assertEqual(validate_yaml(MINIMAL_YAML), [])

    def test_no_proxies_is_warning(self):
        errs = validate_yaml("port: 7890\n")
        self.assertTrue(any("proxies" in e for e in errs))

    def test_garbage_not_a_map(self):
        # Скаляр верхнего уровня — не map.
        errs = validate_yaml("just-a-string")
        self.assertTrue(errs)


class TestPlatform(unittest.TestCase):

    def test_detect_returns_platform(self):
        p = detect_mihomo_platform()
        self.assertIsInstance(p, MihomoPlatform)
        self.assertTrue(p.binary_path().endswith("mihomo"))

    def test_config_path_yaml(self):
        p = detect_mihomo_platform()
        self.assertTrue(p.config_path("foo").endswith("foo.yaml"))


class TestManagerCRUD(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mihomo-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = mihomo_manager.MihomoManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary",
                              return_value=os.path.join(
                                  self.platform.binary_dir, "mihomo")),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_list_empty(self):
        self.assertEqual(self.mgr.list_configs(), [])

    def test_save_and_list(self):
        r = self.mgr.save_config("vpn", text=MINIMAL_YAML)
        self.assertTrue(r["ok"], r)
        names = [c["name"] for c in self.mgr.list_configs()]
        self.assertIn("vpn", names)

    def test_save_bad_name(self):
        r = self.mgr.save_config("bad name!", text=MINIMAL_YAML)
        self.assertFalse(r["ok"])

    def test_save_empty(self):
        r = self.mgr.save_config("vpn", text="")
        self.assertFalse(r["ok"])

    def test_get_config(self):
        self.mgr.save_config("vpn", text=MINIMAL_YAML)
        r = self.mgr.get_config("vpn")
        self.assertTrue(r["ok"])
        self.assertIn("proxies", r["text"])

    def test_delete(self):
        self.mgr.save_config("vpn", text=MINIMAL_YAML)
        r = self.mgr.delete_config("vpn")
        self.assertTrue(r["ok"])
        self.assertEqual(self.mgr.list_configs(), [])

    def test_up_missing_config(self):
        r = self.mgr.up("nonexistent")
        self.assertFalse(r["ok"])

    def test_down_when_not_running(self):
        r = self.mgr.down("vpn")
        self.assertTrue(r["ok"])
        self.assertTrue(r.get("noop"))


if __name__ == "__main__":
    unittest.main()


from core import mihomo_installer as mi
from core import binary_installer as _bi
import gzip as _gzip


class TestMihomoArchMap(unittest.TestCase):

    def test_known(self):
        self.assertEqual(mi.map_arch("x86_64"), "amd64")
        self.assertEqual(mi.map_arch("aarch64"), "arm64")
        self.assertEqual(mi.map_arch("armv7"), "armv7")
        self.assertEqual(mi.map_arch("mipsel-softfloat"), "mipsle-softfloat")
        self.assertEqual(mi.map_arch("mips-softfloat"), "mips-softfloat")

    def test_unknown(self):
        self.assertEqual(mi.map_arch("riscv64"), "")
        self.assertEqual(mi.map_arch(""), "")


class TestSelectAsset(unittest.TestCase):

    ASSETS = [
        {"name": "mihomo-linux-amd64-compatible-v1.18.0.gz",
         "browser_download_url": "u1"},
        {"name": "mihomo-linux-amd64-v1.18.0.gz",
         "browser_download_url": "u2"},
        {"name": "mihomo-linux-arm64-v1.18.0.gz",
         "browser_download_url": "u3"},
        {"name": "mihomo-linux-mipsle-softfloat-v1.18.0.gz",
         "browser_download_url": "u4"},
        {"name": "mihomo-linux-amd64-v1.18.0.deb"},
    ]

    def test_amd64_exact_not_compatible(self):
        r = mi.select_asset(self.ASSETS, "amd64")
        self.assertTrue(r["ok"])
        self.assertEqual(r["name"], "mihomo-linux-amd64-v1.18.0.gz")
        self.assertEqual(r["url"], "u2")

    def test_arm64(self):
        r = mi.select_asset(self.ASSETS, "arm64")
        self.assertEqual(r["url"], "u3")

    def test_mipsle(self):
        r = mi.select_asset(self.ASSETS, "mipsle-softfloat")
        self.assertEqual(r["url"], "u4")

    def test_missing_arch(self):
        r = mi.select_asset(self.ASSETS, "armv7")
        self.assertFalse(r["ok"])
        self.assertIn("candidates", r)

    def test_empty_token(self):
        self.assertFalse(mi.select_asset(self.ASSETS, "")["ok"])


from core.mihomo_detector import MihomoDetector


class TestGvisorDetect(unittest.TestCase):
    """Детект gvisor у бинаря mihomo (best-effort; страховка — фолбэк -t)."""

    def _det(self):
        return MihomoDetector()

    def test_default_true_when_no_tags(self):
        # Обычный вывод `mihomo -v` без строки тегов → считаем gvisor есть.
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="Mihomo Meta v1.18.0 linux amd64 with go"):
            self.assertTrue(self._det()._detect_gvisor("/bin/mihomo"))

    def test_true_when_gvisor_mentioned(self):
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="... Tags: with_gvisor,with_quic"):
            self.assertTrue(self._det()._detect_gvisor("/bin/mihomo"))

    def test_true_on_real_mihomo_v_format(self):
        # Реальный вывод `mihomo -v` (v1.19.x): отдельная строка «Use tags: …».
        out = ("Mihomo Meta v1.19.27 linux amd64 with go1.26.4 ...\n"
               "Use tags: with_gvisor")
        with mock.patch("core.mihomo_detector._cmd_out", return_value=out):
            self.assertTrue(self._det()._detect_gvisor("/bin/mihomo"))

    def test_false_when_tags_without_gvisor(self):
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="Tags: with_quic,with_utls"):
            self.assertFalse(self._det()._detect_gvisor("/bin/mihomo"))


class TestExtractGz(unittest.TestCase):

    def test_gunzip(self):
        with tempfile.TemporaryDirectory() as d:
            gz = os.path.join(d, "mihomo.gz")
            with _gzip.open(gz, "wb") as f:
                f.write(b"\x7fELF-fake-binary")
            out = os.path.join(d, "out", "mihomo")
            r = _bi.extract_gz(gz, out)
            self.assertTrue(r["ok"], r)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"\x7fELF-fake-binary")

    def test_bad_gz(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.gz")
            with open(bad, "wb") as f:
                f.write(b"not gzip at all")
            r = _bi.extract_gz(bad, os.path.join(d, "out"))
            self.assertFalse(r["ok"])


# ─────────────────────────────────────────────────────────────────────
# Конфиг, который наш YAML-парсер не осиливает целиком (якоря/`<<:`-merge —
# частый приём в clash-подписках), раньше выглядел как «пустой»: прокси не
# видно в таблице, а TUN-интерфейса не видно в целях маршрутизации. Оба
# симптома — один корень, поэтому оба пути имеют текстовый фолбэк.
# ─────────────────────────────────────────────────────────────────────

from core.mihomo_config import tun_device_from_text, ENGINE_DEFAULT_TUN_DEVICE
from core import mihomo_proxies as _mp

_ANCHOR_CFG = (
    "defaults: &d\n"
    "  udp: true\n"
    "proxies:\n"
    "  - <<: *d\n"
    "    name: A\n"
    "    type: hysteria2\n"
    "    server: h.example.com\n"
    "    port: 443\n"
    "tun:\n"
    "  enable: true\n"
    "  device: mihomo-tun\n"
    "rules:\n"
    "  - MATCH,DIRECT\n"
)


class TestTunDeviceFromText(unittest.TestCase):

    def test_device_from_normal_config(self):
        self.assertEqual(
            tun_device_from_text("tun:\n  enable: true\n  device: mh0\n"),
            "mh0")

    def test_engine_default_when_device_omitted(self):
        # mihomo назовёт интерфейс сам (listener/sing_tun: InterfaceName).
        self.assertEqual(tun_device_from_text("tun:\n  enable: true\n"),
                         ENGINE_DEFAULT_TUN_DEVICE)

    def test_disabled_tun_gives_nothing(self):
        self.assertEqual(
            tun_device_from_text("tun:\n  enable: false\n  device: mh0\n"), "")

    def test_no_tun_section(self):
        self.assertEqual(tun_device_from_text("proxies: []\n"), "")

    def test_yes_and_quoted_forms(self):
        self.assertEqual(tun_device_from_text("tun:\n  enable: yes\n"
                                              "  device: \"mh1\"\n"), "mh1")

    def test_text_fallback_when_yaml_does_not_parse(self):
        self.assertEqual(tun_device_from_text(_ANCHOR_CFG), "mihomo-tun")


class TestProxiesFromText(unittest.TestCase):

    def test_block_style(self):
        rows = _mp.proxies_from_text(
            "proxies:\n"
            "  - name: A\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n"
            "  - name: opera-proxy\n    type: http\n"
            "    server: 127.0.0.1\n    port: 18080\n"
            "rules:\n  - MATCH,DIRECT\n")
        self.assertEqual([r["name"] for r in rows], ["A", "opera-proxy"])
        self.assertEqual(rows[1]["port"], 18080)

    def test_pyyaml_style_items_at_column_zero(self):
        rows = _mp.proxies_from_text(
            "proxies:\n- name: A\n  type: ss\n  server: a.io\n  port: 1\n"
            "proxy-groups:\n- name: PROXY\n  type: select\n")
        self.assertEqual([r["name"] for r in rows], ["A"])

    def test_flow_items(self):
        rows = _mp.proxies_from_text(
            'proxies:\n'
            '  - {name: "HK 01", type: vless, server: hk.io, port: 443}\n')
        self.assertEqual(rows[0]["name"], "HK 01")
        self.assertEqual(rows[0]["type"], "vless")

    def test_anchors_config_that_structured_parser_loses(self):
        from core.clash_yaml import parse_yaml
        import builtins
        real = builtins.__import__

        def _no_yaml(name, *a, **k):
            if name == "yaml":
                raise ImportError("no yaml")
            return real(name, *a, **k)

        builtins.__import__ = _no_yaml
        try:
            self.assertEqual(_mp.proxy_rows(parse_yaml(_ANCHOR_CFG)), [])
        finally:
            builtins.__import__ = real
        rows = _mp.proxies_from_text(_ANCHOR_CFG)
        self.assertEqual([r["name"] for r in rows], ["A"])

    def test_nested_options_do_not_leak_into_next_item(self):
        rows = _mp.proxies_from_text(
            "proxies:\n"
            "  - name: WS\n    type: vless\n    server: w.io\n    port: 443\n"
            "    ws-opts:\n      path: /ray\n      headers:\n"
            "        Host: w.io\n"
            "  - name: T\n    type: trojan\n    server: t.io\n    port: 443\n")
        self.assertEqual([r["name"] for r in rows], ["WS", "T"])
        self.assertEqual(rows[0]["server"], "w.io")
        self.assertEqual(rows[1]["server"], "t.io")

    def test_no_proxies_section(self):
        self.assertEqual(_mp.proxies_from_text("proxy-providers:\n  s: {}\n"),
                         [])


class TestControllerNodes(unittest.TestCase):
    """Живой /proxies движка — правда рантайма, когда YAML не разобрался."""

    PAYLOAD = {
        "proxies": {
            "DIRECT": {"type": "Direct"},
            "REJECT": {"type": "Reject"},
            "GLOBAL": {"type": "Selector", "now": "A", "all": ["A"]},
            "PROXY": {"type": "Selector", "now": "A", "all": ["A", "B"]},
            "A": {"type": "Vless"},
            "B": {"type": "Trojan"},
        }
    }

    def test_nodes_exclude_groups_and_builtins(self):
        import json as _json
        with mock.patch.object(_mp, "_request",
                               return_value=(200, _json.dumps(self.PAYLOAD))):
            res = _mp.controller_proxies({"host": "127.0.0.1", "port": 1,
                                          "secret": ""})
        self.assertTrue(res["ok"])
        self.assertEqual(sorted(n["name"] for n in res["nodes"]), ["A", "B"])
        # GLOBAL уходит, когда есть своя select-группа.
        self.assertEqual([g["name"] for g in res["groups"]], ["PROXY"])


class TestTestFailureReason(unittest.TestCase):
    """`mihomo -t` пишет ВСЁ в stdout, в stderr не попадает ничего.

    `log.SetOutput(os.Stdout)` в log/log.go, а в ветке `-t` (main.go)
    причина идёт через `log.Errorln`, следом `fmt.Println("configuration
    test failed")`. Мы собирали сообщение только из stderr — пользователь
    видел «mihomo -t test: » без единого слова о причине.
    """

    def test_reason_taken_from_stdout(self):
        out = ('level=error msg="proxy 5 does not exist"\n'
               "configuration file /opt/etc/mihomo/test.yaml test failed\n")
        self.assertIn("proxy 5 does not exist",
                      mihomo_manager.test_failure_reason(out, "", 1))

    def test_verdict_lines_are_dropped(self):
        out = ("configuration test failed\n"
               "configuration file /x/test.yaml test failed\n")
        self.assertIn("вывода нет",
                      mihomo_manager.test_failure_reason(out, "", 1))

    def test_ansi_is_stripped(self):
        out = '\x1b[31mlevel=error msg="init DNS error"\x1b[0m\n'
        self.assertEqual(mihomo_manager.test_failure_reason(out, "", 1),
                         'level=error msg="init DNS error"')

    def test_stderr_still_used_when_present(self):
        # Наш собственный таймаут пишется именно в stderr.
        self.assertIn("timeout",
                      mihomo_manager.test_failure_reason(
                          "", "timeout: Command timed out", 124))

    def test_empty_output_mentions_return_code(self):
        self.assertIn("код 1", mihomo_manager.test_failure_reason("", "", 1))

    def test_multiline_reason_is_joined(self):
        out = "level=error msg=\"a\"\nlevel=error msg=\"b\"\n"
        reason = mihomo_manager.test_failure_reason(out, "", 1)
        self.assertIn("a", reason)
        self.assertIn("b", reason)
