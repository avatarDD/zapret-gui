"""Ускорение NAT роутера (core/nat_offload) и его REST."""

import json
import unittest
from unittest import mock

from core import nat_offload as no
from tests._wsgi_client import WSGIClient, build_test_app


class FakeCfg:
    def __init__(self):
        self.data = {}
        self.saved = 0

    def get(self, section, key, default=None):
        return self.data.get((section, key), default)

    def set(self, section, key, value):
        self.data[(section, key)] = value

    def save(self):
        self.saved += 1


class FakeUci:
    """uci и init.d OpenWrt в памяти."""

    def __init__(self, sw="1", hw="0", fail=""):
        self.vals = {no.UCI_SW: sw, no.UCI_HW: hw}
        self.calls = []
        self.fail = fail

    def __call__(self, argv, timeout=20):
        self.calls.append(list(argv))
        if self.fail and self.fail in " ".join(argv):
            return False, "boom"
        if argv[:3] == ["uci", "-q", "get"]:
            v = self.vals.get(argv[3])
            return (v is not None), (v or "") + "\n"
        if argv[:2] == ["uci", "set"]:
            key, _, val = argv[2].partition("=")
            self.vals[key] = val
        return True, ""


class FakeNdm:
    def __init__(self, sw=True, hw=True):
        self.sw, self.hw = sw, hw
        self.calls = []

    def __call__(self, argv, timeout=20):
        cmd = argv[2]
        self.calls.append(cmd)
        if cmd == "show running-config":
            lines = ["system", "  hostname kn"]
            if not self.sw:
                lines.append("no ppe software")
            if not self.hw:
                lines.append("no ppe hardware")
            return True, "\n".join(lines)
        attr = {"software": "sw", "hardware": "hw"}.get(cmd.split()[-1])
        if cmd.startswith("no ppe "):
            setattr(self, attr, False)
        elif cmd.startswith("ppe "):
            setattr(self, attr, True)
        return True, ""


class TestOpenWrt(unittest.TestCase):

    def test_status(self):
        n = no.NatOffload(run=FakeUci("1", "1"), platform="openwrt",
                          cfg=FakeCfg())
        st = n.status()
        self.assertTrue(st["supported"] and st["enabled"])
        self.assertTrue(st["software"] and st["hardware"])
        n = no.NatOffload(run=FakeUci("0", None), platform="openwrt",
                          cfg=FakeCfg())
        self.assertFalse(n.status()["enabled"])

    def test_off_then_back_as_it_was(self):
        uci, cfg = FakeUci("1", "1"), FakeCfg()
        n = no.NatOffload(run=uci, platform="openwrt", cfg=cfg)
        res = n.set(False)
        self.assertTrue(res["ok"])
        self.assertFalse(res["enabled"])
        self.assertIn(["uci", "commit", "firewall"], uci.calls)
        self.assertIn(["/etc/init.d/firewall", "reload"], uci.calls)
        self.assertEqual(cfg.get("geneva", "nat_offload_saved"),
                         {"software": True, "hardware": True})
        res = n.set(True)
        self.assertTrue(res["software"] and res["hardware"])

    def test_on_without_saved_is_software_only(self):
        n = no.NatOffload(run=FakeUci("0", "0"), platform="openwrt",
                          cfg=FakeCfg())
        res = n.set(True)
        self.assertTrue(res["software"])
        self.assertFalse(res["hardware"])

    def test_command_failure_reported(self):
        n = no.NatOffload(run=FakeUci(fail="commit"), platform="openwrt",
                          cfg=FakeCfg())
        res = n.set(False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "command_failed")
        self.assertIn("commit", res["error"])


class TestKeenetic(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(no.parse_keenetic_running("no ppe software\n"),
                         {"software": False, "hardware": True})
        self.assertEqual(no.parse_keenetic_running(""),
                         {"software": True, "hardware": True})

    def test_toggle(self):
        ndm, cfg = FakeNdm(), FakeCfg()
        n = no.NatOffload(run=ndm, platform="keenetic", cfg=cfg)
        res = n.set(False)
        self.assertTrue(res["ok"])
        self.assertFalse(res["enabled"])
        self.assertIn("no ppe software", ndm.calls)
        self.assertIn("no ppe hardware", ndm.calls)
        self.assertIn("system configuration save", ndm.calls)
        self.assertTrue(n.set(True)["hardware"])


class TestUnsupported(unittest.TestCase):

    def test_linux(self):
        calls = []
        n = no.NatOffload(run=lambda a, timeout=20: calls.append(a),
                          platform="linux", cfg=FakeCfg())
        self.assertFalse(n.status()["supported"])
        res = n.set(False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_code"], "unsupported")
        self.assertEqual(calls, [])


class TestRest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        self.nat = no.NatOffload(run=FakeUci("1", "0"), platform="openwrt",
                                 cfg=FakeCfg())
        p = mock.patch.object(no, "get_nat_offload", return_value=self.nat)
        p.start()
        self.addCleanup(p.stop)

    def test_get(self):
        data = self.client.get_json("/api/geneva/nat-offload")
        self.assertTrue(data["ok"] and data["enabled"])

    def test_post_needs_confirm(self):
        status, body = self.client._call(
            "POST", "/api/geneva/nat-offload",
            body=json.dumps({"enabled": False}).encode(),
            content_type="application/json")
        self.assertTrue(status.startswith("409"), status)
        self.assertEqual(json.loads(body)["error_code"], "need_confirm")
        self.assertTrue(self.nat.status()["enabled"])     # ничего не менял

    def test_post_off(self):
        status, body = self.client._call(
            "POST", "/api/geneva/nat-offload",
            body=json.dumps({"enabled": False, "confirm": True}).encode(),
            content_type="application/json")
        self.assertTrue(status.startswith("200"), status)
        self.assertFalse(json.loads(body)["enabled"])

    def test_post_bad_enabled(self):
        status, _ = self.client._call(
            "POST", "/api/geneva/nat-offload",
            body=json.dumps({"enabled": "no", "confirm": True}).encode(),
            content_type="application/json")
        self.assertTrue(status.startswith("400"), status)


if __name__ == "__main__":
    unittest.main()
