# tests/test_smart_detect.py
"""Smart Detect (core/smart_detect): подтверждение перед автодобавлением."""

import shutil
import tempfile
import unittest
from unittest import mock

from core import smart_detect as sd


class SmartCase(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm
        self.dir = tempfile.mkdtemp(prefix="sd-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager
        from core import named_lists
        self.list_id = named_lists.create("blocked")["list"]["id"]
        self.patches = {}
        for name, value in (("_probe_direct", False), ("_probe_via", True),
                            ("_wan_down", False),
                            ("_target_method", "awg:awg0")):
            p = mock.patch.object(sd, name, return_value=value)
            self.patches[name] = p.start()
            self.addCleanup(p.stop)
        p = mock.patch("core.notify.event")
        self.notify = p.start()
        self.addCleanup(p.stop)
        p = mock.patch("core.named_lists._notify")
        p.start()
        self.addCleanup(p.stop)

    def domains(self):
        from core import named_lists
        return named_lists.get(self.list_id).get("domains") or []


class TestPure(unittest.TestCase):

    def test_via_spec(self):
        self.assertEqual(sd.via_spec("awg:awg0"), "awg:awg0")
        self.assertEqual(sd.via_spec("singbox:tun0"), "awg:tun0")
        self.assertEqual(sd.via_spec("nfqws2"), "")
        self.assertEqual(sd.via_spec("direct"), "")
        self.assertEqual(sd.via_spec("мусор"), "")

    def test_list_entry(self):
        self.assertEqual(sd.list_entry("cdn.example.co.uk"), "example.co.uk")
        self.assertEqual(sd.list_entry("cdn.example.co.uk", False),
                         "cdn.example.co.uk")

    def test_stalled_hosts(self):
        start = "2026-09-21T15:33:00.123456789Z"     # наносекунды, как в Go
        conns = [
            {"metadata": {"host": "stuck.com"}, "chains": ["DIRECT"],
             "upload": 500, "download": 0, "start": start},
            {"metadata": {"host": "ok.com"}, "chains": ["DIRECT"],
             "upload": 500, "download": 10, "start": start},
            {"metadata": {"host": "proxied.com"}, "chains": ["node", "PROXY"],
             "upload": 500, "download": 0, "start": start},
            {"metadata": {"host": ""}, "chains": ["DIRECT"],
             "upload": 1, "download": 0, "start": start},
        ]
        started = sd._parse_ts(start)
        self.assertIsNotNone(started)
        self.assertEqual(sd.stalled_hosts(conns, started + 40), ["stuck.com"])
        self.assertEqual(sd.stalled_hosts(conns, started + 5), [])


class TestFlow(SmartCase):

    def test_confirmed_adds_registrable_with_buttons(self):
        self.assertEqual(sd.submit("cdn.example.co.uk", self.list_id,
                                   "tls_rst", now=0), "queued")
        self.assertEqual(sd.submit("cdn.example.co.uk", self.list_id,
                                   now=10), "pending")
        self.assertEqual(sd.process(now=60), [])          # рано
        res = sd.process(now=200)
        self.assertEqual(res[0]["result"], "added")
        self.assertEqual(self.domains(), ["example.co.uk"])
        kwargs = self.notify.call_args.kwargs
        actions = [b["action"] for b in kwargs["buttons"]]
        self.assertEqual(actions, ["smart_undo", "smart_exclude"])
        self.assertEqual(sd.status()["pending"], [])

    def test_recovered_is_rejected_with_cooldown(self):
        sd.submit("a.com", self.list_id, now=0)
        self.patches["_probe_direct"].return_value = True
        self.assertEqual(sd.process(now=200)[0]["result"], "recovered")
        self.assertEqual(self.domains(), [])
        self.assertEqual(sd.submit("a.com", self.list_id, now=300),
                         "cooldown")
        self.assertEqual(sd.submit("a.com", self.list_id,
                                   now=300 + 25 * 3600), "queued")

    def test_tunnel_also_fails(self):
        sd.submit("a.com", self.list_id, now=0)
        self.patches["_probe_via"].return_value = False
        self.assertEqual(sd.process(now=200)[0]["result"], "tunnel_fails")
        self.assertEqual(self.domains(), [])

    def test_tunnel_down_waits_then_expires(self):
        sd.submit("a.com", self.list_id, now=0)
        self.patches["_probe_via"].return_value = None
        self.assertEqual(sd.process(now=200)[0]["result"], "waiting_tunnel")
        self.assertEqual(sd.process(now=sd.MAX_PENDING_SEC + 10)[0]["result"],
                         "expired")

    def test_nfqws_route_needs_only_second_direct_fail(self):
        self.patches["_target_method"].return_value = "nfqws2"
        sd.submit("a.com", self.list_id, now=0)
        self.assertEqual(sd.process(now=200)[0]["result"], "added")
        self.patches["_probe_via"].assert_not_called()

    def test_wan_down_pauses_queue(self):
        sd.submit("a.com", self.list_id, now=0)
        self.patches["_wan_down"].return_value = True
        self.assertEqual(sd.process(now=200)[0]["result"], "wan_down")
        self.assertEqual(len(sd.status()["pending"]), 1)
        self.patches["_probe_direct"].assert_not_called()

    def test_whitelist_blocks(self):
        self.cfg.set("block_detector", "whitelist", ["example.com"])
        sd.submit("cdn.example.com", self.list_id, now=0)
        self.assertEqual(sd.process(now=200)[0]["result"], "excluded")

    def test_undo_and_exclude(self):
        sd.submit("x.a.com", self.list_id, now=0)
        sd.submit("y.b.com", self.list_id, now=0)
        sd.process(now=200)
        added = {a["entry"]: a["id"] for a in sd.status()["added"]}
        self.assertEqual(sorted(self.domains()), ["a.com", "b.com"])
        self.assertTrue(sd.undo(added["a.com"])["ok"])
        self.assertTrue(sd.undo(added["a.com"])["already"])
        res = sd.exclude(added["b.com"])
        self.assertTrue(res["excluded"])
        self.assertEqual(self.domains(), [])
        self.assertIn("b.com", self.cfg.get("block_detector", "whitelist"))
        self.assertFalse(sd.undo("нет-такого")["ok"])


if __name__ == "__main__":
    unittest.main()
