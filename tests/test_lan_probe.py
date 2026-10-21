# tests/test_lan_probe.py
"""
Проба «как клиент LAN» (core/lan_probe): выбор адреса клиента,
сравнение с пробой роутера, недоступность на Keenetic и без netns,
уборка netns при любом исходе.
"""

import json
import unittest
from unittest import mock

from core import lan_probe as lp


def row(host, ok, stage="ok"):
    return {"host": host, "ok": ok, "stage": stage, "ms": 10 if ok else None,
            "error": "" if ok else "x", "ip": ""}


class TestPure(unittest.TestCase):
    def test_pick_address_from_end(self):
        self.assertEqual(lp.pick_address("192.168.1.1/24"),
                         "192.168.1.254/24")
        self.assertEqual(lp.pick_address("192.168.1.1/24",
                                         ["192.168.1.254", "192.168.1.253"]),
                         "192.168.1.252/24")
        # Роутер сам на .254 — его не берём.
        self.assertEqual(lp.pick_address("10.0.0.254/24"), "10.0.0.253/24")
        self.assertEqual(lp.pick_address("10.0.0.1/31"), "")

    def test_compare(self):
        rows = lp.compare(
            [row("a", True), row("b", True), row("c", False), row("d", False)],
            [row("a", True), row("b", False, "tls"), row("c", True)])
        self.assertEqual([r["verdict"] for r in rows],
                         ["both", "lan_fails", "router_fails", "both_fail"])

    def test_valid_host(self):
        self.assertTrue(lp._valid_host("youtube.com"))
        for bad in ("", "localhost", "a b.com", "x.com;reboot", "-rf"):
            self.assertFalse(lp._valid_host(bad))


class TestAvailability(unittest.TestCase):
    def test_keenetic(self):
        with mock.patch("core.firewall_persistence.is_keenetic",
                        return_value=True):
            r = lp.availability()
        self.assertFalse(r["ok"])
        self.assertIn("Keenetic", r["reason"])

    def test_no_bridge(self):
        with mock.patch("core.firewall_persistence.is_keenetic",
                        return_value=False), \
                mock.patch.object(lp.shutil, "which", return_value="/sbin/ip"), \
                mock.patch.object(lp.os, "geteuid", return_value=0), \
                mock.patch.object(lp, "_run", return_value=(0, "", "")), \
                mock.patch.object(lp, "_bridge", return_value=""):
            r = lp.availability()
        self.assertFalse(r["ok"])
        self.assertIn("мост", r["reason"])


class TestRun(unittest.TestCase):
    def setUp(self):
        self.calls = []
        patches = [
            mock.patch.object(lp, "availability", return_value={
                "ok": True, "bridge": "br-lan", "router": "192.168.1.1/24"}),
            mock.patch.object(lp, "child_probe",
                              return_value=[row("a.com", True),
                                            row("b.com", True)]),
            mock.patch.object(lp, "_cleanup",
                              side_effect=lambda: self.calls.append("clean")),
            mock.patch("core.device_schedule.read_neighbors",
                       return_value=[("192.168.1.254", "aa:bb:cc:dd:ee:ff")]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_lan_only_failure_reported(self):
        child = json.dumps([row("a.com", True), row("b.com", False, "tls")])
        with mock.patch.object(lp, "_setup", return_value="") as setup, \
                mock.patch.object(lp, "_run", return_value=(0, child, "")):
            r = lp.run(["a.com", "b.com", "bad host"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["address"], "192.168.1.253/24")
        setup.assert_called_once_with("br-lan", "192.168.1.253/24",
                                      "192.168.1.1")
        self.assertEqual(r["lan_fails"], ["b.com"])
        self.assertEqual(self.calls, ["clean", "clean"])

    def test_setup_error_still_cleans(self):
        with mock.patch.object(lp, "_setup", return_value="ip netns: nope"):
            r = lp.run(["a.com"])
        self.assertFalse(r["ok"])
        self.assertEqual(self.calls, ["clean", "clean"])

    def test_child_garbage(self):
        with mock.patch.object(lp, "_setup", return_value=""), \
                mock.patch.object(lp, "_run",
                                  return_value=(1, "", "Traceback…")):
            r = lp.run(["a.com"])
        self.assertFalse(r["ok"])
        self.assertIn("Traceback", r["error"])
        self.assertEqual(self.calls[-1], "clean")

    def test_address_outside_lan(self):
        r = lp.run(["a.com"], address="10.9.9.9")
        self.assertFalse(r["ok"])
        self.assertEqual(self.calls, [])

    def test_router_address_refused(self):
        for bad in ("192.168.1.1", "192.168.1.0", "192.168.1.255"):
            self.assertFalse(lp.run(["a.com"], address=bad)["ok"])
        self.assertEqual(self.calls, [])

    def test_one_probe_at_a_time(self):
        self.assertTrue(lp._busy.acquire(blocking=False))
        try:
            r = lp.run(["a.com"])
        finally:
            lp._busy.release()
        self.assertEqual(r["error"], "проба уже идёт")
        self.assertEqual(self.calls, [])

    def test_unavailable(self):
        with mock.patch.object(lp, "availability",
                               return_value={"ok": False, "reason": "нет"}):
            r = lp.run()
        self.assertEqual((r["ok"], r["available"]), (False, False))


if __name__ == "__main__":
    unittest.main()


class TestChildTimeout(unittest.TestCase):
    def test_slow_host_marked(self):
        import threading
        gate = threading.Event()
        self.addCleanup(gate.set)

        def fake(h, timeout):
            if h == "slow.com":
                gate.wait(5)
            return row(h, True)

        with mock.patch.object(lp, "probe_host", side_effect=fake):
            rows = lp.child_probe(["ok.com", "slow.com"], timeout=0.05)
        self.assertTrue(rows[0]["ok"])
        self.assertEqual(rows[1]["stage"], "timeout")
