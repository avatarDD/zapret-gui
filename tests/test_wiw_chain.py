# tests/test_wiw_chain.py
"""
core/wiw_chain.py — кто в WARP-in-WARP внутренний, а кто внешний.

UI подписывает по этим данным туннели в «Маршрутизации» и на #awg:
перепутанные роли отправили бы человека вести маршрут во внешний слой,
то есть в одиночный WARP.
"""

import unittest
from unittest import mock

from core import wiw_chain


class _Cfg:
    def __init__(self, data):
        self._d = data

    def get(self, *keys, default=None):
        v = self._d
        for k in keys:
            if isinstance(v, dict) and k in v:
                v = v[k]
            else:
                return default
        return v


class TestChains(unittest.TestCase):

    def test_nothing_configured(self):
        self.assertEqual(wiw_chain.chains(_Cfg({})), [])

    def test_awg_inactive_state_ignored(self):
        cm = _Cfg({"awg": {"warp_in_warp": {
            "active": False, "outer": "warp1", "inner": "warp2"}}})
        self.assertEqual(wiw_chain.chains(cm), [])

    def test_awg_pair(self):
        cm = _Cfg({"awg": {"warp_in_warp": {
            "active": True, "outer": "warp1", "inner": "warp2"}}})
        (ch,) = wiw_chain.chains(cm)
        self.assertEqual((ch["outer"], ch["inner"]), ("warp1", "warp2"))
        self.assertEqual((ch["outer_kind"], ch["inner_kind"]), ("awg", "awg"))
        self.assertEqual(ch["engine"], "awg")

    def test_masque_modes_kinds(self):
        for mode, kinds in (("masque_masque", ("warp", "warp")),
                            ("masque_awg", ("warp", "awg")),
                            ("awg_masque", ("awg", "warp"))):
            cm = _Cfg({"warp_in_warp": {"runtime": {
                "mode": mode, "outer_iface": "o", "inner_iface": "i"}}})
            (ch,) = wiw_chain.chains(cm)
            self.assertEqual((ch["outer_kind"], ch["inner_kind"]), kinds, mode)
            self.assertEqual(ch["engine"], "masque")

    def test_masque_unknown_mode_ignored(self):
        cm = _Cfg({"warp_in_warp": {"runtime": {
            "mode": "bogus", "outer_iface": "o", "inner_iface": "i"}}})
        self.assertEqual(wiw_chain.chains(cm), [])

    def test_roles(self):
        cm = _Cfg({"awg": {"warp_in_warp": {
            "active": True, "outer": "warp1", "inner": "warp2"}}})
        roles = wiw_chain.roles_by_iface(wiw_chain.chains(cm))
        self.assertEqual(roles["warp2"]["role"], "inner")
        self.assertEqual(roles["warp2"]["peer"], "warp1")
        self.assertEqual(roles["warp1"]["role"], "outer")


class TestApi(unittest.TestCase):

    def test_interfaces_endpoints_carry_chains(self):
        from tests._wsgi_client import WSGIClient, build_test_app
        client = WSGIClient(build_test_app())
        fake = [{"engine": "awg", "mode": "awg_awg", "outer": "warp1",
                 "outer_kind": "awg", "inner": "warp2", "inner_kind": "awg"}]
        with mock.patch("core.wiw_chain.chains", return_value=fake):
            for url in ("/api/routing/interfaces", "/api/awg/interfaces"):
                r = client.get_json(url)
                self.assertEqual(r["_status"], 200, url)
                self.assertEqual(r["wiw_chains"], fake, url)


if __name__ == "__main__":
    unittest.main()
