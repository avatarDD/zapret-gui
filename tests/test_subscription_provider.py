# tests/test_subscription_provider.py
"""Подписки панелей: UA, HWID, happ://crypt4/, защита от усадки."""

import base64
import unittest
from unittest import mock

from core import happ_crypt4 as c4
from core import subscription_manager as sm

PLAIN = ("vless://00000000-0000-4000-8000-000000000001@example.com:443"
         "?encryption=none&security=tls&sni=example.com#HappNode")
# IV 00..0f + AES-256-CBC(sha256("my-custom-device-hwid")) — вектор из
# тестов Tachyon (openssl enc).
VEC_KEY = ("AAECAwQFBgcICQoLDA0OD0OMKcI1aFmugKQB4r4K4OSN6xxDU5FmUUFRentyDOXf"
           "swM3t0kyFovZ5yaTDJ1pva68axdwhD4QWAebC6Jnbv7X5xJKCGOAMMAQ3uRuJe+n"
           "Xl0Az2QN+xgljgGeQaM8UHM1t3+tX4FlEWyuaaNZ4dZFwJUh0Nitkz26Mfa9//Hn")
VEC_SALT = ("AAECAwQFBgcICQoLDA0OD6K0gDGOn/K3and0NuhjH6rDKR/ov8Xn8ESMdCk4+0rU"
            "kXQVLyUBpJTUyCagj1wCUWkMyOczDnAbhwthZ6HsuitMrPx4PnOGQypFH9+MdCQh"
            "Z+5mIkkO4g8+S5p4LTTqzA3H6U2wT6s21QmtkYxCmI8+0flp6JHnnm3Lp6krqaWq")
# AES-128-CBC: ключ — первые 16 байт sha256("k2").
VEC_128 = "AAECAwQFBgcICQoLDA0OD+uzeCjsOjE535nNjd3DteDa9eC+4cz6GzE/goDCbOe4"


class TestAes(unittest.TestCase):

    def test_fips197_vector(self):
        # FIPS-197, приложение C.3 (AES-256): CBC с нулевым IV = ECB.
        key = bytes(range(32))
        ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(c4.aes_cbc_decrypt(ct, key, bytes(16)).hex(),
                         "00112233445566778899aabbccddeeff")
        # C.1 (AES-128).
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(c4.aes_cbc_decrypt(ct, bytes(range(16)),
                                            bytes(16)).hex(),
                         "00112233445566778899aabbccddeeff")

    def test_crypt4(self):
        self.assertTrue(c4.is_crypt4("happ://crypt4/abc"))
        self.assertTrue(c4.is_crypt4("crypt4/abc"))
        self.assertFalse(c4.is_crypt4("https://x/crypt4/abc"))
        self.assertEqual(c4.decrypt("happ://crypt4/" + VEC_KEY,
                                    ["my-custom-device-hwid"]), PLAIN)
        self.assertEqual(c4.decrypt("happ://crypt4/" + VEC_KEY, ["wrong"]),
                         "")
        self.assertEqual(c4.decrypt("crypt4/" + VEC_SALT), PLAIN)
        self.assertEqual(c4.decrypt("crypt4/" + VEC_128, ["k2"]),
                         "https://sub.example.com/x")
        self.assertEqual(c4.decrypt("crypt4/!!!"), "")


class TestHeaders(unittest.TestCase):

    def test_user_agent_presets_and_custom(self):
        self.assertEqual(sm.request_headers({})["User-Agent"], sm.USER_AGENT)
        self.assertTrue(sm.request_headers({"user_agent": "sing-box"})
                        ["User-Agent"].startswith("sing-box/"))
        self.assertEqual(sm.request_headers({"user_agent": "MyApp/1"})
                         ["User-Agent"], "MyApp/1")
        self.assertEqual(sm._norm_user_agent("a\r\nX-Evil: 1"), "aX-Evil: 1")

    def test_hwid_only_when_enabled(self):
        self.assertNotIn("x-hwid", sm.request_headers({}))
        h = sm.request_headers({"send_hwid": True})
        self.assertRegex(h["x-hwid"], r"^[0-9a-f]{4}(-[0-9a-f]{4}){3}$")
        self.assertEqual(h["x-hwid"], sm.device_hwid())   # стабилен
        for k in ("x-device-os", "x-ver-os", "x-device-model"):
            self.assertIn(k, h)
        own = sm.request_headers({"send_hwid": True, "hwid": "my-id"})
        self.assertEqual(own["x-hwid"], "my-id")


class TestRefresh(unittest.TestCase):

    def setUp(self):
        self.sub = {"id": "sub-1", "name": "P", "url": "https://p/s",
                    "last_outbounds": 30}
        for name, value in (("get_subscription", self.sub),):
            p = mock.patch.object(sm, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        self.rec = mock.patch.object(sm, "_record_refresh").start()
        self.addCleanup(mock.patch.stopall)
        mock.patch("core.notify.event").start()

    def _two_nodes(self):
        return "\n".join(
            "vless://00000000-0000-4000-8000-00000000000%d@h%d.com:443"
            "?security=tls#n%d" % (i, i, i) for i in (1, 2))

    def test_shrunk_answer_is_not_applied(self):
        with mock.patch.object(sm, "_fetch", return_value=self._two_nodes()), \
                mock.patch("core.singbox_manager.get_singbox_manager") as mgr:
            res = sm.refresh_one("sub-1")
        self.assertFalse(res["ok"])
        self.assertTrue(res["shrunk"])
        mgr.return_value.save_config.assert_not_called()

    def test_force_accepts_shrunk(self):
        with mock.patch.object(sm, "_fetch", return_value=self._two_nodes()), \
                mock.patch("core.singbox_manager.get_singbox_manager") as mgr:
            mgr.return_value.save_config.return_value = {"ok": True}
            res = sm.refresh_one("sub-1", force=True)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["outbounds"], 2)

    def test_shrunk_rule(self):
        self.assertTrue(sm.shrunk(6, 2))
        self.assertFalse(sm.shrunk(5, 1))
        self.assertFalse(sm.shrunk(30, 3))

    def test_crypt4_url_and_lines(self):
        url = "https://sub.example.com/x"
        self.sub["url"] = "crypt4/" + VEC_128
        self.sub["crypt4_key"] = "k2"
        self.sub["last_outbounds"] = 0
        body = base64.b64encode(("happ://crypt4/" + VEC_SALT).encode())
        with mock.patch.object(sm, "_fetch",
                               return_value=body.decode()) as fetch, \
                mock.patch("core.singbox_manager.get_singbox_manager") as mgr:
            mgr.return_value.save_config.return_value = {"ok": True}
            res = sm.refresh_one("sub-1")
        self.assertEqual(fetch.call_args.args[0], url)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["outbounds"], 1)

    def test_undecryptable_url(self):
        self.sub["url"] = "crypt4/" + VEC_KEY
        res = sm.refresh_one("sub-1")
        self.assertFalse(res["ok"])
        self.assertIn("crypt4", res["error"])


if __name__ == "__main__":
    unittest.main()


class TestUrlChangeResetsShrink(unittest.TestCase):
    def test_new_url_forgets_previous_count(self):
        from core import subscription_manager as sm
        with mock.patch.object(sm, "_load_section", return_value={
                "s1": {"url": "https://a/x", "last_outbounds": 20}}) as ld, \
                mock.patch.object(sm, "_save_section") as sv, \
                mock.patch.object(sm, "get_refresher"):
            self.assertTrue(sm.update_subscription(
                "s1", url="https://b/y")["ok"])
        self.assertEqual(sv.call_args[0][0]["s1"]["last_outbounds"], 0)
        self.assertTrue(ld.called)

    def test_bad_url_changes_nothing(self):
        from core import subscription_manager as sm
        with mock.patch.object(sm, "_load_section", return_value={
                "s1": {"url": "https://a/x", "name": "A"}}), \
                mock.patch.object(sm, "_save_section") as sv:
            r = sm.update_subscription("s1", url="ftp://z", name="B")
        self.assertFalse(r["ok"])
        sv.assert_not_called()
