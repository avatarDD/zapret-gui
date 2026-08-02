# tests/test_opera_proxy_chain.py
"""
Подключение opera-proxy как upstream в sing-box / mihomo
(core/opera_proxy_chain.py).

Своим методом маршрутизации opera-proxy быть не может — она даёт только
локальный порт, а правило единого слоя заворачивает трафик в интерфейс.
Единственный рабочий путь — прокси внутри движка, и здесь проверяется
именно он.
"""

import json
import unittest
from unittest import mock

from core import opera_proxy_chain as chain
from core.clash_yaml import parse_yaml


class FakeSingboxManager:
    def __init__(self, cfg):
        self.cfg = cfg
        self.saved = None

    def get_config(self, name):
        if name != "main":
            return {"ok": False, "error": "Конфиг не найден"}
        return {"ok": True, "name": name, "parsed": json.loads(
            json.dumps(self.cfg)), "text": json.dumps(self.cfg)}

    def save_config(self, name, text="", parsed=None):
        self.saved = text
        self.cfg = json.loads(text)
        return {"ok": True}


class FakeMihomoManager:
    def __init__(self, text):
        self.text = text
        self.saved = None

    def get_config(self, name):
        if name != "meta":
            return {"ok": False, "error": "Конфиг не найден"}
        return {"ok": True, "name": name, "text": self.text}

    def save_config(self, name, text=""):
        self.saved = text
        self.text = text
        return {"ok": True}


def _settings(socks=False, running=True, host="127.0.0.1", port=18080):
    return {"host": host, "port": port, "socks": socks,
            "running": running, "listening": running}


class TestBuilders(unittest.TestCase):

    def test_singbox_http_outbound(self):
        ob = chain.singbox_outbound("opera-proxy", "127.0.0.1", 18080, False)
        self.assertEqual(ob["type"], "http")
        self.assertEqual(ob["server_port"], 18080)
        self.assertNotIn("version", ob)

    def test_singbox_socks_outbound_pins_v5(self):
        """Без version sing-box возьмёт SOCKS4, а opera-proxy умеет только 5."""
        ob = chain.singbox_outbound("opera-proxy", "127.0.0.1", 18080, True)
        self.assertEqual(ob["type"], "socks")
        self.assertEqual(ob["version"], "5")

    def test_mihomo_proxy_types(self):
        self.assertEqual(
            chain.mihomo_proxy("opera", "127.0.0.1", 1080, True)["type"],
            "socks5")
        self.assertEqual(
            chain.mihomo_proxy("opera", "127.0.0.1", 1080, False)["type"],
            "http")

    def test_unknown_engine_rejected(self):
        r = chain.attach("redsocks", "main")
        self.assertFalse(r["ok"])

    def test_config_required(self):
        r = chain.attach("singbox", "")
        self.assertFalse(r["ok"])


class TestAttachSingbox(unittest.TestCase):

    BASE = {"outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": [{"domain_suffix": ["ya.ru"],
                                 "outbound": "direct"}]}}

    def _attach(self, cfg=None, **kw):
        mgr = FakeSingboxManager(cfg if cfg is not None
                                 else json.loads(json.dumps(self.BASE)))
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr), \
             mock.patch.object(chain, "_settings",
                               return_value=_settings(**kw)):
            res = chain.attach("singbox", "main")
        return res, mgr

    def test_adds_outbound_and_bypass_rule(self):
        res, mgr = self._attach()
        self.assertTrue(res["ok"])
        tags = [o["tag"] for o in mgr.cfg["outbounds"]]
        self.assertIn("opera-proxy", tags)
        # Правило обхода должно стоять ПЕРВЫМ: ниже обычно лежит
        # «всё остальное → прокси», оно бы перехватило sec-tunnel.com.
        self.assertEqual(mgr.cfg["route"]["rules"][0],
                         {"domain_suffix": ["sec-tunnel.com"],
                          "outbound": "direct"})
        self.assertTrue(res["bypass_added"])

    def test_repeat_updates_instead_of_duplicating(self):
        """Кнопку можно жать повторно — bind мог поменяться."""
        res, mgr = self._attach()
        self.assertFalse(res["replaced"])
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr), \
             mock.patch.object(chain, "_settings",
                               return_value=_settings(port=19999)):
            res2 = chain.attach("singbox", "main")
        self.assertTrue(res2["ok"])
        self.assertTrue(res2["replaced"])
        opera = [o for o in mgr.cfg["outbounds"] if o["tag"] == "opera-proxy"]
        self.assertEqual(len(opera), 1)
        self.assertEqual(opera[0]["server_port"], 19999)
        # Второе правило обхода не появляется.
        rules = mgr.cfg["route"]["rules"]
        self.assertEqual(
            sum(1 for r in rules
                if r.get("domain_suffix") == ["sec-tunnel.com"]), 1)
        self.assertFalse(res2["bypass_added"])

    def test_stopped_proxy_is_reported_as_warning_not_error(self):
        res, _mgr = self._attach(running=False)
        self.assertTrue(res["ok"])
        self.assertTrue(any("не запущен" in w for w in res["warnings"]))

    def test_missing_config_is_an_error(self):
        mgr = FakeSingboxManager(json.loads(json.dumps(self.BASE)))
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr), \
             mock.patch.object(chain, "_settings", return_value=_settings()):
            res = chain.attach("singbox", "nope")
        self.assertFalse(res["ok"])
        self.assertIsNone(mgr.saved)


class TestAttachMihomo(unittest.TestCase):

    BASE = ("proxies:\n"
            "  - name: existing\n"
            "    type: http\n"
            "    server: 10.0.0.1\n"
            "    port: 8080\n"
            "rules:\n"
            "  - MATCH,DIRECT\n")

    def _attach(self, text=None, **kw):
        mgr = FakeMihomoManager(self.BASE if text is None else text)
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch.object(chain, "_settings",
                               return_value=_settings(**kw)):
            res = chain.attach("mihomo", "meta")
        return res, mgr

    def test_appends_proxy_and_bypass_rule(self):
        res, mgr = self._attach()
        self.assertTrue(res["ok"])
        cfg = parse_yaml(mgr.text)
        names = [p["name"] for p in cfg["proxies"]]
        self.assertIn("opera-proxy", names)
        self.assertIn("existing", names)      # чужие прокси не потеряны
        self.assertEqual(cfg["rules"][0], "DOMAIN-SUFFIX,sec-tunnel.com,DIRECT")
        self.assertEqual(cfg["rules"][-1], "MATCH,DIRECT")

    def test_socks_mode_writes_socks5(self):
        _res, mgr = self._attach(socks=True)
        cfg = parse_yaml(mgr.text)
        opera = next(p for p in cfg["proxies"] if p["name"] == "opera-proxy")
        self.assertEqual(opera["type"], "socks5")

    def test_repeat_updates_single_entry(self):
        _res, mgr = self._attach()
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch.object(chain, "_settings",
                               return_value=_settings(port=19999)):
            res2 = chain.attach("mihomo", "meta")
        self.assertTrue(res2["ok"])
        cfg = parse_yaml(mgr.text)
        opera = [p for p in cfg["proxies"] if p["name"] == "opera-proxy"]
        self.assertEqual(len(opera), 1)
        self.assertEqual(opera[0]["port"], 19999)
        self.assertEqual(
            [r for r in cfg["rules"]
             if r == "DOMAIN-SUFFIX,sec-tunnel.com,DIRECT"].__len__(), 1)


if __name__ == "__main__":
    unittest.main()
