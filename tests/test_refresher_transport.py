# tests/test_refresher_transport.py
"""
Тесты задачи №7 (автообновление списков/подписок/пула + транспорт
скачивания):
  - list_updater: настройка lists.transport (get/set), прокидка
    транспорта в _fetch/refresh_one, зеркало в _fetch;
  - subscription_manager: поле transport у подписки (add/update,
    нормализация), прокидка в _fetch/fetch_outbounds/refresh_one;
  - server_pool: настройка пула transport, прокидка в fetch_outbounds
    при сборке.
"""

import io
import unittest
from unittest import mock

from core import list_updater as lu
from core import subscription_manager as sm
from core import server_pool as sp


class FakeCM:
    """Минимальный config_manager: get(*keys)/set(*args)/save/load."""

    def __init__(self):
        self.data = {}
        self.saved = 0

    def load(self):
        return self.data

    def get(self, *keys, default=None):
        value = self.data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, *args):
        keys, value = args[:-1], args[-1]
        target = self.data
        for k in keys[:-1]:
            target = target.setdefault(k, {})
        target[keys[-1]] = value

    def save(self):
        self.saved += 1
        return True


class _FakeResp:
    def __init__(self, data=b"example.com\n"):
        self._buf = io.BytesIO(data)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# ─────────────────── list_updater ────────────────────────────────


class TestListsTransportSetting(unittest.TestCase):

    def setUp(self):
        self.cm = FakeCM()
        self._p = mock.patch("core.config_manager.get_config_manager",
                             return_value=self.cm)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_roundtrip(self):
        self.assertEqual(lu.get_transport(), "")
        r = lu.set_transport("awg:wg0")
        self.assertTrue(r["ok"], r)
        self.assertEqual(lu.get_transport(), "awg:wg0")
        self.assertGreaterEqual(self.cm.saved, 1)

    def test_direct_normalized_to_empty(self):
        lu.set_transport("direct")
        self.assertEqual(lu.get_transport(), "")

    def test_unknown_rejected(self):
        r = lu.set_transport("tor:9050")
        self.assertFalse(r["ok"])
        self.assertEqual(lu.get_transport(), "")


class TestListsFetchTransport(unittest.TestCase):

    def test_fetch_passes_transport_and_mirror(self):
        url = "https://raw.githubusercontent.com/o/r/main/list.lst"
        with mock.patch("core.download_transport.urlopen_via",
                        return_value=_FakeResp(b"a.com\n")) as uv, \
             mock.patch("core.binary_installer.resolve_url",
                        return_value="https://mirror/" + url) as ru:
            text = lu._fetch(url, transport="singbox:proxy")
        self.assertEqual(text, "a.com\n")
        ru.assert_called_once_with(url)
        self.assertEqual(uv.call_args.args[0], "https://mirror/" + url)
        self.assertEqual(uv.call_args.kwargs.get("transport"),
                         "singbox:proxy")

    def test_transport_error_propagates_readable(self):
        # build_opener кидает RuntimeError с человекочитаемым текстом —
        # он должен дойти до вызывающего как есть (попадёт в last_error).
        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=RuntimeError(
                            "транспорт awg: нет активных интерфейсов")):
            with self.assertRaises(RuntimeError) as cm:
                lu._fetch("https://x/list.lst", transport="awg")
        self.assertIn("транспорт awg", str(cm.exception))

    def test_refresh_one_uses_subsystem_transport(self):
        # refresh_one должен брать транспорт из настройки lists.transport.
        item = {"id": "l1", "source_url": "https://x/l.lst",
                "domains": [], "cidrs": [], "_remote": {}}
        with mock.patch("core.named_lists.get",
                        return_value=item), \
             mock.patch("core.named_lists.update_fields"), \
             mock.patch.object(lu, "get_transport",
                               return_value="mihomo:main"), \
             mock.patch.object(lu, "_fetch",
                               return_value="a.com\n") as f:
            r = lu.refresh_one("l1")
        self.assertTrue(r["ok"], r)
        f.assert_called_once_with("https://x/l.lst",
                                  transport="mihomo:main")


# ─────────────────── subscription_manager ────────────────────────


class TestSubscriptionTransport(unittest.TestCase):

    def setUp(self):
        self.cm = FakeCM()
        self._patches = [
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.cm),
            mock.patch.object(sm, "get_refresher",
                              return_value=mock.Mock()),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_add_stores_transport(self):
        r = sm.add_subscription("Prov", "https://prov/sub",
                                transport="awg:wg0")
        self.assertTrue(r["ok"], r)
        sub = sm.get_subscription(r["id"])
        self.assertEqual(sub["transport"], "awg:wg0")

    def test_add_normalizes_bad_transport(self):
        r = sm.add_subscription("Prov", "https://prov/sub",
                                transport="tor:9050")
        sub = sm.get_subscription(r["id"])
        self.assertEqual(sub["transport"], "")

    def test_update_transport(self):
        r = sm.add_subscription("Prov", "https://prov/sub")
        sid = r["id"]
        self.assertEqual(sm.get_subscription(sid)["transport"], "")
        sm.update_subscription(sid, transport="singbox:server-pool")
        self.assertEqual(sm.get_subscription(sid)["transport"],
                         "singbox:server-pool")
        # Сброс на напрямую: 'direct' → ''
        sm.update_subscription(sid, transport="direct")
        self.assertEqual(sm.get_subscription(sid)["transport"], "")

    def test_refresh_one_passes_transport_to_fetch(self):
        r = sm.add_subscription("Prov", "https://prov/sub",
                                transport="mihomo:main")
        sid = r["id"]
        with mock.patch.object(sm, "_fetch",
                               side_effect=RuntimeError("сеть: x")) as f:
            res = sm.refresh_one(sid)
        self.assertFalse(res["ok"])
        f.assert_called_once_with("https://prov/sub",
                                  transport="mihomo:main")
        # Ошибка зафиксирована в last_error.
        self.assertEqual(sm.get_subscription(sid)["last_status"], "error")

    def test_fetch_outbounds_passes_transport(self):
        with mock.patch.object(sm, "_fetch",
                               return_value="vless://x") as f, \
             mock.patch.object(sm, "_parse_payload",
                               return_value=([{"type": "vless",
                                               "tag": "a"}], "uri")):
            r = sm.fetch_outbounds("https://src/x", "auto",
                                   transport="awg:wg0")
        self.assertTrue(r["ok"])
        f.assert_called_once_with("https://src/x", transport="awg:wg0")

    def test_fetch_uses_urlopen_via(self):
        with mock.patch("core.download_transport.urlopen_via",
                        return_value=_FakeResp(b"data")) as uv, \
             mock.patch("core.binary_installer.resolve_url",
                        side_effect=lambda u: u):
            sm._fetch("https://prov/sub", transport="awg:wg0")
        self.assertEqual(uv.call_args.kwargs.get("transport"), "awg:wg0")


# ─────────────────── server_pool ─────────────────────────────────


class TestPoolTransport(unittest.TestCase):

    def setUp(self):
        self.cm = FakeCM()
        self._patches = [
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.cm),
            mock.patch.object(sp, "get_pool_refresher",
                              return_value=mock.Mock()),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_settings_roundtrip(self):
        self.assertEqual(sp.get_settings()["transport"], "")
        sp.update_settings(transport="singbox:proxy")
        self.assertEqual(sp.get_settings()["transport"], "singbox:proxy")
        sp.update_settings(transport="direct")
        self.assertEqual(sp.get_settings()["transport"], "")

    def test_unknown_transport_not_saved(self):
        sp.update_settings(transport="tor:9050")
        self.assertEqual(sp.get_settings()["transport"], "")

    def test_refresh_pool_passes_transport(self):
        sp.add_source("Src", "https://src/x")
        sp.update_settings(transport="awg:wg0")
        with mock.patch("core.subscription_manager.fetch_outbounds",
                        return_value={"ok": True, "outbounds": [],
                                      "format": "uri", "error": ""}) as fo, \
             mock.patch.object(sp, "_load_cache", return_value={}), \
             mock.patch.object(sp, "_save_cache"):
            res = sp.refresh_pool()
        # Источник пуст и кэша нет → ok=False, но фетч был с транспортом.
        self.assertFalse(res["ok"])
        fo.assert_called_once()
        self.assertEqual(fo.call_args.kwargs.get("transport"), "awg:wg0")


if __name__ == "__main__":
    unittest.main()
