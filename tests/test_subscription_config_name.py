# tests/test_subscription_config_name.py
"""
Регрессия issue #451: обновление подписки sing-box всегда падало на
валидации имени конфига. sid = «sub-» + 8 hex (12 символов), а имя
«imported-subscription-<sid>» выходило 34 символа при лимите 32 в
singbox_manager.save_config(). Теперь имя «imported-sub-<sid>» (25).

refresh_one() прогоняется через настоящий SingboxManager.save_config
на временном каталоге — проверяется, что файл реально пишется.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import singbox_manager
from core import subscription_manager as sm
from tests.test_refresher_transport import FakeCM
from tests.test_singbox_manager_lifecycle import FakePlatform


SUB_TEXT = "\n".join([
    "trojan://pass1@a.example:443?sni=a.example#A",
    "trojan://pass2@b.example:443?sni=b.example#B",
])


class TestConfigName(unittest.TestCase):

    def test_name_fits_singbox_limit_for_any_sid(self):
        # Самый длинный sid, который выдаёт add_subscription().
        sid = "sub-" + "f" * 8
        name = sm._config_name_for(sid)
        self.assertEqual(name, "imported-sub-sub-ffffffff")
        self.assertLessEqual(len(name), 32)
        self.assertTrue(singbox_manager._valid_name(name))

    def test_add_subscription_sid_shape(self):
        # Если формат sid поменяется, имя конфига должно остаться ≤ 32.
        cm = FakeCM()
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=cm), \
             mock.patch.object(sm, "get_refresher",
                               return_value=mock.Mock()):
            sid = sm.add_subscription("P", "https://prov/sub")["id"]
        self.assertTrue(singbox_manager._valid_name(sm._config_name_for(sid)))


class TestRefreshSavesConfig(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="sub-name-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = singbox_manager.SingboxManager()
        self.cm = FakeCM()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(singbox_manager, "get_singbox_manager",
                              return_value=self.mgr),
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
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_refresh_one_saves_config(self):
        sid = sm.add_subscription("P", "https://prov/sub")["id"]
        with mock.patch.object(sm, "_fetch", return_value=SUB_TEXT):
            res = sm.refresh_one(sid)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["config"], "imported-sub-" + sid)
        self.assertEqual(res["outbounds"], 2)
        self.assertTrue(self.mgr.get_config(res["config"]).get("ok"))
        sub = sm.get_subscription(sid)
        self.assertEqual(sub["last_status"], "ok")
        self.assertEqual(sub["last_error"], "")

    def test_remove_subscription_deletes_config(self):
        sid = sm.add_subscription("P", "https://prov/sub")["id"]
        with mock.patch.object(sm, "_fetch", return_value=SUB_TEXT):
            name = sm.refresh_one(sid)["config"]
        files = os.listdir(self.platform.config_dir)
        self.assertTrue(any(name in f for f in files), files)
        sm.remove_subscription(sid)
        files = os.listdir(self.platform.config_dir)
        self.assertFalse(any(name in f for f in files), files)


if __name__ == "__main__":
    unittest.main()
