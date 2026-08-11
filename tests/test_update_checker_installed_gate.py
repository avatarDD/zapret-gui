# tests/test_update_checker_installed_gate.py
"""Регрессия discussion #102: «Обновления» предлагали обновить то, чего нет.

`has_update` считался как «в релизе есть версия И она не равна
установленной». У НЕустановленного бинарника версия пустая, поэтому
неравенство выполнялось всегда — и таблица показывала «← доступно» с
кнопкой «Обновить» для sing-box и mihomo, которых на роутере нет.

Проверяем оба слоя: сами инсталляторы и общий гейт в check_all().
"""

import unittest
from unittest import mock


class TestInstallerGate(unittest.TestCase):

    def test_singbox_no_update_when_not_installed(self):
        from core.singbox_installer import get_singbox_installer
        inst = get_singbox_installer()
        with mock.patch.object(type(inst), "get_installed_version",
                               return_value={"installed": False,
                                             "version": ""}), \
             mock.patch.object(type(inst), "get_manifest",
                               return_value={"tag": "singbox-bin-v1.13.16",
                                             "sing_box": {"version": "1.13.16"}}):
            res = inst.check_for_updates()

        self.assertTrue(res["ok"])
        self.assertFalse(res["has_update"])
        self.assertEqual(res["latest"]["version"], "1.13.16")

    def test_singbox_update_when_installed_and_older(self):
        from core.singbox_installer import get_singbox_installer
        inst = get_singbox_installer()
        with mock.patch.object(type(inst), "get_installed_version",
                               return_value={"installed": True,
                                             "version": "1.13.10"}), \
             mock.patch.object(type(inst), "get_manifest",
                               return_value={"tag": "singbox-bin-v1.13.16",
                                             "sing_box": {"version": "1.13.16"}}):
            res = inst.check_for_updates()

        self.assertTrue(res["has_update"])

    def test_mihomo_no_update_when_not_installed(self):
        from core.mihomo_installer import get_mihomo_installer
        inst = get_mihomo_installer()
        with mock.patch.object(type(inst), "get_installed_version",
                               return_value={"installed": False,
                                             "version": ""}), \
             mock.patch.object(type(inst), "get_release",
                               return_value={"tag_name": "v1.19.13"}):
            res = inst.check_for_updates()

        self.assertTrue(res["ok"])
        self.assertFalse(res["has_update"])

    def test_mihomo_update_when_installed_and_older(self):
        from core.mihomo_installer import get_mihomo_installer
        inst = get_mihomo_installer()
        with mock.patch.object(type(inst), "get_installed_version",
                               return_value={"installed": True,
                                             "version": "1.19.0"}), \
             mock.patch.object(type(inst), "get_release",
                               return_value={"tag_name": "v1.19.13"}):
            res = inst.check_for_updates()

        self.assertTrue(res["has_update"])


class TestCheckAllGate(unittest.TestCase):
    """Страховка на уровне страницы: has_update без installed не выживает."""

    def test_check_all_drops_update_for_missing_binaries(self):
        import core.update_checker as uc

        rows = {
            "_check_zapret": {"name": "zapret2", "installed": True,
                              "has_update": True},
            "_check_singbox": {"name": "singbox", "installed": False,
                               "has_update": True},
            "_check_mihomo": {"name": "mihomo", "installed": False,
                              "has_update": True},
            "_check_awg": {"name": "awg", "installed": False,
                           "has_update": False},
            "_check_gui": {"name": "gui", "installed": True,
                           "has_update": False},
            "_check_usque": {"name": "usque", "installed": False,
                             "has_update": False},
            "_check_tgwsproxy": {"name": "tgwsproxy", "installed": False,
                                 "has_update": False},
            "_check_tgproto": {"name": "tgproto", "installed": False,
                               "has_update": False},
            "_check_opera": {"name": "opera", "installed": False,
                             "has_update": False},
        }

        patches = [mock.patch.object(uc, fn, return_value=dict(row))
                   for fn, row in rows.items()]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

        result = uc.check_all()

        by_name = {r["name"]: r for r in result["results"]}
        self.assertFalse(by_name["singbox"]["has_update"])
        self.assertFalse(by_name["mihomo"]["has_update"])
        self.assertTrue(by_name["zapret2"]["has_update"])
        self.assertEqual(result["updates_count"], 1)


if __name__ == "__main__":
    unittest.main()
