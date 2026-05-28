# tests/test_singbox_manager_lifecycle.py
"""
Lifecycle-тесты для core/singbox_manager.py.

Используем временный config_dir, мокаем subprocess и spawn для
тестов up/down без реального sing-box.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import singbox_manager
from core.singbox_platform import SingboxPlatform


MINIMAL_CONFIG = json.dumps({
    "outbounds": [
        {"type": "direct", "tag": "direct"},
    ],
})


class FakePlatform(SingboxPlatform):
    """Тестовый SingboxPlatform с временными путями."""

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


class TestSingboxManagerCRUD(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="sb-mgr-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = singbox_manager.SingboxManager()
        # Подмена платформы — все пути в /tmp.
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary",
                              return_value=os.path.join(
                                  self.platform.binary_dir, "sing-box")),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_list_empty(self):
        self.assertEqual(self.mgr.list_configs(), [])

    def test_save_valid_config(self):
        r = self.mgr.save_config("my-vpn", text=MINIMAL_CONFIG)
        self.assertTrue(r["ok"])
        self.assertTrue(os.path.isfile(
            os.path.join(self.platform.config_dir, "my-vpn.json")))

    def test_save_invalid_name(self):
        r = self.mgr.save_config("bad/name", text=MINIMAL_CONFIG)
        self.assertFalse(r["ok"])
        self.assertIn("Имя", r["error"])

    def test_save_empty_text(self):
        r = self.mgr.save_config("my-vpn", text="")
        self.assertFalse(r["ok"])

    def test_save_invalid_json(self):
        r = self.mgr.save_config("my-vpn", text="not json")
        self.assertFalse(r["ok"])

    def test_save_missing_outbounds_section(self):
        # Без обязательной секции outbounds — ошибка
        r = self.mgr.save_config("my-vpn", text='{"log":{}}')
        self.assertFalse(r["ok"])
        self.assertIn("outbounds", r["error"])

    def test_save_via_parsed(self):
        parsed = {"outbounds": [{"type": "direct", "tag": "d"}]}
        r = self.mgr.save_config("my-vpn", parsed=parsed)
        self.assertTrue(r["ok"])

    def test_get_after_save(self):
        self.mgr.save_config("my-vpn", text=MINIMAL_CONFIG)
        r = self.mgr.get_config("my-vpn")
        self.assertTrue(r["ok"])
        self.assertEqual(r["name"], "my-vpn")
        self.assertEqual(r["parsed"]["outbounds"][0]["type"], "direct")

    def test_get_nonexistent(self):
        r = self.mgr.get_config("never-saved")
        self.assertFalse(r["ok"])

    def test_get_invalid_name(self):
        r = self.mgr.get_config("bad/name")
        self.assertFalse(r["ok"])

    def test_list_after_saves(self):
        self.mgr.save_config("a", text=MINIMAL_CONFIG)
        self.mgr.save_config("b", text=MINIMAL_CONFIG)
        cfgs = self.mgr.list_configs()
        names = sorted(c["name"] for c in cfgs)
        self.assertEqual(names, ["a", "b"])
        for c in cfgs:
            self.assertFalse(c["running"])

    def test_delete_existing(self):
        self.mgr.save_config("a", text=MINIMAL_CONFIG)
        r = self.mgr.delete_config("a")
        self.assertTrue(r["ok"])
        self.assertEqual(self.mgr.list_configs(), [])

    def test_delete_nonexistent_is_noop(self):
        r = self.mgr.delete_config("never-saved")
        self.assertTrue(r["ok"])

    def test_delete_invalid_name(self):
        r = self.mgr.delete_config("bad/name")
        self.assertFalse(r["ok"])

    def test_delete_running_blocked(self):
        # is_running → True → отказ
        self.mgr.save_config("a", text=MINIMAL_CONFIG)
        with mock.patch.object(self.mgr, "is_running", return_value=True):
            r = self.mgr.delete_config("a")
        self.assertFalse(r["ok"])
        self.assertIn("запущен", r["error"])


class TestSingboxManagerLifecycle(unittest.TestCase):
    """up/down/restart с мокированным subprocess."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="sb-life-test-")
        self.platform = FakePlatform(self.tmpdir)
        # Создаём fake sing-box (просто пустой файл — мы его не выполняем,
        # subprocess мокается).
        self.binary = os.path.join(self.platform.binary_dir, "sing-box")
        open(self.binary, "w").close()

        self.mgr = singbox_manager.SingboxManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary",
                              return_value=self.binary),
        ]
        for p in self._patches:
            p.start()

        # Подготавливаем конфиг
        self.mgr.save_config("my-vpn", text=MINIMAL_CONFIG)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_status_not_running(self):
        s = self.mgr.status("my-vpn")
        self.assertFalse(s["active"])
        self.assertIsNone(s["pid"])

    def test_is_running_false_no_pid(self):
        self.assertFalse(self.mgr.is_running("my-vpn"))

    def test_up_invalid_name(self):
        r = self.mgr.up("bad/name")
        self.assertFalse(r["ok"])

    def test_up_missing_binary(self):
        with mock.patch.object(self.mgr, "_binary", return_value=""):
            r = self.mgr.up("my-vpn")
        self.assertFalse(r["ok"])
        self.assertIn("не установлен", r["error"])

    def test_up_missing_config(self):
        r = self.mgr.up("never-saved")
        self.assertFalse(r["ok"])
        self.assertIn("не найден", r["error"])

    def test_up_check_fails_blocks_start(self):
        # sing-box check вернул rc!=0 → up отказывается стартовать
        with mock.patch.object(singbox_manager, "_run",
                                return_value=(1, "", "syntax error")):
            r = self.mgr.up("my-vpn")
        self.assertFalse(r["ok"])
        self.assertIn("check", r["error"])

    def test_up_then_down(self):
        # check OK, Popen возвращает fake-процесс с pid=12345,
        # poll() возвращает None (жив).
        fake_popen = mock.MagicMock()
        fake_popen.pid = 12345
        fake_popen.poll.return_value = None

        with mock.patch.object(singbox_manager, "_run",
                                return_value=(0, "", "")):
            with mock.patch("subprocess.Popen",
                             return_value=fake_popen):
                with mock.patch("time.sleep"):  # не ждём в тестах
                    r = self.mgr.up("my-vpn")

        self.assertTrue(r["ok"])
        self.assertEqual(r["pid"], 12345)

        # PID-файл должен быть записан
        pid_file = self.platform.pid_path("my-vpn")
        self.assertTrue(os.path.isfile(pid_file))
        with open(pid_file) as f:
            self.assertEqual(int(f.read()), 12345)

        # down: kill TERM + проверяет is_alive (мокаем — труп)
        with mock.patch("os.kill"):
            with mock.patch.object(singbox_manager, "_pid_alive",
                                    return_value=False):
                with mock.patch("time.sleep"):
                    r = self.mgr.down("my-vpn")
        self.assertTrue(r["ok"])
        # PID-файл удалён
        self.assertFalse(os.path.isfile(pid_file))

    def test_up_process_dies_immediately(self):
        # Popen возвращает процесс, который сразу падает (poll → exit=1)
        fake_popen = mock.MagicMock()
        fake_popen.pid = 99999
        fake_popen.poll.return_value = 1
        fake_popen.returncode = 1

        with mock.patch.object(singbox_manager, "_run",
                                return_value=(0, "", "")):
            with mock.patch("subprocess.Popen",
                             return_value=fake_popen):
                with mock.patch("time.sleep"):
                    r = self.mgr.up("my-vpn")

        self.assertFalse(r["ok"])
        self.assertIn("упал", r["error"])

    def test_down_when_not_running(self):
        # PID-файла нет; pgrep тоже ничего не находит
        with mock.patch.object(singbox_manager, "_run",
                                return_value=(1, "", "")):
            r = self.mgr.down("my-vpn")
        self.assertTrue(r["ok"])
        # noop когда нет процесса
        self.assertTrue(r.get("noop") is True)


class TestValidateViaBinary(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="sb-validate-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.binary = os.path.join(self.platform.binary_dir, "sing-box")
        open(self.binary, "w").close()

        self.mgr = singbox_manager.SingboxManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary",
                              return_value=self.binary),
        ]
        for p in self._patches:
            p.start()
        self.mgr.save_config("my-vpn", text=MINIMAL_CONFIG)

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_invalid_name(self):
        r = self.mgr.validate_via_binary("bad/name")
        self.assertFalse(r["ok"])

    def test_no_binary(self):
        with mock.patch.object(self.mgr, "_binary", return_value=""):
            r = self.mgr.validate_via_binary("my-vpn")
        self.assertFalse(r["ok"])
        self.assertIn("не установлен", r["error"])

    def test_missing_config(self):
        r = self.mgr.validate_via_binary("never-saved")
        self.assertFalse(r["ok"])

    def test_check_passes(self):
        with mock.patch.object(singbox_manager, "_run",
                                return_value=(0, "ok", "")):
            r = self.mgr.validate_via_binary("my-vpn")
        self.assertTrue(r["ok"])

    def test_check_fails(self):
        with mock.patch.object(singbox_manager, "_run",
                                return_value=(1, "", "bad config")):
            r = self.mgr.validate_via_binary("my-vpn")
        self.assertFalse(r["ok"])


class TestValidName(unittest.TestCase):
    """Pure-helper _valid_name из singbox_manager."""

    def test_valid(self):
        for n in ("my-vpn", "test1", "config_v2", "a.b.c"):
            self.assertTrue(singbox_manager._valid_name(n), n)

    def test_invalid(self):
        for n in ("", "a/b", "with space", "bad!", "x" * 33):
            self.assertFalse(singbox_manager._valid_name(n), n)


if __name__ == "__main__":
    unittest.main()
