# tests/test_mihomo.py
"""
Тесты mihomo-подсистемы: валидация YAML, CRUD-менеджер (с временным
config_dir и моками), детект платформы.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import mihomo_manager
from core.mihomo_manager import validate_yaml
from core.mihomo_platform import (
    MihomoPlatform, detect_mihomo_platform,
)


MINIMAL_YAML = """\
proxies:
  - name: "vpn-1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: secret
"""


class FakePlatform(MihomoPlatform):
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


class TestValidateYaml(unittest.TestCase):

    def test_empty(self):
        self.assertTrue(validate_yaml(""))

    def test_minimal_ok(self):
        self.assertEqual(validate_yaml(MINIMAL_YAML), [])

    def test_no_proxies_is_warning(self):
        errs = validate_yaml("port: 7890\n")
        self.assertTrue(any("proxies" in e for e in errs))

    def test_garbage_not_a_map(self):
        # Скаляр верхнего уровня — не map.
        errs = validate_yaml("just-a-string")
        self.assertTrue(errs)


class TestPlatform(unittest.TestCase):

    def test_detect_returns_platform(self):
        p = detect_mihomo_platform()
        self.assertIsInstance(p, MihomoPlatform)
        self.assertTrue(p.binary_path().endswith("mihomo"))

    def test_config_path_yaml(self):
        p = detect_mihomo_platform()
        self.assertTrue(p.config_path("foo").endswith("foo.yaml"))


class TestManagerCRUD(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mihomo-test-")
        self.platform = FakePlatform(self.tmpdir)
        self.mgr = mihomo_manager.MihomoManager()
        self._patches = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary",
                              return_value=os.path.join(
                                  self.platform.binary_dir, "mihomo")),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_list_empty(self):
        self.assertEqual(self.mgr.list_configs(), [])

    def test_save_and_list(self):
        r = self.mgr.save_config("vpn", text=MINIMAL_YAML)
        self.assertTrue(r["ok"], r)
        names = [c["name"] for c in self.mgr.list_configs()]
        self.assertIn("vpn", names)

    def test_save_bad_name(self):
        r = self.mgr.save_config("bad name!", text=MINIMAL_YAML)
        self.assertFalse(r["ok"])

    def test_save_empty(self):
        r = self.mgr.save_config("vpn", text="")
        self.assertFalse(r["ok"])

    def test_get_config(self):
        self.mgr.save_config("vpn", text=MINIMAL_YAML)
        r = self.mgr.get_config("vpn")
        self.assertTrue(r["ok"])
        self.assertIn("proxies", r["text"])

    def test_delete(self):
        self.mgr.save_config("vpn", text=MINIMAL_YAML)
        r = self.mgr.delete_config("vpn")
        self.assertTrue(r["ok"])
        self.assertEqual(self.mgr.list_configs(), [])

    def test_up_missing_config(self):
        r = self.mgr.up("nonexistent")
        self.assertFalse(r["ok"])

    def test_down_when_not_running(self):
        r = self.mgr.down("vpn")
        self.assertTrue(r["ok"])
        self.assertTrue(r.get("noop"))


if __name__ == "__main__":
    unittest.main()


from core import mihomo_installer as mi
from core import binary_installer as _bi
import gzip as _gzip


class TestMihomoArchMap(unittest.TestCase):

    def test_known(self):
        self.assertEqual(mi.map_arch("x86_64"), "amd64")
        self.assertEqual(mi.map_arch("aarch64"), "arm64")
        self.assertEqual(mi.map_arch("armv7"), "armv7")
        self.assertEqual(mi.map_arch("mipsel-softfloat"), "mipsle-softfloat")
        self.assertEqual(mi.map_arch("mips-softfloat"), "mips-softfloat")

    def test_unknown(self):
        self.assertEqual(mi.map_arch("riscv64"), "")
        self.assertEqual(mi.map_arch(""), "")


class TestSelectAsset(unittest.TestCase):

    ASSETS = [
        {"name": "mihomo-linux-amd64-compatible-v1.18.0.gz",
         "browser_download_url": "u1"},
        {"name": "mihomo-linux-amd64-v1.18.0.gz",
         "browser_download_url": "u2"},
        {"name": "mihomo-linux-arm64-v1.18.0.gz",
         "browser_download_url": "u3"},
        {"name": "mihomo-linux-mipsle-softfloat-v1.18.0.gz",
         "browser_download_url": "u4"},
        {"name": "mihomo-linux-amd64-v1.18.0.deb"},
    ]

    def test_amd64_exact_not_compatible(self):
        r = mi.select_asset(self.ASSETS, "amd64")
        self.assertTrue(r["ok"])
        self.assertEqual(r["name"], "mihomo-linux-amd64-v1.18.0.gz")
        self.assertEqual(r["url"], "u2")

    def test_arm64(self):
        r = mi.select_asset(self.ASSETS, "arm64")
        self.assertEqual(r["url"], "u3")

    def test_mipsle(self):
        r = mi.select_asset(self.ASSETS, "mipsle-softfloat")
        self.assertEqual(r["url"], "u4")

    def test_missing_arch(self):
        r = mi.select_asset(self.ASSETS, "armv7")
        self.assertFalse(r["ok"])
        self.assertIn("candidates", r)

    def test_empty_token(self):
        self.assertFalse(mi.select_asset(self.ASSETS, "")["ok"])


from core.mihomo_detector import MihomoDetector


class TestGvisorDetect(unittest.TestCase):
    """Детект gvisor у бинаря mihomo (best-effort; страховка — фолбэк -t)."""

    def _det(self):
        return MihomoDetector()

    def test_default_true_when_no_tags(self):
        # Обычный вывод `mihomo -v` без строки тегов → считаем gvisor есть.
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="Mihomo Meta v1.18.0 linux amd64 with go"):
            self.assertTrue(self._det()._detect_gvisor("/bin/mihomo"))

    def test_true_when_gvisor_mentioned(self):
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="... Tags: with_gvisor,with_quic"):
            self.assertTrue(self._det()._detect_gvisor("/bin/mihomo"))

    def test_false_when_tags_without_gvisor(self):
        with mock.patch("core.mihomo_detector._cmd_out",
                        return_value="Tags: with_quic,with_utls"):
            self.assertFalse(self._det()._detect_gvisor("/bin/mihomo"))


class TestExtractGz(unittest.TestCase):

    def test_gunzip(self):
        with tempfile.TemporaryDirectory() as d:
            gz = os.path.join(d, "mihomo.gz")
            with _gzip.open(gz, "wb") as f:
                f.write(b"\x7fELF-fake-binary")
            out = os.path.join(d, "out", "mihomo")
            r = _bi.extract_gz(gz, out)
            self.assertTrue(r["ok"], r)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"\x7fELF-fake-binary")

    def test_bad_gz(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.gz")
            with open(bad, "wb") as f:
                f.write(b"not gzip at all")
            r = _bi.extract_gz(bad, os.path.join(d, "out"))
            self.assertFalse(r["ok"])
