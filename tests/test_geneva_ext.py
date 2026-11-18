"""x-стратегии geneva_c 2.0 и фейки zapret2 (core/geneva_ext): договор
с Zapret2_AutoTuner."""

import json
import os
import tempfile
import unittest
from unittest import mock

from core import geneva_ext as gx

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data",
                    "geneva")

X = "[TCP:flags:PA]-xfake{blob=z2_tls_clienthello_vk_com;ttl=3}-| \\/"
X2 = ("[TCP:flags:PA]-xfake{blob=z2_tls_alert;ttl=3}"
      "(xsplit{pos=2;seqovl=#z2_tls_alert},)-| \\/")
PLAIN = "[TCP:flags:PA]-fragment{tcp:-1:False}-| \\/"


class TestNeedsExt(unittest.TestCase):

    def test_x_actions_and_triggers(self):
        for s in (X, X2,
                  "[FLOW:n:a]-xwhen{iff=L7:payload:tls_client_hello}"
                  "(xfake{blob=fake_default_tls},)-| \\/",
                  "[L7:payload:tls_client_hello]-drop-| \\/",
                  "[META:x:1]-drop-| \\/",
                  "[TCP:flags:PA]-duplicate(xfake{blob=fake_default_tls},)"
                  "-| \\/"):
            self.assertTrue(gx.needs_ext(s), s)

    def test_geneva_actions(self):
        for s in (PLAIN, "\\/", "",
                  "[TCP:flags:PA]-tamper{TCP:flags:replace:FRAPUEN}-| \\/",
                  "[TCP:options-mss:]-drop-| \\/", None):
            self.assertFalse(gx.needs_ext(s), s)


class TestBlobs(unittest.TestCase):

    def test_refs(self):
        self.assertEqual(gx.blob_refs(X), ["z2_tls_clienthello_vk_com"])
        self.assertEqual(gx.blob_refs(X2), ["z2_tls_alert"])
        self.assertEqual(gx.blob_refs(PLAIN), [])
        # «xz2_…» — не ссылка на фейк
        self.assertEqual(gx.blob_refs("[TCP:flags:PA]-xfake{blob=xz2_a}-|"),
                         [])

    def test_names_match_autotuner(self):
        """Тот же файл — в Zapret2_AutoTuner (GenevaBlobsTests)."""
        with open(os.path.join(DATA, "z2-blob-names.json"),
                  encoding="utf-8") as f:
            names = json.load(f)["names"]
        self.assertGreater(len(names), 40)
        for fn, name in names.items():
            self.assertEqual(gx.blob_name(fn), name, fn)

    def test_files(self):
        with tempfile.TemporaryDirectory() as d:
            def put(name, data=b"\x16\x03"):
                with open(os.path.join(d, name), "wb") as f:
                    f.write(data)
            put("tls_alert.bin")
            put("Tls-Alert.bin")                    # то же имя: берётся первый
            put("empty.bin", b"")
            put("readme.txt")
            put("q" * 70 + ".bin")                  # имя длиннее 63
            put("big.bin", b"\0" * (gx.BLOB_FILE_MAX + 1))
            put(".bin")                             # пустое имя
            put("UPPER.BIN")                        # не *.bin
            os.symlink(os.path.join(d, "tls_alert.bin"),
                       os.path.join(d, "link.bin"))
            files = gx.blob_files(d)
            self.assertEqual(files, [("z2_tls_alert",
                                      os.path.join(d, "Tls-Alert.bin"))])
            self.assertEqual(gx.blob_files(os.path.join(d, "nope")), [])

    def test_loaded_and_fits_args(self):
        args = ["geneva", "run", "--ext", "--ext-blob",
                "z2_tls_alert:@/f/tls_alert.bin", "-f", "s"]
        self.assertEqual(gx.loaded_blobs(args), {"z2_tls_alert"})
        self.assertTrue(gx.fits_args(PLAIN, []))
        self.assertTrue(gx.fits_args(X2, args))
        self.assertFalse(gx.fits_args(X, args))          # фейка нет
        self.assertFalse(gx.fits_args(X2, ["geneva", "run", "-f", "s"]))

    def test_fake_dir_follows_settings(self):
        with mock.patch("core.config_manager.get_config_manager") as g:
            g.return_value.get.side_effect = \
                lambda sec, key, default=None: {
                    "bin_path": "/srv/fake",
                    "base_path": "/opt/z"}.get(key, default)
            self.assertEqual(gx.fake_dir(), "/srv/fake")
            g.return_value.get.side_effect = \
                lambda sec, key, default=None: {
                    "bin_path": "", "base_path": "/opt/z"}.get(key, default)
            self.assertEqual(gx.fake_dir(), "/opt/z/files/fake")

    def test_problem_and_argv(self):
        files = [("z2_tls_alert", "/f/tls_alert.bin")]
        names = [n for n, _ in files]
        self.assertEqual(gx.problem(PLAIN, [], []), "")
        self.assertIn("2.0", gx.problem(X2, ["nfqueue"], names))
        self.assertEqual(gx.problem(X2, ["ext", "ext_xact"], names), "")
        self.assertIn("z2_tls_clienthello_vk_com",
                      gx.problem(X, ["ext_xact"], names))
        self.assertEqual(gx.argv([PLAIN], ["ext_xact"], files), [])
        self.assertEqual(gx.argv([X2], ["nfqueue"], files), [])
        self.assertEqual(gx.argv([PLAIN, X2], ["ext_xact"], files),
                         ["--ext", "--ext-blob",
                          "z2_tls_alert:@/f/tls_alert.bin"])


if __name__ == "__main__":
    unittest.main()
