# tests/test_asset_importer_lua_compat.py
"""asset_importer: bundled lua не понижает версию релиза (issue #151).

Бандл GUI кладёт lua-скрипты в /opt/zapret2/lua/. Upstream-core скрипты
(zapret-lib/antidpi/auto/obfs/pcap/tests) — дословные копии релиза
bol-van/zapret2 и жёстко привязаны к бинарнику nfqws2 через
NFQWS2_COMPAT_VER (первая строка zapret-lib.lua). zapret2 1.0 сменил
COMPAT_VER 5→6; если бандл (со старой lua) затирал свежую lua из релиза —
nfqws2 падал с «Incompatible NFQWS2_COMPAT_VER» (issue #151).

Здесь проверяем: (1) сам бандл уже не старый, (2) более новая lua на диске
не затирается нашей копией.
"""

import os
import re
import tempfile
import unittest

from core import asset_importer as ai

LUA_DIR = ai.IMPORT_LUA_DIR


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestBundledLuaIsCurrent(unittest.TestCase):
    """Прямая регрессия issue #151 — bundled lua не должна быть compat 5."""

    def test_bundled_zapret_lib_compat_ver_at_least_6(self):
        ver = ai._lua_compat_ver(os.path.join(LUA_DIR, "zapret-lib.lua"))
        self.assertIsNotNone(
            ver, "не нашли NFQWS2_COMPAT_VER_REQUIRED в bundled zapret-lib.lua")
        self.assertGreaterEqual(
            ver, 6,
            "bundled zapret-lib.lua compat_ver=%s < 6 — устаревшая lua "
            "ломает nfqws2 >= 1.0 (issue #151)" % ver)

    def test_no_stale_writeable_or_compat5_markers(self):
        """В bundled lua не осталось старых маркеров (WRITEABLE, compat=5)."""
        offenders = []
        for name in sorted(os.listdir(LUA_DIR)):
            if not name.endswith(".lua"):
                continue
            with open(os.path.join(LUA_DIR, name), encoding="utf-8",
                      errors="replace") as f:
                txt = f.read()
            if "WRITEABLE" in txt or "writeable_file_name" in txt:
                offenders.append(name + " (WRITEABLE→WRITABLE не выполнен)")
            if re.search(r"NFQWS2_COMPAT_VER_REQUIRED\s*=\s*5\b", txt):
                offenders.append(name + " (compat=5)")
        self.assertEqual(offenders, [],
                         "stale-маркеры в bundled lua: %s" % offenders)

    def test_all_protected_core_files_vendored(self):
        for name in ai._UPSTREAM_CORE_LUA:
            self.assertTrue(
                os.path.isfile(os.path.join(LUA_DIR, name)),
                "upstream-core lua %s отсутствует в bundle" % name)


class TestLuaCompatVerParser(unittest.TestCase):

    def test_parse_value(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "zapret-lib.lua")
            _write(p, "NFQWS2_COMPAT_VER_REQUIRED=6\n-- rest\n")
            self.assertEqual(ai._lua_compat_ver(p), 6)
            _write(p, "NFQWS2_COMPAT_VER_REQUIRED = 12\n")
            self.assertEqual(ai._lua_compat_ver(p), 12)

    def test_no_marker_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.lua")
            _write(p, "function foo() end\n")
            self.assertIsNone(ai._lua_compat_ver(p))

    def test_missing_file_returns_none(self):
        self.assertIsNone(ai._lua_compat_ver("/no/such/zapret-lib.lua"))


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestProtectedCoreLua(unittest.TestCase):

    def setUp(self):
        self.bundled = ai._lua_compat_ver(
            os.path.join(LUA_DIR, "zapret-lib.lua"))
        self.assertIsNotNone(self.bundled)

    @staticmethod
    def _seed(base, ver):
        if ver is not None:
            _write(os.path.join(base, "lua", "zapret-lib.lua"),
                   "NFQWS2_COMPAT_VER_REQUIRED=%d\n" % ver)

    def test_newer_on_disk_is_protected(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed(d, self.bundled + 1)
            self.assertEqual(ai._protected_core_lua(d),
                             set(ai._UPSTREAM_CORE_LUA))

    def test_same_version_not_protected(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed(d, self.bundled)
            self.assertEqual(ai._protected_core_lua(d), set())

    def test_older_on_disk_not_protected(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed(d, self.bundled - 1)
            self.assertEqual(ai._protected_core_lua(d), set())

    def test_missing_on_disk_not_protected(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(ai._protected_core_lua(d), set())


class TestSyncDirSkipNames(unittest.TestCase):

    def test_skip_names_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = os.path.join(d, "src"), os.path.join(d, "dst")
            _write(os.path.join(src, "a.lua"), "NEW-A\n")
            _write(os.path.join(src, "b.lua"), "NEW-B\n")
            _write(os.path.join(dst, "a.lua"), "OLD-A\n")
            _write(os.path.join(dst, "b.lua"), "OLD-B\n")
            stats = ai._sync_dir(src, dst, skip_names={"a.lua"})
            with open(os.path.join(dst, "a.lua")) as f:
                self.assertEqual(f.read(), "OLD-A\n")   # защищён
            with open(os.path.join(dst, "b.lua")) as f:
                self.assertEqual(f.read(), "NEW-B\n")   # обновлён
            self.assertEqual(stats["copied"], 1)


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestImportRuntimePreservesNewerCoreLua(unittest.TestCase):
    """Сквозной сценарий issue #151 (обратная сторона): на диске лежит lua
    из БОЛЕЕ нового релиза — import_runtime_assets её не затирает, но наши
    расширения раскладывает как обычно."""

    def test_newer_core_lua_preserved_extensions_deployed(self):
        bundled = ai._lua_compat_ver(os.path.join(LUA_DIR, "zapret-lib.lua"))
        sentinel = "NFQWS2_COMPAT_VER_REQUIRED=%d\n-- FUTURE RELEASE\n" % (
            bundled + 1)
        with tempfile.TemporaryDirectory() as base:
            _write(os.path.join(base, "lua", "zapret-lib.lua"), sentinel)

            res = ai.import_runtime_assets(base_path=base)
            self.assertTrue(res.get("ok"))

            # core lua из «нового релиза» НЕ затёрта нашей копией
            with open(os.path.join(base, "lua", "zapret-lib.lua"),
                      encoding="utf-8") as f:
                self.assertEqual(f.read(), sentinel)

            # а наши расширения (их в релизе нет) — выложены
            self.assertTrue(
                os.path.isfile(os.path.join(base, "lua", "custom_funcs.lua")),
                "custom_funcs.lua должен раскладываться даже при защите core")
