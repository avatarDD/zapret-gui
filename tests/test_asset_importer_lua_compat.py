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

import hashlib
import os
import re
import tempfile
import unittest

from core import asset_importer as ai

LUA_DIR = ai.IMPORT_LUA_DIR

# ─────────────────────────────────────────────────────────────────────────
# Базовый релиз upstream, с которым побайтово совпадает наш bundled core-lua.
#
# Зачем хэши, а не только COMPAT_VER: защита `_protected_core_lua` срабатывает
# лишь на СМЕНЕ compat-версии. Внутри одной (все zapret2 1.0…1.0.4 = 6) наш
# бандл перезаписывает upstream-копию на диске — то есть апстримный фикс
# «внутри compat» мы молча откатываем пользователю. Единственная защита —
# держать core-lua дословной копией релиза и ловить расхождение тестом.
#
# Как обновлять при выходе нового релиза zapret2:
#   1. скопировать lua/*.lua из релиза в import/lua/
#   2. пересчитать: sha256sum import/lua/zapret-*.lua
#   3. обновить _UPSTREAM_LUA_TAG и _UPSTREAM_LUA_SHA256 ниже
#   4. проверить SKILL §0 (.claude/skills/nfqws2-strategies/SKILL.md) —
#      не поменялась ли семантика, а не только байты
#
# Наши собственные расширения живут в ОТДЕЛЬНЫХ файлах (custom_funcs.lua,
# zapret-multishake.lua, …) и сюда не входят: core-lua правится только
# синхронизацией с апстримом.
# ─────────────────────────────────────────────────────────────────────────
_UPSTREAM_LUA_TAG = "v1.0.4"
_UPSTREAM_LUA_SHA256 = {
    "zapret-lib.lua":
        "b272d207cca145a3b6174793b7d335489519f6d4299418ff2b870765cea24d5a",
    "zapret-antidpi.lua":
        "31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a",
    "zapret-auto.lua":
        "aacfde0c95c3058f8e95f5d7d244398bdc03ebf846a8f17322129fb543366a3d",
    "zapret-obfs.lua":
        "e9581bfbca846630ada78193641d834e25abc11337ba85467d642c2d8c6fa47f",
    "zapret-pcap.lua":
        "6866c37c92fbc62075accf94228da48af618c7f416edc682eba99b2196e05f45",
    "zapret-tests.lua":
        "1d13e191cae02d9ed314ba41a91d2079965d07c16f80e08f1c9bf7c6e0e24100",
}


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


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestBundledCoreLuaMatchesUpstreamRelease(unittest.TestCase):
    """core-lua в bundle — дословная копия релиза bol-van/zapret2.

    Ловит тихий дрейф внутри одной compat-версии: `_protected_core_lua`
    защищает файлы на диске только когда COMPAT_VER вырос, поэтому
    отставший бандл откатывает пользователю апстримные фиксы, не меняя
    ни одной проверяемой версии. Инструкция по обновлению — в шапке файла.
    """

    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def test_hashes_cover_exactly_the_protected_core_set(self):
        """Список хэшей не разъехался с `_UPSTREAM_CORE_LUA`."""
        self.assertEqual(
            set(_UPSTREAM_LUA_SHA256), set(ai._UPSTREAM_CORE_LUA),
            "набор пиннингов не совпадает с защищаемым core-набором")

    def test_bundled_core_lua_is_verbatim_upstream(self):
        drifted = []
        for name, expected in sorted(_UPSTREAM_LUA_SHA256.items()):
            path = os.path.join(LUA_DIR, name)
            if not os.path.isfile(path):
                drifted.append("%s (отсутствует)" % name)
                continue
            actual = self._sha256(path)
            if actual != expected:
                drifted.append("%s (%s… != %s…)"
                               % (name, actual[:12], expected[:12]))
        self.assertEqual(
            drifted, [],
            "bundled core-lua разошлась с upstream %s: %s. "
            "Либо синхронизируйте import/lua/ с релизом, либо (если "
            "апстрим ушёл вперёд) обновите _UPSTREAM_LUA_TAG/SHA256 в этом "
            "тесте и §0 скила nfqws2-strategies"
            % (_UPSTREAM_LUA_TAG, ", ".join(drifted)))


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestBundledCoreLuaSemantics(unittest.TestCase):
    """Точечные признаки zapret2 1.0.x, от которых зависит наш код и скил.

    Хэш-пиннинг ловит любое расхождение, но по нему не видно, ЧТО сломалось.
    Эти проверки называют конкретные вещи, на которые мы опираемся.
    """

    @staticmethod
    def _read(name):
        with open(os.path.join(LUA_DIR, name), encoding="utf-8") as f:
            return f.read()

    def test_desync_timer_name_includes_instance(self):
        """1.0.4: имя таймера уникально на desync+инстанс.

        Без имени инстанса два разных `--lua-desync` в одном профиле дерутся
        за одно имя таймера — второй `timer_set` замещает первый.
        """
        txt = self._read("zapret-lib.lua")
        self.assertRegex(
            txt,
            r"function desync_timer_name\(desync\)\s*\n\s*local name = "
            r"desync\.func_instance",
            "desync_timer_name не включает func_instance (регресс до 1.0.3)")

    def test_send_delay_uses_oneshot_timer(self):
        """1.0: `send:delay` откладывает отправку однократным таймером."""
        txt = self._read("zapret-antidpi.lua")
        self.assertIn("desync.arg.delay", txt,
                      "в send нет поддержки delay (lua старше zapret2 1.0)")
        self.assertIn("function send_timer_delayed", txt,
                      "нет таймер-функции отложенной отправки")

    def test_timer_info_func_not_concatenated(self):
        """1.0.3: `timer_info().func` — функция, а не строка.

        Конкатенация её со строкой роняет Lua с error. Наша копия
        zapret-tests.lua какое-то время это делала.
        """
        self.assertNotIn(
            'tinfo.func', self._read("zapret-tests.lua"),
            "zapret-tests.lua печатает timer_info().func — на zapret2 "
            ">= 1.0.3 это Lua error (func стал функцией)")

    def test_writable_helper_renamed(self):
        """1.0: `writeable_file_name` → `writable_file_name` (env WRITABLE)."""
        txt = self._read("zapret-lib.lua")
        self.assertIn("function writable_file_name", txt)
        self.assertIn('os.getenv("WRITABLE")', txt)


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
