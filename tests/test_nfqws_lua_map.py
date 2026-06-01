# tests/test_nfqws_lua_map.py
"""Инварианты привязки lua-скриптов к --lua-desync (см. SKILL.md §1).

Главная ловушка nfqws2: вызов --lua-desync=FN не подгружает скрипт сам по
себе. Core-скрипты грузятся всегда, extension-скрипты — только если функция
есть в _EXTENSION_LUA_FILES. Если функция определена в extension-скрипте, но
её нет в триггер-наборе (или catalog ссылается на функцию, которой нет ни в
одном загружаемом скрипте) — это тихий 0%.

Эти тесты ловят такой рассинхрон на этапе CI, опираясь на вендоренные
эталонные скрипты в import/lua/.
"""

import glob
import os
import re
import unittest

from core import nfqws_manager as nm

LUA_DIR = os.path.join(os.path.dirname(__file__), "..", "import", "lua")
_GLOBAL_FN_RE = re.compile(r"^\s*function\s+([A-Za-z0-9_]+)\s*\(", re.M)


def _global_funcs(lua_file):
    path = os.path.join(LUA_DIR, lua_file)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return set(_GLOBAL_FN_RE.findall(f.read()))


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestExtensionLuaMap(unittest.TestCase):

    def test_trigger_set_matches_vendored_exports(self):
        """Триггер-набор каждого extension-скрипта == его глобальные функции.

        Не больше (иначе грузим скрипт зря) и не меньше (иначе функция не
        подхватится — issue-класс «тихий 0%»).
        """
        for lua_file, trigger in nm._EXTENSION_LUA_FILES.items():
            exported = _global_funcs(lua_file)
            if exported is None:
                continue  # файл не вендорен — пропускаем
            self.assertEqual(
                trigger, exported,
                "%s: триггер-набор разошёлся с экспортом скрипта.\n"
                "  только в карте: %s\n  только в .lua: %s" % (
                    lua_file, sorted(trigger - exported),
                    sorted(exported - trigger)),
            )

    def test_core_lua_files_are_vendored(self):
        for lua_file in nm._CORE_LUA_FILES:
            self.assertIsNotNone(
                _global_funcs(lua_file),
                "core lua-скрипт %s отсутствует в import/lua/" % lua_file)


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestCatalogDesyncCoverage(unittest.TestCase):

    def _func_to_files(self):
        out = {}
        for f in glob.glob(os.path.join(LUA_DIR, "*.lua")):
            base = os.path.basename(f)
            for fn in _global_funcs(base) or ():
                out.setdefault(fn, set()).add(base)
        return out

    def test_every_catalog_desync_func_is_loadable(self):
        """Каждая --lua-desync функция из каталогов определена в core- или
        в триггеримом extension-скрипте (иначе её вызов = тихий 0%)."""
        deffile = self._func_to_files()
        core = set(nm._CORE_LUA_FILES)

        def satisfied(fn):
            files = deffile.get(fn)
            if not files:
                return False
            if files & core:
                return True
            for extf, trig in nm._EXTENSION_LUA_FILES.items():
                if extf in files and fn in trig:
                    return True
            return False

        cat_dir = os.path.join(os.path.dirname(__file__), "..", "catalogs")
        if not os.path.isdir(cat_dir):
            self.skipTest("no catalogs dir")

        used = set()
        for f in glob.glob(os.path.join(cat_dir, "**", "*"), recursive=True):
            if not os.path.isfile(f):
                continue
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    txt = fh.read()
            except OSError:
                continue
            used |= set(re.findall(r"--lua-desync=([A-Za-z0-9_]+)", txt))

        unloadable = sorted(fn for fn in used if not satisfied(fn))
        self.assertEqual(
            unloadable, [],
            "Каталоги ссылаются на --lua-desync функции, которые не "
            "подгрузит ни один core/extension-скрипт: %s" % unloadable)


if __name__ == "__main__":
    unittest.main()
