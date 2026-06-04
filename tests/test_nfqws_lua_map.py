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

    def test_orchestrator_files_are_vendored(self):
        for lua_file in nm._ORCHESTRATOR_LUA_FILES:
            self.assertIsNotNone(
                _global_funcs(lua_file),
                "orchestrator lua-скрипт %s отсутствует в import/lua/"
                % lua_file)

    def test_orchestrator_triggers_are_defined_somewhere(self):
        """Каждый триггер circular-bundle определён среди файлов, которые
        реально грузятся при срабатывании оркестратора: core + zapret-auto
        (до-грузится в orchestrator-блоке) + companion'ы."""
        loadable = (set(nm._CORE_LUA_FILES) | {"zapret-auto.lua"}
                    | set(nm._ORCHESTRATOR_LUA_FILES))
        defined = set()
        for lf in loadable:
            defined |= _global_funcs(lf) or set()
        missing = sorted(t for t in nm._ORCHESTRATOR_TRIGGERS
                         if t not in defined)
        self.assertEqual(
            missing, [],
            "Триггеры оркестратора без определения в core/zapret-auto/companion: %s"
            % missing)


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

        orch = set(nm._ORCHESTRATOR_LUA_FILES)

        def satisfied(fn):
            files = deffile.get(fn)
            if not files:
                return False
            if files & core:
                return True
            for extf, trig in nm._EXTENSION_LUA_FILES.items():
                if extf in files and fn in trig:
                    return True
            # circular-bundle: триггер грузит весь набор companion'ов.
            if fn in nm._ORCHESTRATOR_TRIGGERS and files & orch:
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


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestInitVarsTrigger(unittest.TestCase):
    """init_vars.lua — value-триггер по именованным паттернам (не функц-карта)."""

    _ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=", re.M)

    def _init_vars_assignments(self):
        path = os.path.join(LUA_DIR, "init_vars.lua")
        with open(path, encoding="utf-8", errors="replace") as f:
            return set(self._ASSIGN_RE.findall(f.read()))

    def test_named_set_matches_vendored_assignments(self):
        """_INIT_VARS_NAMES ⊆ top-level присваиваний init_vars.lua (иначе
        blob=/seqovl_pattern=<NAME> сошлётся на необъявленную переменную)."""
        assigned = self._init_vars_assignments()
        extra = sorted(nm._INIT_VARS_NAMES - assigned)
        self.assertEqual(
            extra, [],
            "В _INIT_VARS_NAMES есть имена, не объявленные в init_vars.lua: %s"
            % extra)

    def test_init_vars_not_in_function_map(self):
        """init_vars не должен быть в core/extension/orchestrator-картах —
        он триггерится только по значению."""
        self.assertNotIn("init_vars.lua", nm._CORE_LUA_FILES)
        self.assertNotIn("init_vars.lua", nm._EXTENSION_LUA_FILES)
        self.assertNotIn("init_vars.lua", nm._ORCHESTRATOR_LUA_FILES)


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestBuildLuaInitArgs(unittest.TestCase):
    """Поведение _build_lua_init_args на вендоренном import/lua/."""

    def _files(self, strategy_args):
        out = nm.NFQWSManager._build_lua_init_args(strategy_args, LUA_DIR)
        return [os.path.basename(a.split("@", 1)[1]) for a in out]

    def test_no_desync_no_lua(self):
        self.assertEqual(self._files(["--filter-tcp=443"]), [])

    def test_plain_fake_loads_only_core(self):
        files = self._files(["--lua-desync=fake:blob=fake_default_tls"])
        self.assertEqual(files, ["zapret-lib.lua", "zapret-antidpi.lua"])

    def test_named_pattern_pulls_init_vars_after_core(self):
        files = self._files(
            ["--lua-desync=multisplit:seqovl_pattern=tls_google"])
        self.assertEqual(
            files,
            ["zapret-lib.lua", "zapret-antidpi.lua", "init_vars.lua"])

    def test_builtin_blob_does_not_pull_init_vars(self):
        files = self._files(["--lua-desync=fake:blob=fake_default_tls"])
        self.assertNotIn("init_vars.lua", files)

    def test_custom_funcs_pulled_by_its_function(self):
        files = self._files(["--lua-desync=http_aggressive"])
        self.assertIn("custom_funcs.lua", files)
        self.assertNotIn("zapret-auto.lua", files)

    def test_circular_pulls_zapret_auto_and_bundle(self):
        files = self._files(["--lua-desync=circular:detector=combined_failure_detector"])
        self.assertIn("zapret-auto.lua", files)
        for comp in nm._ORCHESTRATOR_LUA_FILES:
            self.assertIn(comp, files)

    def test_circular_with_preload_also_pulls_zapret_auto(self):
        """circular_with_preload не входит в экспорт zapret-auto, но bundle
        зависит от standard_*_detector — zapret-auto обязан догрузиться."""
        files = self._files(["--lua-desync=circular_with_preload"])
        self.assertIn("zapret-auto.lua", files)
        self.assertIn("strategy-stats.lua", files)

    # ──────────────── z2k-bundle ────────────────

    def test_circular_pulls_z2k_companions(self):
        """z2k-* companion'ы (detectors, state-persist, modern-core,
        fooling-ext) грузятся при любой circular-стратегии — детекторам
        нужен доступ к standard_*_detector, state-persist обёртывает
        circular()."""
        files = self._files(["--lua-desync=circular"])
        for lf in ("z2k-modern-core.lua", "z2k-detectors.lua",
                   "z2k-fooling-ext.lua", "z2k-state-persist.lua"):
            self.assertIn(lf, files, "%s не загружен при circular" % lf)

    def test_state_persist_loads_after_zapret_auto(self):
        """z2k-state-persist обёртывает функцию `circular` — должен идти
        ПОСЛЕ zapret-auto.lua в списке --lua-init (иначе оборачивать
        нечего)."""
        files = self._files(["--lua-desync=circular"])
        self.assertIn("zapret-auto.lua", files)
        self.assertIn("z2k-state-persist.lua", files)
        self.assertLess(
            files.index("zapret-auto.lua"),
            files.index("z2k-state-persist.lua"),
            "z2k-state-persist должен загружаться ПОСЛЕ zapret-auto",
        )

    def test_z2k_modern_core_pulled_by_its_function(self):
        """Прямой вызов z2k_quic_morph_v2 (без circular) тянет
        z2k-modern-core.lua как extension."""
        files = self._files(["--lua-desync=z2k_quic_morph_v2"])
        self.assertIn("z2k-modern-core.lua", files)
        self.assertNotIn("zapret-auto.lua", files)

    # ──────────────── z2k-range-rand ────────────────

    def test_range_rand_triggered_by_repeats_range(self):
        """`repeats=A-B` синтаксис тянет z2k-range-rand.lua (sticky
        per-flow random)."""
        files = self._files(["--lua-desync=fake:blob=fake_default_tls:repeats=2-6"])
        self.assertIn("z2k-range-rand.lua", files)

    def test_range_rand_triggered_by_seqovl_range(self):
        files = self._files(
            ["--lua-desync=multisplit:pos=1:seqovl=5-50:seqovl_pattern=tls_google"])
        self.assertIn("z2k-range-rand.lua", files)

    def test_range_rand_not_triggered_by_fixed_value(self):
        """`repeats=3` (фиксированное) НЕ должно тянуть range-rand."""
        files = self._files(["--lua-desync=fake:blob=fake_default_tls:repeats=3"])
        self.assertNotIn("z2k-range-rand.lua", files)

    def test_range_rand_triggered_by_negative_range(self):
        """`tcp_seq=-1000-1000` — диапазон со знаком."""
        files = self._files(
            ["--lua-desync=fake:blob=fake_default_tls:tcp_seq=-1000-1000"])
        self.assertIn("z2k-range-rand.lua", files)

    # ──────────────── z2k fool=z2k_dynamic_ttl ────────────────

    def test_fool_ext_triggered_by_dynamic_ttl(self):
        """fake:fool=z2k_dynamic_ttl (НЕ circular) тянет z2k-fooling-ext.lua
        по value-триггеру — иначе fool-функция не определена."""
        files = self._files(
            ["--lua-desync=fake:blob=fake_default_tls:fool=z2k_dynamic_ttl"])
        self.assertIn("z2k-fooling-ext.lua", files)
        # zapret-auto (orchestrator) НЕ должен подтягиваться без circular
        self.assertNotIn("zapret-auto.lua", files)

    def test_fool_ext_not_triggered_without_z2k_fool(self):
        files = self._files(
            ["--lua-desync=fake:blob=fake_default_tls:ip_autottl=-2,3-20"])
        self.assertNotIn("z2k-fooling-ext.lua", files)


if __name__ == "__main__":
    unittest.main()
