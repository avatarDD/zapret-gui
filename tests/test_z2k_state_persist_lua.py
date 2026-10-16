"""z2k-state-persist.lua в настоящем Lua (через lupa, если он стоит).

Ротация circular обязана доходить до state.tsv, а «залипание» на
стратегии — держаться только на настоящем успехе. Иначе «Выученные
стратегии» показывают #1 навсегда, хотя circular перебирает.

``circular`` здесь — заглушка: она ведёт ``autostate`` так же, как
zapret-auto.lua (ротация по флагу пакета), а проверяется обёртка.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

try:
    from lupa import LuaRuntime
except ImportError:                                  # pragma: no cover
    LuaRuntime = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LUA = os.path.join(ROOT, "import", "lua", "z2k-state-persist.lua")

STUB = """
CLOCK = 1000
os.time = function() return CLOCK end
clock_getfloattime = function() return CLOCK end
autostate = {}
function standard_hostkey(desync) return desync.track.hostname end
circular = function(ctx, desync)
  local key = desync.func_instance
  autostate[key] = autostate[key] or {}
  local h = autostate[key][desync.track.hostname] or {}
  autostate[key][desync.track.hostname] = h
  h.ctstrategy = 3
  if not h.nstrategy then h.nstrategy = 1 end
  local crec = desync.track.lua_state.automate
  if desync.rotate then
    h.nstrategy = h.nstrategy % 3 + 1
    crec.failure = true
    crec.nocheck = true
  elseif desync.success then
    crec.nocheck = true
  end
  return 0
end
function pkt(host, opts)
  opts = opts or {}
  local d = { arg = {}, func_instance = "circular_1",
              outgoing = not opts.incoming,
              l7payload = opts.payload or "tls_client_hello",
              rotate = opts.rotate, success = opts.success,
              track = { hostname = host, lua_state = { automate = {} } } }
  circular({}, d)
end
function tick(sec) CLOCK = CLOCK + sec end
function live(host) return autostate.circular_1[host].nstrategy end
"""


@unittest.skipIf(LuaRuntime is None, "нет lupa — Lua-тесты пропущены")
class PersistCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="z2k-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        fallback = os.path.join(self.dir, "fb")
        os.makedirs(fallback)
        patcher = mock.patch.dict(os.environ, {
            "Z2K_STATE_DIR_OVERRIDE": self.dir,
            "Z2K_AUTOCIRCULAR_FALLBACK_OVERRIDE": fallback})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.lua = LuaRuntime()
        self.lua.execute(STUB)
        with open(LUA, encoding="utf-8") as f:
            self.lua.execute(f.read())

    def run_lua(self, code):
        return self.lua.execute(code)

    def disk(self):
        try:
            with open(os.path.join(self.dir, "state.tsv")) as f:
                rows = [line.split("\t") for line in f.read().splitlines()
                        if line and not line.startswith("#")]
        except FileNotFoundError:
            return {}
        return {r[1]: int(r[2]) for r in rows}


class TestRotationReachesDisk(PersistCase):

    def test_rotation_inside_debounce_is_written_later(self):
        # Первый ClientHello пишет «1», ротация через секунду попадает в
        # окно debounce. Раньше она так и оставалась только в памяти.
        self.run_lua("pkt('site.ru')")
        self.assertEqual(self.disk(), {"site.ru": 1})
        self.run_lua("tick(1); pkt('site.ru', {rotate=true})")
        self.assertEqual(self.disk(), {"site.ru": 1})
        self.run_lua("tick(5); pkt('site.ru')")
        self.assertEqual(self.disk(), {"site.ru": 2})
        self.assertFalse(self.lua.eval("z2k_state_persist.pending()"))

    def test_rotation_outside_debounce_is_written_at_once(self):
        self.run_lua("pkt('b.ru'); tick(5); pkt('b.ru', {rotate=true})")
        self.assertEqual(self.disk(), {"b.ru": 2})


class TestStickyNeedsRealSuccess(PersistCase):

    def test_server_hello_does_not_freeze_rotation(self):
        # ServerHello — это «рукопожатие прошло», а не «обход работает»:
        # DPI часто режет позже. Раньше ротация в 30 с после него
        # откатывалась, и circular не уходил с #1.
        self.run_lua("pkt('a.ru'); tick(2);"
                     "pkt('a.ru', {incoming=true, payload='tls_server_hello'});"
                     "tick(3); pkt('a.ru', {rotate=true})")
        self.assertEqual(self.lua.eval("live('a.ru')"), 2)
        self.assertEqual(self.disk(), {"a.ru": 2})

    def test_real_success_still_pins(self):
        # Успех детектора circular (данные за inseq) — настоящий: падающий
        # параллельный поток в 30 с после него стратегию не сдвигает.
        self.run_lua("pkt('c.ru'); tick(2);"
                     "pkt('c.ru', {incoming=true, payload='empty', success=true});"
                     "tick(3); pkt('c.ru', {rotate=true})")
        self.assertEqual(self.lua.eval("live('c.ru')"), 1)

    def test_pin_expires_after_window(self):
        self.run_lua("pkt('d.ru'); tick(2);"
                     "pkt('d.ru', {incoming=true, payload='empty', success=true});"
                     "tick(40); pkt('d.ru', {rotate=true})")
        self.assertEqual(self.lua.eval("live('d.ru')"), 2)


class TestUnreadablePrimary(PersistCase):

    def test_unreadable_primary_is_not_a_mass_delete(self):
        # Файл есть, но nfqws2 (nobody) его не читает — это сбой чтения,
        # а не «оператор стёр всё»: живая ротация не сбрасывается на 1.
        self.run_lua("pkt('e.ru'); tick(5); pkt('e.ru', {rotate=true})")
        self.assertEqual(self.disk(), {"e.ru": 2})
        with open(os.path.join(self.dir, "fb",
                               "z2k-autocircular-state.tsv"), "w") as f:
            f.write("# empty fallback\n")
        primary = os.path.join(self.dir, "state.tsv")
        self.run_lua("""
            local real_open = io.open
            io.open = function(path, mode)
              if path == %r and (mode == nil or mode == 'r') then
                return nil, path .. ': Permission denied', 13
              end
              return real_open(path, mode)
            end
            tick(5); pkt('e.ru')
        """ % primary)
        self.assertEqual(self.lua.eval("live('e.ru')"), 2)


if __name__ == "__main__":
    unittest.main()
