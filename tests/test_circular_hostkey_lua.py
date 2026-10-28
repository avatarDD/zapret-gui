"""Ротация circular и z2k-state-persist обязаны видеть ОДНУ запись autostate.

domain-grouping.lua переопределяет automate_host_record() и раньше строил
ключ сам (host_or_ip + жёсткий список суффиксов), игнорируя nld= и hostkey=.
z2k-state-persist.lua ключевал state.tsv через standard_hostkey (с nld).
Для «updates.discord.com» при nld=2 circular крутил запись
«updates.discord.com», а persist писал/подсеивал «discord.com» — выученная
стратегия не доходила до state.tsv и не восстанавливалась после рестарта.

Здесь грузится настоящий zapret-auto.lua (standard_hostkey, circular),
domain-grouping.lua и z2k-state-persist.lua в том же порядке, что в argv
nfqws2. Заглушены только C-примитивы и детектор неудач.
"""

import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

try:
    from lupa import LuaRuntime
except ImportError:                                  # pragma: no cover
    LuaRuntime = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LUA_DIR = os.path.join(ROOT, "import", "lua")


def _read(name):
    with open(os.path.join(LUA_DIR, name), encoding="utf-8") as f:
        return f.read()


def _lib_func(name):
    # Берём функцию из zapret-lib.lua как есть: целиком файл в lupa не
    # грузится (нужны C-примитивы nfqws2), а копия от руки разошлась бы.
    m = re.search(r"^function %s\(.*?^end$" % name, _read("zapret-lib.lua"),
                  re.M | re.S)
    return m.group(0)


STUB = """
CLOCK = 1000
os.time = function() return CLOCK end
clock_getfloattime = function() return CLOCK end
VERDICT_PASS = 0
LOG = {}
function DLOG(s) LOG[#LOG+1] = s end
DLOG_ERR = DLOG
function host_ip(desync) return desync.target.ip end
function orchestrate(ctx, desync)
  desync.plan = {}
  for i = 1, 3 do desync.plan[i] = { arg = { strategy = tostring(i) } } end
end
function plan_instance_pop(desync)
  return (desync.plan and #desync.plan>0) and table.remove(desync.plan, 1) or nil
end
EXECUTED = {}
function plan_instance_execute(desync, verdict, instance)
  EXECUTED[#EXECUTED+1] = tonumber(instance.arg.strategy)
  return verdict
end
"""

AFTER_AUTO = """
-- детектор неудач: ротация по флагу пакета
automate_failure_check = function(desync, hrec, crec)
  if desync.rotate then crec.failure = true return true end
  return false
end
function pkt(host, opts)
  opts = opts or {}
  local arg = { fails = "2", time = "300", retrans = "3", nld = opts.nld or "2" }
  if opts.hostkey then arg.hostkey = opts.hostkey end
  local d = { arg = arg, func_instance = "circular_6_1", outgoing = true,
              l7payload = "tls_client_hello", rotate = opts.rotate,
              target = { ip = opts.ip or "192.0.2.1" },
              track = { hostname = host, lua_state = { automate = {} } } }
  EXECUTED = {}
  circular({}, d)
  return EXECUTED[1]
end
function tick(sec) CLOCK = CLOCK + sec end
function keys()
  local out = {}
  for k in pairs(autostate.circular_6_1 or {}) do out[#out+1] = k end
  table.sort(out)
  return table.concat(out, ",")
end
"""


@unittest.skipIf(LuaRuntime is None, "нет lupa — Lua-тесты пропущены")
class CircularHostkeyCase(unittest.TestCase):

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
        self.lua = self._engine()

    def _engine(self):
        # Свежий Lua-стейт = рестарт nfqws2 (autostate в памяти пропадает).
        lua = LuaRuntime()
        lua.execute(STUB)
        for fn in ("dissect_nld", "host_or_ip"):
            lua.execute(_lib_func(fn))
        lua.execute(_read("zapret-auto.lua"))
        lua.execute(AFTER_AUTO)
        lua.execute(_read("domain-grouping.lua"))
        lua.execute(_read("z2k-state-persist.lua"))
        return lua

    def disk(self):
        try:
            with open(os.path.join(self.dir, "state.tsv")) as f:
                rows = [line.split("\t") for line in f.read().splitlines()
                        if line and not line.startswith("#")]
        except FileNotFoundError:
            return {}
        return {r[1]: int(r[2]) for r in rows}

    def test_subdomain_outside_list_has_one_bucket_and_reaches_disk(self):
        self.lua.execute("pkt('updates.discord.com')")
        self.assertEqual(self.lua.eval("keys()"), "discord.com")
        self.assertEqual(self.disk(), {"discord.com": 1})
        self.lua.execute("tick(5); pkt('updates.discord.com', {rotate=true})")
        self.assertEqual(
            self.lua.eval("autostate.circular_6_1['discord.com'].nstrategy"), 2)
        self.assertEqual(self.disk(), {"discord.com": 2})
        self.assertEqual(self.lua.eval("keys()"), "discord.com")

    def test_learned_strategy_survives_restart(self):
        self.lua.execute("pkt('www.example.org'); tick(5);"
                         "pkt('www.example.org', {rotate=true}); tick(5);"
                         "pkt('www.example.org', {rotate=true})")
        self.assertEqual(self.disk(), {"example.org": 3})
        self.lua = self._engine()
        # Первый же пакет после рестарта идёт сохранённой стратегией.
        self.assertEqual(self.lua.eval("pkt('cdn.example.org')"), 3)
        self.assertNotIn("circular: start from strategy 1",
                         list(self.lua.eval("LOG").values()))

    def test_hardcoded_group_still_applies(self):
        # без nld список суффиксов по-прежнему схлопывает глубокие имена
        self.lua.execute("pkt('rr5---sn-abc.googlevideo.com', {nld='0'})")
        self.assertEqual(self.lua.eval("keys()"), "googlevideo.com")
        self.assertEqual(self.disk(), {"googlevideo.com": 1})

    def test_explicit_hostkey_function_is_honoured(self):
        # hostless-пулы (hostkey=z2k_nohost_key) раньше молча ключевались по IP
        self.lua.execute("function z2k_nohost_key(d) return 'nohost' end")
        self.lua.execute("pkt(nil, {hostkey='z2k_nohost_key', ip='198.51.100.7'})")
        self.assertEqual(self.lua.eval("keys()"), "nohost")

    def test_hostless_flow_falls_back_to_ip(self):
        self.lua.execute("pkt(nil, {ip='198.51.100.7'})")
        self.assertEqual(self.lua.eval("keys()"), "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
