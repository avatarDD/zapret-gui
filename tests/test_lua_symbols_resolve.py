"""Сторож: каждый вызов в наших lua-расширениях куда-то резолвится.

Зачем
-----
В Lua вызов несуществующего глобала — не ошибка компиляции, а падение в
рантайме на конкретном пакете: «attempt to call a nil value (global 'X')».
Для nfqws2 это означает, что стратегия просто не работает, причём тихо:
десинк не применился, лог без `--debug` пуст.

Ровно так три каталога (basic/advanced/direct) полгода предлагали стратегию
`discord_timestamp_travel`, которая звала `bitright()` — функции с таким
именем в nfqws2 нет и не было, она называется `bitrshift`. Никакой тест
этого не ловил: `--intercept=0` проверяет только загрузку lua-init, а
неизвестное имя всплывает лишь при обработке пакета.

Что проверяем
-------------
Для каждого файла в `import/lua/`, который написали МЫ (не upstream-копии),
каждый вызов вида `name(...)` должен резолвиться хотя бы в одно из:
  * функцию, определённую в любом lua-файле бандла (нашем или upstream);
  * C-функцию nfqws2 (список — `_NFQWS2_C_FUNCS`);
  * стандартную библиотеку Lua;
  * локальную переменную/функцию в том же файле.

Проверка сознательно грубая (регексп, не парсер Lua) — она ловит опечатки
и заимствования из чужого API, а не доказывает корректность. Ложные
срабатывания гасятся через `_ALLOWLIST` с объяснением каждого.

Обновление при смене версии nfqws2
----------------------------------
`_NFQWS2_C_FUNCS` — дословный список из `nfq2/lua.c` (таблица `lfunc[]`)
релиза, записанного в `docs/upstream.json`. С 0.9.5.2 по 1.0.4 он не
менялся. Если апстрим добавит/переименует C-функции, обновить здесь.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LUA_DIR = os.path.join(REPO_ROOT, "import", "lua")

# Дословные копии релиза bol-van/zapret2 — их не проверяем (это эталон).
_UPSTREAM_LUA = {
    "zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua",
    "zapret-obfs.lua", "zapret-pcap.lua", "zapret-tests.lua",
}

# Таблица lfunc[] из nfq2/lua.c (zapret2 v1.0.4). См. docstring.
_NFQWS2_C_FUNCS = {
    "DLOG", "DLOG_ERR", "DLOG_CONDUP",
    "ntop", "pton", "parse_hex",
    "bitand", "bitor", "bitxor", "bitnot", "bitlshift", "bitrshift",
    "bitget", "bitset",
    "u8", "u16", "u24", "u32", "u48", "bu8", "bu16", "bu24", "bu32", "bu48",
    "swap16", "swap32", "swap48",
    "u8add", "u16add", "u24add", "u32add", "u48add",
    "brandom", "bcryptorandom", "brandom_az", "brandom_az09",
    "aes", "aes_gcm", "aes_ctr", "hkdf", "hash",
    "gzip", "gunzip", "gzip_deflate", "gunzip_inflate",
    "uname", "clock_gettime", "clock_getfloattime", "getpid", "gettid",
    "stat", "time", "localtime", "gmtime", "timelocal", "timegm",
    "dissect", "reconstruct_dissect", "reconstruct_tcphdr",
    "reconstruct_iphdr", "reconstruct_ip6hdr",
    "csum_fix", "csum_tcp_fix", "csum_udp_fix", "csum_icmp_fix",
    "csum_ip_fix", "csum_ip6_fix",
    "conntrack_feed", "get_source_ip", "get_ifaddrs",
    "rawsend", "rawsend_dissect",
    "instance_cutoff", "lua_cutoff", "execution_plan",
    "execution_plan_cancel",
    "timer_set", "timer_del", "timer_info", "timer_enum",
    "resolve_pos", "resolve_multi_pos", "resolve_range", "tls_mod",
}

_LUA_STDLIB = {
    "print", "type", "tostring", "tonumber", "pairs", "ipairs", "next",
    "select", "error", "assert", "pcall", "xpcall", "setmetatable",
    "getmetatable", "rawget", "rawset", "rawequal", "rawlen", "unpack",
    "require", "collectgarbage", "load", "loadstring", "dofile", "loadfile",
}

_LUA_KEYWORDS = {
    "function", "if", "while", "for", "return", "and", "or", "not", "then",
    "do", "end", "elseif", "local", "in", "repeat", "until", "else",
}

# Ложные срабатывания грубого регекспа. Каждое имя — с объяснением, почему
# это не вызов. Добавлять сюда можно только разобравшись, а не «чтобы
# позеленело».
_ALLOWLIST = {
    # Слова внутри строк логов: DLOG("... QUIC(...)"), "STUN(binding)" и т.п.
    "ANOMALY", "DISCORD", "PAGE", "QUIC", "STUB", "STUN", "VALID", "FAKE",
    "RST", "detected", "counter", "unlock", "short", "hosts",
    # Однобуквенные имена из строковых шаблонов.
    "d", "t",
    # Хелперы, объявленные как поле таблицы или через присваивание в ветке.
    "ts_of", "parser", "loaded",
    # Необязательный хук: вызывается строго под `if <name> then` — если
    # companion-файл не загружен, ветка не исполняется.
    "get_best_strategy_from_history",
}

_DEF_RE = re.compile(r"^\s*function\s+([A-Za-z_][\w]*)\s*\(", re.M)
_LOCAL_FN_RE = re.compile(r"local\s+function\s+([A-Za-z_][\w]*)")
# `local a`, `local a = …`, `local a, b, c` и `local a, b = f()` — объявление
# без присваивания встречается часто (переменная заполняется ниже по ветвям),
# поэтому ловим весь список имён, а не только первое перед '='.
_LOCAL_LIST_RE = re.compile(
    r"local\s+([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)")
# Имя, за которым идёт '(' и перед которым нет '.' или ':' (то есть не метод).
_CALL_RE = re.compile(r"(?<![\w.:])([A-Za-z_][\w]*)\s*\(")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _strip_comments(text):
    text = re.sub(r"--\[\[.*?\]\]", "", text, flags=re.S)
    return "\n".join(re.sub(r"--.*$", "", line) for line in text.split("\n"))


def _lua_files():
    if not os.path.isdir(LUA_DIR):
        return []
    return sorted(f for f in os.listdir(LUA_DIR) if f.endswith(".lua"))


def _global_defs():
    """Все глобальные `function NAME(` во всём бандле (наши + upstream)."""
    defs = {}
    for name in _lua_files():
        text = _read(os.path.join(LUA_DIR, name))
        for m in _DEF_RE.finditer(text):
            defs.setdefault(m.group(1), name)
    return defs


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestOurLuaCallsResolve(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.defs = _global_defs()
        cls.known = (set(cls.defs) | _NFQWS2_C_FUNCS | _LUA_STDLIB
                     | _LUA_KEYWORDS | _ALLOWLIST)

    @classmethod
    def _unresolved(cls, known):
        """Вызовы, не разрешаемые набором `known`. → {имя: [файлы]}."""
        out = {}
        for name in _lua_files():
            if name in _UPSTREAM_LUA:
                continue
            text = _strip_comments(_read(os.path.join(LUA_DIR, name)))
            local = set(_LOCAL_FN_RE.findall(text))
            for group in _LOCAL_LIST_RE.findall(text):
                local.update(n.strip() for n in group.split(","))
            for called in sorted(set(_CALL_RE.findall(text))):
                if called in known or called in local:
                    continue
                out.setdefault(called, []).append(name)
        return out

    def test_no_unresolved_calls_in_our_lua(self):
        unresolved = self._unresolved(self.known)
        self.assertEqual(
            unresolved, {},
            "вызовы, которые не резолвятся ни в lua-бандл, ни в C-функции "
            "nfqws2 — в рантайме это «attempt to call a nil value» и тихо "
            "неработающая стратегия: %s"
            % {k: sorted(set(v)) for k, v in sorted(unresolved.items())})

    def test_bitright_regression(self):
        """Прямая регрессия: в nfqws2 функция называется bitrshift.

        `discord_timestamp_travel` звал `bitright()` — стратегия предлагалась
        пользователю из трёх каталогов и падала на каждом пакете.
        """
        offenders = [n for n in _lua_files()
                     if re.search(r"\bbitright\s*\(",
                                  _read(os.path.join(LUA_DIR, n)))]
        self.assertEqual(offenders, [],
                         "bitright() не существует в nfqws2 (нужно "
                         "bitrshift): %s" % offenders)

    def test_c_func_list_has_no_typos_against_upstream_usage(self):
        """Список C-функций не выдуман: upstream-lua их реально вызывает.

        Если бы мы вписали в `_NFQWS2_C_FUNCS` несуществующее имя, проверка
        стала бы дырявой ровно в этом месте. Поэтому требуем, чтобы ключевые
        имена встречались в дословных копиях релиза.
        """
        upstream_text = "".join(
            _read(os.path.join(LUA_DIR, n))
            for n in _lua_files() if n in _UPSTREAM_LUA)
        for name in ("bitrshift", "rawsend_dissect", "instance_cutoff",
                     "timer_set", "resolve_pos", "tls_mod", "brandom"):
            self.assertRegex(
                upstream_text, r"\b%s\b" % re.escape(name),
                "%s объявлена known, но upstream-lua её не использует — "
                "проверьте список _NFQWS2_C_FUNCS" % name)


@unittest.skipUnless(os.path.isdir(LUA_DIR), "vendored import/lua not present")
class TestAllowlistIsHonest(unittest.TestCase):
    """Allowlist не должен превращаться в свалку.

    Список исключений — самое слабое место такой проверки: достаточно
    дописать туда имя, и настоящая опечатка проедет незамеченной. Поэтому
    требуем, чтобы каждое исключение было НЕОБХОДИМО: без него проверка
    падает. Как только код поправили и имя стало резолвиться — исключение
    обязано уйти.
    """

    def test_every_allowlist_entry_is_still_needed(self):
        base = (set(_global_defs()) | _NFQWS2_C_FUNCS | _LUA_STDLIB
                | _LUA_KEYWORDS)
        needed = set(TestOurLuaCallsResolve._unresolved(base))
        stale = sorted(_ALLOWLIST - needed)
        self.assertEqual(
            stale, [],
            "исключения в _ALLOWLIST больше не нужны (имена резолвятся сами) "
            "— удалите их, иначе список маскирует будущие опечатки: %s"
            % stale)

    def test_allowlist_does_not_hide_real_functions(self):
        """В allowlist не должно быть имён, которые где-то определены."""
        defs = set(_global_defs())
        overlap = sorted(_ALLOWLIST & defs)
        self.assertEqual(
            overlap, [],
            "имена есть и в _ALLOWLIST, и среди определений — исключение "
            "лишнее и маскирует проверку: %s" % overlap)


if __name__ == "__main__":
    unittest.main()
