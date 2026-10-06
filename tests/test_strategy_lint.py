# tests/test_strategy_lint.py
"""
Линтер профилей nfqws2: каждое правило на минимальном примере.

Здесь два вопроса к каждому правилу, и второй важнее первого:

1. срабатывает ли оно там, где должно;
2. **молчит ли оно там, где не должно.**

Ложное срабатывание дороже пропуска: модель верит линтеру буквально и,
получив предупреждение, начинает переписывать работающую стратегию.
Поэтому на каждое правило здесь есть «негативный» тест с эталонным
профилем из §15 справочника — тем самым, который писать МОЖНО.

Линтер — чистые функции: ни конфига, ни менеджеров, ни роутера. Карта
lua-функций и реестр блобов приходят аргументами, и в тестах они
задаются руками — иначе тест мерил бы содержимое /opt/zapret2 машины,
на которой его запустили.
"""

import unittest

from core import strategy_lint as lint


# Окружение «как на роутере»: что есть из функций и блобов.
FUNCTIONS = {"fake", "multisplit", "multidisorder", "fakedsplit", "drop",
             "tcpseg", "circular", "udplen"}
BLOBS = {"tls_google": True, "quic_google": True, "tls_missing": False}

# Эталонный профиль §15.2: TLS на 443 со списком, фейк + multidisorder.
GOOD = [
    "--filter-tcp=443", "--filter-l7=tls",
    "--hostlist=/opt/zapret2/lists/youtube.txt",
    "--out-range=-d10", "--payload=tls_client_hello",
    "--lua-desync=fake:blob=tls_google:tcp_md5:repeats=11",
    "--lua-desync=multidisorder:pos=1,midsld",
]


def codes(argv, functions=FUNCTIONS, blobs=BLOBS):
    return [f["code"] for f in lint.lint(argv, functions, blobs)]


class TestReferenceProfile(unittest.TestCase):
    """Стратегия из справочника не должна вызывать ни слова."""

    def test_reference_profile_is_silent(self):
        self.assertEqual(codes(GOOD), [])

    def test_every_finding_carries_code_severity_and_section(self):
        findings = lint.lint(["--lua-desync=nosuchfn"], FUNCTIONS, BLOBS)
        self.assertTrue(findings)
        for item in findings:
            with self.subTest(code=item.get("code")):
                self.assertIn(item["code"], lint.known_codes())
                self.assertIn(item["severity"],
                              (lint.SEVERITY_ERROR, lint.SEVERITY_WARNING))
                self.assertTrue(item["message"])
                # Замечание без адреса отправляет читателя искать наугад.
                self.assertTrue(item["section"])

    def test_errors_come_first(self):
        # Окно ответа конечное: обрезать надо предупреждения, а не то,
        # из-за чего стратегия не работает.
        argv = ["--lua-desync=nosuchfn"]          # error + warning разом
        severities = [f["severity"] for f in lint.lint(argv, FUNCTIONS, BLOBS)]
        self.assertEqual(severities,
                         sorted(severities,
                                key=lambda s: 0 if s == "error" else 1))
        self.assertIn(lint.SEVERITY_ERROR, severities)
        self.assertIn(lint.SEVERITY_WARNING, severities)


class TestBareTrick(unittest.TestCase):
    """Приём без фильтра профиля уедет на весь трафик очереди."""

    def test_trick_without_any_filter_warns(self):
        self.assertIn(lint.CODE_BARE_TRICK,
                      codes(["--payload=all", "--lua-desync=fake"]))

    def test_filtered_profile_is_silent(self):
        self.assertNotIn(lint.CODE_BARE_TRICK, codes(GOOD))

    def test_udp_only_filter_counts_as_a_filter(self):
        self.assertNotIn(lint.CODE_BARE_TRICK,
                         codes(["--filter-udp=443", "--lua-desync=udplen"]))

    def test_l7_only_filter_counts_as_a_filter(self):
        # §15.5: `--filter-l7=wireguard,stun` без портов — штатный шаблон.
        self.assertNotIn(
            lint.CODE_BARE_TRICK,
            codes(["--filter-l7=wireguard,stun", "--lua-desync=fake"]))

    def test_profile_without_desync_is_not_a_bare_trick(self):
        # Пустой профиль перед широким — законный способ исключить
        # трафик: побеждает первый подошедший (§3.7).
        argv = ["--filter-tcp=443", "--new",
                "--filter-tcp=*", "--lua-desync=fake"]
        self.assertNotIn(lint.CODE_BARE_TRICK, codes(argv))

    def test_the_message_says_catalog_tricks_are_normal(self):
        # Иначе модель начнёт «чинить» каталог: без фильтра там 600 с
        # лишним приёмов, и фильтр цели им подставляет сканер.
        finding = lint.lint(["--lua-desync=fake"], FUNCTIONS, BLOBS)
        text = next(f["message"] for f in finding
                    if f["code"] == lint.CODE_BARE_TRICK)
        self.assertIn("сканер", text)


class TestUnknownLuaFunction(unittest.TestCase):
    """В lua неизвестное имя — не ошибка загрузки, а тихий 0%."""

    def test_unknown_function_is_an_error(self):
        findings = lint.lint(GOOD + ["--lua-desync=fake_tls_v2"],
                             FUNCTIONS, BLOBS)
        item = next(f for f in findings
                    if f["code"] == lint.CODE_UNKNOWN_LUA_FN)
        self.assertEqual(item["severity"], lint.SEVERITY_ERROR)
        self.assertIn("fake_tls_v2", item["message"])
        self.assertIn("lua_functions_list", item["message"])

    def test_known_functions_are_silent(self):
        self.assertNotIn(lint.CODE_UNKNOWN_LUA_FN, codes(GOOD))

    def test_without_a_function_map_the_rule_is_skipped(self):
        # Карты нет — «неизвестной» оказалась бы каждая функция.
        self.assertNotIn(lint.CODE_UNKNOWN_LUA_FN,
                         codes(GOOD + ["--lua-desync=whatever"],
                               functions=None))

    def test_one_finding_per_name(self):
        argv = GOOD + ["--lua-desync=nope", "--lua-desync=nope"]
        self.assertEqual(codes(argv).count(lint.CODE_UNKNOWN_LUA_FN), 1)

    def test_orchestrator_arguments_are_not_function_calls(self):
        # detector=/success= у circular — это аргументы, а не вызовы:
        # companion'ы desync-действиями не являются (§2, инвариант 4).
        argv = ["--filter-tcp=443",
                "--lua-desync=circular:detector=combined_failure_detector"]
        self.assertNotIn(lint.CODE_UNKNOWN_LUA_FN, codes(argv))


class TestBlobs(unittest.TestCase):
    """Незаявленный blob = ПУСТОЙ fake, и в логе про это ни строки."""

    def test_unknown_blob_is_an_error(self):
        findings = lint.lint(["--filter-tcp=443",
                              "--lua-desync=fake:blob=tls_nope"],
                             FUNCTIONS, BLOBS)
        item = next(f for f in findings
                    if f["code"] == lint.CODE_BLOB_UNKNOWN)
        self.assertEqual(item["severity"], lint.SEVERITY_ERROR)
        self.assertIn("tls_nope", item["message"])

    def test_declared_blob_file_that_is_missing_is_an_error(self):
        self.assertIn(lint.CODE_BLOB_FILE_MISSING,
                      codes(["--filter-tcp=443",
                             "--lua-desync=fake:blob=tls_missing"]))

    def test_builtin_blobs_need_no_declaration(self):
        # fake_default_tls/http/quic встроены в сам nfqws2 (§2).
        self.assertEqual(
            codes(["--filter-tcp=443", "--payload=tls_client_hello",
                   "--lua-desync=fake:blob=fake_default_tls"]), [])

    def test_inline_hex_is_content_not_a_name(self):
        # `blob=0x0000…` — это само содержимое: объявлять нечего, и так
        # живёт полсотни каталожных приёмов (§7).
        self.assertEqual(
            codes(["--filter-l7=dht", "--filter-udp=*",
                   "--lua-desync=fake:blob=0x0000000000000000"]), [])

    def test_a_blob_declared_in_the_same_argv_is_fine(self):
        argv = ["--blob=my_tls:@/opt/zapret2/files/fake/x.bin",
                "--filter-tcp=443",
                "--lua-desync=fake:blob=my_tls"]
        self.assertEqual(codes(argv), [])

    def test_the_declaration_itself_is_not_a_reference(self):
        # `--blob=NAME:…` содержит подстроку «blob=», и без оглядки
        # назад каждое объявление читалось бы как ссылка на себя.
        argv = ["--blob=solo:0xAA", "--filter-tcp=443",
                "--lua-desync=fake:blob=solo"]
        self.assertNotIn(lint.CODE_BLOB_UNKNOWN, codes(argv))

    def test_without_a_registry_blob_rules_are_skipped(self):
        self.assertNotIn(
            lint.CODE_BLOB_UNKNOWN,
            codes(["--filter-tcp=443", "--lua-desync=fake:blob=whatever"],
                  blobs=None))

    def test_pattern_names_are_not_checked_as_blobs(self):
        # `seqovl_pattern=rnd` — переменная lua, заведённая luaexec'ом
        # соседним инстансом (§15.7), а не файл.
        argv = ["--filter-tcp=443",
                "--lua-desync=luaexec:code=x",
                "--lua-desync=tcpseg:pos=0,-1:seqovl_pattern=rnd"]
        self.assertNotIn(lint.CODE_BLOB_UNKNOWN,
                         codes(argv, functions=FUNCTIONS | {"luaexec"}))

    def test_declaration_after_new_is_an_error(self):
        # Декларации глобальны и читаются до первого --new (§2, инв. 6).
        argv = ["--filter-tcp=80", "--lua-desync=fake:blob=tls_google",
                "--new",
                "--blob=late:@/opt/zapret2/files/fake/late.bin",
                "--filter-tcp=443", "--lua-desync=fake:blob=late"]
        self.assertIn(lint.CODE_BLOB_LATE_DECL, codes(argv))

    def test_declaration_before_new_is_silent(self):
        argv = ["--blob=early:@/opt/zapret2/files/fake/e.bin",
                "--filter-tcp=80", "--lua-desync=fake:blob=early",
                "--new",
                "--filter-tcp=443", "--lua-desync=fake:blob=early"]
        self.assertEqual(codes(argv), [])


class TestLuaInitOrder(unittest.TestCase):
    """zapret-lib.lua первым — иначе примитивов ещё нет (§2, инв. 1)."""

    def test_core_not_first_is_an_error(self):
        argv = ["--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
                "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
                "--filter-tcp=443", "--lua-desync=fake:blob=tls_google"]
        findings = lint.lint(argv, FUNCTIONS, BLOBS)
        item = next(f for f in findings
                    if f["code"] == lint.CODE_LUA_INIT_ORDER)
        self.assertEqual(item["severity"], lint.SEVERITY_ERROR)

    def test_correct_order_is_silent(self):
        argv = ["--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
                "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
                "--filter-tcp=443", "--lua-desync=fake:blob=tls_google"]
        self.assertEqual(codes(argv), [])

    def test_no_core_at_all_is_silent(self):
        # На устройстве без lua-скриптов `_build_lua_init_args` не
        # добавляет ничего — ругаться на отсутствие нечего.
        self.assertNotIn(lint.CODE_LUA_INIT_ORDER, codes(GOOD))


class TestL7WithoutPorts(unittest.TestCase):
    """`--filter-l7=tls` без портов зависит от версии — предупреждение."""

    def test_tls_without_ports_warns(self):
        findings = lint.lint(
            ["--filter-l7=tls", "--lua-desync=fake:blob=tls_google"],
            FUNCTIONS, BLOBS)
        item = next(f for f in findings
                    if f["code"] == lint.CODE_L7_WITHOUT_PORTS)
        self.assertEqual(item["severity"], lint.SEVERITY_WARNING)

    def test_with_ports_is_silent(self):
        self.assertNotIn(lint.CODE_L7_WITHOUT_PORTS, codes(GOOD))

    def test_udp_protocols_without_ports_are_silent(self):
        # §15.5 — документированный шаблон без единого порта.
        argv = ["--filter-l7=wireguard,stun,discord",
                "--payload=wireguard_initiation,stun",
                "--lua-desync=fake:blob=0x0000"]
        self.assertEqual(codes(argv), [])


class TestNoDesyncAtAll(unittest.TestCase):
    """argv без единого --lua-desync — это выключенный обход."""

    def test_warns(self):
        self.assertIn(lint.CODE_NO_DESYNC, codes(["--ipcache-hostname"]))

    def test_silent_when_there_is_one(self):
        self.assertNotIn(lint.CODE_NO_DESYNC, codes(GOOD))

    def test_empty_argv_is_a_warning_not_a_crash(self):
        self.assertEqual(codes([]), [lint.CODE_NO_DESYNC])


class TestTtlFakeOnUdp(unittest.TestCase):
    """TTL-фейк на UDP: ICMP time-exceeded рвёт QUIC у Safari (d2k)."""

    def test_quic_fake_with_ttl_warns(self):
        found = lint.lint(["--filter-udp=443", "--filter-l7=quic",
                           "--lua-desync=fake:blob=fake_default_quic:"
                           "ip_ttl=4:repeats=6"])
        hit = [f for f in found if f["code"] == lint.CODE_TTL_FAKE_UDP]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], lint.SEVERITY_WARNING)
        self.assertIn("Safari", hit[0]["message"])

    def test_autottl_and_payload_quic(self):
        found = codes(["--payload=quic_initial",
                       "--lua-desync=fake:blob=fake_default_quic:"
                       "ip6_autottl=-2,3-20"])
        self.assertIn(lint.CODE_TTL_FAKE_UDP, found)

    def test_tcp_ttl_is_fine(self):
        # У TCP ICMP на чужой сегмент — мягкая ошибка: не ругаемся.
        self.assertNotIn(lint.CODE_TTL_FAKE_UDP, codes([
            "--filter-tcp=443", "--lua-desync=fake:blob=fake_default_tls:"
            "ip_autottl=-2,3-20"]))

    def test_udp_without_ttl_is_fine(self):
        self.assertNotIn(lint.CODE_TTL_FAKE_UDP, codes([
            "--filter-udp=443", "--lua-desync=fake:blob=fake_default_quic:"
            "repeats=6"]))

    def test_one_finding_per_profile(self):
        found = codes(["--filter-udp=443",
                       "--lua-desync=fake:blob=a:ip_ttl=3",
                       "--lua-desync=fake:blob=b:ip_ttl=4",
                       "--new", "--filter-udp=50000-65535",
                       "--lua-desync=fake:blob=c:ip_ttl=2"])
        self.assertEqual(found.count(lint.CODE_TTL_FAKE_UDP), 2)


class TestRuleTable(unittest.TestCase):
    """Сама таблица правил остаётся данными и остаётся полной."""

    def test_codes_are_unique(self):
        self.assertEqual(len(lint.known_codes()),
                         len(set(lint.known_codes())))

    def test_every_rule_has_severity_and_section(self):
        for code in lint.known_codes():
            with self.subTest(code=code):
                item = lint.rule(code)
                self.assertIn(item["severity"],
                              (lint.SEVERITY_ERROR, lint.SEVERITY_WARNING))
                self.assertTrue(item["section"])
                self.assertTrue(item["title"])

    def test_summary_counts_by_severity(self):
        findings = lint.lint(["--lua-desync=nosuchfn"], FUNCTIONS, BLOBS)
        summary = lint.summary(findings)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["warnings"], 1)
        self.assertTrue(summary["blocking"])
        self.assertIn(lint.CODE_UNKNOWN_LUA_FN, summary["codes"])

    def test_summary_of_nothing_is_not_blocking(self):
        summary = lint.summary([])
        self.assertEqual((summary["errors"], summary["warnings"]), (0, 0))
        self.assertFalse(summary["blocking"])

    def test_profiles_are_split_by_new(self):
        profiles = lint.split_profiles(["--a", "--new", "--b", "--new=x",
                                        "--c"])
        self.assertEqual(profiles, [["--a"], ["--b"], ["--c"]])


class TestCatalogIsNotNoisy(unittest.TestCase):
    """Сторож против ложных ошибок на встроенных стратегиях.

    Линтер, объявляющий ошибкой каждую вторую каталожную стратегию,
    бесполезен: модель перестанет ему верить. Предупреждения здесь
    законны (каталожные приёмы и правда идут без фильтра — их
    обёртывает сканер), а вот ОШИБОК быть не должно ни одной.
    """

    def test_builtin_strategies_have_no_lint_errors(self):
        from core.blob_registry import list_blobs
        from core.lua_manager import get_lua_manager
        from core.nfqws_manager import lua_named_patterns
        from core.strategy_builder import get_strategy_manager

        functions = {item["name"]
                     for item in get_lua_manager().desync_functions()}
        if not functions:
            self.skipTest("нет lua-скриптов — карту функций не собрать")
        # Файлы блобов лежат на роутере, а не на машине разработчика:
        # здесь проверяется «имя известно», а не «файл на месте».
        blobs = {item["name"]: True for item in list_blobs()}
        for name in lua_named_patterns():
            blobs.setdefault(name, True)

        manager = get_strategy_manager()
        bad = {}
        for strategy in manager.load_strategies():
            argv = manager.build_nfqws_args(strategy)
            for item in lint.lint(argv, functions, blobs):
                if item["severity"] == lint.SEVERITY_ERROR:
                    bad.setdefault(strategy["id"], item["message"])
        self.assertEqual(bad, {})


if __name__ == "__main__":
    unittest.main()
