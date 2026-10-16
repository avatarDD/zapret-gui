# core/strategy_lint.py
"""
Линтер профилей nfqws2: что в argv заведомо не сработает.

Чистые функции без I/O — окружение (какие lua-функции и blob'ы есть на
этом устройстве) приходит **аргументами**. Поэтому линтер одинаково
годится странице стратегий, инструменту ``strategy_compose`` и обычному
юнит-тесту, которому не нужен ни роутер, ни поднятый MCP-сервер.

Зачем он вообще нужен рядом с `nfqws2 --intercept=0`. Валидация движком
ловит разбор опций, отсутствующие файлы и ошибки загрузки lua — и не
ловит целый класс бед, от которых стратегия «тихо не работает»:

* вызов несуществующей ``--lua-desync``-функции происходит **по-пакетно**,
  а не на lua-init: движок стартует, код выхода 0, обход не работает;
* незаявленный blob с 1.0.4 обрывает execution plan в C-коде ещё до входа
  в Lua — ни строки в логе (скил nfqws2-strategies §2);
* приём без ``--filter-*`` десинхронизирует весь трафик очереди, а не цель.

Ровно это и проверяется. Чего здесь НЕТ — правил «на всякий случай»:
ложное предупреждение дороже пропущенного, потому что модель верит
линтеру буквально и начинает переписывать работающую стратегию.

**Линтуется собранный argv** — тот, что вернул
``StrategyManager.build_nfqws_args`` (с автообёрткой «голого приёма»,
дозаявленными blob'ами и отрезолвленными путями), а не строка профиля из
редактора. Иначе линтер ругался бы на то, что сборщик чинит сам.

Использование::

    from core import strategy_lint

    findings = strategy_lint.lint(argv,
                                  known_functions={"fake", "multisplit"},
                                  known_blobs={"tls_google": True})
    summary = strategy_lint.summary(findings)   # errors / warnings / codes
"""

import re


# ─────────────────────────── уровни ────────────────────────────────
#
# error   — собранный argv заведомо не сработает (или сработает мимо);
# warning — подозрительно, но бывает осознанно.
SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

# Коды — стабильные символы: их сохраняет модель, на них ссылается UI и
# по ним же ищутся ложные срабатывания. Переименование кода = поломка
# контракта, текст сообщения менять можно.
CODE_BARE_TRICK = "bare_trick_no_filter"
CODE_UNKNOWN_LUA_FN = "unknown_lua_function"
CODE_BLOB_UNKNOWN = "blob_unknown"
CODE_BLOB_FILE_MISSING = "blob_file_missing"
CODE_BLOB_LATE_DECL = "blob_declared_after_new"
CODE_LUA_INIT_ORDER = "lua_init_order"
CODE_L7_WITHOUT_PORTS = "l7_filter_without_ports"
CODE_NO_DESYNC = "no_desync_action"
CODE_ENGINE_OPTION = "engine_owned_option"
CODE_TTL_FAKE_UDP = "ttl_fake_on_udp"
CODE_TCP_TS_ONLY = "tcp_ts_only_fooling"
CODE_BADACK_NO_TS_UP = "badack_without_ts_up"
CODE_FAKE_NO_BLOB = "fake_without_blob"

# Опции nfqws2, которыми владеет GUI, а не стратегия. Первые четыре —
# базовые аргументы (``NFQWSManager._build_base_args``): стратегия идёт
# ПОСЛЕ них, и последнее значение побеждает — ``--qnum``/``--fwmark``
# ломают перехват и собственный трафик GUI (те же поля закрыты на запись
# в ``config_set``), ``--user``/``--uid`` отменяют сброс прав, и lua
# стратегии исполняется от root. Остальные — операции с файлами,
# которые движок делает от root ещё на разборе опций: ``--pidfile``
# пишет куда скажут, ``--writable`` делает ``chown`` каталога
# пользователю движка (и существующего тоже — ``make_writable_dir``,
# nfq2/darkmagic.c), ``--daemon`` уводит процесс из-под присмотра GUI,
# ``--intercept``/``--dry-run`` превращают запуск в проверку.
ENGINE_OWNED_OPTIONS = (
    "--user", "--uid", "--qnum", "--fwmark",
    "--daemon", "--pidfile", "--writable", "--writeable",
    "--intercept", "--dry-run",
)

# Опции из ENGINE_OWNED_OPTIONS с ОБЯЗАТЕЛЬНЫМ значением. getopt_long
# nfqws2 принимает их и двумя токенами — `--pidfile /путь`, — а стратегия
# из текста режется по пробелам. Такое значение вырезается вместе с
# опцией, иначе оно остаётся висеть позиционным аргументом. Ту же форму
# `--hostlist-auto <путь>` проверяет сам сборщик
# (``NFQWSManager._strip_engine_owned``).
TAKES_VALUE = frozenset((
    "--user", "--uid", "--qnum", "--fwmark", "--pidfile",
))

# ``--debug=@<файл>``: nfqws2 открывает файл на запись (``"wt"`` —
# обнуляет) от root и отдаёт его пользователю движка. Остальные формы
# ``--debug`` (вывод в наш лог, syslog) безвредны и нужны.
_DEBUG_FILE_PREFIX = "--debug=@"

# Таблица правил: данные, а не цепочка `if`. `section` — адрес в
# справочнике, а не пересказ его своими словами: подсказка без адреса
# отправляет читателя искать наугад (тот же принцип, что у `ref` в
# `strategy_experiment.HINT_RULES`).
RULES = (
    {
        "code": CODE_BARE_TRICK,
        "severity": SEVERITY_WARNING,
        "title": "приём без фильтра профиля",
        "section": "скил nfqws2-strategies §3.7 (правила построения фильтров)",
    },
    {
        "code": CODE_UNKNOWN_LUA_FN,
        "severity": SEVERITY_ERROR,
        "title": "неизвестная lua-функция",
        "section": "скил nfqws2-strategies §8 (библиотека стратегий)",
    },
    {
        "code": CODE_BLOB_UNKNOWN,
        "severity": SEVERITY_ERROR,
        "title": "blob не объявлен и не известен реестру",
        "section": "скил nfqws2-strategies §2 (инварианты) и §7 (блобы)",
    },
    {
        "code": CODE_BLOB_FILE_MISSING,
        "severity": SEVERITY_ERROR,
        "title": "файла blob'а нет на устройстве",
        "section": "скил nfqws2-strategies §16 п.3 (нет blob-файлов)",
    },
    {
        "code": CODE_BLOB_LATE_DECL,
        "severity": SEVERITY_ERROR,
        "title": "--blob объявлен после --new",
        "section": "скил nfqws2-strategies §2 (инвариант 6) и §3.2",
    },
    {
        "code": CODE_LUA_INIT_ORDER,
        "severity": SEVERITY_ERROR,
        "title": "нарушен порядок --lua-init",
        "section": "скил nfqws2-strategies §2 (инвариант 1) и §12",
    },
    {
        "code": CODE_L7_WITHOUT_PORTS,
        "severity": SEVERITY_WARNING,
        "title": "--filter-l7 без портов",
        "section": "скил nfqws2-strategies §3.7 и §15 (типовые шаблоны)",
    },
    {
        "code": CODE_NO_DESYNC,
        "severity": SEVERITY_WARNING,
        "title": "в стратегии нет ни одного --lua-desync",
        "section": "скил nfqws2-strategies §12 (сборка argv)",
    },
    {
        "code": CODE_ENGINE_OPTION,
        "severity": SEVERITY_ERROR,
        "title": "опция, которой владеет GUI, а не стратегия",
        "section": "скил nfqws2-strategies §3.1–3.2 (глобальные опции) и "
                   "скил mcp, «Аргументы стратегии: чем владеет GUI»",
    },
    {
        "code": CODE_TTL_FAKE_UDP,
        "severity": SEVERITY_WARNING,
        "title": "фейк с пониженным TTL на UDP/QUIC",
        "section": "скил nfqws2-strategies §8.8 (ip_ttl/ip_autottl) и "
                   "§15.4 (QUIC)",
    },
    {
        "code": CODE_TCP_TS_ONLY,
        "severity": SEVERITY_WARNING,
        "title": "единственная маскировка фейка — tcp_ts (нужны метки TCP)",
        "section": "скил nfqws2-strategies §8 (fooling) и README, "
                   "«Вопросы» (Windows и временные метки TCP)",
    },
    {
        "code": CODE_BADACK_NO_TS_UP,
        "severity": SEVERITY_WARNING,
        "title": "фейк маскируется только через tcp_ack, без tcp_ts_up",
        "section": "скил nfqws2-strategies §8.8 (fooling, tcp_ts_up)",
    },
    {
        "code": CODE_FAKE_NO_BLOB,
        "severity": SEVERITY_ERROR,
        "title": "fake без blob=",
        "section": "скил nfqws2-strategies §8 (fake) и §7 (блобы)",
    },
)

_BY_CODE = {item["code"]: item for item in RULES}


# ───────────────────────── разбор argv ──────────────────────────────

# Имя функции в `--lua-desync=fn:arg=val`. Та же форма, что у
# `nfqws_manager._LUA_DESYNC_FUNC_RE`: две разные мерки одного и того же
# разошлись бы молча.
_LUA_DESYNC_RE = re.compile(r"^--lua-desync=([a-zA-Z0-9_]+)")

# Ссылка на blob внутри аргументов инстанса (`fake:blob=tls_google`).
# Оглядка назад отсекает саму декларацию `--blob=NAME:…`: там перед
# `blob=` стоит дефис.
_BLOB_REF_RE = re.compile(r"(?<!-)blob=([A-Za-z0-9_]+)")

# Декларация blob'а: `--blob=NAME:@файл` или `--blob=NAME:0xHEX`.
_BLOB_DECL_RE = re.compile(r"^--blob=([^:]+):")
_CLONE_BLOB_RE = re.compile(
    r"^--lua-desync=tls_client_hello_clone:(?:.*:)?blob=([A-Za-z0-9_]+)")

# Фильтры, которые реально сужают поток. `--filter-l3` (версия IP) и
# `--hostlist` сюда не входят намеренно: первый не ограничивает ни порт,
# ни протокол, второй не ограничивает payload — «голым приёмом» профиль
# с ними остаётся. Набор совпадает с `strategy_builder._FILTER_FLAG_RE`
# плюс icmp/ipp: профиль, суженный до ICMP, весь трафик не трогает.
_FILTER_NARROW_RE = re.compile(r"^--filter-(?:tcp|udp|l7|icmp|ipp)\b")
_FILTER_PORTS_RE = re.compile(r"^--filter-(?:tcp|udp)=")

# L7, которые в наших шаблонах всегда идут с портами (§15.1/15.2/15.4).
# Остальные (wireguard, stun, discord, dht, …) штатно живут без портов —
# см. §15.5, и предупреждать о них значило бы ругаться на документированно
# верную стратегию.
_PORT_BOUND_L7 = frozenset({"http", "tls", "quic"})

# Встроенные в сам nfqws2 имена блобов: объявлять их не нужно (§2).
_BUILTIN_BLOBS = frozenset({
    "fake_default_http", "fake_default_tls", "fake_default_quic",
})

# Ядро lua: `zapret-lib.lua` обязан грузиться первым — он определяет
# примитивы, на которые опирается всё остальное (§2, инвариант 1).
_CORE_LUA_FIRST = "zapret-lib"


def split_profiles(argv) -> list:
    """Разбить argv на профили по разделителю ``--new``.

    Первым элементом идёт «нулевая» секция — глобальные опции до первого
    ``--new`` (там же живут декларации ``--blob`` и ``--lua-init``).
    """
    profiles = [[]]
    for arg in argv or []:
        text = str(arg)
        if text == "--new" or text.startswith("--new="):
            profiles.append([])
            continue
        profiles[-1].append(text)
    return profiles


def _finding(code, message, where="", profile=None) -> dict:
    rule = _BY_CODE[code]
    out = {
        "code": code,
        "severity": rule["severity"],
        "message": message,
        "section": rule["section"],
    }
    if where:
        out["where"] = where
    if profile is not None:
        out["profile"] = profile
    return out


# ──────────────────────────── правила ───────────────────────────────

def _check_bare_trick(profiles) -> list:
    """Приём без ``--filter-*`` уедет на весь трафик очереди, а не на цель."""
    out = []
    for index, args in enumerate(profiles):
        if not any(_LUA_DESYNC_RE.match(a) for a in args):
            continue
        if any(_FILTER_NARROW_RE.match(a) for a in args):
            continue
        out.append(_finding(
            CODE_BARE_TRICK,
            "профиль %d десинхронизирует ВЕСЬ трафик очереди: в нём есть "
            "--lua-desync, но нет ни --filter-tcp, ни --filter-udp, ни "
            "--filter-l7. Приём может не попасть на нужный пакет — "
            "классический «тихий 0%%». Для каталожных приёмов "
            "(basic/advanced/direct) это НОРМА: фильтр цели подставляет "
            "сканер, и переписывать их не надо — добавляйте фильтр, "
            "когда собираете стратегию сами" % index,
            profile=index))
    return out


def _check_lua_functions(profiles, known_functions) -> list:
    """Вызов несуществующей функции — ошибка рантайма, а не запуска."""
    if not known_functions:
        return []
    known = {str(name) for name in known_functions}
    out = []
    seen = set()
    for index, args in enumerate(profiles):
        for arg in args:
            match = _LUA_DESYNC_RE.match(arg)
            if not match:
                continue
            name = match.group(1)
            if name in known or name in seen:
                continue
            seen.add(name)
            out.append(_finding(
                CODE_UNKNOWN_LUA_FN,
                "функции «%s» нет среди --lua-desync этого устройства: "
                "в lua неизвестное имя не ошибка загрузки, движок "
                "стартует и молча ничего не делает. Список — "
                "lua_functions_list()" % name,
                where=arg, profile=index))
    return out


def _check_blobs(profiles, known_blobs) -> list:
    """Незаявленный blob = ПУСТОЙ fake, и в логе про это ни строки."""
    if known_blobs is None:
        return []
    declared = set()
    for args in profiles:
        for arg in args:
            match = _BLOB_DECL_RE.match(arg)
            if match:
                declared.add(match.group(1).strip())

    out = []
    seen = set()
    for index, args in enumerate(profiles):
        # tls_client_hello_clone:blob=X сам готовит blob X в desync
        # соединения — ссылки на X законны дальше по ЭТОМУ профилю, но
        # не раньше шага clone и не в соседних профилях.
        cloned = set()
        for arg in args:
            clone = _CLONE_BLOB_RE.match(arg)
            refs = _BLOB_REF_RE.findall(arg)
            if clone:
                refs = [n for n in refs if n != clone.group(1)]
            for name in refs:
                if name in _BUILTIN_BLOBS or name in declared \
                        or name in cloned or name in seen:
                    continue
                if name.startswith("0x"):
                    # Инлайновый hex (`blob=0x0000…`) — это не имя, а само
                    # содержимое: объявлять нечего. Так живёт добрая
                    # полусотня каталожных приёмов, и ругаться на них
                    # значит учить модель не верить линтеру.
                    continue
                seen.add(name)
                if name not in known_blobs:
                    out.append(_finding(
                        CODE_BLOB_UNKNOWN,
                        "blob «%s» не объявлен через --blob= и не известен "
                        "реестру: с zapret2 1.0.4 такой инстанс сносится в "
                        "C-коде ещё до Lua — ни десинка, ни строки в логе. "
                        "Что есть — blobs_list()" % name,
                        where=arg, profile=index))
                elif known_blobs[name] is False:
                    out.append(_finding(
                        CODE_BLOB_FILE_MISSING,
                        "blob «%s» объявлен, но файла нет: движок "
                        "запустится и отправит ПУСТОЙ fake — обход тихо не "
                        "сработает. Проверить — "
                        "blobs_list(missing_only=true)" % name,
                        where=arg, profile=index))
            if clone:
                cloned.add(clone.group(1))
    return out


def _check_blob_declaration_order(profiles) -> list:
    """Декларации blob'ов глобальны, но читаются до первого ``--new``."""
    out = []
    for index, args in enumerate(profiles):
        if index == 0:
            continue
        for arg in args:
            match = _BLOB_DECL_RE.match(arg)
            if not match:
                continue
            out.append(_finding(
                CODE_BLOB_LATE_DECL,
                "объявление blob'а «%s» стоит после --new: декларации "
                "глобальные и должны идти ДО первого разделителя "
                "профилей, иначе fake уйдёт пустым"
                % match.group(1).strip(),
                where=arg, profile=index))
    return out


def _check_lua_init_order(argv) -> list:
    """``zapret-lib.lua`` грузится первым, иначе примитивов ещё нет."""
    inits = [a for a in argv if str(a).startswith("--lua-init=")]
    if not inits:
        return []
    positions = [i for i, a in enumerate(inits) if _CORE_LUA_FIRST in a]
    if not positions or positions[0] == 0:
        # Ядра в argv может не быть вовсе (стратегия без --lua-desync,
        # устройство без lua-скриптов) — это не повод ругаться: то, чего
        # нет, `_build_lua_init_args` и не добавляет.
        return []
    return [_finding(
        CODE_LUA_INIT_ORDER,
        "zapret-lib.lua загружается не первым (--lua-init №%d из %d): он "
        "определяет примитивы, на которые опираются zapret-antidpi и "
        "расширения — при таком порядке функции не зарегистрированы к "
        "моменту вызова" % (positions[0] + 1, len(inits)),
        where=inits[positions[0]])]


def _check_l7_without_ports(profiles) -> list:
    """``--filter-l7=tls`` без портов ведёт себя по-разному в версиях."""
    out = []
    for index, args in enumerate(profiles):
        if any(_FILTER_PORTS_RE.match(a) for a in args):
            continue
        for arg in args:
            if not arg.startswith("--filter-l7="):
                continue
            names = [n.strip().lower()
                     for n in arg.split("=", 1)[1].split(",")]
            bound = [n for n in names if n in _PORT_BOUND_L7]
            if not bound:
                continue
            out.append(_finding(
                CODE_L7_WITHOUT_PORTS,
                "профиль %d отбирает по --filter-l7=%s, но без "
                "--filter-tcp/--filter-udp: распознавание L7 без портов "
                "зависит от версии zapret2, и в наших шаблонах эти "
                "протоколы всегда идут с портом (§15.1, §15.2, §15.4)"
                % (index, ",".join(bound)),
                where=arg, profile=index))
    return out


# Опции, которые делают фейк «короче» пути: пакет умирает по дороге, и
# узел, где он умер, отвечает ICMP time-exceeded.
_TTL_OPT_RE = re.compile(r"(?:^|:)(ip6?_(?:auto)?ttl)=")
_FILTER_UDP_RE = re.compile(r"^--filter-udp=")
_QUIC_MARK_RE = re.compile(r"^--(?:filter-l7|payload)=.*\bquic")


def _check_ttl_fake_udp(profiles) -> list:
    """TTL-фейк на UDP: ICMP time-exceeded доходит до клиента.

    NAT роутера переводит ICMP «время жизни истекло» на фейк клиенту по
    кортежу его же потока (conntrack RELATED). Подключённый UDP-сокет
    получает ошибку на пакет, которого не посылал: Network.framework
    (Safari, iOS/macOS) закрывает QUIC-соединение, Chrome ICMP не
    слушает и проходит. Поймано в d2k (necronicle/d2k,
    datapath/include/d2k_icmpguard.h, поле 04.10.2026). У TCP ICMP на
    чужой сегмент — мягкая ошибка, поэтому только UDP.
    """
    out = []
    for index, args in enumerate(profiles):
        if not any(_FILTER_UDP_RE.match(a) or _QUIC_MARK_RE.match(a)
                   for a in args):
            continue
        for arg in args:
            if not _LUA_DESYNC_RE.match(arg):
                continue
            match = _TTL_OPT_RE.search(arg)
            if not match:
                continue
            out.append(_finding(
                CODE_TTL_FAKE_UDP,
                "профиль %d шлёт UDP-фейк с %s: узел, где фейк умрёт, "
                "ответит ICMP time-exceeded, и NAT роутера доставит его "
                "клиенту по его же потоку. Safari и приложения на "
                "Network.framework (iOS/macOS) после этого рвут QUIC, "
                "Chrome — нет, поэтому замер с компьютера проблему не "
                "покажет. Мусорный QUIC Initial сервер отбрасывает и без "
                "TTL — если обход работает без него, лучше убрать"
                % (index, match.group(1)),
                where=arg, profile=index))
            break
    return out


# Маскировки (fooling) шагов --lua-desync. tcp_ts правит опцию TCP
# timestamp — если клиент её не шлёт (Windows по умолчанию), править
# нечего, и фейк уходит серверу настоящим пакетом. Остальные маскировки
# от клиента не зависят. Только IPv4-годные: ip6_* на IPv4-пакет не
# действуют, и с ними IPv4 остаётся замаскированным одним tcp_ts.
# badseq — не из zapret-lib (apply_fooling его не знает), но его понимают
# наши функции (custom_funcs.lua, fakemultidisorder.lua): считаем, чтобы
# не ругаться на рабочую стратегию, но в совет не включаем.
_TS_FOOLING_RE = re.compile(r"(?:^|:)tcp_ts=")
_OTHER_FOOLING_RE = re.compile(
    r"(?:^|:)(?:ip_(?:auto)?ttl=|tcp_seq=|tcp_ack=|tcp_md5(?:=|:|$)|"
    r"tcp_flags_(?:set|unset)=|badsum(?::|$)|badseq(?::|$)|fool=)")


def _ts_only_step(arg: str) -> bool:
    """Шаг --lua-desync, у которого tcp_ts — единственная маскировка."""
    return bool(_LUA_DESYNC_RE.match(arg) and _TS_FOOLING_RE.search(arg)
                and not _OTHER_FOOLING_RE.search(arg))


def _udp_only_profile(args) -> bool:
    """Профиль только про UDP/QUIC — меток TCP он не касается."""
    udp = any(_FILTER_UDP_RE.match(a) or _QUIC_MARK_RE.match(a)
              for a in args)
    return udp and not any(a.startswith("--filter-tcp=") for a in args)


def needs_tcp_timestamps(argv) -> bool:
    """Есть ли в TCP-профиле шаг, у которого tcp_ts — единственная маскировка.

    Такая стратегия работает с роутера и с Linux/Android/macOS/iOS (метки
    TCP включены), а с Windows — нет: Windows по умолчанию меток не шлёт
    (``netsh interface tcp set global timestamps=enabled``). Сканер и
    подбор идут с роутера и этого не видят — отсюда «с роутера
    открывается, с ПК нет». Зеркало — ``Nfqws2Lint.needsTcpTimestamps``.
    """
    for args in split_profiles([str(a) for a in (argv or ())]):
        if _udp_only_profile(args):
            continue
        if any(_ts_only_step(a) for a in args):
            return True
    return False


def _check_tcp_ts_only(profiles) -> list:
    """Шаг, у которого tcp_ts — единственная маскировка (см. выше)."""
    out = []
    for index, args in enumerate(profiles):
        if _udp_only_profile(args):
            continue
        for arg in args:
            if not _ts_only_step(arg):
                continue
            out.append(_finding(
                CODE_TCP_TS_ONLY,
                "профиль %d маскирует фейк только через tcp_ts: это правка "
                "временной метки TCP, а Windows по умолчанию меток не шлёт — "
                "там фейк уйдёт серверу настоящим пакетом. С роутера и с "
                "Linux/Android/macOS/iOS работает, с Windows — нет. Добавьте "
                "вторую маскировку (tcp_md5, ip_autottl, tcp_seq) или включите "
                "метки в Windows: netsh interface tcp set global "
                "timestamps=enabled" % index,
                where=arg, profile=index))
            break
    return out


# badack (tcp_ack=N) без badseq: Linux отбрасывает сегмент с верным seq и
# неверным ack стабильно, только если опция timestamp в заголовке TCP
# идёт первой. nfqws1 ставил её первой всегда, nfqws2 сохраняет порядок
# клиента — и та же стратегия на nfqws2 работает через раз. tcp_ts_up
# (zapret-lib.lua, apply_fooling) поднимает метку наверх, как в nfqws1.
# Только функции, где маскировка ложится на фейки, а не на настоящие
# части: у multisplit/multidisorder tcp_ack — на самих данных.
_BADACK_FAKE_FNS = ("fake", "fakedsplit", "fakeddisorder", "hostfakesplit",
                    "fakemultisplit", "fakemultidisorder")
_BADACK_RE = re.compile(r"(?:^|:)tcp_ack=")
_TS_UP_RE = re.compile(r"(?:^|:)tcp_ts_up(?::|$)")
# Маскировки, при которых фейк до сервера и так не доходит или отброшен
# по другой причине — badack тогда не единственная защита.
_NON_ACK_FOOLING_RE = re.compile(
    r"(?:^|:)(?:ip_(?:auto)?ttl=|tcp_seq=|tcp_ts=|tcp_md5(?:=|:|$)|"
    r"badsum(?::|$)|badseq(?::|$)|fool=)")


def _badack_only_step(arg: str) -> bool:
    """Фейк-шаг, у которого tcp_ack — единственная маскировка, без tcp_ts_up."""
    m = _LUA_DESYNC_RE.match(arg)
    return bool(m and m.group(1) in _BADACK_FAKE_FNS
                and _BADACK_RE.search(arg) and not _TS_UP_RE.search(arg)
                and not _NON_ACK_FOOLING_RE.search(arg))


def _check_badack_ts_up(profiles) -> list:
    """badack без tcp_ts_up (см. выше)."""
    out = []
    for index, args in enumerate(profiles):
        if _udp_only_profile(args):
            continue
        for arg in args:
            if not _badack_only_step(arg):
                continue
            out.append(_finding(
                CODE_BADACK_NO_TS_UP,
                "профиль %d маскирует фейк только через tcp_ack без "
                "tcp_ts_up: Linux-сервер стабильно отбрасывает такой фейк, "
                "лишь когда метка TCP идёт первой опцией. nfqws1 ставил её "
                "первой всегда, nfqws2 — нет, и стратегия работает через "
                "раз. Добавьте tcp_ts_up (или вторую маскировку: tcp_seq, "
                "tcp_md5)" % index,
                where=arg, profile=index))
            break
    return out


# `fake` без `blob=`: zapret-antidpi.lua на первом же пакете бросает
# `error("fake: 'blob' arg required")` — приём ничего не шлёт, а под
# circular это пустой шаг ротации, на котором сайт «то открывается, то
# нет». Так написано и в апстрим-пресетах (MartinBacker, Uvvi2).
_BLOB_ARG_RE = re.compile(r"(?:^|:)blob=")


def _check_fake_blob(profiles) -> list:
    """`--lua-desync=fake` без `blob=` (см. выше)."""
    out = []
    for index, args in enumerate(profiles):
        for arg in args:
            m = _LUA_DESYNC_RE.match(arg)
            if not m or m.group(1) != "fake":
                continue
            if _BLOB_ARG_RE.search(arg[len("--lua-desync="):]):
                continue
            out.append(_finding(
                CODE_FAKE_NO_BLOB,
                "профиль %d: fake без blob= — lua бросит ошибку «fake: 'blob' "
                "arg required» на первом пакете, и приём ничего не пошлёт. "
                "Укажите фейк: blob=fake_default_tls (TLS), "
                "blob=fake_default_quic или fake_default_udp (UDP), "
                "blob=fake_default_http (HTTP)" % index,
                where=arg, profile=index))
    return out


def engine_owned(argv) -> list:
    """Аргументы стратегии, которые движку от неё передавать нельзя.

    ``[{index, arg, reason}]``. Сборщик (``NFQWSManager.compose_command``)
    их вырезает, линтер — называет: модель должна знать, почему её
    ``--qnum`` не доехал до движка.
    """
    out = []
    argv = list(argv or [])
    for index, arg in enumerate(argv):
        text = str(arg)
        name = text.split("=", 1)[0]
        if name in ENGINE_OWNED_OPTIONS:
            out.append({"index": index, "arg": text,
                        "reason": "%s задаёт GUI, а не стратегия" % name})
            if text in TAKES_VALUE and index + 1 < len(argv):
                out.append({"index": index + 1, "arg": str(argv[index + 1]),
                            "reason": "значение %s (записано отдельным "
                                      "аргументом)" % name})
        elif text.startswith(_DEBUG_FILE_PREFIX):
            out.append({"index": index, "arg": text,
                        "reason": "--debug в файл: nfqws2 обнуляет его от "
                                  "root; лог движка и так приходит в "
                                  "журнал GUI"})
    return out


def _check_engine_owned(argv) -> list:
    return [_finding(CODE_ENGINE_OPTION,
                     "%s — сборщик её вырежет" % item["reason"],
                     where=item["arg"])
            for item in engine_owned(argv)]


def _check_has_desync(argv) -> list:
    """argv без единого ``--lua-desync`` — это выключенный обход."""
    if any(_LUA_DESYNC_RE.match(str(a)) for a in argv):
        return []
    return [_finding(
        CODE_NO_DESYNC,
        "в аргументах нет ни одного --lua-desync: движок поднимется, "
        "пакеты будет разбирать, но не менять — снаружи это выглядит как "
        "«обход включён и не работает»")]


# ───────────────────────── точка входа ──────────────────────────────

def lint(argv, known_functions=None, known_blobs=None) -> list:
    """Проверить собранный argv nfqws2 и вернуть список замечаний.

    Args:
        argv: аргументы стратегии — то, что отдал
            ``StrategyManager.build_nfqws_args`` (без пути к бинарнику;
            лишний он не помешает, просто не будет ни на что похож).
        known_functions: имена доступных ``--lua-desync``-функций
            (``LuaManager.desync_functions()``). ``None`` или пусто —
            правило не проверяется: карты функций нет, и «неизвестной»
            оказалась бы каждая.
        known_blobs: ``{имя: существует_ли_файл}`` из
            ``blob_registry.list_blobs()`` плюс имена, которые объявляет
            lua (``nfqws_manager.lua_named_patterns()``). ``None`` —
            правила про blob'ы не проверяются.

    Returns:
        list[dict]: ``code``, ``severity``, ``message``, ``section`` и —
        когда есть, к чему привязаться — ``where`` и ``profile``.
        Порядок: ошибки первыми, внутри уровня — порядок обнаружения.
    """
    argv = [str(a) for a in (argv or [])]
    profiles = split_profiles(argv)

    findings = []
    findings.extend(_check_engine_owned(argv))
    findings.extend(_check_has_desync(argv))
    findings.extend(_check_lua_functions(profiles, known_functions))
    findings.extend(_check_blobs(profiles, known_blobs))
    findings.extend(_check_blob_declaration_order(profiles))
    findings.extend(_check_lua_init_order(argv))
    findings.extend(_check_bare_trick(profiles))
    findings.extend(_check_l7_without_ports(profiles))
    findings.extend(_check_ttl_fake_udp(profiles))
    findings.extend(_check_tcp_ts_only(profiles))
    findings.extend(_check_badack_ts_up(profiles))
    findings.extend(_check_fake_blob(profiles))

    # Ошибки первыми: окно ответа у модели конечное, и обрезать надо
    # предупреждения, а не то, из-за чего стратегия не работает.
    findings.sort(key=lambda f: 0 if f["severity"] == SEVERITY_ERROR else 1)
    return findings


def summary(findings) -> dict:
    """Свод по списку замечаний: сколько чего и какие коды сработали."""
    findings = list(findings or [])
    errors = [f for f in findings if f.get("severity") == SEVERITY_ERROR]
    warnings = [f for f in findings if f.get("severity") == SEVERITY_WARNING]
    return {
        "errors": len(errors),
        "warnings": len(warnings),
        "codes": sorted({f.get("code", "") for f in findings} - {""}),
        "blocking": bool(errors),
    }


def known_codes() -> list:
    """Коды всех правил — чтобы тесты и UI не заводили свои."""
    return [item["code"] for item in RULES]


def rule(code: str) -> dict:
    """Описание правила по коду (или пустой словарь)."""
    return dict(_BY_CODE.get(code) or {})
