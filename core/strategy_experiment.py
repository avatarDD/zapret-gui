# core/strategy_experiment.py
"""
Движок экспериментов со стратегиями: «изменил → увидел результат → откатил».

Ради этого замкнутого цикла затевался весь MCP. Модель (или кнопка
«Сравнить варианты» в UI) описывает несколько вариантов стратегии,
движок прогоняет каждый на одних и тех же целях, меряет одним и тем же
способом и возвращает отчёт, по которому видно **не только кто лучше,
но и почему остальные не сработали**. Человек между шагами не нужен.

Три вещи, которые делают это безопасным:

1. **Общий мьютекс.** Прогон целиком идёт под
   ``core/nfqws_session.py`` (владелец ``OWNER_EXPERIMENT``). Занято —
   отказ с именем держателя, а не тихая драка со сканером за движок.
2. **Снимок и возврат в ``finally``.** Состояние снимается до первого
   изменения и возвращается на каждом выходе — включая падение
   посередине и остановку по просьбе.
3. **Дедмен-свитч.** Не пришёл ``commit`` за ``ttl_sec`` — состояние
   возвращается само. Снимок при этом лежит **на диске**, поэтому
   выключение питания посреди эксперимента тоже не оставляет
   применённой временную стратегию: при следующем старте GUI
   :func:`recover_after_restart` вернёт всё как было.

**``keep_best`` — это не ``commit``.** Вариант, оставленный
применённым, всё равно доживает только до дедлайна: «оставить лучший»
означает «дай посмотреть», а не «утверждаю». Пока идёт это ожидание,
движок остаётся за экспериментом (мьютекс держит тот же поток, который
применил вариант), и решение исполняет он же — ровно поэтому
:meth:`ExperimentRunner.commit` не трогает движок сам, а передаёт
решение рабочему потоку.

Модуль живёт в ``core/``, а не в ``core/mcp/``: тем же движком
пользуется UI (S15 рисует по его отчёту страницу), а инструменты MCP
(``core/mcp/tools/experiments.py``) остаются тонкими обёртками —
контракт §2.
"""

from __future__ import annotations

import json
import os
import threading
import time

from core.log_buffer import log


# ───────────────────────────── состояния ────────────────────────────

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_FINISHED = "finished"
STATE_FAILED = "failed"
STATE_REVERTED = "reverted"

# Фаза внутри прогона — то, что показывают модели и UI.
PHASE_IDLE = "idle"
PHASE_SNAPSHOT = "снимок состояния"
PHASE_BASELINE = "baseline без обхода"
PHASE_VARIANT = "вариант"
PHASE_AWAIT = "ожидание commit"
PHASE_RESTORE = "восстановление"
PHASE_DONE = "готово"

SOURCE = "experiment"

# Имя файла со снимком рядом с settings.json. Не в /tmp: смысл файла в
# том, чтобы пережить выключение питания, а /tmp на роутере чистится.
MARKER_NAME = ".mcp-experiment.json"

# Сколько строк лога движка кладём в отчёт по варианту и сколько
# символов оставляем от строки. Больше модели не нужно: дальше идёт
# `logs_tail(source="nfqws", since=…)`.
LOG_TAIL = 20
LOG_LINE_MAX = 200

# Сколько аргументов варианта показываем в отчёте.
MAX_ARGS = 60

# Вывод dry-run: ошибка nfqws2 умещается в пару строк, а вот `-?` при
# опечатке во флаге печатает всю справку.
VALIDATION_OUTPUT_MAX = 600

# Сколько записей о прошлых прогонах помним (как `_jobs.KEEP`).
HISTORY_KEEP = 8

# Сколько ждёт `commit`/`rollback` ответа от рабочего потока. Решение
# исполняет он (мьютекс держит именно он), и вызывающему нужен ответ, а
# не «принято, посмотрите потом».
DECISION_WAIT_SEC = 45

# Потолки на случай, когда конфиг не прочитался.
DEFAULTS = {
    "default_ttl_sec": 180,
    "stabilize_sec": 3,
    "max_variants": 12,
    "max_targets": 5,
    "repeats": 2,
    "keep_best_default": False,
}

# Что умеет измерить наша проба (одна цепочка DNS → TCP → TLS → HTTP из
# `core/testers/probe.py`). Всё, что сюда не входит, честно уезжает в
# `probes_unsupported`: выдуманный замер хуже отсутствующего.
PROBE_KINDS = ("tls", "http", "body")
PROBE_KINDS_ALL = PROBE_KINDS + ("quic",)


# ───────────────────────── правила-подсказки ────────────────────────
#
# Данные, а не цепочка `if`: S11 дополняет этот список, не трогая код
# движка. Каждое правило говорит, ЧТО увидено и КУДА смотреть; `ref` —
# раздел справочника, а не пересказ его своими словами.

# Условие `log` — все подстроки `patterns` в ОДНОЙ строке лога nfqws2
# (регистр не важен). Именно в одной, а не где-нибудь в хвосте: движок
# печатает десятки строк за прогон, и «rawsend» из первой вместе с «not
# permitted» из десятой — это две разные беды, а не одна.
# Условие `metric` — имя предиката из `_METRIC_RULES`.
HINT_RULES = (
    {
        "id": "rawsend_eperm",
        "when": "log",
        # Сама строка выглядит как «rawsend: sendto: Operation not
        # permitted»: между словами — имя вызова, поэтому подстрок три.
        "patterns": ("rawsend", "sendto", "not permitted"),
        "hint": ("движок не смог отправить сырой пакет: проверьте "
                 "POSTNAT-правила и desync_mark_postnat — без них "
                 "подделанный пакет режется на выходе"),
        "ref": "скил nfqws2-strategies, раздел про firewall и NFQUEUE",
    },
    {
        "id": "lua_nil_call",
        "when": "log",
        "patterns": ("lua", "attempt to call a nil value"),
        "hint": ("стратегия зовёт несуществующую lua-функцию: сверьтесь "
                 "с lua_functions_list() — имя приёма на этом "
                 "устройстве может отличаться"),
        "ref": "скил nfqws2-strategies, раздел про --lua-desync",
    },
    {
        "id": "hostlist_missing",
        "when": "log",
        "patterns": ("register hostlist",),
        "hint": ("файла списка нет: hostlists_list() покажет, какие "
                 "есть, hostlist_edit() создаст нужный"),
        "ref": "скил nfqws2-strategies, раздел про hostlist'ы",
    },
    {
        "id": "blob_missing",
        "when": "log",
        "patterns": ("blob",),
        "hint": ("blob объявлен, но файла нет — nfqws2 шлёт ПУСТОЙ fake "
                 "и обход тихо не работает; blobs_list(missing_only=true)"),
        "ref": "скил nfqws2-strategies, раздел про blob'ы",
    },
    {
        "id": "queue_bind_failed",
        "when": "log",
        "patterns": ("bind", "queue"),
        "hint": ("очередь NFQUEUE не открылась: номер очереди занят "
                 "другим процессом — firewall_status() покажет "
                 "queue_numbers и расхождения"),
        "ref": "скил nfqws2-strategies, раздел про NFQUEUE",
    },
    # ── дополнено S11 по чеклисту §16 скила nfqws2-strategies ──
    {
        "id": "lua_compat_mismatch",
        "when": "log",
        # «Incompatible NFQWS2_COMPAT_VER»: zapret2 1.0 сменил compat 5→6,
        # и lua из другого релиза падает ровно этой строкой.
        "patterns": ("incompatible", "nfqws2_compat_ver"),
        "hint": ("lua-скрипты и бинарник nfqws2 из разных релизов: "
                 "переустановите движок или верните bundled-lua — "
                 "updates_check() покажет, что именно стоит"),
        "ref": "скил nfqws2-strategies §0.2 и §16 п.17",
    },
    {
        "id": "reasm_queue_overflow",
        "when": "log",
        # «rawpacket_queue failed !» — переполнена 64-пакетная очередь
        # реасма: стратегия на tls_client_hello перестаёт применяться.
        "patterns": ("rawpacket_queue", "failed"),
        "hint": ("переполнена очередь реасма: движок отменил сборку "
                 "многопакетного ClientHello и сбросил тип пейлоада в "
                 "unknown — стратегия на tls_client_hello/quic_initial на "
                 "этом соединении просто не применилась"),
        "ref": "скил nfqws2-strategies §8.10 и §16 п.18",
    },
    {
        "id": "lua_bad_argument",
        "when": "log",
        # «bad argument #2 to 'tls_mod' (string expected, got nil)» —
        # классика неверного порядка --lua-init: инлайн зовёт функцию,
        # которую ещё не загрузили.
        "patterns": ("bad argument",),
        "hint": ("lua-функции передан не тот аргумент: чаще всего это "
                 "порядок --lua-init (инлайновый вызов идёт раньше "
                 "скрипта, который его определяет) или опечатка в "
                 "значении параметра — сверьтесь с strategy_validate()"),
        "ref": "скил nfqws2-strategies §12.1 (валидация --intercept=0)",
    },
    {
        "id": "zero_everywhere",
        "when": "metric",
        "rule": "zero_success_valid_dry_run",
        "hint": ("вариант валиден, но не открылась НИ ОДНА цель: до "
                 "движка, похоже, не доходит трафик — проверьте правила "
                 "перехвата (firewall_status) и номер очереди"),
        "ref": "скил nfqws2-strategies, раздел про NFQUEUE",
    },
    {
        "id": "engine_did_not_start",
        "when": "metric",
        "rule": "engine_did_not_start",
        "hint": ("движок не поднялся с этим вариантом: чаще всего дело в "
                 "--user и правах на сырые сокеты; подробности — "
                 "logs_tail(source=\"nfqws\")"),
        "ref": "скил nfqws2-strategies, раздел про запуск движка",
    },
    {
        "id": "dry_run_failed",
        "when": "metric",
        "rule": "dry_run_failed",
        "hint": ("nfqws2 отверг аргументы ещё на валидации — вариант не "
                 "применялся вовсе; текст ошибки в validation.output"),
        "ref": "скил nfqws2-strategies, раздел про сборку argv",
    },
    {
        "id": "worse_than_baseline",
        "when": "metric",
        "rule": "worse_than_baseline",
        "hint": ("с этим вариантом хуже, чем БЕЗ обхода: он ломает то, "
                 "что работало — сравните его args с вариантом-соседом"),
        "ref": "скил nfqws2-strategies, раздел про инварианты фильтров",
    },
    # ── дополнено S18: подсказки по дампу (`capture=true`) ──
    #
    # Ровно ради них снифер и позвали внутрь эксперимента: «вариант B
    # хуже» — это цифра, а «у варианта B fake ушёл с TTL 1» — это
    # следующий шаг.
    {
        "id": "capture_empty",
        "when": "metric",
        "rule": "capture_empty",
        "hint": ("дамп снят, но в нём НИ ОДНОГО пакета: трафик пробы не "
                 "прошёл через интерфейс, на котором мы слушали — "
                 "проверьте capture.iface (по умолчанию это интерфейс "
                 "default route) и capture.filter"),
        "ref": "скил mcp, раздел про traffic_capture_*",
    },
    {
        "id": "capture_ttl_too_low",
        "when": "metric",
        "rule": "capture_ttl_too_low",
        "hint": ("в дампе есть пакеты с TTL ≤ 2: поддельный пакет "
                 "умирает на первом же хопе и до DPI не доезжает — "
                 "поднимите ttl/autottl в параметрах fake"),
        "ref": "скил nfqws2-strategies, раздел про fake и TTL",
    },
    {
        "id": "capture_sni_in_clear",
        "when": "metric",
        "rule": "capture_sni_in_clear",
        "hint": ("в дампе SNI виден целиком, и цель не открылась: "
                 "ClientHello ушёл неразрезанным — приём десинка не "
                 "применился к этому соединению (проверьте --filter-* и "
                 "тип пейлоада)"),
        "ref": "скил nfqws2-strategies, раздел про multisplit/multidisorder",
    },
    # ── дополнено: lua-дамп движка (`lua_capture=true`) ──
    #
    # Отвечает на вопрос, которого tcpdump не различает: пакет не дошёл
    # до стратегии или дошёл, а приём не справился.
    {
        "id": "lua_capture_empty",
        "when": "metric",
        "rule": "lua_capture_empty",
        "hint": ("движок поднят, пробы прошли, а lua-дамп пуст: ни один "
                 "профиль не получил ни пакета — трафик не доходит до "
                 "стратегии. Чините не приём, а фильтр: --filter-*/"
                 "--hostlist профиля, правила NFQUEUE (firewall_status) "
                 "и traffic_recent"),
        "ref": "скил nfqws2-strategies, раздел про фильтры профиля",
    },
)


def _metric_zero_success_valid_dry_run(m: dict) -> bool:
    validation = m.get("validation") or {}
    if validation.get("available") and not validation.get("ok"):
        return False
    return bool(m.get("started_nfqws")) and not m.get("ok_count")


def _metric_engine_did_not_start(m: dict) -> bool:
    return bool(m.get("applied_attempted")) and not m.get("started_nfqws")


def _metric_dry_run_failed(m: dict) -> bool:
    validation = m.get("validation") or {}
    return bool(validation.get("available")) and not validation.get("ok")


def _metric_worse_than_baseline(m: dict) -> bool:
    return bool(m.get("broken_count"))


def _metric_capture_empty(m: dict) -> bool:
    capture = m.get("capture") or {}
    return bool(capture.get("measured")) and not capture.get("packets")


def _metric_capture_ttl_too_low(m: dict) -> bool:
    """Fake ушёл с TTL, которого не хватит и на первый хоп.

    Смысл десинка в том, чтобы поддельный пакет умер ПОСЛЕ DPI и ДО
    сервера. TTL 1–2 означает, что он умирает на домашнем роутере или
    первом хопе провайдера: DPI его не увидит, и стратегия работает
    вхолостую — при том что в логе движка всё чисто.
    """
    capture = m.get("capture") or {}
    ttls = [int(value) for value in (capture.get("ttl") or {})
            if str(value).isdigit()]
    return len(ttls) > 1 and min(ttls) <= 2


def _metric_lua_capture_empty(m: dict) -> bool:
    """Движок поднят, пробы прошли, а ни один профиль не получил пакета."""
    dump = m.get("lua_capture") or {}
    return (bool(dump.get("measured")) and not dump.get("packets")
            and bool(m.get("started_nfqws")) and bool(m.get("target_count")))


def _metric_capture_sni_in_clear(m: dict) -> bool:
    """Имя ушло открытым текстом, а цель так и не открылась."""
    capture = m.get("capture") or {}
    return bool(capture.get("sni")) and not m.get("ok_count")


_METRIC_RULES = {
    "zero_success_valid_dry_run": _metric_zero_success_valid_dry_run,
    "engine_did_not_start": _metric_engine_did_not_start,
    "dry_run_failed": _metric_dry_run_failed,
    "worse_than_baseline": _metric_worse_than_baseline,
    "capture_empty": _metric_capture_empty,
    "capture_ttl_too_low": _metric_capture_ttl_too_low,
    "capture_sni_in_clear": _metric_capture_sni_in_clear,
    "lua_capture_empty": _metric_lua_capture_empty,
}


def hints_for(log_lines, metrics: dict = None) -> list:
    """Подсказки «почему не сработало» по логу и по измерениям.

    Порядок правил — порядок ``HINT_RULES``; одно правило срабатывает
    один раз, даже если строка встретилась трижды.
    """
    metrics = dict(metrics or {})
    lines = [str(line or "").lower() for line in (log_lines or [])]
    out = []
    for rule in HINT_RULES:
        if rule["when"] == "log":
            hit = any(all(part in line for part in rule["patterns"])
                      for line in lines)
        else:
            predicate = _METRIC_RULES.get(rule.get("rule", ""))
            hit = bool(predicate and predicate(metrics))
        if hit:
            out.append({"id": rule["id"], "hint": rule["hint"],
                        "ref": rule["ref"]})
    return out


def known_hint_ids() -> list:
    """Идентификаторы правил — чтобы тесты и UI не заводили свои."""
    return [rule["id"] for rule in HINT_RULES]


# ──────────────────────────── лимиты ────────────────────────────────

def limits() -> dict:
    """Лимиты экспериментов из ``mcp.experiment`` (с дефолтами)."""
    out = dict(DEFAULTS)
    try:
        from core.config_manager import get_config_manager
        section = get_config_manager().get("mcp", "experiment",
                                           default={}) or {}
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Лимиты экспериментов не прочитаны: %s" % e,
                  source=SOURCE)
        return out
    for key, default in DEFAULTS.items():
        value = section.get(key, default)
        if key == "keep_best_default":
            out[key] = bool(value)
            continue
        try:
            # Ноль осмыслен только у паузы стабилизации: «ноль целей» и
            # «ноль секунд TTL» означали бы движок, который ничего не
            # делает или откатывает всё мгновенно.
            out[key] = max(0 if key == "stabilize_sec" else 1, int(value))
        except (TypeError, ValueError):
            out[key] = default
    return out


# ──────────────────────────── движок ────────────────────────────────

class ExperimentRunner:
    """Прогон вариантов стратегии с измерением и гарантированным откатом."""

    def __init__(self):
        self._lock = threading.RLock()
        self._state = STATE_IDLE
        self._phase = PHASE_IDLE
        self._run_id = ""
        self._thread = None
        self._report = {}
        self._history = []

        self._stop_flag = threading.Event()
        self._settled = threading.Event()       # состояние уже улажено
        self._decision_evt = threading.Event()
        self._decision_done = threading.Event()
        self._decision = ""
        self._decision_args = {}
        self._decision_result = {}

        self._deadline = 0.0                    # time.monotonic()
        self._ttl_sec = 0
        self._expired = False
        self._committed = False
        self._applied_label = ""
        self._awaiting = False
        self._progress = (0, 0)
        self._variant_label = ""
        self._started_mono = 0.0
        self._claim_error = None

    # ───────────────────────────── запуск ────────────────────────────

    def start(self, variants, targets=None, probes=None, repeats=None,
              baseline: bool = True, ttl_sec=None, keep_best=None,
              capture=None, capture_port=None, lua_capture=None,
              source: str = SOURCE) -> dict:
        """Запустить эксперимент; ответ — ``run_id``, сразу.

        Прогон идёт минутами, а клиент рвёт HTTP-запрос через десятки
        секунд, поэтому контракт тот же, что у сканера (S8):
        ``start`` → ``get_status`` → ``get_result``.
        """
        cfg = limits()
        with self._lock:
            if self._state == STATE_RUNNING:
                return {
                    "ok": False,
                    "error": "эксперимент уже идёт",
                    "run_id": self._run_id,
                    "hint": ("состояние — strategy_experiment_status(), "
                             "остановка — strategy_experiment_stop()"),
                }

        prepared, rejected = self._prepare_variants(variants,
                                                    cfg["max_variants"])
        if not prepared:
            return {
                "ok": False,
                "error": "ни одного пригодного варианта",
                "rejected": rejected,
                "hint": ("вариант задаётся одним из трёх способов: args "
                         "(argv движка), strategy_id (существующая "
                         "стратегия) или profiles (как в strategy_save)"),
            }

        chosen, dropped = self._prepare_targets(targets, cfg["max_targets"])
        if not chosen:
            return {
                "ok": False,
                "error": "ни одной пригодной цели",
                "rejected": dropped,
                "hint": "цель — домен без схемы и пути, например youtube.com",
            }

        wanted, unsupported = _split_probes(probes)
        repeats = _bounded(repeats, cfg["repeats"], 1, 5)
        ttl = _bounded(ttl_sec, cfg["default_ttl_sec"], 30, 3600)
        keep = (cfg["keep_best_default"] if keep_best is None
                else bool(keep_best))
        # Снифер по окну каждого варианта (S18). Выключен по умолчанию:
        # это лишний процесс на каждый замер и заметный провайдеру след,
        # и просить его надо осознанно.
        sniff = _capture_plan(bool(capture), capture_port)
        # Lua-дамп движка (zapret-pcap.lua): что nfqws2 ПОЛУЧИЛ из
        # очереди — пара к tcpdump, который видит, что ушло в сеть.
        lua_dump = _lua_capture_plan(bool(lua_capture))

        run_id = "exp-%s" % time.strftime("%Y%m%d-%H%M%S")
        plan = {
            "run_id": run_id,
            "variants": prepared,
            "variants_rejected": rejected,
            "targets": chosen,
            "targets_rejected": dropped,
            "probes": wanted,
            "probes_unsupported": unsupported,
            "repeats": repeats,
            "baseline": bool(baseline),
            "ttl_sec": ttl,
            "keep_best": keep,
            "stabilize_sec": cfg["stabilize_sec"],
            "capture": sniff,
            "lua_capture": lua_dump,
            "source": source,
        }

        # Захват берёт РАБОЧИЙ поток: мьютекс потоко-привязан, и держать
        # его должен тот, кто будет применять варианты и возвращать всё
        # назад. Здесь мы только дожидаемся исхода захвата, чтобы отказ
        # «движок занят» пришёл синхронно, а не всплыл в статусе. Пока
        # захват не удался, прежний отчёт не трогаем: неудачный старт не
        # должен стирать результаты предыдущего прогона.
        opened = threading.Event()
        self._claim_error = None
        thread = threading.Thread(target=self._run, args=(plan, opened),
                                  daemon=True, name="mcp-experiment")
        with self._lock:
            self._thread = thread
        thread.start()
        opened.wait(timeout=10)

        busy = self._claim_error
        if busy is not None:
            holder = dict(getattr(busy, "holder", {}) or {})
            return {
                "ok": False,
                "error": "движок занят: %s" % busy,
                "busy": holder.get("owner", ""),
                "holder": holder,
                "hint": ("остановите операцию-держателя или дождитесь её "
                         "окончания: эксперимент меняет движок и делить "
                         "его не с кем"),
            }

        log.info("Эксперимент %s: %d вариант(ов), %d цель(ей), TTL %d с"
                 % (run_id, len(prepared), len(chosen), ttl), source=SOURCE)
        return {
            "ok": True,
            "run_id": run_id,
            "variants": len(prepared),
            "targets": list(chosen),
            "repeats": repeats,
            "baseline": bool(baseline),
            "ttl_sec": ttl,
            "keep_best": keep,
            "rejected": rejected + dropped,
            "probes_unsupported": unsupported,
            "capture": dict(sniff),
            "lua_capture": dict(lua_dump),
            "async": True,
        }

    # ───────────────────────────── опрос ─────────────────────────────

    def get_status(self) -> dict:
        """Где сейчас прогон: фаза, сколько сделано, сколько осталось TTL."""
        with self._lock:
            done, total = self._progress
            out = {
                "state": self._state,
                "run_id": self._run_id,
                "phase": self._phase,
                "variant": self._variant_label,
                "variant_index": done,
                "total": total,
                "progress": done,
                "ttl_sec": self._ttl_sec,
                "ttl_left_sec": self._ttl_left(),
                "awaiting_commit": self._awaiting,
                "applied_variant": self._applied_label,
                "committed": self._committed,
                "expired": self._expired,
                "elapsed_sec": (round(time.monotonic() - self._started_mono,
                                      1) if self._started_mono else 0.0),
            }
        out["eta_sec"] = _eta(out)
        return out

    def get_result(self, run_id: str = "") -> dict:
        """Отчёт прогона: ``run_id`` пустой — последний."""
        run_id = (run_id or "").strip()
        with self._lock:
            if not run_id or (self._report
                              and self._report.get("run_id") == run_id):
                return dict(self._report)
            for entry in reversed(self._history):
                if entry.get("run_id") == run_id:
                    return dict(entry)
            known = [e.get("run_id", "") for e in self._history]
        return {
            "ok": False,
            "error": "прогона %s нет" % run_id,
            "known_run_ids": known,
            "hint": ("отчёты живут в памяти процесса: после перезапуска "
                     "GUI их нет" if not known else
                     "известные прогоны: %s" % ", ".join(known)),
        }

    def history(self, limit: int = HISTORY_KEEP) -> list:
        """Короткие записи о прошлых прогонах, новые первыми."""
        with self._lock:
            entries = list(self._history)
            if self._report:
                entries.append(self._report)
        out = []
        for entry in reversed(entries):
            out.append({
                "run_id": entry.get("run_id", ""),
                "state": entry.get("state", ""),
                "started_at": entry.get("started_at", 0),
                "finished_at": entry.get("finished_at", 0),
                "variants": len(entry.get("variants") or []),
                "targets": list(entry.get("targets") or []),
                "best": entry.get("best", ""),
                "committed": bool(entry.get("committed")),
                "stopped": bool(entry.get("stopped")),
            })
            if len(out) >= max(1, int(limit or HISTORY_KEEP)):
                break
        return out

    # ──────────────────────────── решения ────────────────────────────

    def commit(self, label: str = "", save_as: str = "",
               save_name: str = "", make_active: bool = False) -> dict:
        """Оставить вариант применённым (и, по желанию, сохранить его).

        Работает только пока эксперимент ЖДЁТ решения: подтверждать
        нечего, если состояние уже возвращено. Исполняет решение
        рабочий поток — он держит мьютекс.
        """
        return self._decide("commit", {
            "label": (label or "").strip(),
            "save_as": (save_as or "").strip(),
            "save_name": (save_name or "").strip(),
            "make_active": bool(make_active),
        })

    def rollback(self) -> dict:
        """Вернуть состояние немедленно, не дожидаясь дедлайна."""
        with self._lock:
            waiting = self._awaiting
            running = self._state == STATE_RUNNING
        if waiting:
            return self._decide("rollback", {})
        if running:
            # Прогон ещё идёт: откат = остановка (состояние вернётся в
            # `finally`, как и при любом другом выходе).
            return self.stop(reason="откат по просьбе")
        return self._restore_now("откат по просьбе")

    def stop(self, reason: str = "остановка по просьбе") -> dict:
        """Попросить прогон остановиться; состояние вернётся само."""
        with self._lock:
            if self._state != STATE_RUNNING:
                return {"ok": True, "stopped": False,
                        "state": self._state,
                        "hint": "эксперимент не идёт — останавливать нечего"}
            waiting = self._awaiting
            run_id = self._run_id
        if waiting:
            return self._decide("rollback", {"reason": reason})
        self._stop_flag.set()
        log.info("Эксперимент %s: запрошена остановка (%s)"
                 % (run_id, reason), source=SOURCE)
        return {
            "ok": True,
            "stopped": True,
            "run_id": run_id,
            "hint": ("текущий вариант дотягивается, затем состояние "
                     "возвращается к снимку; отчёт — "
                     "strategy_experiment_result()"),
        }

    # ─────────────────────────── сам прогон ──────────────────────────

    def _run(self, plan: dict, opened: threading.Event) -> None:
        """Тело рабочего потока: захват → снимок → прогон → возврат."""
        from core.nfqws_session import (OWNER_EXPERIMENT, SessionBusy,
                                        get_nfqws_session)

        session = get_nfqws_session()
        try:
            hold = session.claim(
                owner=OWNER_EXPERIMENT, timeout=0,
                reason="эксперимент %s (%d вариант(ов))"
                       % (plan["run_id"], len(plan["variants"])))
        except SessionBusy as busy:
            self._claim_error = busy
            opened.set()
            return
        self._reset_for(plan)
        opened.set()

        snapshot = {}
        try:
            self._set_phase(PHASE_SNAPSHOT)
            snapshot = session.snapshot(source=SOURCE)
            _write_marker(plan, snapshot)
            self._execute(plan, session, snapshot)
        except Exception as e:                  # noqa: BLE001 — граница
            log.error("Эксперимент %s упал: %s: %s"
                      % (plan["run_id"], type(e).__name__, e), source=SOURCE)
            with self._lock:
                self._report["error"] = "%s: %s" % (type(e).__name__, e)
                self._state = STATE_FAILED
        finally:
            try:
                if not self._committed:
                    self._set_phase(PHASE_RESTORE)
                    _stop_engine()
                    restored = session.restore(snapshot, source=SOURCE)
                    with self._lock:
                        self._report["restored"] = bool(restored.get("ok"))
                        self._report["restore_error"] = restored.get(
                            "error", "")
                        self._report["restore_changed"] = list(
                            restored.get("changed") or [])
            finally:
                _drop_marker()
                hold.release()
                self._finish()

    def _execute(self, plan: dict, session, snapshot: dict) -> None:
        """Baseline, варианты, ранжирование и ожидание решения."""
        from core import nfqws_control

        report = self._report
        report["snapshot"] = dict(snapshot)

        if plan["baseline"]:
            self._set_phase(PHASE_BASELINE)
            # Мерить «как без обхода» обычной пробой на работающем
            # движке нельзя: это измерение обхода, а не его отсутствия.
            # Проба с меткой (core/probe_mark.py) идёт мимо очереди — и
            # обход у остальной сети не пропадает на время замера. Нет
            # метки (или правил с её исключением) — гасим движок.
            from core import probe_mark
            mode = probe_mark.baseline_mode()
            if mode["marked"]:
                report["baseline"] = self._measure(
                    plan, note="пробы с меткой мимо очереди, движок не "
                               "останавливался", mark=mode["mark"])
                report["baseline"]["engine_stopped"] = False
                report["baseline"]["method"] = "probe_mark"
            else:
                stopped = nfqws_control.stop(source=SOURCE)
                report["baseline"] = self._measure(
                    plan, note=("движок остановлен" if stopped.get("ok")
                                else "движок не остановился: %s"
                                     % (stopped.get("error") or "—")))
                report["baseline"]["engine_stopped"] = bool(
                    stopped.get("ok"))
                report["baseline"]["method"] = "engine_stopped"
            report["baseline"]["method_note"] = mode["reason"]
        else:
            report["baseline"] = {"measured": False,
                                  "reason": "baseline не запрашивался"}

        open_targets = [row["target"]
                        for row in report["baseline"].get("per_target") or []
                        if row.get("ok")]
        report["baseline"]["open_without_bypass"] = open_targets
        if open_targets:
            report.setdefault("warnings", []).append(
                "цели открыты и БЕЗ обхода (%s): выводы по ним "
                "недостоверны — стратегии там чинить нечего"
                % ", ".join(open_targets[:5]))

        total = len(plan["variants"])
        for index, variant in enumerate(plan["variants"], start=1):
            if self._stop_flag.is_set() or self._past_deadline():
                report.setdefault("warnings", []).append(
                    "прогон прерван на варианте %d из %d (%s)"
                    % (index, total,
                       "TTL" if self._past_deadline() else "по просьбе"))
                report["stopped"] = True
                break
            with self._lock:
                self._progress = (index, total)
                self._variant_label = variant["label"]
                self._phase = "%s %s" % (PHASE_VARIANT, variant["label"])
            report["variants"].append(
                self._run_variant(plan, variant, open_targets))

        self._rank(report)
        # Память подбора (S18): отчёт живёт в памяти процесса и умрёт с
        # ним, а «что сработало на этом домене» должно пережить
        # перезапуск — иначе следующая модель гоняет те же варианты по
        # второму кругу.
        _memory_write(report)
        self._await_decision(plan, session, snapshot)

    def _run_variant(self, plan: dict, variant: dict,
                     open_targets: list) -> dict:
        """Один вариант: валидация → применение → пробы → лог → стоп."""
        from core import nfqws_control

        started = time.time()
        out = {
            "label": variant["label"],
            "source": variant["source"],
            "args": [str(a) for a in variant["args"][:MAX_ARGS]],
            "args_truncated": len(variant["args"]) > MAX_ARGS,
            "args_count": len(variant["args"]),
            "validation": _validate(variant["args"]),
            "started_nfqws": False,
            "applied": False,
            "skipped": False,
            "skip_reason": "",
        }
        if variant.get("strategy_id"):
            out["strategy_id"] = variant["strategy_id"]

        validation = out["validation"]
        if validation.get("available") and not validation.get("ok"):
            # Применять argv, который движок уже отверг, значит потратить
            # минуту на заведомо мёртвый вариант и засорить лог.
            out["skipped"] = True
            out["skip_reason"] = "аргументы не прошли валидацию nfqws2"
            out["per_target"] = []
            out["success_rate"] = 0.0
            out["score"] = 0.0
            out["elapsed_sec"] = round(time.time() - started, 2)
            out["hints"] = hints_for([], _metrics(out, 0, 0))
            return out

        # Lua-дамп: `pcap` встаёт перед первым приёмом каждого профиля.
        # В отчёт и в commit уходят args БЕЗ него — это инструмент
        # замера, а не часть стратегии.
        run_args, lua_files = list(variant["args"]), []
        lua_plan = plan.get("lua_capture") or {}
        if lua_plan.get("wanted") and lua_plan.get("available"):
            from core import lua_capture
            run_args, lua_files = lua_capture.inject(run_args,
                                                     variant["label"])
            lua_capture.clear(lua_files)
            if not lua_files:
                out["lua_capture"] = {
                    "measured": False,
                    "reason": "в argv нет ни одного --lua-desync: пакеты "
                              "идут мимо lua, писать нечего"}

        window_start = time.time()
        applied = nfqws_control.restart(run_args, source=SOURCE)
        out["applied"] = True
        out["started_nfqws"] = bool(applied.get("ok"))
        if not applied.get("ok"):
            out["engine_error"] = str(applied.get("error") or "")[:200]

        if out["started_nfqws"] and plan["stabilize_sec"]:
            time.sleep(plan["stabilize_sec"])

        measured = self._measure(plan, note="")
        out["per_target"] = measured["per_target"]
        out["success_rate"] = measured["success_rate"]
        out["avg_latency_ms"] = measured["avg_latency_ms"]
        out["avg_kbps"] = measured["avg_kbps"]
        if measured.get("capture"):
            # Снятое по окну ИМЕННО этого варианта: что ушло в сеть
            # после движка, а не что собирались отправить.
            out["capture"] = measured["capture"]
        if lua_files:
            out["lua_capture"] = _lua_capture_end(lua_files)

        # Хвост лога режем ПО ОКНУ ВАРИАНТА: иначе в отчёт уезжает лог
        # предыдущего варианта, и модель чинит не то, что сломано.
        out["nfqws_log"] = _log_window(window_start, time.time())
        out["log_truncated"] = len(out["nfqws_log"]) >= LOG_TAIL

        out["delta_vs_baseline"] = self._delta(out["per_target"],
                                               open_targets)
        fixed = len(out["delta_vs_baseline"]["fixed"])
        broken = len(out["delta_vs_baseline"]["broken"])
        out["score"] = _score(out, open_targets)
        out["elapsed_sec"] = round(time.time() - started, 2)
        out["hints"] = hints_for(out["nfqws_log"],
                                 _metrics(out, fixed, broken))

        # Между вариантами движок гасим: следующий поднимется своим
        # `restart`, а лог и conntrack не перемешаются.
        nfqws_control.stop(source=SOURCE)
        return out

    def _measure(self, plan: dict, note: str = "", mark: int = 0) -> dict:
        """Пробы по всем целям одним проходом, медиана по повторам.

        Снифер (S18) включается ровно на это окно: он должен видеть
        пакеты ЭТОГО варианта и ничьи больше. Дамп идёт параллельно
        пробам и глушится сразу после них — иначе в отчёт уехали бы
        пакеты следующего варианта, и вывод «у B фейк с TTL 1» оказался
        бы про C.
        """
        from core import probe_runner

        capture = _capture_begin(plan)
        try:
            timeout = probe_runner.limits()["timeout_sec"]
            rows, latencies, kbps_all, ok_count = [], [], [], 0
            for target in plan["targets"]:
                if self._stop_flag.is_set():
                    break
                row = probe_runner.probe_target(
                    target, timeout=timeout, repeats=plan["repeats"],
                    latency=probe_runner.MEDIAN, mark=mark)
                row["kbps"] = _kbps(row)
                rows.append(_compact_probe(row))
                if row.get("ok"):
                    ok_count += 1
                    latencies.append(float(row.get("latency_ms") or 0.0))
                    kbps_all.append(row["kbps"])
        finally:
            # Снифер не имеет права испортить замер — в том числе своим
            # падением: исключение из `finally` заменило бы собой
            # настоящую ошибку прогона, и в отчёте оказалось бы не то.
            try:
                sniffed = _capture_end(capture)
            except Exception as e:              # noqa: BLE001 — граница
                log.debug("Разбор дампа не удался: %s: %s"
                          % (type(e).__name__, e), source=SOURCE)
                sniffed = {"measured": False,
                           "error": "%s: %s" % (type(e).__name__, e)}
        total = len(rows) or 1
        out = {
            "measured": bool(rows),
            "note": note,
            "per_target": rows,
            "ok_count": ok_count,
            "success_rate": round(ok_count / float(total), 3),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 1)
                              if latencies else 0.0,
            "avg_kbps": round(sum(kbps_all) / len(kbps_all), 1)
                        if kbps_all else 0.0,
        }
        if sniffed:
            out["capture"] = sniffed
        return out

    def _delta(self, rows, open_targets) -> dict:
        """Что вариант починил, что сломал, а что не изменил.

        База — baseline: цель, открытая и без обхода, в «починенные» не
        попадает никогда, иначе победителем стал бы вариант, который
        ничего не делает.
        """
        baseline = {row["target"]: bool(row.get("ok"))
                    for row in (self._report.get("baseline", {})
                                .get("per_target") or [])}
        fixed, broken, unchanged = [], [], []
        for row in rows:
            target = row["target"]
            was = baseline.get(target)
            now = bool(row.get("ok"))
            if was is None:
                unchanged.append(target)
            elif now and not was:
                fixed.append(target)
            elif was and not now:
                broken.append(target)
            else:
                unchanged.append(target)
        return {
            "fixed": fixed,
            "broken": broken,
            "unchanged": unchanged,
            "net": len(fixed) - len(broken),
            "baseline_open": [t for t in open_targets
                              if t in {r["target"] for r in rows}],
        }

    def _rank(self, report: dict) -> None:
        """Ранжирование по той же формуле score, что показывает UI."""
        usable = [v for v in report["variants"] if not v.get("skipped")]
        ranking = sorted(usable, key=lambda v: (-float(v.get("score") or 0),
                                                -float(v.get("success_rate")
                                                       or 0),
                                                v["label"]))
        report["ranking"] = [{
            "label": v["label"],
            "score": v.get("score", 0.0),
            "success_rate": v.get("success_rate", 0.0),
            "net": (v.get("delta_vs_baseline") or {}).get("net", 0),
        } for v in ranking]
        # Победитель — не просто «первый по score». Score считается
        # формулой сканера и у варианта на уже открытой цели выходит
        # ненулевым; объявить такого лучшим значило бы выдать за находку
        # прогон, в котором чинить было нечего. Поэтому при измеренном
        # baseline от победителя требуется, чтобы он что-то ПОЧИНИЛ.
        measured = bool((report.get("baseline") or {}).get("measured"))
        best = ""
        for item in ranking:
            if not item.get("score"):
                continue
            delta = self._delta_of(report, item["label"])
            if measured and not delta.get("fixed"):
                continue
            best = item["label"]
            break
        report["best"] = best
        if not best:
            report.setdefault("warnings", []).append(
                "ни один вариант не открыл ни одной цели, закрытой без "
                "обхода — смотрите hints по вариантам и dpi_report()")

    @staticmethod
    def _delta_of(report: dict, label: str) -> dict:
        for entry in report.get("variants") or []:
            if entry["label"] == label:
                return entry.get("delta_vs_baseline") or {}
        return {}

    # ─────────────────────── ожидание решения ────────────────────────

    def _await_decision(self, plan: dict, session, snapshot: dict) -> None:
        """Оставить лучший применённым и ждать ``commit`` до дедлайна.

        Ждём только когда есть что оставлять: держать мьютекс «просто
        так» значило бы запереть движок для UI и сканера на весь TTL
        при уже возвращённом состоянии.
        """
        report = self._report
        if not plan["keep_best"] or not report.get("best"):
            report["awaiting_commit"] = False
            if plan["keep_best"]:
                report.setdefault("warnings", []).append(
                    "оставлять нечего: ни один вариант не сработал")
            return

        applied = self._apply_label(plan, report["best"])
        report["applied"] = applied
        if not applied.get("ok"):
            report["awaiting_commit"] = False
            return

        with self._lock:
            self._awaiting = True
            self._applied_label = applied["label"]
            self._phase = PHASE_AWAIT
            # Перебор кончился: «текущий вариант» теперь не тот, что
            # мерили последним, а тот, что ОСТАВЛЕН применённым.
            self._variant_label = applied["label"]
        report["awaiting_commit"] = True
        log.warning("Эксперимент %s: вариант %s оставлен применённым, "
                    "ждём commit (%d с), иначе откат"
                    % (plan["run_id"], applied["label"],
                       self._ttl_left()), source=SOURCE)

        while True:
            left = self._ttl_left()
            if left <= 0:
                break
            if self._decision_evt.wait(min(left, 1.0)):
                break
            if self._stop_flag.is_set():
                break

        with self._lock:
            decision = self._decision
            decision_args = dict(self._decision_args)
            self._awaiting = False
        try:
            if decision == "commit":
                self._decision_result = self._do_commit(plan, decision_args)
            elif decision == "rollback":
                self._decision_result = {
                    "ok": True, "reverted": True,
                    "hint": "состояние возвращается к снимку"}
                report["reverted_reason"] = "откат по просьбе"
            elif self._stop_flag.is_set():
                report["reverted_reason"] = "остановка по просьбе"
                log.info("Эксперимент %s: остановлен во время ожидания "
                         "commit — возвращаем состояние" % plan["run_id"],
                         source=SOURCE)
            else:
                with self._lock:
                    self._expired = True
                report["reverted_reason"] = (
                    "дедмен: commit не пришёл за %d с" % plan["ttl_sec"])
                report.setdefault("warnings", []).append(
                    report["reverted_reason"])
                log.warning("Эксперимент %s: %s — возвращаем состояние"
                            % (plan["run_id"], report["reverted_reason"]),
                            source=SOURCE)
        finally:
            if decision:
                self._decision_done.set()

    def _do_commit(self, plan: dict, args: dict) -> dict:
        """Подтвердить вариант: оставить, при желании сохранить и активировать."""
        report = self._report
        label = args.get("label") or report.get("best", "")
        if label != self._applied_label:
            applied = self._apply_label(plan, label)
            if not applied.get("ok"):
                return applied
            report["applied"] = applied

        out = {"ok": True, "label": label, "committed": True,
               "run_id": plan["run_id"]}
        variant = self._variant(label)
        if args.get("save_as"):
            out["saved"] = _save_strategy(
                args["save_as"], args.get("save_name") or label,
                variant, plan)
            if out["saved"].get("ok") and args.get("make_active"):
                out["activated"] = _activate(args["save_as"])
        elif args.get("make_active"):
            out["activated"] = {
                "ok": False,
                "error": "нечего делать активным: без save_as стратегия "
                         "не сохранялась",
                "hint": "передайте save_as, чтобы записать вариант "
                        "USER-стратегией",
            }

        with self._lock:
            self._committed = True
        report["committed"] = True
        report["commit"] = out
        # Память подбора (S18): «померили» и «оставили работать» — разное
        # знание, и следующая модель должна их различать.
        if variant:
            _memory_commit(variant.get("args") or [], plan.get("targets"))
        log.success("Эксперимент %s: вариант %s подтверждён"
                    % (plan["run_id"], label), source=SOURCE)
        return out

    def _apply_label(self, plan: dict, label: str) -> dict:
        """Применить вариант по метке (движок уже наш)."""
        from core import nfqws_control

        variant = self._variant(label)
        if not variant:
            return {"ok": False, "error": "варианта %s в прогоне нет" % label,
                    "known": [v["label"] for v in self._report["variants"]],
                    "hint": "метки вариантов — в отчёте прогона"}
        spec = next((v for v in plan["variants"] if v["label"] == label), None)
        argv = list(spec["args"]) if spec else []
        result = nfqws_control.restart(argv, source=SOURCE)
        return {
            "ok": bool(result.get("ok")),
            "label": label,
            "error": str(result.get("error") or ""),
            "running": bool((result.get("nfqws") or {}).get("running")),
        }

    def _variant(self, label: str):
        for entry in self._report.get("variants") or []:
            if entry["label"] == label:
                return entry
        return None

    def _decide(self, decision: str, args: dict) -> dict:
        """Передать решение рабочему потоку и дождаться его исполнения."""
        with self._lock:
            if not self._awaiting:
                return {
                    "ok": False,
                    "error": "эксперимент не ждёт решения",
                    "state": self._state,
                    "hint": ("подтверждать нечего: состояние уже "
                             "возвращено. Чтобы вариант оставался "
                             "применённым, запускайте с keep_best=true "
                             "— либо сохраните его strategy_save() и "
                             "примените strategy_apply()"),
                }
            self._decision = decision
            self._decision_args = dict(args)
            self._decision_result = {}
        self._decision_done.clear()
        self._decision_evt.set()
        if not self._decision_done.wait(DECISION_WAIT_SEC):
            return {"ok": True, "accepted": True, "pending": True,
                    "hint": ("решение принято, но рабочий поток ещё не "
                             "ответил — посмотрите "
                             "strategy_experiment_status()")}
        result = dict(self._decision_result)
        result.setdefault("ok", True)
        return result

    def _restore_now(self, reason: str) -> dict:
        """Вернуть состояние по снимку вне прогона (аварийный путь)."""
        from core.nfqws_session import get_nfqws_session

        snapshot = (self._report or {}).get("snapshot") or _read_marker()
        if not snapshot:
            return {"ok": False,
                    "error": "снимка нет: возвращать нечего",
                    "hint": "состояние движка — nfqws_status()"}
        result = get_nfqws_session().restore(
            snapshot.get("snapshot", snapshot), source=SOURCE)
        _drop_marker()
        with self._lock:
            self._state = STATE_REVERTED
        log.info("Эксперимент: состояние возвращено (%s)" % reason,
                 source=SOURCE)
        return {"ok": bool(result.get("ok")), "reverted": True,
                "error": result.get("error", ""),
                "changed": list(result.get("changed") or [])}

    # ──────────────────────────── частности ──────────────────────────

    def _reset_for(self, plan: dict) -> None:
        """Подготовить состояние под новый прогон."""
        with self._lock:
            if self._report:
                self._history.append(dict(self._report))
                del self._history[:-HISTORY_KEEP]
            self._state = STATE_RUNNING
            self._phase = PHASE_SNAPSHOT
            self._run_id = plan["run_id"]
            self._ttl_sec = plan["ttl_sec"]
            self._deadline = time.monotonic() + plan["ttl_sec"]
            self._expired = False
            self._committed = False
            self._applied_label = ""
            self._awaiting = False
            self._decision = ""
            self._decision_args = {}
            self._decision_result = {}
            self._progress = (0, len(plan["variants"]))
            self._variant_label = ""
            self._started_mono = time.monotonic()
            self._report = {
                "ok": True,
                "run_id": plan["run_id"],
                "state": STATE_RUNNING,
                "started_at": round(time.time(), 3),
                "finished_at": 0.0,
                "targets": list(plan["targets"]),
                "targets_rejected": list(plan["targets_rejected"]),
                "variants_rejected": list(plan["variants_rejected"]),
                "repeats": plan["repeats"],
                "probes": list(plan["probes"]),
                "probes_unsupported": list(plan["probes_unsupported"]),
                "ttl_sec": plan["ttl_sec"],
                "keep_best": plan["keep_best"],
                "baseline": {},
                "variants": [],
                "ranking": [],
                "best": "",
                "warnings": [],
                "committed": False,
                "stopped": False,
            }
        self._stop_flag.clear()
        self._settled.clear()
        self._decision_evt.clear()
        self._decision_done.clear()

    def _finish(self) -> None:
        """Закрыть прогон: состояние, метки времени, снятие флагов."""
        with self._lock:
            if self._committed:
                state = STATE_FINISHED
            elif self._expired:
                state = STATE_REVERTED
            elif self._state == STATE_FAILED:
                state = STATE_FAILED
            elif self._report.get("reverted_reason"):
                state = STATE_REVERTED
            else:
                state = STATE_FINISHED
            self._state = state
            self._phase = PHASE_DONE
            self._awaiting = False
            self._report["state"] = state
            self._report["committed"] = self._committed
            self._report["finished_at"] = round(time.time(), 3)
            self._report["stopped"] = bool(self._report.get("stopped")
                                           or self._stop_flag.is_set())
        self._settled.set()

    def _set_phase(self, phase: str) -> None:
        with self._lock:
            self._phase = phase

    def _ttl_left(self) -> int:
        if not self._deadline:
            return 0
        return max(0, int(self._deadline - time.monotonic()))

    def _past_deadline(self) -> bool:
        return bool(self._deadline) and time.monotonic() >= self._deadline

    def _prepare_variants(self, raw, maximum: int):
        """``(готовые, отвергнутые)``: метка + argv у каждого."""
        prepared, rejected, used = [], [], set()
        for index, item in enumerate(raw or []):
            if not isinstance(item, dict):
                rejected.append({"label": "", "reason": "вариант — объект "
                                                        "{label, args|"
                                                        "strategy_id|"
                                                        "profiles}"})
                continue
            label = str(item.get("label") or "").strip() or _letter(index)
            if label in used:
                rejected.append({"label": label,
                                 "reason": "метка уже занята"})
                continue
            if len(prepared) >= maximum:
                rejected.append({"label": label,
                                 "reason": "сверх лимита "
                                           "mcp.experiment.max_variants "
                                           "(%d)" % maximum})
                continue
            try:
                args, kind = _variant_args(item)
            except Exception as e:              # noqa: BLE001 — граница
                rejected.append({"label": label,
                                 "reason": "%s: %s" % (type(e).__name__, e)})
                continue
            if not args:
                rejected.append({"label": label,
                                 "reason": "пустой argv: нечего применять"})
                continue
            used.add(label)
            entry = {"label": label, "args": args, "source": kind}
            if item.get("strategy_id"):
                entry["strategy_id"] = str(item["strategy_id"])
            prepared.append(entry)
        return prepared, rejected

    def _prepare_targets(self, raw, maximum: int):
        """Цели прогона; пусто — дефолт из ``core/targets.py``."""
        from core import probe_runner

        if not raw:
            raw = _default_targets()
        return probe_runner.clean_targets(raw, maximum)


# ─────────────────────── снимок на диске ────────────────────────────

def marker_path() -> str:
    """Путь снимка рядом с ``settings.json`` (пусто — каталога нет)."""
    try:
        from core import platform_dirs
        return os.path.join(platform_dirs.config_dir(), MARKER_NAME)
    except Exception:                           # noqa: BLE001 — граница
        return ""


def _write_marker(plan: dict, snapshot: dict) -> None:
    """Записать снимок на диск — ради выключения питания посреди прогона."""
    path = marker_path()
    if not path:
        return
    payload = {
        "run_id": plan["run_id"],
        "pid": os.getpid(),
        "started_at": round(time.time(), 3),
        "ttl_sec": plan["ttl_sec"],
        "snapshot": dict(snapshot),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
    except OSError as e:
        log.debug("Снимок эксперимента не записан: %s" % e, source=SOURCE)


def _read_marker() -> dict:
    path = marker_path()
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _drop_marker() -> None:
    path = marker_path()
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass


def recover_after_restart(source: str = SOURCE) -> dict:
    """Вернуть состояние, если прошлый прогон оборвался вместе с GUI.

    Зовётся при старте GUI. Снимок пережил перезагрузку на диске, а
    временная стратегия — нет: без этого шага роутер остался бы с
    вариантом, который никто не подтверждал.
    """
    marker = _read_marker()
    snapshot = marker.get("snapshot") if marker else None
    if not snapshot:
        return {"ok": True, "recovered": False}

    pid = marker.get("pid")
    if pid and int(pid) == os.getpid():
        runner = get_experiment_runner()
        if runner.get_status()["state"] == STATE_RUNNING:
            # Наш же собственный, ЖИВОЙ прогон: трогать его нельзя.
            return {"ok": True, "recovered": False,
                    "reason": "прогон выполняется прямо сейчас"}

    from core.nfqws_session import get_nfqws_session

    log.warning("Незавершённый эксперимент %s: возвращаем состояние, "
                "снятое до его начала" % marker.get("run_id", "?"),
                source=source)
    result = get_nfqws_session().restore(snapshot, source=source)
    _drop_marker()
    return {
        "ok": bool(result.get("ok")),
        "recovered": True,
        "run_id": marker.get("run_id", ""),
        "error": result.get("error", ""),
        "changed": list(result.get("changed") or []),
    }


# ───────────────────────── общие частности ──────────────────────────

def _variant_args(item: dict):
    """``(argv, откуда)`` для одного варианта.

    Три способа задать вариант, и ни один не «лучше»: ``args`` — когда
    модель собирает приём руками, ``strategy_id`` — когда сравнивается
    уже существующая стратегия, ``profiles`` — когда вариант
    описывается декларативно (тем же форматом, что ``strategy_save``).
    """
    if item.get("args"):
        raw = item["args"]
        if isinstance(raw, str):
            from core.models import tokenize_args
            return tokenize_args(raw), "args"
        return [str(a) for a in raw], "args"

    from core.strategy_builder import get_strategy_manager
    manager = get_strategy_manager()

    if item.get("strategy_id"):
        strategy_id = str(item["strategy_id"])
        strategy = manager.get_strategy(strategy_id)
        if not strategy:
            raise ValueError("стратегии %s нет" % strategy_id)
        return manager.build_nfqws_args(strategy), "strategy_id"

    if item.get("profiles"):
        profiles = [dict(p) for p in item["profiles"] if isinstance(p, dict)]
        if not profiles:
            raise ValueError("profiles пуст")
        return manager.build_nfqws_args({"profiles": profiles}), "profiles"

    raise ValueError("нужен один из ключей: args, strategy_id, profiles")


def _stop_engine() -> None:
    """Погасить движок перед возвратом состояния.

    ``NfqwsSession.restore`` идемпотентен по СОСТОЯНИЮ, а не по
    аргументам: работающий nfqws2 он считает «уже как надо» и argv не
    сверяет. После эксперимента это означало бы, что временная
    стратегия так и осталась применённой — снимок говорит «движок
    работал», движок работает, шага нет. Поэтому гасим сами, а
    ``restore`` поднимает его обратно с аргументами из снимка. Тот же
    двухуровневый возврат, что у ``_ensure_cleanup`` сканера.
    """
    from core import nfqws_control

    try:
        nfqws_control.stop(source=SOURCE)
    except Exception as e:                      # noqa: BLE001 — граница
        log.warning("Движок не остановился перед возвратом: %s" % e,
                    source=SOURCE)


def _validate(argv) -> dict:
    """Dry-run варианта: ``nfqws2 --intercept=0`` тем же кодом, что UI."""
    try:
        from core.nfqws_manager import get_nfqws_manager
        result = get_nfqws_manager().dry_run(list(argv))
    except Exception as e:                      # noqa: BLE001 — граница
        return {"available": False, "ok": False,
                "error": "валидация не выполнилась: %s: %s"
                         % (type(e).__name__, e)}
    return {
        "available": bool(result.get("available")),
        "ok": bool(result.get("ok")),
        "returncode": result.get("returncode"),
        "output": str(result.get("output") or "")[:VALIDATION_OUTPUT_MAX],
    }


# ──────────────────── память подбора (S18) ──────────────────────────
#
# Запись в память никогда не должна ронять прогон: она полезна, но
# эксперимент ценен и без неё. Отсюда одинаковая обёртка на оба вызова.

def _memory_write(report: dict) -> None:
    """Сложить вклад вариантов в ``core/strategy_memory``."""
    try:
        from core import strategy_memory
        written = strategy_memory.remember_report(report)
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Память подбора не записана: %s: %s"
                  % (type(e).__name__, e), source=SOURCE)
        return
    if written.get("written"):
        report["memory"] = {"written": written["written"],
                            "records": written.get("records", 0),
                            "network": written.get("network", "")}


def _memory_commit(args, targets) -> None:
    """Отметить в памяти, что вариант оставили работать."""
    try:
        from core import strategy_memory
        strategy_memory.mark_committed(args, targets)
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Память подбора не отмечена: %s: %s"
                  % (type(e).__name__, e), source=SOURCE)


# ─────────────────── снифер по окну варианта (S18) ──────────────────
#
# Зачем он здесь, если есть отдельные `traffic_capture_*`. Отдельным
# инструментом дамп снимается «когда-нибудь»: модель должна догадаться
# запустить его, успеть выпустить трафик и связать увиденное с
# вариантом. Здесь окно совпадает с замером по построению — и «вариант
# B хуже» превращается в «у варианта B fake ушёл с TTL 1 и не дожил до
# первого хопа».
#
# Рамки те же, что у инструмента (`core/traffic_capture.py`): argv
# фиксирован, потолки из `mcp.capture`, файл удаляется после разбора.
# Плюс два своих правила:
#
# * **по умолчанию выключено.** Это лишний процесс на каждый замер и
#   заметный провайдеру след; просить его надо осознанно;
# * **дамп не ломает прогон.** Нет tcpdump, занят другой дамп, не
#   разобрался файл — в отчёт уезжает строчка «почему», а замер идёт
#   как шёл. Эксперимент меряет стратегию, а не снифер.

# По какому порту снимаем, если не сказано иное. 443 — там, где
# происходит десинк TLS и куда смотрит проба.
CAPTURE_PORT_DEFAULT = 443

# Сколько ждём разбора дампа после остановки (сек). Разбор идёт в
# фоновом потоке снифера; не дождавшись, мы отдали бы пустую сводку.
CAPTURE_PARSE_WAIT_SEC = 6


def _capture_plan(wanted: bool, port) -> dict:
    """Что делать со снифером в этом прогоне (часть плана)."""
    out = {"wanted": bool(wanted),
           "port": _bounded(port, CAPTURE_PORT_DEFAULT, 1, 65535)}
    if not wanted:
        return out
    from core import traffic_capture

    info = traffic_capture.available()
    out["available"] = bool(info.get("available"))
    if not out["available"]:
        # Отказываться от прогона незачем: без дампа эксперимент
        # остаётся ровно тем же экспериментом, просто без картинки.
        out["reason"] = info.get("reason", "")
        out["hint"] = info.get("hint", "")
    return out


def _capture_begin(plan: dict):
    """Запустить дамп на окно замера. Вернуть ярлык прогона или ``None``."""
    sniff = plan.get("capture") or {}
    if not sniff.get("wanted") or not sniff.get("available"):
        return None
    from core import traffic_capture

    try:
        state = traffic_capture.start(port=sniff.get("port"), proto="tcp")
    except traffic_capture.CaptureError as e:
        log.debug("Снифер эксперимента не стартовал: %s" % e, source=SOURCE)
        return {"error": str(e)}
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Снифер эксперимента упал: %s: %s"
                  % (type(e).__name__, e), source=SOURCE)
        return {"error": "%s: %s" % (type(e).__name__, e)}
    return {"run_id": state.get("run_id", ""),
            "params": dict(state.get("params") or {})}


def _capture_end(handle) -> dict:
    """Остановить дамп и свернуть его в сводку для отчёта."""
    if not handle:
        return {}
    if handle.get("error"):
        return {"measured": False, "error": handle["error"]}
    from core import traffic_capture

    run = traffic_capture.get(handle.get("run_id", ""))
    # Глушим только СВОЙ прогон: наш мог кончиться сам (упёрся в
    # потолок пакетов), и к этому времени снифер мог запустить кто-то
    # ещё — `stop()` прибивает последний, а не наш.
    if run is not None and run.running:
        try:
            traffic_capture.stop()
        except traffic_capture.CaptureError:
            pass                                # уже кончился сам
        except Exception as e:                  # noqa: BLE001 — граница
            log.debug("Снифер не остановился: %s: %s"
                      % (type(e).__name__, e), source=SOURCE)

    if run is None:
        return {"measured": False,
                "error": "прогон снифера потерян (перезапуск GUI?)"}
    deadline = time.time() + CAPTURE_PARSE_WAIT_SEC
    while run.running and time.time() < deadline:
        time.sleep(0.2)

    summary = traffic_capture.summary(run)
    out = {
        "measured": not run.running,
        "run_id": run.id,
        "iface": (run.params or {}).get("iface", ""),
        "filter": (run.params or {}).get("filter", ""),
        "packets": summary.get("packets", 0),
        "ttl": dict(summary.get("ttl") or {}),
        "flags": dict(summary.get("flags") or {}),
        "protocols": dict(summary.get("protocols") or {}),
        "sni": list(summary.get("sni") or [])[:5],
        "hosts": list(summary.get("hosts") or [])[:5],
    }
    if run.error:
        out["error"] = run.error
    if run.running:
        out["error"] = out.get("error") or ("дамп не успел разобраться за "
                                            "%d с" % CAPTURE_PARSE_WAIT_SEC)
    return out


# ───────────────── lua-дамп движка (zapret-pcap.lua) ─────────────────
#
# Пара к сниферу: tcpdump видит, что ушло в сеть ПОСЛЕ движка, а
# `pcap` из zapret-pcap.lua — что движок ПОЛУЧИЛ из очереди. Рамки и
# место вставки — в core/lua_capture.py. Правило то же, что у снифера:
# дамп не ломает прогон — нет скрипта, не разобрался файл, в отчёт
# уезжает строчка «почему».

def _lua_capture_plan(wanted: bool) -> dict:
    """Что делать с lua-дампом в этом прогоне (часть плана)."""
    out = {"wanted": bool(wanted)}
    if not wanted:
        return out
    from core import lua_capture

    try:
        from core.config_manager import get_config_manager
        lua_path = (get_config_manager().get("zapret", "lua_path")
                    or "/opt/zapret2/lua")
    except Exception:                           # noqa: BLE001 — граница
        lua_path = "/opt/zapret2/lua"
    script = os.path.join(lua_path, lua_capture.PCAP_LUA_FILE)
    out["available"] = os.path.isfile(script)
    out["dir"] = lua_capture.writable_dir()
    if not out["available"]:
        out["reason"] = "нет %s" % script
        out["hint"] = ("скрипт входит в релиз zapret2 и в поставку GUI "
                       "(import/lua): переустановка GUI или zapret2 "
                       "вернёт его на место")
    return out


def _lua_capture_end(files) -> dict:
    """Прочитать lua-дамп варианта; сбой разбора прогон не роняет."""
    from core import lua_capture

    try:
        return lua_capture.collect(files)
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Разбор lua-дампа не удался: %s: %s"
                  % (type(e).__name__, e), source=SOURCE)
        lua_capture.clear(files)
        return {"measured": False, "error": "%s: %s" % (type(e).__name__, e)}


def _log_window(start: float, end: float) -> list:
    """Хвост лога движка ровно за окно варианта."""
    try:
        from core.log_buffer import get_log_buffer
        entries = get_log_buffer().get_filtered(source="nfqws", since=start,
                                                n=200)
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Лог движка не прочитан: %s" % e, source=SOURCE)
        return []
    out = []
    for entry in entries:
        ts = float(entry.get("timestamp") or 0.0)
        if ts > end:
            continue
        message = str(entry.get("message") or "")[:LOG_LINE_MAX]
        out.append("%s %s" % (entry.get("level", ""), message))
    return out[-LOG_TAIL:]


def _kbps(row: dict) -> float:
    """Грубая скорость пробы: прочитанные байты на измеренное время.

    Это НЕ замер пропускной способности: латентность пробы включает DNS
    и рукопожатие. Числу место только в сравнении вариантов между собой
    — одной и той же меркой на всех, — и формула ранжирования у нас
    общая со сканером.
    """
    latency = float(row.get("latency_ms") or 0.0)
    read = float(row.get("bytes_read") or 0.0)
    if latency <= 0 or read <= 0:
        return 0.0
    return round((read / 1024.0) / (latency / 1000.0), 1)


def _score(variant: dict, open_targets: list) -> float:
    """Score варианта — формулой сканера, чтобы ранжирование совпадало."""
    from core.strategy_scanner import compose_score, credit_success

    rows = variant.get("per_target") or []
    measured = [r["target"] for r in rows]
    # Все измеренные цели были открыты и без обхода — кредита нет.
    baseline_open_all = bool(measured) and all(t in open_targets
                                               for t in measured)
    success = credit_success(bool(variant.get("success_rate")),
                             baseline_open_all)
    return compose_score(success, variant.get("success_rate", 0.0),
                         variant.get("avg_kbps", 0.0),
                         variant.get("avg_latency_ms", 0.0))


def _metrics(variant: dict, fixed: int, broken: int) -> dict:
    """Что правила-подсказки знают о варианте."""
    rows = variant.get("per_target") or []
    return {
        "validation": variant.get("validation") or {},
        "started_nfqws": bool(variant.get("started_nfqws")),
        "applied_attempted": bool(variant.get("applied")),
        "ok_count": sum(1 for r in rows if r.get("ok")),
        "target_count": len(rows),
        "fixed_count": fixed,
        "broken_count": broken,
        # Сводка дампа, если снифер просили (S18): без неё три правила
        # про TTL, SNI и пустой дамп просто не срабатывают.
        "capture": variant.get("capture") or {},
        # Lua-дамп движка: пустой при поднятом движке — пакеты не дошли
        # до стратегии, и чинить надо фильтр, а не приём.
        "lua_capture": variant.get("lua_capture") or {},
    }


def _compact_probe(row: dict) -> dict:
    """Проба одной цели без того, что модели в отчёте не нужно."""
    return {
        "target": row.get("target", ""),
        "ok": bool(row.get("ok")),
        "code": row.get("code", ""),
        "code_desc": row.get("code_desc", ""),
        "latency_ms": row.get("latency_ms", 0.0),
        "latency_stat": row.get("latency_stat", ""),
        "bytes_read": row.get("bytes_read", 0),
        "kbps": row.get("kbps", 0.0),
        "attempts": row.get("attempts", 0),
        "ok_count": row.get("ok_count", 0),
    }


def _save_strategy(strategy_id: str, name: str, variant, plan: dict) -> dict:
    """Записать подтверждённый вариант USER-стратегией (S7 умеет это сам)."""
    spec = next((v for v in plan["variants"]
                 if variant and v["label"] == variant["label"]), None)
    argv = list(spec["args"]) if spec else []
    if not argv:
        return {"ok": False, "error": "у варианта нет аргументов"}
    try:
        from core.strategy_builder import get_strategy_manager
        saved = get_strategy_manager().save_user_strategy({
            "id": strategy_id,
            "name": name or strategy_id,
            "description": "Победитель эксперимента %s (вариант %s)"
                           % (plan["run_id"], variant["label"]),
            "profiles": [{"name": "experiment", "enabled": True,
                          "args": " ".join(argv)}],
        })
    except Exception as e:                      # noqa: BLE001 — граница
        return {"ok": False,
                "error": "не сохранилось: %s: %s" % (type(e).__name__, e)}
    return {"ok": bool(saved), "strategy_id": strategy_id,
            "name": name or strategy_id}


def _activate(strategy_id: str) -> dict:
    """Сделать сохранённую стратегию активной (та же функция, что у UI)."""
    from core import nfqws_control

    result = nfqws_control.apply_strategy(strategy_id, source=SOURCE)
    return {"ok": bool(result.get("ok")),
            "strategy_id": strategy_id,
            "error": str(result.get("error") or "")}


def _default_targets() -> list:
    """Цели по умолчанию — из общего каталога, а не свой список."""
    try:
        from core.targets import SERVICES
        out = []
        for service in SERVICES.values():
            hosts = service.get("hosts") or []
            if hosts:
                out.append(hosts[0])
        return out
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Каталог целей не прочитан: %s" % e, source=SOURCE)
        return ["youtube.com", "rutracker.org"]


def _split_probes(probes):
    """``(что меряем, что не умеем)`` — без выдумок про QUIC."""
    wanted = [str(p).strip().lower() for p in (probes or []) if str(p).strip()]
    if not wanted:
        wanted = ["tls", "http"]
    used = [p for p in wanted if p in PROBE_KINDS]
    unsupported = [{"probe": p,
                    "reason": ("движок экспериментов меряет одной цепочкой "
                               "DNS → TCP → TLS → HTTP; отдельного замера "
                               "нет")}
                   for p in wanted if p not in PROBE_KINDS]
    return (used or list(PROBE_KINDS[:2])), unsupported


def _letter(index: int) -> str:
    """Метка варианта по умолчанию: A, B, C… затем V13, V14."""
    if 0 <= index < 26:
        return chr(ord("A") + index)
    return "V%d" % (index + 1)


def _eta(status: dict):
    """Сколько примерно осталось — по времени уже сделанных вариантов.

    ``None`` вместо числа, пока считать не по чему: выдуманная оценка
    здесь хуже её отсутствия — по ней модель выставляет период опроса.
    """
    done, total = status.get("progress", 0), status.get("total", 0)
    elapsed = float(status.get("elapsed_sec") or 0.0)
    if status.get("state") != STATE_RUNNING or done <= 0 or done >= total:
        return None
    if elapsed <= 0:
        return None
    return int(round(elapsed / done * (total - done)))


def _bounded(value, default, minimum, maximum):
    """Число из аргумента в заданных границах; ``None`` — дефолт."""
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(number, maximum))


_runner = None
_runner_lock = threading.Lock()


def get_experiment_runner() -> ExperimentRunner:
    """Синглтон движка экспериментов (как остальные менеджеры проекта)."""
    global _runner
    if _runner is None:
        with _runner_lock:
            if _runner is None:
                _runner = ExperimentRunner()
    return _runner
