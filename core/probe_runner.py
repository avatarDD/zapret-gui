# core/probe_runner.py
"""
Прогон активных проб: список целей и сравнение «с обходом и без».

Здесь начинается трафик, выпускаемый С РОУТЕРА по просьбе модели, —
поэтому у модуля две обязанности, а не одна:

1. **Собственно пробы.** Одна цель = ``core/testers/probe.py`` (DNS →
   TCP → TLS → HTTP), коды — из ``PROBE_CODES``, никаких своих строк.
   Повторы, параллелизм и бюджет времени живут здесь, чтобы не
   расползтись по вызывающим.
2. **Лимиты.** Число целей, число повторов, таймаут операции и
   суммарное время одного вызова берутся из ``mcp.probes`` и режут
   запрос ДО первого пакета. Сотня доменов подряд с одного адреса —
   это заметный след у провайдера, а не диагностика.

Отдельно — ``compare()``: тот же домен через nfqws2 и мимо него. Это
самый нужный ответ («дело в обходе или домен и так лежит?») и
единственное место модуля, которое **меняет состояние устройства**:
чтобы измерить вторую сторону, движок приходится на секунду
переключить. Поэтому:

* состояние восстанавливается в ``finally`` — всегда, включая падение
  пробы посередине;
* если переключать нельзя (``toggle=False``) или нечем (не выбрана
  стратегия), вторая сторона честно помечается неизмеренной, а вердикт
  становится ``unknown``. Выдуманная вторая половина здесь хуже
  отсутствующей: на ней модель строит весь дальнейший подбор.

Модуль живёт в ``core/``, а не в ``core/mcp/tools/``, намеренно: тем же
кодом пользуются CLI и UI, а инструменты MCP остаются тонкими
обёртками (контракт §2).
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from core.log_buffer import log
from core.testers.probe import PROBE_CODES, describe_code, probe_domain


# Имя хоста: то же, что принимает blockcheck2 (без схемы и пути).
HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$")

# Потолки на случай, когда конфиг не прочитался.
DEFAULTS = {
    "max_targets": 10,
    "max_repeats": 3,
    "timeout_sec": 5,
    "budget_sec": 60,
    "parallel": 4,
    "settle_sec": 2,
}

# Вердикт сравнения → что он значит. Набор фиксированный: свободная
# строка здесь означала бы, что следующий читатель (S10 строит на
# `compare` baseline эксперимента) разбирает её регулярками.
VERDICTS = {
    "bypass_helps": "обход помогает: с ним домен открывается, без него — нет",
    "no_difference": "разницы нет: домен открывается и с обходом, и без",
    "target_down": "не работает ни с обходом, ни без — дело не в DPI",
    "bypass_hurts": "обход мешает: без него домен открывается, с ним — нет",
    "unknown": "сравнения не вышло: измерена только одна сторона",
}

WITH = "with_bypass"
WITHOUT = "without_bypass"

# Как сворачивать латентность повторов.
MEAN = "mean"
MEDIAN = "median"


# ───────────────────────────── лимиты ───────────────────────────────

def limits() -> dict:
    """Лимиты проб из ``mcp.probes`` (с дефолтами, если конфига нет)."""
    out = dict(DEFAULTS)
    try:
        from core.config_manager import get_config_manager
        section = get_config_manager().get("mcp", "probes", default={}) or {}
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Лимиты проб не прочитаны: %s" % e, source="probes")
        return out
    for key, default in DEFAULTS.items():
        value = section.get(key, default)
        try:
            # Ноль осмыслен ровно у одного лимита: пауза после
            # переключения движка. У остальных «ноль целей» и «ноль
            # секунд бюджета» означали бы инструмент, который никогда
            # ничего не делает.
            out[key] = max(0 if key == "settle_sec" else 1, int(value))
        except (TypeError, ValueError):
            out[key] = default
    return out


def clean_targets(domains, maximum: int) -> tuple:
    """``(принятые, отвергнутые)`` — с указанием, почему отвергли.

    «Прислал десять доменов, проверено три» без перечня отвергнутых
    читается как сбой инструмента, поэтому причина есть у каждого.
    """
    accepted, rejected, seen = [], [], set()
    for raw in domains or []:
        name = str(raw or "").strip().rstrip(".").lower()
        if not name:
            continue
        if name in seen:
            rejected.append({"target": name, "reason": "повтор в списке"})
            continue
        if not HOST_RE.match(name):
            rejected.append({"target": name[:80],
                             "reason": "не похоже на имя хоста"})
            continue
        seen.add(name)
        if len(accepted) >= maximum:
            rejected.append({"target": name,
                             "reason": "сверх лимита mcp.probes.max_targets "
                                       "(%d)" % maximum})
            continue
        accepted.append(name)
    return accepted, rejected


# ──────────────────────────── пробы целей ───────────────────────────

def probe_many(domains, timeout=None, repeats=1, port=443,
               budget_sec=None, parallel=None) -> dict:
    """Проба каждого домена из списка; лимиты — из ``mcp.probes``.

    Returns:
        dict: ``results`` (по домену), ``rejected`` (что не приняли),
        ``skipped`` (на что не хватило бюджета), ``elapsed_sec``,
        ``budget_sec``, ``budget_hit``.
    """
    cfg = limits()
    timeout = _bounded(timeout, cfg["timeout_sec"], 1, 30)
    repeats = _bounded(repeats, 1, 1, cfg["max_repeats"])
    budget = _bounded(budget_sec, cfg["budget_sec"], 5, 600)
    workers = _bounded(parallel, cfg["parallel"], 1, 8)

    accepted, rejected = clean_targets(domains, cfg["max_targets"])
    started = time.monotonic()
    results, skipped = [], []

    # Идём порциями по числу воркеров и сверяемся с бюджетом МЕЖДУ
    # порциями: иначе «суммарное время» не ограничивает ничего —
    # отправленные в пул задачи всё равно доработают до конца.
    index = 0
    while index < len(accepted):
        if time.monotonic() - started >= budget:
            break
        chunk = accepted[index:index + workers]
        index += len(chunk)
        if len(chunk) == 1:
            results.append(probe_target(chunk[0], timeout, repeats, port))
            continue
        with ThreadPoolExecutor(max_workers=len(chunk)) as pool:
            futures = [pool.submit(probe_target, name, timeout, repeats, port)
                       for name in chunk]
            for future in futures:
                results.append(future.result())

    for name in accepted[index:]:
        skipped.append({"target": name,
                        "reason": "не хватило бюджета времени (%d с)" % budget})

    elapsed = round(time.monotonic() - started, 2)
    return {
        "results": results,
        "rejected": rejected,
        "skipped": skipped,
        "elapsed_sec": elapsed,
        "budget_sec": budget,
        "budget_hit": bool(skipped),
        "timeout_sec": timeout,
        "repeats": repeats,
        "port": port,
    }


def probe_target(domain: str, timeout: int, repeats: int = 1,
                 port: int = 443, latency: str = MEAN,
                 mark: int = 0) -> dict:
    """Одна цель: ``repeats`` проб, свёрнутых в один вердикт.

    ``latency`` — как сворачивать латентность повторов: ``"mean"``
    (по умолчанию, историческое поведение проб) или ``"median"``.
    ``mark`` — SO_MARK проб (core/probe_mark.py): мимо очереди, то есть
    замер без обхода при работающем движке.
    """
    attempts = []
    for _ in range(max(1, repeats)):
        try:
            attempts.append(probe_domain(domain, timeout=timeout, port=port,
                                         mark=mark))
        except Exception as e:                  # noqa: BLE001 — граница
            # Проба обязана вернуть код, а не исключение: на ней
            # строится вердикт, и «упало» — это тоже ответ.
            log.debug("Проба %s упала: %s" % (domain, e), source="probes")
            attempts.append(None)
    return fold(domain, attempts, latency=latency)


def fold(domain: str, attempts, latency: str = MEAN) -> dict:
    """Свернуть повторы одной цели в запись результата.

    Успехом считаем СТРОГОЕ большинство удачных попыток: домен,
    открывшийся один раз из двух, работает нестабильно, и называть это
    «работает» значит подсунуть модели ложную базу для сравнения.

    ``latency="median"`` — для сравнения вариантов стратегии
    (``core/strategy_experiment.py``): один выброс по латентности на
    роутере (ретрансмит, занятый CPU) — это норма, и среднее из трёх
    замеров он сдвигает так, что варианты меняются местами. Дефолт
    остаётся средним: на нём построены ответы S8, и менять их задним
    числом нельзя.
    """
    codes, latencies, details, ok_count = [], [], [], 0
    bytes_read, resolved = 0, []
    for res in attempts:
        if res is None:
            codes.append("unknown")
            details.append("проба не выполнилась")
            continue
        codes.append(res.code)
        if res.ok:
            ok_count += 1
            latencies.append(res.latency_ms)
        if res.detail:
            details.append(res.detail)
        bytes_read = max(bytes_read, res.bytes_read)
        resolved = resolved or list(res.resolved_ips)

    total = len(attempts) or 1
    ok = ok_count * 2 > total
    code = "ok" if ok else _most_common([c for c in codes if c != "ok"]) \
        or "unknown"
    return {
        "target": domain,
        "ok": ok,
        "code": code,
        "code_desc": describe_code(code),
        "dpi": _dpi(code),
        "remediation": _remediation(code),
        "latency_ms": _fold_latency(latencies, latency),
        "latency_stat": latency if latencies else "",
        "bytes_read": bytes_read,
        "resolved_ips": resolved[:4],
        "detail": (details[0] if details else "")[:200],
        "attempts": total,
        "ok_count": ok_count,
        "measured": True,
    }


# ──────────────────────── сравнение с обходом ───────────────────────

def compare(target: str, timeout=None, repeats=1, toggle: bool = True,
            settle_sec=None, source: str = "probes") -> dict:
    """Проверить домен С обходом и БЕЗ, вернуть вердикт из ``VERDICTS``.

    Одна сторона измеряется в текущем состоянии устройства, вторая —
    после переключения движка (``toggle=True``). Исходное состояние
    восстанавливается всегда: и после удачной пробы, и после падения.

    Args:
        toggle: разрешено ли трогать движок. ``False`` — измеряется
            только текущая сторона, вердикт будет ``unknown``.
    """
    from core import nfqws_control
    from core.nfqws_session import (OWNER_PROBE, SessionBusy,
                                    get_nfqws_session)

    cfg = limits()
    timeout = _bounded(timeout, cfg["timeout_sec"], 1, 30)
    repeats = _bounded(repeats, 1, 1, cfg["max_repeats"])
    settle = _bounded(settle_sec, cfg["settle_sec"], 0, 30)

    accepted, rejected = clean_targets([target], 1)
    if not accepted:
        return {
            "ok": False,
            "error": "не похоже на имя хоста: %s" % str(target)[:80],
            "rejected": rejected,
            "hint": "передайте домен без схемы и пути, например "
                    "rutracker.org",
        }
    domain = accepted[0]

    running = nfqws_control.running()
    here, there = (WITH, WITHOUT) if running else (WITHOUT, WITH)
    sides = {here: probe_target(domain, timeout, repeats)}

    # Движок работает — сторону «без обхода» меряем помеченной пробой
    # мимо очереди: обход у остальной сети не пропадает ни на секунду,
    # и трогать движок (а значит, и разрешение control) не нужно.
    marked = {"marked": False}
    if running:
        from core import probe_mark
        marked = probe_mark.baseline_mode()

    toggled, restore = False, {}
    if marked.get("marked"):
        sides[there] = probe_target(domain, timeout, repeats,
                                    mark=marked["mark"])
    elif not toggle:
        sides[there] = _unmeasured(
            "переключение движка не запрошено (toggle=false)",
            "вторая сторона измеряется только с разрешением control")
    elif not running and not _have_strategy():
        # Движок не поднят и поднимать нечем. Это и есть честный ответ
        # «обхода на устройстве нет» — на dev-машине он основной.
        sides[there] = _unmeasured(
            "обход не настроен: активной стратегии нет",
            "выберите стратегию (strategy_apply) — без неё запускать "
            "нечего, и сравнивать не с чем")
    else:
        # Переключение и обратный ход идут под ОДНИМ захватом общего
        # мьютекса: между «выключил» и «вернул» сканер успел бы
        # стартовать и получить движок в чужом состоянии — а вернули
        # бы мы оба, каждый по-своему.
        try:
            with get_nfqws_session().acquire(
                    owner=OWNER_PROBE, timeout=0,
                    reason="сравнение с обходом и без (%s)" % domain):
                switch = (nfqws_control.stop(source=source) if running
                          else nfqws_control.start(source=source))
                if not switch.get("ok"):
                    sides[there] = _unmeasured(
                        "движок не поддался: %s"
                        % (switch.get("error") or "—"),
                        "состояние устройства не изменилось; подробности "
                        "— logs_tail(source=\"nfqws\")")
                else:
                    toggled = True
                    try:
                        if settle:
                            time.sleep(settle)
                        sides[there] = probe_target(domain, timeout,
                                                    repeats)
                    finally:
                        # Восстанавливаем ВСЕГДА: оставить роутер без
                        # обхода (или с чужим обходом) из-за упавшей
                        # пробы нельзя.
                        restore = _restore(running, source)
        except SessionBusy as busy:
            sides[there] = _unmeasured(
                "движок занят: %s" % busy,
                "дождитесь окончания операции и повторите — вторая "
                "сторона измеряется только на свободном движке")

    verdict = _verdict(sides[WITH], sides[WITHOUT])
    out = {
        "ok": True,
        "target": domain,
        WITH: sides[WITH],
        WITHOUT: sides[WITHOUT],
        "verdict": verdict,
        "verdict_text": VERDICTS[verdict],
        "engine_before": "running" if running else "stopped",
        "engine_toggled": toggled,
        "repeats": repeats,
        "measured_first": here,
        # Как мерилась сторона «без обхода»: меткой мимо очереди или
        # переключением движка (почему не меткой — в without_note).
        "without_method": "probe_mark" if marked.get("marked")
                          else ("engine_toggle" if toggled else "none"),
    }
    if running and not marked.get("marked") and marked.get("reason"):
        out["without_note"] = marked["reason"]
    if toggled:
        out["restored"] = bool(restore.get("ok"))
        out["restore_error"] = restore.get("error", "")
        if not restore.get("ok"):
            out["hint"] = ("ВНИМАНИЕ: вернуть движок в прежнее состояние "
                           "не удалось — проверьте nfqws_status() и при "
                           "необходимости nfqws_start()")
    return out


def _restore(was_running: bool, source: str) -> dict:
    """Вернуть движок в то состояние, в котором он был до сравнения."""
    from core import nfqws_control

    try:
        result = (nfqws_control.start(source=source) if was_running
                  else nfqws_control.stop(source=source))
    except Exception as e:                      # noqa: BLE001 — граница
        log.error("Движок не восстановлен после пробы: %s" % e,
                  source="probes")
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    if not result.get("ok"):
        log.error("Движок не восстановлен после пробы: %s"
                  % result.get("error", ""), source="probes")
    return {"ok": bool(result.get("ok")), "error": result.get("error", "")}


def _have_strategy() -> bool:
    """Есть ли что поднимать: собираются ли аргументы активной стратегии.

    Пустой список аргументов — это не «запусти как есть»: голый nfqws2
    без десинка означал бы «с обходом» при выключенном обходе.
    """
    from core import nfqws_control

    try:
        return bool(nfqws_control.active_strategy_args())
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Аргументы активной стратегии не собрались: %s" % e,
                  source="probes")
        return False


def _verdict(with_bypass: dict, without_bypass: dict) -> str:
    """Вердикт по двум сторонам; неизмеренная сторона → ``unknown``."""
    if not with_bypass.get("measured") or not without_bypass.get("measured"):
        return "unknown"
    helped = bool(with_bypass.get("ok"))
    direct = bool(without_bypass.get("ok"))
    if helped and direct:
        return "no_difference"
    if helped and not direct:
        return "bypass_helps"
    if direct and not helped:
        return "bypass_hurts"
    return "target_down"


def _unmeasured(reason: str, hint: str = "") -> dict:
    """Сторона, которую измерить не вышло — с причиной, а не с нулём.

    ``code`` остаётся пустым намеренно: любой код из ``PROBE_CODES``
    здесь был бы выдумкой, а ноль в ``latency_ms`` читается как
    «мгновенно».
    """
    out = {"measured": False, "ok": False, "code": "", "code_desc": "",
           "latency_ms": 0.0, "reason": reason}
    if hint:
        out["hint"] = hint
    return out


# ──────────────────────────── частности ─────────────────────────────

def _dpi(code: str) -> str:
    from core.testers.probe import dpi_for_code
    return dpi_for_code(code)


def _remediation(code: str) -> str:
    from core.models import remediation_for
    return remediation_for(_dpi(code))


def _fold_latency(values, how: str) -> float:
    """Латентность повторов одним числом: среднее или медиана.

    Медиана нужна там, где сравниваются варианты: единственный выброс
    (ретрансмит, занятый CPU роутера) сдвигает среднее из трёх замеров
    сильнее, чем разница между двумя приличными стратегиями.
    """
    if not values:
        return 0.0
    if how == MEDIAN:
        ordered = sorted(values)
        middle = len(ordered) // 2
        if len(ordered) % 2:
            return round(ordered[middle], 1)
        return round((ordered[middle - 1] + ordered[middle]) / 2.0, 1)
    return round(sum(values) / len(values), 1)


def _most_common(values):
    """Самый частый код; при равенстве — тот, что встретился раньше."""
    best, best_count = "", 0
    for value in values:
        count = values.count(value)
        if count > best_count:
            best, best_count = value, count
    return best


def _bounded(value, default, minimum, maximum):
    """Число из аргумента в заданных границах; ``None`` — дефолт."""
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(number, maximum))


def known_codes() -> list:
    """Все коды проб — чтобы описания и тесты не заводили свои."""
    return list(PROBE_CODES)
