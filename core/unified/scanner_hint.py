# core/unified/scanner_hint.py
"""
Интеграция единого слоя со strategy-scanner (TODO.md).

Если у маршрута выбран метод nfqws2, но мониторинг показывает, что
назначение не тянется текущей стратегией — предлагаем (или по запросу
запускаем) подбор рабочей стратегии для домена назначения, и умеем
применить найденную.

Решение «предлагать ли скан» — чистая функция `should_suggest`,
тестируется без I/O.
"""

from core.log_buffer import log
from core.unified.model import parse_method


# Порог: ниже этой доли успеха (при достаточном числе замеров) считаем,
# что nfqws2 не справляется и стоит подобрать стратегию.
_SUGGEST_RATE = 0.5
_SUGGEST_MIN_SAMPLES = 4


def should_suggest(method: str, rate, samples: int) -> bool:
    """Стоит ли предлагать подбор стратегии (чистая функция)."""
    try:
        kind, _ = parse_method(method)
    except ValueError:
        return False
    if kind != "nfqws2":
        return False
    if rate is None or samples < _SUGGEST_MIN_SAMPLES:
        return False
    return rate < _SUGGEST_RATE


def _probe_target(route) -> str:
    domain = (route.probe_domain or "").strip()
    if domain:
        return domain
    domains = route.destination.resolve().get("domains") or []
    return domains[0] if domains else ""


def suggest_for_route(route) -> dict:
    """
    Вернуть рекомендацию по маршруту:
      {"suggest": bool, "reason": str, "target": <домен>}.
    Активный метод берём из failover-состояния (или primary).
    """
    from core.unified import monitor, applier
    method = applier.active_method(route)
    rate = monitor.success_rate(route.id)
    samples = len(monitor.history(route.id))
    target = _probe_target(route)
    suggest = bool(target) and should_suggest(method, rate, samples)
    reason = ""
    if suggest:
        reason = ("nfqws2 не тянет %s (успех %.0f%% из %d замеров) — "
                  "подберите стратегию" % (target, (rate or 0) * 100, samples))
    return {"suggest": suggest, "reason": reason, "target": target,
            "method": method, "rate": rate, "samples": samples}


def run_scan_for_route(route, *, protocol: str = "tcp",
                       mode: str = "quick") -> dict:
    """Запустить подбор стратегии для домена назначения маршрута."""
    target = _probe_target(route)
    if not target:
        return {"ok": False, "error": "У маршрута нет домена для подбора"}
    try:
        from core.strategy_scanner import get_strategy_scanner
        scanner = get_strategy_scanner()
        started = scanner.start(target=target, protocol=protocol, mode=mode)
        if not started:
            return {"ok": False, "error": "Сканер уже запущен либо занят",
                    "status": scanner.get_status()}
        log.info("unified: запущен подбор стратегии для %s (маршрут %s)"
                 % (target, route.id), source="unified")
        return {"ok": True, "target": target, "status": scanner.get_status()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def apply_best_found() -> dict:
    """
    Применить лучшую найденную рабочую стратегию из последнего скана
    (если он завершён и что-то нашёл). Возвращает что применили.
    """
    try:
        from core.strategy_scanner import get_strategy_scanner
        scanner = get_strategy_scanner()
        working = scanner.get_working_strategies() or []
        if not working:
            return {"ok": False, "error": "Рабочих стратегий не найдено"}
        best = working[0]
        sid = best.get("id") or best.get("strategy_id")
        if not sid:
            return {"ok": False, "error": "У стратегии нет id"}
        ok = scanner.apply_strategy_by_id(sid)
        return {"ok": bool(ok), "applied": sid, "strategy": best}
    except Exception as e:
        return {"ok": False, "error": str(e)}
