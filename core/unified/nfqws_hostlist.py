# core/unified/nfqws_hostlist.py
"""
Авто-подключение доменов nfqws2-маршрутов единого слоя к запущенной
стратегии nfqws2.

Семантика (opt-in, по умолчанию OFF): когда включён флаг
`nfqws.unified_hostlist`, единый слой агрегирует домены всех включённых
маршрутов с методом `nfqws2` в управляемый hostlist `unified_nfqws`, а
nfqws2 запускается с `--hostlist=<этот файл>` ПЕРЕД профилями стратегии —
то есть стратегия применяется именно к этим доменам (единый слой
становится источником «какие домены обходит nfqws2»).

Флаг по умолчанию выключен, чтобы не менять поведение существующих
установок (где стратегия глобальная или со своими hostlist'ами).

Имя агрегата фиксировано — `unified_nfqws`. compose_command в
nfqws_manager берёт путь отсюда.
"""

from core.log_buffer import log

AGGREGATE_NAME = "unified_nfqws"


def enabled() -> bool:
    try:
        from core.config_manager import get_config_manager
        return bool(get_config_manager().get(
            "nfqws", "unified_hostlist", default=False))
    except Exception:
        return False


def aggregate_path() -> str:
    try:
        from core.hostlist_manager import get_hostlist_manager
        return get_hostlist_manager()._file_path(AGGREGATE_NAME)
    except Exception:
        return ""


def _collect_domains() -> list:
    """Союз доменов всех включённых nfqws2-маршрутов единого слоя."""
    from core.unified import storage
    from core.unified.model import parse_method
    out, seen = [], set()
    for route in storage.load_routes():
        if not route.enabled:
            continue
        try:
            kind, _ = parse_method(route.method)
        except ValueError:
            continue
        if kind != "nfqws2":
            continue
        for d in route.destination.resolve().get("domains", []):
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out


def rebuild(*, restart: bool = True) -> dict:
    """
    Пересобрать агрегатный hostlist из текущих nfqws2-маршрутов и (опц.)
    перезапустить nfqws2, если он запущен и фича включена.
    """
    domains = _collect_domains()
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        hm.save_hostlist(AGGREGATE_NAME, domains)
    except Exception as e:
        return {"ok": False, "error": "hostlist: %s" % e}

    restarted = False
    if restart and enabled():
        try:
            from core.nfqws_manager import get_nfqws_manager
            mgr = get_nfqws_manager()
            if mgr.is_running():
                mgr.restart()
                restarted = True
        except Exception as e:
            log.warning("unified nfqws restart: %s" % e, source="unified")
    log.info("unified nfqws-hostlist: %d доменов (restart=%s)"
             % (len(domains), restarted), source="unified")
    return {"ok": True, "domains": len(domains), "restarted": restarted,
            "path": aggregate_path()}


def compose_extra_args() -> list:
    """
    Доп. аргументы для nfqws2 (вызывается из compose_command). Возвращает
    ['--hostlist=<aggregate>'] если фича включена и файл непустой, иначе [].
    """
    if not enabled():
        return []
    domains = _collect_domains()
    if not domains:
        return []
    path = aggregate_path()
    if not path:
        return []
    return ["--hostlist=%s" % path]
