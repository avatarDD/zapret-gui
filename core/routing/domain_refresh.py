# core/routing/domain_refresh.py
"""
Фоновое обновление IP доменных правил, применённых БЕЗ dnsmasq.

Зачем: на Keenetic dnsmasq не поднять (53-й порт занят ndnsproxy), и
доменные правила работают по IP, снятым в момент применения — либо
set-based путём (`domain_rule._apply_domain_via_sets`: ipset/nftset +
fwmark), либо iproute-фолбэком (`ip rule` на каждый IP). IP у CDN
ротируются, поэтому без обновления правило «протухает» и пользователю
приходится либо переприменять его руками, либо перекладывать всё на
device-правила («работает только с выбором устройства»).

Этот демон раз в interval_min минут заново резолвит домены активных
правил и пополняет set'ы (или policy-db для iproute-пути) новыми IP.
Старые записи НЕ удаляем: лишний IP в туннеле безвреден, а чистка
рвала бы живые соединения при ложном «протухании».

Правила, которые обслуживает dnsmasq (или NDMS), не трогаем — там
IP пополняются по живым DNS-запросам.

Настройки (settings.json → routing.domain_refresh):
    enabled       — по умолчанию true;
    interval_min  — период обновления, по умолчанию 10 минут.
"""

import threading

from core.log_buffer import log


DEFAULT_INTERVAL_MIN = 10

_thread = None
_thread_lock = threading.Lock()
_wake = threading.Event()


def _settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        sec = get_config_manager().get("routing", "domain_refresh",
                                       default={}) or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:
        return {}


def is_enabled() -> bool:
    return bool(_settings().get("enabled", True))


def interval_sec() -> int:
    try:
        minutes = float(_settings().get("interval_min",
                                        DEFAULT_INTERVAL_MIN))
    except (TypeError, ValueError):
        minutes = DEFAULT_INTERVAL_MIN
    return max(60, int(minutes * 60))


# ─────────────────────── один проход ────────────────────────────────

def refresh_once() -> dict:
    """
    Один проход обновления по всем enabled domain-правилам.
    Возвращает {"sets": n, "iproute": n, "ips_added": n}.
    """
    from core.routing import domain_rule, storage
    from core.routing.rules import DomainRoutingRule

    sets_state = domain_rule._sets_state_load()
    iproute_state = domain_rule._iproute_state_load()
    out = {"sets": 0, "iproute": 0, "ips_added": 0}
    for rule in storage.load_rules():
        if not isinstance(rule, DomainRoutingRule) or not rule.enabled:
            continue
        try:
            if rule.id in sets_state:
                out["ips_added"] += _refresh_sets_rule(
                    rule, sets_state[rule.id])
                out["sets"] += 1
            elif rule.id in iproute_state:
                out["ips_added"] += _refresh_iproute_rule(rule)
                out["iproute"] += 1
        except Exception as e:
            log.warning("domain_refresh: правило %s: %s" % (rule.id, e),
                        source="routing")
    return out


def _refresh_sets_rule(rule, kind: str) -> int:
    """Пополнить ipset/nftset правила свежерезолвленными IP."""
    from core.routing import domain_rule, ipset_backend, nftset_backend
    backend = nftset_backend if kind == "nftset" else ipset_backend
    if not domain_rule._iface_exists(rule.target_iface):
        return 0
    domains, _cidrs = domain_rule._expand_rule(rule)
    domains = domains[:domain_rule._PREPOP_MAX_DOMAINS]
    base = domain_rule._set_name_for(rule.id, kind)
    results = domain_rule._prepopulate_domains(
        domains, base, base + "6", backend)
    return sum(r.get("added", 0) for r in results)


def _refresh_iproute_rule(rule) -> int:
    """Ре-резолв iproute-правила: `ip rule` для новых IP + учёт в state."""
    import subprocess
    from core.routing import domain_rule
    if not domain_rule._iface_exists(rule.target_iface):
        return 0
    table = domain_rule._table_id_for(rule.target_iface)
    state = domain_rule._iproute_state_load()
    entries = list(state.get(rule.id) or [])
    known = {tuple(e[:2]) for e in entries
             if isinstance(e, (list, tuple)) and len(e) >= 2}
    domains, _cidrs = domain_rule._expand_rule(rule)
    added = 0
    for domain in domains[:domain_rule._PREPOP_MAX_DOMAINS]:
        for fam in ("v4", "v6"):
            for ip in domain_rule._resolve_ips(domain, fam):
                cidr = ip + ("/128" if fam == "v6" else "/32")
                family = "-6" if fam == "v6" else "-4"
                if (cidr, family) in known:
                    continue
                r = subprocess.run(
                    ["ip", family, "rule", "add", "to", cidr,
                     "lookup", str(table),
                     "priority", str(domain_rule.FWMARK_PRIORITY)],
                    capture_output=True, text=True, timeout=5)
                if r.returncode == 0 or "File exists" in (r.stderr or ""):
                    known.add((cidr, family))
                    entries.append([cidr, family])
                    added += 1
    if added:
        state[rule.id] = entries
        domain_rule._iproute_state_save(state)
    return added


# ─────────────────────── демон ───────────────────────────────────────

def _loop():
    while True:
        _wake.wait(interval_sec())
        _wake.clear()
        if not is_enabled():
            continue
        try:
            stats = refresh_once()
            if stats.get("ips_added"):
                log.info("domain_refresh: sets=%d, iproute=%d, +%d новых IP"
                         % (stats["sets"], stats["iproute"],
                            stats["ips_added"]),
                         source="routing")
        except Exception as e:
            log.warning("domain_refresh: %s" % e, source="routing")


def ensure_started():
    """Запустить фоновый поток (идемпотентно). No-op, если выключено."""
    global _thread
    if not is_enabled():
        return
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return
        _thread = threading.Thread(target=_loop, daemon=True,
                                   name="domain-refresh")
        _thread.start()
        log.info("domain_refresh: фоновое обновление IP доменных правил "
                 "запущено (каждые %d мин)" % (interval_sec() // 60),
                 source="routing")


def kick():
    """Разбудить демона немедленно (после apply нового правила)."""
    _wake.set()
