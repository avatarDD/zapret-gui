# core/mcp/tools/firewall.py
"""
Правила перехвата: стоят ли они и сходятся ли с движком.

Половина жалоб «обход не работает» живёт здесь, а не в стратегии.
Правила могут быть не применены вовсе; могут стоять, пока движок лежит;
могут уводить в очередь 300, когда движок слушает 301. Снаружи все три
случая выглядят одинаково — и все три невидимы, если смотреть на статус
движка и на статус firewall по отдельности.

Поэтому инструмент отдаёт не только правила, но и **расхождения**
(``core/firewall.py:get_conflicts``) — тем же кодом, каким их считает
UI. Ни одного вывода здесь не делается заново.
"""

from core.mcp import audit
from core.mcp.registry import tool
from core.mcp.tools import _paging


# Правила — длинные строки, и их бывает полтора десятка на семью
# цепочек. Окно обязательно, иначе ответ съедает лимит.
RULES_MAX = 100
RULES_DEFAULT = 30

# Одна строка правила в выводе iptables-save бывает длинной.
MAX_RULE = 400


@tool(
    name="firewall_status",
    scope="read",
    mutating=False,
    title="Firewall status",
    description=("NFQUEUE rules: backend (iptables/nftables), whether "
                 "they are applied, the queue numbers they point at, and "
                 "conflicts with the engine's settings. / Правила "
                 "перехвата, бэкенд и расхождения с движком."),
    schema={
        "type": "object",
        "properties": {
            "rules": {
                "type": "boolean",
                "description": "Include the rule lines themselves. / "
                               "Вернуть сами строки правил.",
                "default": True,
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0,
                       "description": "Window start in rules. / Начало "
                                      "окна по правилам."},
            "limit": {"type": "integer", "minimum": 1, "maximum": RULES_MAX,
                      "default": RULES_DEFAULT,
                      "description": "How many rule lines (1-100). / "
                                     "Сколько строк правил вернуть."},
        },
        "additionalProperties": False,
    },
)
def firewall_status(args: dict) -> dict:
    """Правила NFQUEUE, бэкенд, номера очередей и расхождения."""
    from core.firewall import get_firewall_manager

    manager = get_firewall_manager()
    try:
        status = manager.get_status()
    except Exception as e:                      # noqa: BLE001 — граница
        return {
            "ok": False,
            "error": "правила не прочитаны: %s: %s" % (type(e).__name__, e),
            "hint": "обычно это отсутствие прав (нужен root) или самих "
                    "iptables/nft на устройстве",
        }

    rules = status.get("rules") or []
    conflicts = _safe(lambda: manager.get_conflicts(rules), [])
    queues = _safe(lambda: manager.queue_numbers(rules), [])

    offset, limit = _paging.limits(args, default=RULES_DEFAULT,
                                   maximum=RULES_MAX)
    want_rules = args.get("rules", True)
    lines = [str(r)[:MAX_RULE] for r in rules] if want_rules else []

    result = _paging.page(lines, offset, limit,
                          total=len(rules) if want_rules else 0)
    result.update({
        "backend": status.get("type") or "",
        "applied": bool(status.get("applied")),
        "rules_count": status.get("rules_count", len(rules)),
        "queue_numbers": queues,
        "conflicts": conflicts,
        "conflicts_count": len(conflicts),
    })

    # Расписание по устройствам: в его окно устройства идут мимо очереди
    # намеренно. Без этого «у устройства обход не работает» модель
    # искала бы в стратегии, а не в расписании.
    schedule = _safe(_device_schedule_brief, None)
    if schedule:
        result["device_schedule"] = schedule

    if not status.get("type"):
        result["hint"] = ("ни iptables, ни nft не найдены — перехват "
                          "невозможен")
    elif not status.get("applied"):
        result["hint"] = ("правила не применены: в NFQUEUE не приходит "
                          "ничего, и стратегия не срабатывает ни на одном "
                          "пакете")
    elif conflicts:
        # Расхождение важнее всего остального в ответе: с ним «правила
        # применены» ничего не значит.
        result["hint"] = "; ".join("%s: %s" % (c["title"], c["hint"])
                                   for c in conflicts[:3])
    return result


# ───────────────────────────── частности ────────────────────────────

def _device_schedule_brief():
    """Сводка расписания (core/device_schedule.py); выключено — None."""
    from core.device_schedule import get_device_scheduler
    st = get_device_scheduler().status()
    if not st.get("enabled"):
        return None
    return {key: st.get(key) for key in (
        "router_time", "active_rules", "excluded", "unresolved", "error")}


def _safe(getter, default):
    try:
        return getter()
    except Exception:                           # noqa: BLE001 — граница
        return default


# ──────────────────────────── правка (control) ──────────────────────

@tool(
    name="firewall_apply",
    scope="control",
    mutating=True,
    title="Apply NFQUEUE rules",
    description=("(Re)apply the NFQUEUE interception rules from config. "
                 "SSH and the GUI port are always excluded. Without a "
                 "running engine the queue has no reader — start nfqws2 "
                 "too. / Поставить правила перехвата."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def firewall_apply(args: dict) -> dict:
    """Поставить правила перехвата; порты управления в них не попадают."""
    from core.firewall import (get_firewall_manager, management_ports,
                               strip_management_ports)
    from core.config_manager import get_config_manager

    manager = get_firewall_manager()
    cfg = get_config_manager()
    before = _applied(manager)

    ports = cfg.get("nfqws", "ports_tcp", default="80,443")
    kept, dropped = strip_management_ports(ports, cfg)
    if not kept:
        # Отказ, а не «применил без портов»: пустой список уехал бы в
        # apply_rules, та подставила бы значение из конфига, и порты
        # управления вернулись бы в правила окольным путём.
        return {
            "ok": False,
            "error": "перехватывать нечего: в nfqws.ports_tcp остались "
                     "только порты управления (%s)"
                     % ", ".join(str(p) for p in dropped),
            "protected_ports": management_ports(cfg),
            "hint": "SSH и порт веб-интерфейса в NFQUEUE не уводятся "
                    "никогда; задайте нормальные порты — "
                    "config_set(path=\"nfqws.ports_tcp\", value=\"80,443\")",
        }

    try:
        ok = manager.apply_rules()
    except Exception as e:                      # noqa: BLE001 — граница
        return {"ok": False,
                "error": "правила не применены: %s: %s"
                         % (type(e).__name__, e),
                "hint": "обычно это отсутствие прав (нужен root) или "
                        "самих iptables/nft на устройстве"}

    return _firewall_result(manager, "apply", ok, before, cfg,
                            dropped=dropped)


@tool(
    name="firewall_remove",
    scope="control",
    mutating=True,
    title="Remove NFQUEUE rules",
    description=("Remove the NFQUEUE interception rules installed by the "
                 "GUI. Traffic goes direct afterwards: the engine may "
                 "stay up but will see no packets. / Снять правила "
                 "перехвата."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def firewall_remove(args: dict) -> dict:
    """Снять правила перехвата (движок при этом остаётся как есть)."""
    from core.firewall import get_firewall_manager

    manager = get_firewall_manager()
    before = _applied(manager)
    try:
        ok = manager.remove_rules()
    except Exception as e:                      # noqa: BLE001 — граница
        return {"ok": False,
                "error": "правила не сняты: %s: %s" % (type(e).__name__, e)}

    return _firewall_result(manager, "remove", ok, before, None)


def _undo_firewall(snapshot: dict) -> dict:
    """Вернуть правила в прежнее состояние: стояли — поставить, нет — снять."""
    from core.firewall import get_firewall_manager

    manager = get_firewall_manager()
    before = snapshot.get("before") or {}
    want = bool(before.get("applied"))
    ok = manager.apply_rules() if want else manager.remove_rules()
    return {"ok": bool(ok),
            "undone_to": "applied" if want else "removed",
            "error": "" if ok else "не удалось вернуть правила"}


def _applied(manager) -> dict:
    """Снимок состояния правил: стоят ли и сколько их."""
    try:
        status = manager.get_status()
    except Exception:                           # noqa: BLE001 — граница
        return {"applied": False, "rules_count": 0}
    return {"applied": bool(status.get("applied")),
            "rules_count": status.get("rules_count", 0),
            "backend": status.get("type") or ""}


def _firewall_result(manager, action, ok, before, cfg, dropped=None) -> dict:
    """Ответ мутирующего инструмента firewall: дифф и что с движком."""
    after = _applied(manager)
    result = {
        "ok": bool(ok),
        "action": action,
        "before": before,
        "after": after,
        "changed": before != after,
        "applied": after.get("applied", False),
        "backend": after.get("backend", ""),
        "rules_count": after.get("rules_count", 0),
    }
    if dropped:
        result["excluded_ports"] = list(dropped)
        result["note"] = ("порты управления (SSH, веб-интерфейс) в "
                          "NFQUEUE не уводятся: %s"
                          % ", ".join(str(p) for p in dropped))
    if not ok:
        result["error"] = ("правила не применены" if action == "apply"
                           else "правила не сняты")
        result["hint"] = ("нужен root и установленные iptables/nft; "
                          "подробности — logs_tail(source=\"firewall\")")
        return result

    undo = audit.snapshot(audit.KIND_FIREWALL, action, before, after,
                          tool="firewall_%s" % action)
    result["undo"] = undo or None
    if action == "apply":
        running = _engine_running()
        result["engine_running"] = running
        result["hint"] = ("правила стоят; откат — mcp_undo_last"
                          if running else
                          "правила стоят, но движок НЕ запущен: пакеты "
                          "уходят в очередь, которую никто не читает. "
                          "Поднимите движок — nfqws_start()")
    else:
        result["hint"] = ("правила сняты: трафик идёт напрямую, и "
                          "стратегия не применяется ни к одному пакету. "
                          "Откат — mcp_undo_last")
    if not undo:
        result["hint"] += " (журнал MCP выключен — снимка для отката нет)"
    return result


def _engine_running() -> bool:
    try:
        from core.nfqws_manager import get_nfqws_manager
        return bool(get_nfqws_manager().is_running())
    except Exception:                           # noqa: BLE001 — граница
        return False


# Откат правил объявляется на импорте, как и у остальных мутирующих.
audit.register_undo(audit.KIND_FIREWALL, _undo_firewall)
