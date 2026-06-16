# core/unified/geo_engine.py
"""
Раскладка geosite/geoip-селекторов единого слоя в route-правила движка.

iptables/ipset-routing не умеет geosite/geoip (это нативные концепции
sing-box/mihomo), поэтому такие селекторы инжектируются прямо в конфиг
движка, который обслуживает целевой интерфейс метода.

Поддержка:
  • sing-box (JSON) — полноценно: находим конфиг по interface_name
    tun-инбаунда (или по имени конфига), добавляем route-правило
    {domain_suffix/geosite/geoip → <proxy outbound>}, при работающем
    инстансе перезапускаем. Идемпотентность — через sidecar в
    settings.json (`unified_geo[route_id] = {engine, config, rule}`):
    при обновлении сначала удаляем ровно прежнее правило.
  • mihomo (YAML) — наш clash-слой не эмитит YAML, поэтому
    автоинъекция не делается; возвращаем понятную причину, чтобы UI
    подсказал добавить правило вручную.

`locate_singbox_config(iface)` и работа с правилом — тестируемы с
моками менеджера.
"""

from core.log_buffer import log
from core.unified.model import parse_method


# ─────────────────────── sidecar (idempotency) ───────────────────────

def _sidecar() -> dict:
    try:
        from core.config_manager import get_config_manager
        v = get_config_manager().get("unified_geo")
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def _save_sidecar(data: dict):
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("unified_geo", data)
        cm.save()
    except Exception as e:
        log.warning("unified geo sidecar save: %s" % e, source="unified")


# ─────────────────────── locate sing-box config ──────────────────────

def locate_singbox_config(iface: str) -> str:
    """
    Найти имя sing-box-конфига, обслуживающего интерфейс `iface`:
      1) конфиг с tun-инбаундом interface_name == iface;
      2) конфиг, чьё имя == iface (частый случай: name==tun-iface).
    Возвращает имя или ''.
    """
    try:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import parse_conf, find_tun_interface
    except Exception:
        return ""
    mgr = get_singbox_manager()
    names = [c["name"] for c in mgr.list_configs()]
    for name in names:
        try:
            cfg_resp = mgr.get_config(name)
            cfg = cfg_resp.get("parsed") if isinstance(cfg_resp, dict) else None
            if not cfg:
                cfg = parse_conf(cfg_resp.get("text") or "{}")
            if find_tun_interface(cfg) == iface and iface:
                return name
        except Exception:
            continue
    if iface in names:
        return iface
    return ""


# ─────────────────────── apply / remove (sing-box) ───────────────────

def apply_geo(route, method: str) -> dict:
    """
    Инжектировать geosite/geoip/домены назначения в конфиг движка для
    данного метода. Возвращает {ok, applied?|skipped?, reason?}.
    """
    resolved = route.destination.resolve()
    geosite = resolved.get("geosite") or []
    geoip = resolved.get("geoip") or []
    if not geosite and not geoip:
        # geo-селекторов нет — снимаем возможный прежний geo-инжект.
        remove_geo(route)
        return {"ok": True, "noop": True}

    try:
        kind, iface = parse_method(method)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    if kind == "mihomo":
        return {"ok": True, "skipped": True,
                "reason": "mihomo: автоинъекция geosite/geoip не "
                          "поддерживается (нет YAML-эмиттера) — добавьте "
                          "правила GEOSITE/GEOIP в конфиг вручную"}
    if kind != "singbox":
        return {"ok": True, "skipped": True,
                "reason": "geosite/geoip работают только с движком "
                          "(метод singbox:/mihomo:)"}

    config_name = locate_singbox_config(iface)
    if not config_name:
        return {"ok": True, "skipped": True,
                "reason": "не найден sing-box-конфиг для интерфейса '%s' — "
                          "geosite/geoip не применены" % iface}

    return _inject_singbox(route, config_name, resolved)


def _inject_singbox(route, config_name, resolved) -> dict:
    from core.singbox_manager import get_singbox_manager
    from core.singbox_config import (
        parse_conf, render_conf, build_geo_route_rule,
        add_route_rule, remove_route_rule, pick_proxy_outbound,
    )
    mgr = get_singbox_manager()
    cfg_resp = mgr.get_config(config_name)
    if not cfg_resp.get("ok"):
        return {"ok": False, "error": "конфиг %s недоступен" % config_name}
    cfg = cfg_resp.get("parsed") or parse_conf(cfg_resp.get("text") or "{}")

    outbound = pick_proxy_outbound(cfg)
    if not outbound:
        return {"ok": True, "skipped": True,
                "reason": "в конфиге %s нет прокси-outbound для geo-маршрута"
                          % config_name}

    # geosite/geoip как route-матчеры УДАЛЕНЫ в sing-box 1.12 (FATAL на старте).
    # Разворачиваем их в домены/CIDR через alias_resolver — тот же путь, что у
    # OS-routing и AWG, — и строим валидное правило domain_suffix/ip_cidr.
    from core.routing.alias_resolver import expand_domains
    tokens = list(resolved.get("domains") or [])
    tokens += ["geosite:%s" % g for g in (resolved.get("geosite") or [])]
    tokens += ["geoip:%s" % g for g in (resolved.get("geoip") or [])]
    exp = expand_domains(tokens)
    if not exp["domains"] and not exp["cidrs"]:
        return {"ok": True, "skipped": True,
                "reason": "geosite/geoip не удалось развернуть в домены/CIDR "
                          "(нет сети/пустой список) — правило не добавлено"}
    if exp.get("aliases_failed"):
        log.warning("unified geo: не развернулись алиасы %s"
                    % exp["aliases_failed"], source="unified")

    # Удаляем прежнее наше правило (по sidecar), затем добавляем новое.
    side = _sidecar()
    prev = side.get(route.id)
    if prev and prev.get("config") == config_name and prev.get("rule"):
        remove_route_rule(cfg, prev["rule"])

    rule = build_geo_route_rule(outbound, domains=exp["domains"],
                                cidrs=exp["cidrs"])
    add_route_rule(cfg, rule, front=True)

    save = mgr.save_config(config_name, text=render_conf(cfg))
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}

    side[route.id] = {"engine": "singbox", "config": config_name, "rule": rule}
    _save_sidecar(side)

    restarted = False
    if mgr.is_running(config_name):
        mgr.restart(config_name)
        restarted = True
    log.info("unified geo: правило для %s инжектировано в sing-box '%s' "
             "(restart=%s)" % (route.id, config_name, restarted),
             source="unified")
    return {"ok": True, "applied": {"config": config_name,
            "outbound": outbound, "restarted": restarted}}


def remove_geo(route) -> dict:
    """Снять ранее инжектированное geo-правило для маршрута (если было)."""
    rid = route.id if hasattr(route, "id") else str(route)
    side = _sidecar()
    prev = side.get(rid)
    if not prev:
        return {"ok": True, "noop": True}
    config_name = prev.get("config")
    rule = prev.get("rule")
    if prev.get("engine") == "singbox" and config_name and rule:
        try:
            from core.singbox_manager import get_singbox_manager
            from core.singbox_config import parse_conf, render_conf, remove_route_rule
            mgr = get_singbox_manager()
            cfg_resp = mgr.get_config(config_name)
            if cfg_resp.get("ok"):
                cfg = cfg_resp.get("parsed") or parse_conf(cfg_resp.get("text") or "{}")
                if remove_route_rule(cfg, rule):
                    mgr.save_config(config_name, text=render_conf(cfg))
                    if mgr.is_running(config_name):
                        mgr.restart(config_name)
        except Exception as e:
            log.warning("unified geo remove: %s" % e, source="unified")
    side.pop(rid, None)
    _save_sidecar(side)
    return {"ok": True, "removed": True}
