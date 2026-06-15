# core/mihomo_routing.py
"""
Оркестраторы маршрутизации mihomo: резолв прокси (ссылка/подписка/конфиг) →
сборка clash-YAML (core/mihomo_config) → проверка `mihomo -t` → сохранение.

Аналог `core/singbox_fakeip.py` (build_and_save / build_lite_route_and_save), но
для mihomo. Точки входа (вызываются из api/mihomo.py):
  build_options()              — данные для формы (версия, gvisor, списки, …).
  build_domain_route_and_save() — выборочно по доменам/спискам (+ fake-ip).
  build_source_route_and_save() — по устройствам (source-IP) / весь трафик.

Подбор формата под версию/сборку — как у sing-box (typed/legacy DNS), но здесь
варьируем СТЕК (gvisor↔system — фолбэк, если сборка без gvisor) и способ
доменных правил (inline RULE-SET ↔ DOMAIN-SUFFIX — фолбэк для старых сборок).
Выбираем первый вариант, который принял `mihomo -t`. Без бинаря — сохраняем
самый совместимый без проверки (graceful-degrade).
"""

from __future__ import annotations

import secrets

from core.log_buffer import log
from core import mihomo_config as mc


# ─────────────────────── proxy resolution ───────────────────────

def _resolve_proxies(proxy_link: str = "", proxy_config: str = "") -> dict:
    """
    Вернуть {ok, proxies} — список clash-proxy dict'ов (с уникальными именами).

    Источник: вставленные ссылки/подписка (`proxy_link`: vless:// ss:// …,
    в т.ч. несколько строк / base64-подписка) ИЛИ узлы существующего конфига
    (`proxy_config`). Если задана ссылка — используется она.
    """
    link = (proxy_link or "").strip()
    proxies: list = []

    if link:
        from core.subscription_importer import extract_items
        from core.clash_yaml import uri_to_clash_proxy
        errors = 0
        for it in extract_items(link):
            if not isinstance(it, dict) or it.get("type") != "uri":
                continue
            uri = it.get("value")
            if not uri:
                continue
            r = uri_to_clash_proxy(uri)
            if r.get("ok") and r.get("proxy"):
                proxies.append(r["proxy"])
            else:
                errors += 1
        if not proxies:
            return {"ok": False,
                    "error": "в ссылке/подписке не нашлось поддерживаемых "
                             "прокси (vless/vmess/trojan/ss/hysteria2/tuic)"}
    elif (proxy_config or "").strip():
        from core.mihomo_manager import get_mihomo_manager
        from core.clash_yaml import parse_yaml
        from core import mihomo_proxies as mp
        cfgname = proxy_config.strip()
        res = get_mihomo_manager().get_config(cfgname)
        if not res.get("ok"):
            return {"ok": False, "error": "конфиг '%s' не найден" % cfgname}
        try:
            cfg = parse_yaml(res.get("text") or "")
        except Exception as e:
            return {"ok": False, "error": "конфиг '%s': %s" % (cfgname, e)}
        proxies = [dict(p) for p in mp.list_proxies(cfg or {})]
        if not proxies:
            return {"ok": False,
                    "error": "в конфиге '%s' нет секции proxies" % cfgname}
    else:
        return {"ok": False,
                "error": "укажите ссылку/подписку на прокси или конфиг"}

    return {"ok": True, "proxies": _dedup_names(proxies)}


def _dedup_names(proxies: list) -> list:
    """Гарантировать уникальные непустые имена прокси (для proxy-group/правил)."""
    seen, out = set(), []
    for i, p in enumerate(proxies):
        if not isinstance(p, dict):
            continue
        nm = str(p.get("name") or p.get("type") or "proxy").strip() or "proxy"
        base, n = nm, 2
        while nm in seen:
            nm = "%s-%d" % (base, n)
            n += 1
        seen.add(nm)
        p = dict(p)
        p["name"] = nm
        out.append(p)
    return out


# ─────────────────────── lists / domains ───────────────────────

def _collect_lists(hostlists=None, lists=None):
    """Собрать домены (+ cidrs) из nfqws2-хостлистов и named-lists."""
    domains: list = []
    cidrs: list = []
    if hostlists:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        for hl in hostlists:
            try:
                domains += hm.get_hostlist(hl)
            except Exception:
                pass
    if lists:
        from core import named_lists
        for lid in lists:
            try:
                r = named_lists.resolve(lid)
                domains += r.get("domains") or []
                cidrs += r.get("cidrs") or []
            except Exception:
                pass
    return domains, cidrs


# ─────────────────────── options for the form ───────────────────────

def build_options() -> dict:
    from core.mihomo_detector import get_mihomo_detector
    from core.mihomo_manager import get_mihomo_manager
    from core.mihomo_platform import detect_mihomo_platform

    det = get_mihomo_detector().detect_binary()
    platform = detect_mihomo_platform()

    hostlists = []
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        stats = hm.get_stats()
        hostlists = [{"name": n, "count": (stats.get(n) or {}).get("count", 0)}
                     for n in hm.list_names()]
    except Exception:
        pass

    named = []
    try:
        from core import named_lists
        named = [{"id": l.get("id"), "name": l.get("name"),
                  "domain_count": l.get("domain_count", 0),
                  "cidr_count": l.get("cidr_count", 0)}
                 for l in named_lists.list_all() if l.get("id")]
    except Exception:
        pass

    try:
        configs = [c["name"] for c in get_mihomo_manager().list_configs()]
    except Exception:
        configs = []

    nft = False
    try:
        nft = platform.get_firewall_backend() == "nftables"
    except Exception:
        pass

    return {
        "ok": True,
        "installed": bool(det.get("installed")),
        "version": det.get("version") or "",
        "has_gvisor": det.get("has_gvisor", True),
        "tun_available": bool(platform.tun_available()),
        "nft": nft,
        "hostlists": hostlists,
        "lists": named,
        "configs": configs,
        "default_stack": "gvisor" if det.get("has_gvisor", True) else "system",
        "fakeip_range": mc.FAKEIP_RANGE,
        "default_device": mc.DEFAULT_TUN_DEVICE,
    }


# ─────────────────────── build + validate + save ───────────────────────

def _pick_stack(requested: str, has_gvisor: bool, default: str) -> str:
    st = (requested or "").strip().lower()
    if st in ("gvisor", "system", "mixed"):
        return st
    return default if has_gvisor or default == "system" else "system"


def _validate_and_pick(name: str, candidates: list) -> dict:
    """
    candidates — список (cfg, meta) в порядке предпочтения. Возвращает первый,
    который принял `mihomo -t`. Без бинаря — первый (самый совместимый) без
    проверки. {ok, text, meta, warning} либо {ok: False, error}.
    """
    from core.clash_yaml import dump_yaml
    from core.mihomo_detector import get_mihomo_detector
    from core.mihomo_manager import get_mihomo_manager

    has_binary = bool(get_mihomo_detector().detect_binary().get("installed"))
    mgr = get_mihomo_manager()
    last_err = ""
    for cfg, meta in candidates:
        text = dump_yaml(cfg)
        if not has_binary:
            return {"ok": True, "text": text, "meta": meta,
                    "warning": "mihomo не установлен — конфиг сохранён "
                               "без проверки"}
        chk = mgr.validate_via_binary(name, text=text)
        if chk.get("ok"):
            return {"ok": True, "text": text, "meta": meta, "warning": ""}
        last_err = (chk.get("stderr") or chk.get("error")
                    or "").strip() or last_err
    return {"ok": False,
            "error": "mihomo отверг сгенерированный конфиг: %s"
                     % (last_err or "неизвестная ошибка")}


def _auto_redirect(nft: bool) -> bool:
    return bool(nft)


def _nft_backend() -> bool:
    try:
        from core.mihomo_platform import detect_mihomo_platform
        return detect_mihomo_platform().get_firewall_backend() == "nftables"
    except Exception:
        return False


def build_domain_route_and_save(*, name: str = "mihomo-domains",
                                proxy_link: str = "", proxy_config: str = "",
                                hostlists=None, lists=None, domains=None,
                                cidrs=None, route_all: bool = False,
                                stack: str = "", mtu: int = 1500,
                                reject_quic: bool = False,
                                group_type: str = "select") -> dict:
    """Собрать и сохранить конфиг доменной маршрутизации (+ fake-ip)."""
    from core.mihomo_detector import get_mihomo_detector
    from core.mihomo_manager import get_mihomo_manager
    from core.proxy_tester import _free_port

    name = (name or "mihomo-domains").strip()
    pr = _resolve_proxies(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr
    proxies = pr["proxies"]

    list_doms, list_cidrs = _collect_lists(hostlists, lists)
    all_domains = list(domains or []) + list_doms
    all_cidrs = [str(c).strip() for c in (list(cidrs or []) + list_cidrs)
                 if str(c).strip()]
    norm_doms = mc._norm_suffix_domains(all_domains)

    if not route_all and not norm_doms and not all_cidrs:
        return {"ok": False,
                "error": "выберите списки/домены/подсети для проксирования "
                         "или включите режим «весь трафик»"}

    det = get_mihomo_detector().detect_binary()
    has_gvisor = det.get("has_gvisor", True)
    chosen_stack = _pick_stack(stack, has_gvisor, "gvisor")
    nft = _nft_backend()
    port, sec = _free_port(), secrets.token_hex(8)

    stacks = [chosen_stack] + (["system"] if chosen_stack != "system" else [])
    use_ruleset_opts = ([True, False]
                        if (norm_doms and not route_all) else [True])
    candidates = []
    for st in stacks:
        for ur in use_ruleset_opts:
            cfg = mc.build_domain_config(
                proxies=proxies, proxied_domains=norm_doms,
                proxied_cidrs=all_cidrs, route_all=route_all, stack=st,
                mtu=mtu, reject_quic=reject_quic,
                auto_redirect=_auto_redirect(nft),
                controller_port=port, controller_secret=sec,
                group_type=group_type, use_ruleset=ur)
            candidates.append((cfg, {"stack": st, "ruleset": ur}))

    picked = _validate_and_pick(name, candidates)
    if not picked.get("ok"):
        return picked

    save = get_mihomo_manager().save_config(name, text=picked["text"])
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}

    meta = picked["meta"]
    log.info("mihomo routing: конфиг '%s' создан (домены=%d, подсети=%d, "
             "режим=%s, стек=%s, ruleset=%s, auto-redirect=%s)"
             % (name, len(norm_doms), len(all_cidrs),
                "всё" if route_all else "выборочно", meta["stack"],
                meta["ruleset"], nft), source="mihomo")
    return {
        "ok": True, "name": name, "mode": "domain",
        "route_all": bool(route_all), "stack": meta["stack"],
        "ruleset": meta["ruleset"], "domains": len(norm_doms),
        "cidrs": len(all_cidrs), "proxies": len(proxies),
        "controller_port": port, "auto_redirect": nft,
        "tun_device": mc.find_tun_device(candidates[0][0]),
        "warning": picked.get("warning") or "",
        "warnings": save.get("warnings") or [],
    }


def build_source_route_and_save(*, name: str = "mihomo-devices",
                                proxy_link: str = "", proxy_config: str = "",
                                source_ips=None, route_all: bool = False,
                                stack: str = "", mtu: int = 1500,
                                reject_quic: bool = False,
                                group_type: str = "select") -> dict:
    """Собрать и сохранить конфиг маршрутизации по устройствам / весь трафик
    (kernel-стек по умолчанию)."""
    from core.mihomo_detector import get_mihomo_detector
    from core.mihomo_manager import get_mihomo_manager
    from core.proxy_tester import _free_port

    name = (name or "mihomo-devices").strip()
    pr = _resolve_proxies(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr
    proxies = pr["proxies"]

    srcs = [str(s).strip() for s in (source_ips or []) if str(s).strip()]
    if not route_all and not srcs:
        return {"ok": False,
                "error": "укажите IP устройств (source-IP) или включите "
                         "режим «весь трафик»"}

    det = get_mihomo_detector().detect_binary()
    has_gvisor = det.get("has_gvisor", True)
    # Для «весь ПК / устройства» дефолт — system (kernel, низкий CPU).
    chosen_stack = _pick_stack(stack, has_gvisor, "system")
    nft = _nft_backend()
    port, sec = _free_port(), secrets.token_hex(8)

    stacks = [chosen_stack] + (["gvisor"] if chosen_stack != "gvisor"
                               and has_gvisor else [])
    candidates = []
    for st in stacks:
        cfg = mc.build_source_config(
            proxies=proxies, source_ips=srcs, route_all=route_all, stack=st,
            mtu=mtu, reject_quic=reject_quic,
            auto_redirect=_auto_redirect(nft), controller_port=port,
            controller_secret=sec, group_type=group_type)
        candidates.append((cfg, {"stack": st}))

    picked = _validate_and_pick(name, candidates)
    if not picked.get("ok"):
        return picked

    save = get_mihomo_manager().save_config(name, text=picked["text"])
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}

    meta = picked["meta"]
    log.info("mihomo routing: конфиг '%s' создан (source=%d, режим=%s, "
             "стек=%s, auto-redirect=%s)"
             % (name, len(srcs), "всё" if route_all else "выборочно",
                meta["stack"], nft), source="mihomo")
    return {
        "ok": True, "name": name, "mode": "source",
        "route_all": bool(route_all), "stack": meta["stack"],
        "sources": len(srcs), "proxies": len(proxies),
        "controller_port": port, "auto_redirect": nft,
        "tun_device": mc.find_tun_device(candidates[0][0]),
        "warning": picked.get("warning") or "",
        "warnings": save.get("warnings") or [],
    }
