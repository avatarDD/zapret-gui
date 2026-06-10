# core/singbox_fakeip.py
"""
FakeIP-роутинг для sing-box — «умный доменный роутинг» (как podkop, но
мультиплатформенно).

Собирает self-contained конфиг: TUN(auto_route) + DNS(FakeIP) + hijack-dns +
domain/cidr route-правила. Домены берём из существующих hostlist-списков
пользователя (те же, что для nfqws) + произвольные домены/подсети из формы.
Прокси-сервер — из вставленной ссылки (vless:// / ss:// / …) или из готового
конфига.

Формат DNS подбираем под версию движка и ПРОВЕРЯЕМ `sing-box check`-ом до
сохранения: legacy (1.8–1.13) или typed (1.12+). См. skill §13.

Точки входа (вызываются из api/singbox.py):
  build_options()  — данные для формы (версия, списки, конфиги, nft).
  build_and_save() — собрать, проверить бинарём, сохранить конфиг.
"""

from __future__ import annotations

import re

from core.log_buffer import log


_VER_RE = re.compile(r"(\d+)\.(\d+)")


def _parse_minor(version: str):
    """'1.13.0' → (1, 13). Неразобранное → (0, 0)."""
    m = _VER_RE.search(version or "")
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


# ─────────────────────── proxy resolution ───────────────────────

def _resolve_proxy(proxy_link: str, proxy_config: str) -> dict:
    """Вернуть {ok, outbound} — конкретный прокси-outbound (vless/ss/...)."""
    link = (proxy_link or "").strip()
    if link:
        from core.singbox_subscription import uri_to_outbound
        res = uri_to_outbound(link)
        if not res.get("ok"):
            return {"ok": False,
                    "error": "ссылка не распознана: %s" % res.get("error")}
        return {"ok": True, "outbound": res["outbound"]}

    cfgname = (proxy_config or "").strip()
    if cfgname:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import parse_conf
        mgr = get_singbox_manager()
        r = mgr.get_config(cfgname)
        if not r.get("ok"):
            return {"ok": False, "error": "конфиг '%s' не найден" % cfgname}
        cfg = r.get("parsed") or parse_conf(r.get("text") or "{}")
        for ob in (cfg.get("outbounds") or []):
            if (isinstance(ob, dict)
                    and ob.get("type") not in ("direct", "block", "dns",
                                               "selector", "urltest")
                    and ob.get("server")):
                return {"ok": True, "outbound": dict(ob)}
        return {"ok": False,
                "error": "в конфиге '%s' нет простого прокси-сервера — "
                         "вставьте ссылку vless://…" % cfgname}

    return {"ok": False,
            "error": "укажите ссылку на прокси или существующий конфиг"}


# ─────────────────────── options for the form ───────────────────────

def build_options() -> dict:
    from core.singbox_detector import get_singbox_detector
    from core.singbox_manager import get_singbox_manager
    from core.singbox_platform import detect_singbox_platform
    from core.hostlist_manager import get_hostlist_manager

    det = get_singbox_detector().detect_binary()
    mgr = get_singbox_manager()
    hm = get_hostlist_manager()

    stats = hm.get_stats()
    hostlists = [{"name": n, "count": stats[n]["count"]}
                 for n in hm.list_names() if n in stats]

    try:
        configs = [c["name"] for c in mgr.list_configs()]
    except Exception:
        configs = []

    nft = False
    try:
        nft = bool(detect_singbox_platform().supports_nftables())
    except Exception:
        pass

    return {
        "ok": True,
        "installed": bool(det.get("installed")),
        "version": det.get("version") or "",
        "nft": nft,
        "hostlists": hostlists,
        "configs": configs,
        "default_direct_dns": "local",
        "fakeip_range": "198.18.0.0/15",
    }


# ─────────────────────── build + validate + save ───────────────────────

def build_and_save(*, name: str = "fakeip", proxy_link: str = "",
                   proxy_config: str = "", hostlists=None, domains=None,
                   cidrs=None, direct_dns: str = "local",
                   route_all: bool = False, tun_iface: str = "singbox-tun",
                   stack: str = "system") -> dict:
    from core.singbox_config import build_fakeip_config, render_conf
    from core.singbox_manager import get_singbox_manager
    from core.singbox_platform import detect_singbox_platform
    from core.singbox_detector import get_singbox_detector
    from core.hostlist_manager import get_hostlist_manager

    name = (name or "fakeip").strip()
    tun_iface = (tun_iface or "singbox-tun").strip()[:15]

    pr = _resolve_proxy(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr
    proxy_outbound = pr["outbound"]

    # Домены: из выбранных hostlist'ов + произвольные из формы.
    hm = get_hostlist_manager()
    proxied = list(domains or [])
    for hl in (hostlists or []):
        try:
            proxied += hm.get_hostlist(hl)
        except Exception:
            pass
    cidrs = [str(c).strip() for c in (cidrs or []) if str(c).strip()]

    if not route_all and not proxied and not cidrs:
        return {"ok": False,
                "error": "выберите списки/домены/подсети для проксирования "
                         "или включите режим «весь трафик»"}

    auto_redirect = False
    try:
        auto_redirect = bool(detect_singbox_platform().supports_nftables())
    except Exception:
        pass

    def _mk(typed: bool):
        cfg = build_fakeip_config(
            proxy_outbound=proxy_outbound, proxied_domains=proxied,
            proxied_cidrs=cidrs, route_all=route_all, direct_dns=direct_dns,
            tun_iface=tun_iface, stack=stack, auto_redirect=auto_redirect,
            typed_dns=typed)
        return render_conf(cfg)

    # Порядок форматов: для свежих движков (≥1.14, legacy-DNS удалён) — typed
    # первым, иначе legacy (он валиден на 1.8–1.13, т.е. почти везде сейчас).
    ver = _parse_minor(get_singbox_detector().detect_binary().get("version"))
    order = [True, False] if ver >= (1, 14) else [False, True]

    mgr = get_singbox_manager()
    chosen_text, fmt, warning = None, "", ""
    last_err = ""
    for typed in order:
        text = _mk(typed)
        chk = mgr.check_text(text)
        if chk.get("no_binary"):
            # Проверить нечем — берём первый (самый совместимый) формат.
            chosen_text = text
            fmt = "typed" if typed else "legacy"
            warning = "sing-box не установлен — конфиг сохранён без проверки"
            break
        if chk.get("ok"):
            chosen_text = text
            fmt = "typed" if typed else "legacy"
            break
        last_err = chk.get("error") or last_err

    if chosen_text is None:
        return {"ok": False,
                "error": "sing-box отверг сгенерированный конфиг: %s"
                         % (last_err or "неизвестная ошибка")}

    save = mgr.save_config(name, text=chosen_text)
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}

    fakeip_on = (not route_all) and bool(proxied)
    log.info("singbox FakeIP: конфиг '%s' создан (формат=%s, домены=%d, "
             "подсети=%d, режим=%s)" % (name, fmt, len(proxied), len(cidrs),
                                        "всё" if route_all else "выборочно"),
             source="singbox")
    return {
        "ok": True, "name": name, "dns_format": fmt, "fakeip": fakeip_on,
        "route_all": bool(route_all), "domains": len(proxied),
        "cidrs": len(cidrs), "auto_redirect": auto_redirect,
        "warning": warning,
        "warnings": save.get("warnings") or [],
    }
