# core/opera_proxy_chain.py
"""
Подключение opera-proxy как upstream внутрь sing-box / mihomo.

Зачем отдельный слой. Маршрутизация в проекте (core/unified) работает
через `ip rule` + таблицу с default-маршрутом НА ИНТЕРФЕЙС: цель метода
всегда сетевой интерфейс (`awg0`, `usque0`, `tun0`). opera-proxy
интерфейса не создаёт — это обычный HTTP- или SOCKS5-прокси на локальном
порту, и завернуть в него трафик правилом `ip rule` невозможно. nat
REDIRECT (как в core/tgproxy_redirect) тоже не подходит: opera-proxy не
читает `SO_ORIGINAL_DST`, и завёрнутое соединение придёт к нему без
CONNECT-заголовка — без адреса назначения.

Рабочий путь один: сделать opera-proxy последним хопом ВНУТРИ движка,
который уже умеет и TUN, и правила. Тогда маршрут в GUI остаётся
обычным (`singbox:<tun>` / `mihomo:<tun>`), а сам движок отдаёт выбранный
трафик в локальный порт opera-proxy.

Петля. Трафик самого opera-proxy идёт на `*.sec-tunnel.com:443`. Если
движок заворачивает «всё», этот трафик тоже уйдёт в туннель — то есть
обратно в opera-proxy. Поэтому вместе с прокси добавляем правило
«sec-tunnel.com → напрямую»; без него связка молча не работает.
"""

from core.log_buffer import log


# Домены SurfEasy, через которые работает сам opera-proxy: API регистрации
# (`api2.sec-tunnel.com`) и узлы (`eu0/as0/am0.sec-tunnel.com`). Всё под
# одним суффиксом, поэтому одного правила достаточно.
UPSTREAM_SUFFIX = "sec-tunnel.com"

DEFAULT_TAG = "opera-proxy"

ENGINES = ("singbox", "mihomo")


def _settings() -> dict:
    """bind и режим opera-proxy: у запущенного — фактические.

    Если процесс поднят, берём адрес, на котором он реально слушает:
    настройки могли поменять после запуска, и прокси, записанный в конфиг
    движка по ним, указывал бы в пустоту.
    """
    from core.opera_proxy_manager import (get_opera_proxy_manager,
                                          parse_bind)
    from core.config_manager import get_config_manager

    mgr = get_opera_proxy_manager()
    st = mgr.status(probe=False) or {}
    cfg = get_config_manager()
    bind = (st.get("bind")
            or cfg.get("opera_proxy", "bind", default="127.0.0.1:18080"))
    host, port = parse_bind(bind)
    return {
        "host": host,
        "port": port,
        "socks": bool(cfg.get("opera_proxy", "socks_mode", default=False)),
        "running": bool(st.get("running")),
        "listening": bool(st.get("listening")),
    }


def singbox_outbound(tag: str, host: str, port: int, socks: bool) -> dict:
    """sing-box outbound на локальный порт opera-proxy.

    `socks` требует явной версии: без `version` sing-box берёт «4»,
    а opera-proxy в `-socks-mode` говорит только SOCKS5.
    """
    ob = {"type": "socks" if socks else "http",
          "tag": tag, "server": host, "server_port": int(port)}
    if socks:
        ob["version"] = "5"
    return ob


def mihomo_proxy(name: str, host: str, port: int, socks: bool) -> dict:
    """clash-прокси на локальный порт opera-proxy."""
    return {"name": name, "type": "socks5" if socks else "http",
            "server": host, "port": int(port), "udp": False}


def singbox_bypass_rule(tag: str = "direct") -> dict:
    return {"domain_suffix": [UPSTREAM_SUFFIX], "outbound": tag}


def mihomo_bypass_rule() -> str:
    return "DOMAIN-SUFFIX,%s,DIRECT" % UPSTREAM_SUFFIX


def attach(engine: str, config: str, tag: str = "") -> dict:
    """Добавить opera-proxy в конфиг движка вместе с защитой от петли.

    Возвращает {ok, tag, engine, config, bypass_added, warnings[]}.
    Существующая запись с тем же именем — не ошибка: обновляем её
    (bind мог измениться), кнопку можно жать повторно.
    """
    engine = (engine or "").strip().lower()
    if engine not in ENGINES:
        return {"ok": False, "error": "Движок должен быть singbox или mihomo"}
    config = (config or "").strip()
    if not config:
        return {"ok": False, "error": "Не выбран конфиг"}
    tag = (tag or "").strip() or DEFAULT_TAG

    try:
        s = _settings()
    except ValueError as e:
        return {"ok": False, "error": "Некорректный bind opera-proxy: %s" % e}
    if not s["port"]:
        return {"ok": False, "error": "У opera-proxy не задан порт"}

    warnings = []
    if not s["running"]:
        warnings.append("opera-proxy сейчас не запущен — движок будет"
                        " получать отказ, пока прокси не поднят.")
    if s["host"] in ("0.0.0.0", "::"):
        # Слушает всё — подключаться движку всё равно надо на петлю.
        s["host"] = "127.0.0.1"

    if engine == "singbox":
        res = _attach_singbox(config, tag, s)
    else:
        res = _attach_mihomo(config, tag, s)
    if not res.get("ok"):
        return res

    res["warnings"] = warnings + list(res.get("warnings") or ())
    res["engine"] = engine
    res["config"] = config
    res["tag"] = tag
    log.info("opera-proxy: добавлен в %s-конфиг %s как '%s' (%s:%d, %s)"
             % (engine, config, tag, s["host"], s["port"],
                "socks5" if s["socks"] else "http"),
             source="opera_proxy")
    return res


def _attach_singbox(config: str, tag: str, s: dict) -> dict:
    from core.singbox_manager import get_singbox_manager
    from core.singbox_config import render_conf, add_route_rule

    mgr = get_singbox_manager()
    got = mgr.get_config(config)
    if not got.get("ok"):
        return {"ok": False, "error": got.get("error")
                or "Конфиг sing-box '%s' не найден" % config}
    cfg = got.get("parsed")
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "Конфиг sing-box не разобрался"}

    outbound = singbox_outbound(tag, s["host"], s["port"], s["socks"])
    obs = cfg.get("outbounds")
    if not isinstance(obs, list):
        obs = []
        cfg["outbounds"] = obs
    idx = next((i for i, o in enumerate(obs)
                if isinstance(o, dict) and o.get("tag") == tag), -1)
    replaced = idx >= 0
    if replaced:
        obs[idx] = outbound
    else:
        obs.append(outbound)

    # Правило петли ставим ПЕРЕД остальными: ниже по списку обычно лежит
    # «всё остальное → прокси», и оно перехватило бы sec-tunnel.com.
    rule = singbox_bypass_rule()
    rules = ((cfg.get("route") or {}).get("rules")
             if isinstance(cfg.get("route"), dict) else None)
    bypass_added = not any(r == rule for r in (rules or []))
    if bypass_added:
        add_route_rule(cfg, rule, front=True)

    save = mgr.save_config(config, text=render_conf(cfg))
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")
                or "Не удалось сохранить конфиг sing-box"}
    return {"ok": True, "replaced": replaced, "bypass_added": bypass_added}


def _attach_mihomo(config: str, tag: str, s: dict) -> dict:
    from core.mihomo_manager import get_mihomo_manager
    from core import mihomo_proxies as mp
    from core.clash_yaml import parse_yaml

    mgr = get_mihomo_manager()
    got = mgr.get_config(config)
    if not got.get("ok"):
        return {"ok": False, "error": got.get("error")
                or "Конфиг mihomo '%s' не найден" % config}
    text = got.get("text") or ""

    try:
        cfg = parse_yaml(text)
    except Exception as e:
        return {"ok": False, "error": "Не удалось разобрать YAML: %s" % e}
    cfg = cfg if isinstance(cfg, dict) else {}

    proxy = mihomo_proxy(tag, s["host"], s["port"], s["socks"])
    if tag in set(mp.proxy_names(cfg)):
        # Round-trip нужен, чтобы заменить существующую запись, а он
        # доступен только с pyyaml (иначе конфиг повредится).
        res = mp.safe_mutate(text, lambda c: _replace_proxy(c, tag, proxy))
        if not res.get("ok"):
            return res
        new_text = res["text"]
        replaced = True
    else:
        new_text = mp.append_proxies_text(text, [proxy])
        if new_text == text:
            return {"ok": False, "error":
                    "Не удалось дописать прокси (нестандартный блок"
                    " proxies). Добавьте его в YAML вручную."}
        replaced = False

    # Правило петли — только round-trip'ом: `rules` в clash-YAML это
    # список скаляров со значимым порядком, текстовая вставка в него
    # слишком легко ломает конфиг.
    warnings = []
    bypass_added = False
    rule = mihomo_bypass_rule()
    if rule in [str(r) for r in (cfg.get("rules") or [])]:
        pass
    elif mp.has_pyyaml():
        res = mp.safe_mutate(new_text, _add_mihomo_bypass)
        if res.get("ok"):
            new_text = res["text"]
            bypass_added = True
        else:
            warnings.append(res.get("error") or "правило обхода не добавлено")
    else:
        warnings.append(
            "Без PyYAML правило «%s» не добавить автоматически — впишите"
            " его первым в секцию rules, иначе трафик самого opera-proxy"
            " уйдёт по кругу." % rule)

    save = mgr.save_config(config, text=new_text)
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")
                or "Не удалось сохранить конфиг mihomo"}
    return {"ok": True, "replaced": replaced, "bypass_added": bypass_added,
            "warnings": warnings}


def _replace_proxy(cfg: dict, name: str, proxy: dict) -> dict:
    proxies = cfg.get("proxies")
    if not isinstance(proxies, list):
        cfg["proxies"] = [proxy]
        return cfg
    for i, p in enumerate(proxies):
        if isinstance(p, dict) and str(p.get("name")) == name:
            proxies[i] = proxy
            return cfg
    proxies.append(proxy)
    return cfg


def _add_mihomo_bypass(cfg: dict) -> dict:
    rules = cfg.get("rules")
    if not isinstance(rules, list):
        rules = []
    rule = mihomo_bypass_rule()
    if rule not in [str(r) for r in rules]:
        rules.insert(0, rule)
    cfg["rules"] = rules
    return cfg
