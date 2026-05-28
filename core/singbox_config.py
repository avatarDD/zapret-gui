# core/singbox_config.py
"""
Парсер и валидатор JSON-конфигов sing-box.

sing-box принимает JSON (не INI-like .conf). Структура схемы
описана в https://sing-box.sagernet.org/configuration/ — нас
интересуют только верхнеуровневые секции:

    {
      "log":       {...},                    # опционально
      "dns":       {"servers": [...], ...},  # опционально
      "inbounds":  [...],   # source трафика: tun / mixed / http / socks
      "outbounds": [...],   # куда уходит: vless / trojan / shadowsocks /
                            #              hysteria2 / wireguard / direct
      "route":     {"rules": [...]},  # правила маршрутизации
                                       # между inbounds и outbounds
      "experimental": {...},
    }

Этот модуль:
  - валидирует обязательные поля (outbounds должны быть, тип каждого
    outbound'а — известный);
  - выдаёт человекочитаемые ошибки для UI;
  - умеет генерить минимальный «route only»-конфиг под наш typical
    use-case: tun inbound → user-defined outbound → direct-fallback.

Сложную валидацию (sing-box check на уровне бинаря) делаем отдельно
через `singbox_manager.validate_config()` — она просто запускает
`sing-box check -c <file>` и парсит вывод.
"""

import json
from typing import Any


# Известные типы outbound'ов (для предварительной валидации без
# реального бинаря). Список неполный — sing-box добавляет новые;
# UI просто выдаст warning «неизвестный тип» вместо отказа.
KNOWN_OUTBOUND_TYPES = {
    "direct", "block", "dns", "selector", "urltest",
    "shadowsocks", "vmess", "vless", "trojan",
    "wireguard", "hysteria", "hysteria2", "tuic",
    "shadowtls", "naive", "ssh", "socks", "http",
    "tor",
}

# Известные типы inbound'ов.
KNOWN_INBOUND_TYPES = {
    "direct", "mixed", "socks", "http", "shadowsocks",
    "vmess", "vless", "trojan", "naive", "hysteria",
    "hysteria2", "tuic", "shadowtls", "tun", "redirect",
    "tproxy",
}


# ─────── parse ───────

def parse_conf(text: str) -> dict:
    """
    Распарсить JSON. Возвращает dict или поднимает ValueError.
    """
    if not text or not text.strip():
        raise ValueError("Пустой конфиг")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError("Некорректный JSON: %s" % e)
    if not isinstance(data, dict):
        raise ValueError("Корень должен быть объектом")
    return data


def render_conf(cfg: dict) -> str:
    """
    Сериализовать конфиг обратно в красивый JSON. Используется при
    сохранении через UI «конструктор» (когда юзер редактирует поля,
    а не raw-JSON).
    """
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"


# ─────── validate ───────

def validate(cfg: dict) -> list:
    """
    Лёгкая структурная валидация. Возвращает list ошибок-строк.

    Глубокая валидация (правильность ssh-key, формата endpoint и т.п.)
    делегируется самому `sing-box check`. Здесь мы ловим только то,
    что точно проблема: отсутствуют outbound'ы, неправильные типы,
    повторяющиеся теги.
    """
    errors = []

    if not isinstance(cfg, dict):
        return ["Корень должен быть объектом"]

    # outbounds — обязательны
    outbounds = cfg.get("outbounds")
    if outbounds is None:
        errors.append("Секция 'outbounds' обязательна")
    elif not isinstance(outbounds, list):
        errors.append("'outbounds' должен быть массивом")
    elif not outbounds:
        errors.append("'outbounds' не должен быть пустым")
    else:
        tags_seen = set()
        for i, ob in enumerate(outbounds):
            if not isinstance(ob, dict):
                errors.append("outbounds[%d]: должен быть объектом" % i)
                continue
            t = ob.get("type")
            if not t:
                errors.append("outbounds[%d]: отсутствует 'type'" % i)
            elif t not in KNOWN_OUTBOUND_TYPES:
                # Warning, а не error — sing-box может добавить новые типы
                errors.append(
                    "outbounds[%d]: неизвестный тип '%s' "
                    "(будет принят как есть)" % (i, t))
            tag = ob.get("tag")
            if tag:
                if tag in tags_seen:
                    errors.append(
                        "outbounds[%d]: tag '%s' уже встречается выше" %
                        (i, tag))
                tags_seen.add(tag)

    # inbounds — опциональны, но если есть, типизированы
    inbounds = cfg.get("inbounds")
    if inbounds is not None:
        if not isinstance(inbounds, list):
            errors.append("'inbounds' должен быть массивом")
        else:
            for i, ib in enumerate(inbounds):
                if not isinstance(ib, dict):
                    errors.append("inbounds[%d]: должен быть объектом" % i)
                    continue
                t = ib.get("type")
                if not t:
                    errors.append("inbounds[%d]: отсутствует 'type'" % i)

    # route — опциональна; если есть, проверим базовую форму
    route = cfg.get("route")
    if route is not None:
        if not isinstance(route, dict):
            errors.append("'route' должен быть объектом")
        else:
            rules = route.get("rules")
            if rules is not None and not isinstance(rules, list):
                errors.append("'route.rules' должен быть массивом")

    return errors


# ─────── helpers для конструктора ───────

def make_minimal_config(*, listen_port: int = 1080,
                       outbound_tag: str = "proxy-out") -> dict:
    """
    Сгенерить минимальный конфиг: SOCKS5-inbound на :1080, single
    outbound, direct-fallback по тегу. Удобный starting point —
    пользователь добавит свой outbound (vless/trojan/...) и UI
    подставит правильный route.

    Имя outbound-тега ('proxy-out') фиксированное, чтобы route
    срабатывал без перепрошивки.
    """
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type":      "mixed",     # http + socks5 одним портом
                "tag":       "mixed-in",
                "listen":    "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [
            # Юзер должен заменить этот элемент через UI на свой
            # vless / trojan / hysteria2 outbound с tag=outbound_tag.
            {"type": "direct", "tag": outbound_tag},
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {
            "rules": [
                # Всё, что пришло на mixed-in, отправляем в выбранный
                # outbound.
                {"inbound": ["mixed-in"], "outbound": outbound_tag},
            ],
            "final": "direct",
        },
    }


# ─────── outbound builders (вызываются из subscription_importer) ───────

def make_vless_outbound(tag: str, server: str, port: int, uuid: str,
                        *, flow: str = "",
                        transport: dict = None,
                        tls: dict = None) -> dict:
    """
    Собрать VLESS-outbound dict. Минимум: server, port, uuid.

    flow:       часто 'xtls-rprx-vision' для Reality
    transport:  {"type": "ws", "path": "/", "headers": {...}} или
                {"type": "grpc", "service_name": "..."}
    tls:        {"enabled": True, "server_name": "...",
                 "reality": {"enabled": True, "public_key": "...",
                            "short_id": "..."}, "utls": {...}}
    """
    out = {"type": "vless", "tag": tag,
           "server": server, "server_port": int(port), "uuid": uuid}
    if flow:
        out["flow"] = flow
    if transport:
        out["transport"] = transport
    if tls:
        out["tls"] = tls
    return out


def make_trojan_outbound(tag: str, server: str, port: int, password: str,
                         *, sni: str = "",
                         transport: dict = None) -> dict:
    out = {"type": "trojan", "tag": tag,
           "server": server, "server_port": int(port), "password": password}
    if sni:
        out["tls"] = {"enabled": True, "server_name": sni}
    else:
        out["tls"] = {"enabled": True, "insecure": True}
    if transport:
        out["transport"] = transport
    return out


def make_shadowsocks_outbound(tag: str, server: str, port: int,
                              method: str, password: str) -> dict:
    return {
        "type": "shadowsocks", "tag": tag,
        "server": server, "server_port": int(port),
        "method": method, "password": password,
    }


def make_hysteria2_outbound(tag: str, server: str, port: int,
                            password: str, *, sni: str = "",
                            insecure: bool = False) -> dict:
    tls_opts: dict[str, Any] = {"enabled": True}
    if sni:
        tls_opts["server_name"] = sni
    if insecure:
        tls_opts["insecure"] = True
    return {
        "type": "hysteria2", "tag": tag,
        "server": server, "server_port": int(port),
        "password": password,
        "tls": tls_opts,
    }


def make_tuic_outbound(tag: str, server: str, port: int,
                       uuid: str, password: str = "",
                       *, sni: str = "") -> dict:
    out = {
        "type": "tuic", "tag": tag,
        "server": server, "server_port": int(port),
        "uuid": uuid,
    }
    if password:
        out["password"] = password
    out["tls"] = {"enabled": True}
    if sni:
        out["tls"]["server_name"] = sni
    return out


def make_selector_outbound(tag: str, outbounds: list,
                           default: str = "") -> dict:
    """
    `selector` — переключатель между outbound'ами «вручную».

    Используется когда у пользователя несколько серверов и он хочет
    переключаться между ними через UI/clash-api. Sing-box на старте
    выбирает `default` (или первый, если не указано).
    """
    if not tag or not outbounds:
        raise ValueError("selector: нужен tag и непустой outbounds")
    out = {
        "type": "selector",
        "tag":  tag,
        "outbounds": list(outbounds),
    }
    if default and default in outbounds:
        out["default"] = default
    else:
        out["default"] = outbounds[0]
    return out


def make_urltest_outbound(tag: str, outbounds: list,
                          *, url: str = "https://www.gstatic.com/generate_204",
                          interval: str = "3m",
                          tolerance: int = 50) -> dict:
    """
    `urltest` — автоматический выбор самого быстрого outbound'а
    по latency-пробе.

      url       — HTTP-пробник (должен отдать 204/200; default Google).
      interval  — как часто перепробовать (sing-box-формат: '30s', '3m').
      tolerance — миллисекунды; не переключаемся, если разница меньше.
    """
    if not tag or not outbounds:
        raise ValueError("urltest: нужен tag и непустой outbounds")
    return {
        "type":      "urltest",
        "tag":       tag,
        "outbounds": list(outbounds),
        "url":       url,
        "interval":  interval,
        "tolerance": int(tolerance),
    }


def list_user_outbound_tags(cfg: dict) -> list:
    """
    Достать tag'и всех «реальных» outbound'ов конфига — то есть
    тех, через которые ходит трафик, исключая служебные direct/block/
    dns и сами selector/urltest.

    Используется UI «обернуть в selector»: показывает пользователю
    набор для выбора.
    """
    if not isinstance(cfg, dict):
        return []
    out = []
    for ob in (cfg.get("outbounds") or []):
        if not isinstance(ob, dict):
            continue
        t = ob.get("type")
        tag = ob.get("tag")
        if not tag or not t:
            continue
        if t in ("direct", "block", "dns", "selector", "urltest"):
            continue
        out.append(tag)
    return out


def wrap_in_group(cfg: dict, group_tag: str, group_type: str,
                  *, route_through: bool = True,
                  default: str = "",
                  url: str = "https://www.gstatic.com/generate_204",
                  interval: str = "3m") -> dict:
    """
    Обернуть все «реальные» outbound'ы конфига в group-outbound
    (selector или urltest) и перенаправить через него route.

    cfg          — sing-box-конфиг (модифицируется и возвращается)
    group_tag    — tag нового group-outbound'а
    group_type   — 'selector' | 'urltest'
    route_through=True → меняем route.rules[*].outbound на group_tag,
                         если они ссылались на старый default.

    Возвращает изменённый cfg.
    """
    if group_type not in ("selector", "urltest"):
        raise ValueError("group_type должен быть selector или urltest")
    tags = list_user_outbound_tags(cfg)
    if not tags:
        raise ValueError("В конфиге нет outbound'ов для обёртки")
    if group_tag in tags:
        raise ValueError("Tag '%s' уже занят реальным outbound'ом"
                         % group_tag)

    if group_type == "selector":
        group = make_selector_outbound(group_tag, tags, default=default)
    else:
        group = make_urltest_outbound(group_tag, tags,
                                       url=url, interval=interval)

    # Положим новый group первым, чтобы он был «более заметен» в JSON.
    # Сохраняем существующие direct/block/etc.
    obs = cfg.setdefault("outbounds", [])
    obs.insert(0, group)

    if route_through:
        route = cfg.setdefault("route", {})
        rules = route.setdefault("rules", [])
        old_targets = set(tags)
        for r in rules:
            if isinstance(r, dict) and r.get("outbound") in old_targets:
                r["outbound"] = group_tag
        # final тоже перенаправим, если он указывал на один из обёрнутых
        if route.get("final") in old_targets:
            route["final"] = group_tag
    return cfg
