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

import base64
import binascii
import json
import re
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
            # NB: спец-outbound {"type":"block"} здесь НЕ добавляем — он
            # deprecated с 1.11 и УДАЛЁН в sing-box 1.13 (заменён route-
            # action "reject"); неиспользуемый block ронял конфиг на 1.13.
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

def make_transparent_inbounds(*, mode: str = "tproxy",
                              tcp_port: int = 1100,
                              udp_port: int = 1102,
                              dns_port: int = 0,
                              sniff: bool = True,
                              mark: int = 1) -> list:
    """
    Сгенерить inbound'ы движка под прозрачное проксирование (см.
    core/singbox_transparent.py — firewall-часть).

      mode='redirect' → один `redirect` inbound (TCP) на tcp_port.
      mode='tproxy'   → один `tproxy` inbound (TCP+UDP) на tcp_port.
      mode='hybrid'   → `redirect` (TCP, tcp_port) + `tproxy` (UDP,
                        udp_port). Два inbound'а.

    Сниффинг (определение домена из TLS/HTTP/QUIC, нужно чтобы доменные/
    geosite route-правила работали для прозрачного трафика) больше НЕ
    задаётся полем inbound'а: sing-box 1.11 объявил поля `sniff`/
    `sniff_override_destination` устаревшими, а 1.13 их УДАЛИЛ — конфиг с
    ними падает с FATAL «legacy inbound fields … removed in sing-box
    1.13.0». Теперь это route-правило `{"action": "sniff"}`, которое
    добавляет set_transparent_inbounds()/make_sniff_rule(). Параметр
    `sniff` здесь оставлен для обратной совместимости и не влияет на
    inbound'ы.

    dns_port>0 добавит `direct`-inbound-слушатель на dns_port, куда
    firewall заворачивает DNS (:53) LAN-клиентов. Сам перехват на
    резолвер движка делает route-правило hijack-dns (его добавляет
    set_transparent_inbounds), а не сам inbound.
    """
    inbounds = []
    if mode in ("redirect", "hybrid"):
        inbounds.append({"type": "redirect", "tag": "redirect-in",
                         "listen": "::", "listen_port": int(tcp_port)})
    if mode in ("tproxy", "hybrid"):
        port = int(udp_port) if mode == "hybrid" else int(tcp_port)
        ib = {"type": "tproxy", "tag": "tproxy-in",
              "listen": "::", "listen_port": port}
        if mode == "hybrid":
            ib["network"] = "udp"
        inbounds.append(ib)
    if dns_port:
        inbounds.append({"type": "direct", "tag": "dns-in",
                         "listen": "::", "listen_port": int(dns_port),
                         "network": "udp"})
    return inbounds


_TRANSPARENT_TAGS = {"redirect-in", "tproxy-in", "dns-in"}


def make_sniff_rule() -> dict:
    """
    Route-правило сниффинга (sing-box 1.11+) — замена удалённого в 1.13
    legacy-поля inbound'а `sniff`. Не-терминальное действие: определяет
    домен (TLS/HTTP/QUIC) и продолжает обработку правил, чтобы доменные/
    geosite-правила срабатывали для прозрачного трафика.
    """
    return {"action": "sniff"}


def make_hijack_dns_rule() -> dict:
    """
    Route-правило перехвата DNS (sing-box 1.11+) — замена удалённого в
    1.13 спец-outbound'а `dns` (`{"protocol":"dns","outbound":"dns"}`).
    Ловит соединения, определённые как DNS, и отдаёт их встроенному
    резолверу движка (секция `dns`). Требует предшествующего
    `{"action":"sniff"}` — иначе протокол DNS не будет распознан.
    """
    return {"protocol": "dns", "action": "hijack-dns"}


def set_transparent_inbounds(cfg: dict, *, mode: str = "tproxy",
                             tcp_port: int = 1100, udp_port: int = 1102,
                             dns_port: int = 0, sniff: bool = True,
                             mark: int = 1) -> dict:
    """
    Вставить/заменить наши transparent-inbound'ы в конфиге (cfg
    модифицируется и возвращается). Прежние наши inbound'ы
    (redirect-in/tproxy-in/dns-in) убираются, пользовательские —
    сохраняются. Чистая функция (без I/O), удобно тестировать.

    sniff=True добавляет route-правило `{"action": "sniff"}` (sing-box
    1.11+; legacy inbound-поле `sniff` удалено в 1.13). dns_port>0
    дополнительно добавляет `{"protocol":"dns","action":"hijack-dns"}`
    (перехват DNS на резолвер движка вместо удалённого спец-outbound'а
    `dns`); поскольку hijack-dns требует определения протокола, sniff при
    этом включается принудительно. Идемпотентно: наши прежние правила
    снимаются перед повторной вставкой, порядок — sniff, затем hijack-dns,
    затем пользовательские правила.

    mark>0 выставляет `route.default_mark` — движок помечает СВОИ
    исходящие сокеты этим fwmark'ом, а firewall-перехват (OUTPUT при
    proxy_self / локальном режиме scope='self') исключает их по
    mark-RETURN. Без этого соединения sing-box к серверам завернулись бы
    в его же inbound — петля. Требует CAP_NET_ADMIN (движок у нас
    запускается от root). Поле валидно во всех поддерживаемых версиях
    (1.8–1.14, не deprecated).
    """
    existing = [ib for ib in (cfg.get("inbounds") or [])
                if not (isinstance(ib, dict)
                        and ib.get("tag") in _TRANSPARENT_TAGS)]
    new_ibs = make_transparent_inbounds(
        mode=mode, tcp_port=tcp_port, udp_port=udp_port,
        dns_port=dns_port, sniff=sniff)
    cfg["inbounds"] = new_ibs + existing
    # Сниффинг и перехват DNS — через route actions (а не legacy-поля
    # inbound'а / спец-outbound `dns`, удалённые в sing-box 1.13).
    _set_managed_route_rules(cfg, sniff=sniff, hijack_dns=bool(dns_port))
    if mark:
        cfg.setdefault("route", {})["default_mark"] = int(mark)
    return cfg


def _set_managed_route_rules(cfg: dict, *, sniff: bool,
                             hijack_dns: bool) -> None:
    """
    Идемпотентно выставить наши служебные route actions в начало
    `route.rules`: сначала `{"action":"sniff"}`, затем
    `{"protocol":"dns","action":"hijack-dns"}`. Прежние наши правила
    (точные совпадения) снимаются, пользовательские — сохраняются.
    hijack_dns требует определения протокола, поэтому включает sniff.
    """
    route = cfg.setdefault("route", {})
    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []
    sniff_rule = make_sniff_rule()
    dns_rule = make_hijack_dns_rule()
    rules = [r for r in rules if r != sniff_rule and r != dns_rule]
    managed = []
    if sniff or hijack_dns:
        managed.append(sniff_rule)
    if hijack_dns:
        managed.append(dns_rule)
    route["rules"] = managed + rules


_TUN_TAG = "tun-in"


def make_tun_inbound(*, interface_name: str = "singbox-tun",
                     address=None, mtu: int = 1500,
                     stack: str = "system",
                     auto_route: bool = False,
                     strict_route: bool = False,
                     auto_redirect: bool = False) -> dict:
    """
    Собрать TUN-inbound sing-box (создаёт сетевой интерфейс
    `interface_name`). Используются ТОЛЬКО актуальные поля 1.11+/1.13:
    `address` (а не удалённые `inet4_address`/`inet6_address`).

    auto_route=False (по умолчанию) — sing-box НЕ забирает маршрут по
    умолчанию: интерфейс просто создаётся, а какой трафик в него
    заворачивать, решает страница «Selective routing» (ip rule/nftset).
    Для режима «весь трафик» выставьте auto_route=True.

    auto_redirect=True (только вместе с auto_route и на nftables-платформах,
    sing-box 1.10+) — sing-box сам ставит nftables-redirect, чтобы забирать
    и ПЕРЕСЫЛАЕМЫЙ трафик LAN-клиентов (нужно для FakeIP-роутинга без ручной
    правки firewall). На iptables-only платформах не включаем.

    stack: 'system' (быстрее, нужен модуль tun ядра — на Keenetic есть),
           'gvisor' (userspace, переносимее) или 'mixed'.

    mtu по умолчанию 1500 (а не 9000): для туннеля поверх прокси
    (hysteria2/…) большой MTU бессмысленен (реальный путь ~1400), а с
    gvisor-стеком 9000 раздувает буферы и на роутере с малым ОЗУ приводит к
    GC-молотьбе и 100% CPU.
    """
    ib = {
        "type": "tun",
        "tag": _TUN_TAG,
        "interface_name": interface_name or "singbox-tun",
        "address": list(address) if address else ["172.18.0.1/30"],
        "mtu": int(mtu) if mtu else 1500,
        "auto_route": bool(auto_route),
        "strict_route": bool(strict_route),
        "stack": stack or "system",
    }
    if auto_redirect and auto_route:
        ib["auto_redirect"] = True
    return ib


def set_tun_inbound(cfg: dict, *, interface_name: str = "singbox-tun",
                    address=None, mtu: int = 1500, stack: str = "gvisor",
                    auto_route: bool = False, strict_route: bool = False,
                    sniff: bool = True, route_to_proxy: bool = True,
                    hijack_dns: bool = False, typed_dns: bool = False,
                    reject_quic: bool = False) -> dict:
    """
    Вставить/заменить TUN-inbound в конфиге (cfg мутируется и
    возвращается). Прежний наш `tun-in` убирается, остальные inbound'ы
    сохраняются. Чистая функция (без I/O).

    stack='gvisor' (НЕ 'system') — критично для выборочной маршрутизации:
    при auto_route=False трафик в TUN заворачивают НАШИ `ip rule`, а
    системный стек sing-box БЕЗ auto_route не перехватывает TCP-соединения
    (UDP/DNS при этом работают) → «сайты не открываются, хотя прокси живой».
    gvisor читает все пакеты из TUN сам, поэтому TCP+UDP работают независимо
    от auto_route.

    После этого конфиг можно запустить — интерфейс `interface_name`
    появится в системе и в «Selective routing» (как цель device/domain/
    cidr-правил). sniff=True добавляет `{"action":"sniff"}` (чтобы
    доменные route-правила Selective routing срабатывали).
    route_to_proxy=True направляет весь попавший в TUN трафик в основной
    прокси-outbound конфига (route.final → selector/первый сервер).

    hijack_dns=True (нужно для маршрутизации УСТРОЙСТВА целиком) — добавляет
    перехват DNS (`{"protocol":"dns","action":"hijack-dns"}`) и DNS-секцию с
    локальным резолвером. Без этого у устройства, чей трафик целиком завёрнут
    в TUN, DNS-запросы (UDP:53) уходят в туннель, но движок их не обрабатывает
    → имена не резолвятся → «интернета нет», хотя прокси живой. Резолвим через
    `local` (резолвер роутера): имена открываются, а трафик к полученным IP всё
    равно идёт в прокси; bootstrap-петли (резолв самого прокси-сервера) нет.
    Приватные адреса (LAN) пускаем мимо прокси (`ip_is_private → direct`).
    typed_dns=True — DNS-секция в формате sing-box 1.12+ (иначе legacy).
    """
    existing = [ib for ib in (cfg.get("inbounds") or [])
                if not (isinstance(ib, dict) and ib.get("tag") == _TUN_TAG)]
    tun = make_tun_inbound(
        interface_name=interface_name, address=address, mtu=mtu,
        stack=stack, auto_route=auto_route, strict_route=strict_route)
    cfg["inbounds"] = [tun] + existing
    _set_managed_route_rules(cfg, sniff=(sniff or hijack_dns),
                             hijack_dns=hijack_dns)
    if route_to_proxy:
        proxy = pick_proxy_outbound(cfg)
        if proxy:
            cfg.setdefault("route", {})["final"] = proxy
    if hijack_dns:
        # DNS перехваченных запросов резолвим ЧЕРЕЗ прокси (DoH поверх
        # прокси-outbound) — чистый ответ без DNS-подмены DPI/провайдера.
        # Иначе блокируемые домены резолвятся в подменённые IP и сайты не
        # открываются, хотя прокси живой. Домены самих прокси-серверов —
        # напрямую (local), чтобы не было петли (резолв сервера через сам
        # же прокси).
        proxy_tag = pick_proxy_outbound(cfg) or "proxy-out"
        cfg["dns"] = make_routing_dns(
            proxy_tag=proxy_tag,
            proxy_server_domains=collect_proxy_server_domains(cfg),
            typed=typed_dns)
        _ensure_private_direct_rule(cfg)
        # QUIC-reject опционален и ВЫКЛ по умолчанию: глушение UDP/443 ломает
        # DNS-over-QUIC (DoH3) клиента, если он не откатывается на TCP/plain —
        # тогда имена вообще не резолвятся. Включать стоит, только если QUIC
        # через прокси реально не ходит (тогда браузер уйдёт на TCP).
        if reject_quic:
            _ensure_quic_reject_rule(cfg)
        else:
            remove_route_rule(
                cfg, {"network": "udp", "port": 443, "action": "reject"})
    return cfg


def _insert_after_managed(cfg: dict, rule: dict) -> None:
    """
    Идемпотентно вставить route-правило сразу ПОСЛЕ служебных
    (sniff/hijack-dns, которые _set_managed_route_rules держит в начале),
    но ПЕРЕД доменными/final. Дубликат не плодим.
    """
    route = cfg.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
        route["rules"] = rules
    if rule in rules:
        return
    insert_at = 0
    for i, r in enumerate(rules):
        if isinstance(r, dict) and r.get("action") in ("sniff", "hijack-dns"):
            insert_at = i + 1
    rules.insert(insert_at, rule)


def _ensure_private_direct_rule(cfg: dict) -> None:
    """
    Гарантировать правило «приватные адреса (LAN/loopback) → direct» и
    наличие самого `direct`-outbound'а. Чтобы устройство, целиком
    завёрнутое в TUN, ходило в локальную сеть (роутер, принтеры, NAS)
    напрямую, а не через прокси.
    """
    outs = cfg.setdefault("outbounds", [])
    if not any(isinstance(o, dict) and o.get("type") == "direct" for o in outs):
        outs.append({"type": "direct", "tag": "direct"})
    direct_tag = next((o.get("tag") for o in outs if isinstance(o, dict)
                       and o.get("type") == "direct"), "direct")
    _insert_after_managed(cfg, {"ip_is_private": True, "outbound": direct_tag})


def _ensure_quic_reject_rule(cfg: dict) -> None:
    """
    Глушить QUIC (UDP/443), чтобы браузеры/ОС откатывались на TCP.

    QUIC поверх прокси (hysteria2/tuic/…) часто не проходит (UDP/MTU/PMTU),
    и тогда «ничего не открывается», хотя TCP через прокси работает. Сюда же
    относится DNS-over-QUIC (DoH3): пока он висит на UDP/443, имена вообще не
    резолвятся, и даже обычный TCP-сайт не открыть (его IP неизвестен). reject
    шлёт ICMP-unreachable → клиент быстро переключается на TCP. Наш DNS (DoH
    поверх прокси) ходит по TCP, поэтому от этого правила не страдает.
    """
    _insert_after_managed(
        cfg, {"network": "udp", "port": 443, "action": "reject"})


def active_outbound_tag(cfg: dict) -> str:
    """
    Тег «активного» outbound'а, через который реально ходит трафик —
    цель для health-пробы watchdog'а:
      1) selector → его `default` (или первый член, или сам тег группы);
      2) иначе route.final, если это пользовательский outbound;
      3) иначе первый пользовательский outbound.
    '' если не нашли.
    """
    if not isinstance(cfg, dict):
        return ""
    outs = [o for o in (cfg.get("outbounds") or []) if isinstance(o, dict)]
    sel = next((o for o in outs if o.get("type") == "selector"), None)
    if sel is not None:
        members = sel.get("outbounds") or []
        return (sel.get("default") or (members[0] if members else "")
                or sel.get("tag") or "")
    user_tags = list_user_outbound_tags(cfg)
    final = ((cfg.get("route") or {}).get("final") or "")
    if final and final in user_tags:
        return final
    return user_tags[0] if user_tags else ""


def _looks_like_ip(s: str) -> bool:
    """Грубо: это IP-литерал (v4/v6), а не доменное имя?"""
    s = (s or "").strip().strip("[]")
    return bool(_IPV4_RE.match(s)) or (":" in s)


def collect_proxy_server_domains(cfg: dict) -> list:
    """
    Доменные имена `server` всех пользовательских outbound'ов (не IP).
    Нужны, чтобы резолвить их НАПРЯМУЮ (а не через прокси) и не словить
    петлю «резолв адреса прокси через сам прокси».
    """
    out = set()
    for ob in (cfg.get("outbounds") or []):
        if not isinstance(ob, dict):
            continue
        if ob.get("type") in ("direct", "block", "dns", "selector", "urltest"):
            continue
        srv = (ob.get("server") or "").strip()
        if srv and not _looks_like_ip(srv):
            out.add(srv)
    return sorted(out)


def make_routing_dns(*, proxy_tag: str = "proxy-out",
                     proxy_server_domains=None, doh_ip: str = "1.1.1.1",
                     typed: bool = False) -> dict:
    """
    DNS-секция для маршрутизации трафика через прокси.

    Клиентские запросы резолвятся ЧЕРЕЗ прокси (DoH `https://<doh_ip>/dns-query`
    поверх `proxy_tag`) — ответ чистый, без DNS-подмены DPI/провайдера (иначе
    блокируемые домены резолвятся в подменённые IP и не открываются). DoH-узел
    задаём IP-литералом (1.1.1.1) — его самого резолвить не нужно, петли нет.

    Домены самих прокси-серверов (`proxy_server_domains`) резолвятся напрямую
    (`local`) — иначе чтобы подключиться к прокси, надо было бы сперва
    зайти на прокси (петля).

    typed=False → legacy-формат (1.8–1.13), typed=True → 1.12+.
    """
    if typed:
        srv_proxy = {"tag": "dns-proxy", "type": "https", "server": doh_ip,
                     "detour": proxy_tag}
        srv_direct = {"tag": "dns-direct", "type": "local"}
    else:
        srv_proxy = {"tag": "dns-proxy",
                     "address": "https://%s/dns-query" % doh_ip,
                     "detour": proxy_tag}
        srv_direct = {"tag": "dns-direct", "address": "local"}
    rules = []
    doms = [d for d in (proxy_server_domains or [])
            if d and not _looks_like_ip(d)]
    if doms:
        rules.append({"domain": doms, "server": "dns-direct"})
    return {"servers": [srv_proxy, srv_direct], "rules": rules,
            "final": "dns-proxy"}


def build_geo_route_rule(outbound_tag: str, *, domains=None,
                         geosite=None, geoip=None) -> dict:
    """
    Собрать route-правило sing-box, отправляющее заданные селекторы в
    outbound `outbound_tag`. Используется единым слоем для geosite/geoip
    (их iptables-routing развернуть не может — это нативные концепции
    движка).

    Используем поля sing-box route rule:
      domain_suffix / geosite / geoip → outbound.
    Пустые селекторы не добавляются. Возвращает dict-правило.
    """
    rule = {}
    doms = [str(d).strip().lower() for d in (domains or []) if str(d).strip()]
    gs = [str(g).strip() for g in (geosite or []) if str(g).strip()]
    gi = [str(g).strip() for g in (geoip or []) if str(g).strip()]
    if doms:
        rule["domain_suffix"] = doms
    if gs:
        rule["geosite"] = gs
    if gi:
        rule["geoip"] = gi
    rule["outbound"] = outbound_tag
    return rule


def add_route_rule(cfg: dict, rule: dict, *, front: bool = True) -> dict:
    """Вставить route-правило в cfg (создаёт route/rules при отсутствии)."""
    route = cfg.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
        route["rules"] = rules
    if front:
        rules.insert(0, rule)
    else:
        rules.append(rule)
    return cfg


def remove_route_rule(cfg: dict, rule: dict) -> bool:
    """Удалить точное совпадение route-правила. True — если удалили."""
    route = cfg.get("route")
    if not isinstance(route, dict):
        return False
    rules = route.get("rules")
    if not isinstance(rules, list):
        return False
    before = len(rules)
    route["rules"] = [r for r in rules if r != rule]
    return len(route["rules"]) != before


def pick_proxy_outbound(cfg: dict) -> str:
    """
    Выбрать «основной» прокси-outbound конфига для маршрутизации geo:
      1) первый selector/urltest (group) — это обычно «PROXY»;
      2) иначе первый реальный outbound (не direct/block/dns).
    Возвращает tag или '' если не нашли.
    """
    obs = cfg.get("outbounds") if isinstance(cfg, dict) else None
    if not isinstance(obs, list):
        return ""
    for ob in obs:
        if isinstance(ob, dict) and ob.get("type") in ("selector", "urltest"):
            if ob.get("tag"):
                return ob["tag"]
    for ob in obs:
        if not isinstance(ob, dict):
            continue
        if ob.get("type") in ("direct", "block", "dns", "selector", "urltest"):
            continue
        if ob.get("tag"):
            return ob["tag"]
    return ""


def find_tun_interface(cfg: dict) -> str:
    """interface_name tun-inbound'а конфига (или '' если нет tun)."""
    for ib in (cfg.get("inbounds") or []):
        if isinstance(ib, dict) and ib.get("type") == "tun":
            return ib.get("interface_name") or ""
    return ""


# ─────── FakeIP-роутинг (умный доменный роутинг через движок) ───────
#
# Полный self-contained конфиг «как podkop, но мультиплатформенно»: TUN с
# auto_route + DNS с FakeIP. Клиентский DNS перехватывается движком
# (hijack-dns), домены из списка получают fake-IP (198.18.0.0/15), их трафик
# по fake-IP роутится в прокси-outbound; остальное идёт напрямую. Это решает
# проблемы ipset-пути: нет DNS-leak, работает для CDN/QUIC/ECH (роутинг по
# домену из DNS, до handshake). См. skill §13.

FAKEIP_INET4 = "198.18.0.0/15"
FAKEIP_INET6 = "fc00::/18"

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _norm_suffix_domains(domains) -> list:
    """Нормализовать домены под `domain_suffix`: lower, без схемы/www/*., без
    дублей; отбросить IP/localhost (это не суффиксы)."""
    out, seen = [], set()
    for d in (domains or []):
        s = str(d).strip().lower()
        for pre in ("https://", "http://", "//", "*.", "www."):
            if s.startswith(pre):
                s = s[len(pre):]
        s = s.split("/")[0].rstrip(".")
        if not s or s in seen:
            continue
        if s == "localhost" or _IPV4_RE.match(s) or ":" in s:
            continue
        seen.add(s)
        out.append(s)
    return out


def make_fakeip_dns(*, proxied_domains=None, direct_dns: str = "local",
                    typed: bool = False, fakeip: bool = True) -> dict:
    """
    DNS-секция для FakeIP-роутинга.

    typed=False → legacy-формат (`address`/top-level `dns.fakeip`), валиден
    sing-box 1.8–1.13 (legacy удалён в 1.14). typed=True → формат 1.12+
    (`type:`/`type:fakeip`). Оркестратор (core/singbox_fakeip) пробует один,
    при провале `sing-box check` — другой.

    direct_dns: 'local'/'' → системный резолвер (без host-поля, переносимо);
    голый IP → udp-резолвер. fakeip=False → секция без FakeIP (для режима
    «весь трафик»), только direct-сервер, чтобы hijack-dns был куда отдавать.
    """
    dd = (direct_dns or "local").strip()
    is_local = dd in ("", "local")
    is_ip = bool(_IPV4_RE.match(dd))

    if typed:
        if is_local:
            direct_srv = {"tag": "dns-direct", "type": "local"}
        elif is_ip:
            direct_srv = {"tag": "dns-direct", "type": "udp", "server": dd,
                          "detour": "direct"}
        else:                                   # https:// / tls:// и т.п.
            direct_srv = {"tag": "dns-direct", "type": "local"}
    else:
        direct_srv = {"tag": "dns-direct", "address": dd if dd else "local"}
        if not is_local:
            direct_srv["detour"] = "direct"

    servers = [direct_srv]
    rules = []
    proxied = _norm_suffix_domains(proxied_domains)

    if fakeip:
        if typed:
            servers.append({"tag": "dns-fakeip", "type": "fakeip",
                            "inet4_range": FAKEIP_INET4,
                            "inet6_range": FAKEIP_INET6})
        else:
            servers.append({"tag": "dns-fakeip", "address": "fakeip"})
        if proxied:
            rules.append({"domain_suffix": proxied, "server": "dns-fakeip"})

    # independent_cache НЕ задаём: опция deprecated в sing-box 1.14 и
    # удаляется в 1.16 (поведение по умолчанию нас устраивает) — иначе на
    # 1.14 сыплет WARN, а на 1.16 конфиг может не пройти проверку.
    dns = {"servers": servers, "rules": rules, "final": "dns-direct"}
    if fakeip and not typed:
        dns["fakeip"] = {"enabled": True,
                         "inet4_range": FAKEIP_INET4,
                         "inet6_range": FAKEIP_INET6}
    return dns


def build_fakeip_config(*, proxy_outbound: dict,
                        proxied_domains=None, proxied_cidrs=None,
                        route_all: bool = False,
                        direct_dns: str = "local",
                        tun_iface: str = "singbox-tun",
                        tun_address=None, mtu: int = 1500,
                        stack: str = "system",
                        auto_redirect: bool = False,
                        typed_dns: bool = False,
                        capture_dns: bool = False,
                        dns_port: int = 1153) -> dict:
    """
    Собрать полный sing-box-конфиг FakeIP-роутинга.

    proxy_outbound — готовый dict outbound'а (vless/ss/...); его тег
    принудительно = 'proxy-out'. route_all=True → весь трафик в прокси
    (FakeIP не нужен, DNS прямой). Иначе — выбранные домены/подсети в прокси,
    остальное напрямую, домены через FakeIP.
    """
    if not isinstance(proxy_outbound, dict) or not proxy_outbound.get("type"):
        raise ValueError("proxy_outbound должен быть dict с полем type")

    proxied = _norm_suffix_domains(proxied_domains)
    cidrs = [str(c).strip() for c in (proxied_cidrs or []) if str(c).strip()]
    fakeip_on = (not route_all) and bool(proxied)

    proxy_ob = dict(proxy_outbound)
    proxy_ob["tag"] = "proxy-out"

    tun = make_tun_inbound(interface_name=tun_iface, address=tun_address,
                           mtu=mtu, stack=stack, auto_route=True,
                           strict_route=True, auto_redirect=auto_redirect)
    inbounds = [tun]
    if capture_dns:
        # DNS-inbound для перехвата :53 LAN-клиентов (firewall REDIRECT :53 →
        # dns_port); сам перехват ловит route-правило hijack-dns. Нужен на
        # iptables-платформах (Keenetic), где auto_redirect недоступен.
        inbounds.append({"type": "direct", "tag": "dns-in",
                         "listen": "::", "listen_port": int(dns_port)})

    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    if not route_all:
        if proxied:
            rules.append({"domain_suffix": proxied, "outbound": "proxy-out"})
        if cidrs:
            rules.append({"ip_cidr": cidrs, "outbound": "proxy-out"})

    route = {
        "rules": rules,
        "final": "proxy-out" if route_all else "direct",
        "auto_detect_interface": True,
    }
    # sing-box 1.12+ требует явный резолвер для доменов в dial-полях (адрес
    # прокси-сервера); на 1.14 без него — FATAL. Резолвим их через dns-direct
    # (local), без петли. Только для typed-формата: поле появилось в 1.12, на
    # старых движках (legacy-DNS) его быть не должно.
    if typed_dns:
        route["default_domain_resolver"] = {"server": "dns-direct"}

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": make_fakeip_dns(proxied_domains=proxied, direct_dns=direct_dns,
                               typed=typed_dns, fakeip=fakeip_on),
        "inbounds": inbounds,
        "outbounds": [proxy_ob, {"type": "direct", "tag": "direct"}],
        "route": route,
        "experimental": {
            "cache_file": {"enabled": True, "store_fakeip": fakeip_on,
                           "path": "cache.db"},
        },
    }


def _norm_src_cidr(s: str) -> str:
    """IP без маски → /32 (v4) или /128 (v6); CIDR — как есть."""
    s = (s or "").strip()
    if not s or "/" in s:
        return s
    return s + ("/128" if ":" in s else "/32")


def build_system_route_config(*, proxy_outbound: dict, source_ips=None,
                              route_all: bool = False,
                              tun_iface: str = "singbox-tun",
                              tun_address=None, mtu: int = 1500,
                              typed_dns: bool = False,
                              reject_quic: bool = False,
                              auto_redirect: bool = False,
                              doh_ip: str = "1.1.1.1") -> dict:
    """
    Конфиг маршрутизации на KERNEL-стеке (low-CPU, без gvisor):

      TUN(auto_route=true, stack="system") — sing-box сам забирает трафик
      через системный сетевой стек ядра (намного легче gvisor на слабом
      MIPS), а кого слать в прокси решают ВНУТРЕННИЕ route-правила движка:
        - route_all=True  → весь трафик → proxy-out (final);
        - иначе           → только source_ip_cidr выбранных устройств →
                            proxy-out, остальное → direct (final).

    DNS перехватывается (hijack-dns) и резолвится через прокси (DoH) — как в
    остальных режимах. Приватные адреса (LAN) — мимо прокси. strict_route НЕ
    включаем (чтобы случайно не «залочить» роутер), auto_detect_interface для
    direct-выхода — чтобы не было петли через сам TUN.

    ⚠️ Экспериментально на Keenetic: auto_route ставит свои ip rule/route, что
    может конфликтовать с NDM; на iptables-Keenetic перехват ПЕРЕСЫЛАЕМОГО
    трафика LAN-клиентов через auto_route не гарантирован (для nft есть
    auto_redirect). Откат — простой `down` инстанса (auto_route снимается).
    """
    if not isinstance(proxy_outbound, dict) or not proxy_outbound.get("type"):
        raise ValueError("proxy_outbound должен быть dict с полем type")

    proxy_ob = dict(proxy_outbound)
    proxy_ob["tag"] = "proxy-out"
    srcs = [_norm_src_cidr(s) for s in (source_ips or []) if str(s).strip()]
    selective = (not route_all) and bool(srcs)

    tun = make_tun_inbound(interface_name=tun_iface, address=tun_address,
                           mtu=mtu, stack="system", auto_route=True,
                           strict_route=False, auto_redirect=auto_redirect)

    srv = (proxy_ob.get("server") or "").strip()
    proxy_doms = [srv] if (srv and not _looks_like_ip(srv)) else []

    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    if reject_quic:
        rules.append({"network": "udp", "port": 443, "action": "reject"})
    if selective:
        rules.append({"source_ip_cidr": srcs, "outbound": "proxy-out"})

    route = {
        "rules": rules,
        "final": "proxy-out" if route_all else "direct",
        "auto_detect_interface": True,
    }
    if typed_dns:
        route["default_domain_resolver"] = {"server": "dns-direct"}

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": make_routing_dns(proxy_tag="proxy-out",
                                proxy_server_domains=proxy_doms,
                                doh_ip=doh_ip, typed=typed_dns),
        "inbounds": [tun],
        "outbounds": [proxy_ob, {"type": "direct", "tag": "direct"}],
        "route": route,
        "experimental": {"cache_file": {"enabled": True, "path": "cache.db"}},
    }
# Любой другой роняет ВЕСЬ процесс на initialize («unsupported flow: …»).
# Xray-вариант 'xtls-rprx-vision-udp443' (vision + пропуск UDP/443)
# для sing-box эквивалентен vision — нормализуем. Легаси-flow
# (xtls-rprx-origin/direct/splice[-udp443]) sing-box не умеет вовсе —
# такие серверы из публичных списков надо отбрасывать.
VLESS_SUPPORTED_FLOW = "xtls-rprx-vision"


def normalize_vless_flow(flow) -> str:
    """'xtls-rprx-vision-udp443' → 'xtls-rprx-vision'; прочее — как есть."""
    f = str(flow or "").strip()
    if f == VLESS_SUPPORTED_FLOW + "-udp443":
        return VLESS_SUPPORTED_FLOW
    return f


def vless_flow_supported(flow) -> bool:
    """Пройдёт ли flow (после нормализации) через sing-box."""
    return normalize_vless_flow(flow) in ("", VLESS_SUPPORTED_FLOW)


def make_vless_outbound(tag: str, server: str, port: int, uuid: str,
                        *, flow: str = "",
                        transport: dict = None,
                        tls: dict = None) -> dict:
    """
    Собрать VLESS-outbound dict. Минимум: server, port, uuid.

    flow:       часто 'xtls-rprx-vision' для Reality
                ('…-udp443' нормализуется, см. normalize_vless_flow)
    transport:  {"type": "ws", "path": "/", "headers": {...}} или
                {"type": "grpc", "service_name": "..."}
    tls:        {"enabled": True, "server_name": "...",
                 "reality": {"enabled": True, "public_key": "...",
                            "short_id": "..."}, "utls": {...}}
    """
    out = {"type": "vless", "tag": tag,
           "server": server, "server_port": int(port), "uuid": uuid}
    flow = normalize_vless_flow(flow)
    if flow:
        out["flow"] = flow
    if transport:
        out["transport"] = transport
    if tls:
        out["tls"] = tls
    return out


def make_vmess_outbound(tag: str, server: str, port: int, uuid: str,
                        *, security: str = "auto", alter_id: int = 0,
                        transport: dict = None, tls: dict = None) -> dict:
    """
    Собрать VMess-outbound dict. Минимум: server, port, uuid.

    security:   шифр VMess ('auto' / 'aes-128-gcm' / 'chacha20-poly1305' /
                'none' / 'zero'); из vmess-URI поле `scy`.
    alter_id:   legacy alterId (обычно 0 для VMess AEAD).
    transport:  как у vless — {"type": "ws"/"grpc"/"http", ...}.
    tls:        {"enabled": True, "server_name": "...", "utls": {...}}.
    """
    out = {"type": "vmess", "tag": tag,
           "server": server, "server_port": int(port), "uuid": uuid,
           "security": security or "auto", "alter_id": int(alter_id or 0)}
    if transport:
        out["transport"] = transport
    if tls:
        out["tls"] = tls
    return out


def make_trojan_outbound(tag: str, server: str, port: int, password: str,
                         *, sni: str = "", insecure: bool = False,
                         alpn=None, fp: str = "",
                         transport: dict = None) -> dict:
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    # allowInsecure=1 (self-signed сертификат) обязателен, иначе TLS-рукопожатие
    # падает. Без SNI — почти всегда self-signed/raw, тоже пропускаем проверку
    # (историческое поведение).
    if insecure or not sni:
        tls["insecure"] = True
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    alpn_list = [a for a in (alpn or []) if a]
    if alpn_list:
        tls["alpn"] = alpn_list
    out = {"type": "trojan", "tag": tag,
           "server": server, "server_port": int(port), "password": password,
           "tls": tls}
    if transport:
        out["transport"] = transport
    return out


def make_shadowsocks_outbound(tag: str, server: str, port: int,
                              method: str, password: str,
                              *, plugin: str = "",
                              plugin_opts: str = "") -> dict:
    out = {
        "type": "shadowsocks", "tag": tag,
        "server": server, "server_port": int(port),
        "method": normalize_ss_method(method) or method,
        "password": password,
    }
    # SIP003-плагин (obfs-local / v2ray-plugin): сервер с плагином НЕ примет
    # «голый» Shadowsocks — без plugin/plugin_opts соединение установится по
    # TCP, но прокси работать не будет (рукопожатие плагина не пройдёт).
    if plugin:
        out["plugin"] = plugin
        if plugin_opts:
            out["plugin_opts"] = plugin_opts
    return out


# Методы Shadowsocks, которые принимает sing-box (только AEAD + 2022).
# Легаси stream-шифры (aes-256-cfb, rc4-md5, chacha20 и т.п.) sing-box
# НЕ поддерживает — такие серверы из публичных списков надо отбрасывать,
# иначе один такой outbound валит весь конфиг («unknown method: …»).
SS_SUPPORTED_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
}

# Часто встречающиеся в подписках алиасы → канонические имена sing-box.
_SS_METHOD_ALIASES = {
    "chacha20-poly1305":   "chacha20-ietf-poly1305",
    "xchacha20-poly1305":  "xchacha20-ietf-poly1305",
    "chacha20-ietf":       "chacha20-ietf-poly1305",
}


def normalize_ss_method(method: str) -> str:
    """
    Привести имя SS-шифра к тому, что понимает sing-box. Возвращает
    канонический метод или '' если шифр не поддерживается (легаси stream).
    """
    m = (method or "").strip().lower()
    m = _SS_METHOD_ALIASES.get(m, m)
    return m if m in SS_SUPPORTED_METHODS else ""


def make_hysteria2_outbound(tag: str, server: str, port: int,
                            password: str, *, sni: str = "",
                            insecure: bool = False,
                            obfs_password: str = "",
                            obfs_type: str = "salamander") -> dict:
    tls_opts: dict[str, Any] = {"enabled": True}
    if sni:
        tls_opts["server_name"] = sni
    if insecure:
        tls_opts["insecure"] = True
    out = {
        "type": "hysteria2", "tag": tag,
        "server": server, "server_port": int(port),
        "password": password,
        "tls": tls_opts,
    }
    # Salamander-обфускация: сервер с `obfs=salamander` НЕ примет соединение
    # без совпадающего obfs-пароля (QUIC-рукопожатие не пройдёт — «ничего не
    # открывается, хотя порт жив»). sing-box поддерживает только salamander.
    if obfs_password:
        out["obfs"] = {"type": (obfs_type or "salamander"),
                       "password": obfs_password}
    return out


def make_tuic_outbound(tag: str, server: str, port: int,
                       uuid: str, password: str = "",
                       *, sni: str = "", alpn=None, insecure: bool = False,
                       congestion_control: str = "",
                       udp_relay_mode: str = "") -> dict:
    out = {
        "type": "tuic", "tag": tag,
        "server": server, "server_port": int(port),
        "uuid": uuid,
    }
    if password:
        out["password"] = password
    # congestion_control / udp_relay_mode часто заданы в ссылке и должны
    # совпадать с сервером (иначе UDP-релей не работает или режется скорость).
    if congestion_control:
        out["congestion_control"] = congestion_control
    if udp_relay_mode:
        out["udp_relay_mode"] = udp_relay_mode
    tls: dict[str, Any] = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if insecure:
        tls["insecure"] = True
    # TUIC поверх QUIC обычно требует ALPN h3 — без него многие серверы рвут
    # рукопожатие («connection refused»/timeout, хотя UDP-порт открыт).
    alpn_list = [a for a in (alpn or []) if a]
    if alpn_list:
        tls["alpn"] = alpn_list
    out["tls"] = tls
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


# ─────── clash_api (для учёта трафика per-outbound) ───────
#
# Чтобы считать, сколько трафика прокачано через каждый сервер, нам
# нужен локальный Clash API у ЗАПУЩЕННОГО инстанса: трекер опрашивает
# `GET /connections` и агрегирует upload/download по тегу outbound'а
# (см. core/proxy_traffic.py). Эти helper'ы умеют добавить clash_api в
# конфиг идемпотентно и вытащить endpoint обратно.

def make_clash_api(port: int, secret: str = "",
                   host: str = "127.0.0.1") -> dict:
    """Секция `experimental.clash_api` со слушателем только на localhost."""
    block = {"external_controller": "%s:%d" % (host, int(port))}
    if secret:
        block["secret"] = secret
    return block


def ensure_clash_api(cfg: dict, *, port: int, secret: str = "",
                     host: str = "127.0.0.1") -> tuple:
    """
    Добавить `experimental.clash_api`, если его ещё нет. Существующий
    НЕ трогаем (у пользователя мог быть свой). Возвращает (cfg, changed).
    """
    if not isinstance(cfg, dict):
        raise ValueError("cfg должен быть dict")
    exp = cfg.setdefault("experimental", {})
    if not isinstance(exp, dict):
        raise ValueError("experimental — не объект")
    if isinstance(exp.get("clash_api"), dict) and \
            exp["clash_api"].get("external_controller"):
        return cfg, False
    exp["clash_api"] = make_clash_api(port, secret, host)
    return cfg, True


def is_x25519_key(s: Any) -> bool:
    """
    True, если строка — валидный 32-байтный ключ curve25519/x25519, как
    того требует sing-box для `tls.reality.public_key` и wireguard-ключей.

    sing-box декодирует reality public_key как 32 байта и иначе падает на
    старте с FATAL «invalid public_key». Принимаем base64 (url-safe и
    обычный, с паддингом и без) и hex(64) — лишь бы декодировалось ровно в
    32 байта. Чистая функция, без сети и без бинаря.
    """
    if not isinstance(s, str):
        return False
    s = s.strip()
    if not s:
        return False
    if len(s) == 64:                       # hex
        try:
            return len(bytes.fromhex(s)) == 32
        except ValueError:
            pass
    pad = "=" * (-len(s) % 4)               # base64 (любой вариант)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            if len(dec(s + pad)) == 32:
                return True
        except (ValueError, binascii.Error):
            continue
    return False


def outbound_key_problem(ob: dict):
    """
    Если sing-box заведомо отвергнет outbound на этапе initialize из-за
    криптоключа — вернуть человекочитаемую причину, иначе None.

    Покрывает частые случаи из публичных пулов, которые роняют ВЕСЬ
    процесс sing-box (всё-или-ничего):
      - reality без public_key (ссылка без `pbk`) → пустой ключ;
      - reality с битым/обрезанным public_key;
      - wireguard с некорректным peer public_key;
      - vless с flow, который sing-box не принимает («unsupported flow»).
        Нормализуемый '…-vision-udp443' проблемой НЕ считается — его
        чинят normalize_vless_flow на этапах импорта/теста.
    """
    if not isinstance(ob, dict):
        return None
    if ob.get("type") == "vless" and not vless_flow_supported(ob.get("flow")):
        return "vless: flow '%s' не поддерживается sing-box" % ob.get("flow")
    tls = ob.get("tls") or {}
    reality = (tls.get("reality") or {}) if isinstance(tls, dict) else {}
    if isinstance(reality, dict) and reality.get("enabled"):
        pk = reality.get("public_key") or ""
        if not str(pk).strip():
            return "reality: пустой public_key (нет pbk в ссылке)"
        if not is_x25519_key(pk):
            return "reality: некорректный public_key"
    if ob.get("type") == "wireguard":
        keys = []
        if ob.get("peer_public_key"):
            keys.append(ob["peer_public_key"])
        for p in (ob.get("peers") or []):
            if isinstance(p, dict) and p.get("public_key"):
                keys.append(p["public_key"])
        for k in keys:
            if not is_x25519_key(k):
                return "wireguard: некорректный public_key"
    return None


def plan_activation(cfg: dict, tag: str) -> dict:
    """
    Подготовить конфиг к «пустить трафик через сервер <tag>» (мутирует cfg).

    Логика (как активация профиля в Throne):
      - если есть selector (приоритет — содержащий tag) → делаем tag его
        default'ом, добавляя его в outbounds при необходимости. Режим
        'selector' + флаг already_member (был ли tag уже в группе — от
        этого зависит, можно ли переключить вживую без рестарта);
      - иначе → route.final = tag. Режим 'route'.

    Возвращает {"ok", "mode", "selector"?, "already_member"?} либо
    {"ok": False, "error"} если tag не найден среди outbound'ов.
    """
    obs = cfg.get("outbounds") or []
    if tag not in {o.get("tag") for o in obs if isinstance(o, dict)}:
        return {"ok": False, "error": "Сервер '%s' не в конфиге" % tag}

    selectors = [o for o in obs if isinstance(o, dict)
                 and o.get("type") == "selector"]
    sel = next((s for s in selectors
                if tag in (s.get("outbounds") or [])), None) \
        or (selectors[0] if selectors else None)

    if sel is not None:
        inner = sel.setdefault("outbounds", [])
        already_member = tag in inner
        if not already_member:
            inner.append(tag)
        sel["default"] = tag
        return {"ok": True, "mode": "selector", "selector": sel.get("tag"),
                "already_member": already_member}

    route = cfg.setdefault("route", {})
    route["final"] = tag
    return {"ok": True, "mode": "route"}


def clash_api_endpoint(cfg: dict) -> dict:
    """
    Вытащить endpoint Clash API из конфига:
      {"host","port","secret"} либо None, если clash_api не настроен.
    """
    if not isinstance(cfg, dict):
        return None
    api = ((cfg.get("experimental") or {}).get("clash_api") or {})
    ctrl = api.get("external_controller")
    if not ctrl or ":" not in str(ctrl):
        return None
    host, _, port = str(ctrl).rpartition(":")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    # `0.0.0.0` / пусто → опрашиваем через loopback.
    if not host or host in ("0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    host = host.strip("[]")
    return {"host": host, "port": port, "secret": api.get("secret") or ""}
