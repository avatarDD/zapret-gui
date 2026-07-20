# core/routing/ndms_backend.py
"""
Keenetic-native backend для selective routing.

Применяет правила через встроенный Keenetic Router Control Interface
(RCI) вместо нашего dnsmasq + ipset/nftset + fwmark стека. На
Keenetic'е этот путь работает «из коробки», потому что:

  - 53-й порт занимает системный `ndnsproxy` — наш dnsmasq не поднять,
    а ndnsproxy штатно умеет резолвить домены и привязывать их к
    интерфейсу через `dns-proxy route`;
  - `ip route <net> <mask> <iface>` через NDMS переживает
    reload-running-config (в отличие от наших голых `ip rule add`,
    которые Keenetic периодически перетирает);
  - per-device маршрутизация делается через `ip policy` + `ip hotspot
    host policy` — на iptables-марки Keenetic смотрит косо.

Backend используется ТОЛЬКО если детектор сказал, что мы на Keenetic
и RCI доступен. На любых других платформах вызываемые тут функции
никогда не должны достигаться — см. `domain_rule._detect_backend()`.

Соглашение по именам: все наши объекты в NDMS-конфиге начинаются с
префикса `ZGUI_<rule_id>` — чтобы пользователь видел их в running-
config'е и руками не пересекался.
"""

import ipaddress
import re

from core.log_buffer import log
from core.ndms.commands import (
    get_ndms_commands, make_owned_name, is_owned_name,
)
from core.routing.rules import (
    DomainRoutingRule,
    CidrRoutingRule,
    DeviceRoutingRule,
)


# ════════════════════════════════════════════════════════════
# domain rules
# ════════════════════════════════════════════════════════════

def apply_domain_rule(rule: DomainRoutingRule) -> dict:
    """
    Применить domain-правило через NDMS.

    Шаги:
      1. Развернуть `geosite:NAME` / `geoip:NAME` алиасы, если они
         встречаются в списке (см. `alias_resolver.expand_domains`).
         Чистые домены идут в FQDN-группу, чистые CIDR — в `ip route`.
      2. `object-group fqdn <ZGUI_id>` — создать/заменить FQDN-группу.
      3. `dns-proxy route group <ZGUI_id> interface <target_iface>` —
         сказать ndnsproxy'у маршрутизировать трафик к этим доменам
         через указанный интерфейс.
      4. `system configuration save` — сохранить в startup.

    Возвращает dict в том же формате, что и остальные `apply_*` —
    {"ok": bool, "error"?: str, "backend": "ndms", ...,
     "aliases_resolved": [...], "aliases_failed": [...]}.
    """
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}
    if not rule.domains:
        return {"ok": False, "error": "Список доменов пуст"}
    if not rule.target_iface:
        return {"ok": False, "error": "Не указан target_iface"}

    # HydraRoute Neo: разворачиваем geosite:/geoip:, если есть.
    from core.routing.alias_resolver import expand_domains
    expanded = expand_domains(rule.domains)
    raw_inputs = list(expanded.get("domains") or [])

    # Расширенные CIDR (через geoip:) применим отдельной NDMS-командой
    # после основной FQDN-группы. Если их много — это будет много
    # `ip route`-записей, поэтому ограничимся 5000 (Keenetic столько
    # переварит, но reload-config начнёт тормозить).
    expanded_cidrs = list(expanded.get("cidrs") or [])[:5000]

    domains = _sanitize_domains(raw_inputs)
    if not domains and not expanded_cidrs:
        return {"ok": False, "error": "Все домены/алиасы отфильтрованы",
                "aliases_failed": expanded.get("aliases_failed") or []}

    cmd = get_ndms_commands()
    group_name = make_owned_name(rule.id)
    description = (rule.description or "")[:200]

    # 1) FQDN-группа (если есть домены после развёртки).
    if domains:
        g_res = cmd.replace_fqdn_group(
            group_name,
            include=domains,
            description=description or ("zapret-gui rule %s" % rule.id),
        )
        if not g_res.get("ok"):
            return {
                "ok": False,
                "backend": "ndms",
                "error": "object-group fqdn: %s" % g_res.get("error", "?"),
                "group": group_name,
            }

        # 2) dns-proxy route: привязка группы к интерфейсу.
        r_res = cmd.set_dns_proxy_route(group_name, rule.target_iface)
        if not r_res.get("ok"):
            cmd.delete_fqdn_group(group_name)
            return {
                "ok": False,
                "backend": "ndms",
                "error": "dns-proxy route: %s" % r_res.get("error", "?"),
                "group": group_name,
            }

    # 3) CIDR-записи (если развернулся geoip:). Идут отдельными
    # `ip route` командами; не падаем правило целиком, если часть
    # не легла — просто отчитаемся об ошибках.
    cidr_added = 0
    cidr_errors = []
    for cidr in expanded_cidrs:
        net, mask = _split_cidr(cidr)
        if not net:
            continue
        if ":" in net:
            # MR-34: IPv6 не поддерживается NDMS-native — fallback на ip-rule
            try:
                from core.routing.manager import RoutingManager
                v6_rule = CidrRoutingRule(
                    target_iface=rule.target_iface,
                    cidrs=[cidr],
                    rule_id=rule.id,
                    description=rule.description,
                    priority=getattr(rule, "priority", 0),
                )
                result = RoutingManager()._apply_cidr(v6_rule)
                if result.get("ok"):
                    cidr_added += 1
                else:
                    cidr_errors.append("IPv6 fallback %s: %s" % (cidr, result.get("error", "?")))
            except Exception as e:
                cidr_errors.append("IPv6 fallback error: %s" % e)
            continue
        r = cmd.add_static_route(
            network=net, mask=str(mask),
            interface=rule.target_iface,
            comment=("zapret-gui %s" % rule.id)[:64],
        )
        if r.get("ok"):
            cidr_added += 1
        else:
            cidr_errors.append("%s/%s: %s" % (net, mask, r.get("error", "?")))
            if len(cidr_errors) >= 10:
                # Не флудим лог одной и той же ошибкой
                cidr_errors.append("... (ещё %d ошибок усечено)"
                                   % max(0, len(expanded_cidrs) - cidr_added
                                         - len(cidr_errors)))
                break

    # 4) save: иначе перезагрузка роутера всё потеряет.
    save_res = cmd.save_running_config()

    log.info(
        "routing(ndms): domain-правило %s применено через %s "
        "(%d доменов, %d CIDR, алиасы: %d разверн., %d не удалось)"
        % (rule.id, rule.target_iface, len(domains), cidr_added,
           len(expanded.get("aliases_resolved") or []),
           len(expanded.get("aliases_failed") or [])),
        source="routing")

    return {
        "ok":        True,
        "backend":   "ndms",
        "group":     group_name if domains else "",
        "interface": rule.target_iface,
        "domains":   len(domains),
        "cidr_added":  cidr_added,
        "cidr_errors": cidr_errors,
        "aliases_resolved": expanded.get("aliases_resolved") or [],
        "aliases_failed":   expanded.get("aliases_failed") or [],
        "saved":     bool(save_res.get("ok")),
    }


def remove_domain_rule(rule: DomainRoutingRule) -> dict:
    """
    Снять domain-правило через NDMS.

    Не падает, если объектов в running-config уже нет —
    `delete_*` идемпотентны.
    """
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}

    cmd = get_ndms_commands()
    group_name = make_owned_name(rule.id)

    errors = []

    # 1) Отвязать dns-proxy route. Удаляем по тому же интерфейсу,
    # который указан в правиле; если интерфейс уже не существует —
    # NDMS обычно тихо съедает.
    if rule.target_iface:
        r_res = cmd.delete_dns_proxy_route(group_name, rule.target_iface)
        if not r_res.get("ok"):
            errors.append("dns-proxy route: %s" % r_res.get("error", "?"))

    # 2) Удалить саму FQDN-группу.
    g_res = cmd.delete_fqdn_group(group_name)
    if not g_res.get("ok"):
        errors.append("object-group fqdn: %s" % g_res.get("error", "?"))

    # 3) Подчистить CIDR-маршруты, которые мы могли добавить через
    # развёрнутый geoip:. Перегенерим список из текущего правила —
    # это best-effort: если состав geoip-списка с момента apply
    # изменился, часть записей останется висеть. Для надёжной
    # очистки пользователь может сделать /api/routing/apply, который
    # переразложит все правила с нуля.
    if rule.target_iface and rule.domains:
        try:
            from core.routing.alias_resolver import expand_domains
            expanded = expand_domains(rule.domains)
            for cidr in (expanded.get("cidrs") or [])[:5000]:
                net, mask = _split_cidr(cidr)
                if not net or ":" in net:
                    continue
                cmd.delete_static_route(
                    network=net, mask=str(mask),
                    interface=rule.target_iface)
        except Exception as e:
            log.warning("routing(ndms): чистка geoip-маршрутов %s: %s"
                        % (rule.id, e), source="routing")

    save_res = cmd.save_running_config()

    log.info("routing(ndms): domain-правило %s снято" % rule.id,
             source="routing")
    return {
        "ok":      not errors,
        "backend": "ndms",
        "errors":  errors,
        "saved":   bool(save_res.get("ok")),
    }


# ════════════════════════════════════════════════════════════
# CIDR rules (опционально — используется когда явно включено)
# ════════════════════════════════════════════════════════════

def apply_cidr_rule(rule: CidrRoutingRule) -> dict:
    """
    Применить CIDR-правило через NDMS (ip route).

    Сейчас используется как опциональная альтернатива дефолтному
    `ip rule add to <cidr>`. Преимущество: маршрут попадает в NDMS-
    running-config и переживает reload. Недостаток: интерфейс должен
    быть нативным NDMS-интерфейсом (для AWG-userspace-туннелей это
    не сработает, NDMS такие интерфейсы не видит).
    """
    if not isinstance(rule, CidrRoutingRule):
        return {"ok": False, "error": "Не CidrRoutingRule"}
    if not rule.cidrs:
        return {"ok": False, "error": "Список CIDR пуст"}

    cmd = get_ndms_commands()
    added = []
    errors = []

    for cidr in rule.cidrs:
        net, mask = _split_cidr(cidr)
        if not net:
            errors.append("Не разобрался с CIDR %s" % cidr)
            continue
        if ":" in net:
            # MR-34: IPv6 не поддерживается NDMS-native — fallback на ip-rule
            try:
                from core.routing.manager import RoutingManager
                v6_cidr = "%s/%s" % (net, mask)
                v6_rule = CidrRoutingRule(
                    target_iface=rule.target_iface,
                    cidrs=[v6_cidr],
                    rule_id=rule.id,
                    description=rule.description,
                    priority=rule.priority,
                )
                result = RoutingManager()._apply_cidr(v6_rule)
                if result.get("ok"):
                    added.append({"network": net, "mask": mask, "backend": "iprule-v6"})
                else:
                    errors.append("IPv6 fallback: %s" % result.get("error", "?"))
            except Exception as e:
                errors.append("IPv6 fallback error: %s" % e)
            continue

        r = cmd.add_static_route(
            network=net, mask=str(mask),
            interface=rule.target_iface,
            comment=("zapret-gui %s" % rule.id)[:64],
        )
        if r.get("ok"):
            added.append({"network": net, "mask": mask})
        else:
            errors.append("ip route %s/%s: %s" %
                          (net, mask, r.get("error", "?")))

    save_res = cmd.save_running_config() if added else {"ok": True}

    log.info("routing(ndms): CIDR-правило %s применено (%d/%d)"
             % (rule.id, len(added), len(rule.cidrs)),
             source="routing")
    return {
        "ok":      bool(added) and not errors,
        "backend": "ndms",
        "added":   added,
        "errors":  errors,
        "saved":   bool(save_res.get("ok")),
    }


def remove_cidr_rule(rule: CidrRoutingRule) -> dict:
    """Снять CIDR-правило через NDMS (ip route ... no)."""
    if not isinstance(rule, CidrRoutingRule):
        return {"ok": False, "error": "Не CidrRoutingRule"}

    cmd = get_ndms_commands()
    removed = []
    errors = []

    for cidr in rule.cidrs:
        net, mask = _split_cidr(cidr)
        if not net or ":" in net:
            continue
        r = cmd.delete_static_route(
            network=net, mask=str(mask), interface=rule.target_iface)
        if r.get("ok"):
            removed.append({"network": net, "mask": mask})
        else:
            errors.append("no ip route %s/%s: %s" %
                          (net, mask, r.get("error", "?")))

    save_res = cmd.save_running_config() if removed else {"ok": True}

    log.info("routing(ndms): CIDR-правило %s снято (%d записей)"
             % (rule.id, len(removed)),
             source="routing")
    return {
        "ok":      not errors,
        "backend": "ndms",
        "removed": removed,
        "errors":  errors,
        "saved":   bool(save_res.get("ok")),
    }


# ════════════════════════════════════════════════════════════
# device rules (per-MAC через ip policy + ip hotspot host policy)
# ════════════════════════════════════════════════════════════
#
# В отличие от domain/CIDR-правил, device-rule через NDMS работает
# только если у пользователя указан MAC устройства. Без MAC мы не
# можем зацепиться за хост в `ip hotspot host` — NDMS не умеет
# привязывать политику к чистому source-IP. В таком случае мы
# отдаём False из can_handle_device_rule() и manager идёт на
# стандартный путь через `ip rule from <ip>`.

# ─────── сохранение прежней политики хоста (parental control и пр.) ──
#
# Перед тем как назначить хосту нашу туннельную политику, запоминаем
# его текущую персональную политику (если это не наша). При снятии
# правила — восстанавливаем её вместо «снять политику», чтобы не
# затереть родительский контроль / «Нет доступа в интернет», которые
# пользователь настроил в самом Keenetic. Заимствовано из XKeen.

def _save_prev_host_policy(mac: str, prev_policy: str):
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        saved = cfg.get("routing", "saved_host_policies", default={}) or {}
        if not isinstance(saved, dict):
            saved = {}
        saved[mac] = prev_policy
        cfg.set("routing", "saved_host_policies", saved)
        cfg.save()
    except Exception as e:
        log.warning("routing(ndms): не удалось сохранить прежнюю политику"
                    " хоста %s: %s" % (mac, e), source="routing")


def _pop_prev_host_policy(mac: str) -> str:
    """Вернуть и удалить сохранённую прежнюю политику хоста (или '')."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        saved = cfg.get("routing", "saved_host_policies", default={}) or {}
        if not isinstance(saved, dict) or mac not in saved:
            return ""
        prev = str(saved.pop(mac) or "")
        cfg.set("routing", "saved_host_policies", saved)
        cfg.save()
        return prev
    except Exception:
        return ""


def can_handle_device_rule(rule: DeviceRoutingRule) -> bool:
    """
    Может ли NDMS-backend обработать это device-правило.

    True, когда:
      - правильный тип
      - указан MAC (NDMS привязывает политику по MAC)
      - target_iface — нативный NDMS-объект (Wireguard0/1, OpenVPN0,
        ISP*); userspace-AWG в NDMS-конфиге не существует.
    """
    if not isinstance(rule, DeviceRoutingRule):
        return False
    if not rule.mac:
        return False
    from core.routing.manager import _is_ndms_native_iface
    return _is_ndms_native_iface(rule.target_iface)


def apply_device_rule(rule: DeviceRoutingRule) -> dict:
    """
    Применить device-правило через NDMS:
      1. `ip policy <ZGUI_id> permit <target_iface>` — создать
         персональную политику с единственным разрешённым иntерфейсом.
      2. `ip hotspot host <mac> policy <ZGUI_id>` — привязать хост.
      3. `system configuration save`.

    Пользователь сохраняет fallback на основной маршрут, если туннель
    не доступен (standalone=False). Это сознательный выбор:
    «kill-switch» поведение лучше делать опционально на уровне самого
    туннеля, а не нашими политиками.
    """
    if not isinstance(rule, DeviceRoutingRule):
        return {"ok": False, "error": "Не DeviceRoutingRule"}
    if not rule.mac:
        return {"ok": False, "error": "Для NDMS-device-rule нужен MAC"}
    if not rule.target_iface:
        return {"ok": False, "error": "Не указан target_iface"}

    cmd = get_ndms_commands()
    policy_name = make_owned_name(rule.id)
    description = (rule.description or rule.hostname or "")[:200]

    p_res = cmd.upsert_ip_policy(
        policy_name,
        permit_iface=rule.target_iface,
        description=description or ("zapret-gui rule %s" % rule.id),
        standalone=False,
    )
    if not p_res.get("ok"):
        return {
            "ok":      False,
            "backend": "ndms",
            "error":   "ip policy: %s" % p_res.get("error", "?"),
            "policy":  policy_name,
        }

    # Совместимость с родительским контролем / «Нет доступа в интернет»:
    # запомним прежнюю персональную политику хоста, если она чужая (не
    # наша). При снятии правила восстановим её, а не просто снимем.
    warning = ""
    prev = cmd.get_host_policy(rule.mac)
    if prev.get("ok") and prev.get("found"):
        prev_pol = prev.get("policy", "")
        if prev_pol and not is_owned_name(prev_pol):
            _save_prev_host_policy(rule.mac, prev_pol)
            warning = ("у устройства уже была политика '%s' (напр. "
                       "родительский контроль) — она временно перекрыта "
                       "туннельной и будет восстановлена при удалении "
                       "правила" % prev_pol)
            log.warning("routing(ndms): %s (mac=%s)" % (warning, rule.mac),
                        source="routing")

    h_res = cmd.assign_host_policy(rule.mac, policy_name)
    if not h_res.get("ok"):
        # Откат — снимаем политику, чтобы не оставлять мусор.
        cmd.delete_ip_policy(policy_name)
        _pop_prev_host_policy(rule.mac)
        return {
            "ok":      False,
            "backend": "ndms",
            "error":   "ip hotspot host policy: %s" % h_res.get("error", "?"),
            "policy":  policy_name,
        }

    save_res = cmd.save_running_config()
    log.info(
        "routing(ndms): device-правило %s применено (mac=%s → %s)"
        % (rule.id, rule.mac, rule.target_iface),
        source="routing")
    return {
        "ok":      True,
        "backend": "ndms",
        "policy":  policy_name,
        "mac":     rule.mac,
        "iface":   rule.target_iface,
        "saved":   bool(save_res.get("ok")),
        "warning": warning,
    }


def remove_device_rule(rule: DeviceRoutingRule) -> dict:
    """Снять device-правило через NDMS — симметрично apply."""
    if not isinstance(rule, DeviceRoutingRule):
        return {"ok": False, "error": "Не DeviceRoutingRule"}

    cmd = get_ndms_commands()
    policy_name = make_owned_name(rule.id)
    errors = []

    if rule.mac:
        # Если у хоста была своя политика (родительский контроль и т.п.) —
        # восстанавливаем её. Иначе просто снимаем нашу.
        prev_pol = _pop_prev_host_policy(rule.mac)
        if prev_pol:
            r_res = cmd.assign_host_policy(rule.mac, prev_pol)
            if not r_res.get("ok"):
                errors.append("restore host policy '%s': %s"
                              % (prev_pol, r_res.get("error", "?")))
            else:
                log.info("routing(ndms): восстановлена прежняя политика"
                         " '%s' хоста %s" % (prev_pol, rule.mac),
                         source="routing")
        else:
            u_res = cmd.unassign_host_policy(rule.mac)
            if not u_res.get("ok"):
                errors.append("ip hotspot host policy: %s"
                              % u_res.get("error", "?"))

    p_res = cmd.delete_ip_policy(policy_name)
    if not p_res.get("ok"):
        errors.append("ip policy: %s" % p_res.get("error", "?"))

    save_res = cmd.save_running_config()
    log.info("routing(ndms): device-правило %s снято" % rule.id,
             source="routing")
    return {
        "ok":      not errors,
        "backend": "ndms",
        "errors":  errors,
        "saved":   bool(save_res.get("ok")),
    }


# ════════════════════════════════════════════════════════════
# helpers
# ════════════════════════════════════════════════════════════

# Разрешённые символы в FQDN: буквы/цифры/точка/дефис/подчёркивание.
# Wildcard '*' не пропускаем — NDMS его не понимает в include,
# для wildcard в FQDN-группе Keenetic использует отдельные суффикс-формы.
_FQDN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_\-.]*[A-Za-z0-9])?$")
_MAX_DOMAINS_PER_GROUP = 500   # практический лимит, чтобы не положить ndnsproxy


def _sanitize_domains(domains) -> list:
    """
    Нормализовать домены под формат NDMS object-group fqdn:

      - lowercase
      - убрать leading dot
      - дедуп
      - выкинуть пустые, IP'шники и явно невалидные
      - обрезать общее количество, если их безумно много
    """
    seen = set()
    out = []
    for d in domains or []:
        s = str(d or "").strip().lower()
        if not s:
            continue
        if s.startswith("."):
            s = s[1:]
        if not s or s in seen:
            continue
        # IP'шники в FQDN-группе бессмысленны — для них есть ip route
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
            continue
        if not _FQDN_RE.match(s):
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= _MAX_DOMAINS_PER_GROUP:
            break
    return out


def _split_cidr(cidr: str):
    """
    '10.0.0.0/24' -> ('10.0.0.0', '255.255.255.0'); IP без маски ->
    ('IP', '255.255.255.255').

    Keenetic `ip route <network> <mask>` ожидает ДОТТЕД-маску, а не
    префикс-длину — поэтому для IPv4 конвертируем `/N` в dotted (раньше
    отдавали '24', и маршрут не устанавливался). IPv6 NDMS-путь не
    применяет (вызывающий отбрасывает адреса с ':'), возвращаем как есть.
    Возвращает (net, mask) или ('', '') если не распарсилось.
    """
    s = (cidr or "").strip()
    if not s:
        return "", ""
    if ":" in s:
        net, _, mask = s.partition("/")
        return net.strip(), (mask or "128").strip()
    try:
        spec = s if "/" in s else s + "/32"
        net = ipaddress.ip_network(spec, strict=False)
        return str(net.network_address), str(net.netmask)
    except ValueError:
        # Не распарсилось как сеть — отдаём прежним способом, чтобы не
        # ронять вызов (валидацию делает вызывающий).
        if "/" in s:
            n, _, m = s.partition("/")
            return n.strip(), (m or "32").strip()
        return s, "255.255.255.255"
