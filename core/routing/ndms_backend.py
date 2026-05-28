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

import re

from core.log_buffer import log
from core.ndms.commands import get_ndms_commands, make_owned_name
from core.routing.rules import DomainRoutingRule, CidrRoutingRule


# ════════════════════════════════════════════════════════════
# domain rules
# ════════════════════════════════════════════════════════════

def apply_domain_rule(rule: DomainRoutingRule) -> dict:
    """
    Применить domain-правило через NDMS.

    Шаги:
      1. `object-group fqdn <ZGUI_id>` — создать/заменить FQDN-группу
         с нашими доменами.
      2. `dns-proxy route group <ZGUI_id> interface <target_iface>` —
         сказать ndnsproxy'у маршрутизировать трафик к этим доменам
         через указанный интерфейс.
      3. `system configuration save` — сохранить в startup.

    Возвращает dict в том же формате, что и остальные `apply_*` —
    {"ok": bool, "error"?: str, "backend": "ndms", ...}.
    """
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}
    if not rule.domains:
        return {"ok": False, "error": "Список доменов пуст"}
    if not rule.target_iface:
        return {"ok": False, "error": "Не указан target_iface"}

    domains = _sanitize_domains(rule.domains)
    if not domains:
        return {"ok": False, "error": "Все домены отфильтрованы"}

    cmd = get_ndms_commands()
    group_name = make_owned_name(rule.id)
    description = (rule.description or "")[:200]

    # 1) Полная замена группы — пользователь мог убрать домены из
    # списка в UI; инкрементальный upsert их не вычистил бы.
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
    # На случай если правило уже было применено с другим интерфейсом —
    # NDMS перепишет route без ошибки.
    r_res = cmd.set_dns_proxy_route(group_name, rule.target_iface)
    if not r_res.get("ok"):
        # Откат: убираем созданную группу, чтобы не плодить мусор.
        cmd.delete_fqdn_group(group_name)
        return {
            "ok": False,
            "backend": "ndms",
            "error": "dns-proxy route: %s" % r_res.get("error", "?"),
            "group": group_name,
        }

    # 3) save: иначе перезагрузка роутера всё потеряет.
    save_res = cmd.save_running_config()

    log.info(
        "routing(ndms): domain-правило %s применено через %s (%d доменов)"
        % (rule.id, rule.target_iface, len(domains)),
        source="routing")

    return {
        "ok":        True,
        "backend":   "ndms",
        "group":     group_name,
        "interface": rule.target_iface,
        "domains":   len(domains),
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
            # NDMS-`ip route` — IPv4. Для IPv6 у Keenetic'а другая
            # команда (`ipv6 route`), пока не поддерживаем.
            errors.append("IPv6 пока не поддержан NDMS-backend'ом: %s" % cidr)
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
    '10.0.0.0/24' -> ('10.0.0.0', '24'); IP без маски -> ('IP', '32').
    Возвращает (net, mask) или ('', '') если не распарсилось.
    """
    s = (cidr or "").strip()
    if not s:
        return "", ""
    if "/" in s:
        net, _, mask = s.partition("/")
        return net.strip(), (mask or "32").strip()
    return s, ("128" if ":" in s else "32")
