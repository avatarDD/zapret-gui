# core/ndms/commands.py
"""
High-level NDMS-команды поверх RCI-клиента.

Каждый метод соответствует одной CLI-команде Keenetic'а и
строит payload в виде JSON-дерева, которое RCI принимает на
POST /rci/.

Соглашение по именам групп: всё, что управляется этим GUI,
пишется с префиксом `ZGUI_` — чтобы пользователь видел в
running-config'е, что это наше, и руками не пересекался.

Примеры:
    cmd = get_ndms_commands()

    # domain-routing: youtube через Wireguard0
    cmd.upsert_fqdn_group("ZGUI_yt",
                          include=["youtube.com", "ytimg.com"])
    cmd.set_dns_proxy_route("ZGUI_yt", "Wireguard0")
    cmd.save_running_config()

    # снятие
    cmd.delete_dns_proxy_route("ZGUI_yt", "Wireguard0")
    cmd.delete_fqdn_group("ZGUI_yt")
"""

import re
import threading

from core.log_buffer import log
from core.ndms.rci_client import get_rci_client


# Префикс для имён групп/политик/комментариев, которыми мы владеем.
# Помогает отличить наши объекты от чужих в running-config'е.
OWNER_PREFIX = "ZGUI_"


def make_owned_name(rule_id: str) -> str:
    """
    Превратить rule-id в имя объекта NDMS.

    NDMS-имена ограничены [A-Za-z0-9_-] и длиной (~64). UUID-хвост
    нашего rule_id (`domain-abcd1234`) пролезает спокойно; почистим
    на всякий случай.
    """
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", rule_id or "rule")
    name = OWNER_PREFIX + safe
    # NDMS обычно держит лимит на длину имени; обрежем с запасом.
    return name[:62]


def is_owned_name(name: str) -> bool:
    return bool(name) and name.startswith(OWNER_PREFIX)


class NdmsCommands:
    """High-level NDMS-команды для selective routing."""

    def __init__(self, client=None):
        self.client = client or get_rci_client()

    # ════════════════════════════════════════════════════════════
    # object-group fqdn
    # ════════════════════════════════════════════════════════════

    def upsert_fqdn_group(self, group_name: str,
                          include=None, exclude=None,
                          description: str = "") -> dict:
        """
        Создать/обновить FQDN-группу.

        В терминах NDMS-CLI это эквивалент:
            object-group fqdn <group_name>
              description <description>
              include <domain1>
              include <domain2>
              ...

        Семантика: domains в `include` добавляются. Чтобы убрать
        домен — нужно вызвать `replace_fqdn_group()` (полная замена),
        либо удалить группу через `delete_fqdn_group()` и создать заново.

        Возвращает {"ok": bool, "error": str?, "data": ...}.
        """
        if not group_name:
            return {"ok": False, "error": "group_name пустой"}

        include = include or []
        exclude = exclude or []

        # Структура payload'а соответствует CLI-дереву Keenetic'а.
        group_body = {}
        if description:
            group_body["description"] = description
        if include:
            group_body["include"] = [{"address": d} for d in include]
        if exclude:
            group_body["exclude"] = [{"address": d} for d in exclude]

        payload = {
            "object-group": {
                "fqdn": {
                    group_name: group_body,
                }
            }
        }
        res = self.client.post(payload)
        if not res.get("ok"):
            log.warning("NDMS upsert_fqdn_group(%s) failed: %s"
                        % (group_name, res.get("error")),
                        source="ndms")
        return res

    def replace_fqdn_group(self, group_name: str,
                           include=None, exclude=None,
                           description: str = "") -> dict:
        """
        Полная замена содержимого группы.

        В CLI Keenetic'а нет «set domains [...]» — есть только
        `include <addr>` и `no include <addr>`. Поэтому мы сначала
        полностью удаляем группу (`no object-group fqdn <name>`),
        потом создаём её заново.

        Это нужно, когда пользователь убрал домен из списка в UI:
        нашими «инкрементальными» include'ами его уже не вычистить.
        """
        self.delete_fqdn_group(group_name)
        return self.upsert_fqdn_group(
            group_name, include=include, exclude=exclude,
            description=description)

    def delete_fqdn_group(self, group_name: str) -> dict:
        """`no object-group fqdn <group_name>`."""
        if not group_name:
            return {"ok": False, "error": "group_name пустой"}
        payload = {
            "object-group": {
                "fqdn": {
                    group_name: {"no": True}
                }
            }
        }
        res = self.client.post(payload)
        # Игнорируем ошибку «group not found» — это идемпотентно.
        if not res.get("ok") and _is_not_found_error(res.get("error", "")):
            return {"ok": True, "data": res.get("data"), "noop": True}
        return res

    # ════════════════════════════════════════════════════════════
    # dns-proxy route — привязка FQDN-группы к интерфейсу
    # ════════════════════════════════════════════════════════════

    def set_dns_proxy_route(self, group_name: str, interface: str) -> dict:
        """
        `dns-proxy route group <group_name> interface <interface>`.

        Эта команда говорит встроенному Keenetic-ndnsproxy: «когда
        кто-то спросит у меня домен из группы <group_name>, направь
        итоговый трафик через интерфейс <interface>».

        Никакие ipset/nftset/fwmark не нужны: ndnsproxy сам резолвит
        домен, добавляет временный PBR для разрезолвленных IP и
        снимает по TTL.
        """
        if not group_name or not interface:
            return {"ok": False, "error": "пустые group_name/interface"}
        payload = {
            "dns-proxy": {
                "route": {
                    "group": group_name,
                    "interface": interface,
                }
            }
        }
        res = self.client.post(payload)
        if not res.get("ok"):
            log.warning(
                "NDMS set_dns_proxy_route(%s → %s) failed: %s"
                % (group_name, interface, res.get("error")),
                source="ndms")
        return res

    def delete_dns_proxy_route(self, group_name: str,
                               interface: str) -> dict:
        """`no dns-proxy route group <group_name> interface <interface>`."""
        if not group_name or not interface:
            return {"ok": False, "error": "пустые group_name/interface"}
        payload = {
            "dns-proxy": {
                "route": {
                    "group": group_name,
                    "interface": interface,
                    "no": True,
                }
            }
        }
        res = self.client.post(payload)
        if not res.get("ok") and _is_not_found_error(res.get("error", "")):
            return {"ok": True, "data": res.get("data"), "noop": True}
        return res

    # ════════════════════════════════════════════════════════════
    # ip route — статические маршруты по CIDR
    # ════════════════════════════════════════════════════════════

    def add_static_route(self, network: str, mask: str,
                         interface: str, comment: str = "",
                         auto: bool = True) -> dict:
        """
        `ip route <network> <mask> <interface> [auto] [comment <...>]`.

        Принимает классическую запись: network='10.0.0.0', mask='24'
        (либо '255.255.255.0'). Для одиночного хоста — mask='32'.
        """
        if not network or not mask or not interface:
            return {"ok": False,
                    "error": "пустые network/mask/interface"}
        route = {
            "network": network,
            "mask": str(mask),
            "interface": interface,
        }
        if auto:
            route["auto"] = True
        if comment:
            route["comment"] = comment
        return self.client.post({"ip": {"route": route}})

    def delete_static_route(self, network: str, mask: str,
                            interface: str) -> dict:
        """`no ip route <network> <mask> <interface>`."""
        if not network or not mask or not interface:
            return {"ok": False,
                    "error": "пустые network/mask/interface"}
        payload = {
            "ip": {
                "route": {
                    "network": network,
                    "mask": str(mask),
                    "interface": interface,
                    "no": True,
                }
            }
        }
        res = self.client.post(payload)
        if not res.get("ok") and _is_not_found_error(res.get("error", "")):
            return {"ok": True, "data": res.get("data"), "noop": True}
        return res

    # ════════════════════════════════════════════════════════════
    # ip policy + ip hotspot host policy — per-device маршрутизация
    # ════════════════════════════════════════════════════════════
    #
    # Модель Keenetic'а: «политика» — это упорядоченный список
    # разрешённых интерфейсов. Хосты привязываются к политике через
    # `ip hotspot host <mac> policy <name>`. Для нашего use-case
    # (отправить устройство через Wireguard0) создаём политику с
    # единственным permit'ом — нашим target_iface — и навешиваем на
    # MAC устройства.

    def upsert_ip_policy(self, policy_name: str, permit_iface: str,
                         description: str = "",
                         standalone: bool = False) -> dict:
        """
        `ip policy <name>
           permit <permit_iface>
           [description <...>]
           [standalone]`

        standalone=True — kill-switch-режим: пакеты этого устройства,
        не попавшие на permit_iface, никуда не уйдут. Используем
        опционально (по умолчанию выключено — fallback на основной
        маршрут разрешён).
        """
        if not policy_name or not permit_iface:
            return {"ok": False,
                    "error": "пустые policy_name/permit_iface"}

        policy_body = {
            "permit": [{"interface": permit_iface}],
        }
        if description:
            policy_body["description"] = description
        if standalone:
            policy_body["standalone"] = True

        payload = {"ip": {"policy": {policy_name: policy_body}}}
        res = self.client.post(payload)
        if not res.get("ok"):
            log.warning("NDMS upsert_ip_policy(%s) failed: %s"
                        % (policy_name, res.get("error")),
                        source="ndms")
        return res

    def delete_ip_policy(self, policy_name: str) -> dict:
        """`no ip policy <name>`."""
        if not policy_name:
            return {"ok": False, "error": "policy_name пустой"}
        payload = {"ip": {"policy": {policy_name: {"no": True}}}}
        res = self.client.post(payload)
        if not res.get("ok") and _is_not_found_error(res.get("error", "")):
            return {"ok": True, "data": res.get("data"), "noop": True}
        return res

    def assign_host_policy(self, mac: str, policy_name: str) -> dict:
        """
        `ip hotspot host <mac> policy <policy_name>`.

        MAC регистрозависимый, ожидается формат XX:XX:XX:XX:XX:XX.
        """
        if not mac or not policy_name:
            return {"ok": False, "error": "пустые mac/policy_name"}
        normalized = _normalize_mac(mac)
        if not normalized:
            return {"ok": False, "error": "Некорректный MAC: %s" % mac}
        payload = {
            "ip": {
                "hotspot": {
                    "host": {
                        "mac": normalized,
                        "policy": policy_name,
                    }
                }
            }
        }
        return self.client.post(payload)

    def get_host_policy(self, mac: str) -> dict:
        """
        Узнать, какая политика сейчас назначена хосту (read-only).

        Нужно для совместимости с родительским контролем и политикой
        «Нет доступа в интернет» (как в XKeen): прежде чем перебить
        политику хоста нашей туннельной, мы должны знать прежнюю —
        чтобы предупредить пользователя и восстановить её при снятии
        правила.

        Возвращает {"ok": bool, "policy": str, "found": bool}.
        policy="" — у хоста нет персональной политики (наследует
        политику сегмента, т.е. обычный доступ).
        """
        if not mac:
            return {"ok": False, "error": "mac пустой"}
        normalized = _normalize_mac(mac)
        if not normalized:
            return {"ok": False, "error": "Некорректный MAC: %s" % mac}
        res = self.client.get("show/ip/hotspot/host")
        if not res.get("ok"):
            return {"ok": False, "error": res.get("error", "?")}
        data = res.get("data") or {}
        hosts = data.get("host")
        if isinstance(hosts, dict):
            hosts = [hosts]
        for h in (hosts or []):
            if not isinstance(h, dict):
                continue
            if _normalize_mac(str(h.get("mac", ""))) == normalized:
                return {"ok": True, "found": True,
                        "policy": str(h.get("policy", "") or "")}
        return {"ok": True, "found": False, "policy": ""}

    def unassign_host_policy(self, mac: str) -> dict:
        """`no ip hotspot host <mac> policy` — снять политику с хоста."""
        if not mac:
            return {"ok": False, "error": "mac пустой"}
        normalized = _normalize_mac(mac)
        if not normalized:
            return {"ok": False, "error": "Некорректный MAC: %s" % mac}
        # NDMS: чтобы убрать привязку, удаляем поле policy с no=True
        payload = {
            "ip": {
                "hotspot": {
                    "host": {
                        "mac": normalized,
                        "policy": {"no": True},
                    }
                }
            }
        }
        res = self.client.post(payload)
        if not res.get("ok") and _is_not_found_error(res.get("error", "")):
            return {"ok": True, "data": res.get("data"), "noop": True}
        return res

    # ════════════════════════════════════════════════════════════
    # read-only — обнаружение интерфейсов и текущих правил
    # ════════════════════════════════════════════════════════════

    def show_interface(self, name: str = ""):
        """
        `show interface [name]`.

        Возвращает разобранный JSON. Если name пуст — список всех
        интерфейсов; иначе подробности одного.
        """
        path = "show/interface"
        if name:
            path += "/" + name
        return self.client.get(path)

    def list_wireguard_interfaces(self) -> list:
        """
        Список нативных Keenetic WG-интерфейсов (Wireguard0..N).

        Возвращает list of dict:
          [{"name": "Wireguard0", "description": "MyVPN",
            "state": "up", "address": "10.0.0.2/24"}, ...]

        Если RCI недоступен или интерфейсов нет — пустой список.
        """
        data = self.show_interface()
        if not isinstance(data, dict):
            return []

        out = []
        # show interface отдаёт dict {<name>: {...}, ...}
        for name, info in data.items():
            if not isinstance(info, dict):
                continue
            # Фильтр по имени: нативные WG-интерфейсы Keenetic'а зовутся
            # Wireguard0, Wireguard1, ... — это и есть критерий.
            # AmneziaWG-интерфейсы, поднятые нашим userspace-демоном,
            # будут не в этом списке (они не в NDMS-конфиге, висят
            # на TUN).
            if not _is_wg_iface_name(name):
                continue
            out.append({
                "name":        name,
                "description": str(info.get("description", "")),
                "state":       str(info.get("state", "")),
                "address":     _extract_iface_address(info),
                "type":        "wireguard",
                "source":      "ndms",
            })
        return out

    def show_dns_proxy_routes(self):
        """
        Прочитать текущие dns-proxy.route записи (running-config).

        Возвращает list of dict вида:
          [{"group": "...", "interface": "..."}, ...]
        Или [] если RCI вернул что-то не то.
        """
        data = self.client.get("show/running-config")
        if not isinstance(data, dict):
            # Иногда RCI отдаёт plain-text running-config. Игнорируем.
            return []
        return _extract_dns_proxy_routes(data)

    # ════════════════════════════════════════════════════════════
    # save
    # ════════════════════════════════════════════════════════════

    def save_running_config(self) -> dict:
        """`system configuration save` — сохранить настройки в startup."""
        return self.client.save_running_config()

    # ════════════════════════════════════════════════════════════
    # Транзакционные операции (MR-23)
    # ════════════════════════════════════════════════════════════

    def apply_domain_route(self, group_name: str, domains: list,
                           interface: str, description: str = "") -> dict:
        """Создать/обновить FQDN-группу и привязать её к интерфейсу.

        MR-23: операция транзакционная — если назначение dns-proxy route
        не удалось, созданная FQDN-группа откатывается (удаляется).

        Args:
            group_name:  имя FQDN-группы (может быть make_owned_name()-output)
            domains:     список доменов для маршрутизации
            interface:   целевой интерфейс (например «Wireguard0»)
            description: опциональное описание группы

        Returns:
            {«ok»: bool, «error»?: str, «rolled_back»?: bool}
        """
        # Шаг 1: создать/обновить FQDN-группу
        r1 = self.upsert_fqdn_group(
            group_name,
            include=domains,
            description=description,
        )
        if not r1.get("ok"):
            return {"ok": False,
                    "error": "upsert_fqdn_group: %s" % r1.get("error", "?")}

        # Шаг 2: назначить dns-proxy route
        r2 = self.set_dns_proxy_route(group_name, interface)
        if not r2.get("ok"):
            # Rollback: удаляем группу, которую только что создали
            try:
                self.delete_fqdn_group(group_name)
            except Exception:
                pass
            log.warning(
                "NDMS apply_domain_route: rollback %s (route failed: %s)"
                % (group_name, r2.get("error")),
                source="ndms")
            return {"ok": False,
                    "error": "set_dns_proxy_route: %s" % r2.get("error", "?"),
                    "rolled_back": True}

        return {"ok": True}

    def remove_domain_route(self, group_name: str, interface: str) -> dict:
        """Симметрично удалить dns-proxy route и FQDN-группу.

        Каждый шаг — идемпотентен (not-found трактуется как успех).
        Возвращает {«ok»: bool, «errors»: [str]}.
        """
        errors = []
        r1 = self.delete_dns_proxy_route(group_name, interface)
        if not r1.get("ok"):
            errors.append("delete_dns_proxy_route: %s" % r1.get("error", "?"))
        r2 = self.delete_fqdn_group(group_name)
        if not r2.get("ok"):
            errors.append("delete_fqdn_group: %s" % r2.get("error", "?"))
        return {"ok": not errors, "errors": errors}


# ─────── helpers ───────

_WG_NAME_RE = re.compile(r"^Wireguard\d+$", re.IGNORECASE)
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _is_wg_iface_name(name: str) -> bool:
    return bool(name) and bool(_WG_NAME_RE.match(name))


def _normalize_mac(mac: str) -> str:
    """
    Привести MAC к формату AA:BB:CC:DD:EE:FF (NDMS любит colon-separated
    и uppercase). Возвращает '' если входная строка не похожа на MAC.
    """
    if not mac:
        return ""
    s = str(mac).strip()
    if not _MAC_RE.match(s):
        return ""
    # Дефисы → двоеточия, lowercase → upper
    return s.replace("-", ":").upper()


def _extract_iface_address(info: dict) -> str:
    """Достать первый IPv4-адрес интерфейса из ответа show interface."""
    if not isinstance(info, dict):
        return ""
    # Формат может варьироваться от прошивки к прошивке.
    # Пробуем популярные ключи.
    addr = info.get("address")
    if isinstance(addr, str) and addr:
        return addr
    if isinstance(addr, dict):
        # {"address": "10.0.0.2", "mask": "255.255.255.0"}
        a = addr.get("address")
        m = addr.get("mask")
        if a and m:
            return "%s/%s" % (a, m)
        if a:
            return str(a)
    ip4 = info.get("ipv4")
    if isinstance(ip4, dict):
        addrs = ip4.get("address")
        if isinstance(addrs, list) and addrs:
            first = addrs[0]
            if isinstance(first, dict):
                a = first.get("address") or first.get("ip")
                p = first.get("prefix-length") or first.get("mask")
                if a and p:
                    return "%s/%s" % (a, p)
                if a:
                    return str(a)
    return ""


def _extract_dns_proxy_routes(cfg: dict) -> list:
    """Грубый разбор running-config-блока dns-proxy.route."""
    try:
        dp = cfg.get("dns-proxy")
        if not isinstance(dp, dict):
            return []
        routes = dp.get("route")
        if not routes:
            return []
        if isinstance(routes, list):
            return [r for r in routes if isinstance(r, dict)]
        if isinstance(routes, dict):
            return [routes]
    except Exception:
        pass
    return []


def _is_not_found_error(err: str) -> bool:
    """
    NDMS на удаление несуществующего объекта может ругаться разными
    фразами. Считаем «not found / no such» успехом для идемпотентности.
    """
    if not err:
        return False
    low = err.lower()
    return any(token in low for token in (
        "not found", "no such", "doesn't exist", "does not exist"))


# ─────── singleton ───────

_commands = None
_commands_lock = threading.Lock()


def get_ndms_commands() -> NdmsCommands:
    global _commands
    if _commands is None:
        with _commands_lock:
            if _commands is None:
                _commands = NdmsCommands()
    return _commands
