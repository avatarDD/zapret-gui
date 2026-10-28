# core/unified/manager.py
"""
Тонкая оркестрация единого слоя: CRUD маршрутов (storage) + применение
(applier). Используется API. Держим API-слой тонким и тестируемым.
"""

import threading

from core.log_buffer import log
from core.unified import storage, applier
from core.unified.model import UnifiedRoute


def list_routes() -> list:
    return [r.to_dict() for r in storage.load_routes()]


def get_route(route_id: str):
    r = storage.get_route(route_id)
    return r.to_dict() if r else None


def save_route(data: dict, *, apply: bool = True,
               validate: bool = False) -> dict:
    """Создать/обновить маршрут из dict. Валидирует модель, сохраняет,
    (опц.) применяет.

    validate=True (ввод из формы/API/импорта) — домены, шаблоны и CIDR
    назначения проверяются (core/unified/bulk.validate_destination).
    Внутренние пересохранения (массовое вкл/выкл, failover) старые
    маршруты не проверяют: из-за давней опечатки нельзя было бы даже
    выключить маршрут."""
    if validate:
        data = _normalize_input(data)
        why = _resolve_devices(data)
        if why:
            return {"ok": False, "error": why}
    try:
        # strict: адрес устройства проверяем на входе из GUI/API —
        # «192.168.0.*» должен вернуться ошибкой в форму, а не осесть в
        # settings.json неработающим правилом (issue #333).
        route = UnifiedRoute.from_dict(data or {}, strict_devices=True)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if validate:
        bad_dev = _router_devices(route)
        if bad_dev:
            return {"ok": False,
                    "error": "%s — адрес самого роутера или его шлюза:"
                             " такое правило увело бы в туннель трафик"
                             " роутера. Уберите его из устройств"
                             % ", ".join(bad_dev)}
        from core.unified.bulk import validate_destination
        bad = validate_destination(route.destination.to_dict())
        if bad:
            more = len(bad) - 5
            return {"ok": False, "invalid": bad,
                    "error": "Некорректные записи назначения: %s%s"
                             % ("; ".join(bad[:5]),
                                " (и ещё %d)" % more if more > 0 else "")}
        # Проверяем только то, что появилось в этой правке: маршрут,
        # чей туннель или список давно удалили, должен оставаться
        # редактируемым (выключить, сменить метод).
        previous = storage.get_route(route.id)
        from core.unified.bulk import unknown_list_ids
        old_lists = set(previous.destination.list_ids) if previous else set()
        missing = unknown_list_ids([lid for lid in route.destination.list_ids
                                    if lid not in old_lists])
        if missing:
            first = missing[0]
            return {"ok": False, "unknown_lists": missing,
                    "error": "Списка «%s» нет%s" % (
                        first["id"],
                        " — есть: %s" % ", ".join(first["available"][:15])
                        if first["available"] else "")}
        why = _unknown_iface(route, previous)
        if why:
            return {"ok": False, "error": why}
    if not route.has_selectors():
        return {"ok": False, "error": "Назначение пустое — укажите домены/"
                                      "CIDR/список/geosite, устройства "
                                      "или DSCP"}
    existing = storage.get_route(route.id)
    if existing is not None:
        storage.update_route(route)
    else:
        storage.add_route(route)
    applied = None
    if apply and route.enabled:
        applied = applier.apply_route(route)
        reasserted = _reassert_priority(route)
        if reasserted and isinstance(applied, dict):
            applied["reapplied_by_priority"] = reasserted
    elif not route.enabled:
        applier.remove_route(route)
        _sweep_dnsmasq("disable")
    _sync_monitor()
    log.info("unified: сохранён маршрут %s (%s → %s)"
             % (route.id, route.name, route.method), source="unified")
    return {"ok": True, "route": route.to_dict(), "applied": applied}


def _normalize_input(data) -> dict:
    """Домены назначения, вставленные как URL, → имена сайтов."""
    data = dict(data or {})
    dest = data.get("destination")
    if isinstance(dest, dict) and dest.get("domains"):
        from core.unified.bulk import normalize_domains
        domains = dest["domains"]
        if isinstance(domains, str):
            domains = [domains]
        dest = dict(dest)
        dest["domains"] = normalize_domains(domains)
        data["destination"] = dest
    return data


def _resolve_devices(data: dict) -> str:
    """Устройства, заданные только MAC или именем, → их текущий IP.

    Правило устройства — `ip rule from <ip>`, поэтому запись без адреса
    модель отбрасывает. Раньше так молча пропадал весь фильтр по
    источнику: маршрут «для одного устройства» сохранялся без устройств
    и (вместе с назначением) действовал на всю сеть. Не нашли адрес —
    ошибка, а не пустой фильтр.
    """
    devices = data.get("devices")
    if not isinstance(devices, list):
        return ""
    need = [i for i, d in enumerate(devices) if isinstance(d, dict)
            and not str(d.get("ip") or "").strip()
            and (str(d.get("mac") or "").strip()
                 or str(d.get("hostname") or "").strip())]
    if not need:
        return ""
    try:
        from core import devices_discovery as dd
        by_mac = {str(m).lower(): ip
                  for m, ip in (dd.mac_ip_map() or {}).items()}
        by_name = {}
        if any(not str(devices[i].get("mac") or "").strip() for i in need):
            for dev in dd.list_devices() or []:
                name = str(dev.get("hostname") or "").strip().lower()
                if name and dev.get("ip"):
                    by_name.setdefault(name, dev["ip"])
    except Exception:
        by_mac, by_name = {}, {}
    out, missing = list(devices), []
    for i in need:
        dev = dict(devices[i])
        mac = str(dev.get("mac") or "").strip()
        name = str(dev.get("hostname") or "").strip()
        ip = ""
        if mac:
            ip = by_mac.get(mac.lower().replace("-", ":"), "")
        if not ip and name:
            ip = by_name.get(name.lower(), "")
        if not ip:
            missing.append(mac or name)
            continue
        dev["ip"] = ip
        out[i] = dev
    if missing:
        return ("Устройство %s не найдено в сети: IP по MAC/имени не "
                "определился. Укажите ip устройства (оно должно быть "
                "подключено)" % ", ".join(missing[:5]))
    data["devices"] = out
    return ""


# Выключатель для тестов (tests/conftest.py): интерфейсов туннелей в
# тестовом окружении нет, проверяется механизм отдельно.
CHECK_IFACES = True

_ENGINE_TITLES = {"awg": "AmneziaWG", "singbox": "sing-box",
                  "mihomo": "mihomo", "warp": "usque (WARP)"}


def _engine_ifaces(kind: str):
    """Интерфейсы из конфигов движка; None — перечень не получен."""
    try:
        if kind == "awg":
            from core.awg_manager import get_awg_manager
            return {c.get("iface") or c.get("name", "")
                    for c in get_awg_manager().list_configs() or []}
        if kind == "singbox":
            from core.singbox_manager import get_singbox_manager
            return {c.get("tun_iface") or ""
                    for c in get_singbox_manager().list_configs() or []}
        if kind == "mihomo":
            from core.mihomo_manager import get_mihomo_manager
            return {c.get("tun_iface") or ""
                    for c in get_mihomo_manager().list_configs() or []}
        if kind == "warp":
            from core.usque_manager import get_usque_manager
            mgr = get_usque_manager()
            names = {c.get("iface") or ""
                     for c in mgr.list_configs() or []}
            names |= {e.get("iface") or ""
                      for e in (mgr.detect() or {}).get("external") or []}
            return names
    except Exception:
        return None
    return None


def _unknown_iface(route, previous=None) -> str:
    """Причина отказа, если метод маршрута смотрит в несуществующий
    интерфейс, иначе ''.

    Опечатка («awg:nosuchiface») сохранялась как туннель, который
    «временно не поднят»: dnsmasq получал nftset в наборы, которых нет,
    монитор мерил прямой путь и считал маршрут здоровым, а имя навсегда
    занимало номер таблицы. Интерфейс годится, если он есть в системе
    или в конфигах своего движка (туннель настроен, но сейчас лежит).
    """
    if not CHECK_IFACES:
        return ""
    from core.unified.model import iface_present, parse_method
    old = set(previous.method_chain()) if previous else set()
    for method in route.method_chain():
        if method in old:
            continue
        try:
            kind, iface = parse_method(method)
        except ValueError:
            continue
        if kind not in _ENGINE_TITLES or iface_present(iface):
            continue
        known = _engine_ifaces(kind)
        if known is None or iface in known:
            continue
        known = sorted(k for k in known if k)
        return ("Интерфейса «%s» нет ни в системе, ни среди конфигов %s%s"
                % (iface, _ENGINE_TITLES[kind],
                   " (есть: %s)" % ", ".join(known[:15]) if known
                   else " — конфигов нет"))
    return ""


def prune_table_map() -> list:
    """Вернуть номера таблиц интерфейсов, которые больше никому не нужны.

    `routing.table_map` закрепляет номер за именем навсегда — это верно
    для живых туннелей (номер стабилен между перезапусками), но имя,
    которого нет ни в системе, ни у одного правила или маршрута, ни в
    конфигах движков (опечатка прошлых версий: «nosuchiface», «sb1»),
    держало номер вечно, а секция routing через MCP закрыта на запись.
    Если перечень конфигов какого-то движка не прочитался — не трогаем
    ничего: лучше лишний номер, чем отобранный у лежащего туннеля.
    Возвращает освобождённые имена.
    """
    try:
        from core.config_manager import get_config_manager
        from core.routing import storage as rstorage
        from core.routing.manager import release_table
        from core.unified.model import iface_present, method_iface
        table_map = get_config_manager().get("routing", "table_map",
                                             default={}) or {}
        if not isinstance(table_map, dict) or not table_map:
            return []
        used = {getattr(r, "target_iface", "") for r in rstorage.load_rules()}
        for other in storage.load_routes():
            used |= {method_iface(m) for m in other.method_chain()}
        candidates = [name for name in table_map
                      if name not in used and not iface_present(name)]
        if not candidates:
            return []
        for kind in _ENGINE_TITLES:
            known = _engine_ifaces(kind)
            if known is None:
                return []
            used |= known
        freed = [name for name in candidates
                 if name not in used and release_table(name)]
        if freed:
            log.info("unified: освобождены таблицы несуществующих "
                     "интерфейсов: %s" % ", ".join(freed), source="unified")
        return freed
    except Exception as e:
        log.debug("unified: освобождение таблиц: %s" % e, source="unified")
        return []


def _reassert_priority(route) -> list:
    """Переприменить пересекающиеся маршруты с бОльшим priority.

    В ядре из двух маршрутов на один адрес побеждает тот, чьи правила
    стоят в цепочке позже, то есть применённый последним. Чтобы решал
    priority, а не порядок правок, после сохранения маршрута те, что
    с ним пересекаются и стоят выше, раскладываются заново — по
    возрастанию priority, и последним в цепочке оказывается старший.
    """
    if not route.enabled:
        return []
    try:
        from core.unified.bulk import find_overlaps
        routes = {r.id: r for r in storage.load_routes()}
        rivals = set()
        for item in find_overlaps([r.to_dict() for r in routes.values()],
                                  resolve=True):
            if route.id in item["routes"]:
                rivals |= set(item["routes"]) - {route.id}
        higher = sorted((routes[rid] for rid in rivals
                         if rid in routes and routes[rid].enabled
                         and routes[rid].priority > route.priority),
                        key=_apply_order)
    except Exception as e:
        log.debug("unified: порядок по priority: %s" % e, source="unified")
        return []
    done = []
    for other in higher:
        try:
            applier.apply_route(other)
            done.append(other.id)
        except Exception as e:                  # noqa: BLE001 — граница
            log.warning("unified: переприменение %s по priority: %s"
                        % (other.id, e), source="unified")
    return done


def _apply_order(route):
    """Ключ порядка раскладки: старший priority — последним (побеждает)."""
    return (route.priority, route.created_at)


def _sync_monitor():
    """Поднять/остановить фоновый мониторинг по факту наличия маршрутов
    с включённым мониторингом/автопереключением."""
    try:
        from core.unified import monitor
        monitor.autostart_if_needed()
    except Exception:
        pass


def delete_route(route_id: str) -> dict:
    route = storage.get_route(route_id)
    if route is None:
        return {"ok": False, "error": "Маршрут не найден"}
    applier.remove_route(route)
    storage.remove_route(route_id)
    try:
        from core.unified import failover, monitor
        failover.reset(route_id)
        monitor.clear(route_id)
    except Exception:
        pass
    _sweep_dnsmasq("delete")
    prune_table_map()
    _sync_monitor()
    return {"ok": True, "id": route_id}


def _sweep_dnsmasq(what: str) -> None:
    """Остатки в dnsmasq (блок `# rule …`, `conf-file=`) — в том числе от
    маршрутов, удалённых раньше мимо этого пути, — сразу, а не только по
    кнопке «Переприменить». Иначе dnsmasq на каждом резолве домена пишет
    «nftset … No such file or directory» в набор, которого уже нет."""
    try:
        from core.routing import sweeper
        sweeper.sweep_dnsmasq()
    except Exception as e:
        log.warning("unified %s: dnsmasq: %s" % (what, e), source="unified")


def apply_route_by_id(route_id: str) -> dict:
    route = storage.get_route(route_id)
    if route is None:
        return {"ok": False, "error": "Маршрут не найден"}
    return applier.apply_route(route)


def apply_all() -> dict:
    res = applier.apply_all()
    _sync_monitor()
    return res


def reapply_all() -> dict:
    """
    Полное переприменение маршрутизации + сброс «левых» артефактов.

    Ручное «привести систему в соответствие с тем, что показано в GUI»:

      1. sweep — снимаем `ip rule`/set'ы/таблицы, за которыми не стоит
         ни одного правила (см. core/routing/sweeper). Первым шагом,
         чтобы протухший перехват не мешал свежим правилам;
      2. unified apply_all — каждый маршрут раскладывается заново
         (update_rule = снять старое + применить новое), домены при
         этом резолвятся заново;
      3. reapply низкоуровневых правил, НЕ производных от единого слоя
         (legacy без `uni-`-префикса) — их apply_all не трогает;
      4. будим рефрешер IP, чтобы не ждать его 10-минутного такта.

    Типичный случай: у туннеля поменяли AllowedIPs (или он переподнялся
    с другим набором подсетей) — правила остались прежними, но набор
    IP/таблица в ядре успели протухнуть.
    """
    out = {"ok": True}

    try:
        from core.routing import sweeper
        out["sweep"] = sweeper.sweep()
    except Exception as e:
        out["sweep"] = {"ok": False, "error": str(e)}
        log.warning("unified reapply: sweep: %s" % e, source="unified")

    out["applied"] = applier.apply_all()

    try:
        out["legacy"] = _reapply_legacy()
    except Exception as e:
        out["legacy"] = {"ok": False, "error": str(e)}
        log.warning("unified reapply: legacy: %s" % e, source="unified")

    try:
        from core.routing import domain_refresh
        domain_refresh.ensure_started()
        domain_refresh.kick()
    except Exception:
        pass

    out["tables_freed"] = prune_table_map()
    _sync_monitor()
    out["ok"] = all(
        (out.get(k) or {}).get("ok", True)
        for k in ("sweep", "applied", "legacy")
    )
    log.info("unified: маршрутизация переприменена (сброшено левых: %d)"
             % (out.get("sweep", {}).get("total") or 0), source="unified")
    return out


def _reapply_legacy() -> dict:
    """Снять и применить заново низкоуровневые правила вне единого слоя.

    Производные единого слоя (`uni-…`) пропускаем: их только что
    переприменил applier.apply_all(), повтор стоил бы второго резолва
    всех доменов.
    """
    from core.routing import get_routing_manager
    mgr = get_routing_manager()
    done, errors = [], []
    for rule in mgr.list_rules():
        if rule.id.startswith("uni-"):
            continue
        try:
            mgr.remove_applied_rule(rule.id)
            if rule.enabled:
                res = mgr.apply_rule(rule.id)
                done.append({"id": rule.id, "result": res})
        except Exception as e:
            errors.append("%s: %s" % (rule.id, e))
    return {"ok": not errors, "applied": done, "errors": errors}


# ─────── переприменение при смене содержимого списка ───────

# Маршрут хранит не домены, а ССЫЛКУ на список (named-list по id,
# `hl:<хостлист>`, `ipl:<ipset>`), а в ядро/dnsmasq уходит снимок его
# содержимого на момент apply. Раньше правка списка в GUI, его
# автообновление по URL и автодобавление детектора блокировок меняли
# только сам список: маршрут жил прежним снимком до ручного
# «Переприменить» или перезагрузки. Теперь каждое изменение списка
# зовёт notify_list_changed(), а маршруты, которые на него ссылаются,
# переприменяются — с задержкой, чтобы пачка правок (импорт, refresh-all)
# дала одно переприменение, а не десятки рестартов dnsmasq.
REAPPLY_DELAY_SEC = 3.0
# Выключатель для тестов (tests/conftest.py): отложенный поток иначе
# переприменял бы маршруты уже чужого теста.
AUTO_REAPPLY = True

_pending_refs = set()
_pending_lock = threading.Lock()
_pending_timer = None


def routes_using(refs) -> list:
    """Включённые маршруты, чьё назначение ссылается на любой из refs."""
    wanted = set(refs or [])
    if not wanted:
        return []
    return [r for r in storage.load_routes()
            if r.enabled and wanted.intersection(r.destination.list_ids)]


def reapply_routes_for(refs) -> dict:
    """Синхронно переприменить маршруты, зависящие от списков refs."""
    done = []
    for route in routes_using(refs):
        try:
            res = applier.apply_route(route)
        except Exception as e:                  # noqa: BLE001 — граница
            res = {"ok": False, "error": str(e)}
        done.append({"id": route.id, "result": res})
        log.info("unified: маршрут %s переприменён — изменился список"
                 % route.id, source="unified")
    return {"ok": all((d["result"] or {}).get("ok", True) for d in done),
            "applied": done}


def reapply_now(refs) -> dict:
    """Переприменить зависящие от списков маршруты сразу, а не по таймеру.

    Для правки из MCP: `zapret-gui mcp call` — короткий процесс, и
    отложенный поток notify_list_changed умирал вместе с ним, не успев
    сработать: домен добавлялся в список, а в dnsmasq/nft не попадал
    до ручного unified_route_apply. Заодно ответ правки может сказать,
    какие маршруты обновились.
    """
    refs = {str(r or "").strip() for r in refs or [] if r}
    with _pending_lock:
        _pending_refs.difference_update(refs)
    return reapply_routes_for(refs)


def notify_list_changed(ref: str) -> None:
    """Сообщить, что содержимое списка ref изменилось.

    ref — id named-list'а, `hl:<имя>` или `ipl:<имя>`. Переприменение
    откладывается на REAPPLY_DELAY_SEC и склеивает все ref'ы за это окно.
    """
    global _pending_timer
    ref = str(ref or "").strip()
    if not ref or not AUTO_REAPPLY:
        return
    with _pending_lock:
        _pending_refs.add(ref)
        if _pending_timer is not None:
            return
        t = threading.Timer(REAPPLY_DELAY_SEC, _flush_pending)
        t.daemon = True
        _pending_timer = t
    t.start()


def _flush_pending() -> None:
    global _pending_timer
    with _pending_lock:
        refs = set(_pending_refs)
        _pending_refs.clear()
        _pending_timer = None
    if not refs:
        return
    try:
        reapply_routes_for(refs)
    except Exception as e:                      # noqa: BLE001 — фоновый поток
        log.warning("unified: переприменение после смены списка: %s" % e,
                    source="unified")


def _safe_can_probe(monitor, route) -> bool:
    try:
        return monitor.can_probe(route)
    except Exception:
        return True


def _iface_missing(method: str) -> str:
    """Интерфейс туннельного метода, которого сейчас нет в системе, или ''."""
    from core.unified.model import iface_present, is_tunnel_method, \
        method_iface
    if not is_tunnel_method(method):
        return ""
    iface = method_iface(method)
    return "" if iface_present(iface) else iface


def _router_devices(route) -> list:
    """Одиночные адреса устройств маршрута, принадлежащие самому роутеру.

    Правило `from <адрес роутера>` уводит в туннель ответы роутера — и
    веб-интерфейс перестаёт открываться из LAN; шлюз провайдера через
    LAN не ходит вовсе. Подсети не трогаем: у них свои исключения.
    """
    if not route.devices:
        return []
    try:
        from core.devices_discovery import router_addresses
        own = router_addresses()
    except Exception:
        return []
    return [d["ip"] for d in route.devices
            if "/" not in d["ip"] and d["ip"] in own]


def _device_drift(route, macs) -> list:
    """Устройства маршрута, которым DHCP с тех пор выдал другой адрес.

    Правило устройства — `ip rule from <ip>`: сменился адрес — трафик
    устройства молча пошёл мимо туннеля. MAC мы запоминаем при выборе
    устройства, по нему и сверяемся. Нет MAC или устройство сейчас не
    видно в сети — молчим: это не рассинхрон, а просто нет данных.
    """
    if not macs or not route.devices:
        return []
    out = []
    for dev in route.devices:
        mac = (dev.get("mac") or "").strip().lower()
        now_ip = macs.get(mac) if mac else ""
        if now_ip and now_ip != dev.get("ip"):
            out.append({"ip": dev.get("ip", ""), "now_ip": now_ip,
                        "mac": mac, "hostname": dev.get("hostname", "")})
    return out


def status() -> dict:
    """Сводка для UI: маршруты + успешность + активный метод + подсказки."""
    from core.unified import monitor, failover, scanner_hint
    routes = storage.load_routes()
    mon = monitor.stats()
    macs = None
    if any(r.devices for r in routes):
        try:
            from core.devices_discovery import mac_ip_map
            macs = mac_ip_map()
        except Exception:
            macs = None
    out = []
    for r in routes:
        rid = r.id
        active = failover.current_method(rid) or r.method
        suggestion = {}
        try:
            suggestion = scanner_hint.suggest_for_route(r)
        except Exception:
            suggestion = {}
        missing = _iface_missing(active)
        mon_row = dict(mon.get(rid, {}) or {})
        if missing and mon_row:
            # Последний замер мог пройти, пока интерфейс был (или мимо
            # него — собственная проба роутера идёт по его таблицам).
            # Сейчас метод заведомо не работает: показывать rate 1.0 и
            # last_ok как текущее здоровье нельзя.
            mon_row["stale"] = True
            mon_row["healthy"] = False
        out.append({
            "id": rid, "name": r.name, "enabled": r.enabled,
            "method": r.method, "active_method": active,
            "fallbacks": r.fallbacks,
            "monitor_enabled": r.monitor_enabled,
            "failover_enabled": r.failover_enabled,
            "monitor": mon_row,
            "suggest_scan": suggestion.get("suggest", False),
            "suggest_reason": suggestion.get("reason", ""),
            "probeable": _safe_can_probe(monitor, r),
            "iface_missing": missing,
            "device_drift": _device_drift(r, macs),
        })
    return {"ok": True, "routes": out,
            "monitor_running": monitor.get_monitor().running()}
