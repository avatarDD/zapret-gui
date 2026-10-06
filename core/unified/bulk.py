# core/unified/bulk.py
"""
Работа со многими маршрутами сразу: проверка содержимого, пересечения,
массовые действия, экспорт и импорт (приёмы MagiTrickle).

* :func:`validate_destination` — домены, шаблоны и CIDR назначения
  проверяются при сохранении: раньше домены лишь приводились к нижнему
  регистру, и опечатка («youtube,com», «https://…») молча ложилась в
  settings.json, а dnsmasq/NDMS её потом отбрасывали;
* :func:`find_overlaps` — один и тот же домен (или домен и его
  поддомен, CIDR и вложенная в него сеть, один и тот же список) в
  нескольких маршрутах. Какой маршрут победит, решает порядок правил в
  ядре, а не пользователь, — такие места надо видеть;
* :func:`bulk` — включить / выключить / удалить / сменить метод у
  выбранных маршрутов одним запросом;
* :func:`export_routes` / :func:`import_routes` — файл с маршрутами
  (выборочно, с добавлением или заменой).
"""

import ipaddress
import time

from core.log_buffer import log


EXPORT_FORMAT = "zapret-gui/unified-routes"
EXPORT_VERSION = 1

_ALIAS_PREFIXES = ("geosite:", "geoip:")


# ─────────────────────── проверка ────────────────────────────────────

def validate_destination(dest: dict) -> list:
    """Ошибки назначения маршрута: ['строка: причина', …]. Чистая."""
    from core.routing import domain_match
    errors = []
    dest = dest or {}
    from core.routing.alias_resolver import _looks_like_ip
    for entry in dest.get("domains") or []:
        e = str(entry or "").strip()
        if not e or e.lower().startswith(_ALIAS_PREFIXES):
            continue
        if not domain_match.is_pattern(e) and ("/" in e or _looks_like_ip(e)):
            # Адрес в поле доменов движок принимает как CIDR
            # (alias_resolver.expand_domains) — проверяем как сеть.
            try:
                ipaddress.ip_network(e, strict=False)
            except ValueError:
                errors.append("%s: не IP-адрес и не подсеть" % e)
            continue
        why = domain_match.validate_entry(e)
        if why:
            errors.append("%s: %s" % (e, why))
    for entry in dest.get("cidrs") or []:
        e = str(entry or "").strip()
        if not e:
            continue
        try:
            ipaddress.ip_network(e, strict=False)
        except ValueError:
            errors.append("%s: не IP-адрес и не подсеть" % e)
    return errors


# ─────────────────────── пересечения ─────────────────────────────────

def find_overlaps(routes: list) -> list:
    """Пересечения назначений включённых маршрутов. Чистая.

    routes — список dict (UnifiedRoute.to_dict()). Возвращает
    [{kind: domain|subdomain|cidr|list, value, other, routes: [id, id]}].
    """
    from core.routing import domain_match
    enabled = [r for r in routes or [] if r.get("enabled", True)]
    out = []
    seen = set()

    def _add(kind, value, other, ids):
        ids = sorted(set(ids))
        if len(ids) < 2:
            return
        key = (kind, value, other, tuple(ids))
        if key in seen:
            return
        seen.add(key)
        out.append({"kind": kind, "value": value, "other": other,
                    "routes": ids})

    # Домены: точные дубли и «домен ↔ поддомен».
    owners = {}
    for r in enabled:
        dest = r.get("destination") or {}
        for d in domain_match.plain_domains(dest.get("domains")):
            owners.setdefault(d, set()).add(r["id"])
    for d, ids in owners.items():
        if len(ids) > 1:
            _add("domain", d, "", ids)
        parent = d
        while "." in parent:
            parent = parent.split(".", 1)[1]
            if parent in owners:
                for a in ids:
                    for b in owners[parent]:
                        if a != b:
                            _add("subdomain", d, parent, [a, b])

    # CIDR: одинаковые и вложенные сети.
    nets = []
    for r in enabled:
        for c in (r.get("destination") or {}).get("cidrs") or []:
            try:
                nets.append((ipaddress.ip_network(str(c).strip(),
                                                  strict=False), r["id"]))
            except ValueError:
                continue
    for i, (na, ra) in enumerate(nets):
        for nb, rb in nets[i + 1:]:
            if ra == rb or na.version != nb.version:
                continue
            if na == nb:
                _add("cidr", str(na), "", [ra, rb])
            elif na.subnet_of(nb):
                _add("cidr", str(na), str(nb), [ra, rb])
            elif nb.subnet_of(na):
                _add("cidr", str(nb), str(na), [ra, rb])

    # Один и тот же список в нескольких маршрутах.
    lists = {}
    for r in enabled:
        for lid in (r.get("destination") or {}).get("list_ids") or []:
            lists.setdefault(lid, set()).add(r["id"])
    for lid, ids in lists.items():
        _add("list", lid, "", ids)
    return out


# ─────────────────────── массовые действия ───────────────────────────

ACTIONS = ("enable", "disable", "delete", "set_method")


def bulk(ids, action: str, method: str = "") -> dict:
    """Применить действие к маршрутам; ошибки — по каждому отдельно."""
    from core.unified import manager, storage
    if action not in ACTIONS:
        return {"ok": False, "error": "неизвестное действие: %s" % action}
    if action == "set_method":
        from core.unified.model import parse_method
        try:
            parse_method(method)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
    done, errors = [], []
    for rid in [str(x) for x in ids or [] if x]:
        route = storage.get_route(rid)
        if route is None:
            errors.append({"id": rid, "error": "не найден"})
            continue
        if action == "delete":
            res = manager.delete_route(rid)
        else:
            data = route.to_dict()
            if action in ("enable", "disable"):
                data["enabled"] = action == "enable"
            else:
                data["method"] = method
            res = manager.save_route(data)
        if res.get("ok"):
            done.append(rid)
        else:
            errors.append({"id": rid, "error": res.get("error", "?")})
    log.info("unified: массовое «%s» — %d маршрутов, ошибок %d"
             % (action, len(done), len(errors)), source="unified")
    return {"ok": not errors, "done": done, "errors": errors}


# ─────────────────────── экспорт / импорт ────────────────────────────

def export_routes(ids=None) -> dict:
    from core.unified import storage
    wanted = set(ids or [])
    routes = [r.to_dict() for r in storage.load_routes()
              if not wanted or r.id in wanted]
    return {"format": EXPORT_FORMAT, "version": EXPORT_VERSION,
            "exported_at": int(time.time()), "routes": routes}


def import_routes(payload, mode: str = "add", ids=None) -> dict:
    """Импорт файла экспорта.

    mode='add' — маршрут с занятым id получает новый id (копия);
    mode='replace' — маршрут с тем же id перезаписывается.
    ids — выбрать из файла только эти маршруты (пусто — все).
    """
    from core.unified import manager, storage
    if isinstance(payload, dict):
        if payload.get("format") not in (None, EXPORT_FORMAT):
            return {"ok": False, "error": "это не файл маршрутов zapret-gui"}
        items = payload.get("routes")
    else:
        items = payload
    if not isinstance(items, list):
        return {"ok": False, "error": "в файле нет списка маршрутов"}
    if mode not in ("add", "replace"):
        return {"ok": False, "error": "mode: add | replace"}
    wanted = set(ids or [])
    existing = {r.id for r in storage.load_routes()}
    imported, errors = [], []
    for item in items:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("id") or "")
        if wanted and rid not in wanted:
            continue
        data = dict(item)
        if mode == "add" and rid in existing:
            data["id"] = ""                 # новый id — копия
        res = manager.save_route(data, validate=True)
        if res.get("ok"):
            imported.append(res["route"]["id"])
        else:
            errors.append({"id": rid, "name": item.get("name", ""),
                           "error": res.get("error", "?")})
    return {"ok": not errors, "imported": imported, "errors": errors}
