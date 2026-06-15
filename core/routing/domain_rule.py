# core/routing/domain_rule.py
"""
Логика применения и снятия domain-based routing-правил.

На Keenetic'е с доступным RCI мы используем штатный NDMS-механизм
(`object-group fqdn` + `dns-proxy route`) — он работает с системным
ndnsproxy на 53-м порту и не требует ни dnsmasq, ни ipset/nftset, ни
fwmark. См. `core/routing/ndms_backend.py`.

На остальных платформах работаем по старой схеме через dnsmasq+
ipset/nftset+fwmark:

  apply:
    1. Выбрать backend (nftset, если dnsmasq поддерживает и nft есть;
       иначе ipset).
    2. Создать пустой именованный set <set_name>.
    3. Добавить mark-правило в firewall (mark = mark_for(rule)).
    4. Добавить ip rule fwmark <mark> lookup <table_for(iface)>.
    5. Гарантировать default-маршрут в таблице.
    6. Перегенерить managed dnsmasq-файл + SIGHUP.

  remove:
    Симметрично: удаляем ip rule, mark-правило, set, перегенерим
    managed-файл, SIGHUP dnsmasq.

Файл собирается из ВСЕХ активных domain-правил, поэтому apply/remove
одного правила всегда вызывают full rewrite managed-файла.
"""

import threading

from core.log_buffer import log
from core.routing import dnsmasq_integration
from core.routing import ipset_backend
from core.routing import nftset_backend
from core.routing.rules import DomainRoutingRule


def _ndms_available() -> bool:
    """
    Можно ли применить правило через Keenetic NDMS-backend.

    Гейтит ВЕСЬ NDMS-путь: эта функция должна вернуть False на
    OpenWrt / generic Linux / Entware-не-Keenetic — там в наличие RCI
    мы даже не лезем. На Keenetic'е без RCI (например, если порт
    закрыт фаерволлом или версия прошивки старая) — тоже False, и мы
    откатываемся на стандартный dnsmasq-путь, который, впрочем, на
    Keenetic'е тоже толком не работает (53 порт занят) — но это всё
    лучше тихого выпадения.
    """
    try:
        from core.ndms import is_ndms_available
        return bool(is_ndms_available())
    except Exception:
        return False


# Базовый приоритет ip rule fwmark — выше CIDR, чтобы маркированный
# трафик уходил в туннель раньше per-CIDR-правил.
FWMARK_PRIORITY = 10100


_lock = threading.Lock()


# ───────────────────────── helpers ──────────────────────────────────

def _table_id_for(ifname: str) -> int:
    """Совпадает с RoutingManager.table_id_for / awg_manager._table_id_for."""
    h = 0
    for ch in ifname:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 100 + (h % 900)


def _mark_for(rule_id: str) -> int:
    """
    Уникальный mark для каждого правила в диапазоне 0x10000..0x1FFFF.
    Не пересекается с типовыми пользовательскими марками (0..0xFFFF).
    """
    h = 0
    for ch in rule_id:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 0x10000 + (h & 0xFFFF)


def _backend_for(prefer_nft: bool):
    """Вернуть модуль-бэкенд (nftset_backend или ipset_backend) или None."""
    if prefer_nft and nftset_backend.available():
        return nftset_backend
    if ipset_backend.available():
        return ipset_backend
    if nftset_backend.available():
        return nftset_backend
    return None


def _detect_backend():
    """
    Подбираем бэкенд исходя из того, что поддерживает dnsmasq.

    Возвращает (backend_module, set_kind_str) или (None, '').
    """
    dn = dnsmasq_integration.DnsmasqIntegration()
    supports_nftset = dn.supports_nftset()

    backend = _backend_for(prefer_nft=supports_nftset)
    if backend is None:
        return None, ""
    kind = "nftset" if backend is nftset_backend else "ipset"
    return backend, kind


def _all_domain_rules():
    """Все enabled DomainRoutingRule из storage."""
    from core.routing import storage
    return [r for r in storage.load_rules()
            if isinstance(r, DomainRoutingRule) and r.enabled]


def _expand_rule_domains(rule):
    """
    Развернуть geosite:/geoip: алиасы в чистые домены/CIDR.

    Для dnsmasq-пути нас интересуют только домены (CIDR не работают
    через dnsmasq-ipset-хук). Если в правиле встречается geoip: —
    он логируется как «не поддержано», но правило не падает.
    """
    from core.routing.alias_resolver import expand_domains as _ex
    expanded = _ex(rule.domains or [])
    domains = expanded.get("domains") or []
    if expanded.get("cidrs"):
        log.warning(
            "dnsmasq-backend: geoip: в правиле %s даёт %d CIDR — "
            "dnsmasq их не поддерживает, см. NDMS-режим или CIDR-rule"
            % (rule.id, len(expanded["cidrs"])),
            source="routing")
    return domains


def _rebuild_managed_dnsmasq():
    """Перегенерить managed-файл по всем активным domain-правилам."""
    dn = dnsmasq_integration.DnsmasqIntegration()
    supports_nftset = dn.supports_nftset()
    set_kind = "nftset" if supports_nftset else "ipset"

    blocks = []
    for r in _all_domain_rules():
        domains = _expand_rule_domains(r)
        if not domains:
            continue
        blocks.append({
            "rule_id":    r.id,
            "set_kind":   set_kind,
            "set_name":   _set_name_for(r.id, set_kind),
            "nft_table":  nftset_backend.TABLE_NAME,
            "nft_family": "inet",
            "domains":    domains,
        })

    dn.ensure_include()
    write_res = dn.write_managed_file(blocks)
    if not write_res.get("ok"):
        log.warning("dnsmasq managed-file: %s" % write_res.get("error"),
                    source="routing")
        return write_res
    reload_res = dn.reload()
    return {"ok": write_res.get("ok") and reload_res.get("ok"),
            "wrote":  write_res,
            "reload": reload_res}


def _set_name_for(rule_id: str, kind: str) -> str:
    if kind == "nftset":
        return nftset_backend.set_name_for(rule_id)
    return ipset_backend.set_name_for(rule_id)


def _iface_exists(ifname: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(["ip", "link", "show", "dev", ifname],
                           capture_output=True, timeout=3)
        return r.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _iface_has_family(ifname: str, ip_fam: str) -> bool:
    """
    Есть ли у интерфейса глобальный адрес заданного семейства
    (`ip_fam` = '-4' | '-6'). Нужно, чтобы не считать ошибкой
    отсутствие v6-маршрута на чисто-v4 туннеле (типичный AWG/WARP
    без IPv6): v4-туннель не может нести v6-трафик, и domain-правило
    должно деградировать мягко (роутим то, что можем), а не падать.
    """
    import subprocess
    try:
        r = subprocess.run(["ip", ip_fam, "-o", "addr", "show", "dev",
                            ifname, "scope", "global"],
                           capture_output=True, text=True, timeout=3)
        return r.returncode == 0 and bool((r.stdout or "").strip())
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


# Pre-population — оптимизация (dnsmasq добьёт set лениво по libc-запросам).
# Ограничиваем число доменов и распараллеливаем резолвы: без этого
# geosite-алиас (десятки тысяч доменов) под _lock делал бы по 2 блокирующих
# DNS+subprocess на каждый домен и вешал routing-API на минуты.
_PREPOP_MAX_DOMAINS = 500     # как и NDMS-путь; остальное — лениво
_PREPOP_WORKERS = 8


def _prepopulate_domains(domains, set_v4, set_v6, backend) -> list:
    """Pre-populate v4+v6 set'ы для списка доменов ограниченным пулом.

    `_prepopulate_set` независим (резолв + идемпотентные ipset/nft add без
    общего состояния), поэтому вызовы безопасно идут параллельно — это
    ограничивает суммарное время даже при медленном/глухом резолвере.
    """
    import concurrent.futures
    tasks = []
    for d in domains:
        tasks.append((set_v4, d, "v4"))
        tasks.append((set_v6, d, "v6"))
    if not tasks:
        return []
    results = []
    workers = min(_PREPOP_WORKERS, len(tasks))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_prepopulate_set, s, d, f, backend)
                for (s, d, f) in tasks]
        for fu in concurrent.futures.as_completed(futs):
            try:
                results.append(fu.result())
            except Exception as e:
                results.append({"ok": False, "added": 0, "error": str(e)})
    return results


def _prepopulate_set(set_name: str, domain: str, family: str,
                     backend) -> dict:
    """
    Резолвим домен и кладём IP'шники в set СРАЗУ — без ожидания того,
    что какой-то софт сделает DNS-запрос через dnsmasq.

    Зачем: dnsmasq заполняет set ТОЛЬКО когда видит query, а браузеры
    с DoH (Firefox/Chrome) уходят мимо системного резолвера прямиком
    в Cloudflare DoH. dnsmasq никогда не видит query → set пуст →
    трафик не маркируется → не маршрутизируется через AWG. У curl и
    `dig` такой проблемы нет (они идут через libc → /etc/resolv.conf →
    dnsmasq), но проверяет пользователь обычно браузером.

    Pre-population работает «на сейчас»: на момент apply мы резолвим
    домен и заносим IP. Если IP позже сменится (CDN, rotation) — про
    это узнает либо dnsmasq при следующем libc-запросе, либо новый
    apply правила.

    Источник резолва:
      - если в settings включён `routing.doh` — берём IP через
        DoH-провайдер (обходит ISP-подмену и DPI на :53);
      - иначе — fallback на системный `socket.getaddrinfo()`.
    """
    ips = []
    src = "getaddrinfo"
    try:
        from core.routing import doh_resolver
        if doh_resolver.is_enabled():
            r = doh_resolver.resolve(domain, family=family)
            if r.get("ok"):
                ips = sorted(set(r.get("ips") or []))
                src = "doh:%s" % (r.get("provider") or "?")
    except Exception as e:
        log.warning("doh prepopulate %s: %s" % (domain, e),
                    source="routing")

    if not ips:
        # Либо DoH выключен, либо он не ответил — фолбэк на libc.
        import socket
        af = socket.AF_INET6 if family == "v6" else socket.AF_INET
        try:
            addrinfos = socket.getaddrinfo(
                domain, None, af, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return {"ok": False, "added": 0, "domain": domain,
                    "family": family, "error": "resolve failed"}
        ips = sorted({a[4][0] for a in addrinfos if a and a[4]})
    if not ips:
        return {"ok": True, "added": 0, "domain": domain,
                "family": family}

    import subprocess
    added = 0
    for ip in ips:
        if backend is nftset_backend:
            cmd = ["nft", "add", "element", "inet",
                   nftset_backend.TABLE_NAME, set_name,
                   "{ %s }" % ip]
        else:
            cmd = ["ipset", "add", set_name, ip, "-exist"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=3)
            if r.returncode == 0 or "exist" in (r.stderr or "").lower():
                added += 1
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return {"ok": True, "added": added, "domain": domain,
            "family": family, "ips": ips, "resolver": src}


def _ensure_table_default(ifname: str, table: int, family: str) -> bool:
    """Гарантировать default-route в таблице (то же, что в manager._ensure_table_default)."""
    import subprocess
    try:
        r = subprocess.run(["ip", family, "route", "show", "table",
                            str(table), "default"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout:
            for line in r.stdout.splitlines():
                parts = line.split()
                if "dev" in parts:
                    i = parts.index("dev")
                    if i + 1 < len(parts) and parts[i + 1] == ifname:
                        return True
        r = subprocess.run(["ip", family, "route", "add", "default",
                            "dev", ifname, "table", str(table)],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 or "File exists" in (r.stderr or ""):
            return True
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return False


# ───────────────────────── public API ───────────────────────────────

def _is_native_ndms_iface(ifname: str) -> bool:
    """NDMS-нативный интерфейс? (lazy-импорт, чтобы не зациклить manager)."""
    try:
        from core.routing.manager import _is_ndms_native_iface
        return bool(_is_ndms_native_iface(ifname))
    except Exception:
        return False


def _resolve_ips(domain: str, family: str) -> list:
    """
    Резолв домена в список IP. Сначала DoH (если включён — обходит
    DNS-подмену провайдера), иначе системный getaddrinfo.
    """
    ips = []
    try:
        from core.routing import doh_resolver
        if doh_resolver.is_enabled():
            r = doh_resolver.resolve(domain, family=family)
            if r.get("ok"):
                ips = sorted(set(r.get("ips") or []))
    except Exception:
        pass
    if not ips:
        import socket
        af = socket.AF_INET6 if family == "v6" else socket.AF_INET
        try:
            ai = socket.getaddrinfo(domain, None, af, socket.SOCK_STREAM)
            ips = sorted({a[4][0] for a in ai if a and a[4]})
        except (socket.gaierror, OSError):
            ips = []
    return ips


def _iproute_state_load() -> dict:
    """Состояние domain-iproute: {rule_id: [[cidr, '-4'|'-6'], ...]}."""
    try:
        from core.config_manager import get_config_manager
        st = get_config_manager().get("routing", "domain_iproute",
                                      default={}) or {}
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _iproute_state_save(state: dict) -> None:
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("routing", "domain_iproute", state)
        cm.save()
    except Exception as e:
        log.warning("routing: сохранение domain_iproute: %s" % e,
                    source="routing")


def _apply_domain_via_iproute(rule: DomainRoutingRule) -> dict:
    """
    Доменное правило для userspace-туннеля (singbox-tun / amneziawg / WARP):
    резолвим домены в IP и кладём их в таблицу интерфейса через
    `ip rule add to <ip> lookup <table>` — ровно как CIDR-правило. Нужно,
    потому что NDMS `dns-proxy route` умеет привязывать домены ТОЛЬКО к
    нативным интерфейсам Keenetic, а dnsmasq+ipset на Keenetic не поднять
    (53-й порт занят ndnsproxy).

    Минус против dnsmasq/NDMS: нет динамического обновления при смене IP
    (CDN-ротация) — IP фиксируются на момент применения. Чистый резолв
    зависит от DoH (см. _resolve_ips); при подмене провайдером IP будут
    неверными — поэтому для блокируемых доменов держите routing.doh вкл.
    """
    import subprocess
    ifname = rule.target_iface
    if not _iface_exists(ifname):
        return {"ok": True, "deferred": True, "backend": "iproute",
                "message": "Интерфейс %s ещё не поднят — домены"
                           " разрешатся и применятся при старте" % ifname}

    table = _table_id_for(ifname)
    domains = _expand_rule_domains(rule)
    if not domains:
        return {"ok": False, "error": "после развёртки доменов не осталось"}

    added = []          # [[cidr, family], ...] для хранения/снятия
    errors = []
    resolved_total = 0
    for domain in domains:
        for fam in ("v4", "v6"):
            ips = _resolve_ips(domain, fam)
            if not ips:
                continue
            resolved_total += len(ips)
            family = "-6" if fam == "v6" else "-4"
            if not _ensure_table_default(ifname, table, family):
                errors.append("default-route %s table %d" % (family, table))
                continue
            for ip in ips:
                cidr = ip + ("/128" if fam == "v6" else "/32")
                subprocess.run(["ip", family, "rule", "del", "to", cidr,
                                "lookup", str(table)],
                               capture_output=True, timeout=5)
                r = subprocess.run(["ip", family, "rule", "add", "to", cidr,
                                    "lookup", str(table),
                                    "priority", str(FWMARK_PRIORITY)],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    added.append([cidr, family])
                elif "File exists" not in (r.stderr or ""):
                    errors.append("ip rule add %s: %s"
                                  % (cidr, (r.stderr or "").strip()))

    if added:
        from core.routing import masquerade
        masquerade.ensure_for_iface(ifname)

    # Сохраняем применённые маршруты для корректного снятия.
    state = _iproute_state_load()
    state[rule.id] = added
    _iproute_state_save(state)

    log.info("routing: domain-правило %s применено через ip-route (iface=%s,"
             " %d IP, %d ошибок)"
             % (rule.id, ifname, len(added), len(errors)), source="routing")
    return {
        "ok": bool(added) or resolved_total == 0,
        "backend": "iproute",
        "iface": ifname,
        "ips_added": len(added),
        "errors": errors,
        "note": ("домены разрешены в IP на момент применения; при смене IP"
                 " (CDN) примените правило заново"),
    }


def _remove_domain_via_iproute(rule: DomainRoutingRule) -> dict:
    """Снять domain-правило, применённое через ip-route."""
    import subprocess
    table = _table_id_for(rule.target_iface)
    state = _iproute_state_load()
    entries = state.pop(rule.id, [])
    for entry in entries:
        try:
            cidr, family = entry[0], entry[1]
        except (TypeError, IndexError, ValueError):
            continue
        subprocess.run(["ip", family, "rule", "del", "to", cidr,
                        "lookup", str(table)], capture_output=True, timeout=5)
    _iproute_state_save(state)
    try:
        from core.routing import masquerade
        masquerade.remove_if_unused(rule.target_iface, excluding_id=rule.id)
    except Exception:
        pass
    log.info("routing: domain-правило %s (ip-route) снято, %d маршрутов"
             % (rule.id, len(entries)), source="routing")
    return {"ok": True, "backend": "iproute", "removed": len(entries)}


def apply_domain_rule(rule: DomainRoutingRule) -> dict:
    """Применить одно domain-правило."""
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}
    if not rule.domains:
        return {"ok": False, "error": "Список доменов пуст"}

    # ── Keenetic NDMS-fast-path ─────────────────────────────────
    # Если детект сказал «это Keenetic + RCI отвечает» — идём
    # через нативный dns-proxy route. Никаких dnsmasq/ipset/fwmark
    # для этого пути не требуется. На любых других платформах
    # _ndms_available() == False и эта ветка пропускается.
    # ВАЖНО: NDMS `dns-proxy route` привязывает домены ТОЛЬКО к нативным
    # NDMS-интерфейсам (Wireguard0/ISP/…). Для НАШИХ userspace-туннелей
    # (singbox-tun, amneziawg/awg, WARP) NDMS такой iface не видит — правило
    # «применяется», но трафик идёт мимо (см. issue: «по IP работает, по
    # доменам нет»). Поэтому NDMS-путь только для нативных интерфейсов; для
    # userspace уходим ниже (dnsmasq или ip-route).
    if _ndms_available() and _is_native_ndms_iface(rule.target_iface):
        try:
            from core.routing import ndms_backend
            return ndms_backend.apply_domain_rule(rule)
        except Exception as e:
            log.warning("routing(ndms): apply упал, fallback на dnsmasq: %s"
                        % e, source="routing")

    with _lock:
        # Preflight: domain-routing работает ТОЛЬКО через dnsmasq —
        # он отвечает за заполнение ipset/nftset при резолве. Если
        # dnsmasq не установлен или не запущен, set останется пустым,
        # а firewall-хуки в mangle уже создадутся «вхолостую». На
        # Debian/Ubuntu, где штатный резолвер — systemd-resolved,
        # это типичный сценарий: до правок мы успевали навешать
        # nft/ipset rules и поломать пользователю DNS (SIGHUP при
        # перегенерации managed-файла попадал в чужой dnsmasq или
        # завершался ошибкой). Лучше упасть до любых side-effects.
        dn = dnsmasq_integration.DnsmasqIntegration()
        dn_status = dn.status()
        if not (dn_status.get("available") and dn_status.get("running")):
            # dnsmasq нет/не запущен (типичный Keenetic: 53-й порт у ndnsproxy,
            # а интерфейс userspace, т.е. NDMS-путь выше не подошёл). Доменное
            # routing через ipset невозможно — резолвим домены и кладём IP в
            # таблицу интерфейса напрямую (ip rule), как CIDR. Динамики при
            # смене IP нет, но для большинства доменов работает.
            return _apply_domain_via_iproute(rule)

        backend, kind = _detect_backend()
        if backend is None:
            return {"ok": False,
                    "error": "Нет доступного бэкенда (ipset/nftables)"}

        # Миграция nft: до v0.19.21 цепочка output создавалась как
        # type=filter — она НЕ триггерит реререйт после изменения mark,
        # поэтому пакеты уходили через WAN, не попадая на AWG. Если
        # обнаружили старый тип — _ensure_table_and_chains внутри
        # backend'а удалит таблицу и пересоздаст. Но это снимет nft
        # state и соседних domain-правил, которые лежат в storage.
        # Поэтому переразложим их вручную после миграции.
        need_repave_neighbors = (
            backend is nftset_backend and nftset_backend.needs_migration()
        )

        ifname = rule.target_iface
        if not _iface_exists(ifname):
            # Регистрируем правило в managed-файле, чтобы dnsmasq
            # уже сейчас собирал IP. Полное применение случится при
            # подъёме интерфейса (хук applier).
            res = _rebuild_managed_dnsmasq()
            return {"ok": True, "deferred": True,
                    "message": "Интерфейс %s не поднят — dnsmasq-часть"
                               " активирована, остальное при старте" % ifname,
                    "dnsmasq": res,
                    "backend": kind}

        table = _table_id_for(ifname)
        mark  = _mark_for(rule.id)
        set_name = _set_name_for(rule.id, kind)

        errors = []
        added  = []

        # ── создаём set'ы и mark-правила (v4 + v6) ──
        for fam in ("v4", "v6"):
            r1 = backend.create_set(set_name + ("6" if fam == "v6" else ""), family=fam)
            if not r1.get("ok"):
                errors.append("create_set %s: %s" % (fam, r1.get("error")))
                continue

            r2 = backend.setup_mark_rule(
                r1["name"], mark, family=fam)
            if not r2.get("ok"):
                errors.extend(r2.get("errors") or [r2.get("error", "?")])
                continue

            ip_fam = "-6" if fam == "v6" else "-4"
            if not _ensure_table_default(ifname, table, ip_fam):
                # Туннель без адреса этого семейства (например, чисто-v4
                # WARP без IPv6) физически не может нести такой трафик —
                # это не ошибка правила: set уже создан (dnsmasq спокойно
                # добавит в него A/AAAA), а v6-трафик просто пойдёт напрямую.
                # Падаем только если адрес есть, а маршрут всё равно не лёг.
                if not _iface_has_family(ifname, ip_fam):
                    log.info("routing(domain): у %s нет адреса %s — leg %s"
                             " пропущен (трафик пойдёт напрямую)"
                             % (ifname, ip_fam, fam), source="routing")
                    continue
                errors.append("default-route v%s в table %d не создан"
                              % (fam[1:], table))
                continue

            r3 = backend.add_ip_rule_fwmark(
                mark, table, family=fam, priority=FWMARK_PRIORITY)
            if not r3.get("ok"):
                errors.append("ip rule fwmark %s: %s" %
                              (fam, r3.get("error")))
                continue

            # MASQUERADE на исходящий AWG-iface: без него пакеты,
            # перенаправленные через fwmark уже после первой маршрутной
            # выборки, уходят через AWG с src=WAN_IP. AWG-сервер дропает
            # такие пакеты по AllowedIPs клиента — и весь domain-routing
            # «работает на бумаге», IP-list работает только потому что
            # для CIDR-правил route lookup и так попадает в таблицу AWG
            # сразу и src сразу выбирается с AWG. См. подробный
            # комментарий в backend.ensure_iface_masquerade().
            from core.routing import masquerade
            mq = masquerade.ensure_for_iface(ifname, families=(fam,))
            if not mq.get("ok"):
                errors.append("masquerade %s: %s" %
                              (fam, mq.get("error")))
                continue

            added.append({"family": fam, "set": r1["name"],
                          "mark": mark, "table": table})

        # Если выше дёрнули миграцию nft-таблицы — соседние domain-rules,
        # лежавшие в той же таблице, потеряли свой nft-state. Восстановим:
        # пере-создадим set + mark-правила + masquerade для каждого. Сам
        # ip rule fwmark и default-route в table N — на уровне kernel-
        # routing, не nft, миграция их не трогает.
        if need_repave_neighbors:
            for other in _all_domain_rules():
                if other.id == rule.id:
                    continue
                if not _iface_exists(other.target_iface):
                    continue
                o_mark  = _mark_for(other.id)
                o_table = _table_id_for(other.target_iface)
                o_setbase = _set_name_for(other.id, kind)
                for fam in ("v4", "v6"):
                    o_set = o_setbase + ("6" if fam == "v6" else "")
                    backend.create_set(o_set, family=fam)
                    backend.setup_mark_rule(o_set, o_mark, family=fam)
                    ip_fam = "-6" if fam == "v6" else "-4"
                    _ensure_table_default(other.target_iface, o_table, ip_fam)
                    backend.add_ip_rule_fwmark(
                        o_mark, o_table, family=fam,
                        priority=FWMARK_PRIORITY)
                from core.routing import masquerade as _masq
                _masq.ensure_for_iface(other.target_iface)
            log.info("nft migration: переразложено %d соседних domain-правил"
                     % max(0, len(_all_domain_rules()) - 1),
                     source="routing")

        dn_res = _rebuild_managed_dnsmasq()

        # Pre-population: набиваем set'ы IP'шниками доменов прямо сейчас.
        # Без этого браузер с DoH идёт мимо dnsmasq, set остаётся пустым,
        # трафик не маркируется. Делаем после _rebuild_managed_dnsmasq —
        # чтобы dnsmasq уже знал директиву (на случай гонки), а ТЕПЕРЬ
        # ещё и кладём IP сами через nft/ipset, не дожидаясь, пока кто-то
        # сделает резолв через libc.
        set_base_v4 = _set_name_for(rule.id, kind)
        set_base_v6 = set_base_v4 + "6"
        # Разворачиваем алиасы (geosite:) — без этого браузер с DoH
        # никогда не запросит youtube.com у dnsmasq, и pre-populate
        # этих доменов критичен для работы пути на не-Keenetic.
        # Но кап + пул: иначе огромный алиас вешал бы apply под _lock.
        prepop_domains = _expand_rule_domains(rule)
        if len(prepop_domains) > _PREPOP_MAX_DOMAINS:
            log.info("routing: pre-populate ограничен %d из %d доменов "
                     "правила %s (остальное dnsmasq набьёт по запросам)"
                     % (_PREPOP_MAX_DOMAINS, len(prepop_domains), rule.id),
                     source="routing")
            prepop_domains = prepop_domains[:_PREPOP_MAX_DOMAINS]
        prepop_results = _prepopulate_domains(
            prepop_domains, set_base_v4, set_base_v6, backend)
        prepop_added = sum(r.get("added", 0) for r in prepop_results)

        ok = bool(added) and not errors and dn_res.get("ok", True)
        log.info(
            "routing: domain-правило %s применено (iface=%s, %d записей,"
            " %d ошибок, prepop=%d IP)"
            % (rule.id, ifname, len(added), len(errors), prepop_added),
            source="routing",
        )
        return {
            "ok":      ok,
            "added":   added,
            "errors":  errors,
            "backend": kind,
            "dnsmasq": dn_res,
            "prepop":  {"total_ips_added": prepop_added,
                        "per_domain": prepop_results},
        }


def remove_domain_rule(rule: DomainRoutingRule) -> dict:
    """Снять одно domain-правило (без удаления из storage)."""
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}

    # ── Keenetic NDMS-fast-path ─────────────────────────────────
    # Симметрично apply_domain_rule — на Keenetic'е снимаем через
    # NDMS — только для нативных интерфейсов (симметрично apply).
    if _ndms_available() and _is_native_ndms_iface(rule.target_iface):
        try:
            from core.routing import ndms_backend
            return ndms_backend.remove_domain_rule(rule)
        except Exception as e:
            log.warning("routing(ndms): remove упал, fallback на dnsmasq: %s"
                        % e, source="routing")

    # Если правило применялось через ip-route (userspace-туннель без
    # dnsmasq) — снимаем тем же путём.
    if rule.id in _iproute_state_load():
        return _remove_domain_via_iproute(rule)

    with _lock:
        backend, kind = _detect_backend()
        if backend is None:
            # Бэкенд недоступен — всё равно перегенерим managed-файл,
            # чтобы dnsmasq не пытался писать в несуществующий set.
            return {"ok": True, "skipped": True,
                    "dnsmasq": _rebuild_managed_dnsmasq()}

        mark = _mark_for(rule.id)
        ifname = rule.target_iface
        table = _table_id_for(ifname)

        for fam in ("v4", "v6"):
            set_name = _set_name_for(rule.id, kind) + ("6" if fam == "v6" else "")
            backend.del_ip_rule_fwmark(mark, table, family=fam)
            backend.teardown_mark_rule(set_name, mark, family=fam)
            backend.destroy_set(set_name)

        # MASQUERADE снимаем только если на этот же интерфейс больше нет
        # других ВКЛЮЧЁННЫХ правил, которым masquerade нужен — теперь это
        # и domain-, и device-, и cidr-rules (CIDR с появлением masquerade
        # тоже завязан на него для forwarded-трафика).
        from core.routing import masquerade
        masquerade.remove_if_unused(ifname, excluding_id=rule.id)

        dn_res = _rebuild_managed_dnsmasq()
        log.info("routing: domain-правило %s снято" % rule.id,
                 source="routing")
        return {"ok": True, "dnsmasq": dn_res, "backend": kind}


def reapply_all_domain_rules() -> dict:
    """Перегенерить managed-файл и переприменить все enabled domain-правила.
    Используется при общем reapply_all."""
    results = []
    for r in _all_domain_rules():
        results.append({"id": r.id, "result": apply_domain_rule(r)})
    return {"ok": True, "applied": results}
