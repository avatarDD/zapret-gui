# core/routing/domain_rule.py
"""
Логика применения и снятия domain-based routing-правил.

Поток для одного DomainRoutingRule:

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


def _rebuild_managed_dnsmasq():
    """Перегенерить managed-файл по всем активным domain-правилам."""
    dn = dnsmasq_integration.DnsmasqIntegration()
    supports_nftset = dn.supports_nftset()
    set_kind = "nftset" if supports_nftset else "ipset"

    blocks = []
    for r in _all_domain_rules():
        if not r.domains:
            continue
        blocks.append({
            "rule_id":    r.id,
            "set_kind":   set_kind,
            "set_name":   _set_name_for(r.id, set_kind),
            "nft_table":  nftset_backend.TABLE_NAME,
            "nft_family": "inet",
            "domains":    r.domains,
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

def apply_domain_rule(rule: DomainRoutingRule) -> dict:
    """Применить одно domain-правило."""
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}
    if not rule.domains:
        return {"ok": False, "error": "Список доменов пуст"}

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
        if not dn_status.get("available"):
            return {
                "ok": False,
                "error": (
                    "dnsmasq не установлен на системе. Доменное routing"
                    " работает только через dnsmasq (он заполняет"
                    " ipset/nftset при резолве). Установите и запустите"
                    " dnsmasq, либо используйте правило по CIDR."
                ),
            }
        if not dn_status.get("running"):
            return {
                "ok": False,
                "error": (
                    "dnsmasq установлен, но не запущен. Откройте"
                    " «Routing» и нажмите «Настроить dnsmasq"
                    " автоматически» — GUI отключит DNSStubListener"
                    " в systemd-resolved, запустит dnsmasq на :53 и"
                    " автоматически откатит всё обратно при выключении"
                    " последнего AWG-интерфейса. Если возиться не"
                    " хочется — используйте правило по CIDR."
                ),
            }

        backend, kind = _detect_backend()
        if backend is None:
            return {"ok": False,
                    "error": "Нет доступного бэкенда (ipset/nftables)"}

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
            mq = (backend.ensure_iface_masquerade(ifname)
                  if backend is nftset_backend
                  else backend.ensure_iface_masquerade(ifname, family=fam))
            if not mq.get("ok"):
                errors.append("masquerade %s: %s" %
                              (fam, mq.get("error")))
                continue

            added.append({"family": fam, "set": r1["name"],
                          "mark": mark, "table": table})

        dn_res = _rebuild_managed_dnsmasq()

        ok = bool(added) and not errors and dn_res.get("ok", True)
        log.info(
            "routing: domain-правило %s применено (iface=%s, %d записей, %d ошибок)"
            % (rule.id, ifname, len(added), len(errors)),
            source="routing",
        )
        return {
            "ok":      ok,
            "added":   added,
            "errors":  errors,
            "backend": kind,
            "dnsmasq": dn_res,
        }


def remove_domain_rule(rule: DomainRoutingRule) -> dict:
    """Снять одно domain-правило (без удаления из storage)."""
    if not isinstance(rule, DomainRoutingRule):
        return {"ok": False, "error": "Не DomainRoutingRule"}

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

        # MASQUERADE снимаем только если на этот же интерфейс больше
        # нет других ВКЛЮЧЁННЫХ domain-правил — оставшиеся domain-rules
        # на том же AWG-iface продолжают на него полагаться.
        others = [r for r in _all_domain_rules()
                  if r.id != rule.id and r.target_iface == ifname]
        if not others:
            if backend is nftset_backend:
                backend.remove_iface_masquerade(ifname)
            else:
                for fam in ("v4", "v6"):
                    backend.remove_iface_masquerade(ifname, family=fam)

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
