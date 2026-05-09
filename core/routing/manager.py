# core/routing/manager.py
"""
RoutingManager — оркестратор selective routing.

Применение правил:
  - Каждому целевому интерфейсу выделяется отдельная таблица
    маршрутизации (ID = 100 + hash(name) % 900). В этой таблице
    лежит default-route на интерфейс.
  - Под каждое CIDR-правило добавляется ip rule:
        ip rule add to <cidr> lookup <table> priority <prio>
    Это гарантирует, что трафик к указанным CIDR уходит через
    нужный интерфейс независимо от AllowedIPs.

Идемпотентность: повторное применение того же правила не должно
порождать дубликатов — перед `add` мы делаем `del` (best-effort).

Зависимости — только subprocess + ip(8). Никаких новых пакетов.
"""

import subprocess
import threading

from core.log_buffer import log
from core.routing.rules import (
    RoutingRule,
    CidrRoutingRule,
    DomainRoutingRule,
    DeviceRoutingRule,
)
from core.routing import storage


# ───────────────────────── helpers ──────────────────────────────────

def _run(args, timeout=10):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def table_id_for(ifname: str) -> int:
    """
    Стабильный id таблицы из имени интерфейса (100..999).

    ВАЖНО: тот же алгоритм, что и в core/awg_manager.py:_table_id_for —
    чтобы default-route, добавленный AwgManager при AllowedIPs=0/0,
    лежал в той же таблице, к которой будут адресовать наши ip rule.
    """
    h = 0
    for ch in ifname:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 100 + (h % 900)


def _iface_exists(ifname: str) -> bool:
    rc, _o, _e = _run(["ip", "link", "show", "dev", ifname])
    return rc == 0


def _table_has_default(family: str, table: int, ifname: str) -> bool:
    """Проверить, есть ли в таблице default-route на наш iface."""
    rc, out, _e = _run(["ip", family, "route", "show", "table", str(table),
                        "default"])
    if rc != 0 or not out:
        return False
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            i = parts.index("dev")
            if i + 1 < len(parts) and parts[i + 1] == ifname:
                return True
    return False


# ───────────────────────── manager ───────────────────────────────────

class RoutingManager:
    """Применение/откат правил routing. Тонкий слой над ip(8)."""

    # Базовый приоритет для наших ip rule (между fwmark-rule и main).
    # main-таблица = 32766; suppress_prefixlength fwmark-rule, который
    # ставит wg-quick / awg_manager._add_default_via — обычно >= 32760.
    # Берём 1000 + offset, чтобы наши правила отрабатывали раньше main.
    BASE_PRIORITY = 10000

    def __init__(self):
        self._lock = threading.Lock()

    # ─────────── CRUD ───────────

    def list_rules(self) -> list:
        """Все правила (объекты RoutingRule)."""
        return storage.load_rules()

    def list_rules_dict(self) -> list:
        """Все правила в виде dict (для API/UI)."""
        return [r.to_dict() for r in self.list_rules()]

    def get_rule(self, rule_id: str):
        return storage.get_rule(rule_id)

    def add_rule(self, rule: RoutingRule, apply_now: bool = True) -> dict:
        """Сохранить и (опционально) применить правило."""
        with self._lock:
            storage.add_rule(rule)
            if apply_now and rule.enabled:
                applied = self._apply(rule)
                return {"ok": applied.get("ok", True),
                        "rule": rule.to_dict(),
                        "applied": applied}
            return {"ok": True, "rule": rule.to_dict()}

    def update_rule(self, rule: RoutingRule, apply_now: bool = True) -> dict:
        """Обновить правило (сначала откатываем старое, потом ставим новое)."""
        with self._lock:
            old = storage.get_rule(rule.id)
            if old is not None:
                self._remove(old)
            storage.update_rule(rule)
            if apply_now and rule.enabled:
                applied = self._apply(rule)
                return {"ok": applied.get("ok", True),
                        "rule": rule.to_dict(),
                        "applied": applied}
            return {"ok": True, "rule": rule.to_dict()}

    def remove_rule(self, rule_id: str) -> dict:
        """Откатить и удалить правило по id."""
        with self._lock:
            rule = storage.get_rule(rule_id)
            if rule is None:
                return {"ok": False, "error": "Правило не найдено"}
            self._remove(rule)
            storage.remove_rule(rule_id)
            return {"ok": True, "id": rule_id}

    # ─────────── apply / remove (одно правило) ───────────

    def apply_rule(self, rule_id: str) -> dict:
        """Применить уже сохранённое правило по id."""
        rule = storage.get_rule(rule_id)
        if rule is None:
            return {"ok": False, "error": "Правило не найдено"}
        return self._apply(rule)

    def remove_applied_rule(self, rule_id: str) -> dict:
        """Снять применённое правило (без удаления из хранилища)."""
        rule = storage.get_rule(rule_id)
        if rule is None:
            return {"ok": False, "error": "Правило не найдено"}
        return self._remove(rule)

    def _apply(self, rule: RoutingRule) -> dict:
        if isinstance(rule, CidrRoutingRule):
            return self._apply_cidr(rule)
        if isinstance(rule, DomainRoutingRule):
            from core.routing.domain_rule import apply_domain_rule
            return apply_domain_rule(rule)
        if isinstance(rule, DeviceRoutingRule):
            return {"ok": False, "skipped": True,
                    "message": "Device-правила появятся в следующем промте"}
        return {"ok": False, "error": "Неизвестный тип правила"}

    def _remove(self, rule: RoutingRule) -> dict:
        if isinstance(rule, CidrRoutingRule):
            return self._remove_cidr(rule)
        if isinstance(rule, DomainRoutingRule):
            from core.routing.domain_rule import remove_domain_rule
            return remove_domain_rule(rule)
        return {"ok": True, "skipped": True}

    # ─────────── apply ALL on iface up/down ───────────

    def apply_all_for_iface(self, ifname: str) -> dict:
        """Применить все правила, привязанные к интерфейсу."""
        results = []
        for rule in self.list_rules():
            if rule.target_iface != ifname or not rule.enabled:
                continue
            results.append({
                "id":     rule.id,
                "type":   rule.type_name,
                "result": self._apply(rule),
            })
        return {"ok": True, "iface": ifname, "applied": results}

    def remove_all_for_iface(self, ifname: str) -> dict:
        """Снять все правила интерфейса (не удаляя их из хранилища)."""
        results = []
        for rule in self.list_rules():
            if rule.target_iface != ifname:
                continue
            results.append({
                "id":     rule.id,
                "type":   rule.type_name,
                "result": self._remove(rule),
            })
        return {"ok": True, "iface": ifname, "removed": results}

    def reapply_all(self) -> dict:
        """
        Снять и заново применить все правила. Полезно после ручных
        изменений в системе или при отладке.
        """
        results = []
        for rule in self.list_rules():
            self._remove(rule)
            if rule.enabled:
                results.append({
                    "id":     rule.id,
                    "type":   rule.type_name,
                    "result": self._apply(rule),
                })
        return {"ok": True, "applied": results}

    # ─────────── CIDR backend ───────────

    def _ensure_table_default(self, ifname: str, family: str, table: int) -> bool:
        """
        Гарантировать default-route в таблице ifname. Возвращает True
        если маршрут уже был или мы его добавили.
        """
        if _table_has_default(family, table, ifname):
            return True
        if not _iface_exists(ifname):
            return False
        rc, _o, err = _run(["ip", family, "route", "add", "default",
                            "dev", ifname, "table", str(table)])
        if rc != 0:
            # Может быть RTNETLINK answers: File exists — это не ошибка
            if "File exists" in (err or ""):
                return True
            log.warning("routing: не удалось добавить default %s в table %d: %s"
                        % (ifname, table, err.strip()),
                        source="routing")
            return False
        return True

    def _apply_cidr(self, rule: CidrRoutingRule) -> dict:
        ifname = rule.target_iface
        table = table_id_for(ifname)

        if not _iface_exists(ifname):
            return {"ok": False,
                    "deferred": True,
                    "message": "Интерфейс %s ещё не поднят — правило"
                               " будет применено при старте" % ifname}

        added = []
        errors = []

        for cidr, fam in rule.cidr_families():
            if rule.ip_version != "auto" and fam != rule.ip_version:
                continue

            family = "-6" if fam == "v6" else "-4"
            if not self._ensure_table_default(ifname, family, table):
                errors.append("default-route в table %d не создан (%s)"
                              % (table, family))
                continue

            # Сначала чистим возможный дубликат, чтобы apply был идемпотентным
            _run(["ip", family, "rule", "del", "to", cidr,
                  "lookup", str(table)])

            rc, _o, err = _run(["ip", family, "rule", "add", "to", cidr,
                                "lookup", str(table),
                                "priority", str(self.BASE_PRIORITY)])
            if rc != 0:
                errors.append("ip rule add to %s: %s" % (cidr, err.strip()))
                continue
            added.append({"family": family, "cidr": cidr, "table": table})

        ok = bool(added) and not errors
        log_msg = "routing: применено %d/%d CIDR для %s" % (
            len(added), len(rule.cidrs), ifname)
        if errors:
            log.warning(log_msg + "; ошибки: " + "; ".join(errors),
                        source="routing")
        else:
            log.info(log_msg, source="routing")

        return {
            "ok":     ok or (not added and not errors),
            "added":  added,
            "errors": errors,
        }

    def _remove_cidr(self, rule: CidrRoutingRule) -> dict:
        ifname = rule.target_iface
        table = table_id_for(ifname)
        removed = []

        for cidr, fam in rule.cidr_families():
            if rule.ip_version != "auto" and fam != rule.ip_version:
                continue
            family = "-6" if fam == "v6" else "-4"
            rc, _o, _e = _run(["ip", family, "rule", "del", "to", cidr,
                               "lookup", str(table)])
            if rc == 0:
                removed.append({"family": family, "cidr": cidr})

        log.info("routing: снят CIDR-rule %s (%d записей)" %
                 (rule.id, len(removed)), source="routing")
        return {"ok": True, "removed": removed}


# ───────────────────────── singleton ─────────────────────────────────

_manager = None
_manager_lock = threading.Lock()


def get_routing_manager() -> RoutingManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = RoutingManager()
    return _manager
