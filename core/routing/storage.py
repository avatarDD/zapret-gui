# core/routing/storage.py
"""
Хранилище правил selective routing в settings.json.

Структура в settings.json:
    "routing": {
        "rules": [ <rule.to_dict()>, ... ]
    }
"""

import threading

from core.config_manager import get_config_manager
from core.routing.rules import RoutingRule, rule_from_dict


_lock = threading.Lock()


def _section() -> list:
    """Получить копию списка правил из settings.json."""
    cm = get_config_manager()
    section = cm.get("routing") or {}
    rules = section.get("rules") if isinstance(section, dict) else None
    return list(rules) if isinstance(rules, list) else []


def _save_section(rules_dicts: list):
    cm = get_config_manager()
    cur = cm.get("routing") or {}
    if not isinstance(cur, dict):
        cur = {}
    cur["rules"] = list(rules_dicts)
    cm.set("routing", cur)
    cm.save()


def load_rules() -> list:
    """Загрузить все правила (десериализованные объекты RoutingRule)."""
    out = []
    for raw in _section():
        try:
            out.append(rule_from_dict(raw))
        except (ValueError, TypeError):
            # Битое правило — пропускаем, но не теряем; логировать здесь
            # не будем, чтобы не тащить лог в storage.
            continue
    return out


def save_rules(rules):
    """Полностью перезаписать список правил."""
    with _lock:
        _save_section([r.to_dict() for r in rules])


def add_rule(rule: RoutingRule):
    """Добавить правило (если id уже есть — заменить)."""
    with _lock:
        existing = _section()
        existing = [r for r in existing if r.get("id") != rule.id]
        existing.append(rule.to_dict())
        _save_section(existing)


def remove_rule(rule_id: str) -> bool:
    """Удалить правило по id. Возвращает True если что-то удалили."""
    with _lock:
        existing = _section()
        new = [r for r in existing if r.get("id") != rule_id]
        if len(new) == len(existing):
            return False
        _save_section(new)
        return True


def get_rule(rule_id: str):
    """Получить одно правило по id."""
    for raw in _section():
        if raw.get("id") == rule_id:
            try:
                return rule_from_dict(raw)
            except (ValueError, TypeError):
                return None
    return None


def update_rule(rule: RoutingRule):
    """Обновить существующее правило."""
    add_rule(rule)
