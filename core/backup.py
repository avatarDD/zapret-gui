# core/backup.py
"""
Резервное копирование и восстановление конфигурации zapret-gui.

Бэкап — единый JSON-файл, который можно скачать и позже загрузить для
восстановления (например, при переустановке или переносе на другой
роутер). Содержит:

  - settings   — полный settings.json (стратегия, автозапуск, routing-
                 правила, единый слой, named-списки, зеркало и т.д.);
  - strategies — пользовательские стратегии (config/strategies/user);
  - singbox    — JSON-конфиги sing-box;
  - mihomo     — YAML-конфиги mihomo;
  - hostlists  — пользовательские hostlist'ы (домены).

Восстановление переиспользует существующие менеджеры (их валидацию):
strategy/singbox/mihomo/hostlist managers + config_manager.

По умолчанию при восстановлении секция `gui` НЕ трогается (host/port/
auth), чтобы не сменить адрес/доступ и не закрыть себе доступ к GUI;
это поведение можно переключить (`restore_gui=True`).

Чистые функции (`validate_backup`, фильтрация секций) тестируются без I/O.
"""

import time

from core.log_buffer import log

FORMAT = "zapret-gui-backup"
FORMAT_VERSION = 1

# Все секции бэкапа.
SECTIONS = ("settings", "strategies", "singbox", "mihomo", "hostlists")

# Встроенные hostlist-имена не бэкапим (они дефолтные/восстановятся сами).
try:
    from core.hostlist_manager import BUILTIN_NAMES as _HL_BUILTIN
except Exception:
    _HL_BUILTIN = ()


# ─────────────────────── build ───────────────────────────────────────

def build_backup(include=None) -> dict:
    """
    Собрать бэкап. include — множество/список секций (None = все).
    """
    sections = _normalize_sections(include)
    backup = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "created_at": int(time.time()),
        "app_version": _app_version(),
    }
    if "settings" in sections:
        backup["settings"] = _collect_settings()
    if "strategies" in sections:
        backup["strategies"] = _collect_strategies()
    if "singbox" in sections:
        backup["singbox"] = _collect_engine_configs("singbox")
    if "mihomo" in sections:
        backup["mihomo"] = _collect_engine_configs("mihomo")
    if "hostlists" in sections:
        backup["hostlists"] = _collect_hostlists()
    return backup


def summary(backup: dict) -> dict:
    """Краткая сводка содержимого бэкапа (для UI-подтверждения)."""
    return {
        "format": backup.get("format"),
        "app_version": backup.get("app_version"),
        "created_at": backup.get("created_at"),
        "has_settings": bool(backup.get("settings")),
        "strategies": len(backup.get("strategies") or []),
        "singbox": len(backup.get("singbox") or []),
        "mihomo": len(backup.get("mihomo") or []),
        "hostlists": len(backup.get("hostlists") or []),
    }


# ─────────────────────── validate ─────────────────────────────────────

def validate_backup(data) -> list:
    """Список ошибок (пустой = валидно)."""
    errors = []
    if not isinstance(data, dict):
        return ["Бэкап должен быть JSON-объектом"]
    if data.get("format") != FORMAT:
        errors.append("Не похоже на бэкап zapret-gui (format != %s)" % FORMAT)
    fv = data.get("format_version")
    if fv is not None and not isinstance(fv, int):
        errors.append("format_version должен быть числом")
    for key, typ in (("strategies", list), ("singbox", list),
                     ("mihomo", list), ("hostlists", list),
                     ("settings", dict)):
        if key in data and not isinstance(data[key], typ):
            errors.append("Секция '%s' имеет неверный тип" % key)
    return errors


# ─────────────────────── restore ─────────────────────────────────────

def restore_backup(data: dict, *, sections=None,
                   restore_gui: bool = False) -> dict:
    """
    Восстановить из бэкапа выбранные секции.

      sections    — какие секции восстанавливать (None = все присутствующие);
      restore_gui — восстанавливать ли секцию settings.gui (host/port/auth).
                    По умолчанию False — чтобы не сменить адрес/доступ.
    """
    errors = validate_backup(data)
    if errors:
        return {"ok": False, "error": "; ".join(errors)}

    want = _normalize_sections(sections)
    result = {"ok": True, "restored": {}, "errors": []}

    if "settings" in want and isinstance(data.get("settings"), dict):
        result["restored"]["settings"] = _restore_settings(
            data["settings"], restore_gui=restore_gui, errors=result["errors"])
    if "strategies" in want and data.get("strategies"):
        result["restored"]["strategies"] = _restore_strategies(
            data["strategies"], result["errors"])
    if "singbox" in want and data.get("singbox"):
        result["restored"]["singbox"] = _restore_engine(
            "singbox", data["singbox"], result["errors"])
    if "mihomo" in want and data.get("mihomo"):
        result["restored"]["mihomo"] = _restore_engine(
            "mihomo", data["mihomo"], result["errors"])
    if "hostlists" in want and data.get("hostlists"):
        result["restored"]["hostlists"] = _restore_hostlists(
            data["hostlists"], result["errors"])

    result["ok"] = not result["errors"]
    log.info("backup: восстановление завершено (%s), ошибок: %d"
             % (", ".join("%s=%s" % (k, v)
                          for k, v in result["restored"].items()),
                len(result["errors"])), source="backup")
    return result


# ─────────────────────── collectors ───────────────────────────────────

def _collect_settings() -> dict:
    try:
        from core.config_manager import get_config_manager
        return get_config_manager().get_all()
    except Exception as e:
        log.warning("backup: settings: %s" % e, source="backup")
        return {}


def _collect_strategies() -> list:
    try:
        from core.strategy_builder import get_strategy_manager
        # Только пользовательские (флаг is_builtin) — builtin не бэкапим,
        # они есть в поставке.
        return [s for s in get_strategy_manager().get_strategies()
                if not s.get("is_builtin")]
    except Exception as e:
        log.warning("backup: strategies: %s" % e, source="backup")
        return []


def _collect_engine_configs(engine: str) -> list:
    try:
        mgr = _engine_manager(engine)
        out = []
        for c in mgr.list_configs():
            r = mgr.get_config(c["name"])
            if r.get("ok"):
                out.append({"name": c["name"], "text": r.get("text", "")})
        return out
    except Exception as e:
        log.warning("backup: %s configs: %s" % (engine, e), source="backup")
        return []


def _collect_hostlists() -> list:
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        out = []
        for name in hm.list_names():
            if name in _HL_BUILTIN:
                continue
            out.append({"name": name, "domains": hm.get_hostlist(name)})
        return out
    except Exception as e:
        log.warning("backup: hostlists: %s" % e, source="backup")
        return []


# ─────────────────────── restorers ────────────────────────────────────

def _restore_settings(settings: dict, *, restore_gui: bool, errors: list) -> int:
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        count = 0
        for key, value in settings.items():
            if key == "gui" and not restore_gui:
                continue
            cm.set(key, value)
            count += 1
        cm.save()
        return count
    except Exception as e:
        errors.append("settings: %s" % e)
        return 0


def _restore_strategies(strategies: list, errors: list) -> int:
    count = 0
    try:
        from core.strategy_builder import get_strategy_manager
        sm = get_strategy_manager()
        for s in strategies:
            if not isinstance(s, dict):
                continue
            r = sm.save_user_strategy(s)
            if isinstance(r, dict) and not r.get("ok", True):
                errors.append("strategy %s: %s"
                              % (s.get("id"), r.get("error")))
            else:
                count += 1
    except Exception as e:
        errors.append("strategies: %s" % e)
    return count


def _restore_engine(engine: str, configs: list, errors: list) -> int:
    count = 0
    try:
        mgr = _engine_manager(engine)
        for c in configs:
            if not isinstance(c, dict) or not c.get("name"):
                continue
            r = mgr.save_config(c["name"], text=c.get("text", ""))
            if isinstance(r, dict) and not r.get("ok", True):
                errors.append("%s %s: %s"
                              % (engine, c.get("name"), r.get("error")))
            else:
                count += 1
    except Exception as e:
        errors.append("%s: %s" % (engine, e))
    return count


def _restore_hostlists(hostlists: list, errors: list) -> int:
    count = 0
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        for h in hostlists:
            if not isinstance(h, dict) or not h.get("name"):
                continue
            if h["name"] in _HL_BUILTIN:
                continue
            hm.save_hostlist(h["name"], h.get("domains") or [])
            count += 1
    except Exception as e:
        errors.append("hostlists: %s" % e)
    return count


# ─────────────────────── helpers ──────────────────────────────────────

def _normalize_sections(include) -> set:
    if include is None:
        return set(SECTIONS)
    if isinstance(include, str):
        include = [include]
    return {s for s in include if s in SECTIONS}


def _engine_manager(engine: str):
    if engine == "singbox":
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager()
    if engine == "mihomo":
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager()
    raise ValueError("Неизвестный движок: %s" % engine)


def _app_version() -> str:
    try:
        from core.version import GUI_VERSION
        return GUI_VERSION
    except Exception:
        return ""
