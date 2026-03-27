# api/strategies.py
"""
API стратегий и категорий.

Стратегии:
  GET    /api/strategies              — список всех стратегий
  GET    /api/strategies/:id          — одна стратегия по id
  POST   /api/strategies              — создать пользовательскую
  PUT    /api/strategies/:id          — редактировать пользовательскую
  DELETE /api/strategies/:id          — удалить пользовательскую
  POST   /api/strategies/:id/apply    — применить стратегию (restart nfqws)
  POST   /api/strategies/:id/favorite — toggle избранного
  POST   /api/strategies/preview      — превью итоговой команды nfqws2

Категории:
  GET    /api/categories              — список категорий
  PUT    /api/categories              — обновить категории (enabled)
"""

import os
import json
from bottle import request, response


def register(app):

    # ═══════════════════ Стратегии ═══════════════════

    @app.route("/api/strategies")
    def api_strategies_list():
        """Список всех стратегий (builtin + user)."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.config_manager import get_config_manager

        sm = get_strategy_manager()
        cfg = get_config_manager()

        strategies = sm.get_strategies()

        # Дополняем информацией из конфига
        current_id = cfg.get("strategy", "current_id")
        favorites = cfg.get("strategy", "favorites", default=[])

        for s in strategies:
            s["is_active"] = (s["id"] == current_id)
            s["is_favorite"] = (s["id"] in favorites)

        return {"ok": True, "strategies": strategies}

    @app.route("/api/strategies/<sid>")
    def api_strategies_get(sid):
        """Получить стратегию по ID."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.config_manager import get_config_manager

        sm = get_strategy_manager()
        cfg = get_config_manager()
        strategy = sm.get_strategy(sid)

        if not strategy:
            response.status = 404
            return {"ok": False, "error": "Стратегия не найдена: %s" % sid}

        current_id = cfg.get("strategy", "current_id")
        favorites = cfg.get("strategy", "favorites", default=[])
        strategy["is_active"] = (strategy["id"] == current_id)
        strategy["is_favorite"] = (strategy["id"] in favorites)

        return {"ok": True, "strategy": strategy}

    @app.post("/api/strategies")
    def api_strategies_create():
        """Создать пользовательскую стратегию."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.log_buffer import log

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        # Проверяем обязательные поля
        if not body.get("id") or not body.get("name"):
            response.status = 400
            return {"ok": False, "error": "Поля 'id' и 'name' обязательны"}

        if not body.get("profiles") or not isinstance(body["profiles"], list):
            response.status = 400
            return {"ok": False, "error": "Поле 'profiles' обязательно (массив)"}

        sm = get_strategy_manager()

        # Проверяем что не пытаемся перезаписать builtin
        existing = sm.get_strategy(body["id"])
        if existing and existing.get("is_builtin"):
            response.status = 409
            return {
                "ok": False,
                "error": "Нельзя перезаписать встроенную стратегию. "
                         "Измените ID."
            }

        result = sm.save_user_strategy(body)
        if not result:
            response.status = 500
            return {"ok": False, "error": "Ошибка сохранения стратегии"}

        log.success("Создана стратегия: %s" % result["name"],
                    source="strategies")

        return {"ok": True, "strategy": result}

    @app.put("/api/strategies/<sid>")
    def api_strategies_update(sid):
        """Редактировать пользовательскую стратегию."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.log_buffer import log

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        sm = get_strategy_manager()

        # Проверяем что стратегия существует
        existing = sm.get_strategy(sid)
        if not existing:
            response.status = 404
            return {"ok": False, "error": "Стратегия не найдена: %s" % sid}

        if existing.get("is_builtin"):
            response.status = 403
            return {
                "ok": False,
                "error": "Встроенные стратегии нельзя редактировать. "
                         "Создайте копию."
            }

        # Обновляем поля
        body["id"] = sid  # ID не меняется
        result = sm.save_user_strategy(body)
        if not result:
            response.status = 500
            return {"ok": False, "error": "Ошибка сохранения стратегии"}

        log.info("Стратегия обновлена: %s" % result["name"],
                 source="strategies")

        return {"ok": True, "strategy": result}

    @app.delete("/api/strategies/<sid>")
    def api_strategies_delete(sid):
        """Удалить пользовательскую стратегию."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.config_manager import get_config_manager
        from core.log_buffer import log

        sm = get_strategy_manager()

        existing = sm.get_strategy(sid)
        if not existing:
            response.status = 404
            return {"ok": False, "error": "Стратегия не найдена"}

        if existing.get("is_builtin"):
            response.status = 403
            return {"ok": False, "error": "Встроенные стратегии нельзя удалить"}

        if not sm.delete_user_strategy(sid):
            response.status = 500
            return {"ok": False, "error": "Ошибка удаления стратегии"}

        # Если удалённая стратегия была активной — сбрасываем
        cfg = get_config_manager()
        if cfg.get("strategy", "current_id") == sid:
            cfg.set("strategy", "current_id", None)
            cfg.set("strategy", "current_name", None)
            cfg.save()

        # Убираем из избранного
        favorites = cfg.get("strategy", "favorites", default=[])
        if sid in favorites:
            favorites.remove(sid)
            cfg.set("strategy", "favorites", favorites)
            cfg.save()

        return {"ok": True}

    @app.post("/api/strategies/<sid>/apply")
    def api_strategies_apply(sid):
        """
        Применить стратегию.

        Собирает аргументы из стратегии, перезапускает nfqws2
        с этими аргументами, сохраняет id/name в конфиг.
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.config_manager import get_config_manager
        from core.nfqws_manager import get_nfqws_manager
        from core.firewall import get_firewall_manager
        from core.log_buffer import log

        sm = get_strategy_manager()
        cfg = get_config_manager()
        mgr = get_nfqws_manager()
        fw = get_firewall_manager()

        strategy = sm.get_strategy(sid)
        if not strategy:
            response.status = 404
            return {"ok": False, "error": "Стратегия не найдена: %s" % sid}

        # Собираем аргументы
        args = sm.build_nfqws_args(strategy)

        if not args:
            response.status = 400
            return {
                "ok": False,
                "error": "Нет включённых профилей в стратегии"
            }

        log.info(
            "Применяем стратегию: %s (%s)" % (strategy["name"], sid),
            source="strategies"
        )

        # Применяем FW правила
        apply_fw = cfg.get("firewall", "apply_on_start", default=True)
        if apply_fw:
            fw.remove_rules()
            fw.apply_rules()

        # Перезапускаем nfqws2 с новыми аргументами
        if mgr.is_running():
            ok = mgr.restart(args)
        else:
            ok = mgr.start(args)

        if not ok:
            response.status = 500
            return {
                "ok": False,
                "error": "Не удалось запустить nfqws2 со стратегией",
                "nfqws": mgr.get_status(),
            }

        # Сохраняем активную стратегию в конфиг
        cfg.set("strategy", "current_id", sid)
        cfg.set("strategy", "current_name", strategy["name"])
        cfg.save()

        log.success(
            "Стратегия применена: %s" % strategy["name"],
            source="strategies"
        )

        return {
            "ok": True,
            "strategy": {
                "id": sid,
                "name": strategy["name"],
            },
            "nfqws": mgr.get_status(),
            "firewall": fw.get_status(),
        }

    @app.post("/api/strategies/<sid>/favorite")
    def api_strategies_favorite(sid):
        """Toggle избранного для стратегии."""
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager
        from core.config_manager import get_config_manager
        from core.log_buffer import log

        sm = get_strategy_manager()
        cfg = get_config_manager()

        strategy = sm.get_strategy(sid)
        if not strategy:
            response.status = 404
            return {"ok": False, "error": "Стратегия не найдена"}

        favorites = cfg.get("strategy", "favorites", default=[])
        if not isinstance(favorites, list):
            favorites = []

        if sid in favorites:
            favorites.remove(sid)
            is_favorite = False
        else:
            favorites.append(sid)
            is_favorite = True

        cfg.set("strategy", "favorites", favorites)
        cfg.save()

        return {"ok": True, "is_favorite": is_favorite}

    @app.post("/api/strategies/preview")
    def api_strategies_preview():
        """
        Превью итоговой команды nfqws2 для стратегии.

        Body:
            { "strategy_id": "tcp_alt2" }
            или
            { "strategy_data": { ...полная стратегия... } }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.strategy_builder import get_strategy_manager

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        sm = get_strategy_manager()

        # Определяем стратегию
        strategy = None
        if "strategy_id" in body:
            strategy = sm.get_strategy(body["strategy_id"])
            if not strategy:
                response.status = 404
                return {"ok": False, "error": "Стратегия не найдена"}
        elif "strategy_data" in body:
            strategy = body["strategy_data"]
        else:
            response.status = 400
            return {
                "ok": False,
                "error": "Укажите strategy_id или strategy_data"
            }

        # Собираем превью
        command = sm.build_preview_command(strategy)
        args = sm.build_nfqws_args(strategy)

        return {
            "ok": True,
            "command": command,
            "args": args,
            "profiles_count": len([
                p for p in strategy.get("profiles", [])
                if p.get("enabled", True)
            ]),
        }

    # ═══════════════════ Категории ═══════════════════

    @app.route("/api/categories")
    def api_categories_list():
        """Получить список категорий сервисов."""
        response.content_type = "application/json; charset=utf-8"

        categories = _load_categories()
        return {"ok": True, "categories": categories}

    @app.put("/api/categories")
    def api_categories_update():
        """
        Обновить категории (enabled/disabled).

        Body:
            { "categories": [ {"id": "youtube", "enabled": false}, ... ] }
        """
        response.content_type = "application/json; charset=utf-8"

        from core.log_buffer import log

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body or "categories" not in body:
            response.status = 400
            return {"ok": False, "error": "Поле 'categories' обязательно"}

        updates = body["categories"]
        if not isinstance(updates, list):
            response.status = 400
            return {"ok": False, "error": "'categories' должен быть массивом"}

        categories = _load_categories()

        # Применяем обновления
        cat_map = {c["id"]: c for c in categories}
        for upd in updates:
            cid = upd.get("id")
            if cid and cid in cat_map:
                if "enabled" in upd:
                    cat_map[cid]["enabled"] = bool(upd["enabled"])

        # Сохраняем
        categories = list(cat_map.values())
        if _save_categories(categories):
            log.info("Категории обновлены", source="categories")
            return {"ok": True, "categories": categories}
        else:
            response.status = 500
            return {"ok": False, "error": "Ошибка сохранения категорий"}


# ═══════════════════ Helpers ═══════════════════

def _get_categories_path():
    """Путь к файлу категорий."""
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "categories.json"
    )


def _load_categories() -> list:
    """Загрузить категории из файла."""
    path = _get_categories_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, IOError, OSError):
        pass

    # Дефолтные
    return [
        {"id": "youtube",  "name": "YouTube",  "icon": "play",    "color": "#ff0000", "enabled": True},
        {"id": "discord",  "name": "Discord",  "icon": "message", "color": "#5865f2", "enabled": True},
        {"id": "telegram", "name": "Telegram", "icon": "send",    "color": "#0088cc", "enabled": True},
        {"id": "social",   "name": "Соцсети",  "icon": "users",   "color": "#e4405f", "enabled": True},
        {"id": "ai",       "name": "AI",       "icon": "brain",   "color": "#8b5cf6", "enabled": True},
        {"id": "other",    "name": "Другое",   "icon": "globe",   "color": "#6b7280", "enabled": True},
    ]


def _save_categories(categories: list) -> bool:
    """Сохранить категории в файл."""
    path = _get_categories_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(categories, f, indent=2, ensure_ascii=False)
        return True
    except (IOError, OSError):
        return False
