# api/hostlists.py
"""
API списков доменов (hostlists).

Эндпоинты:
  GET    /api/hostlists              — список всех файлов со статистикой
  POST   /api/hostlists/create       — создать пустой custom hostlist
  GET    /api/hostlists/:name        — содержимое файла
  PUT    /api/hostlists/:name        — заменить весь список
  DELETE /api/hostlists/:name        — удалить custom hostlist
  POST   /api/hostlists/:name/add    — добавить домены
  POST   /api/hostlists/:name/remove — удалить домены
  POST   /api/hostlists/:name/reset  — сброс к дефолтам
  POST   /api/hostlists/:name/import — импорт из URL или текста
"""

from bottle import request, response


def register(app):

    @app.route("/api/hostlists")
    def api_hostlists_list():
        """Список всех hostlist-файлов со статистикой."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()
        stats = hm.get_stats()
        return {"ok": True, "files": [stats[name] for name in stats]}

    @app.post("/api/hostlists/create")
    def api_hostlists_create():
        """Создать пустой custom hostlist."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        name = str(body.get("name", "")).strip()
        ok, reason = hm.create_hostlist(name)
        if ok:
            return {"ok": True, "name": name, "message": "Список создан: %s.txt" % name}

        response.status = 400
        errors = {
            "invalid_name": "Недопустимое имя списка. Разрешены латиница, цифры, _ и -",
            "reserved_name": "Это имя зарезервировано встроенным списком",
            "already_exists": "Список уже существует",
            "write_error": "Ошибка создания файла",
        }
        return {"ok": False, "error": errors.get(reason, "Не удалось создать список")}

    @app.route("/api/hostlists/<name>")
    def api_hostlists_get(name):
        """Получить содержимое hostlist-файла."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        domains = hm.get_hostlist(name)
        stats = hm.get_stats().get(name, {})
        return {
            "ok": True,
            "name": name,
            "domains": domains,
            "count": len(domains),
            "description": stats.get("description", ""),
            "is_default": stats.get("is_default", False),
            "has_defaults": stats.get("has_defaults", False),
        }

    @app.put("/api/hostlists/<name>")
    def api_hostlists_put(name):
        """Заменить весь список доменов."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domains = body.get("domains")
        if domains is None:
            response.status = 400
            return {"ok": False, "error": "Поле 'domains' обязательно"}

        if not isinstance(domains, list):
            if isinstance(domains, str):
                domains = [d.strip() for d in domains.split("\n") if d.strip()]
            else:
                response.status = 400
                return {"ok": False, "error": "'domains' должен быть массивом или строкой"}

        normalized = []
        invalid = []
        for d in domains:
            nd = hm.normalize_domain(d)
            if nd:
                normalized.append(nd)
            elif isinstance(d, str) and d.strip():
                invalid.append(d.strip())

        ok = hm.save_hostlist(name, normalized)
        if not ok:
            response.status = 500
            return {"ok": False, "error": "Ошибка записи файла"}

        result = {
            "ok": True,
            "count": len(normalized),
            "message": "Сохранено %d доменов" % len(normalized),
        }
        if invalid:
            result["invalid"] = invalid[:50]
            result["invalid_count"] = len(invalid)
        return result

    @app.delete("/api/hostlists/<name>")
    def api_hostlists_delete(name):
        """Удалить custom hostlist."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()
        ok, reason = hm.delete_hostlist(name)
        if ok:
            return {"ok": True, "name": name, "message": "Список удалён: %s.txt" % name}

        response.status = 400
        errors = {
            "invalid_name": "Недопустимое имя списка",
            "protected_name": "Встроенные списки удалять нельзя",
            "not_found": "Список не найден",
            "delete_error": "Ошибка удаления файла",
        }
        return {"ok": False, "error": errors.get(reason, "Не удалось удалить список")}

    @app.post("/api/hostlists/<name>/add")
    def api_hostlists_add(name):
        """Добавить домены в список."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domains = body.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split("\n") if d.strip()]

        if not domains:
            response.status = 400
            return {"ok": False, "error": "Список доменов пуст"}

        added = hm.add_domains(name, domains)
        return {"ok": True, "added": added, "message": "Добавлено %d доменов" % added}

    @app.post("/api/hostlists/<name>/remove")
    def api_hostlists_remove(name):
        """Удалить домены из списка."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domains = body.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split("\n") if d.strip()]

        if not domains:
            response.status = 400
            return {"ok": False, "error": "Список доменов пуст"}

        removed = hm.remove_domains(name, domains)
        return {"ok": True, "removed": removed, "message": "Удалено %d доменов" % removed}

    @app.post("/api/hostlists/<name>/reset")
    def api_hostlists_reset(name):
        """Сбросить список к дефолтным значениям."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok = hm.reset_to_defaults(name)
        if not ok:
            response.status = 500
            return {"ok": False, "error": "Ошибка сброса"}

        domains = hm.get_hostlist(name)
        return {
            "ok": True,
            "count": len(domains),
            "message": "Список сброшен к дефолтам (%d доменов)" % len(domains),
        }

    @app.post("/api/hostlists/<name>/import")
    def api_hostlists_import(name):
        """Импорт доменов из URL или текста."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager

        hm = get_hostlist_manager()

        if not hm.is_valid_name(name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        url = str(body.get("url", "")).strip()
        text = str(body.get("text", "")).strip()

        if url:
            added = hm.import_from_url(name, url)
            if added < 0:
                response.status = 500
                return {"ok": False, "error": "Ошибка загрузки URL"}
            return {"ok": True, "added": added, "message": "Импортировано %d доменов из URL" % added}

        if text:
            added = hm.import_from_text(name, text)
            return {"ok": True, "added": added, "message": "Импортировано %d доменов из текста" % added}

        response.status = 400
        return {"ok": False, "error": "Укажите 'url' или 'text' для импорта"}
