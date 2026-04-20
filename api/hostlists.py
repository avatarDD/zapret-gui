# api/hostlists.py
"""
API списков доменов (hostlists).

Эндпоинты:
  GET    /api/hostlists              — список всех файлов со статистикой
  POST   /api/hostlists/create       — создать новый пользовательский список
  GET    /api/hostlists/:name        — содержимое файла (список доменов)
  PUT    /api/hostlists/:name        — заменить весь список
  DELETE /api/hostlists/:name        — удалить пользовательский список
  POST   /api/hostlists/:name/rename — переименовать пользовательский список
  POST   /api/hostlists/:name/add    — добавить домены
  POST   /api/hostlists/:name/remove — удалить домены
  POST   /api/hostlists/:name/reset  — сброс к дефолтам
  POST   /api/hostlists/:name/import — импорт из URL или текста

Имя списка:
  — встроенные: other, other2, netrogat (нельзя удалить/переименовать)
  — пользовательские: любое имя, удовлетворяющее ^[a-zA-Z0-9_-]{1,64}$
    и НЕ принадлежащее namespace'у IP-списков (ipset-*, my-ipset)
"""

from bottle import request, response


def _validate_name(hm, name):
    """Проверить имя через менеджер (единый источник правды)."""
    return hm._validate_name(name)


def register(app):

    @app.route("/api/hostlists")
    def api_hostlists_list():
        """Список всех hostlist-файлов со статистикой."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        stats = hm.get_stats()
        # Сохраняем порядок: встроенные сначала, затем кастомные по алфавиту
        files = [stats[nm] for nm in hm.list_names() if nm in stats]
        return {"ok": True, "files": files}

    @app.post("/api/hostlists/create")
    def api_hostlists_create():
        """Создать новый пустой пользовательский список."""
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

        name = (body.get("name") or "").strip()
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}

        if not _validate_name(hm, name):
            response.status = 400
            return {
                "ok": False,
                "error": "Недопустимое имя. Разрешены латиница, цифры, '_' и '-' (1..64 символов)",
            }

        ok, err = hm.create_hostlist(name)
        if not ok:
            response.status = 400 if "существует" in err else 500
            return {"ok": False, "error": err or "Ошибка создания"}

        stats = hm.get_stats().get(name, {})
        return {
            "ok": True,
            "name": name,
            "file": stats,
            "message": "Создан список %s.txt" % name,
        }

    @app.route("/api/hostlists/<name>")
    def api_hostlists_get(name):
        """Получить содержимое hostlist-файла."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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
            "is_builtin": stats.get("is_builtin", False),
        }

    @app.put("/api/hostlists/<name>")
    def api_hostlists_put(name):
        """Заменить весь список доменов."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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

        # Нормализуем домены
        normalized = []
        invalid = []
        for d in domains:
            nd = hm.normalize_domain(d)
            if nd:
                normalized.append(nd)
            elif d.strip():
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

    @app.post("/api/hostlists/<name>/rename")
    def api_hostlists_rename(name):
        """Переименовать пользовательский список."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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

        new_name = (body.get("new_name") or "").strip()
        if not new_name:
            response.status = 400
            return {"ok": False, "error": "Поле 'new_name' обязательно"}

        ok, err = hm.rename_hostlist(name, new_name)
        if not ok:
            if "встроенный" in err or "встроенного" in err:
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            elif "уже существует" in err or "совпадает" in err or "Недопустимое" in err:
                response.status = 400
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка переименования"}

        stats = hm.get_stats().get(new_name, {})
        return {
            "ok": True,
            "name": new_name,
            "file": stats,
            "message": "Список %s.txt переименован в %s.txt" % (name, new_name),
        }

    @app.delete("/api/hostlists/<name>")
    def api_hostlists_delete(name):
        """Удалить пользовательский список."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok, err = hm.delete_hostlist(name)
        if not ok:
            if "встроенный" in err:
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка удаления"}

        return {"ok": True, "message": "Удалён список %s.txt" % name}

    @app.post("/api/hostlists/<name>/add")
    def api_hostlists_add(name):
        """Добавить домены в список."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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
        return {
            "ok": True,
            "added": added,
            "message": "Добавлено %d доменов" % added,
        }

    @app.post("/api/hostlists/<name>/remove")
    def api_hostlists_remove(name):
        """Удалить домены из списка."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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
        return {
            "ok": True,
            "removed": removed,
            "message": "Удалено %d доменов" % removed,
        }

    @app.post("/api/hostlists/<name>/reset")
    def api_hostlists_reset(name):
        """Сбросить список к дефолтным значениям."""
        response.content_type = "application/json; charset=utf-8"
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()

        if not _validate_name(hm, name):
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

        if not _validate_name(hm, name):
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

        url = body.get("url", "").strip()
        text = body.get("text", "").strip()

        if url:
            added = hm.import_from_url(name, url)
            if added < 0:
                response.status = 500
                return {"ok": False, "error": "Ошибка загрузки URL"}
            return {
                "ok": True,
                "added": added,
                "message": "Импортировано %d доменов из URL" % added,
            }
        elif text:
            added = hm.import_from_text(name, text)
            return {
                "ok": True,
                "added": added,
                "message": "Импортировано %d доменов из текста" % added,
            }
        else:
            response.status = 400
            return {"ok": False, "error": "Укажите 'url' или 'text' для импорта"}
