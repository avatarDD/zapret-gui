# api/ipsets.py
"""
API IP-списков (ipsets).

Эндпоинты:
  GET    /api/ipsets              — список файлов со статистикой
  POST   /api/ipsets/create       — создать новый пользовательский IP-список
  GET    /api/ipsets/:name        — содержимое файла
  PUT    /api/ipsets/:name        — заменить весь список
  DELETE /api/ipsets/:name        — удалить пользовательский список
  POST   /api/ipsets/:name/rename — переименовать пользовательский список
  POST   /api/ipsets/:name/add    — добавить IP/подсети
  POST   /api/ipsets/:name/remove — удалить IP/подсети
  POST   /api/ipsets/:name/reset  — сброс к дефолтам
  POST   /api/ipsets/load-asn     — загрузить IP по ASN

Имя списка:
  — встроенные: ipset-base, my-ipset (нельзя удалить/переименовать)
  — пользовательские: имена, начинающиеся с "ipset-", "ipset_",
    "my-ipset-" или "my-ipset_", длиной до 64 символов
    (разрешены латиница, цифры, "_" и "-")
"""

from bottle import request, response


def _validate_name(im, name):
    """Проверить имя через менеджер (единый источник правды)."""
    return im._validate_name(name)


def register(app):

    @app.route("/api/ipsets")
    def api_ipsets_list():
        """Список всех ipset-файлов со статистикой."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()
        stats = im.get_stats()

        # Встроенные сначала, затем кастомные по алфавиту
        files = [stats[nm] for nm in im.list_names() if nm in stats]
        return {"ok": True, "files": files}

    @app.post("/api/ipsets/create")
    def api_ipsets_create():
        """Создать новый пустой пользовательский IP-список."""
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()

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

        ok, err = im.create_ipset(name)
        if not ok:
            response.status = 400 if ("существует" in err or "Недопустимое" in err
                                      or "должно начинаться" in err) else 500
            return {"ok": False, "error": err or "Ошибка создания"}

        stats = im.get_stats().get(name, {})
        return {
            "ok": True,
            "name": name,
            "file": stats,
            "message": "Создан IP-список %s.txt" % name,
        }

    @app.route("/api/ipsets/<name>")
    def api_ipsets_get(name):
        """Получить содержимое ipset-файла."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        if not _validate_name(im, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        entries = im.get_ipset(name)
        stats = im.get_stats().get(name, {})

        return {
            "ok": True,
            "name": name,
            "entries": entries,
            "count": len(entries),
            "description": stats.get("description", ""),
            "is_builtin": stats.get("is_builtin", False),
        }

    @app.put("/api/ipsets/<name>")
    def api_ipsets_put(name):
        """Заменить весь IP-список."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        if not _validate_name(im, name):
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

        entries = body.get("entries")
        if entries is None:
            response.status = 400
            return {"ok": False, "error": "Поле 'entries' обязательно"}

        if not isinstance(entries, list):
            if isinstance(entries, str):
                entries = [e.strip() for e in entries.split("\n") if e.strip()]
            else:
                response.status = 400
                return {"ok": False, "error": "'entries' должен быть массивом или строкой"}

        # Валидируем
        validated = []
        invalid = []
        for e in entries:
            v = im.validate_entry(e)
            if v:
                validated.append(v)
            elif e.strip():
                invalid.append(e.strip())

        ok = im.save_ipset(name, validated)

        if not ok:
            response.status = 500
            return {"ok": False, "error": "Ошибка записи файла"}

        result = {
            "ok": True,
            "count": len(validated),
            "message": "Сохранено %d записей" % len(validated),
        }
        if invalid:
            result["invalid"] = invalid[:50]
            result["invalid_count"] = len(invalid)

        return result

    @app.delete("/api/ipsets/<name>")
    def api_ipsets_delete(name):
        """Удалить пользовательский IP-список."""
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()

        if not _validate_name(im, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok, err = im.delete_ipset(name)
        if not ok:
            if "встроенный" in err:
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка удаления"}

        return {"ok": True, "message": "Удалён IP-список %s.txt" % name}

    @app.post("/api/ipsets/<name>/rename")
    def api_ipsets_rename(name):
        """Переименовать пользовательский IP-список."""
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()

        if not _validate_name(im, name):
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

        ok, err = im.rename_ipset(name, new_name)
        if not ok:
            if "встроенный" in err or "встроенного" in err:
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            elif ("уже существует" in err or "совпадает" in err
                  or "Недопустимое" in err or "должно начинаться" in err):
                response.status = 400
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка переименования"}

        stats = im.get_stats().get(new_name, {})
        return {
            "ok": True,
            "name": new_name,
            "file": stats,
            "message": "IP-список %s.txt переименован в %s.txt" % (name, new_name),
        }

    @app.post("/api/ipsets/<name>/add")
    def api_ipsets_add(name):
        """Добавить IP/подсети в список."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        if not _validate_name(im, name):
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

        entries = body.get("entries", [])
        if isinstance(entries, str):
            entries = [e.strip() for e in entries.split("\n") if e.strip()]

        if not entries:
            response.status = 400
            return {"ok": False, "error": "Список записей пуст"}

        added = im.add_entries(name, entries)

        return {
            "ok": True,
            "added": added,
            "message": "Добавлено %d записей" % added,
        }

    @app.post("/api/ipsets/<name>/remove")
    def api_ipsets_remove(name):
        """Удалить IP/подсети из списка."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        if not _validate_name(im, name):
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

        entries = body.get("entries", [])
        if isinstance(entries, str):
            entries = [e.strip() for e in entries.split("\n") if e.strip()]

        if not entries:
            response.status = 400
            return {"ok": False, "error": "Список записей пуст"}

        removed = im.remove_entries(name, entries)

        return {
            "ok": True,
            "removed": removed,
            "message": "Удалено %d записей" % removed,
        }

    @app.post("/api/ipsets/<name>/reset")
    def api_ipsets_reset(name):
        """Сбросить IP-список к дефолтам."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        if not _validate_name(im, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok = im.reset_to_defaults(name)

        if not ok:
            response.status = 500
            return {"ok": False, "error": "Ошибка сброса"}

        entries = im.get_ipset(name)
        return {
            "ok": True,
            "count": len(entries),
            "message": "Список сброшен к дефолтам (%d записей)" % len(entries),
        }

    @app.post("/api/ipsets/load-asn")
    def api_ipsets_load_asn():
        """Загрузить IP-диапазоны по ASN и добавить в указанный файл."""
        response.content_type = "application/json; charset=utf-8"

        from core.ipset_manager import get_ipset_manager

        im = get_ipset_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        asn = body.get("asn")
        target = body.get("target", "my-ipset")

        if not asn:
            response.status = 400
            return {"ok": False, "error": "Поле 'asn' обязательно"}

        if not _validate_name(im, target):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя файла: %s" % target}

        # Загружаем по ASN
        prefixes = im.load_by_asn(asn)

        if not prefixes:
            return {
                "ok": True,
                "prefixes": 0,
                "added": 0,
                "message": "ASN не содержит анонсированных префиксов или ошибка загрузки",
            }

        # Добавляем в целевой файл
        added = im.add_entries(target, prefixes)

        return {
            "ok": True,
            "prefixes": len(prefixes),
            "added": added,
            "message": "ASN: %d префиксов загружено, %d добавлено в %s" % (
                len(prefixes), added, target
            ),
        }
