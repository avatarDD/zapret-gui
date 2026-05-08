# api/lua_scripts.py
"""
API Lua-скриптов (--lua-init=@lua/*.lua для nfqws2).

Эндпоинты:
  GET    /api/lua                    — список всех *.lua файлов со статистикой
  POST   /api/lua/create             — создать новый пользовательский скрипт
  GET    /api/lua/:name              — содержимое скрипта
  PUT    /api/lua/:name              — заменить содержимое скрипта
  DELETE /api/lua/:name              — удалить пользовательский скрипт
  POST   /api/lua/:name/rename       — переименовать пользовательский скрипт
  POST   /api/lua/:name/reset        — восстановить bundled-версию
  POST   /api/lua/:name/check        — проверка синтаксиса по имени
  POST   /api/lua/check              — проверка синтаксиса по содержимому
"""

from bottle import request, response


def _validate_name(lm, name):
    return lm._validate_name(name)


def register(app):

    @app.route("/api/lua")
    def api_lua_list():
        """Список всех Lua-скриптов."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()
        stats = lm.get_stats()
        files = [stats[nm] for nm in lm.list_names() if nm in stats]
        return {"ok": True, "files": files}

    @app.post("/api/lua/create")
    def api_lua_create():
        """Создать новый пустой Lua-скрипт."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

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

        if not _validate_name(lm, name):
            response.status = 400
            return {
                "ok": False,
                "error": (
                    "Недопустимое имя. Разрешены латиница, цифры, "
                    "'_', '-', '.' (1..128 символов)"
                ),
            }

        content = body.get("content")
        if content is not None and not isinstance(content, str):
            response.status = 400
            return {"ok": False, "error": "'content' должен быть строкой"}

        ok, err = lm.create_script(name, content or "")
        if not ok:
            response.status = 400 if "существует" in err else 500
            return {"ok": False, "error": err or "Ошибка создания"}

        stats = lm.get_stats().get(name, {})
        return {
            "ok": True,
            "name": name,
            "file": stats,
            "message": "Создан скрипт %s.lua" % name,
        }

    @app.route("/api/lua/<name>")
    def api_lua_get(name):
        """Получить содержимое Lua-скрипта."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        content = lm.get_script(name)
        stats = lm.get_stats().get(name, {})
        if not stats and not content:
            response.status = 404
            return {"ok": False, "error": "Скрипт не найден"}

        return {
            "ok": True,
            "name": name,
            "filename": name + ".lua",
            "content": content,
            "size": stats.get("size", 0),
            "lines": stats.get("lines", 0),
            "is_builtin": stats.get("is_builtin", False),
            "modified_from_bundled": stats.get("modified_from_bundled", False),
        }

    @app.put("/api/lua/<name>")
    def api_lua_put(name):
        """Заменить содержимое Lua-скрипта."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
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

        content = body.get("content")
        if content is None or not isinstance(content, str):
            response.status = 400
            return {"ok": False, "error": "Поле 'content' обязательно (строка)"}

        ok, err = lm.save_script(name, content)
        if not ok:
            response.status = 400 if "Слишком" in err or "Недопустимое" in err else 500
            return {"ok": False, "error": err or "Ошибка записи"}

        stats = lm.get_stats().get(name, {})
        return {
            "ok": True,
            "name": name,
            "size": stats.get("size", 0),
            "lines": stats.get("lines", 0),
            "message": "Сохранено %s.lua" % name,
        }

    @app.delete("/api/lua/<name>")
    def api_lua_delete(name):
        """Удалить пользовательский скрипт."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok, err = lm.delete_script(name)
        if not ok:
            if "bundled" in err.lower():
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка удаления"}

        return {"ok": True, "message": "Удалён скрипт %s.lua" % name}

    @app.post("/api/lua/<name>/rename")
    def api_lua_rename(name):
        """Переименовать пользовательский скрипт."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
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

        ok, err = lm.rename_script(name, new_name)
        if not ok:
            if "bundled" in err.lower():
                response.status = 400
            elif "не существует" in err:
                response.status = 404
            elif "уже существует" in err or "совпадает" in err or "Недопустимое" in err or "занято" in err:
                response.status = 400
            else:
                response.status = 500
            return {"ok": False, "error": err or "Ошибка переименования"}

        stats = lm.get_stats().get(new_name, {})
        return {
            "ok": True,
            "name": new_name,
            "file": stats,
            "message": "Скрипт %s.lua переименован в %s.lua" % (name, new_name),
        }

    @app.post("/api/lua/<name>/reset")
    def api_lua_reset(name):
        """Восстановить bundled-версию скрипта."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        ok, err = lm.reset_to_bundled(name)
        if not ok:
            response.status = 400 if "bundled" in err.lower() else 500
            return {"ok": False, "error": err or "Ошибка сброса"}

        return {
            "ok": True,
            "message": "Скрипт %s.lua восстановлен из bundled" % name,
        }

    @app.post("/api/lua/<name>/check")
    def api_lua_check_named(name):
        """Проверка синтаксиса по имени файла."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        if not _validate_name(lm, name):
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя: %s" % name}

        # Если в теле передано content — проверяем его, иначе читаем файл.
        body = None
        try:
            body = request.json
        except Exception:
            body = None

        if body and isinstance(body.get("content"), str):
            result = lm.check_syntax(content=body["content"])
        else:
            result = lm.check_syntax(name=name)

        return {
            "ok": True,
            "name": name,
            "valid": result.get("ok", False),
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "checker": result.get("checker", "builtin"),
        }

    @app.post("/api/lua/check")
    def api_lua_check_inline():
        """Проверка синтаксиса произвольного содержимого."""
        response.content_type = "application/json; charset=utf-8"
        from core.lua_manager import get_lua_manager
        lm = get_lua_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body or not isinstance(body.get("content"), str):
            response.status = 400
            return {"ok": False, "error": "Поле 'content' обязательно (строка)"}

        result = lm.check_syntax(content=body["content"])
        return {
            "ok": True,
            "valid": result.get("ok", False),
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "checker": result.get("checker", "builtin"),
        }
