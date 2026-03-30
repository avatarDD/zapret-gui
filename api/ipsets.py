from bottle import request, response
ALLOWED_NAMES = ("ipset-base", "my-ipset")
def register(app):
    @app.route("/api/ipsets")
    def api_ipsets_list():
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        stats = im.get_stats()
        files = []
        for name in ALLOWED_NAMES:
            if name in stats:
                files.append(stats[name])
        return {"ok": True, "files": files}
    @app.route("/api/ipsets/<name>")
    def api_ipsets_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        if name not in ALLOWED_NAMES:
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
        }
    @app.put("/api/ipsets/<name>")
    def api_ipsets_put(name):
        """Заменить весь IP-список."""
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        if name not in ALLOWED_NAMES:
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
    @app.post("/api/ipsets/<name>/add")
    def api_ipsets_add(name):
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        if name not in ALLOWED_NAMES:
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
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        if name not in ALLOWED_NAMES:
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
        response.content_type = "application/json; charset=utf-8"
        from core.ipset_manager import get_ipset_manager
        im = get_ipset_manager()
        if name not in ALLOWED_NAMES:
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
        if target not in ALLOWED_NAMES:
            response.status = 400
            return {"ok": False, "error": "Недопустимое имя файла: %s" % target}
        prefixes = im.load_by_asn(asn)
        if not prefixes:
            return {
                "ok": True,
                "prefixes": 0,
                "added": 0,
                "message": "ASN не содержит анонсированных префиксов или ошибка загрузки",
            }
        added = im.add_entries(target, prefixes)
        return {
            "ok": True,
            "prefixes": len(prefixes),
            "added": added,
            "message": "ASN: %d префиксов загружено, %d добавлено в %s" % (
                len(prefixes), added, target
            ),
        }
