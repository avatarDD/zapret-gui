from bottle import request, response
def register(app):
    @app.route("/api/blobs")
    def api_blobs_list():
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        bm = get_blob_manager()
        blobs = bm.get_blobs()
        return {
            "ok": True,
            "blobs": [
                {
                    "name": b["name"],
                    "size": b["size"],
                    "type": b["type"],
                    "is_builtin": b["is_builtin"],
                }
                for b in blobs
            ],
        }
    @app.route("/api/blobs/stats")
    def api_blobs_stats():
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        bm = get_blob_manager()
        stats = bm.get_stats()
        return {"ok": True, "stats": stats}
    @app.route("/api/blobs/<name>")
    def api_blobs_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        bm = get_blob_manager()
        info = bm.get_blob(name)
        if not info:
            response.status = 404
            return {"ok": False, "error": "Блоб не найден: %s" % name}
        hex_content = bm.get_blob_hex(name)
        raw = bm.get_blob_content(name)
        hex_dump = ""
        if raw:
            hex_dump = bm.format_hex(raw)
        return {
            "ok": True,
            "blob": {
                "name": info["name"],
                "size": info["size"],
                "type": info["type"],
                "is_builtin": info["is_builtin"],
                "hex": hex_content or "",
                "hex_dump": hex_dump,
            },
        }
    @app.post("/api/blobs")
    def api_blobs_create():
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        from core.log_buffer import log
        bm = get_blob_manager()
        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}
        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}
        name = body.get("name", "").strip()
        hex_data = body.get("hex", "").strip()
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}
        if not hex_data:
            response.status = 400
            return {"ok": False, "error": "Поле 'hex' обязательно"}
        valid, err = bm.validate_name(name)
        if not valid:
            response.status = 400
            return {"ok": False, "error": err}
        if bm.is_builtin(name):
            response.status = 400
            return {"ok": False, "error": "Нельзя использовать имя встроенного блоба"}
        if bm.get_blob(name):
            response.status = 409
            return {"ok": False, "error": "Блоб с таким именем уже существует: %s" % name}
        ok, error = bm.save_blob_hex(name, hex_data)
        if not ok:
            response.status = 400
            return {"ok": False, "error": error}
        log.success(f"Блоб создан через API: {name}", source="blobs")
        info = bm.get_blob(name)
        return {
            "ok": True,
            "blob": {
                "name": info["name"],
                "size": info["size"],
                "type": info["type"],
                "is_builtin": info["is_builtin"],
            },
        }
    @app.put("/api/blobs/<name>")
    def api_blobs_update(name):
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        from core.log_buffer import log
        bm = get_blob_manager()
        info = bm.get_blob(name)
        if not info:
            response.status = 404
            return {"ok": False, "error": "Блоб не найден: %s" % name}
        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}
        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}
        hex_data = body.get("hex", "").strip()
        if not hex_data:
            response.status = 400
            return {"ok": False, "error": "Поле 'hex' обязательно"}
        ok, error = bm.save_blob_hex(name, hex_data)
        if not ok:
            response.status = 400
            return {"ok": False, "error": error}
        log.info(f"Блоб обновлён через API: {name}", source="blobs")
        updated = bm.get_blob(name)
        return {
            "ok": True,
            "blob": {
                "name": updated["name"],
                "size": updated["size"],
                "type": updated["type"],
                "is_builtin": updated["is_builtin"],
            },
        }
    @app.delete("/api/blobs/<name>")
    def api_blobs_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        from core.log_buffer import log
        bm = get_blob_manager()
        ok, error = bm.delete_blob(name)
        if not ok:
            response.status = 400
            return {"ok": False, "error": error}
        log.info(f"Блоб удалён через API: {name}", source="blobs")
        return {"ok": True}
    @app.post("/api/blobs/generate")
    def api_blobs_generate():
        response.content_type = "application/json; charset=utf-8"
        from core.blob_manager import get_blob_manager
        from core.log_buffer import log
        bm = get_blob_manager()
        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}
        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}
        gen_type = body.get("type", "").strip().lower()
        domain = body.get("domain", "").strip()
        save_name = body.get("name", "").strip()
        if gen_type not in ("tls", "http"):
            response.status = 400
            return {"ok": False, "error": "Тип должен быть 'tls' или 'http'"}
        if not domain:
            response.status = 400
            return {"ok": False, "error": "Поле 'domain' обязательно"}
        if len(domain) > 253 or not all(
            c.isalnum() or c in ".-_" for c in domain
        ):
            response.status = 400
            return {"ok": False, "error": "Некорректный домен"}
        try:
            if gen_type == "tls":
                data = bm.generate_fake_tls(domain)
            else:
                data = bm.generate_fake_http(domain)
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": "Ошибка генерации: %s" % str(e)}
        hex_str = " ".join(f"{b:02x}" for b in data)
        hex_dump = bm.format_hex(data)
        result = {
            "ok": True,
            "generated": {
                "type": gen_type,
                "domain": domain,
                "size": len(data),
                "hex": hex_str,
                "hex_dump": hex_dump,
            },
        }
        if save_name:
            valid, err = bm.validate_name(save_name)
            if not valid:
                response.status = 400
                return {"ok": False, "error": err}
            if bm.is_builtin(save_name):
                response.status = 400
                return {"ok": False, "error": "Нельзя использовать имя встроенного блоба"}
            ok, error = bm.save_blob(save_name, data)
            if not ok:
                response.status = 500
                return {"ok": False, "error": error}
            result["saved"] = {
                "name": save_name,
                "size": len(data),
                "type": gen_type,
            }
            log.success(
                f"Сгенерирован и сохранён блоб: {save_name} ({gen_type}, {domain})",
                source="blobs",
            )
        return result
