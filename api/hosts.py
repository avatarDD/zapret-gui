# api/hosts.py
"""
API управления файлом /etc/hosts.

Эндпоинты:
  GET    /api/hosts           — все записи (системные + GUI)
  GET    /api/hosts/custom    — только GUI-записи
  GET    /api/hosts/stats     — статистика
  GET    /api/hosts/raw       — raw-текст файла
  PUT    /api/hosts/raw       — сохранить raw
  POST   /api/hosts/add       — добавить запись (ip + domain)
  POST   /api/hosts/remove    — удалить запись (по домену)
  POST   /api/hosts/block     — заблокировать домены (0.0.0.0)
  POST   /api/hosts/unblock   — снять блокировку
  POST   /api/hosts/clear     — удалить все GUI-записи
  GET    /api/hosts/presets   — список пресетов
  POST   /api/hosts/preset    — применить пресет
  POST   /api/hosts/backup    — создать бэкап
  GET    /api/hosts/backups   — список бэкапов
  POST   /api/hosts/restore   — восстановить из бэкапа
"""

from bottle import request, response


def register(app):

    @app.route("/api/hosts")
    def api_hosts_list():
        """Все записи из /etc/hosts."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        entries = hm.get_entries()
        return {
            "ok": True,
            "entries": [
                {
                    "ip": e["ip"],
                    "domain": e["domain"],
                    "comment": e["comment"],
                    "line_num": e["line_num"],
                    "is_system": e["is_system"],
                }
                for e in entries
            ],
            "count": len(entries),
        }

    @app.route("/api/hosts/custom")
    def api_hosts_custom():
        """Только GUI-записи (между маркерами)."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        entries = hm.get_custom_entries()
        return {
            "ok": True,
            "entries": [
                {
                    "ip": e["ip"],
                    "domain": e["domain"],
                    "comment": e["comment"],
                }
                for e in entries
            ],
            "count": len(entries),
        }

    @app.route("/api/hosts/stats")
    def api_hosts_stats():
        """Статистика записей."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        stats = hm.get_stats()
        return {"ok": True, "stats": stats}

    @app.route("/api/hosts/raw")
    def api_hosts_raw():
        """Полный текст /etc/hosts."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        text = hm.get_raw()
        return {"ok": True, "text": text}

    @app.route("/api/hosts/raw", method="PUT")
    def api_hosts_raw_save():
        """Сохранить полный текст /etc/hosts."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        from core.log_buffer import log
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body or "text" not in body:
            response.status = 400
            return {"ok": False, "error": "Поле 'text' обязательно"}

        text = body["text"]
        if not isinstance(text, str):
            response.status = 400
            return {"ok": False, "error": "Поле 'text' должно быть строкой"}

        ok = hm.save_raw(text)
        if ok:
            return {"ok": True, "message": "Файл hosts сохранён"}
        else:
            response.status = 500
            return {"ok": False, "error": "Ошибка записи файла. Возможно, файл read-only."}

    @app.route("/api/hosts/add", method="POST")
    def api_hosts_add():
        """Добавить запись в GUI-блок."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        ip = body.get("ip", "").strip()
        domain = body.get("domain", "").strip()

        if not ip:
            response.status = 400
            return {"ok": False, "error": "Поле 'ip' обязательно"}

        if not domain:
            response.status = 400
            return {"ok": False, "error": "Поле 'domain' обязательно"}

        ok = hm.add_entry(ip, domain)
        if ok:
            return {"ok": True, "message": f"Добавлено: {ip} → {domain}"}
        else:
            response.status = 400
            return {"ok": False, "error": "Ошибка добавления записи. Проверьте IP и домен."}

    @app.route("/api/hosts/remove", method="POST")
    def api_hosts_remove():
        """Удалить запись из GUI-блока по домену."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domain = body.get("domain", "").strip()
        if not domain:
            response.status = 400
            return {"ok": False, "error": "Поле 'domain' обязательно"}

        ok = hm.remove_entry(domain)
        if ok:
            return {"ok": True, "message": f"Удалено: {domain}"}
        else:
            response.status = 404
            return {"ok": False, "error": f"Домен не найден в GUI-блоке: {domain}"}

    @app.route("/api/hosts/block", method="POST")
    def api_hosts_block():
        """Заблокировать домены (0.0.0.0)."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domains = body.get("domains", [])
        if not domains or not isinstance(domains, list):
            response.status = 400
            return {"ok": False, "error": "Поле 'domains' — непустой массив"}

        count = hm.add_block(domains)
        return {"ok": True, "message": f"Заблокировано: {count} доменов", "count": count}

    @app.route("/api/hosts/unblock", method="POST")
    def api_hosts_unblock():
        """Снять блокировку доменов."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        domains = body.get("domains", [])
        if not domains or not isinstance(domains, list):
            response.status = 400
            return {"ok": False, "error": "Поле 'domains' — непустой массив"}

        count = hm.remove_block(domains)
        return {"ok": True, "message": f"Разблокировано: {count} доменов", "count": count}

    @app.route("/api/hosts/clear", method="POST")
    def api_hosts_clear():
        """Удалить все GUI-записи."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        ok = hm.clear_gui_entries()
        if ok:
            return {"ok": True, "message": "Все GUI-записи удалены"}
        else:
            response.status = 500
            return {"ok": False, "error": "Ошибка очистки записей"}

    @app.route("/api/hosts/presets")
    def api_hosts_presets():
        """Список доступных пресетов."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        presets = hm.get_presets()
        return {"ok": True, "presets": presets}

    @app.route("/api/hosts/preset", method="POST")
    def api_hosts_preset_apply():
        """Применить пресет."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        name = body.get("name", "").strip()
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}

        # Опционально: пользовательские записи для пресета
        custom_entries = None
        if "entries" in body and isinstance(body["entries"], list):
            custom_entries = []
            for e in body["entries"]:
                if isinstance(e, dict) and "ip" in e and "domain" in e:
                    custom_entries.append((e["ip"], e["domain"]))

        count = hm.apply_preset(name, custom_entries)
        if count > 0:
            return {"ok": True, "message": f"Пресет применён: {count} записей", "count": count}
        else:
            response.status = 400
            return {"ok": False, "error": "Пресет не найден или записи не добавлены", "count": 0}

    @app.route("/api/hosts/backup", method="POST")
    def api_hosts_backup():
        """Создать бэкап /etc/hosts."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        path = hm.backup()
        if path:
            return {"ok": True, "message": "Бэкап создан", "path": path}
        else:
            response.status = 500
            return {"ok": False, "error": "Ошибка создания бэкапа"}

    @app.route("/api/hosts/backups")
    def api_hosts_backups():
        """Список доступных бэкапов."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        backups = hm.get_backups()
        return {"ok": True, "backups": backups}

    @app.route("/api/hosts/restore", method="POST")
    def api_hosts_restore():
        """Восстановить /etc/hosts из бэкапа."""
        response.content_type = "application/json; charset=utf-8"
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()

        try:
            body = request.json
        except Exception:
            response.status = 400
            return {"ok": False, "error": "Невалидный JSON"}

        if not body:
            response.status = 400
            return {"ok": False, "error": "Пустое тело запроса"}

        path = body.get("path", "").strip()
        if not path:
            response.status = 400
            return {"ok": False, "error": "Поле 'path' обязательно"}

        ok = hm.restore(path)
        if ok:
            return {"ok": True, "message": "Восстановлено из бэкапа"}
        else:
            response.status = 400
            return {"ok": False, "error": "Ошибка восстановления из бэкапа"}


