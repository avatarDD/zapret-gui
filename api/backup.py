# api/backup.py
"""
REST API резервного копирования конфигурации.

  GET  /api/backup/export           — скачать бэкап (JSON-файл, attachment).
                                       Параметр ?sections=settings,singbox,…
  POST /api/backup/summary          — сводка по загруженному бэкапу (без
                                       восстановления): body = бэкап-JSON.
  POST /api/backup/import           — восстановить. body:
                                       {backup: <данные>, sections?: [...],
                                        restore_gui?: bool}
"""

import json
import time
from bottle import request, response


def _json_body():
    try:
        return request.json or {}
    except Exception:
        return {}


def register(app):

    @app.route("/api/backup/export")
    def backup_export():
        from core import backup as bk
        sections = request.params.get("sections") or ""
        include = [s.strip() for s in sections.split(",") if s.strip()] or None
        data = bk.build_backup(include=include)
        body = json.dumps(data, ensure_ascii=False, indent=2)
        fname = "zapret-gui-backup-%s.json" % time.strftime("%Y%m%d-%H%M%S")
        response.content_type = "application/json; charset=utf-8"
        response.set_header("Content-Disposition",
                            'attachment; filename="%s"' % fname)
        return body

    @app.route("/api/backup/summary", method="POST")
    def backup_summary():
        response.content_type = "application/json; charset=utf-8"
        from core import backup as bk
        data = _json_body()
        # Принимаем как «голый» бэкап, так и {backup: ...}
        if isinstance(data, dict) and "backup" in data:
            data = data["backup"]
        errors = bk.validate_backup(data)
        if errors:
            response.status = 400
            return {"ok": False, "error": "; ".join(errors)}
        return {"ok": True, "summary": bk.summary(data)}

    @app.route("/api/backup/import", method="POST")
    def backup_import():
        response.content_type = "application/json; charset=utf-8"
        from core import backup as bk
        body = _json_body()
        data = body.get("backup") if isinstance(body, dict) and "backup" in body \
            else body
        sections = body.get("sections") if isinstance(body, dict) else None
        restore_gui = bool(body.get("restore_gui")) \
            if isinstance(body, dict) else False
        res = bk.restore_backup(data, sections=sections,
                                restore_gui=restore_gui)
        if not res.get("ok"):
            response.status = 400
        return res
