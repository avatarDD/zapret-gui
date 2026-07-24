# api/geosite.py
"""
API-модуль для geosite/geoip импорта и DNS-провайдеров.

Эндпоинты:
  GET  /api/geosite/providers     — список DNS-провайдеров
  GET  /api/geosite/categories    — список категорий в файле
  POST /api/geosite/import        — импорт категории как named list
"""

import os

from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты geosite."""

    @app.route("/api/geosite/providers", method="GET")
    def geosite_providers():
        from core.dns_providers import list_providers
        return {"ok": True, "providers": list_providers()}

    @app.route("/api/geosite/categories", method="GET")
    def geosite_categories():
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        base = cfg.get("zapret", "base_path", default="/opt/zapret2")
        # Ищем geosite.dat
        candidates = [
            os.path.join(base, "files", "geosite.dat"),
            os.path.join(base, "geosite.dat"),
        ]
        path = ""
        for p in candidates:
            if os.path.isfile(p):
                path = p
                break
        if not path:
            return {"ok": False, "error": "geosite.dat не найден",
                    "searched": candidates}

        from core.geosite_importer import parse_geosite
        data = parse_geosite(path)
        return {"ok": True, "path": path,
                "categories": sorted(data.keys()),
                "counts": {k: len(v) for k, v in data.items()}}

    @app.route("/api/geosite/import", method="POST")
    def geosite_import():
        from core.config_manager import get_config_manager
        from core.geosite_importer import import_category
        cfg = get_config_manager()
        base = cfg.get("zapret", "base_path", default="/opt/zapret2")

        data = request.json or {}
        category = (data.get("category") or "").strip()
        list_id = (data.get("list_id") or "").strip()

        if not category:
            return {"ok": False, "error": "category обязателен"}

        path = ""
        for p in [os.path.join(base, "files", "geosite.dat"),
                  os.path.join(base, "geosite.dat")]:
            if os.path.isfile(p):
                path = p
                break
        if not path:
            return {"ok": False, "error": "geosite.dat не найден"}

        return import_category(path, category, list_id)
