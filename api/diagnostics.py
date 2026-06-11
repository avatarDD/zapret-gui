# api/diagnostics.py
"""
API диагностики сети и системы.

Эндпоинты:
  POST /api/diagnostics/ping       — ping хоста
  POST /api/diagnostics/http       — HTTP(S) проверка
  POST /api/diagnostics/dns        — DNS проверка
  POST /api/diagnostics/service    — комплексная проверка сервиса
  POST /api/diagnostics/check-all  — проверить все сервисы
  GET  /api/diagnostics/conflicts  — конфликты nfqws/tpws
  GET  /api/diagnostics/known-conflicts — конфликты окружения
                                          (getdomains/XKeen/podkop/Xray/…)
  GET  /api/diagnostics/firewall   — статус firewall
  GET  /api/diagnostics/system     — расширенная системная информация
  GET  /api/diagnostics/services   — список доступных сервисов

  POST /api/diagnostics/selfcheck         — запустить самодиагностику
                                            (body: {tests, pattern}), фоном
  GET  /api/diagnostics/selfcheck/status  — прогресс/результат прогона
"""

import time
from bottle import request, response


def register(app):

    @app.route("/api/diagnostics/services")
    def api_diagnostics_services():
        """Список доступных сервисов для диагностики."""
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import get_available_services
        return {"ok": True, "services": get_available_services()}

    @app.route("/api/diagnostics/ping", method="POST")
    def api_diagnostics_ping():
        """Ping хоста."""
        response.content_type = "application/json; charset=utf-8"
        body = request.json or {}
        host = (body.get("host") or "").strip()

        if not host:
            response.status = 400
            return {"ok": False, "error": "host обязателен"}

        # Базовая валидация — не допускаем shell-инъекции
        if not _validate_host(host):
            response.status = 400
            return {"ok": False, "error": "Некорректный хост"}

        from core.diagnostics import ping_host
        count = min(int(body.get("count", 3)), 10)
        timeout = min(int(body.get("timeout", 3)), 10)
        result = ping_host(host, count=count, timeout=timeout)

        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/http", method="POST")
    def api_diagnostics_http():
        """HTTP(S) проверка URL."""
        response.content_type = "application/json; charset=utf-8"
        body = request.json or {}
        url = (body.get("url") or "").strip()

        if not url:
            response.status = 400
            return {"ok": False, "error": "url обязателен"}

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        from core.diagnostics import check_http
        timeout = min(int(body.get("timeout", 5)), 15)
        result = check_http(url, timeout=timeout)

        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/dns", method="POST")
    def api_diagnostics_dns():
        """DNS проверка домена."""
        response.content_type = "application/json; charset=utf-8"
        body = request.json or {}
        domain = (body.get("domain") or "").strip()

        if not domain:
            response.status = 400
            return {"ok": False, "error": "domain обязателен"}

        if not _validate_host(domain):
            response.status = 400
            return {"ok": False, "error": "Некорректный домен"}

        dns_server = (body.get("dns_server") or "").strip() or None
        if dns_server and not _validate_host(dns_server):
            response.status = 400
            return {"ok": False, "error": "Некорректный DNS-сервер"}

        from core.diagnostics import check_dns
        timeout = min(int(body.get("timeout", 3)), 10)
        result = check_dns(domain, dns_server=dns_server, timeout=timeout)

        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/service", method="POST")
    def api_diagnostics_service():
        """Комплексная проверка сервиса."""
        response.content_type = "application/json; charset=utf-8"
        body = request.json or {}
        name = (body.get("name") or "").strip()

        if not name:
            response.status = 400
            return {"ok": False, "error": "name обязателен"}

        from core.diagnostics import check_service, SERVICES
        if name not in SERVICES:
            response.status = 404
            return {"ok": False, "error": f"Сервис '{name}' не найден"}

        result = check_service(name)
        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/check-all", method="POST")
    def api_diagnostics_check_all():
        """Проверить все сервисы (может занять 30+ секунд)."""
        response.content_type = "application/json; charset=utf-8"

        from core.diagnostics import check_all_services, clear_cache
        # Очищаем кэш перед полной проверкой
        clear_cache()
        result = check_all_services()

        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/conflicts")
    def api_diagnostics_conflicts():
        """Проверка конфликтов nfqws/tpws."""
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import check_nfqws_conflicts
        result = check_nfqws_conflicts()
        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/known-conflicts")
    def api_diagnostics_known_conflicts():
        """Конфликты окружения: getdomains/XKeen/podkop/Xray/redsocks и пр."""
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import check_known_conflicts
        return {"ok": True, "result": check_known_conflicts()}

    @app.route("/api/diagnostics/firewall")
    def api_diagnostics_firewall():
        """Статус firewall."""
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import get_firewall_status
        result = get_firewall_status()
        return {"ok": True, "result": result}

    @app.route("/api/diagnostics/prerequisites")
    def api_diagnostics_prerequisites():
        """Готовность окружения к работе стратегий (lua/blob/nfqws/NFQUEUE).

        Главный диагност «почему сканер не находит ни одной рабочей
        стратегии / 0%». Возвращает issues с severity error|warning и hint.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import check_strategy_prerequisites
        return {"ok": True, "result": check_strategy_prerequisites()}

    @app.route("/api/diagnostics/system")
    def api_diagnostics_system():
        """Расширенная системная информация."""
        response.content_type = "application/json; charset=utf-8"
        from core.diagnostics import get_system_diagnostics
        result = get_system_diagnostics()
        return {"ok": True, "result": result, "timestamp": time.time()}

    @app.route("/api/diagnostics/selfcheck", method="POST")
    def api_diagnostics_selfcheck_start():
        """
        Запустить самодиагностику zapret-gui в фоне.
        body: {"tests": bool (вкл. юнит-тесты, default true),
               "pattern": "test_*.py" (фильтр тестов, опц.)}.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import selfcheck
        r = selfcheck.start_async(
            include_tests=bool(body.get("tests", True)),
            tests_pattern=(body.get("pattern") or "").strip())
        if not r.get("ok"):
            response.status = 409
        return r

    @app.route("/api/diagnostics/selfcheck/status")
    def api_diagnostics_selfcheck_status():
        """Прогресс и (по завершении) полный результат самодиагностики."""
        response.content_type = "application/json; charset=utf-8"
        from core import selfcheck
        return selfcheck.status()


def _validate_host(host):
    """Базовая валидация хоста/домена — защита от shell-инъекций."""
    import re
    # Допускаем: буквы, цифры, точки, дефисы, двоеточия (IPv6)
    if not host or len(host) > 253:
        return False
    if re.match(r'^[a-zA-Z0-9.:_-]+$', host):
        return True
    return False
