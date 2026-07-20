# api/auto_remediation.py
"""
API-модуль Auto-Remediation.

Эндпоинты:
  POST /api/remediation/run     — запустить по отчёту BlockCheck
  POST /api/remediation/apply   — запустить с auto_apply=true
  GET  /api/remediation/results — последние результаты

Query-параметры:
  ?dry_run=true   — preview: вернуть planned_actions без применения
"""


from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты auto_remediation."""

    @app.route("/api/remediation/run", method="POST")
    def remediation_run():
        from core.auto_remediation import get_auto_remediation
        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()
        report = runner.get_results()
        if not report:
            return {"ok": False, "error": "Сначала запустите BlockCheck"}

        data = request.json or {}
        auto_apply = data.get("auto_apply", False)
        dry_run = request.query.get("dry_run", "").lower() in ("true", "1", "yes")

        return get_auto_remediation().run(report,
                                         auto_apply=auto_apply,
                                         dry_run=dry_run)

    @app.route("/api/remediation/apply", method="POST")
    def remediation_apply():
        from core.auto_remediation import get_auto_remediation
        from core.blockcheck import get_blockcheck_runner

        runner = get_blockcheck_runner()
        report = runner.get_results()
        if not report:
            return {"ok": False, "error": "Сначала запустите BlockCheck"}

        dry_run = request.query.get("dry_run", "").lower() in ("true", "1", "yes")
        return get_auto_remediation().run(report,
                                         auto_apply=True,
                                         dry_run=dry_run)

    @app.route("/api/remediation/results", method="GET")
    def remediation_results():
        from core.auto_remediation import get_auto_remediation
        return {"ok": True, "results": get_auto_remediation().get_results()}

