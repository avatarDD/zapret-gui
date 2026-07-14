# api/block_detector.py
"""
API-модуль Block Detector (DNS-мониторинг + автообнаружение блокировок).

Эндпоинты:
  GET  /api/block-detector/status   — статус детектора
  GET  /api/block-detector/results  — результаты проверок
  POST /api/block-detector/probe    — пронировать домен
  POST /api/block-detector/start    — запустить мониторинг
  POST /api/block-detector/stop     — остановить
"""

import json

from bottle import request

from core.log_buffer import log


def register(app):
    """Зарегистрировать API-маршруты block_detector."""

    @app.route("/api/block-detector/status", method="GET")
    def bd_status():
        from core.block_detector import get_block_detector
        return get_block_detector().get_status()

    @app.route("/api/block-detector/results", method="GET")
    def bd_results():
        from core.block_detector import get_block_detector
        return {"ok": True, "results": get_block_detector().get_results()}

    @app.route("/api/block-detector/probe", method="POST")
    def bd_probe():
        from core.block_detector import get_block_detector
        data = json.loads(request.body.read()) if request.body else {}
        domain = (data.get("domain") or "").strip()
        if not domain:
            return {"ok": False, "error": "domain обязателен"}
        return get_block_detector().probe_now(domain)

    @app.route("/api/block-detector/start", method="POST")
    def bd_start():
        from core.block_detector import get_block_detector
        get_block_detector().start()
        return {"ok": True}

    @app.route("/api/block-detector/stop", method="POST")
    def bd_stop():
        from core.block_detector import get_block_detector
        get_block_detector().stop()
        return {"ok": True}
