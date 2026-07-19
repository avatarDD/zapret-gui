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
        import re
        import socket
        import ipaddress
        from core.block_detector import get_block_detector
        data = request.json or {}
        domain = (data.get("domain") or "").strip()
        if not domain:
            return {"ok": False, "error": "domain обязателен"}

        # MR-62: валидация hostname — предотвращаем SSRF
        # без этого роутер используется как internal-port scanner / TLS-fingerprint oracle
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}[a-zA-Z0-9]$', domain):
            return {"ok": False, "error": "Невалидный домен"}

        # Резолвим и проверяем resolved IPs против RFC-1918/loopback
        try:
            addrs = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            for _fam, _type, _proto, _cn, sockaddr in addrs:
                ip_str = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        log.warning("block-detector probe: SSRF blocked — %s → %s" % (domain, ip_str),
                                    source="block_detector")
                        return {"ok": False, "error": "Домен резолвится во внутренний IP — запрос отклонён"}
                except ValueError:
                    pass
        except Exception:
            pass  # getaddrinfo failure — пусть probe_now обработает сам

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
