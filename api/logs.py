# api/logs.py
"""
API для логов.

GET  /api/logs          — последние записи (JSON)
GET  /api/logs/stream   — SSE поток в реальном времени
POST /api/logs/clear    — очистить буфер
"""

import json
import time
import queue
from bottle import request, response


def register(app):

    @app.route("/api/logs")
    def api_logs():
        """Получить записи логов с фильтрацией."""
        response.content_type = "application/json; charset=utf-8"

        from core.log_buffer import get_log_buffer

        buf = get_log_buffer()

        # Параметры
        n = min(int(request.params.get("n", 200)), 2000)
        level = request.params.get("level", None)
        search = request.params.get("search", None)
        since = request.params.get("since", None)

        if since:
            try:
                entries = buf.get_since(float(since))
            except ValueError:
                entries = buf.get_last(n)
        elif level or search:
            entries = buf.get_filtered(level=level, search=search, n=n)
        else:
            entries = buf.get_last(n)

        return {
            "ok": True,
            "entries": entries,
            "total": buf.get_count(),
            "counter": buf.get_counter(),
        }

    @app.route("/api/logs/stream")
    def api_logs_stream():
        """
        SSE (Server-Sent Events) — поток логов в реальном времени.

        Фронтенд подключается через EventSource:
            const es = new EventSource('/api/logs/stream');
            es.onmessage = (e) => { const entry = JSON.parse(e.data); ... };
        """
        response.content_type = "text/event-stream"
        response.set_header("Cache-Control", "no-cache")
        response.set_header("Connection", "keep-alive")
        response.set_header("X-Accel-Buffering", "no")  # Для nginx/lighttpd

        from core.log_buffer import get_log_buffer

        buf = get_log_buffer()
        q = queue.Queue(maxsize=100)

        def on_entry(entry):
            try:
                q.put_nowait(entry)
            except queue.Full:
                pass  # Пропускаем если клиент не успевает

        buf.add_listener(on_entry)

        try:
            # Отправляем начальное событие
            yield _sse_event({"type": "connected", "timestamp": time.time()})

            while True:
                try:
                    entry = q.get(timeout=15)
                    yield _sse_event(entry.to_dict(), event="log")
                except queue.Empty:
                    # Heartbeat чтобы соединение не закрылось
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            buf.remove_listener(on_entry)

    @app.post("/api/logs/clear")
    def api_logs_clear():
        """Очистить буфер логов."""
        response.content_type = "application/json; charset=utf-8"

        from core.log_buffer import get_log_buffer, log

        get_log_buffer().clear()
        log.info("Буфер логов очищен", source="api")

        return {"ok": True}


def _sse_event(data, event: str = None) -> str:
    """Форматировать SSE-событие."""
    lines = []
    if event:
        lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data, ensure_ascii=False)}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


