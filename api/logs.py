import json
import time
import queue
import traceback
from bottle import request, response
def register(app):
    @app.route("/api/logs")
    def api_logs():
        response.content_type = "application/json; charset=utf-8"
        from core.log_buffer import get_log_buffer
        buf = get_log_buffer()
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
        response.content_type = "text/event-stream"
        response.set_header("Cache-Control", "no-cache")
        response.set_header("Connection", "keep-alive")
        response.set_header("X-Accel-Buffering", "no")
        return _sse_generator()
    @app.post("/api/logs/clear")
    def api_logs_clear():
        response.content_type = "application/json; charset=utf-8"
        from core.log_buffer import get_log_buffer, log
        get_log_buffer().clear()
        log.info("Буфер логов очищен", source="api")
        return {"ok": True}
def _sse_generator():
    from core.log_buffer import get_log_buffer
    buf = get_log_buffer()
    q = queue.Queue(maxsize=100)
    def on_entry(entry):
        try:
            q.put_nowait(entry)
        except queue.Full:
            pass
    buf.add_listener(on_entry)
    try:
        yield _sse_event({"type": "connected", "timestamp": time.time()})
        while True:
            try:
                entry = q.get(timeout=15)
                yield _sse_event(entry.to_dict(), event="log")
            except queue.Empty:
                yield ": heartbeat\n\n"
            except Exception:
                continue
    except (GeneratorExit, BrokenPipeError, ConnectionResetError, OSError):
        pass
    except Exception:
        try:
            from core.log_buffer import log as _log
            _log.error("SSE stream error: %s" % traceback.format_exc(), source="api.logs")
        except Exception:
            pass
    finally:
        buf.remove_listener(on_entry)
def _sse_event(data, event=None):
    lines = []
    if event:
        lines.append("event: %s" % event)
    try:
        lines.append("data: %s" % json.dumps(data, ensure_ascii=False))
    except (TypeError, ValueError):
        lines.append("data: {}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)
