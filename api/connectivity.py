# api/connectivity.py
"""
REST API для матрицы связности.

Маршруты:
  GET    /api/connectivity/matrix         — последний snapshot
                                             (если не было probe — пустой)
  POST   /api/connectivity/probe          — запустить fresh probe
                                             (синхронно, до 30с)
  GET    /api/connectivity/targets        — текущий список таргетов
  POST   /api/connectivity/targets        — задать кастомный список
                                             body: {"targets": [{"name":"","host":""}, ...]}
                                             пустой items → возврат к defaults

  GET    /api/connectivity/traffic/<iface> — серии 1h/3h/24h RX/TX
                                              bps для интерфейса
  GET    /api/connectivity/traffic        — список интерфейсов,
                                              по которым есть сэмплы

  GET    /api/connectivity/peers/<iface>  — 5-минутный sparkline
                                              RX/TX по каждому peer'у
"""

from bottle import request, response


def register(app):

    @app.route("/api/connectivity/matrix")
    def connectivity_matrix():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.connectivity import get_matrix_manager
            snap = get_matrix_manager().get_snapshot()
            return {"ok": True, "snapshot": snap}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/probe", method="POST")
    def connectivity_probe():
        """Force-probe всех (target × iface). Возвращает свежий snapshot."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        ifaces = body.get("ifaces") if isinstance(body, dict) else None
        if isinstance(ifaces, list):
            ifaces = [str(x).strip() for x in ifaces if str(x).strip()]
        else:
            ifaces = None
        try:
            from core.connectivity import get_matrix_manager
            snap = get_matrix_manager().probe_once(ifaces=ifaces)
            return {"ok": True, "snapshot": snap}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/targets")
    def connectivity_targets_get():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.connectivity import get_matrix_manager, DEFAULT_TARGETS
            mgr = get_matrix_manager()
            return {
                "ok":       True,
                "targets":  mgr.get_targets(),
                "defaults": list(DEFAULT_TARGETS),
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/traffic")
    def connectivity_traffic_index():
        """Список интерфейсов, по которым уже накопились сэмплы."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.connectivity import (
                get_traffic_sampler, SAMPLE_INTERVAL_SEC, HISTORY_HOURS)
            sampler = get_traffic_sampler()
            return {
                "ok":              True,
                "ifaces":          sampler.list_known(),
                "sample_interval": SAMPLE_INTERVAL_SEC,
                "history_hours":   HISTORY_HOURS,
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/traffic/<iface>")
    def connectivity_traffic_iface(iface):
        """Серии 1h/3h/24h RX/TX для конкретного интерфейса."""
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.connectivity import get_traffic_sampler
            sampler = get_traffic_sampler()
            return {
                "ok":      True,
                "series":  sampler.get_series(iface),
                "current": sampler.get_current(iface),
            }
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/peers/<iface>")
    def connectivity_peers_iface(iface):
        """
        Per-peer sparkline RX/TX для интерфейса (последние 5 минут).

        Для нативных Keenetic-WG туннелей peers будет пустым — `awg
        show` их не видит, а RCI per-peer-метрику отдаёт в другом
        формате (отдельная задача).
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.connectivity import get_traffic_sampler
            sampler = get_traffic_sampler()
            return {"ok": True, "peers": sampler.get_peer_series(iface)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/connectivity/targets", method="POST")
    def connectivity_targets_set():
        """body: {"targets": [...]} — заменить список таргетов."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        targets = body.get("targets") if isinstance(body, dict) else None
        if targets is not None and not isinstance(targets, list):
            response.status = 400
            return {"ok": False, "error": "targets должен быть массивом"}
        try:
            from core.connectivity import get_matrix_manager
            mgr = get_matrix_manager()
            mgr.set_targets(targets or [])
            return {"ok": True, "targets": mgr.get_targets()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
