# api/awg.py
"""
REST API для интеграции amneziawg-go.

Маршруты:
  GET  /api/awg/environment  — полный отчёт об окружении
  POST /api/awg/environment/refresh — сбросить кэш и пересканировать
"""

from bottle import response


def register(app):

    @app.route("/api/awg/environment")
    def awg_environment():
        """
        Полный отчёт об окружении для AWG:
          platform     — платформа и её возможности
          architecture — uname / opkg-arch / artifact_arch
          tun          — доступность TUN
          existing     — уже установленные бинарники, конфиги, интерфейсы
          prerequisites — что нужно для работы и что пока не выполнено
          ready        — true если все обязательные prerequisites выполнены
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report()

    @app.route("/api/awg/environment/refresh", method="POST")
    def awg_environment_refresh():
        """Сбросить кэш детекта и вернуть свежий отчёт."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report(force=True)
