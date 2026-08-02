"""CI smoke tests: app boot, routes, filesystem safety."""

import os
import tempfile
import unittest
from unittest import mock

from app import create_app
from tests._wsgi_client import WSGIClient


class TestCiSmoke(unittest.TestCase):

    def _create_app(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        with mock.patch("threading.Thread.start", return_value=None):
            app = create_app(tmpdir.name)
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        try:
            cfg.set("gui", "auth_enabled", False)
            cfg.save()
        except Exception:
            pass
        return app, tmpdir.name

    def test_app_boot_smoke(self):
        app, _cfgdir = self._create_app()
        routes = {route.rule for route in app.routes}
        self.assertIn("/api/tgproxy/status", routes)
        self.assertIn("/api/tgproxy/detect", routes)
        self.assertIn("/api/updates/check", routes)
        self.assertIn("/", routes)

    def test_route_smoke(self):
        app, _cfgdir = self._create_app()
        client = WSGIClient(app)
        for path in ("/api/tgproxy/status", "/api/tgproxy/detect"):
            r = client.get_json(path)
            self.assertEqual(r["_status"], 200)

    def test_filesystem_smoke(self):
        app, cfgdir = self._create_app()
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        self.assertTrue(os.path.realpath(cfg.path).startswith(os.path.realpath(cfgdir)))
        self.assertTrue(os.path.isdir(os.path.dirname(cfg.path)))

    def test_api_500_carries_the_real_reason(self):
        """Issue #280: необработанное исключение отдавало «Internal Server
        Error» и не писалось никуда — в браузере оставался голый 500."""
        app, _cfgdir = self._create_app()

        @app.route("/api/_boom_test", method="GET")
        def _boom():
            raise ValueError("duplicate tag 'proxy'")

        logged = []
        import core.log_buffer as log_buffer
        with mock.patch.object(log_buffer.log, "error",
                               side_effect=lambda m, **k: logged.append(m)):
            r = WSGIClient(app).get_json("/api/_boom_test")

        self.assertEqual(r["_status"], 500)
        self.assertFalse(r["ok"])
        self.assertIn("duplicate tag 'proxy'", r["error"])
        self.assertIn("ValueError", r["error"])
        # traceback уезжает в лог GUI, а не только в stderr процесса
        self.assertTrue(any("/api/_boom_test" in m for m in logged), logged)


if __name__ == "__main__":
    unittest.main()
