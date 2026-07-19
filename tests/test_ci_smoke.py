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


if __name__ == "__main__":
    unittest.main()
