# tests/test_static_cache.py
"""
Тесты кэширования статики (app.py).

Симптом, ради которого это сделано: после обновления GUI браузер
показывает старый интерфейс, пока пользователь не нажмёт Ctrl+F5. Причина
— js/css отдавались без Cache-Control, и браузер по RFC 9111 считал их
свежими «на глазок» (эвристика от возраста файла).

Схема: index.html без кэша + ?v=<mtime> у каждой ссылки на статику +
вечный кэш для версионированных адресов.
"""

import os
import unittest

import app as app_module
from tests._wsgi_client import WSGIClient


def _build_app():
    """Приложение целиком (не только API) — нужны маршруты статики."""
    return app_module.create_app()


class TestIndexNotCached(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(_build_app())

    def test_index_has_no_store(self):
        status, headers, _ = self.client.get_raw("/")
        self.assertTrue(status.startswith("200"), status)
        self.assertIn("no-store", headers.get("cache-control", ""))

    def test_index_is_html(self):
        _, headers, body = self.client.get_raw("/")
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"<title>Zapret GUI</title>", body)

    def test_spa_route_returns_index(self):
        status, headers, body = self.client.get_raw("/dashboard")
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"page-container", body)
        self.assertIn("no-store", headers.get("cache-control", ""))
        self.assertTrue(status)


class TestAssetVersioning(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(_build_app())
        _, _, cls.html = cls.client.get_raw("/")
        cls.text = cls.html.decode("utf-8")

    def test_every_local_asset_is_versioned(self):
        # Ни одной ссылки на js/css/img без ?v= — иначе именно этот файл
        # и застрянет в кэше после обновления.
        import re
        bare = re.findall(r'\b(?:src|href)="(/(?:js|css|img)/[^"]+)"', self.text)
        stale = [u for u in bare if "?v=" not in u]
        self.assertEqual(stale, [], "без версии: %s" % stale)

    def test_version_is_file_mtime(self):
        import re
        m = re.search(r'src="(/js/app\.js)\?v=(\d+)"', self.text)
        self.assertIsNotNone(m, "app.js не найден в index.html")
        expected = int(os.path.getmtime(
            os.path.join(app_module.WEB_DIR, "js", "app.js")))
        self.assertEqual(int(m.group(2)), expected)

    def test_new_page_scripts_present(self):
        # Хабы разделов должны попадать в разметку — иначе вкладки не
        # соберутся (а сломается это молча).
        for name in ("blockcheck_hub.js", "strategy_scan_hub.js"):
            self.assertIn(name, self.text)

    def test_asset_version_of_missing_file_is_empty(self):
        self.assertEqual(app_module._asset_version("/js/no-such-file.js"), "")

    def test_missing_file_link_left_as_is(self):
        html = '<script src="/js/no-such-file.js"></script>'
        import re
        out = app_module._ASSET_URL_RE.sub(
            lambda m: m.group(0), html)
        self.assertEqual(out, html)
        self.assertIsNotNone(re.search(r'src="/js/', out))


class TestAssetCachePolicy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(_build_app())

    def test_versioned_asset_cached_forever(self):
        _, headers, _ = self.client.get_raw("/js/app.js?v=123")
        cc = headers.get("cache-control", "")
        self.assertIn("immutable", cc)
        self.assertIn("max-age=31536000", cc)

    def test_unversioned_asset_must_revalidate(self):
        _, headers, _ = self.client.get_raw("/js/app.js")
        self.assertEqual(headers.get("cache-control", ""), "no-cache")

    def test_css_and_img_follow_the_same_rule(self):
        for path in ("/css/style.css", "/img/favicon.svg"):
            with self.subTest(path=path):
                _, h1, _ = self.client.get_raw(path + "?v=1")
                self.assertIn("immutable", h1.get("cache-control", ""))
                _, h2, _ = self.client.get_raw(path)
                self.assertEqual(h2.get("cache-control", ""), "no-cache")


class TestMissingAssetIsNotHtml(unittest.TestCase):
    """Отсутствующий файл статики должен быть 404, а не главной страницей:
    иначе браузер получал HTML со статусом 200 и падал, разбирая его как
    скрипт."""

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(_build_app())

    def test_missing_js(self):
        status, headers, body = self.client.get_raw("/js/no-such-file.js")
        self.assertTrue(status.startswith("404"), status)
        self.assertNotIn("text/html", headers.get("content-type", ""))
        self.assertNotIn(b"<title>", body)

    def test_missing_css_and_img(self):
        for path in ("/css/no-such.css", "/img/no-such.svg"):
            with self.subTest(path=path):
                status, _, body = self.client.get_raw(path)
                self.assertTrue(status.startswith("404"), status)
                self.assertNotIn(b"<title>", body)

    def test_unknown_api_path_answers_json_not_html(self):
        # Несуществующий /api/-путь ловит catch-all OPTIONS-маршрут, поэтому
        # статус тут 405, а не 404 — важно, что ответ остаётся JSON и
        # клиент не получает HTML главной страницы.
        _, headers, body = self.client.get_raw("/api/no-such-endpoint")
        self.assertIn("json", headers.get("content-type", ""))
        self.assertIn(b'"ok"', body)
        self.assertNotIn(b"<title>", body)


if __name__ == "__main__":
    unittest.main()
