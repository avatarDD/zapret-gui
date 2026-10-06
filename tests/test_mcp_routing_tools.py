# tests/test_mcp_routing_tools.py
"""
Маршруты единого слоя через MCP: чтение, правка, границы разрешений.

Почему это вообще инструменты. Разговор с моделью почти всегда кончается
вопросом «а теперь пустить этот домен через что?»: обход подобран,
туннель поднят — и связать одно с другим было нечем.

Что стережём:

* **три уровня разрешений, и каждый обоснован.** Чтение — без
  разрешения (в маршруте нет ничего секретного, а половина жалоб
  «почему не открывается» объясняется именно им). Правка —
  `tunnels_write`. `unified_reapply_all` — `dangerous`: он не правит
  запись, а сносит «левые» ip rule и раскладывает картину маршрутов
  заново;
* **сохранение НЕ теряет непереданные поля.** «Поменяй метод» не должно
  стирать список доменов: маршрут сохраняется целиком, и недостающее
  берётся из прежней записи;
* **снимок на каждую правку** — иначе `mcp_undo_last` для маршрутов не
  работает;
* **отказ называет, что есть.**

Настоящая маршрутизация здесь не раскладывается: `core.unified.manager`
подменён.
"""

import unittest

from core.mcp import registry


WRITE = {"tunnels_write": True}
DANGEROUS = {"dangerous": True}


class FakeUnified:
    """Хранилище маршрутов в памяти с формой ответа настоящего слоя."""

    def __init__(self):
        self.routes = {}
        self.applied = []
        self.reapplied = 0

    # ── как `core.unified.manager` ──
    def list_routes(self):
        return [dict(r) for r in self.routes.values()]

    def get_route(self, route_id):
        found = self.routes.get(route_id)
        return dict(found) if found else None

    def save_route(self, data, apply=True, **_kw):
        if not str(data.get("method") or "").strip():
            return {"ok": False, "error": "Не выбран метод маршрута"}
        route = dict(data)
        route.setdefault("id", "route-%d" % (len(self.routes) + 1))
        route.setdefault("name", route["id"])
        route.setdefault("enabled", True)
        route.setdefault("destination", {})
        route.setdefault("fallbacks", [])
        self.routes[route["id"]] = route
        applied = {"ok": True} if apply and route["enabled"] else None
        return {"ok": True, "route": dict(route), "applied": applied}

    def delete_route(self, route_id):
        if route_id not in self.routes:
            return {"ok": False, "error": "Маршрут не найден"}
        del self.routes[route_id]
        return {"ok": True, "id": route_id}

    def apply_route_by_id(self, route_id):
        self.applied.append(route_id)
        return {"ok": True, "id": route_id}

    def reapply_all(self):
        self.reapplied += 1
        return {"ok": True, "sweep": {"ok": True, "total": 3},
                "applied": {"ok": True}, "legacy": {"ok": True}}

    def status(self):
        out = []
        for route in self.routes.values():
            out.append({"id": route["id"], "name": route["name"],
                        "enabled": route["enabled"],
                        "method": route["method"],
                        "active_method": route.get("_active",
                                                   route["method"]),
                        "monitor": {}, "suggest_scan": False,
                        "suggest_reason": ""})
        return {"ok": True, "routes": out, "monitor_running": False}


class Base(unittest.TestCase):

    def setUp(self):
        import core.unified.manager as manager

        registry.load_tools()
        self.fake = FakeUnified()
        for name in ("list_routes", "get_route", "save_route",
                     "delete_route", "apply_route_by_id", "reapply_all",
                     "status"):
            saved = getattr(manager, name)
            self.addCleanup(setattr, manager, name, saved)
            setattr(manager, name, getattr(self.fake, name))

    def data(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             WRITE if perms is None else perms
                             )["structuredContent"]

    def seed(self, **kwargs):
        payload = dict({"method": "awg:awg0",
                        "name": "youtube",
                        "destination": {"domains": ["youtube.com",
                                                    "googlevideo.com"]}},
                       **kwargs)
        return self.data("unified_route_save", payload)


class TestReading(Base):

    def test_list_is_open_without_any_permission(self):
        self.seed()
        payload = self.data("unified_route_list", {}, perms={})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["items"][0]["method"], "awg:awg0")

    def test_empty_list_says_how_to_create_one(self):
        payload = self.data("unified_route_list", {}, perms={})
        self.assertEqual(payload["total"], 0)
        self.assertIn("unified_route_save", payload["hint"])

    def test_filter_by_method_kind(self):
        self.seed()
        self.seed(name="other", method="nfqws2")
        by_kind = self.data("unified_route_list", {"method": "awg"},
                            perms={})
        self.assertEqual(by_kind["total"], 1)
        by_token = self.data("unified_route_list", {"method": "nfqws2"},
                             perms={})
        self.assertEqual(by_token["total"], 1)

    def test_search_looks_inside_the_destination(self):
        self.seed()
        payload = self.data("unified_route_list",
                            {"search": "googlevideo"}, perms={})
        self.assertEqual(payload["total"], 1)

    def test_status_reports_a_failover_switch(self):
        self.seed()
        route = next(iter(self.fake.routes.values()))
        route["_active"] = "singbox:tun0"
        payload = self.data("unified_route_status", {}, perms={})
        # Настроено одно, работает другое — молчать об этом нельзя.
        self.assertIn("failover", payload["hint"])


class TestWriting(Base):

    def test_save_needs_the_permission(self):
        answer = registry.call("unified_route_save",
                               {"method": "direct"}, {})
        self.assertTrue(answer["isError"])
        self.assertEqual(answer["structuredContent"]["permission"],
                         "tunnels_write")

    def test_save_creates_and_applies(self):
        payload = self.seed()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["created"])
        self.assertIsNotNone(payload["undo"])
        self.assertIn("unified_route_status", payload["hint"])

    def test_update_keeps_the_fields_that_were_not_sent(self):
        created = self.seed()
        payload = self.data("unified_route_save",
                            {"id": created["id"], "method": "singbox:tun0"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["created"])
        # «Поменяй метод» не должно стирать домены.
        self.assertEqual(
            payload["route"]["destination"]["domains"],
            ["youtube.com", "googlevideo.com"])

    def test_unknown_id_is_refused_with_the_known_ones(self):
        self.seed()
        payload = self.data("unified_route_save",
                            {"id": "route-nope", "method": "direct"})
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["known"])

    def test_bad_method_explains_the_choices(self):
        payload = self.data("unified_route_save",
                            {"method": "   "})
        self.assertFalse(payload["ok"])
        self.assertIn("awg:<iface>", payload["hint"])

    def test_disabled_route_says_it_does_nothing(self):
        payload = self.seed(enabled=False)
        self.assertIn("ВЫКЛЮЧЕННЫМ", payload["hint"])

    def test_delete_and_undo(self):
        created = self.seed()
        payload = self.data("unified_route_delete", {"id": created["id"]})
        self.assertTrue(payload["deleted"])
        self.assertEqual(self.fake.routes, {})

        undone = registry.call("mcp_undo_last", {},
                               WRITE)["structuredContent"]
        self.assertTrue(undone["reverted"])
        self.assertIn(created["id"], self.fake.routes)

    def test_undo_of_a_created_route_deletes_it(self):
        created = self.seed()
        undone = registry.call("mcp_undo_last", {},
                               WRITE)["structuredContent"]
        self.assertTrue(undone["reverted"])
        self.assertNotIn(created["id"], self.fake.routes)

    def test_apply_one_route(self):
        created = self.seed()
        payload = self.data("unified_route_apply", {"id": created["id"]})
        self.assertTrue(payload["ok"])
        self.assertEqual(self.fake.applied, [created["id"]])


class TestReapplyAll(Base):

    def test_needs_dangerous_not_tunnels_write(self):
        # Он меняет всю картину маршрутов сразу — включая тот путь,
        # которым ходит сам админ.
        answer = registry.call("unified_reapply_all", {}, WRITE)
        self.assertTrue(answer["isError"])
        self.assertEqual(answer["structuredContent"]["permission"],
                         "dangerous")

    def test_reports_what_it_swept(self):
        payload = self.data("unified_reapply_all", {}, perms=DANGEROUS)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["swept"], 3)
        self.assertEqual(self.fake.reapplied, 1)


if __name__ == "__main__":
    unittest.main()
