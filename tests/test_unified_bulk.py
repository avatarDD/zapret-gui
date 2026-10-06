"""Работа со многими маршрутами (core/unified/bulk.py): проверка
назначения, пересечения, массовые действия, экспорт/импорт."""

import unittest
from unittest import mock

from core.unified import bulk
from core.unified.model import UnifiedRoute


def _route(rid, domains=(), cidrs=(), lists=(), enabled=True,
           method="awg:awg0"):
    return {"id": rid, "name": rid, "enabled": enabled, "method": method,
            "destination": {"domains": list(domains), "cidrs": list(cidrs),
                            "list_ids": list(lists)}}


class TestValidate(unittest.TestCase):

    def test_bad_entries_are_named(self):
        errs = bulk.validate_destination({
            "domains": ["youtube.com", "youtube,com", "geosite:google",
                        "regexp:(", "cdn*.x.com"],
            "cidrs": ["10.0.0.0/8", "10.0.0.0/33", "nope"]})
        joined = " | ".join(errs)
        self.assertIn("youtube,com", joined)
        self.assertIn("regexp:(", joined)
        self.assertIn("10.0.0.0/33", joined)
        self.assertIn("nope", joined)
        self.assertNotIn("geosite", joined)
        self.assertNotIn("cdn*", joined)
        self.assertEqual(len(errs), 4)

    def test_save_route_validates_only_when_asked(self):
        from core.unified import manager
        data = {"name": "x", "method": "direct",
                "destination": {"domains": ["bad domain"]}}
        with mock.patch("core.unified.storage.get_route", return_value=None), \
                mock.patch("core.unified.storage.add_route"), \
                mock.patch("core.unified.applier.apply_route",
                           return_value={"ok": True}), \
                mock.patch.object(manager, "_sync_monitor"):
            refused = manager.save_route(data, validate=True)
            accepted = manager.save_route(data)
        self.assertFalse(refused["ok"])
        self.assertIn("bad domain", refused["error"])
        self.assertTrue(accepted["ok"])


class TestOverlaps(unittest.TestCase):

    def test_domains_cidrs_and_lists(self):
        found = bulk.find_overlaps([
            _route("a", domains=["youtube.com", "x.org"],
                   cidrs=["10.0.0.0/8"], lists=["hl:other"]),
            _route("b", domains=["youtube.com", "r1.googlevideo.com"],
                   cidrs=["10.1.0.0/16"]),
            _route("c", domains=["googlevideo.com"], lists=["hl:other"]),
            _route("off", domains=["x.org"], enabled=False),
        ])
        kinds = {(o["kind"], o["value"], tuple(o["routes"])) for o in found}
        self.assertIn(("domain", "youtube.com", ("a", "b")), kinds)
        self.assertIn(("subdomain", "r1.googlevideo.com", ("b", "c")), kinds)
        self.assertIn(("cidr", "10.1.0.0/16", ("a", "b")), kinds)
        self.assertIn(("list", "hl:other", ("a", "c")), kinds)
        # выключенный маршрут не в счёт
        self.assertFalse(any(o["value"] == "x.org" for o in found))

    def test_no_overlap_inside_one_route(self):
        self.assertEqual(bulk.find_overlaps([
            _route("a", domains=["a.com", "b.a.com"],
                   cidrs=["10.0.0.0/8", "10.1.0.0/16"])]), [])


class FakeStore:

    def __init__(self, routes):
        self.routes = {r.id: r for r in routes}

    def get_route(self, rid):
        return self.routes.get(rid)

    def load_routes(self):
        return list(self.routes.values())


class TestBulkAndTransfer(unittest.TestCase):

    def setUp(self):
        self.store = FakeStore([
            UnifiedRoute(route_id="r1", name="one", method="direct",
                         destination={"domains": ["a.com"]}),
            UnifiedRoute(route_id="r2", name="two", method="direct",
                         destination={"domains": ["b.com"]}),
        ])
        self.saved, self.deleted = [], []

        def save(data, **kw):
            self.saved.append((data, kw))
            r = UnifiedRoute.from_dict(data)
            self.store.routes[r.id] = r
            return {"ok": True, "route": r.to_dict()}

        def delete(rid):
            self.deleted.append(rid)
            self.store.routes.pop(rid, None)
            return {"ok": True}
        patches = [
            mock.patch("core.unified.storage.get_route",
                       side_effect=self.store.get_route),
            mock.patch("core.unified.storage.load_routes",
                       side_effect=self.store.load_routes),
            mock.patch("core.unified.manager.save_route", side_effect=save),
            mock.patch("core.unified.manager.delete_route",
                       side_effect=delete),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_disable_and_method(self):
        res = bulk.bulk(["r1", "r2", "zz"], "disable")
        self.assertEqual(res["done"], ["r1", "r2"])
        self.assertEqual(res["errors"][0]["id"], "zz")
        self.assertFalse(self.store.routes["r1"].enabled)
        res = bulk.bulk(["r1"], "set_method", method="nfqws2")
        self.assertTrue(res["ok"])
        self.assertEqual(self.store.routes["r1"].method, "nfqws2")
        self.assertFalse(bulk.bulk(["r1"], "set_method", method="bogus:")["ok"])
        self.assertFalse(bulk.bulk(["r1"], "explode")["ok"])

    def test_delete(self):
        bulk.bulk(["r2"], "delete")
        self.assertEqual(self.deleted, ["r2"])

    def test_export_import_roundtrip(self):
        data = bulk.export_routes(["r1"])
        self.assertEqual(data["format"], bulk.EXPORT_FORMAT)
        self.assertEqual([r["id"] for r in data["routes"]], ["r1"])
        # add: занятый id → копия с новым id
        res = bulk.import_routes(data, mode="add")
        self.assertTrue(res["ok"])
        self.assertNotEqual(res["imported"][0], "r1")
        self.assertTrue(self.saved[-1][1].get("validate"))
        # replace: тот же id
        res = bulk.import_routes(data, mode="replace")
        self.assertEqual(res["imported"], ["r1"])

    def test_import_rejects_foreign_files(self):
        self.assertFalse(bulk.import_routes({"format": "other"})["ok"])
        self.assertFalse(bulk.import_routes({"routes": "x"})["ok"])
        self.assertFalse(bulk.import_routes([], mode="merge")["ok"])

    def test_import_selected_ids_only(self):
        data = bulk.export_routes()
        res = bulk.import_routes(data, mode="replace", ids=["r2"])
        self.assertEqual(res["imported"], ["r2"])


if __name__ == "__main__":
    unittest.main()
