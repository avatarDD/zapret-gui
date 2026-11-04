# tests/test_mcp_tools_diagnostics.py
"""
Диагностика, вердикт DPI и обновления — и граница «читает / пробует».

Главное, что здесь зафиксировано, — **инструмент публикуется всегда, а
разрешение спрашивается за действие**. `diagnostics_run` без `probes`
делает пассивную часть (окружение, конфликты, предпосылки) и прямо
пишет, что сетевые пробы пропущены и чем включаются; с `probes` —
полный прогон. Спрятать инструмент целиком было бы хуже: пассивная
часть не выпускает ни одного пакета и чинит половину жалоб.

Тот же приём повторяет `updates_check` (поход в апстрим) и повторит
healthcheck из S8 — поэтому проверяется именно он, а не только текст
ответа.

Сетевые вызовы замоканы: тест, который правда ходит в интернет, красен
на машине без интернета и зелен там, где сломан код.
"""

import json
import time
import unittest

from core import diagnostics as diag
from core.config_manager import get_config_manager
from core.mcp import registry


def call(name, args=None):
    return registry.call(name, args or {}, {})["structuredContent"]


class Probes:
    """Включить/выключить разрешение `probes` на время теста.

    Инструмент спрашивает разрешения у конфига, а не у аргументов
    вызова: обработчику карта разрешений не передаётся (см.
    `registry.call`), и спрашивать её больше негде.
    """

    def __init__(self, case, granted):
        cfg = get_config_manager()
        saved = cfg.get("mcp", "permissions", default={}) or {}
        case.addCleanup(cfg.set, "mcp", "permissions", dict(saved))
        updated = dict(saved)
        updated["probes"] = granted
        cfg.set("mcp", "permissions", updated)


class Patch:
    """Подмена атрибутов модулей на время теста."""

    def __init__(self, case, *targets):
        for module_name, attr, value in targets:
            module = __import__(module_name, fromlist=["x"])
            case.addCleanup(setattr, module, attr, getattr(module, attr))
            setattr(module, attr, value)


SERVICES_REPORT = {
    "services": {
        "youtube": {"name": "youtube", "display_name": "YouTube",
                    "status": "down",
                    "summary": {"ping_ok": True, "dns_ok": True,
                                "http_ok": False}},
        "telegram": {"name": "telegram", "display_name": "Telegram",
                     "status": "ok",
                     "summary": {"ping_ok": True, "dns_ok": True,
                                 "http_ok": True}},
    },
    "checked": ["youtube", "telegram"], "skipped": [], "unknown": [],
    "total": 2, "ok": 1, "down": 1, "partial": 0,
    "deadline_hit": False, "timestamp": 0,
}


class TestPassiveByDefault(unittest.TestCase):

    def setUp(self):
        Probes(self, False)

    def test_network_checks_are_skipped_and_said_to_be_skipped(self):
        data = call("diagnostics_run")
        self.assertTrue(data["ok"])
        self.assertNotIn("services", data["checks_run"])
        self.assertEqual(len(data["checks_skipped"]), 1)
        skipped = data["checks_skipped"][0]
        self.assertEqual(skipped["check"], "services")
        self.assertEqual(skipped["permission"], "probes")
        # Отказ, не называющий переключатель, заставляет модель
        # пробовать то же самое ещё раз.
        self.assertIn("probes", skipped["hint"])

    def test_passive_checks_still_run(self):
        data = call("diagnostics_run")
        self.assertEqual(data["checks_run"],
                         ["environment", "conflicts", "prerequisites"])
        self.assertIn("environment", data)

    def test_no_probe_is_fired_without_the_permission(self):
        def boom(*a, **kw):
            raise AssertionError("без probes сетевых проб быть не должно")

        Patch(self, ("core.diagnostics", "check_services", boom),
              ("core.diagnostics", "check_service", boom),
              ("core.diagnostics", "ping_host", boom),
              ("core.diagnostics", "check_http", boom))
        self.assertTrue(call("diagnostics_run")["ok"])

    def test_probes_block_describes_the_state(self):
        probes = call("diagnostics_run")["probes"]
        self.assertFalse(probes["allowed"])
        self.assertEqual(probes["permission"], "probes")
        self.assertTrue(probes["hint"])


class TestFullRunWithProbes(unittest.TestCase):

    def setUp(self):
        Probes(self, True)
        Patch(self, ("core.diagnostics", "check_services",
                     lambda names=None, deadline_sec=0.0: SERVICES_REPORT))

    def test_services_are_checked_and_reported(self):
        data = call("diagnostics_run")
        self.assertIn("services", data["checks_run"])
        self.assertEqual(data["checks_skipped"], [])
        self.assertTrue(data["probes"]["allowed"])
        self.assertEqual(data["services"]["ok"], 1)

    def test_a_dead_service_becomes_an_error_finding(self):
        items = call("diagnostics_run")["items"]
        found = [f for f in items if f["id"] == "service-youtube"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["status"], "error")
        self.assertIn("YouTube", found[0]["title"])

    def test_a_live_service_is_not_an_error(self):
        items = call("diagnostics_run")["items"]
        found = [f for f in items if f["id"] == "service-telegram"][0]
        self.assertEqual(found["status"], "ok")

    def test_checks_argument_narrows_the_run(self):
        data = call("diagnostics_run", {"checks": ["conflicts"]})
        self.assertEqual(data["checks_run"], ["conflicts"])
        self.assertNotIn("environment", data)

    def test_findings_are_sorted_errors_first(self):
        statuses = [f["status"] for f in call("diagnostics_run")["items"]]
        order = {"error": 0, "warning": 1, "info": 2, "ok": 3}
        self.assertEqual(statuses,
                         sorted(statuses, key=lambda s: order.get(s, 4)))


class TestProbeBudget(unittest.TestCase):
    """Долгий прогон режется бюджетом, а не таймаутом вызова."""

    def setUp(self):
        Probes(self, True)
        self.seen = {}

        def fake(names=None, deadline_sec=0.0):
            self.seen["deadline"] = deadline_sec
            self.seen["names"] = names
            report = dict(SERVICES_REPORT)
            report["skipped"] = ["discord"]
            report["deadline_hit"] = True
            return report

        Patch(self, ("core.diagnostics", "check_services", fake))

    def test_budget_is_a_share_of_the_tool_timeout(self):
        call("diagnostics_run")
        self.assertGreater(self.seen["deadline"], 0)

    def test_skipped_services_are_named_not_swallowed(self):
        # Молча недосчитанный сервис читается как «проверил, всё хорошо».
        data = call("diagnostics_run")
        self.assertEqual(data["services"]["skipped"], ["discord"])
        budget = [f for f in data["items"] if f["id"] == "probe-budget"]
        self.assertEqual(len(budget), 1)
        self.assertIn("discord", budget[0]["detail"])

    def test_service_list_is_passed_through(self):
        call("diagnostics_run", {"services": ["youtube"]})
        self.assertEqual(self.seen["names"], ["youtube"])


class TestServicesBudgetInCore(unittest.TestCase):
    """Бюджет живёт в core/diagnostics — значит, доступен и UI."""

    def test_deadline_stops_the_walk_and_names_the_rest(self):
        calls = []

        def slow(name):
            calls.append(name)
            time.sleep(0.02)
            return {"name": name, "display_name": name, "status": "ok",
                    "summary": {}}

        original = diag.check_service
        diag.check_service = slow
        self.addCleanup(setattr, diag, "check_service", original)

        # Бюджет меньше одной проверки: первый сервис успевает (бюджет
        # ещё цел), на остальных обход останавливается — и они названы,
        # а не потеряны.
        report = diag.check_services(deadline_sec=0.01)
        self.assertEqual(len(calls), 1)
        self.assertTrue(report["deadline_hit"])
        self.assertEqual(report["checked"], calls)
        self.assertEqual(len(report["checked"]) + len(report["skipped"]),
                         len(diag.SERVICES))

    def test_unknown_service_is_reported_not_ignored(self):
        report = diag.check_services(["нет-такого-сервиса"])
        self.assertEqual(report["unknown"], ["нет-такого-сервиса"])
        self.assertEqual(report["checked"], [])

    def test_check_all_services_keeps_its_contract(self):
        original = diag.check_service
        diag.check_service = lambda name: {"name": name, "status": "ok",
                                           "display_name": name,
                                           "summary": {}}
        self.addCleanup(setattr, diag, "check_service", original)
        report = diag.check_all_services()
        for field in ("services", "total", "ok", "down", "partial",
                      "timestamp"):
            self.assertIn(field, report)


class TestDpiReport(unittest.TestCase):

    def test_no_report_is_an_answer_not_an_error(self):
        data = call("dpi_report")
        self.assertTrue(data["ok"])
        if not data.get("available", True):
            self.assertIn("reason", data)
            self.assertIn("hint", data)

    def test_nothing_is_started(self):
        def boom(*a, **kw):
            raise AssertionError("dpi_report не запускает пробы")

        from core import blockcheck
        runner = blockcheck.get_blockcheck_runner()
        original = runner.start
        runner.start = boom
        self.addCleanup(setattr, runner, "start", original)
        self.assertTrue(call("dpi_report")["ok"])

    def test_saved_report_is_rendered_compactly(self):
        from core import blockcheck
        runner = blockcheck.get_blockcheck_runner()
        original = runner.get_results_dict
        runner.get_results_dict = lambda: {
            "dpi_classification": "tls_dpi",
            "dpi_detail": "SNI-блокировка",
            "remediation": "zapret",
            "recommendations": ["фрагментировать ClientHello"],
            "mode": "quick", "finished_at": 1700000000,
            "elapsed_seconds": 12.5, "total_tests": 10,
            "passed_tests": 4, "failed_tests": 6, "error": "",
            "targets": [{
                "domain": "youtube.com", "overall_status": "blocked",
                "dpi_classification": "tls_dpi", "dpi_detail": "RST",
                "remediation": "zapret",
                "results": [{"status": "failed"}, {"status": "success"}],
            }],
        }
        self.addCleanup(setattr, runner, "get_results_dict", original)

        data = call("dpi_report")
        self.assertEqual(data["classification"], "tls_dpi")
        self.assertEqual(data["remediation"], "zapret")
        self.assertEqual(data["tests"], {"total": 10, "passed": 4,
                                         "failed": 6})
        target = data["items"][0]
        self.assertEqual(target["domain"], "youtube.com")
        self.assertEqual(target["passed"], 1)
        # Сырые results наружу не уезжают: это весь лимит ответа на
        # данные, по которым вердикт уже вынесен.
        self.assertNotIn("results", target)

    def test_stale_report_is_marked(self):
        from core import blockcheck
        runner = blockcheck.get_blockcheck_runner()
        original = runner.get_results_dict
        runner.get_results_dict = lambda: {
            "dpi_classification": "none", "finished_at": 1,
            "targets": [], "recommendations": []}
        self.addCleanup(setattr, runner, "get_results_dict", original)

        data = call("dpi_report")
        self.assertGreater(data["age_sec"], 86400)
        self.assertIn("blockcheck", data["hint"])


class TestUpdatesCheck(unittest.TestCase):

    def setUp(self):
        from core import update_checker
        self.module = update_checker

    def _patch_cache(self, results, checked_at=1700000000):
        original = self.module.get_cached_results
        self.module.get_cached_results = lambda: {
            "ok": True, "results": results,
            "updates_count": sum(1 for r in results if r.get("has_update")),
            "checked_at": checked_at}
        self.addCleanup(setattr, self.module, "get_cached_results", original)

    def test_cache_is_used_and_marked_as_cache(self):
        self._patch_cache([{"name": "sing-box", "installed": True,
                            "current": "1.12.0", "latest": "1.12.4",
                            "has_update": True, "path": "/opt/sbin/sing-box"}])
        data = call("updates_check")
        self.assertTrue(data["from_cache"])
        self.assertEqual(data["items"][0]["name"], "sing-box")
        self.assertEqual(data["updates_count"], 1)

    def test_refresh_without_probes_falls_back_to_cache(self):
        Probes(self, False)

        def boom():
            raise AssertionError("без probes в сеть не ходим")

        original = self.module.check_all
        self.module.check_all = boom
        self.addCleanup(setattr, self.module, "check_all", original)

        self._patch_cache([])
        data = call("updates_check", {"refresh": True})
        self.assertTrue(data["ok"])
        self.assertTrue(data["from_cache"])
        self.assertFalse(data["refresh"]["done"])
        self.assertIn("probes", data["hint"])

    def test_refresh_with_probes_asks_upstream(self):
        Probes(self, True)
        original = self.module.check_all
        self.module.check_all = lambda: {
            "ok": True, "checked_at": 1700000000, "updates_count": 0,
            "results": [{"name": "GUI", "installed": True,
                         "current": "1.0", "latest": "1.0"}]}
        self.addCleanup(setattr, self.module, "check_all", original)

        data = call("updates_check", {"refresh": True})
        self.assertFalse(data["from_cache"])
        self.assertTrue(data["refresh"]["done"])

    def test_network_failure_is_an_answer_not_a_crash(self):
        # Роутер без интернета — штатная ситуация: отдаём кеш и
        # объясняем, почему он кеш.
        Probes(self, True)
        original = self.module.check_all

        def fail():
            raise OSError("Network is unreachable")

        self.module.check_all = fail
        self.addCleanup(setattr, self.module, "check_all", original)
        self._patch_cache([{"name": "GUI", "installed": True,
                            "current": "1.0", "latest": "", "path": ""}])

        data = call("updates_check", {"refresh": True})
        self.assertTrue(data["ok"])
        self.assertIn("Network is unreachable", data["refresh"]["error"])
        self.assertEqual(data["count"], 1)

    def test_updates_only_narrows_the_table(self):
        self._patch_cache([
            {"name": "a", "installed": True, "has_update": True},
            {"name": "b", "installed": True, "has_update": False}])
        data = call("updates_check", {"updates_only": True})
        self.assertEqual([r["name"] for r in data["items"]], ["a"])

    def test_pinned_row_keeps_upstream_truth(self):
        # geneva: «последняя» — пин; про вышедший апстримный релиз должны
        # сказать поля строки, фильтр updates_only и подсказка.
        self._patch_cache([
            {"name": "geneva", "installed": True, "current": "1.2.0",
             "latest": "1.2.0", "has_update": False, "pinned": True,
             "latest_source": "pinned", "upstream_latest": "v1.3.0",
             "upstream_newer": True,
             "pin_reason": "sha256 сверены для этой версии"},
            {"name": "b", "installed": True, "has_update": False}])
        data = call("updates_check", {"updates_only": True})
        self.assertEqual([r["name"] for r in data["items"]], ["geneva"])
        row = data["items"][0]
        self.assertEqual(row["upstream_latest"], "v1.3.0")
        self.assertTrue(row["upstream_newer"])
        self.assertTrue(row["pinned"])
        self.assertEqual(row["latest_source"], "pinned")
        self.assertIn("geneva 1.3.0", data["hint"])

    def test_stale_cache_is_marked(self):
        self._patch_cache([], checked_at=1)
        data = call("updates_check")
        self.assertTrue(data["stale"])

    def test_empty_cache_points_at_the_tools_that_know_versions(self):
        self._patch_cache([], checked_at=0)
        data = call("updates_check")
        self.assertIn("tunnels_status", data["hint"])


class TestNoSecretsInDiagnostics(unittest.TestCase):

    def test_a_token_in_a_finding_is_masked(self):
        Probes(self, False)
        secret = "diagtokencafebabe42"

        Patch(self, ("core.diagnostics", "check_nfqws_conflicts",
                     lambda: {"conflicts": [
                         {"pid": 9, "name": "nfqws",
                          "cmdline": "nfqws --token=%s" % secret}],
                      "has_conflicts": True}))
        result = registry.call("diagnostics_run", {"checks": ["conflicts"]},
                               {})
        text = json.dumps(result["structuredContent"], ensure_ascii=False)
        self.assertIn("посторонний процесс", text)
        self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
