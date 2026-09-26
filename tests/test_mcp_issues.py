# tests/test_mcp_issues.py
"""
Ошибки самого GUI: журнал падений и черновики issue.

Что здесь фиксируется, кроме «работает»:

* **падение оставляет место в коде.** Ответ модели несёт ``crash_id`` и
  ``where``, запись — кадры проекта без кадра ``registry.call`` (он
  есть в каждой трассировке и ничего не локализует);
* **секреты не уезжают ни в журнал падений, ни в черновик** — ни
  аргументом, ни текстом, который написала модель;
* **черновик несёт то, что модель исказила бы**: обработчик,
  трассировку и команду воспроизведения;
* **повтор склеивается**, а не плодит черновики, и черновиков не
  больше потолка;
* **домены и публичные адреса замаскированы по умолчанию**, частные
  адреса и имена файлов — нет;
* **ссылка «открыть на GitHub» доезжает целиком** (ключ вида
  ``*_url`` маска режет до хоста) и укладывается в длину адреса.

Всё пишется во временный каталог.
"""

import json
import os
import shutil
import tempfile
import unittest
from urllib.parse import unquote

from core.mcp import audit, crashes, issues, registry


PROBE_TOOL = "zz_issue_probe"


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value


def _crashing_handler(args):
    """Падает в коде проекта: кадры обязаны быть «нашими»."""
    from core.mcp.tools import _paging
    return _paging.page(None, "не число", 1)


class _Base(unittest.TestCase):

    def setUp(self):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="mcp-issues-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.addCleanup(_restore_env, os.environ.get("ZAPRET_GUI_CONFIG_DIR"))
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        registry.load_tools()
        if registry.get_tool(PROBE_TOOL) is None:
            registry.register_tool(PROBE_TOOL, _crashing_handler,
                                   description="test / тест", scope=None)
            self.addCleanup(registry._REGISTRY.pop, PROBE_TOOL, None)

    def call(self, name, args=None):
        return registry.call(name, args or {}, perms={})

    def crash(self, args=None):
        result = self.call(PROBE_TOOL, args)
        self.assertTrue(result["isError"])
        return result["structuredContent"]

    def draft(self, **args):
        args.setdefault("title", "инструмент падает")
        return self.call("issue_draft", args)["structuredContent"]


class TestCrashJournal(_Base):

    def test_failed_tool_returns_crash_id_and_location(self):
        payload = self.crash()
        self.assertTrue(payload["crash_id"].startswith("crash-"))
        self.assertIn("issue_draft", payload["hint"])
        self.assertTrue(payload["where"].startswith("core/mcp/tools/"),
                        payload["where"])

    def test_record_has_project_frames_without_registry(self):
        crash_id = self.crash()["crash_id"]
        entry = crashes.get(crash_id)
        self.assertIsNotNone(entry)
        files = [f["file"] for f in entry["frames"]]
        self.assertIn("tests/test_mcp_issues.py", files)
        self.assertEqual(files[-1], "core/mcp/tools/_paging.py")
        self.assertNotIn(("core/mcp/registry.py", "call"),
                         [(f["file"], f["function"]) for f in entry["frames"]])
        for frame in entry["frames"]:
            self.assertFalse(frame["file"].startswith("/"), frame)
        self.assertEqual(entry["handler"]["file"], "tests/test_mcp_issues.py")
        self.assertEqual(entry["exc_type"], "TypeError")

    def test_secrets_do_not_reach_the_crash_file(self):
        self.crash({"token": "abc-SECRET-1", "q": "password=hunter2"})
        with open(crashes.path(), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("abc-SECRET-1", text)
        self.assertNotIn("hunter2", text)

    def test_audit_record_links_the_crash(self):
        crash_id = self.crash()["crash_id"]
        records, _ = audit.read_records(limit=5)
        linked = [r for r in records
                  if (r.get("result") or {}).get("crash_id") == crash_id]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["status"], audit.STATUS_ERROR)

    def test_fingerprint_ignores_line_numbers(self):
        a = [{"file": "core/x.py", "line": 10, "function": "f"}]
        b = [{"file": "core/x.py", "line": 99, "function": "f"}]
        self.assertEqual(crashes.fingerprint("t", "E", a),
                         crashes.fingerprint("t", "E", b))

    def test_ring_is_bounded(self):
        for _ in range(crashes.KEEP + 5):
            self.crash()
        with open(crashes.path(), encoding="utf-8") as f:
            self.assertLessEqual(len(f.readlines()), crashes.KEEP)


class TestIssueDraft(_Base):

    def test_crash_draft_carries_location_and_repro(self):
        crash_id = self.crash({"query": "x"})["crash_id"]
        out = self.draft(crash_id=crash_id, actual="упал")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["draft"]["kind"], "crash")
        self.assertEqual(out["draft"]["tool"], PROBE_TOOL)
        md = out["markdown"]
        self.assertIn("core/mcp/tools/_paging.py:", md)
        self.assertIn("zapret-gui mcp call %s" % PROBE_TOOL, md)
        self.assertIn("zapret-gui-report/v1", md)
        self.assertIn(crash_id, md)

    def test_handler_of_a_real_tool_is_named(self):
        out = self.draft(tool="blobs_list", kind="wrong_result",
                         actual="не тот список")
        self.assertIn("core/mcp/tools/lists.py:", out["markdown"])

    def test_repeat_is_merged(self):
        crash_id = self.crash()["crash_id"]
        first = self.draft(crash_id=crash_id)
        again = self.draft(crash_id=self.crash()["crash_id"],
                           title="другими словами о том же")
        self.assertFalse(first["merged"])
        self.assertTrue(again["merged"])
        self.assertEqual(again["draft"]["occurrences"], 2)
        self.assertEqual(len(again["draft"]["crash_ids"]), 2)
        self.assertEqual(len(issues.list_drafts()), 1)

    def test_sent_draft_is_not_merged_into(self):
        out = self.draft(tool="blobs_list")
        issues.set_status(out["draft"]["id"], issues.STATUS_SENT)
        again = self.draft(tool="blobs_list")
        self.assertFalse(again["merged"])

    def test_drafts_are_capped(self):
        for n in range(issues.MAX_DRAFTS + 5):
            self.draft(title="ошибка номер %d" % n)
        self.assertEqual(len(issues.list_drafts()), issues.MAX_DRAFTS)

    def test_unknown_tool_and_crash_are_refused(self):
        self.assertTrue(self.call("issue_draft", {
            "title": "x", "tool": "no_such_tool"})["isError"])
        self.assertTrue(self.call("issue_draft", {
            "title": "x", "crash_id": "crash-nope"})["isError"])

    def test_secrets_in_model_text_are_masked(self):
        out = self.draft(evidence="token=supersecret42 Authorization: "
                                  "Bearer abcdef123456")
        self.assertNotIn("supersecret42", out["markdown"])
        self.assertNotIn("abcdef123456", out["markdown"])

    def test_targets_masked_by_default(self):
        text = ("rutracker.org и www.youtube.com через 8.8.8.8, роутер "
                "192.168.1.1, файл settings.json, core/mcp/tools/lists.py")
        md = self.draft(actual=text)["markdown"]
        for hidden in ("rutracker.org", "youtube.com", "8.8.8.8"):
            self.assertNotIn(hidden, md)
        for kept in ("192.168.1.1", "settings.json",
                     "core/mcp/tools/lists.py", "<домен-1>", "<ip-1>"):
            self.assertIn(kept, md)

    def test_domains_that_look_like_our_packages_are_masked(self):
        # `api.` и `web.` — и наши пакеты, и начало настоящих доменов:
        # раньше такие домены уезжали в отчёт открытым текстом.
        text = ("web.whatsapp.com, api.telegram.org и tools.example.ru; "
                "код: core.mcp.tools.lists, api.mcp_ui, "
                "urllib.error.URLError, os.path.join")
        md = self.draft(actual=text)["markdown"]
        for hidden in ("web.whatsapp.com", "api.telegram.org",
                       "tools.example.ru"):
            self.assertNotIn(hidden, md)
        for kept in ("core.mcp.tools.lists", "api.mcp_ui",
                     "urllib.error.URLError", "os.path.join"):
            self.assertIn(kept, md)

    def test_repro_args_from_model_are_masked_on_disk(self):
        self.draft(tool="blobs_list",
                   args={"password": "hunter2xyz", "offset": 0})
        with open(issues.path(), encoding="utf-8") as f:
            stored = f.read()
        self.assertNotIn("hunter2xyz", stored)
        self.assertIn('"offset": 0', stored)

    def test_include_targets_keeps_them(self):
        md = self.draft(actual="rutracker.org и 8.8.8.8",
                        include_targets=True)["markdown"]
        self.assertIn("rutracker.org", md)
        self.assertIn("8.8.8.8", md)

    def test_link_survives_redaction_and_fits(self):
        out = self.draft(actual="x" * 3000, evidence="y" * 3000,
                         steps=["шаг %d" % n for n in range(12)])
        url = out["open_on_github"]
        self.assertTrue(url.startswith(issues.NEW_ISSUE_URL + "?"), url[:80])
        self.assertIn("title=", url)
        self.assertLessEqual(len(url), issues.MAX_URL)
        self.assertTrue(out["body_shortened"])

    def test_short_body_fits_unshortened(self):
        # Лог-буфер общий на весь прогон: после «шумных» соседних тестов
        # строки лога сами раздували бы короткий черновик сверх ссылки.
        from unittest import mock
        with mock.patch.object(issues, "_log_rows", return_value=[]):
            out = self.draft(actual="коротко")
        self.assertFalse(out["body_shortened"])
        self.assertIn("коротко", unquote(out["open_on_github"]))

    def test_list_shows_orphan_crashes_until_drafted(self):
        crash_id = self.crash()["crash_id"]
        listed = self.call("issue_draft_list")["structuredContent"]
        self.assertIn(crash_id, [c["crash_id"]
                                 for c in listed["crashes_without_draft"]])
        self.draft(crash_id=crash_id)
        listed = self.call("issue_draft_list")["structuredContent"]
        self.assertNotIn(crash_id, [c["crash_id"]
                                    for c in listed["crashes_without_draft"]])
        self.assertEqual(listed["total"], 1)

    def test_list_by_id_gives_text_and_link(self):
        draft_id = self.draft(actual="x")["draft"]["id"]
        one = self.call("issue_draft_list",
                        {"id": draft_id})["structuredContent"]
        self.assertTrue(one["found"])
        self.assertIn("markdown", one)
        self.assertTrue(one["open_on_github"].startswith("https://github.com/"))
        missing = self.call("issue_draft_list", {"id": "draft-nope"})
        self.assertTrue(missing["isError"])

    def test_drafting_does_not_count_as_repro_call(self):
        # Команда воспроизведения — про упавший инструмент, а не про
        # сам вызов issue_draft, который пишется в журнал раньше.
        self.call("blobs_list", {"query": "zzz"})
        out = self.draft(tool="blobs_list")
        self.draft(tool="blobs_list", title="ещё")
        md = issues.render_markdown(issues.get(out["draft"]["id"]))
        self.assertIn("zapret-gui mcp call blobs_list", md)
        self.assertIn('"query": "zzz"', md)


class TestIssuesUi(_Base):

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def test_state_lists_drafts_and_draft_route_gives_text(self):
        draft_id = self.draft(actual="x")["draft"]["id"]
        code, _, state = self.client.request("GET", "/api/mcp/ui/state")
        self.assertEqual(code, 200)
        ids = [d["id"] for d in state["issues"]["drafts"]]
        self.assertIn(draft_id, ids)
        # Текст в общем состоянии не ездит: он тяжёлый.
        self.assertNotIn("markdown", json.dumps(state["issues"]))

        code, _, one = self.client.request(
            "GET", "/api/mcp/ui/issues/draft?id=" + draft_id)
        self.assertEqual(code, 200)
        self.assertIn("zapret-gui-report/v1", one["markdown"])

    def test_status_and_delete(self):
        draft_id = self.draft(actual="x")["draft"]["id"]
        code, _, body = self.client.request(
            "POST", "/api/mcp/ui/issues/status",
            body={"id": draft_id, "status": "sent"})
        self.assertEqual(code, 200, body)
        self.assertEqual(issues.get(draft_id)["status"], "sent")
        code, _, body = self.client.request(
            "POST", "/api/mcp/ui/issues/delete", body={"id": draft_id})
        self.assertEqual(code, 200, body)
        self.assertIsNone(issues.get(draft_id))
        code, _, _ = self.client.request(
            "POST", "/api/mcp/ui/issues/delete", body={"id": draft_id})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
