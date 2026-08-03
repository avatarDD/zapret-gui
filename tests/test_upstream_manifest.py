"""Сторож: манифест апстримов (docs/upstream.json) не разъехался с репозиторием.

Гоняет offline-часть `tools/check_upstream.py` в обычном прогоне тестов:
vendored-файлы совпадают с записанными sha256, скилы и спеки упоминают ту
версию, на которую мы ссылаемся, сам манифест внутренне согласован.

Сети здесь нет и не должно быть — отставание от апстрима ловит еженедельный
`.github/workflows/check-upstream.yml`, а эти тесты стерегут то, что можно
проверить локально и детерминированно.

Починка при падении:
  - разошёлся vendored-файл → синхронизировать с релизом (или, если апстрим
    ушёл вперёд, обновить pinned/sha256 в манифесте вместе со скилом);
  - не упоминается pinned-версия → обновить документ или манифест;
  - `python3 tools/check_upstream.py --offline` покажет то же самое подробнее.
"""

import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import check_upstream as cu  # noqa: E402


class TestManifestShape(unittest.TestCase):
    """Сам манифест валиден и полон."""

    def setUp(self):
        self.manifest = cu.load_manifest()

    def test_manifest_is_valid_json_with_entries(self):
        self.assertGreater(len(self.manifest.get("upstreams", [])), 0,
                           "в манифесте нет ни одного апстрима")

    def test_manifest_internally_consistent(self):
        problems = cu.check_manifest_shape(self.manifest)
        self.assertEqual(problems, [],
                         "манифест несогласован: %s" % problems)

    def test_every_skill_has_an_upstream_entry(self):
        """Каждый скил привязан хотя бы к одному апстриму.

        Скил без записи в манифесте — это ровно тот случай, из-за которого
        всё затевалось: документ живёт своей жизнью, и о его устаревании
        никто не узнает.
        """
        skills_dir = os.path.join(REPO_ROOT, ".claude", "skills")
        on_disk = {
            os.path.join(".claude", "skills", name, "SKILL.md").replace(
                os.sep, "/")
            for name in os.listdir(skills_dir)
            if os.path.isfile(os.path.join(skills_dir, name, "SKILL.md"))
        }
        covered = {e.get("skill") for e in self.manifest["upstreams"]
                   if e.get("skill")}
        uncovered = sorted(on_disk - covered)
        self.assertEqual(
            uncovered, [],
            "скилы без записи в docs/upstream.json: %s — добавьте апстрим, "
            "иначе их устаревание никто не заметит" % uncovered)

    def test_pinned_versions_are_parseable(self):
        for entry in self.manifest["upstreams"]:
            pinned = entry.get("pinned")
            if pinned is None:
                continue
            self.assertIsNotNone(
                cu.version_key(pinned),
                "%s: pinned=%r не разбирается как версия"
                % (entry["id"], pinned))

    def test_pinned_entries_record_verification_date(self):
        """Есть pinned — должна быть и дата сверки (иначе непонятно, когда)."""
        for entry in self.manifest["upstreams"]:
            if entry.get("pinned") and not entry.get("verified_at"):
                self.fail("%s: есть pinned, но нет verified_at" % entry["id"])


class TestOfflineChecksPass(unittest.TestCase):
    """Offline-часть чекера проходит на текущем дереве."""

    def setUp(self):
        self.manifest = cu.load_manifest()

    def test_no_offline_problems(self):
        report = cu.run(self.manifest, offline=True)
        self.assertEqual(
            report["offline_problems"], [],
            "расхождения манифеста с репозиторием:\n  %s\nПодробнее: "
            "python3 tools/check_upstream.py --offline"
            % "\n  ".join(report["offline_problems"]))

    def test_vendored_files_are_pinned(self):
        """У каждого vendored-файла есть хэш и файл существует."""
        for entry in self.manifest["upstreams"]:
            for rel, sha in (entry.get("vendored") or {}).items():
                self.assertRegex(sha, r"^[0-9a-f]{64}$",
                                 "%s: %s — не sha256" % (entry["id"], rel))
                self.assertTrue(
                    os.path.isfile(os.path.join(REPO_ROOT, rel)),
                    "%s: нет файла %s" % (entry["id"], rel))


class TestVersionOrdering(unittest.TestCase):
    """Сравнение версий числовое, а не лексикографическое.

    Прямая регрессия: у sing-box лексикографически «последний» тег — v1.9.7,
    хотя актуален v1.13.x. На строковом сравнении сторож молчал бы вечно.
    """

    def test_numeric_not_lexicographic(self):
        self.assertGreater(cu.version_key("v1.13.0"), cu.version_key("v1.9.7"))
        self.assertGreater(cu.version_key("1.0.10"), cu.version_key("1.0.9"))
        self.assertGreater(cu.version_key("v2.0"), cu.version_key("v1.99.99"))

    def test_non_version_tags_ignored(self):
        self.assertIsNone(cu.version_key("latest"))
        self.assertIsNone(cu.version_key("nightly"))

    def test_latest_stable_skips_prereleases(self):
        tags = ["v1.0.0", "v1.1.0-rc1", "v1.0.9", "v1.1.0-beta", "v0.9.9"]
        self.assertEqual(cu.latest_stable(tags), "v1.0.9")

    def test_latest_stable_picks_numeric_max(self):
        tags = ["v1.9.7", "v1.13.15", "v1.12.0"]
        self.assertEqual(cu.latest_stable(tags), "v1.13.15")

    def test_latest_stable_honours_tag_prefix(self):
        tags = ["usque-bin-v4.2.1", "v9.9.9", "usque-bin-v4.2.0"]
        self.assertEqual(cu.latest_stable(tags, "usque-bin-"),
                         "usque-bin-v4.2.1")

    def test_latest_stable_empty(self):
        self.assertIsNone(cu.latest_stable(["nightly", "latest"]))


class TestDriftDetection(unittest.TestCase):
    """Логика «отстали / актуально» — на фикстурах, без сети."""

    @staticmethod
    def _entry(**kw):
        base = {"id": "x", "repo": "o/r", "kind": "release", "pinned": "v1.0.0"}
        base.update(kw)
        return base

    def _with_tags(self, tags, entry):
        real = cu.remote_tags
        cu.remote_tags = lambda repo, **kw: (tags, None)
        try:
            return cu.check_release_drift(entry)
        finally:
            cu.remote_tags = real

    def test_behind_when_upstream_newer(self):
        status, msg, latest = self._with_tags(["v1.0.0", "v1.2.0"],
                                              self._entry())
        self.assertEqual(status, "behind")
        self.assertEqual(latest, "v1.2.0")
        self.assertIn("v1.2.0", msg)

    def test_ok_when_equal(self):
        status, _, _ = self._with_tags(["v0.9.0", "v1.0.0"], self._entry())
        self.assertEqual(status, "ok")

    def test_ok_when_pinned_ahead(self):
        """Пин впереди тегов (например, собираем из ветки) — не «отстали»."""
        status, _, _ = self._with_tags(["v0.9.0"], self._entry())
        self.assertEqual(status, "ok")

    def test_unpinned_reported_but_not_behind(self):
        status, msg, _ = self._with_tags(["v3.0.0"],
                                         self._entry(pinned=None))
        self.assertEqual(status, "unpinned")
        self.assertIn("v3.0.0", msg)

    def test_unknown_on_network_error(self):
        real = cu.remote_tags
        cu.remote_tags = lambda repo, **kw: ([], "нет сети")
        try:
            status, msg, _ = cu.check_release_drift(self._entry())
        finally:
            cu.remote_tags = real
        self.assertEqual(status, "unknown")
        self.assertIn("нет сети", msg)

    def test_hold_turns_behind_into_held(self):
        """Осознанная задержка видна в отчёте, но не поднимает тревогу.

        Апстрим может уйти туда, куда мы за ним не идём (tg-ws-proxy-go
        переписан с Go на Python и перестал выпускать пакеты для роутера).
        Такое отставание надо ВИДЕТЬ, но еженедельно тревожить им нельзя —
        иначе сторожа перестанут читать.
        """
        entry = self._entry(hold={"reason": "апстрим сменил платформу"})
        status, msg, latest = self._with_tags(["v1.0.0", "v2.0.0"], entry)
        self.assertEqual(status, "held")
        self.assertEqual(latest, "v2.0.0")
        self.assertIn("апстрим сменил платформу", msg)

    def test_held_does_not_fail_the_run(self):
        manifest = {"upstreams": [self._entry(
            hold={"reason": "r"}, vendored={}, mentions=[], skill=None)]}
        real = cu.remote_tags
        cu.remote_tags = lambda repo, **kw: (["v9.9.9"], None)
        try:
            report = cu.run(manifest)
        finally:
            cu.remote_tags = real
        self.assertEqual(report["behind"], [])
        self.assertEqual(len(report["held"]), 1)
        self.assertTrue(report["ok"])

    def test_hold_does_not_hide_an_up_to_date_entry(self):
        """`hold` не должен маскировать нормальное состояние."""
        entry = self._entry(hold={"reason": "r"})
        status, _, _ = self._with_tags(["v1.0.0"], entry)
        self.assertEqual(status, "ok")

    def test_unpinned_does_not_fail_the_run(self):
        """Незапиннованный апстрим — долг, а не регресс: сборку не валит."""
        manifest = {"upstreams": [self._entry(pinned=None, vendored={},
                                              mentions=[], skill=None)]}
        real = cu.remote_tags
        cu.remote_tags = lambda repo, **kw: (["v5.0.0"], None)
        try:
            report = cu.run(manifest)
        finally:
            cu.remote_tags = real
        self.assertEqual(report["behind"], [])
        self.assertTrue(report["ok"])


class TestOfflineDetectsRealDrift(unittest.TestCase):
    """Offline-проверки действительно ловят подмену — а не всегда зелёные."""

    def test_wrong_hash_is_reported(self):
        entry = {"id": "t", "repo": "o/r", "kind": "release", "pinned": "v1",
                 "vendored": {"docs/upstream.json": "0" * 64}}
        problems = cu.check_offline(entry)
        self.assertTrue(any("разошёлся" in p for p in problems),
                        "подменённый хэш не пойман: %s" % problems)

    def test_missing_vendored_file_is_reported(self):
        entry = {"id": "t", "repo": "o/r", "kind": "release", "pinned": "v1",
                 "vendored": {"нет/такого/файла.lua": "0" * 64}}
        problems = cu.check_offline(entry)
        self.assertTrue(any("отсутствует" in p for p in problems))

    def test_missing_version_mention_is_reported(self):
        entry = {"id": "t", "repo": "o/r", "kind": "release",
                 "pinned": "v99.99.99",
                 "mentions": ["docs/upstream.json"]}
        problems = cu.check_offline(entry)
        self.assertTrue(any("не упоминает" in p for p in problems),
                        "устаревшее упоминание версии не поймано: %s"
                        % problems)

    def test_mention_accepts_tag_with_or_without_v(self):
        """`v1.0.4` в манифесте матчится и на `1.0.4` в тексте.

        Проверяем ровно упоминания: vendored-хэши той же записи стережёт
        `TestOfflineChecksPass`, и смешивать причины падения не нужно.
        """
        manifest = cu.load_manifest()
        zapret2 = next(e for e in manifest["upstreams"] if e["id"] == "zapret2")
        mentions_only = dict(zapret2, vendored={})
        self.assertEqual(
            cu.check_offline(mentions_only), [],
            "документы zapret2 разъехались с pinned-версией манифеста")


class TestManifestMatchesReality(unittest.TestCase):
    """Точечные утверждения, которые должны пережить рефакторинги."""

    def setUp(self):
        self.manifest = cu.load_manifest()
        self.by_id = {e["id"]: e for e in self.manifest["upstreams"]}

    def test_zapret2_pins_all_protected_core_lua(self):
        """Пиннинг покрывает ровно тот набор, который защищает importer."""
        from core import asset_importer as ai
        pinned = {os.path.basename(p)
                  for p in self.by_id["zapret2"]["vendored"]}
        self.assertEqual(
            pinned, set(ai._UPSTREAM_CORE_LUA),
            "набор запиннованных core-lua разошёлся с _UPSTREAM_CORE_LUA")

    def test_strategy_catalogs_paths_match_updater(self):
        """Пути в манифесте — те же, что реально запрашивает catalog_updater."""
        from core import catalog_updater as cup
        paths = self.by_id["strategy-catalogs"]["paths"]
        self.assertIn(cup.SOURCE_PRESETS_SUBPATH, paths,
                      "путь пресетов из catalog_updater не отслеживается")
        for name in cup.CATALOG_FILES:
            expected = "%s/%s" % (cup.SOURCE_DIRECT_SUBPATH, name)
            self.assertIn(expected, paths,
                          "каталог %s не отслеживается манифестом" % name)

    def test_strategy_catalogs_branch_matches_updater(self):
        from core import catalog_updater as cup
        entry = self.by_id["strategy-catalogs"]
        self.assertEqual(entry["branch"], cup.SOURCE_BRANCH)
        self.assertEqual(entry["repo"],
                         "%s/%s" % (cup.SOURCE_OWNER, cup.SOURCE_REPO))


if __name__ == "__main__":
    unittest.main()
