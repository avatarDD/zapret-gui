"""Сторож: индекс скилов для AI-агентов синхронен со скилами на диске.

Скилы живут в `.claude/skills/<name>/SKILL.md` — этот каталог находит только
Claude Code. Чтобы их видели ЛЮБЫЕ агенты, `tools/gen_agent_index.py`
раскладывает индекс по кросс-инструментальным точкам входа (AGENTS.md,
GEMINI.md, .github/copilot-instructions.md, .cursor/rules/, docs/skills.json).

Тест падает, если добавили/переименовали/переописали скил, а индекс не
перегенерировали — тогда часть агентов о нём просто не узнает.

Починка: python3 tools/gen_agent_index.py
"""

import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import gen_agent_index as gen  # noqa: E402


class TestAgentSkillIndex(unittest.TestCase):

    def setUp(self):
        self.skills = gen.collect_skills()

    def test_skills_are_discovered(self):
        """Скилы вообще читаются и у каждого разобран frontmatter."""
        self.assertGreater(len(self.skills), 0,
                           "не найдено ни одного SKILL.md")
        for s in self.skills:
            self.assertTrue(s["name"], "пустое имя скила: %r" % s)
            self.assertTrue(s["description"],
                            "пустое описание у скила %s" % s["name"])
            self.assertTrue(
                os.path.isfile(os.path.join(REPO_ROOT, s["path"])),
                "нет файла %s" % s["path"])

    def test_skill_dir_matches_frontmatter_name(self):
        """Имя каталога == `name` во frontmatter (иначе ссылки врут)."""
        for s in self.skills:
            dirname = s["path"].split("/")[2]
            self.assertEqual(
                dirname, s["name"],
                "каталог %s не совпадает с name: %s" % (dirname, s["name"]))

    def test_index_files_are_in_sync(self):
        """Все точки входа для агентов синхронны со скилами."""
        stale = []
        for rel, content in gen.targets(self.skills):
            path = os.path.join(REPO_ROOT, rel)
            if rel == "AGENTS.md":
                content = gen._preserve_manual_text(path, content)
            if not os.path.isfile(path):
                stale.append("%s (отсутствует)" % rel)
                continue
            with open(path, "r", encoding="utf-8") as f:
                if f.read() != content:
                    stale.append(rel)
        self.assertEqual(
            stale, [],
            "индекс скилов устарел (%s). Выполните: "
            "python3 tools/gen_agent_index.py" % ", ".join(stale))

    def test_every_skill_listed_everywhere(self):
        """Каждый скил упомянут в каждой точке входа — по имени и по пути."""
        entrypoints = ["AGENTS.md", "GEMINI.md",
                       os.path.join(".github", "copilot-instructions.md"),
                       os.path.join(".cursor", "rules", "zapret-gui.mdc")]
        for rel in entrypoints:
            path = os.path.join(REPO_ROOT, rel)
            self.assertTrue(os.path.isfile(path), "нет файла %s" % rel)
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            for s in self.skills:
                self.assertIn(s["name"], text,
                              "скил %s не упомянут в %s" % (s["name"], rel))
                self.assertIn(s["path"], text,
                              "путь %s не упомянут в %s" % (s["path"], rel))

    def test_skills_json_is_valid(self):
        """docs/skills.json — валидный JSON и покрывает все скилы."""
        path = os.path.join(REPO_ROOT, "docs", "skills.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        names = {s["name"] for s in data["skills"]}
        self.assertEqual(names, {s["name"] for s in self.skills})
        for entry in data["skills"]:
            self.assertTrue(
                os.path.isfile(os.path.join(REPO_ROOT, entry["path"])),
                "битый путь в skills.json: %s" % entry["path"])

    def test_pointer_files_reference_agents_md(self):
        """Указатели ведут на AGENTS.md — единый источник правды."""
        for rel in ["GEMINI.md",
                    os.path.join(".github", "copilot-instructions.md"),
                    os.path.join(".cursor", "rules", "zapret-gui.mdc")]:
            with open(os.path.join(REPO_ROOT, rel), "r",
                      encoding="utf-8") as f:
                self.assertIn("AGENTS.md", f.read(),
                              "%s не ссылается на AGENTS.md" % rel)


if __name__ == "__main__":
    unittest.main()
