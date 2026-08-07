"""Сторож: «latest» в Releases принадлежит релизу GUI, и только ему.

В одном репозитории публикуются две разные вещи:

  * релизы самого GUI — тэг `vX.Y.Z`, внутри пакеты `zapret-gui-*.ipk/.apk`
    и `zapret-gui-linux.tar.gz`;
  * наши сборки сторонних бинарников — тэги `awg-bin-*`, `usque-bin-*`,
    `singbox-bin-*`, `opera-bin-*`, `tgproto-bin-*`, внутри только
    `amneziawg-go`, `usque`, `sing-box` и т.п. плюс `manifest.json`.

GitHub считает «latest» самый свежий по дате non-draft/non-prerelease релиз.
Бинарные сборки выходят чаще GUI, поэтому без `make_latest: "false"` они
перехватывают «latest» — и все ссылки вида

    https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-openwrt.apk

(README, команды установки в одну строку, бейдж версии) начинают вести на
релиз, где пакетов GUI нет вовсе. Пользователь получает HTTP 404, а следом
невнятное «./zapret-gui-openwrt.apk (no such package)» от apk — issue #305.

Тест падает, если новый workflow сборки бинарников забыл `make_latest`, или
если релиз GUI перестал его требовать. Поиск бинарных workflow — по факту
публикации релиза, а не по списку имён: список устареет на первом же новом
движке.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

# Workflow релиза самого GUI — единственный, кому «latest» разрешён.
GUI_RELEASE_WORKFLOW = "release.yml"

# Публикация релиза (softprops/action-gh-release) — по ней и опознаём
# workflow, который вообще создаёт Release.
PUBLISH_RE = re.compile(r"uses:\s*softprops/action-gh-release@", re.M)

# `make_latest: "false"` / make_latest: false — кавычки не принципиальны.
MAKE_LATEST_FALSE_RE = re.compile(
    r"^\s*make_latest:\s*['\"]?false['\"]?\s*$", re.M)
MAKE_LATEST_ANY_RE = re.compile(r"^\s*make_latest:", re.M)

# Пререлиз в «latest» не попадает по определению — с него спроса нет.
PRERELEASE_TRUE_RE = re.compile(r"^\s*prerelease:\s*true\s*$", re.M)


def _workflows():
    if not os.path.isdir(WORKFLOW_DIR):
        return {}
    out = {}
    for name in sorted(os.listdir(WORKFLOW_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(WORKFLOW_DIR, name)
        with open(path, encoding="utf-8") as f:
            out[name] = f.read()
    return out


class TestReleaseWorkflows(unittest.TestCase):

    def setUp(self):
        self.workflows = _workflows()
        self.assertTrue(self.workflows,
                        "не найдено ни одного workflow в .github/workflows")

    def test_gui_release_workflow_exists(self):
        self.assertIn(GUI_RELEASE_WORKFLOW, self.workflows)
        self.assertRegex(
            self.workflows[GUI_RELEASE_WORKFLOW], PUBLISH_RE,
            "release.yml больше не публикует Release — тест надо обновить")

    def test_binary_workflows_do_not_claim_latest(self):
        """Сборки бинарников не перехватывают «latest» у релиза GUI."""
        checked = []
        for name, text in self.workflows.items():
            if name == GUI_RELEASE_WORKFLOW:
                continue
            if not PUBLISH_RE.search(text):
                continue          # workflow вообще не создаёт релиз
            if PRERELEASE_TRUE_RE.search(text):
                continue          # пререлиз «latest» не станет
            checked.append(name)
            self.assertRegex(
                text, MAKE_LATEST_FALSE_RE,
                "%s публикует НЕ-пререлиз без `make_latest: \"false\"`. "
                "Такой релиз перехватит «latest» у vX.Y.Z, и ссылки "
                "/releases/latest/download/zapret-gui-*.apk отдадут 404 "
                "(issue #305)." % name)

        self.assertTrue(
            checked,
            "не найдено ни одного workflow сборки бинарников — "
            "проверка перестала что-либо проверять")

    def test_gui_release_claims_latest(self):
        """У релиза GUI «latest» задан явно и не выключен наглухо."""
        text = self.workflows[GUI_RELEASE_WORKFLOW]
        self.assertRegex(
            text, MAKE_LATEST_ANY_RE,
            "release.yml должен явно объявлять make_latest: на «latest» "
            "завязаны все ссылки на пакеты в README")
        self.assertNotRegex(
            text, MAKE_LATEST_FALSE_RE,
            "release.yml выключил make_latest — тогда «latest» не будет "
            "указывать ни на один релиз с пакетами GUI")


if __name__ == "__main__":
    unittest.main()
