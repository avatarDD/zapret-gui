"""Сторож: команды установки для OpenWrt соответствуют реальному менеджеру.

OpenWrt перешёл с opkg (.ipk) на apk (.apk) НЕ в 24.10, а в релизе **25.12**
(5 марта 2026); в main/SNAPSHOT apk появился раньше. Release notes 24.10
говорят прямо: «OpenWrt 24.10 uses OPKG only, APK packages are *not*
supported. Only main branch was changed to APK».

В README же 24.10 был записан в apk-ветку («новые версии, 24.10+ / 25.x —
apk»), а .ipk предлагался только для «≤ 23.05». Владелец 24.10 по такой
инструкции запускал `apk add` — которого у него нет, — и оставался без
рабочей команды вообще (issue #305).

Тест проверяет два инварианта:

  1. в README у каждого OpenWrt-блока установки менеджер в заголовке
     совпадает с командой внутри: `opkg install` — у блока, покрывающего
     24.10; `apk add` — у блока про 25.12+/SNAPSHOT, и 24.10 в его
     заголовке быть не должно;
  2. нигде в репозитории не осталось шорткатов вида `24.10+/25.x` и
     `24.10+/SNAPSHOT` — это и есть та самая неверная привязка apk к 24.10,
     размноженная по комментариям.

Разбор README идёт по факту команды в блоке, а не по списку заголовков:
список устареет на первом же переименовании раздела.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(REPO_ROOT, "README.md")

# Границы раздела: жирная «шапка» рецепта (**Keenetic (Entware):**,
# **OpenWrt … :**) либо обычный markdown-заголовок. Любая из них закрывает
# предыдущий блок — иначе последний рецепт вбирает в себя весь остаток файла.
BOLD_HEADING_RE = re.compile(r"^\*\*([^*]+)\*\*\s*$")
MD_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^```")

# Первый релиз OpenWrt на apk. Всё, что раньше, — opkg.
APK_RELEASE = "25.12"
# Последний релиз на opkg — именно он и терялся в README.
LAST_OPKG_RELEASE = "24.10"

# Шорткаты, которыми неверная привязка расползлась по комментариям.
BAD_SHORTCUTS = ("24.10+/25.x", "24.10+ / 25.x", "24.10+/SNAPSHOT")

# Каталоги, которые не наши (или генерируются) — их не сканируем.
SKIP_DIRS = {".git", "vendor", "node_modules", "__pycache__", "build", "dist"}
SCAN_EXT = (".md", ".py", ".sh", ".js", ".yml", ".yaml")


def _openwrt_install_blocks():
    """[(заголовок, тело кодовых блоков до следующего заголовка)] из README."""
    with open(README, encoding="utf-8") as f:
        lines = f.read().splitlines()

    blocks = []
    heading = None
    body, in_fence = [], False
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            m = BOLD_HEADING_RE.match(line) or MD_HEADING_RE.match(line)
            if m:
                if heading is not None:
                    blocks.append((heading, "\n".join(body)))
                heading, body = m.group(1).strip(), []
                continue
        if heading is not None and in_fence:
            body.append(line)
    if heading is not None:
        blocks.append((heading, "\n".join(body)))

    # Только блоки, которые реально ставят наш пакет для OpenWrt.
    return [(h, b) for h, b in blocks
            if h.startswith("OpenWrt") and "zapret-gui-openwrt." in b]


class ReadmeOpenWrtInstallTest(unittest.TestCase):
    def setUp(self):
        self.blocks = _openwrt_install_blocks()
        self.assertTrue(
            self.blocks,
            "В README не нашлось ни одного блока установки для OpenWrt — "
            "разбор сломался или разделы переписали")

    def test_apk_and_opkg_blocks_both_present(self):
        managers = set()
        for _heading, body in self.blocks:
            if "apk add" in body:
                managers.add("apk")
            if "opkg install" in body:
                managers.add("opkg")
        self.assertEqual(
            managers, {"apk", "opkg"},
            "В README должны остаться обе команды установки для OpenWrt: "
            "opkg (24.10 и старее) и apk (25.12+/SNAPSHOT). Найдено: %s"
            % sorted(managers))

    def test_block_manager_matches_heading(self):
        for heading, body in self.blocks:
            uses_apk = "apk add" in body
            uses_opkg = "opkg install" in body
            self.assertFalse(
                uses_apk and uses_opkg,
                "Блок «%s» смешивает apk и opkg в одном рецепте" % heading)

            if uses_apk:
                self.assertIn(
                    APK_RELEASE, heading,
                    "Блок с `apk add` («%s») должен называть версию, с которой "
                    "apk реально появился (%s), — иначе непонятно, кому он "
                    "адресован" % (heading, APK_RELEASE))
                self.assertNotIn(
                    LAST_OPKG_RELEASE, heading,
                    "Блок с `apk add` («%s») адресован %s, а этот релиз — "
                    "последний на opkg: apk там просто нет (issue #305)"
                    % (heading, LAST_OPKG_RELEASE))
            if uses_opkg:
                self.assertIn(
                    LAST_OPKG_RELEASE, heading,
                    "Блок с `opkg install` («%s») обязан явно покрывать %s — "
                    "владелец этой версии иначе не поймёт, что .ipk для него"
                    % (heading, LAST_OPKG_RELEASE))

    def test_ipk_and_apk_filenames_not_swapped(self):
        for heading, body in self.blocks:
            if "apk add" in body:
                self.assertIn("zapret-gui-openwrt.apk", body, heading)
                self.assertNotIn("zapret-gui-openwrt.ipk", body, heading)
            if "opkg install" in body:
                self.assertIn("zapret-gui-openwrt.ipk", body, heading)
                self.assertNotIn("zapret-gui-openwrt.apk", body, heading)


class NoStaleShortcutTest(unittest.TestCase):
    def test_no_apk_24_10_shortcut(self):
        hits = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                if not name.endswith(SCAN_EXT) or name == os.path.basename(__file__):
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                except (OSError, UnicodeDecodeError):
                    continue
                # CHANGELOG — историческая запись, её не переписываем.
                if os.path.relpath(path, REPO_ROOT) == "CHANGELOG.md":
                    continue
                for bad in BAD_SHORTCUTS:
                    if bad in text:
                        hits.append("%s: %s" % (os.path.relpath(path, REPO_ROOT), bad))
        self.assertFalse(
            hits,
            "Шорткат привязывает apk к OpenWrt 24.10, а тот на opkg "
            "(apk с 25.12/SNAPSHOT):\n  " + "\n  ".join(hits))


if __name__ == "__main__":
    unittest.main()
