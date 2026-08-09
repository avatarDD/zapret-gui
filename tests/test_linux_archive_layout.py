"""Сторож: `zapret-gui-linux.tar.gz` разворачивается в каталог, а не в cwd.

README для Linux советует:

    tar xzf zapret-gui-linux.tar.gz && cd zapret-gui

но CI паковал архив командой `tar czf "$ARCHIVE" --exclude=… .` из корня
репозитория — то есть без верхнего каталога. Такой архив («tar-бомба»)
распаковывается прямо в текущий каталог: `cd zapret-gui` падает с «No such
file or directory», а ~70 файлов проекта рассыпаются по ~/Downloads, откуда
их потом выковыривать руками. Ровно тот же класс дефекта, что и issue #305:
команда из README, которая не работает.

Тест не сверяет строки, а ДЕЛАЕТ архив: вынимает настоящую команду `tar` из
workflow, запускает её на игрушечном дереве и смотрит на верхний уровень
результата. Поэтому он переживёт и смену `--transform` на staging-каталог, и
любую другую реализацию — важен наблюдаемый результат, а не способ.
"""

import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "release.yml")

PKG_NAME = "zapret-gui"
STEP_NAME = "Create Linux archive"


def _archive_command():
    """Команда `tar czf …` из шага сборки linux-архива, одной строкой."""
    with open(WORKFLOW, encoding="utf-8") as f:
        lines = f.read().splitlines()

    # Ищем шаг по имени, дальше — первую команду tar в его теле.
    start = None
    for i, line in enumerate(lines):
        if line.strip() == "- name: %s" % STEP_NAME:
            start = i
            break
    if start is None:
        return None

    cmd, collecting = [], False
    for line in lines[start + 1:]:
        stripped = line.strip()
        # Следующий шаг — тело закончилось.
        if stripped.startswith("- name:"):
            break
        if not collecting and stripped.startswith("tar "):
            collecting = True
        if collecting:
            cmd.append(stripped.rstrip("\\").strip())
            if not stripped.endswith("\\"):
                break
    return " ".join(cmd) if cmd else None


class LinuxArchiveLayoutTest(unittest.TestCase):
    def setUp(self):
        if shutil.which("tar") is None:
            self.skipTest("tar не найден")
        self.cmd = _archive_command()
        self.assertIsNotNone(
            self.cmd,
            "В %s не нашёлся шаг «%s» с командой tar — шаг переименовали "
            "или переписали, тест надо обновить вместе с ним"
            % (os.path.relpath(WORKFLOW, REPO_ROOT), STEP_NAME))

    def _build(self):
        """Собирает архив командой из workflow на игрушечном дереве."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        src = os.path.join(tmp, "src")
        os.makedirs(os.path.join(src, "core"))
        os.makedirs(os.path.join(src, "web", "js"))
        for path in ("app.py", "core/version.py", "web/js/app.js", ".gitignore"):
            full = os.path.join(src, path)
            with open(full, "w", encoding="utf-8") as f:
                f.write("x\n")

        archive = os.path.join(tmp, "out.tar.gz")
        env = dict(os.environ, ARCHIVE=archive, PKG_NAME=PKG_NAME)
        proc = subprocess.run(["bash", "-c", self.cmd], cwd=src, env=env,
                              capture_output=True, text=True)
        self.assertEqual(
            proc.returncode, 0,
            "Команда из workflow упала:\n%s\n%s" % (self.cmd, proc.stderr))
        return archive

    def test_archive_has_single_top_level_dir(self):
        archive = self._build()
        with tarfile.open(archive, "r:gz") as tar:
            tops = {name.split("/")[0] for name in tar.getnames()}
        tops.discard("")
        self.assertEqual(
            tops, {PKG_NAME},
            "Архив должен разворачиваться в один каталог «%s/» — README "
            "советует `tar xzf … && cd %s`. Верхний уровень сейчас: %s"
            % (PKG_NAME, PKG_NAME, sorted(tops)))

    def test_readme_recipe_actually_works(self):
        """Проверяем README буквально: распаковать и войти в каталог."""
        archive = self._build()
        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, True)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(dest)

        pkg_dir = os.path.join(dest, PKG_NAME)
        self.assertTrue(
            os.path.isdir(pkg_dir),
            "После распаковки нет каталога «%s» — команда из README "
            "`cd %s` упадёт" % (PKG_NAME, PKG_NAME))
        self.assertTrue(
            os.path.isfile(os.path.join(pkg_dir, "app.py")),
            "В каталоге «%s» нет app.py — следующая строка README "
            "`python3 app.py` не сработает" % PKG_NAME)


class ReadmeLinuxRecipeTest(unittest.TestCase):
    """README и workflow должны говорить об одном и том же каталоге."""

    def test_readme_cds_into_package_dir(self):
        with open(os.path.join(REPO_ROOT, "README.md"), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"tar xzf %s-linux\.tar\.gz[^\n]*" % re.escape(PKG_NAME), text)
        self.assertIsNotNone(
            m, "В README пропала команда распаковки linux-архива")
        self.assertIn(
            "cd %s" % PKG_NAME, m.group(0),
            "README распаковывает архив, но не заходит в «%s» — либо "
            "инструкция разошлась с раскладкой архива, либо архив снова "
            "стал разворачиваться в текущий каталог" % PKG_NAME)


if __name__ == "__main__":
    unittest.main()
