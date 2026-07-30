# tests/test_no_undefined_names.py
"""Статический сторож: в коде нет обращений к несуществующим именам.

`make lint` гоняет только ``ast.parse`` — он ловит синтаксис, но НЕ ловит
опечатку в имени переменной. Именно так уехал issue #266: в цикле сканера
осталось ``actual_idx >= total - 1`` вместо ``self._total``, и весь подбор
стратегий падал в рантайме с ``name 'total' is not defined``.

Проверка построена на stdlib-модуле ``symtable`` (без внешних зависимостей —
на роутере их ставить нечем). Для каждой функции берём имена, которые она
ЧИТАЕТ и которые резолвятся в глобальную область (``is_global()``), но при
этом нигде в модуле не объявлены и не являются встроенными → это
гарантированный ``NameError`` при исполнении ветки.

Ложных срабатываний тут не бывает по построению: локальные, параметры и
замыкания ``is_global()`` не возвращают. Единственное исключение — модульные
дандеры (``__file__`` и т.п.), которых нет в таблице символов модуля.
"""

import builtins
import os
import symtable
import unittest

# Каталоги проекта, которые проверяем.
CHECKED_DIRS = ("core", "api", "tools", "tests", "config")
CHECKED_FILES = ("app.py",)

# Дандеры модуля: реально существуют в рантайме, но в symtable модуля их нет.
MODULE_DUNDERS = frozenset({
    "__file__", "__name__", "__doc__", "__package__",
    "__spec__", "__loader__", "__builtins__", "__debug__",
})

BUILTIN_NAMES = frozenset(dir(builtins)) | MODULE_DUNDERS

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _walk(table, module_globals, relpath, found):
    """Рекурсивно собрать неразрешимые глобальные имена во вложенных областях."""
    for sym in table.get_symbols():
        # is_assigned() отсекает `global x; x = ...` — там имя создаётся.
        if not (sym.is_referenced() and sym.is_global()
                and not sym.is_assigned()):
            continue
        name = sym.get_name()
        if name in module_globals or name in BUILTIN_NAMES:
            continue
        found.append(
            "%s:%d  %s() → %s"
            % (relpath, table.get_lineno(), table.get_name(), name)
        )
    for child in table.get_children():
        _walk(child, module_globals, relpath, found)


def _check_file(path):
    relpath = os.path.relpath(path, PROJECT_ROOT)
    with open(path, encoding="utf-8") as f:
        src = f.read()
    try:
        top = symtable.symtable(src, path, "exec")
    except SyntaxError as e:          # ловится отдельно (make lint)
        return ["%s: синтаксическая ошибка: %s" % (relpath, e)]

    module_globals = {s.get_name() for s in top.get_symbols()}
    found = []
    for child in top.get_children():
        _walk(child, module_globals, relpath, found)
    return found


def _iter_python_files():
    for d in CHECKED_DIRS:
        base = os.path.join(PROJECT_ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [n for n in dirnames if n != "__pycache__"]
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)
    for fn in CHECKED_FILES:
        p = os.path.join(PROJECT_ROOT, fn)
        if os.path.isfile(p):
            yield p


class TestNoUndefinedNames(unittest.TestCase):

    def test_no_undefined_global_names(self):
        problems = []
        for path in _iter_python_files():
            problems.extend(_check_file(path))

        self.assertEqual(
            problems, [],
            "Обращение к несуществующим именам (гарантированный NameError "
            "в рантайме):\n  " + "\n  ".join(problems),
        )

    def test_detector_catches_regression(self):
        """Сам сторож работает — на образце issue #266 он срабатывает."""
        import tempfile

        sample = (
            "SELF_TOTAL = 1\n"
            "def scan(items):\n"
            "    for idx, it in enumerate(items):\n"
            "        if idx >= total - 1:\n"
            "            return it\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py",
                                         delete=False) as f:
            f.write(sample)
            tmp = f.name
        self.addCleanup(os.unlink, tmp)

        found = _check_file(tmp)
        self.assertTrue(any(item.endswith("total") for item in found), found)


if __name__ == "__main__":
    unittest.main()
