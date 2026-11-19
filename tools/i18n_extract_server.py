#!/usr/bin/env python3
"""
i18n_extract_server.py — русские сообщения сервера для английского UI.

Сервер (api/, core/, app.py) отвечает и пишет в лог по-русски. В режиме
EN веб-интерфейс переводит их тем же переводчиком, что и свои тексты
(web/js/utils/i18n.js), по словарю web/js/i18n/en.server.js. Этот
инструмент собирает из исходников ключи словаря:

  - строковые литералы с кириллицей, кроме docstring'ов, регулярок и
    строк в сравнениях (`"…" in text`, `== "…"` — это разбор, а не текст);
  - "Сохранён %s (%d записей)" % (...)  → "Сохранён {0} ({1} записей)";
  - f"Найдено {n} доменов"               → "Найдено {0} доменов";
  - "Порт {}: {}".format(...)            → "Порт {0}: {1}";
  - "а" + x + "б"                         → "а{0}б".

Ключи нормализуются как в браузере: пробелы схлопываются, края
обрезаются. Подробно — docs/i18n.md.

Запуск:
  python3 tools/i18n_extract_server.py --check     # 0 непереведённых = успех
  python3 tools/i18n_extract_server.py --missing   # JSON недостающих
  python3 tools/i18n_extract_server.py --stats
  python3 tools/i18n_extract_server.py --unused    # ключи без источника
"""

import ast
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DICT = os.path.join(ROOT, "web", "js", "i18n", "en.server.js")
DICT_VAR = "i18n_en_server"

SOURCES = ("api", "core", "app.py")

# Не попадает в веб-интерфейс: инструменты MCP (их ответы читает модель)
# и CLI (ответы — в терминал).
EXCLUDE = (
    "core/mcp/",
    "api/mcp.py",
    "core/cli.py",
)

CYR = re.compile(r"[А-Яа-яЁё]")
# %s, %d, %5.1f, %(name)s, %r … (но не %%). Флаг «пробел» не берём:
# «50% done» в обычном тексте — не подстановка.
PCT = re.compile(r"%(?:\([^)]*\))?[-+#0]*(?:\d+|\*)?(?:\.\d+)?[sdifrxXeEgGcoaub]")
FMT = re.compile(r"\{[^{}]*\}")
# Shell-код (init-скрипты, хуки firewall) — не сообщение.
CODE = re.compile(r"\$\(|\(\) \{|\bthen\b.*\bfi\b|\bcase\b.*\besac\b|"
                  r"^#!|;\s*fi\b", re.S)


def normalize(s):
    return re.sub(r"[\s   ]+", " ", s).strip()


def placeholders(s):
    return ",".join(sorted(re.findall(r"\{\d+\}", s)))


def _pct_template(s):
    """'%s из %d' → '{0} из {1}'; '%%' → '%'."""
    out = []
    n = 0
    i = 0
    while i < len(s):
        if s.startswith("%%", i):
            out.append("%")
            i += 2
            continue
        m = PCT.match(s, i)
        if m:
            out.append("{%d}" % n)
            n += 1
            i = m.end()
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _fmt_template(s):
    """'{} из {name}' → '{0} из {1}'; '{{' → '{'."""
    n = [0]
    s = s.replace("{{", "\0").replace("}}", "\1")

    def sub(_m):
        r = "{%d}" % n[0]
        n[0] += 1
        return r
    s = FMT.sub(sub, s)
    return s.replace("\0", "{").replace("\1", "}")


def _joined(node):
    """f-строка → шаблон."""
    parts = []
    n = 0
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        else:
            parts.append("{%d}" % n)
            n += 1
    return "".join(parts)


def _concat(node):
    """'а' + x + 'б' → ('а{0}б', есть ли литерал с кириллицей, узлы-литералы).

    Нелитеральные слагаемые (x if c else 'текст', '…'.format(), '…' % e)
    становятся {k}; их собственные литералы обходчик соберёт отдельно,
    а переводчик переведёт подстановку тем же словарём."""
    items = []

    def walk(n):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            walk(n.left)
            walk(n.right)
        else:
            items.append(n)
    walk(node)
    out = []
    k = 0
    lit = False
    direct = []
    for it in items:
        if isinstance(it, ast.Constant) and isinstance(it.value, str):
            direct.append(it)
            out.append(it.value)
            lit = lit or bool(CYR.search(it.value))
        elif isinstance(it, ast.JoinedStr):
            s = _joined(it)
            # подстановки внутри f-строки — продолжают общую нумерацию
            cnt = len(re.findall(r"\{\d+\}", s))
            s = re.sub(r"\{(\d+)\}", lambda m, b=k: "{%d}" % (b + int(m.group(1))), s)
            k += cnt
            direct.append(it)
            out.append(s)
            lit = lit or bool(CYR.search(s))
        else:
            out.append("{%d}" % k)
            k += 1
    others = [it for it in items if it not in direct]
    return "".join(out), lit, direct, others


class _Collector(ast.NodeVisitor):
    def __init__(self):
        self.keys = set()
        self.skip = set()          # id() узлов, которые не брать

    def add(self, s):
        s = normalize(s)
        # Тексты генерируемых скриптов, конфигов и отчётов (комментарии
        # «# …») — не сообщения интерфейса.
        # Одиночная буква — таблица транслитерации, не сообщение.
        if CYR.search(s) and not s.startswith("#") \
                and not CODE.search(s) and 2 <= len(s) <= 2000:
            self.keys.add(s)

    # docstring'и
    def _docstring(self, node):
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            self.skip.add(id(body[0].value))

    def visit_Module(self, node):
        self._docstring(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._docstring(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._docstring(node)
        self.generic_visit(node)

    def _mark(self, node):
        for n in ast.walk(node):
            self.skip.add(id(n))

    # Сравнения и регулярки — разбор чужого вывода, не текст.
    def visit_Compare(self, node):
        self._mark(node)

    def visit_Call(self, node):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else \
            (f.id if isinstance(f, ast.Name) else "")
        owner = f.value.id if isinstance(f, ast.Attribute) \
            and isinstance(f.value, ast.Name) else ""
        # Образец поиска — разбор, а не текст; замена в .replace(old, new)
        # и re.sub(pat, repl, s) попадает в вывод и остаётся сообщением.
        if owner == "re" and node.args:
            self._mark(node.args[0])
        elif name in ("startswith", "endswith", "find", "index", "count",
                      "split", "rsplit", "partition", "rpartition", "strip",
                      "lstrip", "rstrip", "replace"):
            if name == "replace":
                if node.args:
                    self._mark(node.args[0])
            else:
                for a in node.args:
                    self._mark(a)
        # "…".format(...)
        if name == "format" and isinstance(f, ast.Attribute) \
                and isinstance(f.value, ast.Constant) \
                and isinstance(f.value.value, str) \
                and id(f.value) not in self.skip:
            self.skip.add(id(f.value))
            if CYR.search(f.value.value):
                self.add(_fmt_template(f.value.value))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if id(node) in self.skip:
            return
        # "…" % (...)
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
                and isinstance(node.left.value, str):
            self.skip.add(id(node.left))
            if CYR.search(node.left.value):
                self.add(_pct_template(node.left.value))
            self.generic_visit(node)
            return
        if isinstance(node.op, ast.Add):
            s, lit, direct, others = _concat(node)
            if lit:
                self.add(s)
                # Выражения внутри f-строк цепочки ({'вкл' if x else 'выкл'})
                # — свои сообщения.
                for n in direct:
                    if isinstance(n, ast.JoinedStr):
                        for v in n.values:
                            if isinstance(v, ast.FormattedValue):
                                self.visit(v.value)
            else:
                # Без кириллицы в самой цепочке её литералы — не сообщение,
                # но внутри f-строк могут быть свои подстановки с текстом.
                for n in direct:
                    self.visit(n)
            # Вложенные «+» уже вошли в шаблон; обходим только
            # нелитеральные слагаемые — у них могут быть свои сообщения.
            for n in others:
                self.visit(n)
            return
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if id(node) in self.skip:
            return
        for v in node.values:
            self.skip.add(id(v))
        s = _joined(node)
        if CYR.search(s):
            self.add(s)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if id(node) in self.skip or not isinstance(node.value, str):
            return
        v = node.value
        if not CYR.search(v):
            return
        # Шаблон, который форматируют позже (MSG % x, log("%s …", x),
        # TPL.format(...)): в интерфейс он придёт уже заполненным.
        if PCT.search(v):
            v = _pct_template(v)
        elif re.search(r"\{\w*\}", v):
            v = _fmt_template(v)
        self.add(v)


def list_files():
    out = []
    for src in SOURCES:
        p = os.path.join(ROOT, src)
        if os.path.isfile(p):
            out.append(p)
            continue
        for d, dirs, files in os.walk(p):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                if f.endswith(".py"):
                    out.append(os.path.join(d, f))
    res = []
    for f in sorted(out):
        rel = os.path.relpath(f, ROOT).replace(os.sep, "/")
        if any(rel == e or rel.startswith(e) for e in EXCLUDE):
            continue
        res.append(f)
    return res


def extract_source(src):
    c = _Collector()
    c.visit(ast.parse(src))
    return c.keys


def extract_all(errors=None):
    """{ключ: [файлы]}; файлы, которые не разобрались, — в errors."""
    out = {}
    for f in list_files():
        with open(f, encoding="utf-8") as fh:
            src = fh.read()
        try:
            keys = extract_source(src)
        except SyntaxError as e:
            if errors is not None:
                errors.append("%s: %s" % (os.path.relpath(f, ROOT), e))
            continue
        rel = os.path.relpath(f, ROOT).replace(os.sep, "/")
        for k in keys:
            out.setdefault(k, []).append(rel)
    return out


def load_dict(path=DICT):
    """Словарь: по строке `"ключ": "перевод",` — это JSON внутри JS."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    body = src[src.index("= {") + 2:src.rindex("}") + 1]
    body = re.sub(r",\s*}$", "}", body)
    return json.loads(body)


HEADER = (
    "/* Английский словарь сообщений сервера (api/, core/): «русская фраза»\n"
    " * → «English». Ключи собирает tools/i18n_extract_server.py; {0}, {1} —\n"
    " * места подстановки (%s, {x} в Python). Подробно: docs/i18n.md.\n"
    " * Грузится только в английском режиме (см. web/js/utils/i18n.js). */\n"
)


def save_dict(d, path=DICT):
    lines = [HEADER, "const %s = {\n" % DICT_VAR]
    for k in sorted(d):
        lines.append("%s: %s,\n" % (json.dumps(k, ensure_ascii=False),
                                    json.dumps(d[k], ensure_ascii=False)))
    lines.append("};\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(lines))


def main(argv):
    errors = []
    allk = extract_all(errors)
    d = load_dict()
    if "--missing" in argv:
        miss = {k: "" for k in sorted(allk) if not d.get(k)}
        print(json.dumps(miss, ensure_ascii=False, indent=1))
        return 0
    if "--unused" in argv:
        for k in sorted(set(d) - set(allk)):
            print(k)
        return 0
    if "--stats" in argv:
        miss = [k for k in allk if not d.get(k)]
        print("ключей: %d, без перевода: %d, в словаре: %d"
              % (len(allk), len(miss), len(d)))
        return 0
    # --check
    bad = ["не разобран (сообщения не проверены): %s" % e for e in errors]
    for k in allk:
        if not d.get(k):
            bad.append("нет перевода: %s  (%s)" % (k[:80], allk[k][0]))
    for k, v in d.items():
        if placeholders(k) != placeholders(v):
            bad.append("подстановки не совпадают: %s" % k[:80])
        if CYR.search(v):
            bad.append("кириллица в переводе: %s" % k[:80])
    if bad:
        print("\n".join(bad[:50]))
        print("всего проблем: %d" % len(bad))
        return 1
    print("ok: %d ключей" % len(allk))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
