#!/usr/bin/env python3
"""gen_agent_index.py — генератор индекса скилов для ЛЮБЫХ AI-агентов.

Зачем
-----
Скилы проекта живут в `.claude/skills/<name>/SKILL.md` — это формат, который
Claude Code находит сам. Остальные агенты (Codex, Cursor, Copilot, Gemini CLI,
Aider, Zed, Windsurf, Continue …) про этот каталог не знают: каждый читает
свой файл-инструкцию в корне репозитория.

Чтобы не плодить копии одного и того же текста, у нас ОДИН источник правды —
сами `SKILL.md` (их YAML-frontmatter `name` + `description`), а этот скрипт
раскладывает из него индекс по всем точкам входа:

  AGENTS.md                          — кросс-инструментальный стандарт
                                       (Codex, Cursor, Jules, Aider, Zed, …)
  GEMINI.md                          — Gemini CLI
  .github/copilot-instructions.md    — GitHub Copilot
  .cursor/rules/zapret-gui.mdc       — Cursor (alwaysApply)
  docs/skills.json                   — машиночитаемый индекс для всего прочего

Все файлы, кроме AGENTS.md, — тонкие указатели на AGENTS.md; дублируется
только сам список скилов, а не их содержимое.

Использование
-------------
    python3 tools/gen_agent_index.py            # перегенерировать
    python3 tools/gen_agent_index.py --check    # только проверить (CI/тест)

Инвариант стережёт `tests/test_agent_skill_index.py`.
"""

import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO_ROOT, ".claude", "skills")

# Маркеры автогенерируемого блока. Текст ВНЕ них правится руками и переживает
# перегенерацию — держим в них только индекс скилов.
BEGIN = "<!-- BEGIN GENERATED SKILL INDEX -->"
END = "<!-- END GENERATED SKILL INDEX -->"

POINTER_NOTE = (
    "Этот файл — указатель. Полные инструкции для AI-агентов: "
    "[AGENTS.md](AGENTS.md)."
)


# ─────────────────────────── чтение скилов ───────────────────────────

def _parse_frontmatter(text):
    """Достать `name` и `description` из YAML-frontmatter SKILL.md.

    Свой мини-парсер вместо pyyaml: зависимость опциональна (см. принцип
    «минимум зависимостей» в CoderManual §1), а формат здесь фиксированный —
    `name: <строка>` и `description: >-` со свёрнутым блоком.
    """
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm = text[3:end]

    name = None
    m = re.search(r"^name:\s*(.+?)\s*$", fm, re.M)
    if m:
        name = m.group(1).strip().strip("'\"")

    desc = None
    m = re.search(r"^description:\s*(>-|>|\|-|\||.*)$", fm, re.M)
    if m:
        inline = m.group(1).strip()
        if inline and inline not in (">-", ">", "|-", "|"):
            desc = inline.strip("'\"")
        else:
            # свёрнутый блок: последующие строки с отступом
            lines = []
            for line in fm[m.end():].split("\n"):
                if line.strip() == "":
                    continue
                if not line.startswith((" ", "\t")):
                    break
                lines.append(line.strip())
            desc = " ".join(lines)

    if not name or not desc:
        return None
    return {"name": name, "description": re.sub(r"\s+", " ", desc).strip()}


def collect_skills():
    """Список скилов из .claude/skills/*/SKILL.md, отсортированный по имени."""
    skills = []
    if not os.path.isdir(SKILLS_DIR):
        return skills
    for entry in sorted(os.listdir(SKILLS_DIR)):
        path = os.path.join(SKILLS_DIR, entry, "SKILL.md")
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            meta = _parse_frontmatter(f.read())
        if not meta:
            print("ПРЕДУПРЕЖДЕНИЕ: не разобран frontmatter в %s" % path,
                  file=sys.stderr)
            continue
        meta["path"] = ".claude/skills/%s/SKILL.md" % entry
        meta["summary"] = _summary(meta["description"])
        skills.append(meta)
    return skills


def _summary(description):
    """Первое предложение описания — короткая строка для таблицы."""
    m = re.match(r"^(.+?)\.\s", description + " ")
    s = (m.group(1) if m else description).strip()
    if len(s) > 200:
        s = s[:197].rstrip() + "…"
    return s


# ─────────────────────────── рендеринг ───────────────────────────

def render_index(skills):
    """Автогенерируемый блок: таблица + полные описания-триггеры."""
    out = [BEGIN, ""]
    out.append("| Скил | Файл | О чём |")
    out.append("|---|---|---|")
    for s in skills:
        out.append("| **%s** | [`%s`](%s) | %s |"
                   % (s["name"], s["path"], s["path"], s["summary"]))
    out.append("")
    out.append("### Когда какой открывать")
    out.append("")
    for s in skills:
        out.append("- **`%s`** — %s" % (s["name"], s["description"]))
    out.append("")
    out.append(END)
    return "\n".join(out)


def render_agents_md(skills):
    return AGENTS_TEMPLATE.replace("@@INDEX@@", render_index(skills))


def render_pointer(title, skills, extra=""):
    lines = ["# %s" % title, "", POINTER_NOTE, ""]
    if extra:
        lines += [extra, ""]
    lines.append(
        "В репозитории есть подробные предметные справочники (скилы) — "
        "плотные, выверенные по официальным источникам документы по каждому "
        "движку. **Перед правкой соответствующей подсистемы открывай нужный "
        "файл целиком**: он избавляет от догадок про CLI-флаги, формат "
        "конфигов и типовые причины «не работает».")
    lines.append("")
    lines.append(render_index(skills))
    lines.append("")
    return "\n".join(lines)


def render_cursor_rule(skills):
    head = (
        "---\n"
        "description: Индекс предметных справочников (скилов) zapret-gui\n"
        "alwaysApply: true\n"
        "---\n\n"
    )
    return head + render_pointer("zapret-gui — правила проекта", skills)


def render_skills_json(skills):
    payload = {
        "$comment": ("Машиночитаемый индекс предметных справочников проекта. "
                     "Генерируется tools/gen_agent_index.py из frontmatter "
                     ".claude/skills/*/SKILL.md — руками не править."),
        "version": 1,
        "skills": [
            {"name": s["name"], "path": s["path"],
             "summary": s["summary"], "description": s["description"]}
            for s in skills
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


# ─────────────────────────── AGENTS.md ───────────────────────────

AGENTS_TEMPLATE = """# AGENTS.md — инструкции для AI-агентов

Файл читают Codex, Cursor, Jules, Aider, Zed, Continue и другие агенты,
поддерживающие стандарт `AGENTS.md`. Claude Code дополнительно сам подхватывает
скилы из `.claude/skills/`. Указатели для Gemini CLI, Copilot и Cursor лежат в
`GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/` и ведут сюда.

**Человеку читать не это, а:** [README.md](README.md) — пользовательская
документация, [CoderManual.md](CoderManual.md) — руководство разработчика
(архитектура, `core/` по доменам, REST, фронтенд, тесты, «куда добавить X»).

---

## Что это за проект

`zapret-gui` — веб-GUI и оркестратор средств обхода блокировок для роутеров
(Keenetic на Entware, OpenWrt, обычный Linux). Питон + Bottle на бэкенде,
vanilla-JS SPA на фронте, один `settings.json` как хранилище. Управляет
несколькими независимыми движками: nfqws2/zapret2, sing-box, mihomo,
AmneziaWG, MASQUE/usque, Opera Proxy, Telegram-туннель.

Ключевые принципы (подробно — CoderManual §1): минимум зависимостей (код едет
на роутер с `python3-light`, HTTP через `urllib`, не `requests`), логи в RAM,
singleton-менеджеры `get_xxx_manager()`, чистые функции отделены от I/O,
идемпотентный firewall, кроссплатформенность через детект платформы.

---

## Предметные справочники (скилы) — читать ПЕРЕД правкой

Каждый движок описан отдельным плотным справочником, выверенным по официальным
источникам (апстрим-репозиторий и его документация) и привязанным к нашему
коду. Это не обзорные тексты, а рабочие спецификации: точные CLI-флаги, форматы
конфигов, инварианты, типовые причины «не работает».

**Правило простое: собираешься трогать подсистему — сначала открой её скил
целиком.** Он экономит часы и предотвращает целый класс ошибок (устаревшие
флаги, несуществующие опции конфига, неверные пути на платформе).

@@INDEX@@

---

## Как проверять работу

```sh
python3 -m pytest tests/ -q      # Python-тесты (147+ файлов)
node --test tests/*.js           # JS-тесты (линтер стратегий и пр.)
make lint                        # синтаксис всех .py
```

Тесты-сторожа — заметная часть проекта: они фиксируют инварианты, которые
нельзя нарушить молча (соответствие карты lua-файлов их реальным функциям,
совместимость версий, синхронность этого индекса со скилами и т.п.). Если
такой тест упал — почти всегда сломан инвариант, а не тест.

## Рабочие соглашения

- **Язык.** Комментарии, docstring'и, сообщения коммитов, тексты в UI и
  документация — по-русски, как и весь существующий код.
- **Стиль.** Пиши так, как написан окружающий код: та же плотность
  комментариев, те же имена, те же идиомы. Новых зависимостей не добавлять.
- **Документация рядом с изменением.** Меняешь поведение — обнови
  `CHANGELOG.md`, при необходимости `README.md` / `CoderManual.md` и
  соответствующий скил.
- **Источник правды у скилов — апстрим.** Если апстрим-проект (bol-van/zapret2,
  sagernet/sing-box, MetaCubeX/mihomo, amnezia-vpn/amneziawg-go …) разошёлся со
  скилом — правь скил, а не подгоняй код под устаревший текст.

## Апстримы: чему мы соответствуем

`docs/upstream.json` — единственное место, где записана сверенная версия
каждого чужого проекта: репозиторий, `pinned`, дата сверки, скил,
vendored-файлы с sha256, отслеживаемые пути. Без него отставание не видно:
скил nfqws2 три месяца описывал zapret2 0.9.5.2, пока вышло пять релизов.

```sh
make upstream            # сверка с апстримами (нужна сеть)
make upstream-offline    # только локальные проверки, идёт в тестах
```

Еженедельный `.github/workflows/check-upstream.yml` заводит issue с меткой
`upstream-drift`, когда апстрим уходит вперёд. Работая по такой issue:
прочитай changelog между `pinned` и `latest` (важен не номер, а изменившаяся
семантика), синхронизируй vendored-файлы, **обнови скил**, потом `pinned` и
`verified_at`. Подробности — CoderManual §3.2.

Отдельно про lua: `import/lua/zapret-*.lua` — дословные копии релиза zapret2,
правятся только синхронизацией; наши расширения живут в отдельных файлах, и
каждый их вызов резолвится тестом `tests/test_lua_symbols_resolve.py`
(в Lua неизвестное имя — не ошибка загрузки, а тихо неработающая стратегия).

## Перегенерация этого индекса

Список скилов ниже автогенерируется из frontmatter самих `SKILL.md`:

```sh
python3 tools/gen_agent_index.py           # перегенерировать
python3 tools/gen_agent_index.py --check    # проверить синхронность
```

Правь текст **вне** маркеров `BEGIN/END GENERATED SKILL INDEX` — он переживает
перегенерацию. Добавил новый скил — прогони генератор.
"""


# ─────────────────────────── запись ───────────────────────────

def _preserve_manual_text(path, generated):
    """Сохранить ручные правки вне маркеров, обновив только блок индекса."""
    if not os.path.isfile(path):
        return generated
    with open(path, "r", encoding="utf-8") as f:
        existing = f.read()
    if BEGIN not in existing or END not in existing:
        return generated
    m_new = re.search(re.escape(BEGIN) + r".*?" + re.escape(END),
                      generated, re.S)
    if not m_new:
        return generated
    return re.sub(re.escape(BEGIN) + r".*?" + re.escape(END),
                  lambda _: m_new.group(0), existing, count=1, flags=re.S)


def targets(skills):
    """Список (относительный путь, содержимое)."""
    return [
        ("AGENTS.md", render_agents_md(skills)),
        ("GEMINI.md", render_pointer("zapret-gui — контекст для Gemini CLI",
                                     skills)),
        (os.path.join(".github", "copilot-instructions.md"),
         render_pointer("zapret-gui — инструкции для GitHub Copilot", skills)),
        (os.path.join(".cursor", "rules", "zapret-gui.mdc"),
         render_cursor_rule(skills)),
        (os.path.join("docs", "skills.json"), render_skills_json(skills)),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="только проверить синхронность, ничего не писать")
    args = ap.parse_args()

    skills = collect_skills()
    if not skills:
        print("ОШИБКА: не найдено ни одного скила в %s" % SKILLS_DIR,
              file=sys.stderr)
        return 1

    stale = []
    for rel, content in targets(skills):
        path = os.path.join(REPO_ROOT, rel)
        if rel == "AGENTS.md":
            content = _preserve_manual_text(path, content)
        current = None
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                current = f.read()
        if current == content:
            continue
        if args.check:
            stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("обновлён: %s" % rel)

    if args.check:
        if stale:
            print("Индекс скилов устарел: %s\n"
                  "Выполните: python3 tools/gen_agent_index.py"
                  % ", ".join(stale), file=sys.stderr)
            return 1
        print("✓ Индекс скилов синхронен (%d скилов)" % len(skills))
    return 0


if __name__ == "__main__":
    sys.exit(main())
