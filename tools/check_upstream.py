#!/usr/bin/env python3
"""check_upstream.py — сторож отставания от апстримов.

Проблема, которую решает
------------------------
Наши справочники (скилы), спеки редактора и vendored-файлы описывают
конкретные версии чужих проектов. Апстрим уезжает вперёд молча: скил
nfqws2 три месяца документировал zapret2 0.9.5.2, пока вышло пять релизов,
а bundled core-lua отставала на релиз и перезаписывала пользователю более
свежие файлы. Ни один тест этого не ловил — сравнивать было не с чем.

Теперь есть `docs/upstream.json`, где записано, чему мы соответствуем, и
этот скрипт, который проверяет две разные вещи:

**offline** (идёт в обычном прогоне тестов, сети не нужно):
  - vendored-файлы побайтово совпадают с записанными sha256;
  - файлы из `mentions` дословно упоминают pinned-версию — то есть скил и
    спека не разъехались с манифестом;
  - манифест внутренне согласован (нет битых путей, дублей id и т.п.).

**online** (сеть; вручную и раз в неделю в CI):
  - для `kind=release` — перечисляет теги апстрима через `git ls-remote`
    и сравнивает последний стабильный с pinned;
  - для `kind=branch` — проверяет, что пути, от которых мы зависим, всё
    ещё существуют в дереве апстрима (он их периодически переносит).

`git ls-remote` вместо GitHub REST API сознательно: не нужен токен, нет
rate-limit, работает для любого публичного репозитория.

Использование
-------------
    python3 tools/check_upstream.py              # offline + online
    python3 tools/check_upstream.py --offline    # только локальные сверки
    python3 tools/check_upstream.py --json       # машиночитаемый отчёт (CI)
    python3 tools/check_upstream.py --id zapret2 # только один апстрим

Код возврата: 0 — всё сходится, 1 — есть расхождения или отставание.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO_ROOT, "docs", "upstream.json")

# Теги предрелизов не считаем «последней версией».
_PRERELEASE_RE = re.compile(r"(rc|alpha|beta|dev|pre|test|snapshot)", re.I)
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")

GIT_TIMEOUT = 120


# ─────────────────────────── манифест ───────────────────────────

def load_manifest(path=MANIFEST):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def version_key(tag):
    """Числовой ключ тега для сортировки. None — тег не похож на версию.

    Лексикографическая сортировка тут врёт: 'v1.9.7' > 'v1.13.0' как строки,
    хотя 1.13 новее. Поэтому сравниваем кортежами чисел.
    """
    m = _VERSION_RE.match(tag)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────── offline-сверки ───────────────────────────

def check_offline(entry, repo_root=REPO_ROOT):
    """Локальные сверки одной записи. Возвращает список проблем (строк)."""
    problems = []
    uid = entry["id"]

    # 1. vendored-файлы побайтово соответствуют пиннингу
    for rel, expected in sorted((entry.get("vendored") or {}).items()):
        path = os.path.join(repo_root, rel)
        if not os.path.isfile(path):
            problems.append("%s: vendored-файл отсутствует — %s" % (uid, rel))
            continue
        actual = _sha256(path)
        if actual != expected:
            problems.append(
                "%s: %s разошёлся с апстримом %s (sha256 %s… вместо %s…). "
                "Либо синхронизируйте файл с релизом, либо, если апстрим ушёл "
                "вперёд, обновите pinned/sha256 в docs/upstream.json"
                % (uid, rel, entry.get("pinned") or "?",
                   actual[:12], expected[:12]))

    # 2. скил/спека упоминают ту же версию, что и манифест
    pinned = entry.get("pinned")
    for rel in entry.get("mentions") or []:
        path = os.path.join(repo_root, rel)
        if not os.path.isfile(path):
            problems.append("%s: файл из mentions отсутствует — %s"
                            % (uid, rel))
            continue
        if not pinned:
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        # Тег может писаться и с 'v', и без неё — принимаем оба написания.
        bare = pinned.lstrip("vV")
        if pinned not in text and bare not in text:
            problems.append(
                "%s: %s не упоминает pinned-версию %s — документация "
                "разъехалась с манифестом" % (uid, rel, pinned))

    # 3. скил существует
    skill = entry.get("skill")
    if skill and not os.path.isfile(os.path.join(repo_root, skill)):
        problems.append("%s: скил отсутствует — %s" % (uid, skill))

    return problems


def check_manifest_shape(manifest):
    """Целостность самого манифеста."""
    problems = []
    seen = set()
    for entry in manifest.get("upstreams", []):
        uid = entry.get("id")
        if not uid:
            problems.append("запись без id: %r" % entry)
            continue
        if uid in seen:
            problems.append("дублирующийся id: %s" % uid)
        seen.add(uid)
        if not entry.get("repo"):
            problems.append("%s: не указан repo" % uid)
        kind = entry.get("kind")
        if kind not in ("release", "branch"):
            problems.append("%s: неизвестный kind=%r" % (uid, kind))
        if kind == "branch" and not entry.get("branch"):
            problems.append("%s: kind=branch без branch" % uid)
        if entry.get("vendored") and not entry.get("pinned"):
            problems.append(
                "%s: есть vendored-файлы, но нет pinned — непонятно, "
                "какой версии они соответствуют" % uid)
    return problems


# ─────────────────────────── online-сверки ───────────────────────────

def _git(args):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=GIT_TIMEOUT)


def remote_tags(repo, url_tmpl="https://github.com/%s.git"):
    """Теги апстрима через ls-remote. Возвращает (теги, ошибка|None)."""
    try:
        res = _git(["git", "ls-remote", "--tags", "--refs", url_tmpl % repo])
    except subprocess.TimeoutExpired:
        return [], "таймаут ls-remote"
    except OSError as e:
        return [], "не удалось запустить git: %s" % e
    if res.returncode != 0:
        return [], (res.stderr or "").strip().splitlines()[-1:] or ["ошибка"]
    tags = [line.split("refs/tags/")[-1].strip()
            for line in res.stdout.splitlines() if "refs/tags/" in line]
    return tags, None


def latest_stable(tags, tag_prefix=""):
    """Последний стабильный тег по числовому порядку."""
    cands = []
    for t in tags:
        if tag_prefix and not t.startswith(tag_prefix):
            continue
        if _PRERELEASE_RE.search(t):
            continue
        key = version_key(t[len(tag_prefix):] if tag_prefix else t)
        if key:
            cands.append((key, t))
    if not cands:
        return None
    cands.sort()
    return cands[-1][1]


def check_release_drift(entry):
    """Отставание от последнего релиза. → (статус, сообщение, latest)."""
    tags, err = remote_tags(entry["repo"])
    if err:
        return "unknown", "не удалось опросить %s: %s" % (entry["repo"], err), None
    latest = latest_stable(tags, entry.get("tag_prefix", ""))
    if not latest:
        return "unknown", "у %s не нашлось версионных тегов" % entry["repo"], None

    pinned = entry.get("pinned")
    if not pinned:
        return ("unpinned",
                "%s: базовая версия не зафиксирована, у апстрима сейчас %s — "
                "проставьте pinned при ближайшей сверке"
                % (entry["id"], latest), latest)

    pk, lk = version_key(pinned), version_key(latest)
    if pk is None or lk is None:
        return ("unknown",
                "%s: не разобрать версии (pinned=%s, latest=%s)"
                % (entry["id"], pinned, latest), latest)
    if lk > pk:
        # Осознанная задержка: мы знаем, что апстрим ушёл, и остаёмся
        # намеренно (например, он переписан на другом языке и сменил
        # раскладку). Это должно быть ВИДНО в отчёте, но не должно
        # каждую неделю поднимать тревогу — иначе сторожа перестанут читать.
        hold = entry.get("hold")
        if hold:
            return ("held",
                    "%s: остаёмся на %s (апстрим на %s) — %s"
                    % (entry["id"], pinned, latest,
                       hold.get("reason") or "решение зафиксировано"),
                    latest)
        return ("behind",
                "%s: мы на %s, апстрим на %s" % (entry["id"], pinned, latest),
                latest)
    return "ok", "%s: %s — актуально" % (entry["id"], pinned), latest


def check_branch_paths(entry, workdir=None):
    """Ветка: пути на месте И содержимое всё ещё нашего формата.

    Проверять только существование путей мало. У источника без релизов
    (каталоги стратегий) ломается не «версия», а договорённость о формате:
    файл на месте, но внутри уже не INI-секции с `--lua-desync=`, и наш
    парсер молча получает ноль стратегий. Поэтому вторым шагом файлы,
    перечисленные в `content_checks`, выкачиваются и проверяются регекспом.
    """
    import shutil
    import tempfile

    paths = entry.get("paths") or []
    if not paths:
        return "ok", "%s: путей для проверки нет" % entry["id"]

    checks = entry.get("content_checks") or {}
    tmp = workdir or tempfile.mkdtemp(prefix="upstream-check-")
    clone = os.path.join(tmp, entry["id"])
    try:
        res = _git(["git", "clone", "-q", "--depth", "1",
                    "--filter=blob:none", "--no-checkout",
                    "--branch", entry.get("branch", "main"),
                    "https://github.com/%s.git" % entry["repo"], clone])
        if res.returncode != 0:
            return "unknown", ("%s: не удалось склонировать %s: %s"
                               % (entry["id"], entry["repo"],
                                  (res.stderr or "").strip()[-200:]))
        missing = []
        for p in paths:
            r = _git(["git", "-C", clone, "ls-tree", "--name-only",
                      "HEAD", p])
            if r.returncode != 0 or not r.stdout.strip():
                missing.append(p)
        if missing:
            return "behind", (
                "%s: в апстриме больше нет путей: %s. Апстрим "
                "реструктурировал дерево — поправьте пути в коде-потребителе "
                "и в docs/upstream.json"
                % (entry["id"], ", ".join(missing)))

        # Формат содержимого. Блобы отфильтрованы при клонировании, поэтому
        # `git show` дотягивает ровно нужные файлы — это дешевле чекаута.
        broken = []
        for rel, pattern in sorted(checks.items()):
            r = _git(["git", "-C", clone, "show", "HEAD:%s" % rel])
            if r.returncode != 0:
                broken.append("%s (не читается)" % rel)
                continue
            if not re.search(pattern, r.stdout, re.M):
                broken.append("%s (не найдено /%s/)" % (rel, pattern))
        if broken:
            return "behind", (
                "%s: файлы на месте, но формат изменился: %s. Пути целы, "
                "поэтому существующая проверка путей это пропустила бы, а "
                "наш парсер получил бы ноль стратегий"
                % (entry["id"], "; ".join(broken)))

        tail = (", формат %d файлов прежний" % len(checks)) if checks else ""
        return "ok", ("%s: все %d путей на месте%s"
                      % (entry["id"], len(paths), tail))
    finally:
        if workdir is None:
            shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────────── отчёт ───────────────────────────

_ICON = {"ok": "✓", "behind": "!", "unpinned": "?", "unknown": "~",
         "held": "=", "problem": "✗"}


def run(manifest, offline=False, only_id=""):
    """Прогнать все проверки. Возвращает отчёт-словарь."""
    report = {"offline_problems": check_manifest_shape(manifest),
              "entries": []}

    for entry in manifest.get("upstreams", []):
        if only_id and entry.get("id") != only_id:
            continue
        row = {"id": entry.get("id"), "repo": entry.get("repo"),
               "kind": entry.get("kind"), "pinned": entry.get("pinned"),
               "skill": entry.get("skill"),
               "problems": check_offline(entry),
               "status": "ok", "message": "", "latest": None}
        if not offline:
            if entry.get("kind") == "branch":
                row["status"], row["message"] = check_branch_paths(entry)
            else:
                row["status"], row["message"], row["latest"] = \
                    check_release_drift(entry)
        report["entries"].append(row)

    report["offline_problems"] += [p for r in report["entries"]
                                   for p in r["problems"]]
    report["behind"] = [r for r in report["entries"] if r["status"] == "behind"]
    report["unpinned"] = [r for r in report["entries"]
                          if r["status"] == "unpinned"]
    report["held"] = [r for r in report["entries"] if r["status"] == "held"]
    report["ok"] = (not report["offline_problems"]) and not report["behind"]
    return report


def print_report(report, offline=False):
    probs = report["offline_problems"]
    print("── Сверка с апстримами %s──"
          % ("(offline) " if offline else ""))
    for row in report["entries"]:
        icon = _ICON["problem"] if row["problems"] else _ICON.get(
            row["status"], "~")
        line = "%s %-18s %-32s pinned=%s" % (
            icon, row["id"], row["repo"], row["pinned"] or "—")
        if row["latest"] and row["latest"] != row["pinned"]:
            line += "  latest=%s" % row["latest"]
        print(line)
        if not offline and row["message"] and row["status"] != "ok":
            print("    %s" % row["message"])

    if probs:
        print("\nРасхождения в репозитории (%d):" % len(probs))
        for p in probs:
            print("  ✗ %s" % p)

    if report["behind"]:
        print("\nОтставание от апстрима (%d):" % len(report["behind"]))
        for r in report["behind"]:
            print("  ! %s" % r["message"])
        print("\nЧто делать: синхронизировать vendored-файлы, перечитать "
              "changelog апстрима, обновить скил и pinned в docs/upstream.json.")

    if report.get("held"):
        print("\nОтстаём намеренно (%d) — решение зафиксировано в манифесте:"
              % len(report["held"]))
        for r in report["held"]:
            print("  = %s" % r["message"])

    if report["unpinned"]:
        print("\nБез базовой версии (%d) — не ошибка, но и не контроль:"
              % len(report["unpinned"]))
        for r in report["unpinned"]:
            print("  ? %s" % r["message"])

    if report["ok"]:
        print("\n✓ Всё сходится")
    return 0 if report["ok"] else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--offline", action="store_true",
                    help="только локальные сверки, без сети")
    ap.add_argument("--json", action="store_true",
                    help="машиночитаемый отчёт вместо текста")
    ap.add_argument("--id", default="", help="проверить только этот апстрим")
    ap.add_argument("--manifest", default=MANIFEST)
    args = ap.parse_args()

    manifest = load_manifest(args.manifest)
    report = run(manifest, offline=args.offline, only_id=args.id)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1
    return print_report(report, offline=args.offline)


if __name__ == "__main__":
    sys.exit(main())
