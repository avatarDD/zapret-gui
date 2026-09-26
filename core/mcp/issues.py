# core/mcp/issues.py
"""
Черновики issue: модель нашла ошибку в GUI — разработчик получает отчёт,
по которому её можно найти.

Модель хорошо замечает, что инструмент повёл себя не так, как описан, и
плохо — где именно в коде это случилось. Поэтому черновик собирается
**вдвоём**: модель пишет то, что видела (что ожидала, что получила,
какими шагами), а сервер дописывает то, что модель исказила бы или не
знает вовсе:

* **где искать** — файл и строка обработчика инструмента
  (``crashes.locate``), кадры трассировки по ``crash_id``;
* **как воспроизвести** — готовая команда ``zapret-gui mcp call <tool>
  '<args>'`` с аргументами последнего вызова из журнала;
* окружение: версия GUI, платформа, действующие разрешения, версии
  движков из кеша, признак локальных правок кода (номера строк после
  самоправки с релизом не совпадают);
* хвост журнала MCP и строки лога уровня warning+ за окно вокруг
  проблемы.

## Куда черновик едет дальше

Никуда сам. Черновики лежат в ``mcp-issue-drafts.json`` рядом с
``settings.json``; человек видит их на странице MCP (и в
``zapret-gui mcp issues``) и открывает issue **своим** браузером по
ссылке ``/issues/new?title=…&body=…``. GitHub-токена на роутере нет и
не будет: модель, которой отдали право публиковать, может заспамить
репозиторий, а человек, открывший ссылку, видит, что отправляет.

## Приватность

* весь текст проходит ``redact_text(force=True)`` — как журнал;
* **домены и публичные адреса маскируются по умолчанию**
  (``<домен-1>``, ``<ip-1>``, одна метка на одно значение во всём
  черновике): список обходимых сайтов и WAN-адрес — личные данные, а
  для разбора ошибки почти всегда хватает «домен A» и «домен B».
  ``include_targets=true`` при создании черновика это выключает;
* код (файлы, функции, строки трассировки) не маскируется: он публичный.

## Повторы

Одинаковая ошибка склеивается по отпечатку: у падения это отпечаток
трассировки (``crashes.fingerprint``), у остального — вид, инструмент
и нормализованный заголовок. Повтор увеличивает ``occurrences`` и
дописывает ``crash_id``, а не плодит черновик.
"""

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import uuid
from urllib.parse import quote

from core.log_buffer import log
from core.mcp import crashes
from core.mcp import redact as redact_mod
from core.safe_io import atomic_write_text


FILE_NAME = "mcp-issue-drafts.json"

REPO_URL = "https://github.com/avatarDD/zapret-gui"
NEW_ISSUE_URL = REPO_URL + "/issues/new"
LABEL = "from-agent"
REPORT_SCHEMA = "zapret-gui-report/v1"

KINDS = ("crash", "wrong_result", "contract", "docs_mismatch", "other")
KIND_TEXT = {
    "crash": "падение инструмента",
    "wrong_result": "неверный результат",
    "contract": "ответ не соответствует описанию инструмента",
    "docs_mismatch": "документация расходится с поведением",
    "other": "другое",
}
SEVERITIES = ("low", "medium", "high")

STATUS_DRAFT = "draft"
STATUS_SENT = "sent"
STATUSES = (STATUS_DRAFT, STATUS_SENT)

# Сколько черновиков храним. Больше — это уже не черновики, а модель,
# которая пишет отчёт на каждый чих; старые отправленные уходят первыми.
MAX_DRAFTS = 30

# Подрезка полей, которые пишет модель.
MAX_TITLE = 120
MAX_TEXT = 2000
MAX_STEPS = 12
MAX_STEP = 300

# Сколько контекста собираем.
AUDIT_ROWS = 8
LOG_ROWS = 20
LOG_WINDOW_SEC = 600
CRASH_IDS_KEEP = 5

# Ссылка /issues/new живёт в адресной строке: браузеры и GitHub режут
# длинные адреса (практический потолок ~8 КБ). Сверх — укороченный текст
# и просьба вставить полный из буфера.
MAX_URL = 7500

_lock = threading.Lock()


# ────────────────────────────── создание ────────────────────────────

def create(*, title, kind="other", tool="", component="", actual="",
           expected="", steps=None, evidence="", crash_id="",
           severity="medium", args=None, include_targets=False,
           source="mcp") -> dict:
    """Создать черновик (или склеить с уже существующим таким же).

    Возвращает ``{ok, draft, merged, markdown, open_on_github, …}``.
    Отказ — ``ok: false`` + ``error`` + ``hint``, без исключений.
    """
    title = _clip(title, MAX_TITLE)
    if not title:
        return _refusal("пустой заголовок",
                        "одна строка: что сломалось, например «blobs_list "
                        "падает на пустом каталоге blobs»")
    kind = kind if kind in KINDS else "other"
    severity = severity if severity in SEVERITIES else "medium"
    tool = str(tool or "").strip()
    spec = _tool_spec(tool) if tool else None
    if tool and spec is None:
        return _refusal("инструмента «%s» нет в реестре" % tool,
                        "имя — как в tools/list; для страницы веб-"
                        "интерфейса или движка используйте component")

    crash = None
    if crash_id:
        crash = crashes.get(crash_id)
        if crash is None:
            return _refusal("падения %s нет в журнале падений" % crash_id,
                            "crash_id приходит в ответе упавшего "
                            "инструмента; последние — issue_draft_list")
        if not tool:
            tool = crash.get("tool", "")
            spec = _tool_spec(tool)
        kind = "crash"
    elif kind == "crash" and tool:
        # Модель назвала вид, но потеряла id — берём свежее падение
        # этого инструмента, если оно было за последний час.
        crash = _recent_crash(tool)

    now = time.time()
    draft = {
        "id": "draft-%s" % uuid.uuid4().hex[:8],
        "created": round(now, 3),
        "updated": round(now, 3),
        "time": _stamp(now),
        "status": STATUS_DRAFT,
        "source": source,
        "occurrences": 1,
        "kind": kind,
        "severity": severity,
        "title": title,
        "tool": tool,
        "component": _clip(component, MAX_TITLE),
        "actual": _clip(actual, MAX_TEXT),
        "expected": _clip(expected, MAX_TEXT),
        "steps": _steps(steps),
        "evidence": _clip(evidence, MAX_TEXT),
        "crash_ids": [crash["crash_id"]] if crash else [],
        "include_targets": bool(include_targets),
        "context": collect_context(spec, crash, args=args, now=now),
    }
    draft["fingerprint"] = draft_fingerprint(draft, crash)

    with _lock:
        drafts = _read()
        same = _find_same(drafts, draft["fingerprint"])
        if same is not None:
            _merge(same, draft)
            result_draft, merged = same, True
        else:
            drafts.append(draft)
            result_draft, merged = draft, False
        drafts = _trim(drafts)
        saved = _write(drafts)

    out = describe(result_draft)
    out.update({"ok": True, "merged": merged, "saved": saved})
    if merged:
        out["hint"] = ("такой черновик уже был — посчитали повтор "
                       "(occurrences=%d); новый не заводили"
                       % result_draft.get("occurrences", 1))
    else:
        out["hint"] = ("черновик сохранён на устройстве; отправляет его "
                       "человек со страницы MCP (блок «Черновики issue») "
                       "или по ссылке open_on_github")
    if not saved:
        out["warning"] = ("каталог настроек недоступен — черновик не "
                          "сохранён, но текст ниже годен для отправки")
    return out


def collect_context(spec, crash, *, args=None, now=None) -> dict:
    """То, что сервер знает лучше модели. Каждая часть — под своим try."""
    now = now or time.time()
    ctx = {"version": crashes.gui_version(), "environment": _environment()}
    if spec is not None:
        ctx["tool"] = {"name": spec.name,
                       "scope": spec.scope or "read",
                       "mutating": spec.mutating,
                       "handler": crashes.locate(spec.handler)}
        # Аргументы от модели — как в журнале: маска по ключам и подрезка
        # уже при сохранении, а не только при рендере текста issue.
        repro_args = (_safe_args(args) if isinstance(args, dict)
                      else _last_args(spec.name))
        if repro_args is not None:
            ctx["repro"] = {"tool": spec.name, "args": repro_args}
    if crash:
        ctx["crash"] = {k: crash.get(k) for k in (
            "crash_id", "time", "exc_type", "message", "frames", "handler",
            "fingerprint", "version") if crash.get(k) is not None}
        if crash.get("args") and "repro" not in ctx:
            ctx["repro"] = {"tool": crash.get("tool"),
                            "args": crash.get("args")}
    ctx["audit"] = _audit_rows()
    ctx["log"] = _log_rows(now)
    ctx["permissions"] = _permissions()
    engines = _engines()
    if engines:
        ctx["engines"] = engines
    changes = crashes.local_code_changes()
    if changes.get("count"):
        ctx["local_code_changes"] = {"count": changes.get("count"),
                                     "files": list(changes.get("files")
                                                   or [])[:20]}
    return ctx


def draft_fingerprint(draft: dict, crash=None) -> str:
    if crash and crash.get("fingerprint"):
        return "crash:" + str(crash["fingerprint"])
    title = re.sub(r"[\W_]+", " ", draft.get("title", "").lower()).strip()
    raw = "|".join((draft.get("kind", ""), draft.get("tool", ""),
                    draft.get("component", "").lower(), title))
    return "text:" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# ──────────────────────────── чтение и правка ───────────────────────

def list_drafts() -> list:
    """Черновики, свежие первыми."""
    drafts = _read()
    drafts.sort(key=lambda d: d.get("updated", 0), reverse=True)
    return drafts


def get(draft_id: str):
    for item in _read():
        if item.get("id") == draft_id:
            return item
    return None


def summary(draft: dict) -> dict:
    """Строка списка: без контекста и текста."""
    out = {k: draft.get(k) for k in (
        "id", "time", "status", "kind", "severity", "title", "tool",
        "component", "occurrences", "crash_ids", "source")}
    out["updated"] = _stamp(draft.get("updated") or 0)
    return out


def describe(draft: dict) -> dict:
    """Черновик целиком + то, что с ним делать: текст и ссылка."""
    body = render_markdown(draft)
    url, shortened = github_url(draft, body)
    # Не «github_url»: ключ вида *_url маска режет до хоста
    # (redact.URL_KEY_RE), и ссылка доехала бы до модели обрубком.
    return {"draft": summary(draft), "markdown": body,
            "open_on_github": url, "body_shortened": shortened}


def set_status(draft_id: str, status: str) -> dict:
    if status not in STATUSES:
        return _refusal("неизвестный статус «%s»" % status,
                        "допустимы: %s" % ", ".join(STATUSES))
    with _lock:
        drafts = _read()
        for item in drafts:
            if item.get("id") == draft_id:
                item["status"] = status
                item["updated"] = round(time.time(), 3)
                _write(drafts)
                return {"ok": True, "draft": summary(item)}
    return _refusal("черновика %s нет" % draft_id, "список — issue_draft_list")


def delete(draft_id: str) -> dict:
    with _lock:
        drafts = _read()
        left = [d for d in drafts if d.get("id") != draft_id]
        if len(left) == len(drafts):
            return _refusal("черновика %s нет" % draft_id,
                            "список — issue_draft_list")
        _write(left)
    return {"ok": True, "deleted": draft_id}


def crashes_without_draft(limit: int = 10) -> list:
    """Падения, по которым черновика ещё нет — модели есть о чём писать."""
    known = set()
    for draft in _read():
        known.update(draft.get("crash_ids") or [])
    out = []
    for crash in crashes.recent():
        if crash.get("crash_id") in known:
            continue
        top = (crash.get("frames") or [{}])[-1]
        out.append({"crash_id": crash.get("crash_id"),
                    "time": crash.get("time"), "tool": crash.get("tool"),
                    "error": "%s: %s" % (crash.get("exc_type"),
                                         crash.get("message", "")),
                    "where": "%s:%s" % (top.get("file", "?"),
                                        top.get("line", "?"))})
        if len(out) >= limit:
            break
    return out


# ────────────────────────────── рендер ──────────────────────────────

def render_markdown(draft: dict, compact: bool = False) -> str:
    """Тело issue. ``compact`` — без журнала и лога (для ссылки)."""
    mask = _Masker(enabled=not draft.get("include_targets"))
    ctx = draft.get("context") or {}
    tool_ctx = ctx.get("tool") or {}
    crash = ctx.get("crash") or {}
    lines = ["<!-- %s -->" % REPORT_SCHEMA]

    head = ["**Вид:** %s" % KIND_TEXT.get(draft.get("kind"), "другое")]
    if draft.get("tool"):
        head.append("**Инструмент:** `%s`" % draft["tool"])
    if draft.get("component"):
        head.append("**Компонент:** %s" % mask(draft["component"]))
    head.append("**Серьёзность:** %s" % draft.get("severity", "medium"))
    if (draft.get("occurrences") or 1) > 1:
        head.append("**Повторов:** %d" % draft["occurrences"])
    lines += [" · ".join(head), ""]

    for heading, key in (("Что произошло", "actual"),
                         ("Что ожидалось", "expected")):
        if draft.get(key):
            lines += ["### " + heading, mask(draft[key]), ""]
    if draft.get("steps"):
        lines.append("### Шаги")
        lines += ["%d. %s" % (i + 1, mask(s))
                  for i, s in enumerate(draft["steps"])]
        lines.append("")

    where = []
    handler = tool_ctx.get("handler") or crash.get("handler") or {}
    if handler.get("file"):
        where.append("- обработчик: `%s:%s` (`%s`)" % (
            handler["file"], handler.get("line"), handler.get("function")))
    if crash:
        where.append("- падение `%s`: `%s: %s`" % (
            crash.get("crash_id"), crash.get("exc_type"),
            mask(crash.get("message", ""))))
    if where or crash.get("frames"):
        lines += ["### Где искать"] + where
        frames = crash.get("frames") or []
        if frames:
            if compact:
                frames = frames[-3:]
            lines += ["", "Трассировка (последний кадр — место падения):",
                      "```"]
            for fr in frames:
                lines.append("%s:%s in %s" % (fr.get("file"), fr.get("line"),
                                              fr.get("function")))
                if fr.get("code"):
                    lines.append("    " + fr["code"])
            lines.append("```")
        lines.append("")

    repro = ctx.get("repro")
    if repro:
        args_json = json.dumps(repro.get("args") or {}, ensure_ascii=False)
        args_json = mask(args_json).replace("'", "'\\''")
        lines += ["### Как воспроизвести", "```sh",
                  "zapret-gui mcp call %s '%s'" % (repro.get("tool"),
                                                   args_json),
                  "```"]
        if "<домен-" in args_json or "<ip-" in args_json:
            lines.append("_Метки `<домен-N>`/`<ip-N>` замените любым "
                         "доменом или адресом: исходные скрыты._")
        lines.append("")

    lines.append("### Окружение")
    env = ctx.get("environment") or {}
    lines.append("- zapret-gui %s, %s, %s, Python %s" % (
        ctx.get("version") or "?", env.get("platform", "?"),
        env.get("arch", "?"), env.get("python", "?")))
    if tool_ctx:
        lines.append("- инструмент: scope `%s`, %s" % (
            tool_ctx.get("scope"),
            "мутирующий" if tool_ctx.get("mutating") else "только чтение"))
    perms = [k for k, v in (ctx.get("permissions") or {}).items() if v]
    lines.append("- действующие разрешения: %s"
                 % (", ".join(perms) if perms else "только чтение"))
    if ctx.get("engines"):
        lines.append("- движки: " + ", ".join(
            "%s %s" % (e.get("name"), e.get("current") or "?")
            for e in ctx["engines"]))
    changes = ctx.get("local_code_changes")
    if changes:
        lines.append("- ⚠ на устройстве локальные правки кода (%d файл(ов): "
                     "%s) — номера строк могут не совпадать с релизом"
                     % (changes.get("count", 0),
                        ", ".join(changes.get("files") or [])[:300]))
    lines.append("")

    if draft.get("evidence"):
        lines += ["### Наблюдения модели", "```",
                  mask(draft["evidence"]), "```", ""]

    if not compact:
        audit_rows = ctx.get("audit") or []
        if audit_rows:
            lines += ["### Журнал MCP (последние вызовы, новые сверху)",
                      "| время | инструмент | итог | ошибка |",
                      "|---|---|---|---|"]
            for row in audit_rows:
                lines.append("| %s | `%s` | %s | %s |" % (
                    row.get("time", ""), row.get("tool", ""),
                    row.get("status", ""),
                    _cell(mask(row.get("error", "")))))
            lines.append("")
        log_rows = ctx.get("log") or []
        if log_rows:
            lines += ["### Лог (warning и выше, вокруг проблемы)", "```"]
            lines += [mask(r) for r in log_rows]
            lines += ["```", ""]

    lines += ["<details><summary>Машиночитаемый блок</summary>", "",
              "```json", mask(json.dumps(machine_block(draft),
                                         ensure_ascii=False, indent=1)),
              "```", "</details>", "",
              "_Черновик составлен ИИ через MCP-сервер zapret-gui "
              "(`issue_draft`) и проверен человеком перед отправкой._"]
    if mask.enabled and mask.count:
        lines.append("_Домены и публичные адреса заменены метками "
                     "(`<домен-N>`, `<ip-N>`)._")
    return redact_mod.redact_text("\n".join(lines), force=True)


def machine_block(draft: dict) -> dict:
    """Короткий JSON для разбора отчёта программой (и разработчиком)."""
    ctx = draft.get("context") or {}
    crash = ctx.get("crash") or {}
    tool_ctx = ctx.get("tool") or {}
    block = {"schema": REPORT_SCHEMA, "kind": draft.get("kind"),
             "tool": draft.get("tool") or None,
             "component": draft.get("component") or None,
             "version": ctx.get("version"),
             "platform": (ctx.get("environment") or {}).get("platform"),
             "handler": tool_ctx.get("handler") or crash.get("handler"),
             "fingerprint": draft.get("fingerprint"),
             "occurrences": draft.get("occurrences", 1),
             "local_code_changes": (ctx.get("local_code_changes")
                                    or {}).get("count", 0)}
    if crash:
        block["exception"] = "%s: %s" % (crash.get("exc_type"),
                                         crash.get("message", ""))
        block["frames"] = ["%s:%s:%s" % (f.get("file"), f.get("line"),
                                         f.get("function"))
                           for f in crash.get("frames") or []]
    if ctx.get("repro"):
        block["repro"] = ctx["repro"]
    return block


def github_url(draft: dict, body: str = "") -> tuple:
    """Ссылка «новое issue» и признак, что тело в ней укорочено."""
    title = draft.get("title", "")
    body = body or render_markdown(draft)
    url = _issue_url(title, body)
    if len(url) <= MAX_URL:
        return url, False
    url = _issue_url(title, render_markdown(draft, compact=True))
    if len(url) <= MAX_URL:
        return url, True
    note = ("Полный отчёт не поместился в ссылку — скопируйте его со "
            "страницы MCP (блок «Черновики issue») и вставьте сюда.\n\n"
            "Черновик: `%s`, вид: %s, инструмент: `%s`."
            % (draft.get("id"), draft.get("kind"), draft.get("tool") or "—"))
    return _issue_url(title, note), True


def _issue_url(title, body) -> str:
    return "%s?labels=%s&title=%s&body=%s" % (
        NEW_ISSUE_URL, quote(LABEL), quote(title, safe=""),
        quote(body, safe=""))


# ───────────────────────────── маскировка ───────────────────────────

# Кандидат в домены: метки через точку, последняя — буквы.
_DOMAIN_RE = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"([a-z]{2,24}))(?![\w-]|\.\w)", re.IGNORECASE)
# Кандидаты в адреса: проверяются ipaddress, а не регэкспом.
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IPV6_RE = re.compile(r"(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})"
                      r"(?![\w:])")

# «Домены», которые на самом деле имена файлов и модулей: окончание
# совпадает с расширением. Маскировать `settings.json` — портить отчёт.
_FILE_SUFFIXES = frozenset((
    "py", "pyc", "js", "json", "jsonl", "lua", "txt", "conf", "cfg", "yaml",
    "yml", "log", "md", "html", "css", "sh", "bin", "ipk", "apk", "gz",
    "tar", "tgz", "zip", "xz", "pcap", "tsv", "csv", "ini", "so", "pid",
    "lock", "tmp", "bak", "list", "srs", "dat", "db", "mmdb", "pem", "crt",
    "key", "service", "rules", "nft", "hex", "exe", "dll", "svg", "png",
))
# Первая метка, по которой видно, что это путь модуля, а не домен.
# Только пока окончание не похоже на настоящую зону: `api.` и `web.` —
# это и наши пакеты, и `api.telegram.org` / `web.whatsapp.com`, а
# список обходимых сайтов — ровно то, что прячем.
_MODULE_HEADS = ("core.", "api.", "web.", "tests.", "tools.", "self.",
                 "os.", "sys.", "json.", "re.")
# Зоны, при которых «путь модуля» всё-таки считаем доменом. Двухбуквенные
# (все национальные) проверяются по длине, здесь — частые общие.
_COMMON_TLDS = frozenset((
    "com", "net", "org", "info", "biz", "edu", "gov", "int", "app", "dev",
    "io", "xyz", "top", "site", "online", "pro", "shop", "club", "cloud",
    "tech", "store", "live", "media", "news", "art", "link", "space",
    "website", "world", "one", "games", "video", "social",
))
# Наши собственные адреса и адреса апстримов: публичные, в отчёте полезны.
_KEEP_DOMAINS = ("github.com", "githubusercontent.com", "entware.net",
                 "sagernet.org", "metacubex.one", "amnezia.org",
                 "cloudflareclient.com", "sec-tunnel.com", "example.com",
                 "modelcontextprotocol.io", "openwrt.org")


class _Masker:
    """Одна метка на одно значение во всём черновике."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.map = {}
        self.count = 0

    def __call__(self, text):
        if not self.enabled or not isinstance(text, str) or not text:
            return text if isinstance(text, str) else ""
        text = _IPV4_RE.sub(lambda m: self._ip(m.group(1)), text)
        text = _IPV6_RE.sub(lambda m: self._ip(m.group(1)), text)
        return _DOMAIN_RE.sub(self._domain, text)

    def _label(self, kind, value):
        key = (kind, value.lower())
        if key not in self.map:
            n = sum(1 for k in self.map if k[0] == kind) + 1
            self.map[key] = "<%s-%d>" % (kind, n)
            self.count += 1
        return self.map[key]

    def _ip(self, value):
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        if not addr.is_global:
            return value            # 192.168.1.1 и 127.0.0.1 — не личное
        return self._label("ip", value)

    def _domain(self, match):
        value, tld = match.group(1), match.group(2)
        low = value.lower()
        if tld.lower() in _FILE_SUFFIXES or _looks_like_code(low, tld):
            return value
        if any(low == d or low.endswith("." + d) for d in _KEEP_DOMAINS):
            return value
        return self._label("домен", value)


def _looks_like_code(low: str, tld: str) -> bool:
    """Имя из кода (``urllib.error.URLError``, ``core.mcp.tools``), а не домен.

    Сомнение решается в пользу маски: лишняя метка портит строку
    отчёта, а пропущенный домен уезжает на GitHub.
    """
    # CamelCase в последней метке — имя класса: зон вида `URLError` нет,
    # а `YouTube.Com` и `YOUTUBE.COM` остаются доменами.
    if any(c.isupper() for c in tld[1:]) and any(c.islower() for c in tld):
        return True
    if low.startswith(_MODULE_HEADS):
        zone = tld.lower()
        return not (len(zone) == 2 or zone in _COMMON_TLDS)
    return False


# ───────────────────────────── частности ────────────────────────────

def path() -> str:
    from core import platform_dirs
    return os.path.join(platform_dirs.config_dir(), FILE_NAME)


def _refusal(error, hint) -> dict:
    return {"ok": False, "error": error, "hint": hint}


def _clip(value, limit) -> str:
    text = redact_mod.redact_text(str(value or "").strip(), force=True)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _steps(steps) -> list:
    if isinstance(steps, str):
        steps = [s for s in steps.splitlines() if s.strip()]
    if not isinstance(steps, list):
        return []
    return [_clip(s, MAX_STEP) for s in steps if str(s or "").strip()][
        :MAX_STEPS]


def _stamp(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts or 0))


def _cell(text) -> str:
    text = str(text or "").replace("|", "\\|").replace("\n", " ")
    return text[:160]


def _tool_spec(name):
    try:
        from core.mcp import registry
        return registry.get_tool(name)
    except Exception:                           # noqa: BLE001 — граница
        return None


def _recent_crash(tool: str, window: float = 3600):
    now = time.time()
    for crash in crashes.recent():
        if crash.get("tool") == tool and now - (crash.get("ts") or 0) < window:
            return crash
    return None


def _safe_args(args: dict) -> dict:
    try:
        from core.mcp import audit
        return audit._safe_args(args)
    except Exception:                           # noqa: BLE001 — граница
        return {}


def _last_args(tool: str):
    """Аргументы последнего вызова инструмента — из журнала (уже без
    секретов). ``None`` — вызова не было."""
    try:
        from core.mcp import audit
        records, _ = audit.read_records(limit=200)
    except Exception:                           # noqa: BLE001 — граница
        return None
    for rec in records:
        if rec.get("tool") == tool and rec.get("tool") != "issue_draft":
            args = rec.get("args")
            return args if isinstance(args, dict) else {}
    return None


def _audit_rows() -> list:
    try:
        from core.mcp import audit
        records, _ = audit.read_records(limit=AUDIT_ROWS + 4)
    except Exception:                           # noqa: BLE001 — граница
        return []
    rows = []
    for rec in records:
        if rec.get("tool", "").startswith("issue_draft"):
            continue
        row = {"time": rec.get("time", ""), "tool": rec.get("tool", ""),
               "status": rec.get("status", "")}
        if rec.get("error"):
            row["error"] = str(rec["error"])[:200]
        crash_id = (rec.get("result") or {}).get("crash_id")
        if crash_id:
            row["crash_id"] = crash_id
        rows.append(row)
        if len(rows) >= AUDIT_ROWS:
            break
    return rows


def _log_rows(now: float) -> list:
    try:
        from core.log_buffer import get_log_buffer
        entries = get_log_buffer().get_filtered(
            level="WARNING", n=LOG_ROWS, since=now - LOG_WINDOW_SEC)
    except Exception:                           # noqa: BLE001 — граница
        return []
    out = []
    for e in entries[-LOG_ROWS:]:
        src = "[%s] " % e.get("source") if e.get("source") else ""
        text = "%s %s %s%s" % (e.get("time", ""), e.get("level", ""), src,
                               e.get("message", ""))
        out.append(redact_mod.redact_text(text, force=True)[:300])
    return out


def _permissions() -> dict:
    try:
        from core.mcp import permissions as perms_mod
        return perms_mod.effective(perms_mod.current())
    except Exception:                           # noqa: BLE001 — граница
        return {}


def _engines() -> list:
    """Версии движков из КЕША проверки обновлений: в сеть не ходим."""
    try:
        from core import update_checker
        rows = update_checker.get_cached_results().get("results") or []
    except Exception:                           # noqa: BLE001 — граница
        return []
    out = []
    for row in rows:
        if isinstance(row, dict) and row.get("installed"):
            out.append({"name": row.get("name", ""),
                        "current": row.get("current", "")})
    return out[:12]


def _environment() -> dict:
    """Платформа без имени хоста и WAN-адреса."""
    import platform as platform_mod
    kind = "linux"
    if os.path.isdir("/opt/etc/ndm"):
        kind = "keenetic"
    elif os.path.exists("/etc/openwrt_release"):
        kind = "openwrt"
    return {"platform": kind, "arch": platform_mod.machine(),
            "kernel": platform_mod.release(),
            "python": platform_mod.python_version()}


def _find_same(drafts, fingerprint):
    for item in drafts:
        if (item.get("fingerprint") == fingerprint
                and item.get("status") == STATUS_DRAFT):
            return item
    return None


def _merge(old: dict, new: dict):
    """Повтор: счётчик, свежий контекст, новые crash_id и шаги-пустоты."""
    old["occurrences"] = int(old.get("occurrences") or 1) + 1
    old["updated"] = new["updated"]
    ids = list(old.get("crash_ids") or [])
    for cid in new.get("crash_ids") or []:
        if cid not in ids:
            ids.append(cid)
    old["crash_ids"] = ids[-CRASH_IDS_KEEP:]
    for key in ("actual", "expected", "evidence", "steps"):
        if not old.get(key) and new.get(key):
            old[key] = new[key]
    old["context"] = new.get("context") or old.get("context")


def _trim(drafts: list) -> list:
    if len(drafts) <= MAX_DRAFTS:
        return drafts
    drafts = sorted(drafts, key=lambda d: d.get("updated", 0))
    while len(drafts) > MAX_DRAFTS:
        victim = next((d for d in drafts if d.get("status") == STATUS_SENT),
                      drafts[0])
        drafts.remove(victim)
    return drafts


def _read() -> list:
    try:
        with open(path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    items = data.get("drafts") if isinstance(data, dict) else None
    return [d for d in items or [] if isinstance(d, dict)]


def _write(drafts: list) -> bool:
    target = path()
    if not os.path.isdir(os.path.dirname(target)):
        return False
    try:
        atomic_write_text(target, json.dumps(
            {"version": 1, "drafts": drafts}, ensure_ascii=False,
            default=str))
        return True
    except (OSError, TypeError, ValueError) as e:
        try:
            log.debug("MCP: не удалось сохранить черновик issue: %s" % e,
                      source="mcp")
        except Exception:                       # noqa: BLE001 — граница
            pass
        return False
