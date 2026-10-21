# core/mcp/tools/config.py
"""
Чтение и запись настроек GUI (``settings.json``).

Отдаём **редактированное** дерево: секреты режет единая
``core/mcp/redact.py`` на сериализации результата, здесь о них думать
не надо. Что можно менять — видно сразу, в поле ``writable``.

Запись (``config_set``) устроена так:

* **граница — не здесь.** Что открыто, решает
  ``core/mcp/permissions.py`` (:func:`~core.mcp.permissions.is_writable`);
  инструмент её только спрашивает и пересказывает отказ словами;
* **ответ — diff «было/стало»**, а не ``{ok: true}``: иначе модель не
  отличит запись от записи не туда;
* **список заменяется целиком.** Прежнее значение возвращается в
  ``before`` — это единственная защита от «добавил домен, стёр
  остальные»;
* **каждая удачная запись кладёт снимок** (``core/mcp/audit.py``), и
  ``mcp_undo_last`` возвращает прежнее значение. Обработчик отката для
  вида ``config`` зарегистрирован здесь же, внизу файла.

Писать мимо ``ConfigManager`` нельзя: там уже решены атомарность,
слияние с дефолтами и права на файл.
"""

import json

from core.mcp import audit
from core.mcp import permissions as perms_mod
from core.mcp import redact
from core.mcp.registry import tool
from core.mcp.tools import _paging


# Глубже этого дерево не разворачиваем даже по запросу: ответ читает
# модель с ограниченным контекстом.
MAX_DEPTH = 6

# Чем заменяется поддерево, до которого не хватило глубины.
#
# Имя поля намеренно НЕ содержит «key»: под этот корень подпадает
# маскировка секретов (``redact.SECRET_KEY_RE``), и служебное поле
# ``_keys`` уехало бы модели как ``"***"``.
CUT_FIELD = "_fields"


@tool(
    name="config_get",
    scope="read",
    mutating=False,
    title="Read settings",
    description=("Read zapret-gui settings (secrets redacted): whole tree "
                 "or one dotted path, with a writable flag telling what "
                 "config_set may change. / Прочитать настройки GUI по "
                 "точечному пути."),
    schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Dotted path, e.g. nfqws.ports_tcp. Empty "
                               "= whole tree. / Точечный путь; пусто — всё "
                               "дерево.",
                "maxLength": 200,
                "default": "",
            },
            "depth": {
                "type": "integer",
                "description": "How many nesting levels to expand (1-6). "
                               "/ Сколько уровней вложенности раскрыть.",
                "minimum": 1,
                "maximum": MAX_DEPTH,
                "default": 2,
            },
            "raw": {
                "type": "boolean",
                "default": False,
                "description": "Return secrets as-is, no masking (needs "
                               "the `secrets` permission). / Отдать "
                               "значения без маскировки.",
            },
        },
        "additionalProperties": False,
    },
)
def config_get(args: dict) -> dict:
    """Прочитать настройки целиком или по точечному пути.

    Берём `effective()`, а не `get_all()`: ключ, которого ещё нет в
    `settings.json`, всё равно действует — из дефолтов, — и модель
    должна видеть то же, что действует.
    """
    from core.config_manager import get_config_manager

    path = (args.get("path") or "").strip().strip(".")
    depth = int(args.get("depth") or 2)
    parts = perms_mod.split_path(path)

    node = get_config_manager().effective()
    walked = []
    for key in parts:
        if not isinstance(node, dict) or key not in node:
            return _not_found(path, walked, node)
        node = node[key]
        walked.append(key)

    from core.mcp import redact

    cut = []
    value = _limit_depth(node, depth, path, cut)
    secrets = perms_mod.granted("secrets")
    writable = perms_mod.is_writable(path, secrets=secrets) if parts \
        else False
    result = {
        "ok": True,
        "path": path,
        "type": _json_type(node),
        "value": value,
        "writable": writable,
        # Маскировку делает сериализация ответа (registry.tool_result);
        # здесь только честно говорим, применялась ли она, — иначе
        # «***» неотличимо от настоящего значения.
        "redacted": not redact.raw_mode(),
        "truncated": bool(cut),
    }
    if not writable:
        result["writable_reason"] = (
            perms_mod.why_not_writable(path, secrets=secrets) if parts else
            "корень дерева: запись идёт по путям вида «секция.ключ»")
    if cut:
        result["hint"] = ("свёрнуто поддеревьев: %d — запросите их "
                          "отдельно (path=%s) или увеличьте depth"
                          % (len(cut), cut[0]))
    return result


# ───────────────────────────── частности ────────────────────────────

def _not_found(path, walked, node) -> dict:
    """Путь не найден — показать, что есть рядом, а не просто отказать."""
    available = sorted(node.keys()) if isinstance(node, dict) else []
    where = ".".join(walked) or "корень"
    return {
        "ok": False,
        "error": "путь «%s» в настройках не найден" % path,
        "path": path,
        "available": available[:60],
        "hint": "в «%s» есть: %s" % (where, ", ".join(available[:20])
                                     or "ничего"),
    }


def _limit_depth(node, depth, prefix, cut):
    """Свернуть слишком глубокие поддеревья в список их ключей.

    Обрезаем **по структуре, а не по длине текста**: список ключей
    говорит модели, что там лежит и каким путём это дочитать, а
    обрубленная строка — не говорит ничего.
    """
    if not isinstance(node, dict):
        return node
    if depth <= 0:
        cut.append(prefix or "<корень>")
        return {CUT_FIELD: sorted(node.keys()), "_truncated": True}
    out = {}
    for key, value in node.items():
        child = "%s.%s" % (prefix, key) if prefix else key
        out[key] = _limit_depth(value, depth - 1, child, cut)
    return out


def _json_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


# ─────────────────────────── запись (S6) ────────────────────────────
#
# Граница записи целиком в core/mcp/permissions.py: здесь её только
# СПРАШИВАЮТ. Любая проверка «а вот это, наверное, можно» на этом
# уровне означала бы две модели границы вместо одной — и они разойдутся
# в первую же правку.

# Потолок на размер одного записываемого значения. Настройка — это не
# файл: гигантский список в settings.json делает конфиг нечитаемым для
# всех остальных, а перечитывать его придётся каждому менеджеру.
MAX_VALUE_BYTES = 32 * 1024

# Тип значения → чем его можно записать. Проверяем по значению из
# DEFAULT_CONFIG: строка, молча ставшая числом, ломается не здесь, а у
# того, кто её читает, — и уже без следов.
_ACCEPTS = {
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float))
    and not isinstance(v, bool),
    "string": lambda v: isinstance(v, str),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    # Дефолт `null` (strategy.current_id, current_name) типа не задаёт:
    # там законно и «ничего», и строка, и число.
    "null": lambda v: not isinstance(v, dict),
}


@tool(
    name="config_set",
    scope="config_write",
    mutating=True,
    title="Write one setting",
    description=("Write ONE whitelisted setting by dotted path and return "
                 "the before/after diff. Lists are REPLACED whole: read the "
                 "current value first and send it back complete. / Записать "
                 "одну настройку; список заменяется целиком."),
    schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Dotted path of ONE setting, e.g. "
                               "nfqws.ports_tcp. Sections cannot be "
                               "written. / Точечный путь одной настройки.",
                "minLength": 3,
                "maxLength": 200,
            },
            "value": {
                "description": "New value. Type must match the default "
                               "(config_writable_paths shows it). For a "
                               "list — the COMPLETE new list. / Новое "
                               "значение; для списка — полный список.",
            },
        },
        "required": ["path", "value"],
        "additionalProperties": False,
    },
)
def config_set(args: dict) -> dict:
    """Записать одну настройку и вернуть diff «было/стало».

    Ответ — именно diff, а не `{ok: true}`: модель обязана видеть, что
    изменилось на самом деле, иначе она не отличит запись от
    молчаливого приведения типа или от записи не туда.
    """
    from core.config_manager import get_config_manager
    from core.mcp import resources

    path = (args.get("path") or "").strip().strip(".")
    parts = perms_mod.split_path(path)
    value = args.get("value")

    if not parts or len(parts) < 2:
        return _refuse(path, "нужен путь вида «секция.ключ»: секцию "
                             "целиком записать нельзя")
    # Разрешение `secrets` (S17) снимает запрет на листья, похожие на
    # секрет, — и только на них: пути к файлам закрыты им всё равно.
    secrets = perms_mod.granted("secrets")
    if not perms_mod.is_writable(path, secrets=secrets):
        return _refuse(path, perms_mod.why_not_writable(path,
                                                        secrets=secrets))

    described = resources.describe_path(path)
    expected = described.get("type") or "null"
    accepts = _ACCEPTS.get(expected, _ACCEPTS["null"])
    if not accepts(value):
        return {
            "ok": False,
            "error": "«%s» — %s, а передано %s" % (path, expected,
                                                   _json_type(value)),
            "path": path,
            "type": expected,
            "default": described.get("default"),
            "value": described.get("value"),
            "describe": _describe_brief(described),
            "hint": "передайте значение типа %s; тип и допустимые "
                    "значения показывает config_writable_paths, смысл "
                    "настройки — config_describe(path=\"%s\")"
                    % (expected, path),
        }

    if value == redact.MASK and redact.is_secret_key(parts[-1]):
        # Маска из ответа config_get, отправленная обратно, — не пароль
        # «***», а стёртый пароль.
        return {"ok": False,
                "error": "«%s»: передана маска «%s», а не значение"
                         % (path, redact.MASK),
                "path": path,
                "hint": redact.MASK_WRITE_HINT}

    allowed_values = perms_mod.ENUMS.get(path)
    if allowed_values and value not in allowed_values:
        return {
            "ok": False,
            "error": "«%s» принимает только: %s (передано %r)"
                     % (path, ", ".join(str(v) for v in allowed_values),
                        value),
            "path": path,
            "enum": list(allowed_values),
            "value": described.get("value"),
            "hint": "выберите одно из перечисленных значений",
        }

    size = len(json.dumps(value, ensure_ascii=False,
                          default=str).encode("utf-8"))
    if size > MAX_VALUE_BYTES:
        return {
            "ok": False,
            "error": "значение великовато для настройки: %d байт при "
                     "пределе %d" % (size, MAX_VALUE_BYTES),
            "path": path,
            "hint": "длинные списки доменов живут в hostlist'ах и "
                    "именованных списках, а не в settings.json",
        }

    cfg = get_config_manager()
    before = described.get("value")
    is_list = isinstance(before, list) or expected == "array"

    if before == value:
        # Записывать нечего — и снимок делать нечего: откатывать такой
        # вызов означало бы вернуть то же самое.
        result = {
            "ok": True, "path": path, "type": expected,
            "before": before, "after": value, "changed": False,
            "saved": False,
            "hint": "значение уже такое — ничего не записано",
        }
        if is_list:
            result["is_list"] = True
        return result

    cfg.set(*parts, value)
    if not cfg.save():
        cfg.set(*parts, before)             # вернуть живой конфиг как был
        return {
            "ok": False,
            "error": "не удалось сохранить settings.json — значение не "
                     "записано",
            "path": path, "before": before, "after": before,
            "changed": False, "saved": False,
            "hint": "проверьте место на диске и права на %s" % cfg.path,
        }

    undo = audit.snapshot(audit.KIND_CONFIG, path, before, value,
                          tool="config_set")
    applied = _apply_live(parts[0], ".".join(parts))
    result = {
        "ok": True,
        "path": path,
        "type": expected,
        "before": before,
        "after": value,
        "changed": True,
        "saved": True,
        "undo": undo or None,
        "hint": "записано в settings.json; откат — mcp_undo_last. Часть "
                "настроек движок читает при запуске: чтобы они начали "
                "действовать, стратегию нужно применить заново",
    }
    if applied:
        result["applied_live"] = applied
    if is_list:
        result["is_list"] = True
        result["replaced"] = True
        # Самая дорогая ошибка модели здесь — «добавить домен», стерев
        # остальные. Прежнее значение возвращаем целиком, чтобы его
        # можно было собрать обратно без второго вызова.
        result["hint"] = ("список заменён ЦЕЛИКОМ, а не дополнен: прежнее "
                          "значение — в поле before, откат — "
                          "mcp_undo_last")
    if not undo:
        result["hint"] += " (журнал MCP выключен — снимка для отката нет)"
    return result


@tool(
    name="config_writable_paths",
    scope="read",
    mutating=False,
    title="List writable settings",
    description=("List settings config_set may change: dotted path, type, "
                 "current value, default and allowed values. Read this "
                 "before writing instead of guessing paths. / Что модель "
                 "может менять: путь, тип, значение, допустимые значения."),
    schema={
        "type": "object",
        "properties": {
            "section": {
                "type": "string",
                "description": "Only this top-level section, e.g. nfqws. "
                               "/ Только эта секция настроек.",
                "maxLength": 40,
                "default": "",
            },
            "search": {
                "type": "string",
                "description": "Substring of the path. / Подстрока пути.",
                "maxLength": 80,
                "default": "",
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1,
                      "maximum": _paging.MAX_LIMIT, "default": 50},
        },
        "additionalProperties": False,
    },
)
def config_writable_paths(args: dict) -> dict:
    """Какие настройки открыты на запись — с типом и текущим значением.

    Отказ за отказом стоит модели вызовов и контекста: дешевле один раз
    показать список, чем объяснять по одному пути за вызов.
    """
    section = (args.get("section") or "").strip().strip(".")
    search = (args.get("search") or "").strip().lower()
    offset, limit = _paging.limits(args, default=50)

    items = []
    for item in perms_mod.writable_paths(
            secrets=perms_mod.granted("secrets")):
        path = item["path"]
        if section and not path.startswith(section + "."):
            continue
        if search and search not in path.lower():
            continue
        items.append(item)

    if not items:
        reason = ("в секции «%s» нет настроек, открытых на запись"
                  % section) if section else "ничего не подошло под фильтр"
        return _paging.empty(
            reason,
            hint="открыты только листья секций: %s"
                 % ", ".join(perms_mod.WRITABLE_SECTIONS),
            sections=list(perms_mod.WRITABLE_SECTIONS))

    result = _paging.page(items, offset, limit,
                          sections=list(perms_mod.WRITABLE_SECTIONS))
    note = ("списочные настройки config_set заменяет целиком; остальное "
            "закрыто осознанно — причину даёт config_get(path=…) полем "
            "writable_reason")
    result["hint"] = ("%s; %s" % (result["hint"], note)) if \
        result.get("hint") else note
    return result


def _apply_live(section: str, path: str = "") -> str:
    """Применить настройку «вживую» там, где это умеет сам GUI.

    Ровно то же, что делает ``PUT /api/config`` после записи секции:
    запись, которая начнёт действовать только после перезапуска GUI, —
    это запись наполовину, а поднять уровень лога модели нужно ЗДЕСЬ И
    СЕЙЧАС, иначе воспроизводить проблему нечем. Движков это не
    касается: их старт и перезапуск — разрешение ``control`` (S7).
    """
    if path in ("dns_routing.rules", "dns_routing.auto_server") \
            or (section == "dns_routing" and path.startswith(
                "dns_routing.rules.")):
        # Правила и сервер «auto» живут в dnsmasq: без пересборки
        # dns-routing.conf запись (и её откат) не действовала бы.
        try:
            from core.dns_routing import get_dns_routing_manager
            r = get_dns_routing_manager().apply()
            return "dns_routing" if r.get("ok") else ""
        except Exception:                       # noqa: BLE001 — граница
            return ""
    if section != "logging":
        return ""
    try:
        from core.log_buffer import reconfigure_persistent_from_config
        reconfigure_persistent_from_config()
        return "logging"
    except Exception:                           # noqa: BLE001 — граница
        return ""


def _undo_config(snapshot: dict) -> dict:
    """Вернуть настройке значение из снимка (обработчик ``mcp_undo_last``).

    Регистрируется здесь, а не в журнале: журнал хранит снимки любого
    вида (файлы S12, код S13) и про настройки знать не должен.
    """
    from core.config_manager import get_config_manager

    path = snapshot.get("target") or ""
    parts = perms_mod.split_path(path)
    secrets = perms_mod.granted("secrets")
    if not parts or not perms_mod.is_writable(path, secrets=secrets):
        return {"ok": False,
                "error": "«%s» сейчас не принимается на запись: %s"
                         % (path, perms_mod.why_not_writable(
                             path, secrets=secrets)
                            or "путь недоступен"),
                "hint": "настройка закрылась после того, как снимок был "
                        "сделан — верните значение вручную"}

    cfg = get_config_manager()
    node = cfg.effective()
    for key in parts:
        node = node.get(key) if isinstance(node, dict) else None
    current = node
    before = snapshot.get("before")

    cfg.set(*parts, before)
    if not cfg.save():
        cfg.set(*parts, current)
        return {"ok": False,
                "error": "не удалось сохранить settings.json — откат не "
                         "выполнен"}
    applied = _apply_live(parts[0], ".".join(parts))
    out = {"ok": True, "undone_from": current}
    if applied:
        out["applied_live"] = applied
    return out


def _refuse(path, reason) -> dict:
    """Отказ записи: почему нельзя и что делать вместо этого.

    Отказ без «что можно» модель читает как «попробуй иначе» и пробует
    соседний путь — поэтому здесь и причина, и описание самой настройки,
    и имя инструмента со списком разрешённого.
    """
    from core.mcp import resources

    described = resources.describe_path(path) if path else {}
    return {
        "ok": False,
        "error": "настройка «%s» на запись через MCP не принимается"
                 % (path or "<пусто>"),
        "path": path,
        "writable": False,
        "reason": reason or "путь вне разрешённых поддеревьев",
        "describe": _describe_brief(described),
        "sections": list(perms_mod.WRITABLE_SECTIONS),
        "hint": "полный список разрешённого — config_writable_paths(); "
                "что означает настройка — config_describe(path=…). Если "
                "менять всё-таки надо, это делает человек в веб-интерфейсе",
    }


def _describe_brief(described) -> dict:
    """Короткая выжимка из ``resources.describe_path`` для отказа."""
    if not isinstance(described, dict) or not described:
        return {}
    keys = ("type", "default", "value", "enum", "exists", "documented",
            "text", "unit", "writable", "writable_reason")
    return {k: described[k] for k in keys if k in described}


# Откат настроек объявляется при импорте модуля: инструменты грузит
# реестр, и `mcp_undo_last` находит обработчик уже готовым. Журнал про
# настройки не знает — он хранит снимки любого вида (файлы в S12, код
# в S13), а как их применять, говорит тот, кто их делает.
audit.register_undo(audit.KIND_CONFIG, _undo_config)
