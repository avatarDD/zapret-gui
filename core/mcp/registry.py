# core/mcp/registry.py
"""
Реестр инструментов MCP: декоратор ``@tool``, вызов, форма ответа.

Инструмент объявляется **рядом со своей логикой** — в модуле
``core/mcp/tools/*.py``, декоратором:

.. code-block:: python

    @tool(
        name="config_get",          # <домен>_<действие>, snake_case
        scope="read",               # одно из permissions.SCOPES
        mutating=False,
        title="Read settings",
        description="EN + RU одной строкой, ≤ 300 символов",
        schema={"type": "object", "properties": {...}},
    )
    def config_get(args: dict) -> dict:
        '''Короткий docstring по-русски.'''

Реестр сам находит модули ``core/mcp/tools/*`` (``pkgutil``): новый файл
подхватывается без правки этого. Импорт — **ленивый**, при первом
обращении к реестру: инструменты тянут менеджеры, менеджеры тянут
конфиг, и импорт на уровне ``core.mcp`` замкнул бы круг.

Ошибки объявления — исключение при импорте, а не тихая регистрация:
имя не в snake_case, пустое или слишком длинное описание, неизвестный
``scope``, мутирующий инструмент с ``scope="read"``. Инструмент, который
зарегистрировался «как-нибудь», уедет модели и будет ею вызван.

Здесь же — **единственная точка сериализации результата**
(:func:`tool_result`): редактирование секретов и обрезка по
``mcp.limits.response_kb``. Инструменты об этом не знают и знать не
должны.

Там же решается и **режим «без маскировки»** (S17): инструмент, у
которого в схеме объявлен аргумент ``raw``, вызывается внутри
``redact.unredacted()`` — но только если включено разрешение
``secrets``. Без разрешения ``raw: true`` — не тихая маскировка, а
честный отказ: модель, прочитавшая конфиг с ``***`` вместо ключа и
записавшая его обратно, этот ключ уничтожит.
"""

import importlib
import json
import pkgutil
import re
import threading
import time
import traceback

from core.log_buffer import log
from core.mcp import audit
from core.mcp import crashes
from core.mcp import permissions as perms_mod
from core.mcp import redact as redact_mod
from core.mcp import schema as schema_mod


# Имя инструмента: snake_case, начинается с буквы.
NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

# Описание читает модель, и оно уезжает в каждый tools/list: длинное
# описание съедает её контекст, пустое — делает инструмент бесполезным.
MAX_DESCRIPTION = 300

# Сколько инструментов отдаём за одну страницу tools/list. Набор «только
# чтение» перерос 50 (geneva_c добавила шесть), а часть клиентов
# nextCursor у tools/list не запрашивает вовсе — и не увидела бы хвост.
PAGE_SIZE = 100

# Отличаем «не передали» от «передали None»: scope=None — это законное
# значение (чтение), а отсутствие scope — ошибка объявления.
_MISSING = object()

# Сколько символов строки верхнего уровня оставляем в ответе «слишком
# много». Длиннее — это и есть содержимое (текст конфига, файла, вывод
# команды), из-за которого ответ не влез: оставить его — значит отдать
# тот же самый ответ под видом обрезанного.
TRUNCATED_STR_MAX = 300

# Имя аргумента, которым вызов просит ответ без маскировки секретов.
# Одно на все инструменты: разные имена («full», «plain», «no_redact»)
# модель перепутает, а проверка разрешения тут ровно одна.
RAW_ARG = "raw"


class ToolError(ValueError):
    """Инструмент объявлен неверно (ошибка программиста, не клиента)."""


class UnknownTool(KeyError):
    """Запрошен инструмент, которого нет в реестре."""


class ToolSpec:
    """Объявление инструмента в реестре."""

    __slots__ = ("name", "handler", "title", "description", "schema",
                 "scope", "mutating", "module")

    def __init__(self, name, handler, title, description, schema,
                 scope=None, mutating=False):
        self.name = name
        self.handler = handler
        self.title = title
        self.description = description
        self.schema = schema_mod.normalize_tool_schema(schema)
        self.scope = scope
        self.mutating = bool(mutating)
        self.module = getattr(handler, "__module__", "")

    def to_wire(self) -> dict:
        """Вид инструмента в ответе ``tools/list``."""
        item = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema,
        }
        if self.title:
            item["title"] = self.title
        # Подсказки клиенту: read-only инструмент можно звать без
        # подтверждения, мутирующий — спросив пользователя. У мутирующих
        # destructiveHint истинен: по спеке `false` значит «только
        # добавляет», и клиент вправе не спрашивать подтверждения — а
        # среди них перезагрузка, удаление пакета и перезапись файла.
        item["annotations"] = {
            "title": self.title or self.name,
            "readOnlyHint": not self.mutating,
            "destructiveHint": self.mutating,
            "openWorldHint": False,
        }
        meta = {"scope": self.scope or perms_mod.READ_SCOPE,
                "mutating": self.mutating}
        item["_meta"] = {"zapret-gui": meta}
        return item


# Реестр: имя → ToolSpec.
_REGISTRY = {}

# Состояние автозагрузки модулей инструментов. Замок — повторно
# входимый: модуль инструмента, обратившийся к реестру на своём импорте,
# не должен запереть сам себя, а ЧУЖОЙ поток обязан дождаться конца
# загрузки, а не получить полреестра («инструмент не найден» на первом
# же запросе, пришедшем одновременно с другим).
_loaded = False
_loading = False
_load_lock = threading.RLock()


# ───────────────────────────── объявление ───────────────────────────

def tool(name, *, scope=_MISSING, mutating=_MISSING, title="",
         description="", schema=None):
    """Декоратор объявления инструмента (эталон — в docstring модуля).

    ``scope`` и ``mutating`` обязательны и указываются явно: инструмент,
    у которого забыли ``scope``, стал бы доступен всем без разрешения, а
    забытый ``mutating`` уехал бы клиенту с пометкой «только чтение».
    """
    def decorator(handler):
        if scope is _MISSING:
            raise ToolError(
                "инструмент %r: не объявлен scope (одно из: %s)"
                % (name, ", ".join(perms_mod.SCOPES)))
        if mutating is _MISSING:
            raise ToolError("инструмент %r: не объявлен mutating "
                            "(True/False)" % name)
        register_tool(name, handler, description=description, title=title,
                      schema=schema, scope=scope, mutating=mutating)
        return handler
    return decorator


def register_tool(name, handler, *, description, title="", schema=None,
                  scope=None, mutating=False):
    """Зарегистрировать инструмент (низкий уровень, зовётся из ``tool``).

    Все проверки объявления — здесь: декоратор добавляет к ним только
    обязательность ``scope``/``mutating``.
    """
    _check_declaration(name, description, scope, mutating, schema)
    if name in _REGISTRY:
        raise ToolError("инструмент %r уже зарегистрирован (в %s)"
                        % (name, _REGISTRY[name].module or "?"))
    if scope == perms_mod.READ_SCOPE:
        scope = None                      # чтение хранится как «нет scope»
    _REGISTRY[name] = ToolSpec(name, handler, title, description,
                               schema or {}, scope, mutating)
    return _REGISTRY[name]


def _check_declaration(name, description, scope, mutating, schema):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ToolError("имя инструмента %r должно быть snake_case: "
                        "<домен>_<действие>" % (name,))
    if not isinstance(description, str) or not description.strip():
        raise ToolError("инструмент %r: пустое описание — его читает "
                        "модель" % name)
    if len(description) > MAX_DESCRIPTION:
        raise ToolError("инструмент %r: описание %d символов, максимум %d "
                        "(оно уезжает в каждый tools/list)"
                        % (name, len(description), MAX_DESCRIPTION))
    if scope is not None and scope not in perms_mod.SCOPES:
        raise ToolError("инструмент %r: неизвестный scope %r (допустимы: "
                        "%s)" % (name, scope, ", ".join(perms_mod.SCOPES)))
    if not isinstance(mutating, bool):
        raise ToolError("инструмент %r: mutating должен быть bool" % name)
    if mutating and (scope is None or scope == perms_mod.READ_SCOPE):
        raise ToolError("инструмент %r: mutating=True при scope чтения — "
                        "он был бы доступен без разрешения" % name)
    _check_schema(name, schema, "inputSchema")


def _check_schema(name, node, where):
    """Проверить схему инструмента по тем же правилам, что валидатор.

    Схема пишется руками и уезжает модели: опечатка в ``type``
    («str» вместо «string») не сломает ничего в рантайме — валидатор
    просто не проверит поле, и мусор доедет до движка.
    """
    if node is None:
        return
    if not isinstance(node, dict):
        raise ToolError("инструмент %r: %s должен быть объектом" %
                        (name, where))
    types = node.get("type")
    wanted = [types] if isinstance(types, str) else list(types or ())
    for item in wanted:
        if item not in schema_mod.KNOWN_TYPES:
            raise ToolError("инструмент %r: %s — неизвестный тип %r "
                            "(допустимы: %s)"
                            % (name, where, item,
                               ", ".join(sorted(schema_mod.KNOWN_TYPES))))
    props = node.get("properties")
    if props is not None:
        if not isinstance(props, dict):
            raise ToolError("инструмент %r: %s.properties должен быть "
                            "объектом" % (name, where))
        for key, sub in props.items():
            _check_schema(name, sub, "%s.%s" % (where, key))
    required = node.get("required")
    if required is not None:
        if not isinstance(required, list):
            raise ToolError("инструмент %r: %s.required должен быть "
                            "списком" % (name, where))
        known = props if isinstance(props, dict) else {}
        for key in required:
            if key not in known:
                raise ToolError("инструмент %r: %s.required называет %r, "
                                "которого нет в properties"
                                % (name, where, key))
    items = node.get("items")
    if items is not None:
        _check_schema(name, items, "%s.items" % where)


# ────────────────────────── чтение реестра ──────────────────────────

def load_tools(force: bool = False):
    """Импортировать модули ``core/mcp/tools/*`` (идемпотентно).

    Зовётся лениво — из любой функции, читающей реестр. Явно нужна
    только тестам и CLI, которым реестр нужен без вызова методов MCP.
    """
    global _loaded, _loading
    if _loaded and not force:
        return
    with _load_lock:
        if (_loaded and not force) or _loading:
            return
        _loading = True
        try:
            if force:
                # Модуль, положенный в пакет уже после старта процесса,
                # иначе не виден: список каталога у импортёра закеширован.
                importlib.invalidate_caches()
            package = importlib.import_module("core.mcp.tools")
            for info in sorted(pkgutil.iter_modules(package.__path__),
                               key=lambda m: m.name):
                if info.name.startswith("_"):
                    continue
                importlib.import_module("core.mcp.tools.%s" % info.name)
            _loaded = True
        finally:
            _loading = False


def get_tool(name):
    """``ToolSpec`` по имени или ``None``."""
    load_tools()
    return _REGISTRY.get(name)


def all_tools() -> list:
    """Все объявленные инструменты, по имени."""
    load_tools()
    return sorted(_REGISTRY.values(), key=lambda spec: spec.name)


def available_tools(perms=None) -> list:
    """Инструменты, доступные при данных разрешениях."""
    perms = perms if isinstance(perms, dict) else perms_mod.current()
    return [spec for spec in all_tools() if scope_allowed(spec, perms)]


def scope_allowed(spec: ToolSpec, perms: dict) -> bool:
    """Открыт ли ``scope`` инструмента текущими разрешениями."""
    return perms_mod.allowed(spec.scope, perms)


def list_tools(perms=None) -> list:
    """Разрешённые инструменты в виде, готовом для ``tools/list``."""
    return [spec.to_wire() for spec in available_tools(perms)]


def scope_counts(perms=None) -> dict:
    """Сколько инструментов доступно по каждому scope.

    Число инструментов — контракт с UI (S15 его показывает) и со
    сторожем ``tests/test_mcp_tool_counts.py``.
    """
    counts = {}
    for spec in available_tools(perms):
        key = spec.scope or perms_mod.READ_SCOPE
        counts[key] = counts.get(key, 0) + 1
    return counts


# ─────────────────────────────── вызов ──────────────────────────────

def call(name, args=None, perms=None, ctx=None) -> dict:
    """Вызвать инструмент и вернуть готовый результат ``tools/call``.

    Порядок: разрешение → валидация аргументов → вызов → редактирование
    секретов → обрезка. Ошибка исполнения — это **результат** с
    ``isError: true``, а не ошибка JSON-RPC: модель должна её прочитать
    и исправиться.

    Каждый вызов — включая отклонённый и упавший — пишется в журнал
    (``core/mcp/audit.py``): там же реестр забирает снимки «до»,
    которые инструмент сделал по дороге, и связывает их с записью.
    ``ctx`` — то, что знает о вызывающем HTTP-слой (адрес, чем
    авторизовался); его отсутствие журналу не мешает.

    Бросает :class:`UnknownTool` (нет такого имени) и
    ``schema.SchemaError`` (аргументы не по схеме) — оба случая про сам
    протокол, и вызывающий превращает их в ``-32602``.
    """
    spec = get_tool(name)
    if spec is None:
        known = ", ".join(t.name for t in available_tools(perms))
        audit.begin(str(name))
        audit.record(name, status=audit.STATUS_UNKNOWN, ok=False,
                     args=args, ctx=ctx,
                     error="инструмента нет в реестре")
        raise UnknownTool("инструмент %s не найден; доступны: %s"
                          % (name, known or "нет"))

    audit.begin(spec.name)
    if not scope_allowed(spec, perms):
        denial = perms_mod.denial(spec.scope, perms)
        audit.record(spec.name, scope=spec.scope, mutating=spec.mutating,
                     args=args, ctx=ctx, status=audit.STATUS_DENIED,
                     ok=False, error=denial.get("error", ""))
        return tool_result(denial, is_error=True)

    args = args if isinstance(args, dict) else {}
    try:
        args = schema_mod.validate(args, spec.schema, "arguments")
    except schema_mod.SchemaError as e:
        audit.record(spec.name, scope=spec.scope, mutating=spec.mutating,
                     args=args, ctx=ctx, status=audit.STATUS_INVALID,
                     ok=False, error=e.message)
        raise

    if args.get(RAW_ARG) is True and not perms_mod.allowed("secrets", perms):
        # Молча замаскировать ответ на явную просьбу «как есть» нельзя:
        # модель запишет полученное обратно и уничтожит настоящий ключ.
        denial = perms_mod.denial("secrets", perms)
        denial["hint"] = ("ответ без маскировки требует разрешения "
                          "«secrets»; без него повторите вызов без "
                          "raw=true — секреты приедут как «***»")
        audit.record(spec.name, scope=spec.scope, mutating=spec.mutating,
                     args=args, ctx=ctx, status=audit.STATUS_DENIED,
                     ok=False, error=denial.get("error", ""))
        return tool_result(denial, is_error=True)

    started = time.time()
    try:
        # Режим «без маскировки» охватывает и обработчик, и сериализацию:
        # часть инструментов (file_read, shell) чистит текст у себя, до
        # `tool_result`, и выключать их надо тем же переключателем.
        with _maybe_raw(args):
            payload = spec.handler(args)
            payload = _finish(payload, started)
            ok = bool(payload.get("ok", True))
            result = tool_result(payload, is_error=not ok)
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug(traceback.format_exc(), source="mcp")
        elapsed = int((time.time() - started) * 1000)
        # Трассировка — на диск, с crash_id: иначе от падения остаётся
        # одна строка без файла и номера, и отчёт об ошибке не говорит,
        # где она (core/mcp/crashes.py).
        crash = crashes.capture(spec.name, e, args=args,
                                handler=spec.handler, elapsed_ms=elapsed)
        crash_id = crash.get("crash_id", "")
        if crash_id:
            audit.note(crash_id=crash_id)
        audit.record(spec.name, scope=spec.scope, mutating=spec.mutating,
                     args=args, ctx=ctx, status=audit.STATUS_ERROR,
                     ok=False, error="%s: %s" % (type(e).__name__, e),
                     elapsed_ms=elapsed)
        failure = {"ok": False,
                   "error": "%s: %s" % (type(e).__name__, e),
                   "tool": spec.name}
        if crash_id:
            failure["crash_id"] = crash_id
            top = (crash.get("frames") or [{}])[-1]
            if top.get("file"):
                failure["where"] = "%s:%s" % (top["file"], top.get("line"))
            failure["hint"] = (
                "это похоже на ошибку в самом GUI, а не в состоянии "
                "устройства: составьте черновик issue — "
                "issue_draft(kind=\"crash\", crash_id=\"%s\")" % crash_id)
        return tool_result(failure, is_error=True)

    audit.record(spec.name, scope=spec.scope, mutating=spec.mutating,
                 args=args, ctx=ctx,
                 status=audit.STATUS_OK if ok else audit.STATUS_ERROR,
                 ok=ok, error="" if ok else str(payload.get("error", "")),
                 elapsed_ms=payload.get("elapsed_ms", 0))
    return result


def _finish(payload, started):
    """Дописать в ответ инструмента общие поля."""
    if not isinstance(payload, dict):
        payload = {"ok": True, "result": payload}
    payload.setdefault("ok", True)
    payload.setdefault("elapsed_ms", int((time.time() - started) * 1000))
    return payload


class _maybe_raw:
    """``redact.unredacted()``, если вызов просил ``raw`` — иначе ничего."""

    __slots__ = ("_inner",)

    def __init__(self, args):
        self._inner = (redact_mod.unredacted()
                       if args.get(RAW_ARG) is True else None)

    def __enter__(self):
        if self._inner is not None:
            self._inner.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._inner is not None:
            self._inner.__exit__(exc_type, exc, tb)
        return False


# ───────────────────────── результат инструмента ────────────────────

def tool_result(payload: dict, is_error: bool = False) -> dict:
    """Собрать ответ ``tools/call`` из словаря инструмента.

    Отдаём и ``structuredContent`` (машинно-читаемо), и тот же JSON
    строкой в ``content[0].text`` — клиенты, не умеющие
    ``structuredContent``, иначе увидят пустой ответ.

    Здесь — единственная точка, где режутся секреты
    (``core/mcp/redact.py``) и где ответ обрезается по
    ``mcp.limits.response_kb``. Порядок важен: сначала маскируем, потом
    считаем размер, иначе лимит считался бы по данным, которых в ответе
    не будет.
    """
    payload = redact_mod.redact(payload)
    text = _dumps(payload)
    limit = _response_limit_bytes()
    if limit and len(text.encode("utf-8")) > limit:
        payload, text = _truncated(payload, limit)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": bool(is_error),
    }


def _truncated(payload: dict, limit: int):
    """Заменить слишком большой ответ на объяснение, а не на обрубок.

    Обрезать JSON посередине нельзя: клиент получит неразбираемую
    строку и не поймёт, что произошло. Честнее отдать валидный объект,
    который прямо говорит «слишком много, сузьте запрос».
    """
    size = len(_dumps(payload).encode("utf-8"))
    keep = {k: v for k, v in payload.items()
            if isinstance(v, (bool, int, float)) or v is None
            or (isinstance(v, str) and len(v) <= TRUNCATED_STR_MAX)}
    dropped = sorted(k for k in payload if k not in keep)
    short = {
        "ok": payload.get("ok", True),
        "truncated": True,
        "size_bytes": size,
        "limit_bytes": limit,
        "hint": "ответ больше лимита mcp.limits.response_kb — сузьте "
                "запрос (фильтр, limit, пагинация)",
    }
    # Короткие скаляры верхнего уровня оставляем: по ним видно, что
    # вообще произошло. Длинные строки — нет (TRUNCATED_STR_MAX), зато
    # называем, какие поля выброшены: модель должна знать, ЧТО сужать.
    if dropped:
        short["dropped_fields"] = dropped[:20]
    for key, value in keep.items():
        if key not in short and len(short) < 24:
            short[key] = value
    return short, _dumps(short)


def _response_limit_bytes() -> int:
    try:
        from core.mcp import auth
        kb = int(auth.settings().get("limits", {}).get("response_kb", 32))
    except Exception:
        kb = 32
    return max(0, kb) * 1024


def _dumps(payload) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=False,
                      default=str)
