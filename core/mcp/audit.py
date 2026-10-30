# core/mcp/audit.py
"""
Журнал вызовов MCP и снимки «до» для отката.

Две задачи, которые нарочно решены в одном модуле: **что модель
сделала** и **как это вернуть назад**. Разводить их по разным файлам
нельзя — снимок без записи в журнале никем не найден, а запись без
снимка не откатывается.

## Где лежит

Рядом с ``settings.json`` (``core/platform_dirs.config_dir()``), а не в
``/tmp``: на роутере ``/tmp`` — это tmpfs, и после перезагрузки там
пусто. А «верни как было» нужно как раз после неудачного эксперимента,
за которым нередко следует ребут.

* ``mcp-audit.jsonl`` — журнал, строка на вызов, ротация по
  ``mcp.audit.keep``;
* ``mcp-undo.json`` — **закреплённые снимки** (последние
  :data:`SNAPSHOT_KEEP`), отдельным файлом. Ротация журнала не может
  унести снимок, нужный ``mcp_undo_last``: это разные файлы, и обрезка
  одного не трогает другой.

Каталога нет — не пишем и не создаём: у работающего GUI он есть всегда
(там лежит его конфиг), а в тестах и на чужой машине писать в
``/opt/etc`` мы не нанимались.

## Форма снимка — обобщённая

``{kind, target, before, after}``, и это не «настройки, оформленные
универсально»: в S7 сюда лягут стратегии и списки, в S12 — файлы
(``file_write``), в S13 правка кода станет ``code_rollback``. Поэтому
модуль **не знает про настройки**: как откатывать конкретный ``kind``,
говорит обработчик, зарегистрированный рядом со своим инструментом
(:func:`register_undo`). Здесь — только хранение и выбор последнего.

## Как это видит инструмент

.. code-block:: python

    before = ...                       # прочитали
    ...                                # применили
    audit.snapshot(audit.KIND_CONFIG, path, before, after)

Всё остальное (запись в журнал, строка в лог-буфер, привязка снимка к
вызову) делает реестр: ``registry.call`` зовёт :func:`begin` перед
обработчиком и :func:`record` после него.

## Что в журнал не попадает

**Токен — никогда**, ни предъявленный, ни настроенный. Аргументы
пишутся **после** ``redact.redact()``, длинные — подрезаются: журнал
читает человек и модель, а не отладчик.

Уровень строки в лог-буфере: отклонённый вызов — ``warning`` (попытка
сделать то, на что прав не давали, должна быть заметна на фоне обычной
работы), упавший — ``error``, мутирующий успешный — ``info``, обычное
чтение — ``debug``.
"""

import json
import os
import threading
import time
import uuid

from core.log_buffer import log
from core.mcp import redact as redact_mod
from core.safe_io import atomic_write_text


# Имена файлов рядом с settings.json.
JOURNAL_NAME = "mcp-audit.jsonl"
SNAPSHOT_NAME = "mcp-undo.json"

# Виды снимков. S6 завёл настройки, S7 — стратегии и списки; следующие
# сессии добавляют свои константы сюда же, чтобы имена не расходились по
# модулям. Обработчик отката объявляет тот, кто снимок делает
# (``register_undo``), — журналу про виды знать незачем.
KIND_CONFIG = "config"
KIND_STRATEGY = "strategy"
KIND_STRATEGY_ACTIVE = "strategy_active"
KIND_HOSTLIST = "hostlist"
KIND_IPSET = "ipset"
KIND_BLOB = "blob"
KIND_LUA = "lua"
KIND_FIREWALL = "firewall"
# S12 — shell и система.
KIND_FILE = "file"
KIND_PACKAGE = "package"
KIND_SERVICE = "service"
# S13 — самоправка кода GUI. ``before``/``after`` здесь короткие
# (список файлов и id снимка): сами файлы лежат в каталоге снимка
# ``code-snapshots/<id>/``, и класть их ещё и в mcp-undo.json значило
# бы хранить исходники дважды. Откат этого вида равен ``code_rollback``.
KIND_CODE = "code"
# S17 — туннели и маршрутизация. ``tunnel_config`` хранит ПРЕЖНИЙ текст
# конфига целиком (конфиг sing-box на полсотни outbound'ов — десятки
# килобайт, и это тот предел, ради которого стоит держать снимок);
# ``unified_route`` — прежнюю запись маршрута, а ``None`` в ``before``
# означает, что маршрута не было и откат его удалит.
KIND_TUNNEL_CONFIG = "tunnel_config"
KIND_UNIFIED_ROUTE = "unified_route"
# geneva_c: ``geneva_strategy`` — прежняя рабочая стратегия geneva
# (откат вернёт её и в живой движок); ``bypass_engine`` — прежний
# активный движок обхода (откат переключит обратно).
KIND_GENEVA_STRATEGY = "geneva_strategy"
KIND_BYPASS_ENGINE = "bypass_engine"

# Ротация журнала: сколько записей хранить, если mcp.audit.keep не
# прочитался или задан бессмысленно.
DEFAULT_KEEP = 500
MIN_KEEP = 20
MAX_KEEP = 10000

# Сколько снимков держим закреплёнными. Больше одного — чтобы откатить
# серию правок подряд; сильно больше нельзя: файл переписывается
# целиком на каждую мутацию.
SNAPSHOT_KEEP = 20

# Через сколько добавленных строк проверять длину журнала. Считать
# строки на каждой записи — это чтение всего файла на каждый вызов
# инструмента; на роутере это заметно.
ROTATE_CHECK_EVERY = 50

# Сколько байт журнала читаем с конца. Файл ограничен ротацией, но
# ротацию могли выключить руками, а память на роутере не резиновая.
MAX_READ_BYTES = 2 * 1024 * 1024

# Насколько подрезаем длинный аргумент в записи журнала.
MAX_ARG_CHARS = 400

# Статусы записи.
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_DENIED = "denied"
STATUS_INVALID = "invalid"
STATUS_UNKNOWN = "unknown"

_lock = threading.RLock()

# Откат — «выбрать последний снимок → откатить → пометить» — идёт под
# своим замком. Без него два одновременных mcp_undo_last (модель плюс
# кнопка на странице MCP) берут ОДИН снимок и откатывают его дважды, а
# следующий по очереди не трогает никто. Замок отдельный от ``_lock``:
# откат бывает долгим (перезапуск движка), и журнал вызовов всё это
# время должен писаться.
_undo_lock = threading.Lock()

# Снимки, сделанные текущим вызовом (у каждого потока свои: сервер
# обслуживает запросы в потоках, и снимок чужого вызова прицепился бы
# к нашей записи).
_local = threading.local()

# Сколько строк дописано с последней проверки ротации. Начинаем с
# порога: состояние файла после рестарта GUI нам неизвестно.
_appends = ROTATE_CHECK_EVERY

# kind → обработчик отката. Регистрируется рядом с инструментом.
_UNDO_HANDLERS = {}


# ──────────────────────────── настройки ─────────────────────────────

def settings() -> dict:
    """Секция ``mcp.audit`` поверх дефолтов."""
    try:
        from core.mcp import auth
        section = auth.settings().get("audit", {})
    except Exception:                           # noqa: BLE001 — граница
        section = {}
    return section if isinstance(section, dict) else {}


def is_enabled() -> bool:
    """Ведём ли журнал и снимки.

    Выключенный журнал означает и выключенный откат: снимки живут в нём
    же. ``mcp_undo_last`` в этом случае честно говорит, чего не хватает,
    а не молчит.
    """
    return bool(settings().get("enabled", True))


def keep() -> int:
    """Сколько записей журнала хранить (``mcp.audit.keep``)."""
    try:
        value = int(settings().get("keep", DEFAULT_KEEP))
    except (TypeError, ValueError):
        value = DEFAULT_KEEP
    return max(MIN_KEEP, min(value, MAX_KEEP))


def directory() -> str:
    """Каталог, в котором лежат журнал и снимки (рядом с настройками)."""
    from core import platform_dirs
    return platform_dirs.config_dir()


def journal_path() -> str:
    return os.path.join(directory(), JOURNAL_NAME)


def snapshots_path() -> str:
    return os.path.join(directory(), SNAPSHOT_NAME)


# ───────────────────────── снимки для отката ────────────────────────

def begin(tool: str = ""):
    """Начать вызов: забыть снимки предыдущего.

    Зовётся реестром перед обработчиком. Без этого снимок вызова,
    упавшего до записи в журнал, прицепился бы к следующему.
    """
    _local.pending = []
    _local.notes = {}
    _local.tool = tool


def snapshot(kind, target, before, after, detail: str = "",
             tool: str = "") -> dict:
    """Записать снимок «было/стало» и закрепить его для ``mcp_undo_last``.

    Зовёт **инструмент**, уже применивший изменение: только он знает,
    что именно менял и удалось ли. Возвращает короткую ссылку
    (``kind``/``target``/``id``), которую не стыдно положить в ответ
    модели, — сами значения в ответе уже есть.
    """
    if not is_enabled():
        return {}
    entry = {
        "id": uuid.uuid4().hex[:12],
        "ts": round(time.time(), 3),
        "time": _stamp(),
        "tool": tool or getattr(_local, "tool", "") or "",
        "kind": str(kind),
        "target": str(target),
        "before": before,
        "after": after,
        "undone": False,
    }
    if detail:
        entry["detail"] = detail
    _pin(entry)

    ref = {"kind": entry["kind"], "target": entry["target"],
           "id": entry["id"]}
    pending = getattr(_local, "pending", None)
    if pending is None:
        pending = _local.pending = []
    pending.append(ref)
    return dict(ref)


def note(**fields):
    """Прицепить к записи журнала ИТОГ вызова, а не только его аргументы.

    Аргументы говорят, что модель просила; для shell (S12) этого мало:
    журнал обязан отвечать «что получилось» — код возврата и первые
    строки вывода. Поля кладутся в ``result`` записи и проходят ту же
    маскировку, что аргументы.
    """
    current = getattr(_local, "notes", None)
    if current is None:
        current = _local.notes = {}
    current.update(fields)


def take_notes() -> dict:
    """Забрать пометки текущего вызова (и очистить их)."""
    notes = getattr(_local, "notes", None) or {}
    _local.notes = {}
    return dict(notes)


def take_pending() -> list:
    """Забрать снимки текущего вызова (и очистить их)."""
    pending = getattr(_local, "pending", None) or []
    _local.pending = []
    return list(pending)


def register_undo(kind, handler):
    """Объявить, как откатывается снимок вида ``kind``.

    ``handler(snapshot) -> dict``: ``{"ok": bool, ...}``. Регистрация
    живёт рядом с инструментом, который снимок делает, — журналу про
    настройки, файлы и код знать незачем.
    """
    _UNDO_HANDLERS[str(kind)] = handler


def undo_kinds() -> list:
    """Виды снимков, которые умеем откатывать прямо сейчас."""
    _load_tools()
    return sorted(_UNDO_HANDLERS)


def snapshots(include_undone: bool = False) -> list:
    """Закреплённые снимки, новые первыми."""
    entries = _read_snapshots()
    entries.reverse()
    if include_undone:
        return entries
    return [e for e in entries if not e.get("undone")]


def last_snapshot(kind: str = ""):
    """Последний неоткаченный снимок (при желании — заданного вида)."""
    for entry in snapshots():
        if not kind or entry.get("kind") == kind:
            return entry
    return None


def undo_last(kind: str = "") -> dict:
    """Откатить последний мутирующий вызов по его снимку.

    Работает **и после перезапуска GUI**: снимки лежат на диске, а не в
    памяти процесса. Это главное отличие от журнала «в оперативке»:
    роутер перезагружается чаще, чем заканчивается сеанс модели.
    """
    if not is_enabled():
        return {
            "ok": True, "reverted": False,
            "reason": "журнал MCP выключен (mcp.audit.enabled=false) — "
                      "снимков нет",
            "hint": "включите mcp.audit.enabled, чтобы изменения можно "
                    "было откатывать",
        }

    _load_tools()
    with _undo_lock:
        return _undo_last_locked(kind)


def _undo_last_locked(kind: str) -> dict:
    entry = last_snapshot(kind)
    if entry is None:
        return {
            "ok": True, "reverted": False,
            "reason": ("откатывать нечего: неоткаченных снимков вида «%s» "
                       "нет" % kind) if kind else
                      "откатывать нечего: неоткаченных снимков нет",
            "kinds": undo_kinds(),
            "hint": "снимок появляется после мутирующего вызова; что уже "
                    "делалось — покажет audit_list",
        }

    handler = _UNDO_HANDLERS.get(entry.get("kind"))
    if handler is None:
        return {
            "ok": False,
            "error": "снимок вида «%s» откатывать нечем" % entry.get("kind"),
            "kind": entry.get("kind"), "target": entry.get("target"),
            "kinds": undo_kinds(),
            "hint": "этот вид снимка делает инструмент, обработчик отката "
                    "которого не зарегистрирован — сообщите об этом в "
                    "issue",
        }

    try:
        outcome = handler(dict(entry))
    except Exception as e:                      # noqa: BLE001 — граница
        return {
            "ok": False,
            "error": "откат %s не удался: %s: %s"
                     % (entry.get("target"), type(e).__name__, e),
            "kind": entry.get("kind"), "target": entry.get("target"),
        }

    outcome = outcome if isinstance(outcome, dict) else {}
    result = {
        "ok": bool(outcome.get("ok", True)),
        "reverted": bool(outcome.get("ok", True)),
        "kind": entry.get("kind"),
        "target": entry.get("target"),
        "tool": entry.get("tool", ""),
        "snapshot_id": entry.get("id"),
        "made_at": entry.get("time", ""),
        "restored": entry.get("before"),
        "was": entry.get("after"),
    }
    for key, value in outcome.items():
        if key != "ok":
            result[key] = value
    if result["reverted"]:
        mark_undone(entry.get("id"))
        result.setdefault(
            "hint", "вернули прежнее значение «%s»; следующий вызов "
                    "откатит предыдущее изменение, если оно есть"
                    % entry.get("target"))
    return result


def mark_undone(snapshot_id) -> bool:
    """Пометить снимок откаченным (второй ``undo`` его не повторит)."""
    with _lock:
        entries = _read_snapshots()
        found = False
        for entry in entries:
            if entry.get("id") == snapshot_id:
                entry["undone"] = True
                entry["undone_ts"] = round(time.time(), 3)
                found = True
        if found:
            _write_snapshots(entries)
        return found


# ──────────────────────────── запись вызова ─────────────────────────

def record(tool, *, scope="", mutating=False, args=None, status=STATUS_OK,
           ok=True, error="", elapsed_ms=0, ctx=None) -> dict:
    """Записать вызов в журнал и в лог-буфер.

    Зовётся реестром на **каждый** ``tools/call`` — включая отклонённые
    и упавшие: журнал, в котором видны только удачные вызовы, отвечает
    на вопрос «что сломалось» хуже, чем его отсутствие.
    """
    ctx = ctx if isinstance(ctx, dict) else {}
    entry = {
        "ts": round(time.time(), 3),
        "time": _stamp(),
        "tool": str(tool),
        "scope": scope or "read",
        "mutating": bool(mutating),
        "status": str(status),
        "ok": bool(ok),
        "elapsed_ms": _as_int(elapsed_ms),
        "args": _safe_args(args),
    }
    subject = str(ctx.get("subject") or "")
    if subject:
        entry["subject"] = subject
    remote = str(ctx.get("remote_addr") or ctx.get("remote") or "")
    if remote:
        entry["remote"] = remote
    if error:
        entry["error"] = redact_mod.redact_text(str(error),
                                            force=True)[:500]

    undo = take_pending()
    if undo:
        entry["undo"] = undo
    notes = _safe_args(take_notes())
    if notes:
        entry["result"] = notes

    _log_entry(entry)
    if is_enabled():
        _append(entry)
    return entry


# ──────────────────────────── чтение журнала ────────────────────────

def read_records(limit: int = 0) -> tuple:
    """Записи журнала, **новые первыми**, и сводка о чтении.

    Битая строка (роутер выключили розеткой посреди записи) — не повод
    падать: она пропускается и попадает в счётчик ``skipped_lines``.
    """
    path = journal_path()
    stats = {"path": path, "exists": os.path.exists(path),
             "skipped_lines": 0, "enabled": is_enabled()}
    if not stats["exists"]:
        return [], stats

    records = []
    for line in _tail_lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            stats["skipped_lines"] += 1
            continue
        if isinstance(item, dict):
            records.append(item)
        else:
            stats["skipped_lines"] += 1

    records.reverse()
    if limit and limit > 0:
        records = records[:limit]
    return records, stats


def snapshot_index() -> dict:
    """``id`` → закреплённый снимок: что ещё можно откатить."""
    return {e.get("id"): e for e in _read_snapshots() if e.get("id")}


# ───────────────────────────── частности ────────────────────────────

def _load_tools():
    """Подгрузить инструменты: с ними приезжают обработчики отката."""
    try:
        from core.mcp import registry
        registry.load_tools()
    except Exception:                           # noqa: BLE001 — граница
        pass


def _as_int(value) -> int:
    """Число из чужого поля: журнал не место, где стоит падать."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _safe_args(args) -> dict:
    """Аргументы для журнала: сначала маскировка, потом подрезка.

    Маскировка двойная. ``redact.redact`` смотрит на **имя** ключа, а
    имена аргументов у нас рабочие (``path``, ``value``, ``search``), и
    секрет внутри строки под таким именем прошёл бы насквозь. Журнал
    лежит на диске и переживает вызов — поэтому строки дополнительно
    чистятся по маркерам (``token=``, ``Authorization:``).

    ``force=True`` везде: вызов мог быть сделан в режиме «без
    маскировки» (S17, разрешение ``secrets``), и тогда ответ уезжает
    модели как есть — но журнал остаётся на диске, и секрет в нём
    переживёт и вызов, и разрешение.
    """
    if not isinstance(args, dict) or not args:
        return {}
    clean = redact_mod.redact(args, force=True)
    out = {}
    for key, value in clean.items():
        if isinstance(value, str):
            value = redact_mod.redact_text(value, force=True)
        if isinstance(value, str) and len(value) > MAX_ARG_CHARS:
            out[key] = value[:MAX_ARG_CHARS] + "…"
        elif isinstance(value, (dict, list)):
            text = redact_mod.redact_text(
                json.dumps(value, ensure_ascii=False, default=str),
                force=True)
            if len(text) > MAX_ARG_CHARS:
                out[key] = text[:MAX_ARG_CHARS] + "…"
            else:
                try:
                    out[key] = json.loads(text)
                except ValueError:
                    # Чистка испортила JSON — кладём текстом: журнал не
                    # то место, ради которого стоит рисковать записью.
                    out[key] = text
        else:
            out[key] = value
    return out


def _log_entry(entry: dict):
    """Строка в лог-буфер: уровень зависит от того, чем кончился вызов."""
    status = entry.get("status")
    message = "MCP: %s → %s за %s мс" % (entry.get("tool"), status,
                                         entry.get("elapsed_ms"))
    if entry.get("error"):
        message += " (%s)" % entry["error"][:200]
    try:
        if status in (STATUS_DENIED, STATUS_INVALID, STATUS_UNKNOWN):
            log.warning(message, source="mcp")
        elif status == STATUS_ERROR:
            log.error(message, source="mcp")
        elif entry.get("mutating"):
            log.info(message, source="mcp")
        else:
            log.debug(message, source="mcp")
    except Exception:                           # noqa: BLE001 — граница
        pass


def _append(entry: dict):
    """Дописать строку в JSONL и, изредка, подрезать журнал.

    Пишем построчно и флашим: роутер выключают розеткой, и потерянный
    хвост — это ровно те вызовы, ради которых журнал заводили.
    """
    global _appends
    path = journal_path()
    with _lock:
        if not os.path.isdir(os.path.dirname(path)):
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False,
                                   default=str) + "\n")
                f.flush()
        except OSError as e:
            log.debug("MCP: не удалось записать журнал: %s" % e,
                      source="mcp")
            return
        _appends += 1
        if _appends >= ROTATE_CHECK_EVERY:
            _appends = 0
            _rotate(path)


def _rotate(path: str):
    """Оставить в журнале последние ``keep`` записей.

    Снимки при этом не страдают: они лежат в другом файле (см. шапку
    модуля), и обрезка журнала не может унести тот, который нужен
    ``mcp_undo_last``.
    """
    limit = keep()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return
    if len(lines) <= limit:
        return
    try:
        atomic_write_text(path, "".join(lines[-limit:]))
    except OSError as e:
        log.debug("MCP: не удалось подрезать журнал: %s" % e, source="mcp")


def _tail_lines(path: str) -> list:
    """Последние строки файла, не читая его целиком."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > MAX_READ_BYTES:
                f.seek(size - MAX_READ_BYTES)
                f.readline()            # первая строка обрезана — выкинуть
            data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def _read_snapshots() -> list:
    """Закреплённые снимки, старые первыми (как лежат в файле)."""
    path = snapshots_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)]


def _write_snapshots(entries: list):
    path = snapshots_path()
    if not os.path.isdir(os.path.dirname(path)):
        return
    payload = {"version": 1, "entries": entries[-SNAPSHOT_KEEP:]}
    try:
        atomic_write_text(path, json.dumps(payload, ensure_ascii=False,
                                           default=str))
    except (OSError, TypeError, ValueError) as e:
        log.debug("MCP: не удалось сохранить снимок: %s" % e, source="mcp")


def _pin(entry: dict):
    """Закрепить снимок: атомарно, чтобы ребут не оставил полфайла."""
    with _lock:
        entries = _read_snapshots()
        entries.append(entry)
        _write_snapshots(entries)
