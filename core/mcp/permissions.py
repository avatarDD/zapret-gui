# core/mcp/permissions.py
"""
Модель разрешений MCP и whitelist настроек, доступных на запись.

Здесь только **модель и проверки**. Саму запись (``config_set``,
аудит, ``mcp_undo_last``) делает S6 — она обязана спрашивать
:func:`is_writable` и ничего не решать сама.

## Разрешения

Двенадцать переключателей в ``settings.json → mcp.permissions``, все
по умолчанию ``False``; чтение доступно всегда и переключателя не
имеет. Инструмент объявляет ``scope``; ``tools/list`` отдаёт только
разрешённые.

Два разрешения не самостоятельны:

* ``experiments`` требует ``control`` и ``probes`` — эксперимент
  применяет стратегию и выпускает трафик; включённый сам по себе, он
  обещает то, чего не может;
* ``self_edit_core`` требует ``self_edit`` — это расширение, а не
  отдельная дверь.

Одно разрешение не открывает НИ ОДНОГО инструмента: ``secrets`` (S17)
снимает маскировку в ответе (``raw: true`` в вызове, см.
:mod:`core.mcp.redact`) и пускает запись в поля, похожие на секрет. Само
по себе оно ничего не читает и не пишет — оно расширяет то, что уже
открыто другими разрешениями, поэтому и в :data:`WRITE_PERMISSIONS` его
нет: с одним ``secrets`` менять нечего, а значит и откатывать нечего.

Невыполненная зависимость **не игнорируется молча**: :func:`denial`
возвращает причину и список того, что нужно включить, — иначе
пользователь видит выключенный инструмент при включённом разрешении и
идёт чинить то, что не сломано.

## Граница записи

Проходит по **обратимости, а не по чувствительности** (контракт §4).
Неверное значение внутри стратегии ломает часть сайтов — это видно и
откатывается одним вызовом. Неверный порт GUI, бэкенд firewall или
desync-метка оставляют роутер недоступным, и отменить изменение уже
нечем.

Поэтому:

* писать можно только в перечисленные поддеревья
  (:data:`WRITABLE_SECTIONS`) и только в **листья** — секцию целиком
  подменить нельзя;
* **запреты сильнее разрешений** (:data:`DENY_PATHS`,
  :func:`_is_denied_key`): расположения файлов и каталогов, метки
  десинка, номер очереди и всё, что похоже на секрет, не принимаются
  даже внутри разрешённого поддерева. Отклоняем **расположение**, но не
  содержимое: сами списки и lua модель правит через ``strategies_write``.

Единственное послабление — разрешение ``secrets`` (S17): с ним
снимается запрет на **секретные** листья (``is_writable(path,
secrets=True)``). Запрет на расположения файлов не снимается ничем:
неверный путь не ломает GUI громко, а тихо выключает часть логики, и к
секретам это отношения не имеет.

Неверный путь не «ломает громко»: GUI продолжает работать, просто часть
логики тихо выключается — поэтому пути и не отдаются на запись.
"""

import re

from core.mcp import redact


# Отличаем «ключа нет» от «дефолт равен None».
_MISSING = object()


# Порядок — как в docs/mcp/00-contract.md §4.
# ``secrets`` заведён позже остальных (S17) и стоит последним: порядок
# §4 контракта — это порядок, в котором разрешения объясняются человеку,
# и переставлять его ради алфавита значит ломать README и страницу MCP.
PERMISSIONS = (
    "control", "strategies_write", "config_write", "probes", "experiments",
    "tunnels_write", "dangerous", "shell_readonly", "shell_full",
    "self_edit", "self_edit_core", "secrets",
)

# Scope инструмента, доступного всегда (чтение).
READ_SCOPE = "read"

# Псевдо-scope «любое разрешение на запись». Нужен ровно одному
# инструменту — ``mcp_undo_last``. Снимки бывают любого вида: настройки
# (S6), стратегии и списки (S7), файлы (S12), код (S13). Прибить откат к
# одному разрешению значит выдать модели право менять, не выдав права
# вернуть, — прямое нарушение инварианта §5.4 контракта: с
# ``strategies_write`` без ``config_write`` стратегия сохранялась бы без
# пути назад. Обратное — «откат виден, менять нечем» — безвредно, но и
# оно исключено: без единого write-разрешения инструмент не публикуется.
ANY_WRITE_SCOPE = "any_write"

# Разрешения, каждое из которых означает «эта модель что-то меняет».
# ``probes`` сюда не входит: проба выпускает трафик, но снимка не
# оставляет и откатывать в ней нечего. ``secrets`` — тоже: он ничего не
# меняет сам, а только снимает маску с ответа и запрет с секретных
# листьев настроек, которые всё равно пишет ``config_write``.
WRITE_PERMISSIONS = (
    "control", "strategies_write", "config_write", "experiments",
    "tunnels_write", "dangerous", "shell_full", "self_edit",
    "self_edit_core",
)

# Все допустимые значения ``scope`` в объявлении инструмента.
SCOPES = (READ_SCOPE, ANY_WRITE_SCOPE) + PERMISSIONS

# Разрешение → что обязано быть включено вместе с ним.
REQUIRES = {
    "experiments": ("control", "probes"),
    "self_edit_core": ("self_edit",),
}

# Разрешение → что оно открывает ЗАОДНО (S12). Обратная сторона
# ``REQUIRES``: кому отдали произвольную команду от root, тому
# безопасные команды уже отданы. Без этого ``shell_full`` без
# ``shell_readonly`` выглядел бы включённым, а половина shell-
# инструментов (чтение файлов, список пакетов, статус служб) оставалась
# бы невидимой — и это читалось бы как поломка, а не как настройка.
IMPLIES = {
    "shell_full": ("shell_readonly",),
}

# Короткое описание для UI и для текста отказа.
TITLES = {
    "control": "управление движками (старт/стоп/перезапуск, применение "
               "стратегий)",
    "strategies_write": "правка стратегий, hostlist'ов, ipset'ов, lua",
    "config_write": "запись настроек в разрешённые поддеревья",
    "probes": "активные пробы: трафик с роутера, blockcheck, сканер",
    "experiments": "движок экспериментов со стратегиями",
    "tunnels_write": "конфиги и запуск туннелей (sing-box, mihomo, AWG, "
                     "usque, tgproxy, opera)",
    "dangerous": "бинарники, автозапуск, миграции, правила единого слоя, "
                 "перезагрузка",
    "shell_readonly": "безопасные команды, чтение файлов и каталогов",
    "shell_full": "произвольная команда от root, запись файлов, пакеты, "
                  "службы — по всей системе",
    "self_edit": "чтение и правка файлов GUI на устройстве (только "
                 "каталог установки, с проверками и авто-откатом)",
    "self_edit_core": "правка защищённого ядра GUI",
    "secrets": "полные ответы без маскировки (raw) и запись полей, "
               "похожих на секрет",
}

# ─────────────────────── настройки на запись ────────────────────────

# Поддеревья settings.json, открытые для config_set (S6).
#
# ``logging`` здесь не для удобства: без него модель не может поднять
# уровень лога, воспроизвести проблему и прочитать результат — то есть
# не может отладить ничего.
WRITABLE_SECTIONS = (
    "nfqws", "filter", "strategy", "blockcheck", "healthcheck", "scan",
    "block_detector", "dns_routing", "logging",
)

# Точечные запреты внутри разрешённых поддеревьев.
DENY_PATHS = frozenset((
    # На них держится перехват и собственный трафик GUI.
    "nfqws.queue_num",
    "nfqws.user",
    # Очередь песочницы сканера — та же природа, что у queue_num.
    "scan.sandbox_queue_num",
))

# Запрет по префиксу: nfqws.desync_mark, nfqws.desync_mark_postnat.
DENY_PATH_PREFIXES = ("nfqws.desync_mark",)

# Ключи-расположения: путь, каталог, бинарник. Неверный путь не роняет
# GUI с ошибкой — он тихо выключает часть логики, и понять это снаружи
# нельзя.
DENY_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:path|paths|dir|dirs|file|files|binary|bin|exe|"
    r"workdir|root)$")

# Поля с заданным набором значений. Держим руками: источник — те же
# списки, что в web/js/pages/settings.js. Расхождение здесь не опасно
# (значение всё равно проверит менеджер), но подсказка модели врать не
# должна.
ENUMS = {
    "filter.mode": ["none", "autohostlist", "ipset", "hostlist"],
    "logging.level": ["DEBUG", "INFO", "WARNING", "ERROR"],
    "logging.persist_min_level": ["WARNING", "ERROR"],
    "blockcheck.default_mode": ["quick", "full"],
    "scan.default_mode": ["quick", "full"],
    "scan.default_protocol": ["tcp", "udp"],
    "block_detector.dns_source": ["auto", "dnsmasq_log", "adguard_log",
                                  "af_packet"],
    "nfqws.fastpath_workaround": ["auto", "1", "0"],
    "scan.isolated": ["auto", "off"],
}


# ──────────────────────────── разрешения ────────────────────────────

def current() -> dict:
    """Разрешения из конфига, все ключи, значения — ``bool``."""
    from core.mcp import auth
    return normalize(auth.permissions())


def normalize(perms=None) -> dict:
    """Привести карту разрешений к полному виду.

    Отсутствующий ключ — это ``False``: новая настройка не становится
    доступной на запись сама по себе (инвариант §5.1).
    """
    given = perms if isinstance(perms, dict) else {}
    return {name: bool(given.get(name)) for name in PERMISSIONS}


def effective(perms=None) -> dict:
    """Разрешения с учётом зависимостей и того, что они открывают заодно.

    ``experiments`` без ``control``/``probes`` выключен, как бы ни
    стоял его собственный флаг; ``shell_full``, наоборот, включает
    ``shell_readonly`` — он его надмножество.

    Порядок важен: сначала гасим невыполненные зависимости, потом
    раздаём вложенные разрешения. Иначе снятое зависимостью
    разрешение успело бы открыть своё вложенное.
    """
    granted = normalize(perms)
    out = dict(granted)
    for name, needed in REQUIRES.items():
        if out.get(name) and not all(granted.get(dep) for dep in needed):
            out[name] = False
    for name, opened in IMPLIES.items():
        if out.get(name):
            for dep in opened:
                out[dep] = True
    return out


def implied_by(name: str, perms=None) -> list:
    """Какие включённые разрешения открывают ``name`` сами по себе."""
    granted = normalize(perms)
    return [owner for owner, opened in IMPLIES.items()
            if name in opened and granted.get(owner) and not granted.get(name)]


def unmet(name: str, perms=None) -> list:
    """Какие зависимости разрешения ``name`` не включены."""
    granted = normalize(perms)
    return [dep for dep in REQUIRES.get(name, ())
            if not granted.get(dep)]


def allowed(scope, perms=None) -> bool:
    """Открыт ли ``scope`` текущими разрешениями.

    ``None``/``"read"`` — чтение, доступно всегда.
    """
    if not scope or scope == READ_SCOPE:
        return True
    granted_map = effective(perms)
    if scope == ANY_WRITE_SCOPE:
        return any(granted_map.get(name) for name in WRITE_PERMISSIONS)
    return bool(granted_map.get(scope))


def granted(name: str) -> bool:
    """Включено ли разрешение ПРЯМО СЕЙЧАС, с учётом зависимостей.

    Нужно инструментам, у которых часть действий читает, а часть
    выпускает трафик (``diagnostics_run``, ``updates_check``, дальше —
    healthcheck): они публикуются всегда, а спрашивают разрешение по
    месту, за конкретное действие. ``allowed()`` для этого не годится
    напрямую — без явных ``perms`` она видит пустую карту, то есть
    «ничего не разрешено».
    """
    return allowed(name, current())


def denial(scope, perms=None) -> dict:
    """Готовый ответ инструмента, которому не хватило разрешения.

    Текст читает модель: он обязан называть, что именно включить, —
    иначе она пробует ещё раз то же самое.
    """
    granted = normalize(perms)
    if scope == ANY_WRITE_SCOPE:
        return {
            "ok": False,
            "error": "нет ни одного разрешения на запись",
            "permission": ANY_WRITE_SCOPE,
            "requires": list(WRITE_PERMISSIONS),
            "missing": list(WRITE_PERMISSIONS),
            "hint": "откатывать нечего: включите любое из разрешений на "
                    "изменение (%s) в настройках MCP"
                    % ", ".join(WRITE_PERMISSIONS),
        }
    missing = unmet(scope, granted)
    if granted.get(scope) and missing:
        # Флаг стоит, но зависимость не выполнена — самый непонятный
        # случай, и молчать о нём нельзя.
        hint = ("разрешение «%s» включено, но требует ещё: %s — включите "
                "их в настройках MCP" % (scope, ", ".join(missing)))
        error = "разрешение %s не действует без %s" % (scope,
                                                       ", ".join(missing))
    else:
        hint = "включите разрешение «%s» в настройках MCP" % scope
        error = "нет разрешения %s" % scope
        if missing:
            hint += " (вместе с ним: %s)" % ", ".join(missing)
    return {
        "ok": False,
        "error": error,
        "permission": scope,
        "requires": list(REQUIRES.get(scope, ())),
        "missing": missing,
        "hint": hint,
    }


def describe(perms=None) -> list:
    """Таблица разрешений для UI и для ``/api/mcp/info``."""
    granted = normalize(perms)
    active = effective(granted)
    out = []
    for name in PERMISSIONS:
        item = {
            "key": name,
            "title": TITLES.get(name, ""),
            "granted": granted[name],
            "effective": active[name],
            "requires": list(REQUIRES.get(name, ())),
            "missing": unmet(name, granted) if granted[name] else [],
        }
        opens = IMPLIES.get(name)
        if opens:
            item["opens"] = list(opens)
        owners = implied_by(name, granted)
        if owners:
            # Галочка снята, а инструменты доступны — UI обязан это
            # объяснить, иначе выглядит как ошибка интерфейса.
            item["implied_by"] = owners
        out.append(item)
    return out


# ───────────────────── настройки: что можно писать ──────────────────

def is_writable(path, secrets: bool = False) -> bool:
    """Можно ли записать значение по точечному пути ``settings.json``.

    Путь — строка (``"nfqws.ports_tcp"``) или последовательность
    ключей. Секцию целиком (``"nfqws"``) записать нельзя: в ней есть
    запрещённые листья, и запись пачкой обошла бы их проверку.

    ``secrets=True`` (разрешение ``secrets``, S17) снимает запрет на
    листья, похожие на секрет: с ним модель читает такое поле как есть
    (``raw: true``) и может вернуть значение обратно. Всё остальное —
    поддеревья, ``DENY_PATHS`` и ключи-расположения — не меняется.
    """
    parts = split_path(path)
    if len(parts) < 2:
        return False
    if parts[0] not in WRITABLE_SECTIONS:
        return False

    dotted = ".".join(parts)
    if dotted in DENY_PATHS:
        return False
    if any(dotted.startswith(prefix) for prefix in DENY_PATH_PREFIXES):
        return False
    for segment in parts[1:]:
        if _is_denied_key(segment, secrets=secrets):
            return False

    # Настройки, которой нет в DEFAULT_CONFIG, не существует: записать
    # её — значит завести в settings.json ключ, который никто не читает.
    # Отсюда же закрыт путь «a.b.c» с несуществующим промежуточным
    # узлом: снаружи он выглядит как лист внутри разрешённой секции.
    known = _default_at(parts, missing=_MISSING)
    if known is _MISSING:
        return False
    # Существующее поддерево — не лист: писать в него нельзя.
    if isinstance(known, dict):
        return False
    return True


def why_not_writable(path, secrets: bool = False) -> str:
    """Почему путь не принимается на запись — текстом для модели."""
    parts = split_path(path)
    if len(parts) < 2:
        return ("нужен путь вида «секция.ключ»: секцию целиком записать "
                "нельзя")
    if parts[0] not in WRITABLE_SECTIONS:
        return ("секция «%s» закрыта на запись через MCP; открыты: %s"
                % (parts[0], ", ".join(WRITABLE_SECTIONS)))
    dotted = ".".join(parts)
    if dotted in DENY_PATHS or any(dotted.startswith(p)
                                   for p in DENY_PATH_PREFIXES):
        return ("«%s» закрыт: на нём держатся перехват и собственный "
                "трафик GUI" % dotted)
    for segment in parts[1:]:
        if redact.is_secret_key(segment) and not secrets:
            return ("«%s» похож на секрет и на запись не принимается; "
                    "включите разрешение «secrets», если такое поле "
                    "нужно менять через MCP" % dotted)
        if DENY_KEY_RE.search(segment):
            return ("«%s» задаёт расположение файла или каталога: неверный "
                    "путь не ломает GUI громко, а тихо выключает часть "
                    "логики" % dotted)
    known = _default_at(parts, missing=_MISSING)
    if known is _MISSING:
        return ("такой настройки нет: «%s» не описан в дефолтах GUI — "
                "проверьте путь по config_writable_paths" % dotted)
    if isinstance(known, dict):
        return "«%s» — поддерево, а не значение: укажите конкретный ключ" \
            % dotted
    return ""


def writable_paths(secrets: bool = False) -> list:
    """Все листья настроек, открытые на запись.

    Отдаётся инструменту ``config_writable_paths`` (S6): путь, тип,
    текущее значение и допустимые значения — чтобы модель не угадывала
    формат. ``secrets`` передаётся как в :func:`is_writable`: список
    обязан совпадать с тем, что реально примет ``config_set``, иначе
    модель узнаёт о границе не из справочника, а из отказа.
    """
    from core.config_manager import DEFAULT_CONFIG, get_config_manager

    cfg = get_config_manager()
    out = []
    for section in WRITABLE_SECTIONS:
        defaults = DEFAULT_CONFIG.get(section)
        if not isinstance(defaults, dict):
            continue
        for path, default in sorted(_walk(section, defaults)):
            if not is_writable(path, secrets=secrets):
                continue
            keys = path.split(".")
            value = cfg.get(*keys, default=default)
            item = {
                "path": path,
                "type": _json_type(default if default is not None else value),
                "value": value,
                "default": default,
            }
            if path in ENUMS:
                item["enum"] = list(ENUMS[path])
            out.append(item)
    return out


def non_writable_paths() -> list:
    """Листья настроек, закрытые на запись, — с причиной отказа.

    Нужна сторожу (``tests/test_mcp_writable_paths.py``): каждый ключ
    конфига обязан быть отнесён к одной из двух сторон осознанно, а не
    «не попал в whitelist, и ладно».
    """
    from core.config_manager import DEFAULT_CONFIG

    out = []
    for section in sorted(DEFAULT_CONFIG):
        defaults = DEFAULT_CONFIG.get(section)
        if not isinstance(defaults, dict):
            out.append({"path": section,
                        "reason": "значение верхнего уровня"})
            continue
        for path, _ in sorted(_walk(section, defaults)):
            if is_writable(path):
                continue
            out.append({"path": path, "reason": why_not_writable(path)})
    return out


def split_path(path) -> list:
    """Разобрать точечный путь в список ключей."""
    if isinstance(path, str):
        return [p for p in path.split(".") if p]
    if isinstance(path, (list, tuple)):
        return [str(p) for p in path if str(p)]
    return []


# ───────────────────────────── частности ────────────────────────────

def _is_denied_key(segment: str, secrets: bool = False) -> bool:
    if DENY_KEY_RE.search(segment):
        # Расположение файла не отдаётся на запись никогда: к секретам
        # оно отношения не имеет, а неверный путь выключает логику тихо.
        return True
    return redact.is_secret_key(segment) and not secrets


def _default_at(parts, missing=None):
    """Значение по пути в ``DEFAULT_CONFIG``.

    ``missing`` отличает «дефолт равен None» от «такого ключа нет»:
    первое — законная настройка, второе — выдуманный путь.
    """
    from core.config_manager import DEFAULT_CONFIG

    node = DEFAULT_CONFIG
    for key in parts:
        if not isinstance(node, dict) or key not in node:
            return missing
        node = node[key]
    return node


def _walk(prefix: str, node: dict):
    """Пары (точечный путь, значение) по всем листьям поддерева."""
    for key, value in node.items():
        path = "%s.%s" % (prefix, key)
        if isinstance(value, dict) and value:
            for item in _walk(path, value):
                yield item
        else:
            yield path, value


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
