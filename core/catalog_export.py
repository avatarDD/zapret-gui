# core/catalog_export.py
"""
Обратная дорога: найденная стратегия → секция каталога ``catalogs/*.txt``.

## Зачем

Каталоги приезжают к нам сверху — из сборки GUI. А находки появляются
снизу: сканер подобрал, эксперимент подтвердил, человек допилил руками.
До сих пор такая находка оставалась на устройстве USER-стратегией
(JSON), и путь «поделиться ею с сообществом» выглядел как «открой INI,
разберись в формате, перепечатай argv руками». Ровно поэтому им никто
не пользовался.

Здесь этот путь становится одним вызовом: на входе argv (или id
стратегии), на выходе — **готовая секция INI**, которую можно вставить
в `catalogs/<уровень>/<протокол>.txt` и отправить pull request'ом.

## Что здесь есть и чего нет

Есть: разбор argv, выбор уровня и протокола по его содержимому,
экранирование метаданных, сборка текста и **проверка round-trip** —
собранная секция тут же читается нашим же парсером
(``core/catalog_loader``), и если argv не совпал дословно, экспорт
честно отвечает отказом. Экспорт, который не читается нашим же
загрузчиком, — это не экспорт.

Нет: **записи в файл**. `catalogs/` — часть поставки GUI, её
перезаписывает установщик (`core/asset_importer.py`), и класть туда
локальные правки значит терять их при первом же обновлении. Текст
отдаётся наружу — человеку в буфер обмена, модели в ответ, — а дальше
он едет в git, где ему и место.

## Формат

Разбирается тем же парсером, что и каталоги (см. `catalogs/README.md`):

    [section_id]
    name = Человеческое имя
    author = Кто нашёл
    label = recommended | stable | experimental | game
    description = Одна строка
    blobs = blob1, blob2
    --lua-desync=…
    --lua-desync=…

Два правила формата, которые легко нарушить и трудно заметить:

* **аргумент — это строка, начинающаяся с ``--``.** Любая другая строка
  парсер читает как метаданные (``ключ = значение``) или молча
  выбрасывает. Поэтому argv проверяется, а не «пишется как есть»;
* **метаданные однострочны.** Перевод строки в описании разрежет
  секцию пополам, и вторая половина станет чужими аргументами.
"""

import re


# Метки, которые понимает загрузчик каталогов (``_VALID_LABELS``).
# Держим свой список, а не импортируем приватное имя: связь фиксирует
# тест (`tests/test_catalog_export.py`), а не подчёркивание в чужом
# модуле. Неизвестная метка не ломает загрузку — она просто теряется
# при чтении, и находка уезжает в каталог без пометки.
LABELS = ("recommended", "experimental", "game", "stable", "caution",
          "deprecated")

# Имя секции: то же, что принимает парсер, плюс здравый смысл.
SECTION_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")

# Аргументы WinDivert: в наших каталогах их нет (это Windows-сборка
# winws2), и загрузчик их всё равно выбрасывает.
WINDIVERT_PREFIXES = ("--wf-", "--ssid-", "--wlan-")

# Сколько аргументов принимаем в одной секции. Стратегия длиннее — это
# почти наверняка склеенные argv двух разных.
MAX_ARGS = 120

# Длина метаданных. Каталог читают глазами, а не только парсером.
MAX_META = 200


class ExportError(ValueError):
    """Из этого argv секции не получится — и вот почему."""


# ──────────────────────────── разбор argv ───────────────────────────

def clean_args(args) -> list:
    """Проверить и нормализовать argv под формат каталога.

    Raises:
        ExportError: аргумент не похож на аргумент nfqws2.
    """
    out = []
    for raw in (args or []):
        item = str(raw or "").strip()
        if not item:
            continue
        if "\n" in item or "\r" in item:
            raise ExportError(
                "аргумент содержит перевод строки — в INI это разрежет "
                "секцию пополам: %r" % item[:60])
        if not item.startswith("--"):
            raise ExportError(
                "аргумент не начинается с «--»: %r. В каталоге такая "
                "строка читается как метаданные, а не как аргумент "
                "движка" % item[:60])
        if item.lower().startswith(WINDIVERT_PREFIXES):
            continue                    # Windows-only, загрузчик их режет
        if len(out) >= MAX_ARGS:
            raise ExportError("аргументов больше %d — это похоже на два "
                              "argv, склеенных в один" % MAX_ARGS)
        out.append(item)
    if not out:
        raise ExportError("нечего экспортировать: ни одного аргумента "
                          "nfqws2")
    return out


def guess_protocol(args) -> str:
    """tcp или udp — по фильтрам и приёмам десинка.

    Не «угадать поточнее», а **не соврать**: при смешанном argv
    отвечаем tcp, потому что каталоги udp-уровня собирают ровно
    udp-приёмы, а tcp-файл терпит и то и другое.
    """
    text = "\n".join(args).lower()
    udp = ("--filter-udp" in text or "quic" in text or "stun" in text)
    tcp = ("--filter-tcp" in text or "tls" in text or "http" in text
           or "multisplit" in text or "multidisorder" in text
           or "seqovl" in text or "syndata" in text)
    if udp and not tcp:
        return "udp"
    return "tcp"


def guess_level(args) -> str:
    """direct — один приём, builtin — полная конфигурация.

    Граница ровно та же, что в ``catalogs/README.md``: секция с
    ``--filter-*`` или ``--new`` — это готовая конфигурация целиком,
    остальное — одиночный приём, который сканер подставляет сам.
    """
    text = "\n".join(args).lower()
    if "--new" in text or "--filter-" in text:
        return "builtin"
    return "direct"


def guess_blobs(args) -> list:
    """Имена blob'ов, на которые ссылается argv (``blob=имя``).

    Каталог объявляет их отдельной строкой ``blobs =``: по ней GUI
    понимает, чего не хватает на устройстве, ДО запуска движка.
    """
    found = []
    for item in args:
        for name in re.findall(r"(?:^|[:=,])blob=([A-Za-z0-9_.\-]+)", item):
            if name not in found:
                found.append(name)
        for name in re.findall(r"fake_blob=([A-Za-z0-9_.\-]+)", item):
            if name not in found:
                found.append(name)
    # Шестнадцатеричные константы (`blob=0x00`) — это не файл blob'а, а
    # литерал: объявлять его в `blobs =` значит слать GUI искать файл,
    # которого нет и не должно быть.
    return [name for name in found if not name.lower().startswith("0x")]


def slugify(text: str, fallback: str = "strategy") -> str:
    """Имя секции из человеческого имени: латиница, цифры, подчёркивания."""
    value = (text or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", _translit(value)).strip("_")
    value = re.sub(r"_+", "_", value)[:64]
    return value or fallback


# Транслит нужен ровно затем, чтобы стратегия с русским именем не
# превратилась в секцию `_____`. Таблица короткая и своя: тянуть ради
# неё зависимость на роутер незачем.
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e",
    "ё": "e", "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k",
    "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r",
    "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c",
    "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "",
    "э": "e", "ю": "yu", "я": "ya",
}


def _translit(text: str) -> str:
    return "".join(_TRANSLIT.get(char, char) for char in text)


# ─────────────────────────── сборка секции ──────────────────────────

def render_section(section_id: str, args, name: str = "", author: str = "",
                   label: str = "", description: str = "",
                   blobs=None) -> str:
    """Собрать текст секции INI (без проверки round-trip)."""
    if not SECTION_RE.match(section_id or ""):
        raise ExportError(
            "id секции «%s» не годится: нужны строчные латинские буквы, "
            "цифры и подчёркивания (до 64 символов)" % (section_id or ""))

    lines = ["[%s]" % section_id]
    if name:
        lines.append("name = %s" % _meta(name))
    if author:
        lines.append("author = %s" % _meta(author))
    if label:
        clean = str(label).strip().lower()
        if clean not in LABELS:
            raise ExportError("метка «%s» не из набора каталога: %s"
                              % (label, ", ".join(LABELS)))
        lines.append("label = %s" % clean)
    if description:
        lines.append("description = %s" % _meta(description))
    if blobs:
        lines.append("blobs = %s" % ", ".join(
            _meta(str(b)) for b in blobs if str(b).strip()))
    lines.extend(args)
    return "\n".join(lines) + "\n"


def _meta(value: str) -> str:
    """Однострочное значение метаданных: без переводов строки и решёток.

    Решётка в начале строки — комментарий, перевод строки — конец
    значения; и то и другое портит секцию молча.
    """
    text = " ".join(str(value or "").split())
    return text.lstrip("#").strip()[:MAX_META]


# ───────────────────────────── экспорт ──────────────────────────────

def export(args, *, section_id: str = "", name: str = "", author: str = "",
           label: str = "", description: str = "", blobs=None,
           protocol: str = "", level: str = "") -> dict:
    """Превратить argv в секцию каталога и проверить, что она читается.

    Returns:
        dict: ``text`` (секция), ``section_id``, ``protocol``, ``level``,
        ``file`` (куда её класть), ``blobs``, ``warnings``.

    Raises:
        ExportError: argv не годится или собранная секция не читается
        нашим же парсером.
    """
    cleaned = clean_args(args)
    section_id = (section_id or slugify(name)) or slugify("")
    section_id = slugify(section_id)
    protocol = (protocol or guess_protocol(cleaned)).strip().lower()
    if protocol not in ("tcp", "udp"):
        raise ExportError("протокол «%s»: каталоги знают только tcp и udp"
                          % protocol)
    level = (level or guess_level(cleaned)).strip().lower()
    declared = list(blobs) if blobs else guess_blobs(cleaned)

    text = render_section(section_id, cleaned, name=name, author=author,
                          label=label, description=description,
                          blobs=declared)
    parsed = _round_trip(text, protocol, level)

    warnings = []
    if declared:
        warnings.extend(_blob_warnings(declared))
    if level == "builtin":
        warnings.append(
            "в argv есть --filter-*/--new: это полная конфигурация, ей "
            "место в catalogs/builtin/, а не в наборе одиночных приёмов")
    return {
        "ok": True,
        "text": text,
        "section_id": section_id,
        "name": parsed.name,
        "protocol": protocol,
        "level": level,
        "file": suggest_file(protocol, level),
        "args": cleaned,
        "blobs": declared,
        "warnings": warnings,
    }


def suggest_file(protocol: str, level: str) -> str:
    """Куда класть секцию в дереве каталогов."""
    if level == "builtin":
        return "catalogs/builtin/zapret_gui_defaults.txt"
    return "catalogs/%s/%s.txt" % (level, protocol)


def _round_trip(text: str, protocol: str, level: str):
    """Прочитать собранную секцию нашим же парсером и сверить argv."""
    from core.catalog_loader import _parse_catalog_content

    entries = _parse_catalog_content(text, source_file="export",
                                     protocol=protocol, level=level)
    if len(entries) != 1:
        raise ExportError(
            "собранная секция читается как %d секций вместо одной — "
            "похоже, в метаданных остался перевод строки"
            % len(entries))
    entry = entries[0]
    source = [line for line in text.splitlines() if line.startswith("--")]
    if entry.get_args_list() != source:
        raise ExportError(
            "argv после разбора не совпал с исходным: парсер прочитал %d "
            "аргументов из %d" % (len(entry.get_args_list()), len(source)))
    return entry


def _blob_warnings(names) -> list:
    """Есть ли объявленные blob'ы на этом устройстве."""
    try:
        from core.blob_registry import list_blobs
        # Свои блобы (kind=user) есть только на этом роутере: у того,
        # кто поставит стратегию из каталога, их не будет.
        known = {item.get("name") for item in (list_blobs() or [])
                 if item.get("exists", True)
                 and item.get("kind") != "user"}
    except Exception:                           # noqa: BLE001 — граница
        return []
    missing = [name for name in names if name not in known]
    if not missing:
        return []
    return ["blob'ов нет на этом устройстве: %s — у того, кто поставит "
            "стратегию из каталога, их тоже может не быть"
            % ", ".join(sorted(missing))]
