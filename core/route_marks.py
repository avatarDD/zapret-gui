# core/route_marks.py
"""
Метки клиентов, которых роутер ведёт политикой маршрутизации мимо WAN.

## Зачем

Keenetic (и наш же единый слой маршрутизации) уводит трафик части
устройств в VPN не через основную таблицу, а правилом ``ip rule``: NDMS
метит пакеты клиента fwmark'ом (``0xffffaaa`` → таблица 4096 и т.п.), и
ядро выбирает для них другую таблицу — с default через туннель.

Если такой поток попал в NFQUEUE, nfqws2 отправляет фейки и разрезанные
сегменты сырым сокетом со СВОЕЙ меткой (``desync_mark``), без метки
клиента — значит, по основной таблице, то есть в WAN мимо туннеля.
Клиент считает, что ходит через VPN, а часть его пакетов (и фейк с
настоящим SNI) уходит провайдеру. Поймано в d2k (necronicle/d2k,
``datapath/routemark.c``, задача 47): там же решение — не трогать поток,
чья метка выбирает правило с другим выходом.

У нас это возможно ТОЛЬКО при перехвате «на всех интерфейсах»: когда
WAN известен, правила висят на ``-o <wan>`` в POSTROUTING, а он идёт
ПОСЛЕ маршрутизации — пакет, уведённый в ``nwg0``, в очередь и так не
попадает. Поэтому firewall зовёт этот модуль, только если список WAN
пуст.

## Что считается «уведённым»

Правило ``ip rule`` с ``fwmark`` (без ``not``), у которого:

* действие ``blackhole``/``unreachable``/``prohibit`` — такой пакет
  вообще не должен уходить, и наш фейк в WAN — утечка;
* ``lookup <таблица>``, где таблица — не local/main/default, а её
  default-маршрут идёт через устройство, которого нет среди default
  основной таблицы. Таблица без default не уводит ничего: ядро идёт к
  следующему правилу.

Политика доступа Keenetic, чья таблица ведёт в того же провайдера, под
это не попадает — иначе мы выключили бы обход всем устройствам политики.

Разбор — чистые функции (тестам не нужен ни ``ip``, ни роутер); тот же
алгоритм на shell живёт в ``FIREWALL_SH_FUNCTIONS`` (`_routed_marks`)
для автозапуска и reapply-хука.
"""

import re
import subprocess


# Таблицы, поиск в которых — это обычная маршрутизация.
STANDARD_TABLES = frozenset(("local", "main", "default", "253", "254", "255"))

# Действия правила без таблицы: пакет никуда не должен уходить.
DROP_ACTIONS = frozenset(("blackhole", "unreachable", "prohibit"))

FULL_MASK = 0xFFFFFFFF

_DEV_RE = re.compile(r"\bdev\s+(\S+)")


def _parse_mark(token: str):
    """``0xffffaaa`` / ``0x10000/0x1ffff`` / ``42`` → (mark, mask) или None."""
    value, _, mask = str(token).partition("/")
    try:
        mark = int(value, 0)
        mask = int(mask, 0) if mask else FULL_MASK
    except ValueError:
        return None
    if mask == 0 or not (0 <= mark <= FULL_MASK and 0 < mask <= FULL_MASK):
        return None
    return mark & mask, mask


def parse_rules(text: str) -> list:
    """Разобрать вывод ``ip rule show``: правила с fwmark.

    Returns:
        list[dict]: ``mark``, ``mask`` (int), ``table`` (строка или
        ``""``), ``action`` (``lookup`` или действие из DROP_ACTIONS).
        Правила с ``not`` пропускаются: «все, КРОМЕ метки» — не про
        помеченного клиента.
    """
    out = []
    for line in str(text or "").splitlines():
        tokens = line.replace(":", " ", 1).split()
        if "fwmark" not in tokens or "not" in tokens:
            continue
        index = tokens.index("fwmark")
        if index + 1 >= len(tokens):
            continue
        parsed = _parse_mark(tokens[index + 1])
        if parsed is None:
            continue
        table, action = "", ""
        for keyword in ("lookup", "table"):
            if keyword in tokens:
                pos = tokens.index(keyword)
                if pos + 1 < len(tokens):
                    table, action = tokens[pos + 1], "lookup"
                break
        if not action:
            for name in DROP_ACTIONS:
                if name in tokens:
                    action = name
                    break
        if not action:
            continue
        out.append({"mark": parsed[0], "mask": parsed[1],
                    "table": table, "action": action})
    return out


def parse_default_devs(text: str) -> list:
    """Устройства default-маршрутов из ``ip route show [table T]``."""
    devs = []
    for line in str(text or "").splitlines():
        if not line.strip().startswith("default"):
            continue
        match = _DEV_RE.search(line)
        if match and match.group(1) not in devs:
            devs.append(match.group(1))
    return devs


def format_mark(mark: int, mask: int) -> str:
    """Форма ``значение/маска`` для ``-m mark --mark``."""
    return "0x%x/0x%x" % (mark, mask)


def routed_marks(rules, main_devs, table_devs) -> list:
    """Какие метки уводят клиента мимо основного выхода.

    Args:
        rules: результат :func:`parse_rules`.
        main_devs: устройства default основной таблицы.
        table_devs: ``{таблица: [устройства default]}`` для таблиц из
            правил (нет ключа — default у таблицы нет).

    Returns:
        list[str]: ``0xMARK/0xMASK`` без повторов, в порядке правил.
    """
    main = set(main_devs or [])
    out = []
    for rule in rules or []:
        if rule["action"] in DROP_ACTIONS:
            routed = True
        elif rule["table"] in STANDARD_TABLES:
            routed = False
        else:
            devs = table_devs.get(rule["table"]) or []
            routed = any(dev not in main for dev in devs)
        text = format_mark(rule["mark"], rule["mask"])
        if routed and text not in out:
            out.append(text)
    return out


def _ip(args) -> str:
    try:
        result = subprocess.run(["ip"] + list(args), capture_output=True,
                                text=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def detect(family: str = "4") -> list:
    """Метки, уводящие клиента мимо основного выхода, для ``-4``/``-6``.

    Ошибка ``ip`` — пустой список: не знаем — не исключаем (прежнее
    поведение, а не новое).
    """
    flag = "-6" if str(family) == "6" else "-4"
    rules = parse_rules(_ip([flag, "rule", "show"]))
    if not rules:
        return []
    main = parse_default_devs(_ip([flag, "route", "show", "table", "main"]))
    tables = {}
    for rule in rules:
        name = rule["table"]
        if rule["action"] == "lookup" and name not in STANDARD_TABLES \
                and name not in tables:
            tables[name] = parse_default_devs(
                _ip([flag, "route", "show", "table", name]))
    return routed_marks(rules, main, tables)
