# core/shell_exec.py
"""
Исполнение команд на устройстве: safe-список, запреты, подтверждения,
дедмен-свитч.

Модуль **не про MCP**: он про то, как zapret-gui вообще запускает
чужую команду на роутере. MCP (``core/mcp/tools/shell.py``) — первый
его потребитель, дальше сюда же придут диагностика и терминал в GUI.
Поэтому здесь нет ни разрешений, ни ответов ``isError``: только
«можно ли», «как запустить» и «как вернуть назад».

## Два режима и граница между ними

``argv``-режим
    Команда собрана списком и запускается **без оболочки**. Ни пайпов,
    ни редиректов, ни подстановок: ``["cat", "/tmp/a; rm -rf /"]``
    честно откроет файл с таким именем и ничего не удалит. В этом
    режиме работает safe-список (:data:`SAFE_COMMANDS`) — то, что
    отдаётся под разрешением ``shell_readonly``.

``sh -c``-режим
    Произвольная строка одним аргументом в ``["sh", "-c", command]``.
    Это root на всём роутере, и закрыт он разрешением ``shell_full``.

Строка, которую можно разобрать в argv без единого метасимвола
оболочки, исполняется **argv-режимом**, даже когда есть ``shell_full``:
оболочка, которую не звали, — лишний слой, в котором ошибаются.

## Что нельзя никогда

:data:`DENY_RULES` — жёсткий отказ, **подтверждением не обходится**:
перепрошивка, ``mkfs``, ``dd of=/dev/…``, ``rm -rf /``, смена пароля
root. Матчинг идёт по **нормализованной** строке
(:func:`normalize_text`): без нормализации ``env  rm   -rf /``,
``"rm" -rf /`` и ``/bin/rm -rf /`` проходят мимо наивного сравнения, и
защита оказывается декоративной.

## Что можно только дважды

:data:`CONFIRM_RULES` — двухшаговое подтверждение: первый вызов
возвращает ``confirm_token`` (одноразовый, живёт
:data:`CONFIRM_TTL_SEC` секунд) и человеческое описание последствий,
второй — исполняет.

Часть этих правил помечена ``network=True``: это команды, которыми
модель отрезает доступ к роутеру себе и пользователю (``iptables -F``,
``ip link set … down``, остановка ``dropbear``). Им обязателен
``guard`` — **дедмен-свитч**: после исполнения заводится таймер,
который выполнит ``revert_cmd``, если никто не пришёл с
``shell_confirm(run_id=…)``. Таймер продублирован на диске
(``mcp-shell-guards.json`` рядом с ``settings.json``, **не в /tmp** —
там tmpfs): дедмен, живущий только в памяти упавшего процесса, не
откатывает ничего.

## Правила исполнения

1. ``stdin`` закрыт (``/dev/null``): команда не уйдёт в интерактивный
   запрос и не повиснет на нём.
2. Окружение минимальное (:data:`BASE_ENV`) — **без переменных
   процесса GUI**: там токены, пути и всё, что мы старательно не
   отдаём в ответах.
3. Таймаут обязателен: ``SIGTERM`` всей группе процессов, через
   :data:`KILL_GRACE_SEC` — ``SIGKILL``; в ответе ``timed_out``.
4. ``stdout`` и ``stderr`` слиты, обрезка до ``mcp.shell.output_kb``
   **с сохранением хвоста** (он информативнее шапки), к тексту
   применяется ``redact_text``: ``cat`` конфига с паролем не должен
   уехать в облачную модель.
5. Одна синхронная команда за раз, не больше ``mcp.shell.max_jobs``
   фоновых.
"""

import collections
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
import uuid

from core.log_buffer import log
from core.mcp.redact import redact_text
from core.safe_io import atomic_write_text


SOURCE = "shell"

# ──────────────────────────── настройки ─────────────────────────────

# Дефолты дублируют DEFAULT_CONFIG["mcp"]["shell"]: модуль обязан
# работать и на конфиге, в котором секции ещё нет (старый settings.json).
DEFAULTS = {
    "timeout_sec": 30,
    "max_timeout_sec": 300,
    "output_kb": 64,
    "workdir": "/opt",
    "max_jobs": 3,
    "allow_write_paths": ["/opt", "/tmp", "/etc"],
    "guard_default_ttl_sec": 120,
}

# Сколько живёт одноразовый токен подтверждения.
CONFIRM_TTL_SEC = 60

# Сколько ждём после SIGTERM, прежде чем послать SIGKILL.
KILL_GRACE_SEC = 3

# Во сколько раз буфер фоновой задачи больше обрезки синхронного
# ответа: её вывод читают порциями по offset, и терять начало нельзя.
ASYNC_BUFFER_FACTOR = 4

# Длиннее этого команду не принимаем: это не команда, а попытка.
MAX_COMMAND_LEN = 4096

# Минимальное окружение. Ничего из os.environ сюда не попадает: у
# процесса GUI в переменных живут пути, токены и настройки отладки.
BASE_ENV = {
    "PATH": ("/opt/bin:/opt/sbin:/usr/local/sbin:/usr/local/bin:"
             "/usr/sbin:/usr/bin:/sbin:/bin"),
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
    "TERM": "dumb",
}

# Имя файла дедмен-свитчей рядом с settings.json.
GUARDS_NAME = "mcp-shell-guards.json"


def settings() -> dict:
    """Секция ``mcp.shell`` поверх дефолтов."""
    section = {}
    try:
        from core.config_manager import get_config_manager
        value = get_config_manager().get("mcp", "shell", default={})
        if isinstance(value, dict):
            section = value
    except Exception:                           # noqa: BLE001 — граница
        section = {}
    out = dict(DEFAULTS)
    out.update({k: v for k, v in section.items() if v is not None})
    return out


def limits() -> dict:
    """Числовые лимиты, приведённые к осмысленным значениям."""
    raw = settings()
    out = {
        "timeout_sec": _positive(raw.get("timeout_sec"), 30),
        "max_timeout_sec": _positive(raw.get("max_timeout_sec"), 300),
        "output_kb": _positive(raw.get("output_kb"), 64),
        "max_jobs": _positive(raw.get("max_jobs"), 3),
        "guard_default_ttl_sec": _positive(
            raw.get("guard_default_ttl_sec"), 120),
        "workdir": str(raw.get("workdir") or "/opt"),
        "allow_write_paths": [str(p) for p in
                              (raw.get("allow_write_paths") or []) if p],
    }
    out["timeout_sec"] = min(out["timeout_sec"], out["max_timeout_sec"])
    return out


def _positive(value, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


# ─────────────────────────── нормализация ───────────────────────────

# Слова, которые стоят ПЕРЕД настоящей командой и ничего о ней не
# говорят. `env FOO=1 rm -rf /` обязан читаться как `rm -rf /`.
PREFIX_WORDS = frozenset((
    "sudo", "doas", "env", "nohup", "exec", "command", "busybox",
    "setsid", "nice", "ionice", "stdbuf", "time", "eval",
))

# VAR=value перед командой — тот же префикс.
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Разделители команд внутри строки: нормализуем каждый кусок отдельно,
# иначе `ls; /bin/rm -rf /` остался бы с абсолютным путём.
_SPLIT_RE = re.compile(r"\s*(?:\|\||&&|[;|&\n])\s*")

# Метасимволы оболочки: строка с ними в argv-режим не превращается.
SHELL_META_RE = re.compile(r"[|&;<>()$`\n\\*?\[\]{}~!#]|\$\(")


def normalize_text(command: str) -> str:
    """Привести команду к виду, по которому матчатся запреты.

    Снимает кавычки и обратные слэши (``r\\m`` → ``rm``), схлопывает
    пробелы, выкидывает префиксы (``env``, ``sudo``, ``busybox``,
    ``VAR=1``) и абсолютный путь у самой команды (``/bin/rm`` →
    ``rm``). Без этого запреты обходятся школьными приёмами.
    """
    if not isinstance(command, str):
        return ""
    text = command.replace("\r", " ")
    text = re.sub(r"[\"'\\]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return ""
    parts = [_normalize_segment(p) for p in _SPLIT_RE.split(text)]
    return " ; ".join(p for p in parts if p)


def _normalize_segment(segment: str) -> str:
    tokens = [t for t in segment.split(" ") if t]
    return " ".join(normalize_argv(tokens))


def normalize_argv(argv) -> list:
    """Снять с argv префиксы и путь у команды (см. :func:`normalize_text`)."""
    tokens = [str(t) for t in (argv or []) if str(t) != ""]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name = os.path.basename(token.rstrip("/")) or token
        if _ASSIGN_RE.match(token) or name in PREFIX_WORDS:
            index += 1
            # Флаги самого префикса (`env -i`, `nice -n 10`) — туда же.
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
                if index < len(tokens) and name in ("nice", "ionice",
                                                    "stdbuf", "timeout"):
                    index += 1
            continue
        break
    rest = tokens[index:]
    if not rest:
        return []
    return [os.path.basename(rest[0].rstrip("/")) or rest[0]] + rest[1:]


# ───────────────────────────── запреты ──────────────────────────────

# Каталоги, снос которых равен потере устройства. Из них собираются
# правила «rm -rf /opt» и «chmod -R 777 /» — руками такой список
# переписывать по одному правилу нельзя, разойдётся.
PROTECTED_ROOTS = (
    "/", "/bin", "/sbin", "/lib", "/usr", "/etc", "/var", "/root", "/tmp",
    "/opt", "/opt/bin", "/opt/sbin", "/opt/lib", "/opt/etc", "/opt/share",
    "/opt/zapret2", "/overlay", "/proc", "/sys", "/dev",
)


def _roots_alternation() -> str:
    roots = sorted(PROTECTED_ROOTS, key=len, reverse=True)
    return "|".join(re.escape(r) for r in roots)


def _root_destroyer(command: str, flag: str) -> str:
    """Регулярка «``command`` с рекурсивным флагом по защищённому корню»."""
    return (r"\b%s\b(?:\s+-{1,2}[^\s]+)*\s+-{1,2}[a-zA-Z]*%s[a-zA-Z]*"
            r"(?:\s+[^\s]+)*?\s+(?:%s)/?\*?(?:\s|;|$)"
            % (command, flag, _roots_alternation()))


DENY_RULES = (
    {
        "code": "flash_write",
        "re": re.compile(r"(?i)(?:\bmtd\b|\bflash_erase\w*\b|"
                         r"of=/dev/mtd|>\s*/dev/mtd)"),
        "why": "запись во флеш-память устройства — это кирпич, а не "
               "настройка",
    },
    {
        "code": "mkfs",
        "re": re.compile(r"(?i)\bmkfs(?:\.[a-z0-9]+)?\b"),
        "why": "форматирование файловой системы уничтожает данные "
               "устройства",
    },
    {
        "code": "sysupgrade",
        "re": re.compile(r"(?i)\bsysupgrade\b"),
        "why": "перепрошивка устройства из чата — не то, что можно "
               "отменить",
    },
    {
        "code": "firstboot",
        "re": re.compile(r"(?i)\b(?:firstboot|jffs2reset)\b"),
        "why": "сброс к заводским настройкам стирает конфигурацию "
               "целиком",
    },
    {
        "code": "dd_to_device",
        "re": re.compile(r"(?i)\bdd\b[^;]*\bof=\s*/dev/"),
        "why": "запись dd напрямую в устройство портит раздел или флеш",
    },
    {
        "code": "rm_protected_root",
        "re": re.compile(r"(?i)" + _root_destroyer("rm", "[rR]")),
        "why": "рекурсивное удаление системного каталога — потеря "
               "устройства без пути назад",
    },
    {
        "code": "chmod_protected_root",
        "re": re.compile(r"(?i)" + _root_destroyer("chmod", "[rR]")),
        "why": "рекурсивная смена прав на системный каталог ломает "
               "загрузку и ssh",
    },
    {
        "code": "chown_protected_root",
        "re": re.compile(r"(?i)" + _root_destroyer("chown", "[rR]")),
        "why": "рекурсивная смена владельца системного каталога ломает "
               "службы",
    },
    {
        "code": "root_password",
        "re": re.compile(r"(?i)(?:^|[\s;])(?:passwd|chpasswd)\b|"
                         r"\busermod\b[^;]*\s-p\b|"
                         r">\s*/etc/shadow"),
        "why": "смена пароля root закрывает вход владельцу устройства",
    },
    {
        "code": "fork_bomb",
        "re": re.compile(r":\(\)\s*\{.*\};\s*:|:\s*;\s*:\s*&"),
        "why": "форк-бомба вешает роутер до перезагрузки по питанию",
    },
)


def deny_reason(command) -> dict:
    """Правило запрета, под которое попала команда (или ``{}``).

    Принимает строку или argv. Матчинг — по нормализованному виду:
    ``env  "rm"   -rf /`` и ``/bin/rm -rf /`` обязаны отклоняться так
    же, как ``rm -rf /``.
    """
    text = _as_text(command)
    if not text:
        return {}
    for rule in DENY_RULES:
        if rule["re"].search(text):
            return {"code": rule["code"], "why": rule["why"]}
    return {}


# ─────────────────────── правила подтверждения ──────────────────────

CONFIRM_RULES = (
    {
        "code": "reboot",
        "re": re.compile(r"(?i)\b(?:reboot|halt|poweroff|shutdown)\b"),
        "network": False,
        "why": "устройство перезагрузится: связь пропадёт на 1–2 минуты, "
               "а незаписанные изменения будут потеряны",
    },
    {
        "code": "package_remove",
        "re": re.compile(r"(?i)\bopkg\b[^;]*\bremove\b|\bapk\b[^;]*\bdel\b"),
        "network": False,
        "why": "удаление пакета может оставить LAN без DNS, DHCP или "
               "самого обхода",
    },
    {
        "code": "rm_recursive",
        "re": re.compile(r"(?i)\brm\b(?:\s+-{1,2}[^\s]+)*\s+"
                         r"-{1,2}[a-zA-Z]*[rR][a-zA-Z]*\b"),
        "network": False,
        "why": "рекурсивное удаление необратимо: проверьте путь до "
               "последнего символа",
    },
    {
        "code": "firewall_flush",
        "re": re.compile(r"(?i)\bip6?tables\b[^;]*\s-[a-zA-Z]*F|"
                         r"\bnft\b[^;]*\bflush\b|"
                         r"\bip6?tables\b[^;]*\s-[a-zA-Z]*X"),
        "network": True,
        "why": "сброс правил firewall снимает и правила доступа: SSH и "
               "веб-интерфейс могут стать недоступны",
    },
    {
        "code": "interface_down",
        "re": re.compile(r"(?i)\bifconfig\b[^;]*\bdown\b|"
                         r"\bip\b[^;]*\blink\b[^;]*\bset\b[^;]*\bdown\b|"
                         r"\bifdown\b"),
        "network": True,
        "why": "интерфейс погаснет: если это тот, через который вы "
               "подключены, связь оборвётся совсем",
    },
    {
        "code": "route_change",
        "re": re.compile(r"(?i)\bip\b[^;]*\broute\b[^;]*\b(?:del|delete|"
                         r"flush|replace)\b|\broute\b\s+del\b"),
        "network": True,
        "why": "правка таблицы маршрутов уводит трафик мимо вас — "
               "обратно уже не подключиться",
    },
    {
        "code": "ssh_stop",
        "re": re.compile(r"(?i)\b(?:dropbear|sshd|ssh)\b[^;]*\b(?:stop|"
                         r"disable)\b|\bkillall\b[^;]*\b(?:dropbear|sshd)\b|"
                         r"\b(?:stop|disable)\b[^;]*\b(?:dropbear|sshd)\b"),
        "network": True,
        "why": "остановка SSH убирает последний способ починить роутер "
               "руками",
    },
    {
        "code": "network_restart",
        "re": re.compile(r"(?i)/etc/init\.d/network\b|\bservice\s+network\b"),
        "network": True,
        "why": "перезапуск сети рвёт текущее соединение; если конфиг "
               "неверен, оно не вернётся",
    },
    {
        "code": "passwd_edit",
        "re": re.compile(r"(?i)>\s*/etc/passwd|\b(?:vi|sed|tee)\b[^;]*"
                         r"/etc/passwd"),
        "network": False,
        "why": "правка /etc/passwd закрывает вход владельцу устройства",
    },
)


def confirm_rules(command) -> list:
    """Правила подтверждения, под которые попала команда."""
    text = _as_text(command)
    if not text:
        return []
    out = []
    for rule in CONFIRM_RULES:
        if rule["re"].search(text):
            out.append({"code": rule["code"], "why": rule["why"],
                        "network": rule["network"]})
    return out


def _as_text(command) -> str:
    if isinstance(command, (list, tuple)):
        return normalize_text(" ".join(str(t) for t in command))
    return normalize_text(str(command or ""))


# ──────────────────────────── safe-список ───────────────────────────

def _cmd(letters="", flags=(), value_flags=None, numeric=False, first=None,
         deny=(), args=0, require=(), forbid="", verbs=None, hints=None):
    """Описание разрешённой команды (данные, а не код).

    ``verbs`` — белый список ВТОРОГО слова (``ip route show``). Он
    нужен там, где программа понимает сокращения: iproute2 и tc читают
    ``a`` как ``add``, ``d`` как ``delete``, ``s`` как ``set``, и
    чёрный список глаголов (``deny``) такие формы пропускает.

    ``hints`` — флаг → подсказка вместо общего «нужно shell_full»,
    когда у флага есть читающая замена (``logread -n`` → ``-l N``).
    """
    return {
        "letters": set(letters),
        "flags": set(flags),
        "value_flags": dict(value_flags or {}),
        "numeric": bool(numeric),
        "first": set(first) if first else None,
        "deny": set(deny),
        "args": int(args),
        "require": set(require),
        "forbid": re.compile(forbid) if forbid else None,
        "verbs": set(verbs) if verbs else None,
        "hints": dict(hints or {}),
    }


# Глаголы, которые превращают читающую команду в меняющую.
_NET_WRITE = ("add", "del", "delete", "set", "change", "replace", "flush",
              "append", "save", "restore", "up", "down", "exec")

# Читающие глаголы iproute2/tc — БЕЛЫЙ список: обе программы понимают
# префиксы (`ip r d default` = `ip route delete default`), так что
# перечислять запретные формы бесполезно.
_READ_VERBS = ("show", "list", "ls", "lst", "get")

# Куда безопасно «скачать»: в никуда или в stdout. Без этого `wget`
# пишет файл в рабочий каталог, а `curl -o` — куда скажут.
_SINKS = ("-", "/dev/null")

# Что разрешено под `shell_readonly`. Список **курируемый**: команда
# сюда попадает, только если ею нельзя ни писать, ни исполнять чужое.
# Поэтому здесь нет `awk` (system()), `sed` (-i, w), `env`, `nc` и
# самого `sh`: одна пропущенная опция у них превращает «чтение» в
# root-доступ. `find`, `wget` и `tc` есть, но только белым списком
# опций: `-exec`/`-delete`, запись в файл и меняющие глаголы туда не
# входят.
SAFE_COMMANDS = {
    # ── система ──
    "uname": _cmd(letters="asnrvmpio"),
    "uptime": _cmd(letters="ps"),
    "free": _cmd(letters="bkmghwt"),
    # Позиционный аргумент — только формат `+…`: `date 0101000025`
    # у busybox и GNU date УСТАНАВЛИВАЕТ время.
    "date": _cmd(flags=("-u", "-R", "-I", "--utc", "--rfc-3339"),
                 value_flags={"-d": "word", "--date": "word"}, args=1,
                 forbid=r"^[^+]"),
    "hostname": _cmd(letters="fs"),
    "id": _cmd(letters="unGgrZ", args=1),
    "mount": _cmd(letters="l"),
    "lsmod": _cmd(),
    "dmesg": _cmd(flags=("-T", "-x", "-k", "-u")),
    # `-e` — регэксп по тексту сообщения, пробелы в нём законны
    # (`-e "Oct 28 19:2"`): argv идёт без оболочки.
    "logread": _cmd(value_flags={"-l": "int", "-e": "text"},
                    hints={"-n": "у logread хвост задаётся -l N; отбор "
                                 "строк — -e или аргумент filter"}),
    "sysctl": _cmd(letters="an", args=4, forbid=r"="),
    # ── файлы ──
    "ls": _cmd(letters="laAhtrS1dRinFC", args=8),
    "cat": _cmd(letters="nAvET", args=8),
    "head": _cmd(letters="qv", value_flags={"-n": "int", "-c": "int"},
                 numeric=True, args=8),
    "tail": _cmd(letters="qv", value_flags={"-n": "int", "-c": "int"},
                 numeric=True, args=8),
    "wc": _cmd(letters="lwcmL", args=8),
    "stat": _cmd(letters="Lft", value_flags={"-c": "word",
                                             "--format": "word"}, args=4),
    "readlink": _cmd(letters="fem", args=2),
    "which": _cmd(letters="a", args=4),
    "df": _cmd(letters="hkmiTPal", args=4),
    "du": _cmd(letters="hskmax", value_flags={"-d": "int",
                                              "--max-depth": "int"}, args=4),
    "grep": _cmd(letters="inrRvcloEFqswxahHz",
                 value_flags={"-m": "int", "-A": "int", "-B": "int",
                              "-C": "int", "-e": "text",
                              "--include": "word", "--exclude": "word"},
                 args=10),
    # Только тесты и печать: `-exec`/`-execdir`/`-ok`/`-delete`/
    # `-fprint*` не входят в белый список и отбиваются как флаги.
    "find": _cmd(flags=("-L", "-H", "-P", "-xdev", "-print", "-print0",
                        "-ls", "-o", "-or", "-a", "-and", "-not",
                        "-prune", "-depth", "-follow", "-empty"),
                 value_flags={"-name": "word", "-iname": "word",
                              "-path": "word", "-ipath": "word",
                              "-regex": "word", "-type": "word",
                              "-maxdepth": "int", "-mindepth": "int",
                              "-size": "word", "-mtime": "word",
                              "-mmin": "word", "-newer": "word",
                              "-perm": "word", "-user": "word",
                              "-group": "word"},
                 args=8),
    # ── процессы ──
    "ps": _cmd(letters="aeflxwuo", value_flags={"-o": "word"},
               first=("aux", "ax", "auxw", "auxww", "w", "ww", "axjf", "ef"),
               args=2),
    "pgrep": _cmd(letters="flna", value_flags={"-u": "word"}, args=2),
    "top": _cmd(flags=("-b", "-H", "-1"),
                value_flags={"-n": "int", "-d": "int"},
                require=("-n",)),
    # ── сеть: состояние ──
    # Без `-b` (batch-файл команд) и `-n` (у iproute2 это `-netns`,
    # который съедает следующее слово и сдвигает разбор).
    "ip": _cmd(letters="sdor46cjp",
               first=("addr", "address", "a", "link", "l", "route", "r",
                      "ro", "rule", "ru", "neigh", "n", "neighbour",
                      "neighbor", "tunnel", "tun", "maddr", "mroute"),
               verbs=_READ_VERBS, deny=_NET_WRITE, args=12),
    "tc": _cmd(letters="sdjpg",
               first=("qdisc", "class", "filter", "action", "actions",
                      "chain"),
               verbs=_READ_VERBS, deny=_NET_WRITE, args=10),
    "ifconfig": _cmd(letters="a", args=1,
                     deny=("up", "down", "add", "del", "netmask", "mtu",
                           "promisc", "-promisc", "hw", "broadcast",
                           "arp", "-arp", "multicast")),
    "route": _cmd(letters="ne", deny=("add", "del", "delete", "flush")),
    "arp": _cmd(letters="an", args=2),
    "netstat": _cmd(letters="anptuwlrxes"),
    "ss": _cmd(letters="antuplrsxemi46", args=12),
    "conntrack": _cmd(letters="L", require=("-L",),
                      value_flags={"-p": "word", "-s": "word",
                                   "-d": "word", "-o": "word"}),
    # ── сеть: правила ──
    "iptables": _cmd(letters="LSnvx", value_flags={"-t": "word"},
                     require=("-L", "-S"), args=2),
    "ip6tables": _cmd(letters="LSnvx", value_flags={"-t": "word"},
                      require=("-L", "-S"), args=2),
    "iptables-save": _cmd(flags=("-c",), value_flags={"-t": "word"}),
    "ip6tables-save": _cmd(flags=("-c",), value_flags={"-t": "word"}),
    # nft склеивает argv в одну строку и разбирает её как скрипт:
    # `ruleset;flush` в одном аргументе — это две команды. Поэтому
    # в аргументах нет ни разделителей, ни пробелов, ни блоков.
    "nft": _cmd(letters="ansjt", first=("list",), deny=("add", "delete",
                "flush", "insert", "replace", "create", "destroy", "reset",
                "rename", "import"), args=8, forbid=r"[\s;#{}]"),
    # ── сеть: пробы ──
    "nslookup": _cmd(args=2),
    "dig": _cmd(letters="x46", value_flags={"-t": "word", "-p": "int"},
                args=6),
    "host": _cmd(letters="atv46", value_flags={"-t": "word"}, args=3),
    "ping": _cmd(letters="nq46", require=("-c",), args=1,
                 value_flags={"-c": "int", "-W": "int", "-w": "int",
                              "-s": "int", "-i": "word", "-I": "word",
                              "-t": "int", "-M": "word"}),
    "ping6": _cmd(letters="nq", require=("-c",), args=1,
                  value_flags={"-c": "int", "-W": "int", "-w": "int",
                               "-s": "int", "-i": "word", "-I": "word"}),
    "traceroute": _cmd(letters="nIU46", args=1,
                       value_flags={"-m": "int", "-q": "int", "-w": "int",
                                    "-p": "int", "-s": "word",
                                    "-i": "word"}),
    "traceroute6": _cmd(letters="nIU", args=1,
                        value_flags={"-m": "int", "-q": "int",
                                     "-w": "int", "-p": "int"}),
    # `-o` только в никуда; `-w` — без `%output{…}` (curl 8.3+ пишет
    # им в файл) и без `@файла`.
    "curl": _cmd(letters="sSILkv46f",
                 flags=("--head", "--silent", "--show-error", "--location",
                        "--insecure", "--compressed", "--fail",
                        "--http1.1", "--http2", "--tlsv1.2", "--tlsv1.3",
                        "--no-keepalive"),
                 value_flags={"-o": "sink", "--output": "sink",
                              "-w": "writeout", "--write-out": "writeout",
                              "--tls-max": "word",
                              "-m": "int", "--max-time": "int",
                              "--connect-timeout": "int", "-A": "word",
                              "--user-agent": "word", "-H": "word",
                              "--header": "word", "--resolve": "word",
                              "--interface": "word", "-x": "word",
                              "--proxy": "word"},
                 args=1),
    # busybox wget, uclient-fetch и GNU wget: без `-O -`/`-O /dev/null`
    # или `--spider` они сохраняют файл в рабочий каталог — требуем.
    "wget": _cmd(letters="qS46",
                 flags=("--spider", "--no-check-certificate", "--quiet",
                        "--server-response"),
                 value_flags={"-O": "sink", "--output-document": "sink",
                              "-T": "int", "--timeout": "int",
                              "-t": "int", "--tries": "int",
                              "-U": "word", "--user-agent": "word",
                              "--header": "word"},
                 require=("-O", "--output-document", "--spider"), args=1),
    "uclient-fetch": _cmd(letters="q46",
                          flags=("--spider", "--no-check-certificate",
                                 "--quiet"),
                          value_flags={"-O": "sink",
                                       "--output-document": "sink",
                                       "-T": "int", "--timeout": "int",
                                       "-U": "word", "--user-agent": "word"},
                          require=("-O", "--output-document", "--spider"),
                          args=1),
    # ── туннели и пакеты ──
    "wg": _cmd(first=("show", "showconf"), args=3,
               deny=("set", "setconf", "addconf", "syncconf", "genkey",
                     "genpsk", "pubkey")),
    "awg": _cmd(first=("show", "showconf"), args=3,
                deny=("set", "setconf", "addconf", "syncconf", "genkey",
                      "genpsk", "pubkey")),
    "opkg": _cmd(first=("list-installed", "list", "list-upgradable",
                        "info", "status", "files", "search", "whatprovides",
                        "print-architecture", "compare-versions"),
                 args=4),
    "apk": _cmd(letters="vIiea",
                first=("info", "list", "version", "policy", "search",
                       "stats"),
                args=4),
}


def check_safe(argv) -> dict:
    """Проверить argv по safe-списку.

    Возвращает ``{"safe": bool, "reason": str, "command": str}``.
    ``argv`` ожидается **нормализованным** (:func:`normalize_argv`):
    иначе ``/bin/ls`` и ``busybox ls`` не найдутся в списке.
    """
    tokens = [str(t) for t in (argv or [])]
    if not tokens:
        return {"safe": False, "reason": "пустая команда", "command": ""}
    name = tokens[0]
    spec = SAFE_COMMANDS.get(name)
    if spec is None:
        return {"safe": False, "command": name,
                "reason": "команда «%s» не входит в безопасный список "
                          "(нужно разрешение shell_full)" % name}

    seen = set()
    positionals = []
    rest = tokens[1:]
    index = 0
    while index < len(rest):
        token = rest[index]
        index += 1
        if token == "--":
            positionals.extend(rest[index:])
            break
        if len(token) > 1 and token.startswith("-"):
            verdict, need_value, marks = _check_flag(spec, token)
            if not verdict:
                hint = spec["hints"].get(token.partition("=")[0])
                return {"safe": False, "command": name,
                        "reason": "флаг %s у «%s» не разрешён (%s)"
                                  % (token, name,
                                     hint or "нужно разрешение shell_full")}
            seen.update(marks)
            if need_value:
                if index >= len(rest):
                    return {"safe": False, "command": name,
                            "reason": "флагу %s не хватает значения" % token}
                value = rest[index]
                index += 1
                if not _check_value(spec["value_flags"].get(need_value),
                                    value):
                    return {"safe": False, "command": name,
                            "reason": "значение %s у флага %s не подходит"
                                      % (value, token)}
            continue
        positionals.append(token)

    if spec["require"] and not (seen & spec["require"]):
        return {"safe": False, "command": name,
                "reason": "«%s» разрешена только с %s"
                          % (name, "/".join(sorted(spec["require"])))}
    if len(positionals) > spec["args"]:
        return {"safe": False, "command": name,
                "reason": "у «%s» слишком много аргументов (максимум %d)"
                          % (name, spec["args"])}
    if len(positionals) > 1 and spec["verbs"] is not None \
            and positionals[1] not in spec["verbs"]:
        return {"safe": False, "command": name,
                "reason": "«%s %s %s» — не читающая форма команды "
                          "(разрешены: %s; нужно разрешение shell_full)"
                          % (name, positionals[0], positionals[1],
                             ", ".join(sorted(spec["verbs"])))}
    if positionals and spec["first"] is not None \
            and positionals[0] not in spec["first"]:
        return {"safe": False, "command": name,
                "reason": "«%s %s» — не читающая форма команды "
                          "(разрешены: %s)"
                          % (name, positionals[0],
                             ", ".join(sorted(spec["first"])))}
    for token in positionals:
        if token in spec["deny"]:
            return {"safe": False, "command": name,
                    "reason": "«%s %s» меняет состояние системы "
                              "(нужно разрешение shell_full)"
                              % (name, token)}
        if spec["forbid"] is not None and spec["forbid"].search(token):
            return {"safe": False, "command": name,
                    "reason": "аргумент «%s» у «%s» не принимается"
                              % (token, name)}
    return {"safe": True, "reason": "", "command": name}


def _check_flag(spec, token):
    """``(можно, флаг-с-значением, что засчитать)`` для одного флага."""
    if token in spec["flags"]:
        return True, "", {token}
    if token in spec["value_flags"]:
        return True, token, {token}
    if token.startswith("--"):
        base, sep, value = token.partition("=")
        if sep and base in spec["value_flags"]:
            if _check_value(spec["value_flags"][base], value):
                return True, "", {base}
        return False, "", set()
    body = token[1:]
    if spec["numeric"] and body.isdigit():
        return True, "", {token}
    for flag, kind in spec["value_flags"].items():
        if len(flag) == 2 and token.startswith(flag) and len(token) > 2:
            if _check_value(kind, token[2:]):
                return True, "", {flag}
    if body and all(ch in spec["letters"] for ch in body):
        return True, "", {"-%s" % ch for ch in body}
    return False, "", set()


def _check_value(kind, value) -> bool:
    if kind == "int":
        return bool(value) and str(value).isdigit()
    if kind == "text":
        return bool(value) and "\n" not in str(value)
    if kind == "sink":
        return str(value) in _SINKS
    if kind == "writeout":
        text = str(value)
        return bool(text) and not text.startswith("@") \
            and "%output" not in text and "\n" not in text
    return bool(value) and not re.search(r"\s", str(value))


# ───────────────────────────── разбор ───────────────────────────────

def plan_command(command="", argv=None, full=False) -> tuple:
    """Как эту команду исполнять: ``(план, отказ)``.

    План — ``{"mode", "argv", "display", "safe"}``. ``mode`` = ``argv``
    (без оболочки) или ``shell`` (``sh -c``). Строка без метасимволов
    исполняется argv-режимом **всегда**: оболочка, которую не звали, —
    лишний слой.
    """
    if argv:
        if isinstance(argv, str):
            return None, _refusal("argv должен быть списком строк",
                                  "передайте argv=[\"df\", \"-h\"] или "
                                  "command=\"df -h\"")
        tokens = [str(t) for t in argv if str(t) != ""]
        if not tokens:
            return None, _refusal("пустой argv", "укажите команду")
        display = " ".join(shlex.quote(t) for t in tokens)
        return _finish_plan(tokens, display, "argv", full)

    text = str(command or "").strip()
    if not text:
        return None, _refusal("команда не указана",
                              "передайте command=\"df -h\" или "
                              "argv=[\"df\", \"-h\"]")
    if len(text) > MAX_COMMAND_LEN:
        return None, _refusal(
            "команда длиннее %d символов" % MAX_COMMAND_LEN,
            "положите её в скрипт через file_write и запустите файл")

    if SHELL_META_RE.search(text):
        if not full:
            return None, _refusal(
                "в команде есть метасимволы оболочки (пайп, редирект, "
                "подстановка) — под shell_readonly они не выполняются",
                "вместо «| grep … | tail» передайте shell_exec аргумент "
                "filter={\"include\": [\"…\"], \"tail\": 50} (или "
                "count_only=true вместо grep -c); для одиночной команды "
                "— argv=[\"ls\", \"-la\"]. Остальное — shell_full")
        return {"mode": "shell", "argv": ["sh", "-c", text],
                "display": text, "safe": False,
                "normalized": normalize_text(text)}, None

    try:
        tokens = shlex.split(text)
    except ValueError as e:
        return None, _refusal("команду не разобрать: %s" % e,
                              "проверьте кавычки")
    if not tokens:
        return None, _refusal("команда не указана", "")
    return _finish_plan(tokens, text, "argv", full)


def _finish_plan(tokens, display, mode, full):
    """Доделать план argv-режима: нормализация и safe-проверка."""
    normalized = normalize_argv(tokens) or list(tokens)
    verdict = check_safe(normalized)
    if not verdict["safe"] and not full:
        return None, _refusal(
            verdict["reason"],
            "это не входит в safe-список shell_readonly; включите "
            "разрешение shell_full или воспользуйтесь профильным "
            "инструментом (file_read, package_list, service_list)",
            command=verdict.get("command", ""))
    # Под safe-списком исполняем ИМЕННО нормализованный argv: иначе
    # `/tmp/evil/ls` прошёл бы проверку по имени `ls`.
    run_argv = normalized if verdict["safe"] else tokens
    return {"mode": mode, "argv": run_argv,
            "display": display if not verdict["safe"]
                       else " ".join(shlex.quote(t) for t in run_argv),
            "safe": verdict["safe"],
            "normalized": " ".join(normalized)}, None


def _refusal(error, hint, **extra) -> dict:
    out = {"ok": False, "error": error}
    if hint:
        out["hint"] = hint
    out.update(extra)
    return out


# ──────────────────────────── исполнение ────────────────────────────

_sync_lock = threading.Lock()
_jobs_lock = threading.Lock()
_JOBS = {}


class _Collector:
    """Сборщик вывода с ограничением памяти.

    ``keep="tail"`` — для синхронного ответа: хвост информативнее
    шапки, в нём ошибка. ``keep="head"`` — для фоновой задачи: её
    вывод читают порциями по ``offset``, и выкидывать начало нельзя.
    """

    def __init__(self, limit, keep="tail"):
        self.limit = max(1024, int(limit))
        self.keep = keep
        self.buffer = bytearray()
        self.total = 0
        self.lock = threading.Lock()

    def pump(self, stream):
        # read1(), а не read(): у буферизованного потока read(n) ждёт
        # ровно n байт или конца процесса, и вывод фоновой задачи
        # появлялся бы у модели только после её завершения.
        read = getattr(stream, "read1", None) or stream.read
        try:
            while True:
                chunk = read(65536)
                if not chunk:
                    break
                self.add(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def add(self, chunk: bytes):
        with self.lock:
            self.total += len(chunk)
            if self.keep == "head":
                room = self.limit - len(self.buffer)
                if room > 0:
                    self.buffer.extend(chunk[:room])
                return
            self.buffer.extend(chunk)
            if len(self.buffer) > self.limit * 2:
                del self.buffer[:-self.limit]

    def text(self) -> str:
        with self.lock:
            data = bytes(self.buffer)
            total = self.total
        if total > self.limit:
            data = data[-self.limit:] if self.keep == "tail" \
                else data[:self.limit]
        return data.decode("utf-8", "replace")

    def slice(self, offset: int) -> tuple:
        """``(текст с offset, общий размер)`` для инкрементального чтения."""
        with self.lock:
            data = bytes(self.buffer)
        offset = max(0, min(int(offset or 0), len(data)))
        return data[offset:].decode("utf-8", "replace"), len(data)

    @property
    def truncated(self) -> bool:
        with self.lock:
            return self.total > self.limit


# Потолки фильтра вывода: он работает в потоке чтения, и строк в
# include/exclude должно быть столько, чтобы проход по выводу
# оставался линейным и дешёвым на слабом роутере.
FILTER_MAX_TERMS = 16
FILTER_MAX_TERM_LEN = 200
FILTER_MAX_LINES = 100000
# Строка длиннее этого режется на куски: иначе один `cat` бинарника
# без переводов строки держал бы в памяти весь файл.
FILTER_LINE_BYTES = 65536


def parse_filter(raw) -> tuple:
    """Проверить ``filter`` из аргументов: ``(конфиг или None, отказ)``.

    Фильтр — замена пайпу ``| grep … | tail`` под ``shell_readonly``:
    строки отбираются **подстрокой**, не регулярным выражением. Регэксп
    от модели в потоке чтения — это катастрофический backtracking на
    ровном месте, а подстрока проходит вывод линейно. Регулярные
    выражения есть у самих программ: ``logread -e``, ``grep -E``.
    """
    if not raw:
        return None, None
    if not isinstance(raw, dict):
        return None, _refusal("filter должен быть объектом",
                              "filter={\"include\": [\"dnsmasq\"], "
                              "\"tail\": 50}")
    conf = {"include": [], "exclude": [],
            "ignore_case": bool(raw.get("ignore_case")),
            "count_only": bool(raw.get("count_only")),
            "head": 0, "tail": 0}
    for key in ("include", "exclude"):
        terms = raw.get(key) or []
        if isinstance(terms, str):
            terms = [terms]
        if not isinstance(terms, list) or len(terms) > FILTER_MAX_TERMS:
            return None, _refusal(
                "filter.%s — список не длиннее %d строк"
                % (key, FILTER_MAX_TERMS), "")
        for term in terms:
            term = str(term)
            if not term or len(term) > FILTER_MAX_TERM_LEN:
                return None, _refusal(
                    "filter.%s: пустая строка или длиннее %d символов"
                    % (key, FILTER_MAX_TERM_LEN), "")
            conf[key].append(term.lower() if conf["ignore_case"] else term)
    for key in ("head", "tail"):
        value = raw.get(key) or 0
        if not isinstance(value, int) or isinstance(value, bool) \
                or not 0 <= value <= FILTER_MAX_LINES:
            return None, _refusal(
                "filter.%s — целое от 1 до %d" % (key, FILTER_MAX_LINES), "")
        conf[key] = value
    if conf["head"] and conf["tail"]:
        return None, _refusal("filter.head и filter.tail вместе не "
                              "задаются", "оставьте одно из двух")
    return conf, None


class _LineFilter:
    """Построчный фильтр перед :class:`_Collector`.

    Стоит ДО обрезки: иначе ``logread`` на 109 КБ обрезался бы до
    хвоста ``output_kb``, и фильтр видел бы только его. Отобранные
    строки уходят в сборщик; ``count_only`` не отдаёт ни одной, только
    счётчики.
    """

    def __init__(self, collector, conf):
        self.collector = collector
        self.conf = conf
        self.partial = b""
        self.seen = 0
        self.matched = 0
        self.bytes_in = 0
        self.tail = collections.deque(maxlen=conf["tail"] or None) \
            if conf["tail"] else None
        self.lock = threading.Lock()

    @property
    def total(self):
        return self.collector.total

    def pump(self, stream):
        try:
            _Collector.pump(self, stream)
        finally:
            self.finish()

    def add(self, chunk: bytes):
        with self.lock:
            self.bytes_in += len(chunk)
            data = self.partial + chunk
            lines = data.split(b"\n")
            self.partial = lines.pop()
            while len(self.partial) > FILTER_LINE_BYTES:
                lines.append(self.partial[:FILTER_LINE_BYTES])
                self.partial = self.partial[FILTER_LINE_BYTES:]
            for line in lines:
                self._line(line)

    def finish(self):
        with self.lock:
            if self.partial:
                self._line(self.partial)
                self.partial = b""
            if self.tail:
                self.collector.add(b"".join(self.tail))
                self.tail.clear()

    def _line(self, line: bytes):
        self.seen += 1
        text = line.decode("utf-8", "replace")
        if self.conf["ignore_case"]:
            text = text.lower()
        include, exclude = self.conf["include"], self.conf["exclude"]
        if include and not any(term in text for term in include):
            return
        if exclude and any(term in text for term in exclude):
            return
        self.matched += 1
        if self.conf["count_only"]:
            return
        if self.tail is not None:
            self.tail.append(line + b"\n")
        elif not self.conf["head"] or self.matched <= self.conf["head"]:
            self.collector.add(line + b"\n")

    def stats(self) -> dict:
        with self.lock:
            return {"lines_seen": self.seen, "lines_matched": self.matched,
                    "bytes_seen": self.bytes_in}


def _reader(collector, plan):
    """Чем читать вывод: сборщиком или фильтром перед ним."""
    conf = plan.get("filter")
    return _LineFilter(collector, conf) if conf else collector


def environ() -> dict:
    """Окружение команды: минимальное и БЕЗ переменных процесса GUI."""
    return dict(BASE_ENV)


def workdir_for(requested: str = "") -> str:
    """Каталог запуска: запрошенный, настроенный или корень."""
    for candidate in (str(requested or ""), limits()["workdir"], "/"):
        if candidate and os.path.isdir(candidate):
            return candidate
    return "/"


def execute(plan: dict, timeout_sec: int = 0, workdir: str = "") -> dict:
    """Запустить готовый план синхронно и вернуть результат.

    Ответ одинаков при успехе и неуспехе: ``{ok, returncode, output,
    truncated, timed_out, duration_ms, command}``. ``ok`` — это
    «команда выполнилась сама», а не «вернула ноль»: ``grep``, ничего
    не нашедший, отвечает кодом 1, и ошибкой вызова это не является.
    """
    conf = limits()
    timeout = _timeout(timeout_sec, conf)
    cwd = workdir_for(workdir)
    if not _sync_lock.acquire(blocking=False):
        return _refusal(
            "уже выполняется другая команда",
            "синхронная команда идёт одна за раз: дождитесь ответа или "
            "запускайте долгое через shell_exec_async",
            busy=True)
    try:
        return _run_sync(plan, timeout, cwd, conf)
    finally:
        _sync_lock.release()


def _run_sync(plan, timeout, cwd, conf) -> dict:
    started = time.time()
    collector = _Collector(conf["output_kb"] * 1024, keep="tail")
    reader_sink = _reader(collector, plan)
    try:
        proc = _spawn(plan, cwd)
    except (OSError, ValueError) as e:
        return _refusal("команда не запустилась: %s" % e,
                        "проверьте, что программа установлена: "
                        "shell_exec(argv=[\"which\", \"%s\"])"
                        % plan["argv"][0],
                        command=plan["display"], returncode=-1,
                        output="", truncated=False, timed_out=False,
                        duration_ms=0)

    reader = threading.Thread(target=reader_sink.pump, args=(proc.stdout,),
                              daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_process(proc)
    reader.join(timeout=KILL_GRACE_SEC)

    result = _result(plan, proc.returncode, collector, timed_out, started,
                     timeout, cwd)
    if reader_sink is not collector:
        result["filter"] = dict(reader_sink.stats(), **plan["filter"])
    return result


def _result(plan, returncode, collector, timed_out, started, timeout,
            cwd) -> dict:
    output = redact_text(collector.text())
    result = {
        "ok": not timed_out,
        "returncode": returncode if returncode is not None else -1,
        "output": output,
        "output_bytes": collector.total,
        "truncated": collector.truncated,
        "timed_out": timed_out,
        "duration_ms": int((time.time() - started) * 1000),
        "command": plan["display"],
        "mode": plan["mode"],
        "safe_list": bool(plan.get("safe")),
        "workdir": cwd,
        "timeout_sec": timeout,
    }
    if timed_out:
        result["error"] = ("команда не уложилась в %d с и была прибита"
                           % timeout)
        result["hint"] = ("увеличьте timeout_sec (потолок — "
                          "mcp.shell.max_timeout_sec) или запустите её "
                          "через shell_exec_async")
    elif result["returncode"] != 0:
        result["hint"] = ("команда завершилась с кодом %d — это её "
                          "ответ, а не ошибка вызова"
                          % result["returncode"])
    if result["truncated"]:
        # Не `note`: там пометка «вывод — недоверенные данные», и
        # затирание оставило бы модель без одного из двух объяснений.
        result["output_note"] = ("вывод обрезан до mcp.shell.output_kb, "
                                 "сохранён ХВОСТ (%d байт всего)"
                                 % collector.total)
    return result


def _spawn(plan, cwd):
    """Запустить процесс отдельной сессией (чтобы убить всю группу)."""
    return subprocess.Popen(
        plan["argv"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=cwd,
        env=environ(),
        start_new_session=True,
        close_fds=True,
    )


def kill_process(proc) -> None:
    """SIGTERM всей группе, через паузу — SIGKILL."""
    for sig, wait in ((signal.SIGTERM, KILL_GRACE_SEC),
                      (signal.SIGKILL, 2)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _timeout(requested, conf) -> int:
    try:
        value = int(requested or 0)
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        value = conf["timeout_sec"]
    return max(1, min(value, conf["max_timeout_sec"]))


# ────────────────────────── фоновые задачи ──────────────────────────

def start_job(plan: dict, timeout_sec: int = 0, workdir: str = "",
              label: str = "") -> dict:
    """Запустить команду фоном и вернуть ярлык задачи."""
    conf = limits()
    timeout = _timeout(timeout_sec, conf)
    cwd = workdir_for(workdir)

    with _jobs_lock:
        active = [j for j in _JOBS.values() if not j["done"]]
        if len(active) >= conf["max_jobs"]:
            return _refusal(
                "уже выполняется %d фоновых команд (потолок "
                "mcp.shell.max_jobs)" % len(active),
                "дождитесь их (shell_job_status) или остановите лишние "
                "(shell_job_stop)",
                job_ids=[j["job_id"] for j in active])

    collector = _Collector(conf["output_kb"] * 1024 * ASYNC_BUFFER_FACTOR,
                           keep="head")
    try:
        proc = _spawn(plan, cwd)
    except (OSError, ValueError) as e:
        return _refusal("команда не запустилась: %s" % e, "",
                        command=plan["display"])

    job = {
        "job_id": "sh-%s" % uuid.uuid4().hex[:8],
        "command": plan["display"],
        "label": label,
        "mode": plan["mode"],
        "safe_list": bool(plan.get("safe")),
        "started_at": round(time.time(), 3),
        "finished_at": 0.0,
        "done": False,
        "returncode": None,
        "timed_out": False,
        "stopped": False,
        "timeout_sec": timeout,
        "workdir": cwd,
        "proc": proc,
        "collector": collector,
        "reader": _reader(collector, plan),
    }
    with _jobs_lock:
        _JOBS[job["job_id"]] = job
        _trim_jobs()

    threading.Thread(target=_watch_job, args=(job,), daemon=True).start()
    return {"ok": True, "async": True, "job_id": job["job_id"],
            "command": plan["display"], "timeout_sec": timeout,
            "workdir": cwd,
            "hint": "опрашивайте shell_job_status(job_id) и дочитывайте "
                    "вывод shell_job_output(job_id, offset)"}


def _watch_job(job):
    """Дождаться конца фоновой команды, собрав её вывод."""
    proc = job["proc"]
    reader = threading.Thread(target=job["reader"].pump,
                              args=(proc.stdout,), daemon=True)
    reader.start()
    try:
        proc.wait(timeout=job["timeout_sec"])
    except subprocess.TimeoutExpired:
        job["timed_out"] = True
        kill_process(proc)
    reader.join(timeout=KILL_GRACE_SEC)
    job["returncode"] = proc.returncode if proc.returncode is not None else -1
    job["finished_at"] = round(time.time(), 3)
    job["done"] = True


def job_status(job_id: str) -> dict:
    """Состояние фоновой задачи (или отказ, если ярлыка нет)."""
    job, refusal = _job(job_id)
    if refusal:
        return refusal
    return _job_view(job)


def job_output(job_id: str, offset: int = 0) -> dict:
    """Инкрементальный вывод задачи: с ``offset`` до конца буфера."""
    job, refusal = _job(job_id)
    if refusal:
        return refusal
    text, size = job["collector"].slice(offset)
    result = _job_view(job)
    result.update({
        "output": redact_text(text),
        "offset": max(0, min(int(offset or 0), size)),
        "next_offset": size,
        "output_bytes": job["collector"].total,
        "truncated": job["collector"].truncated,
    })
    if result["truncated"]:
        result["output_note"] = ("вывод длиннее буфера задачи: сохранено "
                                 "начало, хвост потерян (всего %d байт)"
                                 % job["collector"].total)
    return result


def job_stop(job_id: str) -> dict:
    """Прибить фоновую задачу (SIGTERM группе, затем SIGKILL)."""
    job, refusal = _job(job_id)
    if refusal:
        return refusal
    if job["done"]:
        result = _job_view(job)
        result["stopped"] = False
        result["hint"] = "задача уже завершилась — останавливать нечего"
        return result
    job["stopped"] = True
    kill_process(job["proc"])
    time.sleep(0.05)
    result = _job_view(job)
    result["hint"] = ("задача остановлена; собранный вывод остаётся "
                      "читаемым через shell_job_output")
    return result


def _job_view(job) -> dict:
    view = {
        "ok": True,
        "job_id": job["job_id"],
        "command": job["command"],
        "label": job["label"],
        "done": job["done"],
        "running": not job["done"],
        "returncode": job["returncode"],
        "timed_out": job["timed_out"],
        "stopped": job["stopped"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "duration_ms": int(((job["finished_at"] or time.time())
                            - job["started_at"]) * 1000),
        "output_bytes": job["collector"].total,
        "workdir": job["workdir"],
        "timeout_sec": job["timeout_sec"],
    }
    if job.get("reader") is not None \
            and job["reader"] is not job["collector"]:
        view["filter"] = job["reader"].stats()
    return view


def _job(job_id):
    with _jobs_lock:
        job = _JOBS.get(str(job_id or ""))
        known = sorted(_JOBS)
    if job is None:
        return None, _refusal(
            "задачи %s нет" % job_id,
            "известные задачи: %s" % (", ".join(known) or "ни одной — "
                                      "ярлыки живут в памяти процесса GUI"),
            known_job_ids=known)
    return job, None


def jobs() -> list:
    """Все известные фоновые задачи, новые первыми."""
    with _jobs_lock:
        items = list(_JOBS.values())
    items.sort(key=lambda j: j["started_at"], reverse=True)
    return [_job_view(j) for j in items]


# Сколько завершённых задач помним: модель опрашивает статус и через
# минуту после конца, «задачи нет» она прочитает как «прогон потерян».
JOBS_KEEP = 16


def _trim_jobs():
    """Выкинуть старые ЗАВЕРШЁННЫЕ задачи (вызывать под ``_jobs_lock``)."""
    done = sorted((j for j in _JOBS.values() if j["done"]),
                  key=lambda j: j["finished_at"])
    for job in done[:max(0, len(_JOBS) - JOBS_KEEP)]:
        _JOBS.pop(job["job_id"], None)


def reset_jobs():
    """Забыть все задачи (нужно тестам)."""
    with _jobs_lock:
        _JOBS.clear()


# ──────────────────────── подтверждения ─────────────────────────────

_confirm_lock = threading.Lock()
_CONFIRMS = {}


def pending_confirm(kind, summary, consequences, *, scope="",
                    payload=None, action=None, rules=()) -> dict:
    """Завести одноразовый токен и вернуть готовый отказ-приглашение.

    Токен живёт в памяти процесса: 60 секунд переживать перезапуск GUI
    незачем, а вот «подтверждение, валяющееся на диске сутки» — это
    заряженное ружьё.
    """
    token = "cf-%s" % uuid.uuid4().hex[:10]
    record = {
        "token": token,
        "kind": str(kind),
        "summary": str(summary),
        "scope": str(scope or ""),
        "payload": dict(payload or {}),
        "action": action,
        "created_at": round(time.time(), 3),
        "expires_at": round(time.time() + CONFIRM_TTL_SEC, 3),
    }
    with _confirm_lock:
        _expire_confirms()
        _CONFIRMS[token] = record
    return {
        "ok": False,
        "need_confirm": True,
        "confirm_token": token,
        "expires_in_sec": CONFIRM_TTL_SEC,
        "matched_rules": [r.get("code") for r in rules],
        "command": str(summary),
        "consequences": str(consequences),
        "error": "команда требует подтверждения: %s" % consequences,
        "hint": "повторите через shell_confirm(confirm_token=\"%s\"), "
                "если уверены; токен одноразовый и живёт %d секунд"
                % (token, CONFIRM_TTL_SEC),
    }


def take_confirm(token: str):
    """Забрать токен подтверждения (одноразово): ``(запись, отказ)``."""
    token = str(token or "").strip()
    with _confirm_lock:
        _expire_confirms()
        record = _CONFIRMS.pop(token, None)
    if record is None:
        return None, _refusal(
            "подтверждение %s не найдено или просрочено" % token,
            "токен одноразовый и живёт %d секунд — повторите исходный "
            "вызов и подтвердите свежим токеном" % CONFIRM_TTL_SEC)
    return record, None


def list_confirms() -> list:
    """Ожидающие подтверждения, старые первыми — без самих команд-данных.

    Нужно странице MCP (S15): человек видит, что модель просит
    подтвердить, и решает сам, а не ждёт, пока модель повторит вызов с
    токеном. Отдаём то же, что видела бы модель в отказе, плюс
    остаток жизни токена.
    """
    now = time.time()
    with _confirm_lock:
        _expire_confirms()
        records = sorted(_CONFIRMS.values(), key=lambda r: r["created_at"])
        return [{
            "token": r["token"],
            "kind": r["kind"],
            "summary": r["summary"],
            "scope": r["scope"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "expires_in_sec": max(0, int(r["expires_at"] - now)),
        } for r in records]


def drop_confirm(token: str) -> bool:
    """Отклонить ожидающее подтверждение: ``True``, если оно было."""
    token = str(token or "").strip()
    with _confirm_lock:
        _expire_confirms()
        return _CONFIRMS.pop(token, None) is not None


def run_confirmed(record: dict) -> dict:
    """Выполнить подтверждённую запись: своё действие или команду.

    Одна точка на обе двери — инструмент ``shell_confirm`` и кнопку
    «Подтвердить» на странице MCP. Разрешение проверяет вызывающий:
    токен сам по себе прав не даёт.
    """
    action = (record or {}).get("action")
    if callable(action):
        return action(record)
    return run_pending(record)


def _expire_confirms():
    now = time.time()
    for token, record in list(_CONFIRMS.items()):
        if record["expires_at"] <= now:
            _CONFIRMS.pop(token, None)


def reset_confirms():
    """Забыть все токены (нужно тестам)."""
    with _confirm_lock:
        _CONFIRMS.clear()


def stop_all_jobs() -> list:
    """Прибить все живые фоновые задачи; вернуть их состояние.

    Кнопка «Запретить shell немедленно» (S15): снять разрешения мало —
    уже запущенная асинхронная команда продолжает работать, и отбирать
    доступ, оставив её в живых, значит обещать то, чего не сделано.
    """
    with _jobs_lock:
        alive = [j["job_id"] for j in _JOBS.values() if not j["done"]]
    return [job_stop(job_id) for job_id in alive]


# ───────────────────────── дедмен-свитч ─────────────────────────────

_guard_lock = threading.RLock()
_TIMERS = {}


def guards_path() -> str:
    """Файл дедмен-свитчей — рядом с settings.json, а не в /tmp."""
    from core import platform_dirs
    return os.path.join(platform_dirs.config_dir(), GUARDS_NAME)


def read_guards() -> list:
    path = guards_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    entries = data.get("entries") if isinstance(data, dict) else None
    return [e for e in entries if isinstance(e, dict)] \
        if isinstance(entries, list) else []


def _write_guards(entries: list):
    path = guards_path()
    if not os.path.isdir(os.path.dirname(path)):
        return
    try:
        atomic_write_text(path, json.dumps(
            {"version": 1, "entries": entries[-32:]},
            ensure_ascii=False, default=str))
    except (OSError, TypeError, ValueError) as e:
        log.debug("Дедмен: снимок не записан: %s" % e, source=SOURCE)


def _put_guard(entry: dict):
    with _guard_lock:
        entries = [e for e in read_guards()
                   if e.get("run_id") != entry.get("run_id")]
        entries.append(entry)
        _write_guards(entries)


def _update_guard(run_id: str, **fields):
    with _guard_lock:
        entries = read_guards()
        for entry in entries:
            if entry.get("run_id") == run_id:
                entry.update(fields)
        _write_guards(entries)


def get_guard(run_id: str) -> dict:
    for entry in read_guards():
        if entry.get("run_id") == run_id:
            return entry
    return {}


def armed_guards() -> list:
    """Заряженные дедмены: что откатится и когда."""
    now = time.time()
    out = []
    for entry in read_guards():
        if entry.get("state") != "armed":
            continue
        item = dict(entry)
        item["expires_in_sec"] = max(0, int(entry.get("expires_at", 0) - now))
        out.append(item)
    return out


def check_guard(guard, required: bool) -> tuple:
    """Проверить параметр ``guard``: ``(нормализованный, отказ)``."""
    conf = limits()
    if not guard:
        if not required:
            return None, None
        return None, _refusal(
            "команда трогает сеть и без guard не выполняется",
            "добавьте guard={\"revert_cmd\": \"<чем вернуть>\", "
            "\"ttl_sec\": %d} — если не придёт "
            "shell_confirm(run_id=…), revert_cmd выполнится сам и "
            "вернёт доступ" % conf["guard_default_ttl_sec"],
            need_guard=True)
    if not isinstance(guard, dict):
        return None, _refusal("guard должен быть объектом",
                              "guard={\"revert_cmd\": \"…\", "
                              "\"ttl_sec\": 120}")
    revert = str(guard.get("revert_cmd") or "").strip()
    if not revert:
        return None, _refusal("в guard не указан revert_cmd",
                              "revert_cmd — команда, возвращающая "
                              "доступ (перезапуск сети, firewall, "
                              "интерфейса)")
    deny = deny_reason(revert)
    if deny:
        return None, _refusal(
            "revert_cmd сам попадает под запрет «%s»" % deny["code"],
            deny["why"])
    try:
        ttl = int(guard.get("ttl_sec") or conf["guard_default_ttl_sec"])
    except (TypeError, ValueError):
        ttl = conf["guard_default_ttl_sec"]
    ttl = max(10, min(ttl, conf["max_timeout_sec"] * 4))
    return {"revert_cmd": revert, "ttl_sec": ttl}, None


def arm_guard(guard: dict, command: str = "") -> dict:
    """Зарядить дедмен и вернуть его описание."""
    run_id = "sh-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"),
                           uuid.uuid4().hex[:4])
    entry = {
        "run_id": run_id,
        "command": str(command),
        "revert_cmd": guard["revert_cmd"],
        "ttl_sec": guard["ttl_sec"],
        "created_at": round(time.time(), 3),
        "expires_at": round(time.time() + guard["ttl_sec"], 3),
        "state": "armed",
        "pid": os.getpid(),
    }
    _put_guard(entry)
    _arm_timer(run_id, guard["ttl_sec"])
    log.warning("Дедмен %s заряжен на %d с: «%s» вернёт «%s»"
                % (run_id, guard["ttl_sec"], command, guard["revert_cmd"]),
                source=SOURCE)
    return {"run_id": run_id, "ttl_sec": guard["ttl_sec"],
            "revert_cmd": guard["revert_cmd"],
            "expires_at": entry["expires_at"]}


def _arm_timer(run_id: str, delay: float):
    with _guard_lock:
        old = _TIMERS.pop(run_id, None)
        if old is not None:
            old.cancel()
        timer = threading.Timer(max(0.0, delay), fire_guard, args=(run_id,))
        timer.daemon = True
        _TIMERS[run_id] = timer
        timer.start()


def cancel_guard(run_id: str) -> dict:
    """Снять дедмен: команда подтверждена, откатывать нечего."""
    run_id = str(run_id or "").strip()
    entry = get_guard(run_id)
    if not entry:
        armed = [e["run_id"] for e in armed_guards()]
        return _refusal(
            "дедмена %s нет" % run_id,
            "заряженные сейчас: %s" % (", ".join(armed) or "ни одного"),
            armed=armed)
    with _guard_lock:
        timer = _TIMERS.pop(run_id, None)
        if timer is not None:
            timer.cancel()
    if entry.get("state") != "armed":
        return {"ok": True, "run_id": run_id, "cancelled": False,
                "state": entry.get("state"),
                "hint": "дедмен уже сработал (%s): revert_cmd выполнен"
                        % entry.get("state")}
    _update_guard(run_id, state="confirmed",
                  confirmed_at=round(time.time(), 3))
    log.info("Дедмен %s снят подтверждением" % run_id, source=SOURCE)
    return {"ok": True, "run_id": run_id, "cancelled": True,
            "state": "confirmed", "command": entry.get("command", ""),
            "hint": "откат отменён: команда подтверждена"}


def fire_guard(run_id: str) -> dict:
    """Сработать дедмену: выполнить ``revert_cmd``.

    Зовётся таймером и :func:`recover_guards`. Идемпотентна: снимок на
    диске — единственный источник правды, и второй вызов ничего не
    повторит.
    """
    with _guard_lock:
        _TIMERS.pop(run_id, None)
        entry = get_guard(run_id)
        if not entry or entry.get("state") != "armed":
            return {"ok": True, "fired": False,
                    "reason": "дедмен уже снят или сработал"}
        _update_guard(run_id, state="firing")

    revert = entry.get("revert_cmd", "")
    log.warning("Дедмен %s сработал: подтверждения не было, выполняем "
                "«%s»" % (run_id, revert), source=SOURCE)
    plan, refusal = plan_command(revert, full=True)
    if refusal:
        _update_guard(run_id, state="failed", error=refusal.get("error", ""))
        return {"ok": False, "fired": False, "error": refusal.get("error")}

    # Намеренно мимо `execute`: её мьютекс «одна синхронная команда за
    # раз» не должен откладывать возврат доступа. Дедмен срабатывает
    # именно тогда, когда что-то пошло не так и кто-то ещё висит.
    conf = limits()
    result = _run_sync(plan, _timeout(0, conf), workdir_for(), conf)
    _update_guard(run_id, state="fired", fired_at=round(time.time(), 3),
                  returncode=result.get("returncode"),
                  output=result.get("output", "")[-1000:])
    _journal_guard(run_id, entry, result)
    return {"ok": bool(result.get("ok")), "fired": True, "run_id": run_id,
            "returncode": result.get("returncode"),
            "output": result.get("output", "")}


def _journal_guard(run_id, entry, result):
    """Событие дедмена — в журнал MCP: его смотрят, когда «само упало»."""
    try:
        from core.mcp import audit
        audit.begin("shell_guard_revert")
        audit.record("shell_guard_revert", scope="shell_full",
                     mutating=True,
                     args={"run_id": run_id,
                           "command": entry.get("command", ""),
                           "revert_cmd": entry.get("revert_cmd", "")},
                     status=audit.STATUS_OK if result.get("ok")
                     else audit.STATUS_ERROR,
                     ok=bool(result.get("ok")),
                     error="" if result.get("ok") else "revert не удался",
                     elapsed_ms=result.get("duration_ms", 0))
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Дедмен: запись в журнал не удалась: %s" % e,
                  source=SOURCE)


def recover_guards(source: str = SOURCE) -> dict:
    """Перезарядить дедмены после перезапуска GUI.

    Таймер в памяти процесса, который сам же и упал, не откатывает
    ничего — поэтому дедмены лежат на диске. Просроченные исполняем
    немедленно: раз никто не подтвердил, доступ надо возвращать.
    """
    now = time.time()
    fired, rearmed = [], []
    for entry in read_guards():
        if entry.get("state") != "armed":
            continue
        run_id = entry.get("run_id", "")
        left = float(entry.get("expires_at", 0)) - now
        if left <= 0:
            log.warning("Дедмен %s пережил перезапуск GUI и просрочен: "
                        "откатываем" % run_id, source=source)
            fire_guard(run_id)
            fired.append(run_id)
        else:
            _arm_timer(run_id, left)
            rearmed.append(run_id)
    return {"ok": True, "fired": fired, "rearmed": rearmed,
            "recovered": bool(fired or rearmed)}


def reset_guards():
    """Снять все таймеры (нужно тестам; файл не трогаем)."""
    with _guard_lock:
        for timer in _TIMERS.values():
            timer.cancel()
        _TIMERS.clear()


# ───────────────────────── общий вход ───────────────────────────────

def run_command(command="", argv=None, *, full=False, timeout_sec=0,
                workdir="", guard=None, background=False, label="",
                scope="", line_filter=None) -> dict:
    """Проверить команду и выполнить её (или вернуть, чего не хватает).

    Порядок проверок неслучаен: **запрет** (не обходится ничем) →
    **guard** (без него сетевую команду не выполняем вовсе) →
    **подтверждение** (второй шаг). Если бы подтверждение шло раньше
    guard'а, модель получала бы токен, подтверждала — и только тогда
    узнавала, что нужен ещё и дедмен.
    """
    filter_conf, refusal = parse_filter(line_filter)
    if refusal:
        return refusal
    plan, refusal = plan_command(command, argv, full=full)
    if refusal:
        return refusal
    if filter_conf:
        plan["filter"] = filter_conf

    deny = deny_reason(plan["normalized"])
    if deny:
        return _refusal(
            "команда запрещена правилом «%s»" % deny["code"],
            "%s. Это правило не обходится подтверждением: такие вещи "
            "делаются руками, с консолью под рукой" % deny["why"],
            denied=True, rule=deny["code"], command=plan["display"])

    rules = confirm_rules(plan["normalized"])
    needs_guard = any(r["network"] for r in rules)
    checked, refusal = check_guard(guard, needs_guard)
    if refusal:
        refusal["command"] = plan["display"]
        refusal["matched_rules"] = [r["code"] for r in rules]
        return refusal

    if rules:
        # Подтверждать команду должно то же разрешение, каким её
        # запускали: иначе shell_readonly подтверждал бы то, что сам
        # выполнить не может.
        token_scope = scope or ("shell_readonly" if plan["safe"]
                                else "shell_full")
        return pending_confirm(
            "command", plan["display"],
            "; ".join(r["why"] for r in rules),
            scope=token_scope, rules=rules,
            payload={"argv": plan["argv"], "mode": plan["mode"],
                     "display": plan["display"], "safe": plan["safe"],
                     "normalized": plan["normalized"],
                     "filter": plan.get("filter"),
                     "timeout_sec": timeout_sec, "workdir": workdir,
                     "background": background, "label": label,
                     "guard": checked})

    return _execute_plan(plan, timeout_sec, workdir, checked, background,
                         label)


def run_pending(record: dict) -> dict:
    """Выполнить то, что было отложено до подтверждения."""
    payload = record.get("payload") or {}
    plan = {"mode": payload.get("mode", "argv"),
            "argv": list(payload.get("argv") or []),
            "display": payload.get("display", ""),
            "safe": bool(payload.get("safe")),
            "normalized": payload.get("normalized", ""),
            "filter": payload.get("filter")}
    if not plan["argv"]:
        return _refusal("подтверждать нечего: в токене нет команды", "")
    result = _execute_plan(plan, payload.get("timeout_sec", 0),
                           payload.get("workdir", ""),
                           payload.get("guard"),
                           bool(payload.get("background")),
                           payload.get("label", ""))
    result["confirmed"] = True
    return result


def _execute_plan(plan, timeout_sec, workdir, guard, background, label):
    """Исполнить план и, если надо, зарядить дедмен."""
    if background:
        result = start_job(plan, timeout_sec, workdir, label=label)
    else:
        result = execute(plan, timeout_sec, workdir)
    if guard and result.get("ok"):
        armed = arm_guard(guard, plan["display"])
        result.update({
            "run_id": armed["run_id"],
            "guard_expires_in": armed["ttl_sec"],
            "revert_cmd": armed["revert_cmd"],
        })
        result["hint"] = (
            "дедмен заряжен: через %d с выполнится «%s», если не придёт "
            "shell_confirm(run_id=\"%s\"). Проверьте связь и подтвердите."
            % (armed["ttl_sec"], armed["revert_cmd"], armed["run_id"]))
    return result
