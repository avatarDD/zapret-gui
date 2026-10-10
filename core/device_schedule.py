# core/device_schedule.py
"""
Расписание обхода по устройствам: в заданные часы выбранные устройства
идут МИМО nfqws2, остальные — с обходом всегда (issue #381).

Пример: детские смартфоны и телевизор днём без обхода (YouTube через
nfqws2 у них не работает), вечером — как все.

Механизм — то же connmark-исключение, которым основной firewall уводит
мимо очереди пробы GUI и устройства политики Keenetic
(`nfqws.desync_mark_postnat`, бит 0x20000000):

  • iptables: своя цепочка `mangle zgui_sched` с прыжком из PREROUTING.
    Пакет устройства с LAN (до NAT, источник — его адрес) метит соединение
    CONNMARK-исключением; POSTROUTING основного firewall по этой метке
    возвращает исходящие пакеты, PREROUTING — ответы. IPv4 и IPv6 —
    iptables и ip6tables.
  • nftables: своя таблица `inet zgui_sched` с prerouting-цепочкой
    раньше нашей основной (priority -160 против -150), `ct mark set`.

Правила держим отдельно от `core/firewall.py`: основной набор не
пересобирается каждую минуту, а планировщик сам проверяет на каждом
тике, что его правила на месте (прошивка Keenetic сбрасывает netfilter
при reload), и возвращает их.

Устройство задаётся IP (v4/v6, можно подсеть) или MAC. MAC переводим в
текущие адреса по таблице соседей (`ip neigh`, запасной путь —
/proc/net/arp) — так ловится и IPv6 устройства, и смена адреса по DHCP,
а модуль `xt_mac` (которого на Keenetic может не быть) не нужен.

Снятие правил не полагается на память процесса: после перезапуска GUI
посреди окна или частичного сбоя применения первый же тик вне окна
снимает цепочку/таблицу, если она есть.

Время — локальное время роутера. На Entware часовой пояс в окружении
Python бывает не задан (тогда это UTC), поэтому есть ручной сдвиг
`tz_offset` («+03:00»), а UI показывает «сейчас на роутере».

Уже установленное соединение исключение не обрывает: начало окна
действует на НОВЫЕ соединения (видео, начатое до окна, может доиграть),
а соединение, начатое в окне, остаётся без обхода до своего закрытия.

Настройки — `firewall.device_schedule` (enabled, tz_offset, rules).
"""

import ipaddress
import re
import shutil
import subprocess
import threading
import time

from core.log_buffer import log


CHAIN = "zgui_sched"           # iptables: цепочка в mangle
NFT_TABLE = "zgui_sched"       # nftables: таблица inet
_CHECK_INTERVAL = 30           # секунд между тиками

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_HHMM_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_TZ_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

DAY_NAMES = ("Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс")
MAX_RULES = 32
MAX_DEVICES = 64


# ─────────────────────────── разбор и проверка ───────────────────────────

def parse_hhmm(text):
    """«8:05» → 485 (минуты от полуночи); мусор → None."""
    m = _HHMM_RE.match(str(text or "").strip())
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def parse_tz_offset(text):
    """«+03:00» / «-5» / «+0530» → минуты; пусто → None (время системы).

    Неверная строка → ValueError.
    """
    text = str(text or "").strip()
    if not text:
        return None
    m = _TZ_RE.match(text)
    if not m:
        raise ValueError("сдвиг часового пояса — вида +03:00")
    hours, mins = int(m.group(2)), int(m.group(3) or 0)
    if hours > 14 or mins > 59:
        raise ValueError("сдвиг часового пояса вне диапазона")
    total = hours * 60 + mins
    return -total if m.group(1) == "-" else total


def normalize_device(token):
    """IP/подсеть → канонический вид, MAC → «aa:bb:…» в нижнем регистре.

    Возвращает ``("ip"|"mac", value)``; неверное → ValueError.
    """
    text = str(token or "").strip().lower().replace("-", ":")
    if not text:
        raise ValueError("пустое устройство")
    if _MAC_RE.match(text):
        return "mac", text
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError("«%s» — не IP-адрес, не подсеть и не MAC" % token)
    if net.prefixlen == net.max_prefixlen:
        return "ip", str(net.network_address)
    return "ip", str(net)


def normalize_rule(rule):
    """Привести правило к каноническому виду. Ошибки → ValueError."""
    if not isinstance(rule, dict):
        raise ValueError("правило — объект")
    name = str(rule.get("name") or "").strip()[:64]
    start = parse_hhmm(rule.get("from"))
    end = parse_hhmm(rule.get("to"))
    if start is None or end is None:
        raise ValueError("«%s»: время — вида ЧЧ:ММ" % (name or "правило"))
    days = rule.get("days")
    if days in (None, ""):
        days = []
    if not isinstance(days, list):
        raise ValueError("days — список дней 1..7")
    norm_days = []
    for d in days:
        try:
            d = int(d)
        except (TypeError, ValueError):
            raise ValueError("день недели — число 1..7")
        if not 1 <= d <= 7:
            raise ValueError("день недели — число 1..7")
        if d not in norm_days:
            norm_days.append(d)
    devices = rule.get("devices") or []
    if isinstance(devices, str):
        devices = re.split(r"[\s,;]+", devices)
    if not isinstance(devices, list):
        raise ValueError("devices — список IP/MAC")
    norm_devices = []
    for token in devices:
        if not str(token or "").strip():
            continue
        _, value = normalize_device(token)
        if value not in norm_devices:
            norm_devices.append(value)
    if not norm_devices:
        raise ValueError("«%s»: не указано ни одного устройства"
                         % (name or "правило"))
    if len(norm_devices) > MAX_DEVICES:
        raise ValueError("слишком много устройств в правиле (> %d)"
                         % MAX_DEVICES)
    return {
        "name": name,
        "enabled": bool(rule.get("enabled", True)),
        "devices": norm_devices,
        "days": sorted(norm_days),
        "from": "%02d:%02d" % divmod(start, 60),
        "to": "%02d:%02d" % divmod(end, 60),
    }


def normalize_settings(data):
    """Проверить весь блок настроек. Ошибки → ValueError."""
    if not isinstance(data, dict):
        raise ValueError("ожидается объект")
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        raise ValueError("rules — список")
    if len(rules) > MAX_RULES:
        raise ValueError("слишком много правил (> %d)" % MAX_RULES)
    tz = str(data.get("tz_offset") or "").strip()
    parse_tz_offset(tz)
    return {
        "enabled": bool(data.get("enabled", False)),
        "tz_offset": tz,
        "rules": [normalize_rule(r) for r in rules],
    }


# ─────────────────────────── время и окна ───────────────────────────

def local_now(tz_offset="", now=None):
    """(ISO-день 1..7, минута суток) по времени роутера или сдвигу."""
    ts = time.time() if now is None else now
    minutes = parse_tz_offset(tz_offset)
    if minutes is None:
        tm = time.localtime(ts)
    else:
        tm = time.gmtime(ts + minutes * 60)
    return tm.tm_wday + 1, tm.tm_hour * 60 + tm.tm_min


def rule_active(rule, day, minute):
    """Действует ли правило в день ``day`` (1..7) и минуту ``minute``.

    from < to — окно внутри дня; from > to — через полночь (день окна —
    день его начала); from == to — весь день. Пустые days — каждый день.
    """
    if not rule.get("enabled", True):
        return False
    start, end = parse_hhmm(rule.get("from")), parse_hhmm(rule.get("to"))
    if start is None or end is None:
        return False
    days = rule.get("days") or list(range(1, 8))
    if start == end:
        return day in days
    if start < end:
        return day in days and start <= minute < end
    prev_day = 7 if day == 1 else day - 1
    return ((day in days and minute >= start)
            or (prev_day in days and minute < end))


def active_devices(rules, day, minute):
    """Устройства (IP/подсети и MAC) всех действующих сейчас правил."""
    out = []
    for rule in rules or []:
        if rule_active(rule, day, minute):
            for dev in rule.get("devices") or []:
                if dev not in out:
                    out.append(dev)
    return out


# ─────────────────────────── MAC → адреса ───────────────────────────

def parse_ip_neigh(text):
    """Вывод `ip neigh show` → [(ip, mac)]; без lladdr — пропускаем."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or "lladdr" not in parts:
            continue
        i = parts.index("lladdr")
        if i + 1 >= len(parts):
            continue
        mac = parts[i + 1].lower()
        if _MAC_RE.match(mac):
            out.append((parts[0], mac))
    return out


def resolve_addresses(devices, neigh, known=None):
    """Устройства → {"4": [...], "6": [...]} адресов/подсетей.

    ``neigh`` — пары (ip, mac) из таблицы соседей, ``known`` — то же из
    списка устройств GUI. IPv6 link-local (fe80::/10) не берём: в
    интернет с него не ходят.
    """
    pairs = list(neigh or []) + list(known or [])
    fam = {"4": [], "6": []}

    def add(value):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return
        if net.version == 6 and net.network_address.is_link_local:
            return
        text = (str(net.network_address)
                if net.prefixlen == net.max_prefixlen else str(net))
        bucket = fam[str(net.version)]
        if text not in bucket:
            bucket.append(text)

    for dev in devices or []:
        if _MAC_RE.match(dev):
            for ip, mac in pairs:
                if mac == dev:
                    add(ip)
        else:
            add(dev)
    return fam


# ─────────────────────────── команды firewall ───────────────────────────

def ipt_rule_args(addr, mark):
    """Аргументы правила цепочки для одного адреса (без iptables -t …)."""
    return ["-s", addr, "-j", "CONNMARK", "--set-xmark",
            "%s/%s" % (mark, mark)]


def nft_script(addrs, mark):
    """Скрипт для `nft -f -`: таблица целиком, пересоздаётся атомарно."""
    lines = [
        "add table inet %s" % NFT_TABLE,
        "delete table inet %s" % NFT_TABLE,
        "table inet %s {" % NFT_TABLE,
        "  chain prerouting {",
        "    type filter hook prerouting priority -160; policy accept;",
    ]
    for fam, kw in (("4", "ip"), ("6", "ip6")):
        if addrs.get(fam):
            lines.append("    %s saddr { %s } ct mark set ct mark or %s"
                         % (kw, ", ".join(addrs[fam]), mark))
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def _run(args, input_text=None, timeout=10):
    try:
        r = subprocess.run(args, input=input_text, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _ipt(cmd, quiet=False):
    """iptables с `-w` по детекции основного firewall.

    Свой запуск, а не FirewallManager._run_cmd: проверки «есть ли
    цепочка/прыжок» (-N/-C/-S/-D) падают штатно, и каждая такая неудача
    писала бы предупреждение в лог раз в тик.
    """
    from core.firewall import FirewallManager
    if "-w" not in cmd:
        cmd = [cmd[0]] + FirewallManager._iptables_wait_flag(cmd[0]) + cmd[1:]
    rc, _, err = _run(cmd)
    if rc != 0 and not quiet:
        log.warning("расписание устройств: %s: %s"
                    % (" ".join(cmd[:4]), err.strip()), source="firewall")
    return rc == 0


# ─────────────────────────── планировщик ───────────────────────────

def parse_proc_arp(text):
    """/proc/net/arp → [(ip, mac)] — запасной путь, если нет `ip neigh`."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and _MAC_RE.match(parts[3].lower()) \
                and parts[3] != "00:00:00:00:00:00":
            out.append((parts[0], parts[3].lower()))
    return out


def read_neighbors():
    """Пары (ip, mac) соседей роутера — IPv4 и IPv6.

    Только таблица соседей, без DHCP-аренд и опроса NDM: устройство,
    которое сейчас ходит через роутер, в ней есть всегда (роутер обязан
    знать его MAC, чтобы ответить), а аренда может быть устаревшей и
    указывать на чужой IP. Дёшево — годится для тика раз в 30 секунд.
    """
    rc, out, _ = _run(["ip", "neigh", "show"], timeout=5)
    if rc == 0:
        return parse_ip_neigh(out)
    try:
        with open("/proc/net/arp") as f:
            return parse_proc_arp(f.read())
    except OSError:
        return []


def load_settings(raw):
    """Настройки из settings.json — терпимо к ошибкам.

    → (рабочие настройки, правила для формы, ошибки). Битое правило не
    обнуляет расписание: оно не действует, а в форму уходит как есть с
    полем ``error`` — пользователь видит, что чинить, и сохранение его
    не теряет молча (сервер не примет правило, пока его не исправят).
    """
    raw = raw if isinstance(raw, dict) else {}
    errors = []
    tz = str(raw.get("tz_offset") or "").strip()
    try:
        parse_tz_offset(tz)
    except ValueError as e:
        errors.append("tz_offset: %s" % e)
        tz = ""
    rules, form = [], []
    raw_rules = raw.get("rules")
    for rule in (raw_rules if isinstance(raw_rules, list) else [])[:MAX_RULES]:
        try:
            norm = normalize_rule(rule)
        except ValueError as e:
            errors.append(str(e))
            bad = dict(rule) if isinstance(rule, dict) else {}
            bad["error"] = str(e)
            form.append(bad)
            continue
        rules.append(norm)
        form.append(norm)
    work = {"enabled": bool(raw.get("enabled", False)), "tz_offset": tz,
            "rules": rules}
    return work, form, errors


class DeviceScheduler:
    """Фоновый поток: раз в _CHECK_INTERVAL сверяет правила с расписанием.

    Поток работает всегда, пока жив GUI: выключенное расписание стоит
    одного чтения настроек за тик, зато расписание, включённое любым
    путём (импорт настроек, восстановление бэкапа), начинает действовать
    без перезапуска.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._apply_lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._applied = None        # {"4": [...], "6": [...]} или None
        # Могут ли в системе стоять наши правила. Изначально — да: их мог
        # оставить прошлый процесс GUI (перезапуск посреди окна), а после
        # частичного сбоя применения часть правил стоит, хотя _applied
        # пуст. Сбрасывается только успешным снятием.
        self._maybe_installed = True
        self._backend = ""
        self._last_error = ""
        self._unresolved = []
        self._warned = set()

    # ── настройки ──

    def _load(self):
        from core.config_manager import get_config_manager
        raw = get_config_manager().get("firewall", "device_schedule",
                                       default={}) or {}
        work, form, errors = load_settings(raw)
        for msg in errors:
            if msg not in self._warned:   # не раз в тик — один раз
                self._warned.add(msg)
                log.warning("расписание устройств: %s — правило не "
                            "действует" % msg, source="firewall")
        return work, form, errors

    def settings(self):
        """Рабочие настройки: только правила, прошедшие проверку."""
        return self._load()[0]

    def form_settings(self):
        """Настройки для формы: все правила, битые — с полем error."""
        work, form, errors = self._load()
        return {"enabled": work["enabled"], "tz_offset": work["tz_offset"],
                "rules": form, "errors": errors}

    @staticmethod
    def _mark():
        from core.config_manager import get_config_manager
        from core.firewall import normalize_mark
        cfg = get_config_manager()
        return normalize_mark(cfg.get("nfqws", "desync_mark_postnat",
                                      default="0x20000000")) or "0x20000000"

    # ── жизненный цикл ──

    def reconfigure(self, apply_now=False):
        """Поднять поток (если не поднят); apply_now — тик сразу.

        При старте GUI тик идёт в потоке (не держит запуск), из API —
        сразу, чтобы ответ показывал уже применённое состояние.
        """
        self._start()
        if apply_now:
            self.tick()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            t = threading.Thread(target=self._run_loop, args=(stop_evt,),
                                 name="device-schedule", daemon=True)
            t.start()
            self._thread = t

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None

    def _run_loop(self, stop_evt):
        while not stop_evt.is_set():
            try:
                self.tick(stop_evt)
            except Exception as e:
                log.warning("расписание устройств: %s" % e, source="firewall")
            stop_evt.wait(_CHECK_INTERVAL)

    # ── тик ──

    def desired(self, st=None, now=None):
        """Какие адреса сейчас должны идти мимо обхода.

        → (адреса {"4": [...], "6": [...]}, MAC без найденного адреса).
        """
        st = st or self.settings()
        empty = {"4": [], "6": []}
        if not st["enabled"]:
            return empty, []
        day, minute = local_now(st["tz_offset"], now)
        devices = active_devices(st["rules"], day, minute)
        if not devices:
            return empty, []
        neigh = (read_neighbors()
                 if any(_MAC_RE.match(d) for d in devices) else [])
        unresolved = [d for d in devices if _MAC_RE.match(d) and not any(
            resolve_addresses([d], neigh).values())]
        return resolve_addresses(devices, neigh), unresolved

    def tick(self, stop_evt=None):
        st = self.settings()
        addrs, unresolved = self.desired(st)
        with self._apply_lock:
            # Пока тик считал адреса (ip neigh — до секунды на роутере),
            # расписание могли выключить или GUI — остановить. Перечитываем
            # под замком, иначе запоздалый тик вернул бы только что снятые
            # правила.
            if stop_evt is not None and stop_evt.is_set():
                return
            if st["enabled"] and not self.settings()["enabled"]:
                return
            self._unresolved = unresolved
            if not (addrs["4"] or addrs["6"]):
                if self._maybe_installed:
                    had = bool(self._applied)
                    if self._remove():
                        self._maybe_installed = False
                    if had:
                        log.info("расписание устройств: окно закончилось, "
                                 "обход для всех", source="firewall")
                self._applied = None
                return
            if addrs == self._applied and self._present():
                return
            self._maybe_installed = True
            if self._apply(addrs):
                if addrs != self._applied:
                    log.info("расписание устройств: мимо обхода — %s"
                             % ", ".join(addrs["4"] + addrs["6"]),
                             source="firewall")
                self._applied = addrs
            else:
                # Часть правил могла встать — следующий тик повторит
                # (или снимет, если окно уже кончилось).
                self._applied = None

    def remove_all(self):
        """Снять правила обоих бэкендов — для полной очистки (teardown)."""
        self._stop()
        with self._apply_lock:
            self._remove(every_backend=True)
            self._applied = None
            self._maybe_installed = False

    # ── backend ──

    def _fw_type(self):
        from core.firewall import get_firewall_manager
        return get_firewall_manager().detect_fw_type() or ""

    def _present(self):
        if self._backend == "nftables":
            rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
            return rc == 0
        if self._backend == "iptables":
            ok = True
            for ipt, fam in (("iptables", "4"), ("ip6tables", "6")):
                if (self._applied or {}).get(fam) and shutil.which(ipt):
                    ok = ok and _ipt([ipt, "-t", "mangle", "-C", "PREROUTING",
                                      "-j", CHAIN], quiet=True)
            return ok
        return False

    def _apply(self, addrs):
        backend = self._fw_type()
        if not backend:
            self._last_error = "не найден ни iptables, ни nft"
            return False
        if self._backend and self._backend != backend:
            self._remove()
        self._backend = backend
        mark = self._mark()
        if backend == "nftables":
            rc, _, err = _run(["nft", "-f", "-"],
                              input_text=nft_script(addrs, mark))
            self._last_error = "" if rc == 0 else (err.strip() or "nft rc=%d"
                                                   % rc)
        else:
            self._last_error = ""
            for ipt, fam in (("iptables", "4"), ("ip6tables", "6")):
                if not self._apply_ipt(ipt, addrs.get(fam) or [], mark):
                    self._last_error = ("%s: не удалось применить правила"
                                        % ipt)
        if self._last_error:
            log.warning("расписание устройств: %s" % self._last_error,
                        source="firewall")
        return not self._last_error

    @staticmethod
    def _apply_ipt(ipt, addrs, mark):
        if not addrs:
            if shutil.which(ipt):
                DeviceScheduler._remove_ipt(ipt)
            return True
        if not shutil.which(ipt):
            # Нет ip6tables — IPv6 у роутера не обрабатывается и nfqws2.
            return True
        # -N падает, если цепочка есть, — это нормально: ниже -F.
        _ipt([ipt, "-t", "mangle", "-N", CHAIN], quiet=True)
        if not _ipt([ipt, "-t", "mangle", "-F", CHAIN]):
            return False
        ok = True
        for addr in addrs:
            ok = _ipt([ipt, "-t", "mangle", "-A", CHAIN]
                      + ipt_rule_args(addr, mark)) and ok
        if not _ipt([ipt, "-t", "mangle", "-C", "PREROUTING", "-j", CHAIN],
                    quiet=True):
            ok = _ipt([ipt, "-t", "mangle", "-I", "PREROUTING", "1",
                       "-j", CHAIN]) and ok
        return ok

    @staticmethod
    def _remove_ipt(ipt):
        """Снять прыжок и цепочку. True — цепочки больше нет."""
        for _ in range(8):   # дубли прыжка после сбоев — снимаем все
            if not _ipt([ipt, "-t", "mangle", "-D", "PREROUTING",
                         "-j", CHAIN], quiet=True):
                break
        _ipt([ipt, "-t", "mangle", "-F", CHAIN], quiet=True)
        _ipt([ipt, "-t", "mangle", "-X", CHAIN], quiet=True)
        return not _ipt([ipt, "-t", "mangle", "-S", CHAIN], quiet=True)

    def _remove(self, every_backend=False):
        """Снять наши правила. True — в системе их больше нет.

        Без known-бэкенда (прошлый процесс, teardown) смотрим оба: цепочка
        или таблица могла остаться от другого бэкенда.
        """
        backend = "" if every_backend else self._backend
        ok = True
        if backend in ("", "nftables") and shutil.which("nft"):
            if _run(["nft", "list", "table", "inet", NFT_TABLE])[0] == 0:
                ok = _run(["nft", "delete", "table", "inet",
                           NFT_TABLE])[0] == 0 and ok
        if backend in ("", "iptables"):
            for ipt in ("iptables", "ip6tables"):
                if shutil.which(ipt) and _ipt(
                        [ipt, "-t", "mangle", "-S", CHAIN], quiet=True):
                    ok = self._remove_ipt(ipt) and ok
        return ok

    # ── для UI ──

    def status(self):
        st = self.settings()
        try:
            day, minute = local_now(st["tz_offset"])
            now_text = "%s %02d:%02d" % (DAY_NAMES[day - 1],
                                         *divmod(minute, 60))
        except ValueError:
            day, minute, now_text = 0, 0, ""
        active_rules = [r.get("name") or "%s–%s" % (r["from"], r["to"])
                        for r in st["rules"] if rule_active(r, day, minute)]
        applied = self._applied or {"4": [], "6": []}
        return {
            "enabled": st["enabled"],
            "running": bool(self._thread and self._thread.is_alive()),
            "router_time": now_text,
            "tz_offset": st["tz_offset"],
            "active_rules": active_rules if st["enabled"] else [],
            "excluded": applied.get("4", []) + applied.get("6", []),
            # MAC действующих правил, которым не нашлось адреса: устройство
            # не в сети или не попало в таблицу соседей — обход у него есть.
            "unresolved": list(self._unresolved),
            "backend": self._backend,
            "error": self._last_error,
        }


_scheduler = None
_scheduler_lock = threading.Lock()


def get_device_scheduler() -> DeviceScheduler:
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
            if _scheduler is None:
                _scheduler = DeviceScheduler()
    return _scheduler
