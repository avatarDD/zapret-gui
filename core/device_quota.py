# core/device_quota.py
"""
Дневные квоты времени для устройств (приём Tachyon,
``service/parental_quota.uc``): N минут интернета в день, потом доступ
закрыт до полуночи.

## Как считается время

Минута засчитывается, если за неё устройство (все адреса правила)
отправило не меньше ``active_packets`` пакетов. Счётчики — правила без
действия в своей цепочке ``FORWARD`` (iptables) или ``counter`` в своей
таблице nftables; по ним же видно, что телефон просто лежит с
открытыми push-соединениями (единицы пакетов в минуту) и время не идёт.

## Как закрывается доступ

Когда минуты правила кончились, в ту же цепочку встают ``REJECT`` от
устройства и ``DROP`` к нему. Цепочка стоит и в FORWARD, и в INPUT:
transparent-режим sing-box/mihomo заворачивает трафик клиента на
локальный порт, и он идёт в INPUT. DHCP и DNS роутера остаются. Блок действует и на уже открытые
соединения. В полночь (по времени роутера, тот же ``tz_offset``, что у
расписания) счёт обнуляется и блок снимается. «Добавить минут на
сегодня» — :func:`DeviceQuota.grant`.

## Ограничения

* Аппаратное или программное ускорение NAT (flow offload на OpenWrt,
  аппаратный NAT Keenetic) уводит установленные соединения мимо
  netfilter: счёт и блок увидят только их начало.
* Устройство по MAC переводится в адреса по таблице соседей, как в
  ``core/device_schedule``; смена адреса подхватывается на следующем
  тике.

Настройки — ``firewall.device_quota``; счёт за день —
``<config_dir>/device-quota.json`` (пишется раз в :data:`SAVE_EVERY` и
при каждом блоке, чтобы не изнашивать флеш раз в минуту).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import threading
import time

from core.device_schedule import (
    _MAC_RE, _ipt, _run, normalize_device, normalize_names,
    parse_tz_offset, read_neighbors, resolve_addresses)
from core.log_buffer import log

CHAIN = "zgui_quota"
NFT_TABLE = "zgui_quota"
TICK_SEC = 60
SAVE_EVERY = 300
MAX_RULES = 32
MAX_DEVICES = 16
MAX_GRANT = 24 * 60
DEFAULT_ACTIVE_PACKETS = 30


# ─────────────────────────── настройки ───────────────────────────────

def rule_key(rule: dict) -> str:
    """Опознаёт правило между правками: набор его устройств."""
    return "|".join(sorted(rule.get("devices") or []))


def normalize_rule(rule) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("правило — объект")
    name = str(rule.get("name") or "").strip()[:64]
    try:
        minutes = int(rule.get("minutes"))
    except (TypeError, ValueError):
        raise ValueError("«%s»: минуты — число" % (name or "правило"))
    if not 1 <= minutes <= 24 * 60:
        raise ValueError("«%s»: минут в день — от 1 до 1440"
                         % (name or "правило"))
    days = rule.get("days") or []
    if not isinstance(days, list):
        raise ValueError("days — список дней 1..7")
    norm_days = sorted({int(d) for d in days
                        if str(d).isdigit() and 1 <= int(d) <= 7})
    devices = rule.get("devices") or []
    if isinstance(devices, str):
        devices = re.split(r"[\s,;]+", devices)
    norm = []
    for token in devices if isinstance(devices, list) else []:
        if str(token or "").strip():
            value = normalize_device(token)[1]
            if value not in norm:
                norm.append(value)
    if not norm:
        raise ValueError("«%s»: не указано ни одного устройства"
                         % (name or "правило"))
    if len(norm) > MAX_DEVICES:
        raise ValueError("слишком много устройств в правиле (> %d)"
                         % MAX_DEVICES)
    return {"name": name, "enabled": bool(rule.get("enabled", True)),
            "devices": norm, "names": normalize_names(rule.get("names"),
                                                      norm),
            "minutes": minutes, "days": norm_days}


def normalize_settings(data) -> dict:
    if not isinstance(data, dict):
        raise ValueError("ожидается объект")
    rules = data.get("rules") or []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("rules — список до %d правил" % MAX_RULES)
    tz = str(data.get("tz_offset") or "").strip()
    parse_tz_offset(tz)
    try:
        pk = int(data.get("active_packets") or DEFAULT_ACTIVE_PACKETS)
    except (TypeError, ValueError):
        raise ValueError("active_packets — число")
    norm = [normalize_rule(r) for r in rules]
    keys = [rule_key(r) for r in norm]
    if len(set(keys)) != len(keys):
        raise ValueError("у двух правил одинаковый набор устройств")
    return {"enabled": bool(data.get("enabled", False)), "tz_offset": tz,
            "active_packets": max(1, min(pk, 100000)), "rules": norm}


def load_settings(raw) -> tuple:
    """→ (рабочие настройки, правила для формы, ошибки).

    Битое правило не действует, но в форму уходит как есть с полем
    ``error``: иначе следующее сохранение стёрло бы его молча.
    """
    raw = raw if isinstance(raw, dict) else {}
    errors, rules, form = [], [], []
    tz = str(raw.get("tz_offset") or "").strip()
    try:
        parse_tz_offset(tz)
    except ValueError as e:
        errors.append("tz_offset: %s" % e)
        tz = ""
    for r in (raw.get("rules") if isinstance(raw.get("rules"), list)
              else [])[:MAX_RULES]:
        try:
            norm = normalize_rule(r)
        except ValueError as e:
            errors.append(str(e))
            bad = dict(r) if isinstance(r, dict) else {}
            bad["error"] = str(e)
            form.append(bad)
            continue
        rules.append(norm)
        form.append(norm)
    try:
        pk = max(1, int(raw.get("active_packets")
                        or DEFAULT_ACTIVE_PACKETS))
    except (TypeError, ValueError):
        pk = DEFAULT_ACTIVE_PACKETS
    return ({"enabled": bool(raw.get("enabled", False)), "tz_offset": tz,
             "active_packets": pk, "rules": rules}, form, errors)


# ─────────────────────────── чистая логика ───────────────────────────

def local_date(tz_offset="", now=None) -> tuple:
    """(``YYYY-MM-DD``, ISO-день 1..7) по времени роутера или сдвигу."""
    ts = time.time() if now is None else now
    minutes = parse_tz_offset(tz_offset)
    tm = time.localtime(ts) if minutes is None else \
        time.gmtime(ts + minutes * 60)
    return time.strftime("%Y-%m-%d", tm), tm.tm_wday + 1


def applies_today(rule: dict, day: int) -> bool:
    return bool(rule.get("enabled", True)) and (
        not rule.get("days") or day in rule["days"])


def left_minutes(rule: dict, used: int, extra: int) -> int:
    return max(0, int(rule["minutes"]) + int(extra or 0) - int(used or 0))


def count_minute(prev: dict, cur: dict, addrs: list,
                 threshold: int) -> bool:
    """Чистая функция: была ли минута активной для набора адресов.

    ``prev``/``cur`` — счётчики пакетов {адрес: пакеты}. Адрес без
    прежнего значения (новое правило, перестройка цепочки) не считается:
    иначе накопленное за всё время засчиталось бы одной минутой.
    """
    total = 0
    for a in addrs:
        if a in prev and a in cur:
            total += max(0, cur[a] - prev[a])
    return total >= threshold


_TARGETS = ("REJECT", "DROP", "RETURN", "ACCEPT")
_NFT_RE = re.compile(r"\bip6?\s+saddr\s+(\S+)\s+counter\s+packets\s+(\d+)")


def _canon(addr: str) -> str:
    try:
        net = ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return addr
    return str(net.network_address) if net.prefixlen == net.max_prefixlen \
        else str(net)


def parse_ipt_list(text: str) -> dict:
    """Вывод ``iptables -nvxL zgui_quota`` → {адрес: пакеты} счётчиков.

    Только своя цепочка, а не ``iptables-save`` всей таблицы раз в
    минуту. Правило-счётчик — без действия и без доп. условий: строка
    кончается «источник назначение-любое».
    """
    out = {}
    for ln in (text or "").splitlines():
        f = ln.split()
        if len(f) < 7 or not f[0].isdigit() or any(t in f for t in _TARGETS):
            continue
        if f[-1] not in ("0.0.0.0/0", "::/0"):
            continue
        out[_canon(f[-2])] = out.get(_canon(f[-2]), 0) + int(f[0])
    return out


def parse_nft(text: str) -> dict:
    out = {}
    for ln in (text or "").splitlines():
        if "reject" in ln or "drop" in ln:
            continue
        m = _NFT_RE.search(ln)
        if m:
            # Счётчики цепочек forward и input складываются.
            a = _canon(m.group(1))
            out[a] = out.get(a, 0) + int(m.group(2))
    return out


# DHCP и DNS роутера заблокированному устройству оставляем: без DHCP оно
# отвалится от сети целиком, а квота — про интернет.
EXEMPT = (("udp", "67:68"), ("udp", "53"), ("tcp", "53"))


def nft_script(count: dict, block: dict) -> str:
    """Таблица целиком (пересоздаётся атомарно). Цепочки forward и input:
    трафик, завёрнутый transparent-режимом на локальный порт движка,
    идёт в INPUT, а не в FORWARD."""
    lines = ["add table inet %s" % NFT_TABLE,
             "delete table inet %s" % NFT_TABLE,
             "table inet %s {" % NFT_TABLE]
    for chain in ("forward", "input"):
        lines += ["  chain %s {" % chain,
                  "    type filter hook %s priority -5; policy accept;"
                  % chain]
        if any(block.get(f) for f in ("4", "6")):
            for proto, port in EXEMPT:
                lines.append("    %s dport %s return"
                             % (proto, port.replace(":", "-")))
        for fam, kw in (("4", "ip"), ("6", "ip6")):
            for a in block.get(fam) or []:
                lines.append("    %s saddr %s reject" % (kw, a))
                if chain == "forward":
                    lines.append("    %s daddr %s drop" % (kw, a))
        for fam, kw in (("4", "ip"), ("6", "ip6")):
            for a in count.get(fam) or []:
                lines.append("    %s saddr %s counter" % (kw, a))
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def ipt_rules(count: list, block: list) -> list:
    """Аргументы правил цепочки (без ``iptables -A CHAIN``). Цепочка
    общая для FORWARD и INPUT; ``-d`` к устройству в INPUT не встретится."""
    rules = []
    if block:
        for proto, port in EXEMPT:
            rules.append(["-p", proto, "--dport", port, "-j", "RETURN"])
    for a in block:
        rules.append(["-s", a, "-j", "REJECT"])
        rules.append(["-d", a, "-j", "DROP"])
    for a in count:
        rules.append(["-s", a])
    return rules


# ─────────────────────────── состояние за день ──────────────────────

def _state_path() -> str:
    from core.config_manager import get_config_manager
    return os.path.join(get_config_manager().config_dir,
                        "device-quota.json")


def _read_state() -> dict:
    try:
        with open(_state_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(data: dict) -> None:
    from core.safe_io import atomic_write_json
    try:
        atomic_write_json(_state_path(), data)
    except OSError as e:
        log.warning("квоты устройств: счёт не сохранён: %s" % e,
                    source="firewall")


# ─────────────────────────── планировщик ────────────────────────────

class DeviceQuota:
    def __init__(self):
        self._lock = threading.RLock()
        self._thread = None
        self._stop = threading.Event()
        st = _read_state()
        self._date = str(st.get("date") or "")
        self._used = dict(st.get("used") or {})
        self._extra = dict(st.get("extra") or {})
        self._notified = set(st.get("notified") or [])
        self._prev = {}             # адрес → пакеты на прошлом тике
        self._installed = None      # (count, block), что сейчас стоит
        self._maybe_installed = True
        self._backend = ""
        self._last_error = ""
        self._saved_at = 0.0
        self._addrs = {}            # ключ правила → его адреса
        self._blocked = set()

    # ── настройки ──

    def settings(self) -> dict:
        from core.config_manager import get_config_manager
        raw = get_config_manager().get("firewall", "device_quota",
                                       default={}) or {}
        return load_settings(raw)[0]

    # ── жизненный цикл ──

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop,
                                            name="device-quota", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        # Первый тик сразу: после перезапуска блок должен вернуться не
        # через минуту, а тут же.
        while True:
            try:
                self.tick(count=True)
            except Exception as e:                  # noqa: BLE001 — граница
                log.warning("квоты устройств: %s" % e, source="firewall")
            if self._stop.wait(TICK_SEC):
                return

    # ── тик ──

    def _roll_day(self, date: str) -> None:
        if date != self._date:
            if self._date:
                log.info("квоты устройств: новый день, счёт обнулён",
                         source="firewall")
            self._date = date
            self._used, self._extra = {}, {}
            self._notified = set()
            self._saved_at = 0.0

    def tick(self, now: float = None, count: bool = False) -> dict:
        """Шаг квот. ``count`` — засчитать минуту: только у тика раз в
        :data:`TICK_SEC`. Внеочередной тик (сохранение, «добавить минут»)
        лишь применяет блоки, иначе каждое нажатие съедало бы минуту."""
        now = time.time() if now is None else now
        st = self.settings()
        with self._lock:
            if not st["enabled"] or not st["rules"]:
                if self._maybe_installed and self._remove():
                    self._maybe_installed = False
                    self._installed = None
                self._blocked = set()
                return {"action": "off"}
            date, day = local_date(st["tz_offset"], now)
            self._roll_day(date)
            rules = [r for r in st["rules"] if applies_today(r, day)]
            needs_mac = any(_MAC_RE.match(d) for r in rules
                            for d in r["devices"])
            neigh = read_neighbors() if needs_mac else []
            self._addrs = {rule_key(r): resolve_addresses(r["devices"],
                                                          neigh)
                           for r in rules}
            cur = self._read_counters() if count else self._prev
            blocked_keys = set()
            for r in rules:
                key = rule_key(r)
                fam = self._addrs[key]
                addrs = fam["4"] + fam["6"]
                if count and key not in self._blocked and count_minute(
                        self._prev, cur, addrs, st["active_packets"]):
                    self._used[key] = int(self._used.get(key, 0)) + 1
                if left_minutes(r, self._used.get(key, 0),
                                self._extra.get(key, 0)) <= 0:
                    blocked_keys.add(key)
            self._prev = cur
            newly = blocked_keys - self._blocked
            self._blocked = blocked_keys
            self._install(
                {"4": _uniq(a for k in self._addrs
                            for a in self._addrs[k]["4"]),
                 "6": _uniq(a for k in self._addrs
                            for a in self._addrs[k]["6"])},
                {"4": _uniq(a for k in blocked_keys
                            for a in self._addrs[k]["4"]),
                 "6": _uniq(a for k in blocked_keys
                            for a in self._addrs[k]["6"])})
            for r in rules:
                key = rule_key(r)
                if key in newly and key not in self._notified:
                    self._notified.add(key)
                    self._notify(r)
            if newly or now - self._saved_at >= SAVE_EVERY:
                self._save(now)
            return {"action": "tick", "blocked": sorted(blocked_keys),
                    "used": dict(self._used)}

    def _save(self, now: float) -> None:
        self._saved_at = now
        _write_state({"date": self._date, "used": self._used,
                      "extra": self._extra,
                      "notified": sorted(self._notified)})

    def _notify(self, rule: dict) -> None:
        title = rule.get("name") or ", ".join(
            (rule.get("names") or {}).get(d, d) for d in rule["devices"])
        log.info("квоты устройств: «%s» — время на сегодня вышло" % title,
                 source="firewall")
        try:
            from core import notify
            notify.event("device_quota", "⏳ «%s»: %d мин на сегодня "
                         "истрачены, интернет закрыт до полуночи"
                         % (title, rule["minutes"]))
        except Exception:                           # noqa: BLE001 — граница
            pass

    # ── ручное ──

    def _find(self, ident: str):
        st = self.settings()
        for r in st["rules"]:
            if ident in (rule_key(r), r.get("name")) or \
                    ident in r["devices"]:
                return r
        return None

    def grant(self, ident: str, minutes: int, now: float = None) -> dict:
        """Добавить минут на сегодня правилу (по имени, устройству или
        ключу). Отрицательное — забрать."""
        r = self._find(str(ident or "").strip().lower()) \
            or self._find(str(ident or "").strip())
        if r is None:
            return {"ok": False, "error": "правило не найдено"}
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return {"ok": False, "error": "минуты — число"}
        if not -MAX_GRANT <= minutes <= MAX_GRANT or not minutes:
            return {"ok": False, "error": "минуты — от -1440 до 1440, не 0"}
        now = time.time() if now is None else now
        st = self.settings()
        key = rule_key(r)
        with self._lock:
            self._roll_day(local_date(st["tz_offset"], now)[0])
            self._extra[key] = int(self._extra.get(key, 0)) + minutes
            if minutes > 0:
                self._notified.discard(key)
            self._save(now)
        self.tick(now)
        return {"ok": True, "rule": r.get("name") or key,
                "left": left_minutes(r, self._used.get(key, 0),
                                     self._extra.get(key, 0))}

    def remove_all(self) -> None:
        self._stop.set()
        with self._lock:
            if self._date:
                self._save(time.time())
            self._remove(every_backend=True)
            self._installed = None
            self._maybe_installed = False

    # ── firewall ──

    def _fw_type(self) -> str:
        from core.firewall import get_firewall_manager
        return get_firewall_manager().detect_fw_type() or ""

    def _read_counters(self) -> dict:
        if not self._installed:
            return {}
        if self._backend == "nftables":
            rc, out, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
            return parse_nft(out) if rc == 0 else {}
        from core.firewall import FirewallManager
        cur = {}
        for ipt in ("iptables", "ip6tables"):
            if shutil.which(ipt):
                rc, out, _ = _run([ipt] + FirewallManager._iptables_wait_flag(
                    ipt) + ["-t", "filter", "-nvxL", CHAIN])
                if rc == 0:
                    cur.update(parse_ipt_list(out))
        return cur

    def _present(self) -> bool:
        if self._backend == "nftables":
            return _run(["nft", "list", "table", "inet", NFT_TABLE])[0] == 0
        count = (self._installed or ({}, {}))[0]
        for ipt, fam in (("iptables", "4"), ("ip6tables", "6")):
            if count.get(fam) and shutil.which(ipt):
                for hook in ("FORWARD", "INPUT"):
                    if not _ipt([ipt, "-C", hook, "-j", CHAIN], quiet=True):
                        return False
        return True

    def _install(self, count: dict, block: dict) -> None:
        want = (count, block)
        if not (count["4"] or count["6"]):
            if self._maybe_installed and self._remove():
                self._maybe_installed = False
            self._installed = None
            return
        if want == self._installed and self._present():
            return
        backend = self._fw_type()
        if not backend:
            self._last_error = "не найден ни iptables, ни nft"
            return
        if self._backend and self._backend != backend:
            self._remove()
        self._backend = backend
        self._maybe_installed = True
        if backend == "nftables":
            rc, _, err = _run(["nft", "-f", "-"],
                              input_text=nft_script(count, block))
            ok = rc == 0
            self._last_error = "" if ok else (err.strip() or "nft rc=%d" % rc)
        else:
            ok = all([self._install_ipt("iptables", count["4"], block["4"]),
                      self._install_ipt("ip6tables", count["6"],
                                        block["6"])])
            self._last_error = "" if ok else "iptables: правила не встали"
        if ok:
            # Цепочка пересобрана — счётчики с нуля; прежние значения
            # дали бы отрицательную разницу.
            self._prev = {}
            self._installed = want
        else:
            log.warning("квоты устройств: %s" % self._last_error,
                        source="firewall")
            self._installed = None

    @staticmethod
    def _install_ipt(ipt: str, count: list, block: list) -> bool:
        if not shutil.which(ipt):
            return True             # нет IPv6 — нечего и считать
        if not count:
            DeviceQuota._remove_ipt(ipt)
            return True
        _ipt([ipt, "-N", CHAIN], quiet=True)
        if not _ipt([ipt, "-F", CHAIN]):
            return False
        ok = True
        for args in ipt_rules(count, block):
            ok = _ipt([ipt, "-A", CHAIN] + args) and ok
        for hook in ("FORWARD", "INPUT"):
            if not _ipt([ipt, "-C", hook, "-j", CHAIN], quiet=True):
                ok = _ipt([ipt, "-I", hook, "1", "-j", CHAIN]) and ok
        return ok

    @staticmethod
    def _remove_ipt(ipt: str) -> bool:
        for hook in ("FORWARD", "INPUT"):
            for _ in range(8):
                if not _ipt([ipt, "-D", hook, "-j", CHAIN], quiet=True):
                    break
        _ipt([ipt, "-F", CHAIN], quiet=True)
        _ipt([ipt, "-X", CHAIN], quiet=True)
        return not _ipt([ipt, "-S", CHAIN], quiet=True)

    def _remove(self, every_backend: bool = False) -> bool:
        backend = "" if every_backend else self._backend
        ok = True
        if backend in ("", "nftables") and shutil.which("nft"):
            if _run(["nft", "list", "table", "inet", NFT_TABLE])[0] == 0:
                ok = _run(["nft", "delete", "table", "inet",
                           NFT_TABLE])[0] == 0 and ok
        if backend in ("", "iptables"):
            for ipt in ("iptables", "ip6tables"):
                if shutil.which(ipt) and _ipt([ipt, "-S", CHAIN],
                                              quiet=True):
                    ok = self._remove_ipt(ipt) and ok
        return ok

    # ── для UI и MCP ──

    def status(self, now: float = None) -> dict:
        st = self.settings()
        date, day = local_date(st["tz_offset"], now)
        with self._lock:
            same_day = date == self._date
            rows = []
            for r in st["rules"]:
                key = rule_key(r)
                used = self._used.get(key, 0) if same_day else 0
                extra = self._extra.get(key, 0) if same_day else 0
                fam = self._addrs.get(key) or {"4": [], "6": []}
                rows.append({
                    "key": key, "name": r.get("name") or "",
                    "devices": r["devices"], "names": r.get("names") or {},
                    "minutes": r["minutes"], "extra": extra, "used": used,
                    "left": left_minutes(r, used, extra),
                    "today": applies_today(r, day),
                    "blocked": st["enabled"] and key in self._blocked,
                    "addresses": fam["4"] + fam["6"]})
            return {"enabled": st["enabled"], "date": date,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "backend": self._backend, "error": self._last_error,
                    "active_packets": st["active_packets"], "rules": rows}


def _uniq(items) -> list:
    out = []
    for a in items:
        if a not in out:
            out.append(a)
    return out


_inst = None
_inst_lock = threading.Lock()


def get_device_quota() -> DeviceQuota:
    global _inst
    if _inst is None:
        with _inst_lock:
            if _inst is None:
                _inst = DeviceQuota()
    return _inst
