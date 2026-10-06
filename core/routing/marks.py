# core/routing/marks.py
"""
Метки (fwmark) маршрутов: своё поле бит, выдача без коллизий.

## Зачем

Раньше метка доменного правила считалась хешем id в 0x10000..0x1FFFF и
ставилась целиком (`--set-mark N`, `meta mark set N`), а `ip rule
fwmark N` сравнивал её тоже целиком. Отсюда три беды:

* метка затирала чужие биты пакета — метку проб (0x10000000) и
  песочницы сканера (0x80000000), метку пакетов nfqws2 (0x40000000), а
  на Keenetic и метку политики NDMS. Фейк nfqws2 к IP из набора терял
  свою метку и снова уходил в очередь;
* 16-битный хеш двух правил мог совпасть — и трафик одного маршрута
  уезжал в таблицу другого;
* DSCP-правила ставили меткой номер таблицы — снова целиком.

Здесь (приём MagiTrickle: «метка = свободное число, проверенное по
факту», только с маской):

* поле меток маршрутов — биты 16..27 (:data:`MASK` = 0x0FFF0000);
  младшие 16 бит (пользовательские метки) и старшие 4 (наши метки
  обхода) не трогаются — правило ставит ``--set-xmark value/MASK``,
  ``ip rule`` сравнивает ``fwmark value/MASK``;
* значение поля — слот 1..4094, выдаётся по ключу и хранится в
  ``routing.mark_slots`` (как ``routing.table_map`` для таблиц): два
  ключа одного слота не получат никогда. 0xFFF не выдаётся — метки
  политик NDMS (0xffffaaa и соседние) несут в этих битах все единицы,
  и ``ip rule`` такого слота ловил бы клиентов политики.

Старые метки (полные, 0x10000..0x1FFFF) распознаются как свои —
уборщик (`core/routing/sweeper.py`) снимает оставшиеся от прошлой
версии ``ip rule``.
"""

import threading

from core.log_buffer import log


SHIFT = 16
MASK = 0x0FFF0000
SLOT_MAX = 0xFFE            # 0xFFF — все единицы, как у меток политик NDMS

# Полная маска: так `ip rule` печатает правило без маски.
FULL = 0xFFFFFFFF

# Метки прошлых версий (поставленные целиком, без маски).
LEGACY_MIN = 0x10000
LEGACY_MAX = 0x1FFFF

_lock = threading.Lock()


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def _load() -> dict:
    try:
        raw = _cfg().get("routing", "mark_slots", default={}) or {}
    except Exception:
        return {}
    out = {}
    if isinstance(raw, dict):
        for key, slot in raw.items():
            try:
                slot = int(slot)
            except (TypeError, ValueError):
                continue
            if 1 <= slot <= SLOT_MAX:
                out[str(key)] = slot
    return out


def _save(slots: dict) -> None:
    try:
        cm = _cfg()
        cm.set("routing", "mark_slots", dict(slots))
        cm.save()
    except Exception as e:
        log.warning("routing: сохранение mark_slots: %s" % e,
                    source="routing")


def pick_free(used) -> int:
    """Наименьший свободный слот 1..SLOT_MAX (0 — места нет). Чистая."""
    taken = set(used)
    for slot in range(1, SLOT_MAX + 1):
        if slot not in taken:
            return slot
    return 0


def slot_for(key: str) -> int:
    """Слот ключа: выданный ранее или новый свободный (сохраняется)."""
    key = str(key)
    with _lock:
        slots = _load()
        if key in slots:
            return slots[key]
        slot = pick_free(slots.values())
        if not slot:
            raise RuntimeError("закончились метки маршрутов (%d)" % SLOT_MAX)
        slots[key] = slot
        _save(slots)
        return slot


def mark_for(key: str) -> int:
    """Метка ключа: слот, сдвинутый в поле :data:`MASK`."""
    return slot_for(key) << SHIFT


def release(key: str) -> None:
    """Вернуть слот ключа (правило удалено)."""
    key = str(key)
    with _lock:
        slots = _load()
        if slots.pop(key, None) is not None:
            _save(slots)


def keys() -> dict:
    """{ключ: метка} — все выданные (для уборщика и диагностики)."""
    return {k: v << SHIFT for k, v in _load().items()}


def rule_key(rule_id: str) -> str:
    """Ключ доменного правила."""
    return "dom:%s" % rule_id


def dscp_key(ifname: str) -> str:
    """Ключ DSCP-маршрута: одна метка на интерфейс (как и таблица)."""
    return "dscp:%s" % ifname


# ─────────────────────── форматирование ──────────────────────────────

def spec(mark: int) -> str:
    """``0x10000/0xfff0000`` — для ``ip rule``, ``--set-xmark`` и nft."""
    return "0x%x/0x%x" % (mark, MASK)


def nft_set_expr(mark: int) -> str:
    """nft: выставить поле, не трогая остальные биты метки."""
    return "meta mark set meta mark and 0x%08x or 0x%08x" % (
        FULL & ~MASK, mark)


def nft_ct_set_expr(mark: int) -> str:
    """nft: то же для метки соединения."""
    return "ct mark set ct mark and 0x%08x or 0x%08x" % (FULL & ~MASK, mark)


def parse(token: str):
    """``0x10000/0xfff0000`` | ``0x10000`` | ``65536`` → (mark, mask)."""
    value, _, mask = str(token).partition("/")
    try:
        mark = int(value, 0)
        mask = int(mask, 0) if mask else FULL
    except ValueError:
        return None
    return mark, mask


def is_ours(mark: int, mask: int) -> bool:
    """Метка из нашего поля (или старого формата прошлых версий)."""
    if mask == MASK:
        return bool(mark & MASK) and (mark & ~MASK) == 0
    if mask == FULL:
        # Без маски: метка прошлых версий или наш слот, поставленный
        # BusyBox-`ip`, который маску не понимает.
        return (LEGACY_MIN <= mark <= LEGACY_MAX
                or (bool(mark & MASK) and (mark & ~MASK) == 0))
    return False


# ─────────────────────── ip rule fwmark ──────────────────────────────
#
# iproute2 понимает `fwmark value/mask` давно, а BusyBox `ip` — нет
# (маску не разбирает вовсе). Там правило ставится без маски: сравнение
# метки целиком работает для пакетов без чужих бит — как было раньше.

_mask_unsupported = False


def _ip(args, timeout=5):
    import subprocess
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _fam(family: str) -> str:
    return "-6" if family in ("v6", "-6") else "-4"


def ip_rule_add(mark: int, table: int, family: str = "v4",
                priority: int = 10100) -> dict:
    """``ip rule add fwmark mark/MASK lookup table`` (идемпотентно)."""
    global _mask_unsupported
    fam = _fam(family)
    ip_rule_del(mark, table, family)
    if not _mask_unsupported:
        rc, _o, err = _ip(["ip", fam, "rule", "add", "fwmark", spec(mark),
                           "lookup", str(table), "priority", str(priority)])
        if rc == 0 or "File exists" in err:
            return {"ok": True, "error": "", "masked": True}
        low = err.lower()
        if not any(s in low for s in ("fwmark", "invalid", "argument",
                                      "usage")):
            return {"ok": False, "error": err.strip(), "masked": True}
        _mask_unsupported = True
        log.info("routing: `ip rule` не понимает маску fwmark (BusyBox?) — "
                 "метки маршрутов сравниваются целиком", source="routing")
    rc, _o, err = _ip(["ip", fam, "rule", "add", "fwmark", str(mark),
                       "lookup", str(table), "priority", str(priority)])
    return {"ok": rc == 0 or "File exists" in err, "error": err.strip(),
            "masked": False}


def ip_rule_del(mark: int, table: int, family: str = "v4") -> dict:
    """Снять правило в обеих формах (с маской и без)."""
    fam = _fam(family)
    for token in (spec(mark), str(mark)):
        for _ in range(4):
            rc, _o, _e = _ip(["ip", fam, "rule", "del", "fwmark", token,
                              "lookup", str(table)])
            if rc != 0:
                break
    return {"ok": True}
