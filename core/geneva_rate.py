# core/geneva_rate.py
"""
Шейпер (полка скорости) и ёмкость канала — для режима «Авто» geneva.

Перенос ``Core/Diagnostics/RateShelf.cs`` Zapret2_AutoTuner
(dpi-diagnostics §2.16) — то же правило, что у класса ``THROTTLE``
детектора geneva_c (docs/EXT.md, X9b):

- загрузка делится на окна по :data:`WINDOW` с; первое окно с данными —
  разгон TCP (slow start), не считается; берутся последние
  :data:`WINDOWS` окон с данными;
- **полка** — медиана этих окон ниже четверти ёмкости канала (пока
  ёмкость неизвестна — ниже :data:`FLOOR_RATE`), окна ровные
  (коэффициент вариации < :data:`MAX_CV`), ни одно не быстрее двух
  медиан, пришло ≥ :data:`MIN_BYTES`. Медленный сервер или занятый
  канал так не выглядят; ровный поток честного сервера (радио) —
  выглядит, поэтому полка — подозрение, решает подбор;
- **порог** стратегии на такой цели — 3 полки, но не больше половины
  канала и не меньше 1,5 полки (:func:`threshold`).

Ёмкость канала (:class:`LinkCapacity`) — самая быстрая загрузка
не-полкой за 10 мин (как ``C`` детектора geneva); детектор тоже кормит
её своим ``capacity``. Чистые функции, время приходит от вызывающего.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

WINDOW = 0.5
WINDOWS = 5
MIN_WINDOWS = 4
MAX_CV = 0.3
MIN_BYTES = 64 * 1024
FLOOR_RATE = 128 * 1024          # 1 Мбит/с: полки ТСПУ — 16–100 КБ/с
TRUST_RATE = 4 * FLOOR_RATE      # без ёмкости ёмкостью может стать только это
CAPACITY_LIFE = 600.0
RATE_BYTES = 1024 * 1024         # сколько тела читать, чтобы мерить скорость
VOLUME_PAD = 24000               # добивка запроса: обрыв на 16 КБ
PADDED_MIN = 128 * 1024          # критерий цели с обрывом 16 КБ
CUTOFF_MIN = 14 * 1024           # обрыв «на 16 КБ»: отправлено + принято


@dataclass
class Reading:
    """Ровная скорость одной загрузки: медиана окон, разброс, пик."""
    rate: float
    cv: float
    peak: float
    windows: int
    bytes: int

    def to_dict(self) -> dict:
        return {"rate": round(self.rate), "cv": round(self.cv, 3),
                "peak": round(self.peak), "windows": self.windows,
                "bytes": self.bytes}


def _median(v) -> float:
    s = sorted(v)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def read(per_window, window: float = WINDOW):
    """Байты по окнам (по времени, 0 — окно без данных) → :class:`Reading`
    или ``None`` (окон с данными после первого меньше
    :data:`MIN_WINDOWS`)."""
    if window <= 0:
        return None
    data = [int(b) for b in per_window or [] if int(b) > 0]
    if len(data) < MIN_WINDOWS + 1:
        return None
    last = [b / window for b in data[1:][-WINDOWS:]]
    med = _median(last)
    mean = sum(last) / len(last)
    sd = (sum((x - mean) ** 2 for x in last) / len(last)) ** 0.5
    return Reading(med, sd / mean if mean > 0 else 0.0, max(last),
                   len(last), sum(data))


def burst(nbytes: int, elapsed: float):
    """Загрузка короче окон (быстрый канал): только средняя, не полка.
    Не меньше 512 КБ за 200 мс — иначе это буферы сокета, не канал."""
    if nbytes >= 512 * 1024 and elapsed >= 0.2:
        r = nbytes / elapsed
        return Reading(r, 1.0, r, 0, nbytes)
    return None


def is_shelf(r, capacity: float) -> bool:
    if r is None or r.bytes < MIN_BYTES or r.cv >= MAX_CV or \
            r.peak > 2 * r.rate:
        return False
    return r.rate < capacity / 4 if capacity > 0 else r.rate < FLOOR_RATE


def threshold(shelf: float, capacity: float) -> float:
    """Скорость, которую должна дать стратегия на цели с полкой."""
    t = 3 * shelf
    return max(1.5 * shelf, min(t, capacity / 2)) if capacity > 0 else t


def human(rate: float) -> str:
    if rate >= 1024 * 1024:
        return "%.1f МБ/с" % (rate / (1024 * 1024))
    return "%d КБ/с" % round(rate / 1024)


class LinkCapacity:
    """Ёмкость канала: самая быстрая загрузка не-полкой за 10 мин."""

    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._rate = 0.0
        self._at = float("-inf")

    def observe(self, rate: float, now: float = None) -> None:
        t = self._clock() if now is None else now
        with self._lock:
            if t - self._at > CAPACITY_LIFE or rate > self._rate:
                self._rate, self._at = float(rate), t

    def current(self, now: float = None) -> float:
        t = self._clock() if now is None else now
        with self._lock:
            return 0.0 if t - self._at > CAPACITY_LIFE else self._rate

    def judge(self, r, now: float = None) -> bool:
        """Полка ли ``r`` при нынешней ёмкости; не полка — кандидат в
        ёмкость (без ёмкости — только от :data:`TRUST_RATE`)."""
        if r is None:
            return False
        cap = self.current(now)
        shelf = is_shelf(r, cap)
        if not shelf and (cap > 0 or r.rate >= TRUST_RATE):
            self.observe(r.rate, now)
        return shelf


SHARED = LinkCapacity()
