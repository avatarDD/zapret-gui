# core/connectivity/traffic.py
"""
Traffic graphs per-interface (RX/TX за 1h/3h/24h).

Семплер раз в N секунд читает счётчики туннелей и кладёт пары
(timestamp, rx_bytes, tx_bytes) в кольцевой буфер per-iface
в RAM. Никакой записи на flash — на роутерах это критично:
кольцевой буфер на 24 часа с дискретностью 60с — это 1440 точек
× 24 байта ≈ 35 КБ на интерфейс, что приемлемо.

Источники счётчиков:
  - наши amneziawg-go: `awg show <iface> transfer` → rx/tx
  - нативные Keenetic-WG: `core.ndms.ping_check.get_native_wg_status()`
    → rx_bytes/tx_bytes из RCI
  - всё остальное (если когда-то понадобится): `/proc/net/dev`

Возвращаем UI'у три серии (1h, 3h, 24h) — это не три буфера, а
разные ресемплинги одного с разной дискретностью:
  - 1h:  60с-точки × 60     = 60 точек
  - 3h:  180с-точки × 60    = 60 точек
  - 24h: 1440с-точки × 60   = 60 точек

UI получает массив {ts, rx_bps, tx_bps} — пересчёт байт-за-период
в bytes/sec идёт здесь, чтобы фронт мог тупо рисовать линию.
"""

import subprocess
import threading
import time

from core.log_buffer import log


# ─────── константы ───────

SAMPLE_INTERVAL_SEC = 30        # как часто опрашиваем счётчики
HISTORY_HOURS = 24              # глубина кольцевого буфера
# Кол-во raw-семплов в буфере (24ч × 3600с / 30с = 2880)
RAW_BUFFER_SIZE = int((HISTORY_HOURS * 3600) / SAMPLE_INTERVAL_SEC) + 8

# Per-peer sparkline (5 минут). Дискретность та же, что у iface-семплов
# (мы лезем за peer-инфой в том же tick'е, что и за iface-счётчиками).
PEER_HISTORY_MINUTES = 5
PEER_BUFFER_SIZE = int((PEER_HISTORY_MINUTES * 60) / SAMPLE_INTERVAL_SEC) + 4
# Кол-во точек peer-серии. Бакет (_series_from_samples) даёт точку только
# если в нём ≥2 сэмпла, поэтому bucket_sec = window // points должен быть
# ≥ 2×SAMPLE_INTERVAL_SEC. Иначе (как было при points=PEER_BUFFER_SIZE=14 →
# bucket_sec=21с<30с) каждый бакет получает <2 сэмплов и серия ВСЕГДА пуста.
PEER_SERIES_POINTS = max(1, (PEER_HISTORY_MINUTES * 60) //
                         (2 * SAMPLE_INTERVAL_SEC))


# ─────── per-iface буфер ───────

class _RingBuffer:
    """
    Универсальный кольцевой буфер сэмплов (ts, rx, tx).

    Размер задаётся при создании — для iface-долгой истории это
    RAW_BUFFER_SIZE, для per-peer 5-минутной — PEER_BUFFER_SIZE.
    """

    __slots__ = ("samples", "last_idx", "_size")

    def __init__(self, size: int):
        self._size    = int(size)
        self.samples  = [None] * self._size
        self.last_idx = -1

    def append(self, ts: int, rx: int, tx: int):
        idx = (self.last_idx + 1) % self._size
        self.samples[idx] = (int(ts), int(rx), int(tx))
        self.last_idx = idx

    def iter_chronological(self):
        """Сэмплы в хронологическом порядке (oldest → newest)."""
        if self.last_idx < 0:
            return
        n = self._size
        for k in range(1, n + 1):
            idx = (self.last_idx + k) % n
            s = self.samples[idx]
            if s is not None:
                yield s


def _IfaceBuffer():
    """Алиас для совместимости — буфер на полные 24ч."""
    return _RingBuffer(RAW_BUFFER_SIZE)


def _PeerBuffer():
    """Буфер на 5 минут — для sparkline'а."""
    return _RingBuffer(PEER_BUFFER_SIZE)


# ─────── samples → series ───────

def _series_from_samples(raw: list, window_sec: int, points: int) -> list:
    """
    Превратить raw-семплы в `points` равноотстоящих точек за
    последние `window_sec` секунд.

    Каждая точка — {"ts": int, "rx_bps": float, "tx_bps": float}.
    Если в окне нет данных или была только одна точка, серия пустая.

    Защита от сброса счётчика (рестарт туннеля → rx/tx обнуляется):
    если delta < 0, bps в этом интервале считается как 0.
    """
    if len(raw) < 2:
        return []

    now = int(time.time())
    start = now - window_sec
    bucket_sec = max(1, window_sec // points)

    out = []
    buckets = [[] for _ in range(points)]
    for ts, rx, tx in raw:
        if ts < start:
            continue
        b = min(points - 1, max(0, (ts - start) // bucket_sec))
        buckets[b].append((ts, rx, tx))

    for b in range(points):
        bucket = buckets[b]
        if len(bucket) < 2:
            continue
        ts0, rx0, tx0 = bucket[0]
        ts1, rx1, tx1 = bucket[-1]
        dt = ts1 - ts0
        if dt <= 0:
            continue
        drx = max(0, rx1 - rx0)
        dtx = max(0, tx1 - tx0)
        out.append({
            "ts":     ts1,
            "rx_bps": drx / dt,
            "tx_bps": dtx / dt,
        })
    return out


def _series_from_buffer(buf, window_sec: int, points: int) -> list:
    """Обёртка — выдаёт серию из любого _RingBuffer."""
    return _series_from_samples(
        list(buf.iter_chronological()), window_sec, points)


# ─────── сборщик ───────

class TrafficSampler:
    """
    Фоновый поток-семплер.

    Запускается ровно один экземпляр через get_traffic_sampler();
    при первом запуске поднимает background-thread, который раз
    в SAMPLE_INTERVAL_SEC опрашивает все известные туннели.
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._buffers  = {}    # iface → _RingBuffer (24h history)
        # Per-peer буферы: {iface: {peer_pubkey: _RingBuffer}}
        self._peer_buffers = {}
        self._thread   = None
        self._stop_evt = threading.Event()

    # ─── lifecycle ───

    def start(self):
        """Поднять фоновой поток, если ещё не запущен."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(
                target=self._run_loop,
                name="traffic-sampler",
                daemon=True,
            )
            t.start()
            self._thread = t
            log.info("traffic-sampler: запущен (раз в %dс)"
                     % SAMPLE_INTERVAL_SEC, source="connectivity")

    def stop(self):
        self._stop_evt.set()

    # ─── API для UI ───

    def get_series(self, iface: str) -> dict:
        """
        Вернуть три серии (1h/3h/24h) для интерфейса.

        Если буфер пуст, серии пустые. UI должен показать
        «недостаточно данных».
        """
        with self._lock:
            buf = self._buffers.get(iface)
        if not buf:
            return {"iface": iface, "1h": [], "3h": [], "24h": []}
        return {
            "iface": iface,
            "1h":    _series_from_buffer(buf, 3600,        60),
            "3h":    _series_from_buffer(buf, 3 * 3600,    60),
            "24h":   _series_from_buffer(buf, 24 * 3600,   60),
        }

    def get_current(self, iface: str) -> dict:
        """Последний known cumulative (rx, tx) для интерфейса."""
        with self._lock:
            buf = self._buffers.get(iface)
        if not buf or buf.last_idx < 0:
            return {"iface": iface, "rx_bytes": 0, "tx_bytes": 0, "ts": 0}
        ts, rx, tx = buf.samples[buf.last_idx]
        return {"iface": iface, "rx_bytes": rx, "tx_bytes": tx, "ts": ts}

    def list_known(self) -> list:
        """Список интерфейсов, по которым у нас есть хоть один сэмпл."""
        with self._lock:
            return sorted(self._buffers.keys())

    def get_peer_series(self, iface: str) -> dict:
        """
        5-минутный sparkline RX/TX по каждому peer'у интерфейса.

        Возвращает:
          {"iface": str,
           "peers": [
             {"public_key": "...",
              "series": [{"ts": int, "rx_bps": float, "tx_bps": float}, ...]},
             ...]}

        Если ни одного peer-сэмпла ещё нет (нативный Keenetic-WG —
        для него awg show недоступен), peers будет пустым.
        """
        with self._lock:
            iface_peers = self._peer_buffers.get(iface) or {}
            snapshot = {pk: list(buf.iter_chronological())
                        for pk, buf in iface_peers.items()}

        peers = []
        for pk, raw in snapshot.items():
            series = _series_from_samples(raw,
                                          PEER_HISTORY_MINUTES * 60,
                                          PEER_SERIES_POINTS)
            peers.append({"public_key": pk, "series": series})
        # Стабильный порядок — по pubkey
        peers.sort(key=lambda x: x["public_key"])
        return {"iface": iface, "peers": peers,
                "window_seconds": PEER_HISTORY_MINUTES * 60}

    # ─── internal ───

    def _run_loop(self):
        # Один тик сразу, чтобы UI получил данные быстрее.
        try:
            self._tick()
        except Exception as e:
            log.warning("traffic-sampler tick: %s" % e,
                        source="connectivity")
        while not self._stop_evt.wait(SAMPLE_INTERVAL_SEC):
            try:
                self._tick()
            except Exception as e:
                log.warning("traffic-sampler tick: %s" % e,
                            source="connectivity")

    def _tick(self):
        """Один опрос всех интерфейсов + per-peer."""
        from core.awg_manager import AwgManager
        mgr = AwgManager()
        ifaces = mgr.list_interfaces()
        now = int(time.time())
        for entry in ifaces:
            name = (entry or {}).get("name", "")
            if not name:
                continue
            counters = self._read_counters(name, entry)
            if counters is None:
                continue
            rx, tx = counters
            with self._lock:
                buf = self._buffers.get(name)
                if buf is None:
                    buf = _IfaceBuffer()
                    self._buffers[name] = buf
                buf.append(now, rx, tx)

            # Per-peer счётчики — только для наших awg/wg-туннелей.
            # Нативные Keenetic-WG туннели (source=ndms) `awg show`
            # не видит, и пер-peer там пока недоступен — пропускаем
            # такие интерфейсы.
            if entry.get("source") == "ndms" or entry.get("native"):
                continue
            self._tick_peers(name, now)

    def _tick_peers(self, iface: str, now: int):
        """Записать сэмпл по каждому peer'у интерфейса."""
        peers = _read_peers(iface)
        if not peers:
            return
        with self._lock:
            iface_peers = self._peer_buffers.get(iface)
            if iface_peers is None:
                iface_peers = {}
                self._peer_buffers[iface] = iface_peers
            seen = set()
            for pubkey, rx, tx in peers:
                seen.add(pubkey)
                buf = iface_peers.get(pubkey)
                if buf is None:
                    buf = _PeerBuffer()
                    iface_peers[pubkey] = buf
                buf.append(now, rx, tx)
            # Если peer пропал из awg show — оставляем его буфер
            # ещё на одну итерацию (вдруг handshake восстановится).
            # Чистка приходит при «полном переподключении» — мы её
            # делаем редко, чтобы не мерцать данными в UI.

    def _read_counters(self, iface: str, info: dict):
        """
        Прочитать (rx, tx) для интерфейса.

        Источники в порядке приоритета:
          1) если в `info` от AwgManager уже есть `rx_bytes`/`tx_bytes`
             (нативный Keenetic-WG через NDMS) — берём их;
          2) `awg show <iface> transfer` — даёт rx/tx на каждый peer;
             суммируем;
          3) `/proc/net/dev` как универсальный фолбэк.

        Возвращает (rx, tx) или None если не удалось.
        """
        if info and (info.get("rx_bytes") or info.get("tx_bytes")):
            return int(info.get("rx_bytes") or 0), \
                   int(info.get("tx_bytes") or 0)

        # awg show <iface> transfer:
        #   <peer-pubkey>\t<rx>\t<tx>
        for binary in ("awg", "wg"):
            rc, out, _err = _run([binary, "show", iface, "transfer"],
                                  timeout=3)
            if rc == 0 and out:
                rx_sum, tx_sum = 0, 0
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        try:
                            rx_sum += int(parts[1])
                            tx_sum += int(parts[2])
                        except (ValueError, TypeError):
                            continue
                return rx_sum, tx_sum

        # /proc/net/dev фолбэк
        try:
            with open("/proc/net/dev", "r") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or ":" not in line:
                        continue
                    name, _, rest = line.partition(":")
                    if name.strip() != iface:
                        continue
                    cols = rest.split()
                    if len(cols) >= 9:
                        # rx_bytes col[0], tx_bytes col[8]
                        try:
                            return int(cols[0]), int(cols[8])
                        except (ValueError, TypeError):
                            return None
        except (IOError, OSError):
            pass
        return None


def _read_peers(iface: str) -> list:
    """
    `awg show <iface> dump` → list of (peer_pubkey, rx_bytes, tx_bytes).

    Формат вывода awg show dump:
      <priv_key>\\t<pub_key>\\t<listen_port>\\t<fwmark>   ← Interface
      <pub_key>\\t<psk>\\t<endpoint>\\t<allowed_ips>\\t
        <latest_handshake>\\t<rx>\\t<tx>\\t<keepalive>   ← каждый peer
    """
    for binary in ("awg", "wg"):
        rc, out, _err = _run([binary, "show", iface, "dump"], timeout=3)
        if rc != 0 or not out:
            continue
        peers = []
        lines = [l for l in out.splitlines() if l.strip()]
        # Первая строка — секция [Interface], её пропускаем.
        for line in lines[1:]:
            cols = line.split("\t")
            if len(cols) < 8:
                continue
            pub = cols[0]
            try:
                rx = int(cols[5])
                tx = int(cols[6])
            except (ValueError, IndexError):
                continue
            if pub and pub != "(none)":
                peers.append((pub, rx, tx))
        return peers
    return []


def _run(args, timeout=3):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return 1, "", "subprocess error"


# ─────── singleton ───────

_sampler = None
_sampler_lock = threading.Lock()


def get_traffic_sampler() -> TrafficSampler:
    """Глобальный экземпляр семплера. Лениво стартует поток."""
    global _sampler
    if _sampler is None:
        with _sampler_lock:
            if _sampler is None:
                _sampler = TrafficSampler()
                _sampler.start()
    return _sampler
