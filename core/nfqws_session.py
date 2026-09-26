# core/nfqws_session.py
"""
Общий мьютекс на nfqws2/firewall и снимок состояния движка.

Зачем. Движок один, а желающих его подержать — несколько: сканер
стратегий, сравнение «с обходом и без» (``core/probe_runner``), будущий
движок экспериментов и обычные кнопки «Старт»/«Стоп». Каждый из них
умеет сохранить состояние и вернуть «как было» — и в этом вся беда:
два независимых восстановления дерутся, побеждает закончивший вторым, и
роутер остаётся с чужой стратегией. Поэтому сохранение состояния и право
трогать движок вынесены сюда, в один примитив.

Как пользоваться::

    from core.nfqws_session import OWNER_EXPERIMENT, get_nfqws_session

    session = get_nfqws_session()
    with session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
        snapshot = session.snapshot()
        try:
            session.apply_temporary(argv)
            ...
        finally:
            session.restore(snapshot)

``timeout=0`` — это «не ждать, сразу сказать занято» (а не «ждать
вечно»): вызывающему нужен ответ, а не зависший запрос. Занято —
:class:`SessionBusy`, и по нему видно, **кто** держит и **с какого
времени**.

**Блокировка процессная, а не потоковая.** Фоновые воркеры GUI живут
потоками одного процесса (CoderManual §8), но CLI ``zapret-gui`` —
отдельный процесс, и он тоже поднимает движок. Поэтому внутри процесса
работает ``threading``-мьютекс, а между процессами — lock-файл рядом с
``settings.json`` (не в ``/tmp``: ``/tmp`` на роутере чистится, а
каталог настроек переживает перезагрузку). Лок с мёртвым PID крадётся:
упавший процесс не должен запирать движок навсегда.

Повторный захват тем же потоком разрешён (как у ``RLock``): держатель
сессии вправе звать ``core/nfqws_control``, который берёт тот же
мьютекс.
"""

import json
import os
import threading
import time
from contextlib import contextmanager

from core.log_buffer import log


# ─────────────────────────── владельцы ──────────────────────────────

OWNER_SCANNER = "scanner"
OWNER_EXPERIMENT = "experiment"
OWNER_BLOCKCHECK = "blockcheck"
OWNER_PROBE = "probe"
OWNER_UI = "ui"

# Человеческие названия для текстов отказа. Владелец, которого здесь
# нет, покажется как есть: выдуманное описание хуже сырого имени.
OWNER_TEXT = {
    OWNER_SCANNER: "подбор стратегий",
    OWNER_EXPERIMENT: "эксперимент со стратегиями",
    OWNER_BLOCKCHECK: "диагностика blockcheck",
    OWNER_PROBE: "сравнение «с обходом и без»",
    OWNER_UI: "управление обходом",
}

# Имя lock-файла рядом с settings.json.
LOCK_NAME = ".nfqws-session.lock"

# Лок живого процесса старше этого — брошенный. Полный скан идёт
# десятки минут, эксперимент — минуты; шесть часов заведомо больше
# любого честного удержания и заведомо меньше «навсегда».
STALE_SEC = 6 * 3600

# Шаг опроса чужого (межпроцессного) лока: его освобождение нам никто
# не сигналит, ждать приходится поллингом.
POLL_SEC = 0.2

# Пауза перед тем, как счесть нечитаемый lock-файл мусором: между
# созданием файла и записью в него есть щель, и в неё виден пустой лок.
WRITE_GRACE_SEC = 0.05


class SessionBusy(RuntimeError):
    """Движок держит кто-то другой.

    ``holder`` — словарь ``{owner, reason, since, held_sec, pid, text}``:
    из него строятся человеческие тексты отказов в инструментах MCP и в
    ответах REST.
    """

    def __init__(self, holder: dict):
        self.holder = dict(holder or {})
        super().__init__(describe(self.holder))


def describe(holder: dict) -> str:
    """Человеческий текст «кто держит движок и сколько уже»."""
    holder = holder or {}
    owner = str(holder.get("owner") or "?")
    text = OWNER_TEXT.get(owner, owner)
    since = float(holder.get("since") or 0.0)
    held = holder.get("held_sec")
    if held is None:
        held = max(0, int(time.time() - since)) if since else 0
    out = "%s (%s), уже %d с" % (text, owner, int(held))
    reason = str(holder.get("reason") or "").strip()
    if reason:
        out += ": %s" % reason
    pid = holder.get("pid")
    if pid and int(pid) != os.getpid():
        out += " (процесс %s)" % pid
    return out


class NfqwsSession:
    """Единственный держатель прав на nfqws2 и правила перехвата."""

    def __init__(self):
        self._cond = threading.Condition()
        self._holder = {}          # owner, reason, since, pid, thread
        self._depth = 0            # вложенные захваты одного потока
        self._warned_file = False  # о недоступности lock-файла — один раз

    # ──────────────────────── блокировка ────────────────────────

    @contextmanager
    def acquire(self, owner: str, timeout: float = 0.0, reason: str = ""):
        """Контекст «движок наш»; занято — :class:`SessionBusy`.

        Args:
            owner: кто берёт (``OWNER_*``); попадёт в текст отказа
                остальным.
            timeout: сколько секунд ждать освобождения. ``0`` — не ждать.
            reason: одна фраза о том, что делается, — тоже для отказа.
        """
        hold = self.claim(owner, timeout=timeout, reason=reason)
        try:
            yield self
        finally:
            hold.release()

    def claim(self, owner: str, timeout: float = 0.0, reason: str = ""):
        """То же, что :meth:`acquire`, но без ``with``.

        Возвращает объект с идемпотентным ``release()`` — для случаев,
        когда захват и освобождение живут в разных функциях (например,
        асинхронная задача). Освобождение обязательно: без него движок
        останется занятым до конца процесса.
        """
        owner = str(owner or "").strip() or OWNER_UI
        me = threading.get_ident()
        deadline = time.monotonic() + max(0.0, float(timeout or 0.0))

        with self._cond:
            while True:
                if self._depth and self._holder.get("thread") == me:
                    # Держатель вправе позвать nfqws_control, который
                    # берёт этот же мьютекс: считаем вложенность.
                    self._depth += 1
                    return _Hold(self, owner, nested=True)

                foreign = dict(self._holder) if self._depth else {}
                if not self._depth:
                    record = {"owner": owner, "reason": reason,
                              "since": time.time(), "pid": os.getpid(),
                              "boot_id": _boot_id(), "thread": me}
                    taken, foreign = self._take_file(record)
                    if taken:
                        self._holder = record
                        self._depth = 1
                        return _Hold(self, owner, nested=False)

                left = deadline - time.monotonic()
                if left <= 0:
                    raise SessionBusy(_public(foreign))
                self._cond.wait(min(left, POLL_SEC))

    def holder(self) -> dict:
        """Кто держит движок сейчас; ``{}`` — свободен.

        Читает и чужой (межпроцессный) лок, поэтому годится для
        человеческих отказов из любого процесса.
        """
        with self._cond:
            if self._depth:
                return _public(self._holder)
        record = self._read_file()
        if record and self._alive(record):
            return _public(record)
        return {}

    def held_by_me(self) -> bool:
        """Держит ли сессию ТЕКУЩИЙ поток.

        Нужна тем, кто спрашивает «занято ли» перед действием: своя же
        блокировка — это не «занято другим».
        """
        with self._cond:
            return bool(self._depth
                        and self._holder.get("thread")
                        == threading.get_ident())

    # ───────────────────── снимок и восстановление ──────────────────

    def snapshot(self, source: str = "session") -> dict:
        """Снять состояние движка и правил — всё, что нужно для отката.

        В снимке: активная стратегия, запущен ли nfqws2 и с какими
        аргументами, стоят ли правила перехвата.
        """
        mgr, fw, cfg = _managers()

        running = bool(_call(mgr, "is_running", False))
        status = _call(fw, "get_status", None)
        if isinstance(status, dict) and "applied" in status:
            applied = bool(status.get("applied"))
        else:
            # Один вызов get_status вместо двух шеллов в ядро; но если
            # статус не прочитался — спрашиваем прямо.
            status = {}
            applied = bool(_call(fw, "is_applied", False))

        snap = {
            "taken_at": time.time(),
            "nfqws_running": running,
            "nfqws_args": list(_call(mgr, "get_last_args", []) or []),
            "nfqws_pid": _call(mgr, "get_pid", None) if running else None,
            "firewall_applied": applied,
            "firewall_type": status.get("type", ""),
            "firewall_rules_count": status.get("rules_count", 0),
            "strategy_id": _cfg_get(cfg, "strategy", "current_id"),
            "strategy_name": _cfg_get(cfg, "strategy", "current_name"),
        }
        if running:
            log.info("Сохранено состояние: nfqws2 запущен (PID %s)"
                     % snap["nfqws_pid"], source=source)
        return snap

    def restore(self, snapshot: dict, source: str = "session") -> dict:
        """Вернуть движок и правила в состояние снимка.

        Идемпотентно: каждый шаг делается, только если состояние
        разошлось со снимком, поэтому повторный вызов ничего не ломает
        и ничего лишнего не трогает.
        """
        snapshot = dict(snapshot or {})
        mgr, fw, cfg = _managers()
        want_running = bool(snapshot.get("nfqws_running"))
        want_rules = bool(snapshot.get("firewall_applied"))
        changed = []
        error = ""

        log.info("Восстанавливаем предыдущее состояние nfqws2",
                 source=source)
        try:
            if want_running:
                if want_rules and not _call(fw, "is_applied", False):
                    fw.apply_rules()
                    changed.append("firewall")
                if not _call(mgr, "is_running", False):
                    mgr.start(self._restore_args(snapshot, source) or None)
                    changed.append("nfqws")
            else:
                if _call(mgr, "is_running", False):
                    mgr.stop()
                    changed.append("nfqws")
                if not want_rules and _call(fw, "is_applied", False):
                    # Правила без движка — чёрная дыра: пакеты уходят в
                    # NFQUEUE, где их никто не читает.
                    fw.remove_rules()
                    changed.append("firewall")
            if self._restore_strategy(cfg, snapshot):
                changed.append("strategy")
            log.success("Предыдущее состояние восстановлено", source=source)
        except Exception as e:                  # noqa: BLE001 — граница
            error = "%s: %s" % (type(e).__name__, e)
            log.error("Ошибка восстановления состояния: %s" % e,
                      source=source)

        return {"ok": not error, "error": error, "changed": changed}

    def apply_temporary(self, argv, source: str = "session") -> dict:
        """Поднять движок с чужими аргументами — временно.

        «Временно» держится не кодом, а дисциплиной вызывающего:
        сначала :meth:`snapshot`, в ``finally`` — :meth:`restore`.
        Поэтому метод требует захваченной сессии: временное применение
        без блокировки — это ровно та драка за движок, ради которой
        модуль и написан.
        """
        if not self.held_by_me():
            raise RuntimeError(
                "apply_temporary без захваченной сессии: сначала "
                "acquire(owner=...), иначе вернуть «как было» сможет "
                "кто угодно")
        from core import nfqws_control
        return nfqws_control.restart(list(argv or []), source=source)

    # ───────────────────────── частности ────────────────────────

    def _restore_args(self, snapshot: dict, source: str) -> list:
        """Аргументы, с которыми поднимать движок обратно.

        Аргументов может не быть вовсе: до захвата nfqws2 работал не с
        нашего запуска, а с автозапуска (после перезагрузки роутера это
        обычное дело), и «последних аргументов» менеджер не помнит.
        Голый nfqws2 без десинка тогда бесполезен — пересобираем
        активную стратегию, как это делает кнопка «Старт».
        """
        args = list(snapshot.get("nfqws_args") or [])
        if args:
            return args
        try:
            from core.strategy_builder import active_strategy_args
            return list(active_strategy_args(source=source) or [])
        except Exception as e:                  # noqa: BLE001 — граница
            log.warning("Аргументы активной стратегии не пересобраны: %s"
                        % e, source=source)
            return []

    def _restore_strategy(self, cfg, snapshot: dict) -> bool:
        """Вернуть в конфиг ту стратегию, что была отмечена активной."""
        if "strategy_id" not in snapshot:
            return False
        want = snapshot.get("strategy_id")
        if _cfg_get(cfg, "strategy", "current_id") == want:
            return False
        cfg.set("strategy", "current_id", want)
        cfg.set("strategy", "current_name", snapshot.get("strategy_name"))
        cfg.save()
        return True

    # ────────────────────── межпроцессный лок ───────────────────

    def _lock_path(self) -> str:
        """Путь lock-файла рядом с ``settings.json``."""
        try:
            from core import platform_dirs
            return os.path.join(platform_dirs.config_dir(), LOCK_NAME)
        except Exception:                       # noqa: BLE001 — граница
            return ""

    def _take_file(self, record: dict):
        """Занять межпроцессный лок. Возвращает ``(взяли, чужой)``.

        Каталога настроек может не быть (свежая установка, тесты) или
        ФС может быть только на чтение: тогда работаем одной
        внутрипроцессной блокировкой — это слабее, но лучше, чем
        отказать в запуске обхода.
        """
        path = self._lock_path()
        if not path:
            return True, {}

        payload = {k: v for k, v in record.items() if k != "thread"}
        for _attempt in (0, 1):
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o644)
            except FileExistsError:
                foreign = self._read_file(path)
                if not foreign:
                    # Файл мог быть создан соседом мгновение назад и
                    # ещё не дописан. Считать его мусором сразу —
                    # значит украсть только что взятый чужой лок.
                    time.sleep(WRITE_GRACE_SEC)
                    foreign = self._read_file(path)
                if foreign and self._alive(foreign):
                    return False, foreign
                # Протухший лок или наш собственный остаток после
                # падения процесса — крадём, как это делает Lua-сторож
                # в core/strategy_state.py.
                try:
                    os.remove(path)
                except OSError:
                    pass
                continue
            except OSError as e:
                if not self._warned_file:
                    self._warned_file = True
                    log.debug("Межпроцессный лок движка недоступен (%s): "
                              "блокировка только внутри процесса" % e,
                              source="session")
                return True, {}
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(payload, f)
            except OSError as e:                # noqa: BLE001 — граница
                log.debug("Лок движка не записан: %s" % e, source="session")
            return True, {}
        return False, self._read_file(path)

    def _read_file(self, path: str = "") -> dict:
        """Прочитать чужой лок; ``{}`` — файла нет или он битый."""
        path = path or self._lock_path()
        if not path:
            return {}
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _alive(self, record: dict) -> bool:
        """Жив ли процесс, записавший лок.

        Мёртвый держатель не должен запирать движок навсегда: роутер
        перезагружают, процессы падают, а settings.json переживает и
        то, и другое.
        """
        try:
            pid = int(record.get("pid") or 0)
        except (TypeError, ValueError):
            return False
        if pid <= 0:
            return False
        if pid == os.getpid():
            # Наш собственный остаток: в памяти захвата нет (сюда
            # попадают только при свободном мьютексе процесса).
            return False
        # Лок из прошлой загрузки: файл пережил ребут (он рядом с
        # settings.json), а PID за это время почти наверняка занял
        # кто-то другой — `kill(pid, 0)` сказал бы «жив», и движок
        # стоял бы запертым до STALE_SEC. Типичный путь сюда —
        # перезагрузка роутера посреди подбора стратегий.
        boot = str(record.get("boot_id") or "")
        current = _boot_id()
        if boot and current and boot != current:
            return False
        try:
            since = float(record.get("since") or 0.0)
        except (TypeError, ValueError):
            since = 0.0
        if since and (time.time() - since) > STALE_SEC:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True                 # чужой пользователь, но живой
        except OSError:
            return True
        return True

    def _release_file(self) -> None:
        """Снять межпроцессный лок, если он наш."""
        path = self._lock_path()
        if not path:
            return
        record = self._read_file(path)
        if record and int(record.get("pid") or 0) != os.getpid():
            return                      # чужой лок не трогаем
        try:
            os.remove(path)
        except OSError:
            pass

    def _free(self) -> None:
        """Отпустить один уровень захвата (зовёт только ``_Hold``)."""
        with self._cond:
            if not self._depth:
                return
            self._depth -= 1
            if self._depth:
                return
            self._holder = {}
            self._release_file()
            self._cond.notify_all()


class _Hold:
    """Расписка о захвате: освобождение идемпотентно.

    Повторный ``release()`` (например, из ``finally`` поверх уже
    закрытого ``with``) не должен отпускать чужой захват — иначе
    мьютекс «протекает» ровно в тех сценариях, ради которых он нужен.
    """

    __slots__ = ("session", "owner", "nested", "_released")

    def __init__(self, session, owner: str, nested: bool):
        self.session = session
        self.owner = owner
        self.nested = nested
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self.session._free()

    def __enter__(self):
        return self.session

    def __exit__(self, *exc):
        self.release()
        return False


# ────────────────────────── общие частности ─────────────────────────

def _public(record: dict) -> dict:
    """Запись держателя наружу: без идентификатора потока, с текстом."""
    record = record or {}
    since = float(record.get("since") or 0.0)
    out = {
        "owner": record.get("owner", ""),
        "reason": record.get("reason", ""),
        "since": since,
        "held_sec": max(0, int(time.time() - since)) if since else 0,
        "pid": record.get("pid"),
    }
    out["text"] = describe(out)
    return out


def _managers():
    """Три менеджера — те же, что у ``core/nfqws_control``.

    Намеренно одна точка подмены на два модуля: тест, подменивший
    менеджеры у ``nfqws_control``, не должен получить настоящий
    iptables из снимка состояния.
    """
    from core import nfqws_control
    return nfqws_control._managers()


def _call(obj, name: str, default):
    """Спросить менеджер о состоянии, не падая на нём.

    Метода может не быть вовсе (подменённый в тестах менеджер знает не
    всё), а настоящий — сходить в ядро и не вернуться. Снимок нужен
    именно там, где что-то сломалось, поэтому здесь граница: не знаем —
    значение по умолчанию, а не исключение на весь захват.
    """
    fn = getattr(obj, name, None)
    if not callable(fn):
        return default
    try:
        return fn()
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Снимок состояния: %s не опросился (%s)" % (name, e),
                  source="session")
        return default


def _boot_id() -> str:
    """Идентификатор текущей загрузки ядра; ``""`` — не прочитался."""
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as f:
            return f.read().strip()
    except OSError:
        return ""


def _cfg_get(cfg, *path):
    try:
        return cfg.get(*path, default=None)
    except Exception:                           # noqa: BLE001 — граница
        return None


_session = None
_session_lock = threading.Lock()


def get_nfqws_session() -> NfqwsSession:
    """Синглтон сессии движка (как остальные менеджеры проекта)."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                _session = NfqwsSession()
    return _session
