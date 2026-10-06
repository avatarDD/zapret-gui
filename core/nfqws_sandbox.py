# core/nfqws_sandbox.py
"""
Песочница сканера: второй nfqws2 на своей очереди — только для проб.

## Зачем

Сканер стратегий проверял кандидатов на ЕДИНСТВЕННОМ движке: гасил обход
сети, ставил правила перехвата на весь трафик и по очереди поднимал
nfqws2 с каждым кандидатом. Пока шёл подбор (минуты, а в режиме full —
десятки минут), у всех домашних устройств обхода не было, а то и хуже —
их трафик шёл через заведомо битые кандидаты.

Здесь иначе (приём d2k: «пробный план — только на поток своего опыта»):

* основной nfqws2 и его правила не трогаются вовсе — сеть живёт со
  своей стратегией;
* кандидат поднимается во **втором** nfqws2 на отдельной очереди
  (:func:`queue_num`), со своим PID-файлом, каталогом состояния z2k и
  источником в журнале (``nfqws-sandbox``);
* в эту очередь firewall уводит **только соединения с меткой песочницы**
  (``nfqws.desync_mark_sandbox``, SO_MARK на сокетах проб —
  ``core/probe_mark.marking``), а основным правилам ставит на них
  connmark-исключение (``FirewallManager.apply_sandbox_rules``).

Основной менеджер песочницу не видит: ``NFQWSManager._find_nfqws_pids``
пропускает PID из её файла — иначе «зачистка дублей» убила бы её на
первом же старте основного движка, а она — основной.

## Когда песочницы нет

:func:`available` говорит, можно ли: SO_MARK (нужен root), известный
бэкенд firewall, отдельная очередь. Нельзя — сканер работает по-старому
(гасит движок сети на время подбора) и пишет почему.
"""

import os
import signal
import time

from core.log_buffer import log
from core.nfqws_manager import (NFQWSManager, SANDBOX_PID_FILE,
                                _sandbox_pid)


SOURCE = "nfqws-sandbox"

# Метка проб песочницы. Бит 31: младшие 28 заняты NDMS (политики,
# 0x0fffffff), 28 — метка проб «мимо очереди», 29 — EXCLUDE, 30 — пакеты
# nfqws2.
SANDBOX_MARK = "0x80000000"

# state.tsv кандидатов — отдельно от состояния обхода сети: два движка с
# circular в одном файле переписывали бы друг другу закреплённое.
STATE_DIR = "/tmp/zapret-gui-sandbox-state"


def mark(cfg=None) -> int:
    """Метка проб песочницы из ``nfqws.desync_mark_sandbox`` (0 — выкл)."""
    from core.firewall import normalize_mark
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    value = normalize_mark(cfg.get("nfqws", "desync_mark_sandbox",
                                   default=SANDBOX_MARK))
    return int(value, 16) if value else 0


def queue_num(cfg=None) -> int:
    """Очередь песочницы: ``scan.sandbox_queue_num`` или основная + 1.

    Совпасть с основной она не может: две программы на одной очереди —
    пакеты делятся между ними как попало.
    """
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    main = int(cfg.get("nfqws", "queue_num", default=300) or 300)
    try:
        value = int(cfg.get("scan", "sandbox_queue_num", default=0) or 0)
    except (TypeError, ValueError):
        value = 0
    if value <= 0 or value > 65535 or value == main:
        value = main + 1 if main < 65535 else main - 1
    return value


def available(cfg=None) -> dict:
    """Можно ли проверять кандидатов в песочнице: ``{ok, reason}``."""
    from core import probe_mark
    from core.firewall import get_firewall_manager
    if cfg is None:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
    setting = str(cfg.get("scan", "isolated", default="auto")
                  or "auto").strip().lower()
    if setting in ("off", "0", "false", "no"):
        return {"ok": False, "reason": "выключено (scan.isolated=off)"}
    value = mark(cfg)
    if not value:
        return {"ok": False,
                "reason": "метка песочницы выключена "
                          "(nfqws.desync_mark_sandbox)"}
    if not probe_mark.supported(value):
        return {"ok": False,
                "reason": "процесс не может ставить SO_MARK (нужен root)"}
    if not get_firewall_manager().detect_fw_type():
        return {"ok": False, "reason": "бэкенд firewall не найден"}
    return {"ok": True, "reason": "кандидаты — во втором nfqws2 (очередь "
                                  "%d), обход сети не трогается"
                                  % queue_num(cfg)}


class NFQWSSandbox(NFQWSManager):
    """Второй nfqws2: своя очередь, свой PID-файл, чужих не трогает."""

    PID_PATH = SANDBOX_PID_FILE
    LOG_SOURCE = SOURCE

    def __init__(self, queue: int = None):
        self._queue = queue
        super().__init__()

    # ── отличия от основного движка ──

    def _build_base_args(self, cfg) -> list:
        """Базовые аргументы основного движка, но со своей очередью."""
        queue = self._queue or queue_num(cfg)
        return ["--qnum=%d" % queue if a.startswith("--qnum=") else a
                for a in super()._build_base_args(cfg)]

    @staticmethod
    def _state_dir() -> str:
        return STATE_DIR

    def _recover_pid(self):
        """Чужую песочницу не подбираем — гасим (GUI упал посреди скана)."""
        self._kill_stale()

    def _find_external_pid(self):
        # «Внешней» песочницы не бывает: автозапуск её не поднимает.
        return None

    def _sweep_stray_processes(self, exclude_pid=None):
        """Только свой осиротевший процесс; основной движок не трогаем."""
        self._kill_stale(exclude_pid=exclude_pid)

    def _kill_stale(self, exclude_pid=None) -> None:
        pid = _sandbox_pid()
        if pid is None or pid in (exclude_pid, self._pid):
            return
        log.warning("Осталась песочница сканера от прошлого прогона "
                    "(PID %d) — завершаем" % pid, source=SOURCE)
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                break
            deadline = time.time() + 2.0
            while time.time() < deadline and self._check_pid_alive(pid):
                time.sleep(0.1)
            if not self._check_pid_alive(pid):
                break
        self._remove_pid_file()
