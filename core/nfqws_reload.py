# core/nfqws_reload.py
"""
Горячая перезагрузка списков в работающем nfqws2 (SIGHUP).

nfqws2 читает файлы списков (``--hostlist``, ``--hostlist-exclude``,
``--ipset``, ``--ipset-exclude``) ОДИН раз — при разборе опций
(``RegisterHostlist()`` в ``nfq2/hostlist.c``). Дальше список живёт в памяти
процесса, и правка файла на диске сама по себе НЕ меняет ничего: движок
перечитывает зарегистрированные хостлисты и ipset-ы только по **SIGHUP**
(см. §10.5 справочника nfqws2).

Именно на этом ломался сценарий из issue #265 «добавил сайт в Exclude, а он
всё равно не грузится»: GUI честно дописывал домен в ``lists/netrogat.txt``,
но живой nfqws2 продолжал работать со старой копией списка — до ближайшего
ручного перезапуска обхода. Теперь запись любого списка домёнов/IP
сопровождается SIGHUP, и исключение начинает действовать на новых
соединениях сразу.

PID ищем максимально широко, потому что nfqws2 может быть поднят по-разному:
  • ``/var/run/zapret-gui-nfqws.pid`` — процесс, поднятый GUI;
  • ``/var/run/zapret-nfqws.pid``     — процесс автозапуска S99zapret
    (``--daemon``, свой PID-файл);
  • скан ``/proc``                    — страховка на случай, когда PID-файла
    нет вовсе (GUI запускает nfqws2 обычным Popen, без ``--daemon``) или он
    протух.

SIGHUP безопасен: для nfqws2 это «перечитать списки», а не перезапуск —
установленные соединения не рвутся.
"""

import os
import signal

from core.log_buffer import log

# PID-файлы, куда nfqws2 могли записать снаружи (GUI и автозапуск).
PID_FILES = (
    "/var/run/zapret-gui-nfqws.pid",
    "/var/run/zapret-nfqws.pid",
)


def find_nfqws_pids() -> list:
    """Все живые PID nfqws/nfqws2 (PID-файлы + скан /proc), без дублей."""
    pids = []

    for pf in PID_FILES:
        try:
            with open(pf, "r") as f:
                pid = int((f.read() or "0").strip())
            if pid > 0 and pid not in pids:
                pids.append(pid)
        except (IOError, OSError, ValueError):
            continue

    # Скан /proc — единый источник правды, когда PID-файла нет или он протух.
    try:
        from core.nfqws_manager import NFQWSManager
        for pid in NFQWSManager._find_nfqws_pids():
            if pid not in pids:
                pids.append(pid)
    except Exception:
        pass

    return pids


def reload_lists(reason: str = "") -> dict:
    """Послать SIGHUP всем работающим nfqws2 — перечитать списки.

    Args:
        reason: что именно поменялось (идёт в лог, напр. ``netrogat.txt``).

    Returns:
        dict: ``{"ok": bool, "pids": [...], "error": str}``. ``ok=False`` без
        ошибки означает просто «обход не запущен» — это штатная ситуация
        (списки подхватятся при следующем старте), а не сбой.
    """
    pids = find_nfqws_pids()
    if not pids:
        log.debug(
            "SIGHUP не нужен: nfqws2 не запущен (%s)" % (reason or "lists"),
            source="hostlists",
        )
        return {"ok": False, "pids": [], "error": "nfqws2 не запущен"}

    signalled = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGHUP)
            signalled.append(pid)
        except (OSError, ProcessLookupError):
            # Процесс умер между поиском и сигналом — не наша проблема.
            continue

    if not signalled:
        return {"ok": False, "pids": [], "error": "nfqws2 не запущен"}

    log.info(
        "SIGHUP → nfqws2 PID %s: перечитать списки (%s)"
        % (", ".join(str(p) for p in signalled), reason or "lists"),
        source="hostlists",
    )
    return {"ok": True, "pids": signalled, "error": ""}
