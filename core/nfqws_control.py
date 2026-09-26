# core/nfqws_control.py
"""
Управление движком nfqws2 одним местом: старт, стоп, перезапуск,
применение стратегии и горячая перезагрузка списков.

Зачем отдельный модуль. «Запустить обход» — это не ``NFQWSManager.start()``:
это правила firewall до старта, пересборка аргументов активной стратегии,
снятие правил при неудаче и запись выбранной стратегии в конфиг. Раньше вся
эта последовательность жила в ``api/control.py`` и ``api/strategies.py``,
то есть была доступна только веб-интерфейсу. MCP (сессия S7) и CLI повторили
бы её своими словами — и разошлись бы с UI на первой же правке: обход,
запущенный «из модели», отличался бы от запущенного кнопкой.

Поэтому последовательность переехала сюда, а роуты стали тонкими. Форма
ответа у всех функций одна:

    {"ok": bool, "error": str, "nfqws": <NFQWSManager.get_status()>,
     "firewall": <FirewallManager.get_status()>, ...}

**Конкуренция за движок.** Сканер стратегий и blockcheck поднимают и
роняют nfqws2 сами: применить стратегию поверх работающего скана значит
испортить и скан, и стратегию. Общий мьютекс на движок живёт в
``core/nfqws_session.py``; здесь он берётся на время каждой мутирующей
функции (декоратор ``_guarded``), а ``busy()`` отвечает на вопрос «кто
держит движок прямо сейчас» для тех, кто спрашивает ДО вызова.

Захват вложенный: держатель сессии (эксперимент, сравнение проб) вправе
звать эти функции — второй захват тем же потоком проходит насквозь.
Занято — это обычный отказ той же формы, а не исключение.
"""

import functools

from core.log_buffer import log


# Кто способен держать движок, кроме нас. Порядок = порядок опроса.
BUSY_SCANNER = "scanner"
BUSY_BLOCKCHECK = "blockcheck"


def _owner_for(source: str) -> str:
    """Источник вызова → владелец общего мьютекса.

    Всё, что здесь не названо, — короткое управляющее действие
    человека: кнопка в веб-интерфейсе, CLI, инструмент MCP.
    """
    from core.nfqws_session import (OWNER_EXPERIMENT, OWNER_PROBE,
                                    OWNER_UI)
    return {"probes": OWNER_PROBE,
            "experiment": OWNER_EXPERIMENT}.get(source, OWNER_UI)


def busy() -> dict:
    """Кто сейчас занимает движок; пустой словарь — свободен.

    Источник истины — общий мьютекс ``core/nfqws_session``: его берут
    сканер, сравнение проб, эксперименты и сами функции этого модуля.
    Своя же блокировка «занятостью» не считается: иначе держатель
    сессии не смог бы позвать ни одну функцию отсюда.

    Запасной путь — опрос держателей, которые мьютекс пока не берут:
    blockcheck поднимает и роняет nfqws2 из собственного скрипта.

    Returns:
        dict: ``who`` (``scanner``/``blockcheck``/…), ``reason`` и
        ``hint`` человеческим языком, либо ``{}``.
    """
    from core.nfqws_session import get_nfqws_session

    session = get_nfqws_session()
    if session.held_by_me():
        return {}
    holder = session.holder()
    if holder:
        return _from_holder(holder)
    return _legacy_busy()


def _from_holder(holder: dict) -> dict:
    """Ответ ``busy()`` по записи держателя мьютекса."""
    who = holder.get("owner", "")
    if who == BUSY_SCANNER:
        return {
            "who": who,
            "reason": _scanner_reason(holder),
            "hint": "дождитесь окончания или остановите подбор "
                    "(POST /api/scan/stop)",
        }
    return {
        "who": who,
        "reason": holder.get("text", "движок держит другая операция"),
        "hint": "дождитесь окончания и повторите",
    }


def _scanner_reason(holder: dict) -> str:
    """Текст про сканер — с прогрессом, если он читается."""
    try:
        from core.strategy_scanner import get_strategy_scanner
        status = get_strategy_scanner().get_status()
        return ("идёт подбор стратегий (%s из %s): сканер сам поднимает "
                "и роняет nfqws2"
                % (status.get("progress", 0), status.get("total", 0)))
    except Exception:                           # noqa: BLE001 — граница
        return holder.get("text", "идёт подбор стратегий")


def _legacy_busy() -> dict:
    """Держатели, которые общий мьютекс пока не берут.

    Мьютекс появился в S9 и его берут не все: blockcheck управляет
    движком из своего скрипта. Убрать этот опрос — значит вернуть
    применение стратегии прямо поверх идущих проб.
    """
    try:
        from core.strategy_scanner import STATUS_RUNNING, get_strategy_scanner
        status = get_strategy_scanner().get_status()
        if status.get("status") == STATUS_RUNNING:
            return {
                "who": BUSY_SCANNER,
                "reason": "идёт подбор стратегий (%s из %s): сканер сам "
                          "поднимает и роняет nfqws2"
                          % (status.get("progress", 0),
                             status.get("total", 0)),
                "hint": "дождитесь окончания или остановите подбор "
                        "(POST /api/scan/stop)",
            }
    except Exception as e:                      # noqa: BLE001 — граница
        # Сканера на устройстве может не быть вовсе. «Не смог спросить»
        # — это не «занято»: иначе обход стало бы не запустить.
        log.debug("Статус сканера не прочитан: %s" % e, source="control")

    for module, factory in (("core.blockcheck2", "get_blockcheck2_runner"),
                            ("core.blockcheck", "get_blockcheck_runner")):
        try:
            mod = __import__(module, fromlist=[factory])
            manager = getattr(mod, factory)()
            if _is_running(manager):
                return {
                    "who": BUSY_BLOCKCHECK,
                    "reason": "идёт диагностика blockcheck: она сама "
                              "управляет движком",
                    "hint": "дождитесь окончания или остановите проверку",
                }
        except Exception:                       # noqa: BLE001 — граница
            continue

    return {}


def _is_running(manager) -> bool:
    """``is_running`` у двух blockcheck'ов объявлен по-разному.

    У ``Blockcheck2Runner`` это метод, у ``BlockcheckRunner`` —
    ``@property``. Безусловный вызов ``manager.is_running()`` на втором
    бросает ``TypeError``, который тут же съедался общим ``except``, —
    то есть наша Python-реализация blockcheck НИКОГДА не считалась
    занявшей движок, и стратегия применялась прямо поверх её проб.
    """
    flag = getattr(manager, "is_running", False)
    return bool(flag() if callable(flag) else flag)


def running() -> bool:
    """Поднят ли движок прямо сейчас — без единого побочного действия.

    Нужна тем, кто сравнивает состояние «с обходом и без»
    (``core/probe_runner.py``): спрашивать менеджер напрямую они не
    могут — тесты подменяют его здесь, в ``_managers()``.
    """
    try:
        mgr, _fw, _cfg = _managers()
        return bool(mgr.is_running())
    except Exception as e:                      # noqa: BLE001 — граница
        log.debug("Состояние движка не прочитано: %s" % e, source="control")
        return False


def active_strategy_args():
    """Аргументы активной стратегии, пересобранные из конфига (или None)."""
    from core.strategy_builder import active_strategy_args as rebuild
    return rebuild(source="control")


def _guarded(fn):
    """Взять общий мьютекс на движок на время вызова.

    Проверка ``busy()`` перед вызовом — вежливость (у неё текст лучше),
    а не защита: между «спросил» и «сделал» сканер успевает стартовать.
    Защита — вот она: сама последовательность идёт под мьютексом.

    Занято — не исключение, а отказ обычной формы (``ok``/``error``/
    ``nfqws``/``firewall``) плюс ``busy`` и ``error_code="busy"``:
    вызывающему нужен разбираемый ответ, а не трассировка. Таймаут
    захвата нулевой — никто не ждёт освобождения молча.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from core.nfqws_session import SessionBusy, get_nfqws_session

        source = kwargs.get("source") or "control"
        try:
            with get_nfqws_session().acquire(
                    owner=_owner_for(source), timeout=0,
                    reason="%s (%s)" % (fn.__name__, source)):
                return fn(*args, **kwargs)
        except SessionBusy as busy_error:
            return _busy_fail(busy_error)
    return wrapper


def _busy_fail(busy_error) -> dict:
    """Отказ «движок занят» в той же форме, что и остальные ответы."""
    mgr, fw, _cfg = _managers()
    out = _fail("движок занят: %s" % busy_error, mgr, fw)
    out["error_code"] = "busy"
    out["busy"] = busy_error.holder.get("owner", "")
    out["hint"] = "дождитесь окончания операции и повторите"
    return out


@_guarded
def start(strategy_args=None, source: str = "control") -> dict:
    """Применить правила firewall и поднять nfqws2.

    Args:
        strategy_args: аргументы движка; ``None`` — пересобрать из
            активной стратегии (``strategy.current_id``). Так кнопка
            «Старт» и MCP поднимают ТУ ЖЕ стратегию, что выбрана, со
            свежими правками, а не «голый» nfqws2 без десинка.
        source: чем помечать строки журнала.
    """
    mgr, fw, cfg = _managers()

    args = _as_args(strategy_args)
    if args is None:
        args = active_strategy_args()

    apply_fw = cfg.get("firewall", "apply_on_start", default=True)
    fw_ok = True
    if apply_fw:
        fw_ok = fw.apply_rules()
        if not fw_ok:
            log.warning("Правила firewall не применены, но пробуем "
                        "запустить nfqws2", source=source)

    if not mgr.start(args if args else None):
        # Правила без движка — это чёрная дыра: пакеты уходят в NFQUEUE,
        # где их никто не читает. Снимаем то, что сами же поставили, —
        # и при неудачном apply_rules() тоже: он снимает прежние правила
        # до наката, так что всё, что осталось, поставлено им частично.
        if apply_fw:
            fw.remove_rules()
        return _fail("Не удалось запустить nfqws2", mgr, fw)

    return _done(mgr, fw, strategy_args=args or [])


@_guarded
def stop(source: str = "control") -> dict:
    """Остановить nfqws2 и снять правила firewall."""
    mgr, fw, _ = _managers()

    nfqws_ok = mgr.stop()
    # Правила снимаем даже при неудачной остановке: иначе перехват
    # остаётся стоять на движок, которого нет.
    fw.remove_rules()

    if not nfqws_ok:
        return _fail("Не удалось полностью остановить nfqws2", mgr, fw)
    return _done(mgr, fw)


@_guarded
def restart(strategy_args=None, source: str = "control") -> dict:
    """Перезапустить nfqws2 и переприменить правила firewall."""
    mgr, fw, cfg = _managers()

    args = _as_args(strategy_args)
    if args is None:
        args = active_strategy_args()

    nfqws_ok = mgr.restart(args)

    if cfg.get("firewall", "apply_on_start", default=True):
        fw.remove_rules()
        # Движок не поднялся — правила обратно не ставим, как и в
        # start(): перехват на пустую очередь диагностика называет
        # ошибкой `rules_without_engine`.
        if nfqws_ok:
            fw.apply_rules()

    if not nfqws_ok:
        return _fail("Ошибка перезапуска nfqws2", mgr, fw)
    return _done(mgr, fw, strategy_args=args or [])


@_guarded
def apply_strategy(strategy_id: str, source: str = "strategies") -> dict:
    """Собрать стратегию, переприменить firewall и поднять с ней движок.

    Возвращает ту же форму, что ``start``/``restart``, плюс ``strategy``
    (``id``/``name``) и ``strategy_args``. ``error_code`` отличает
    «нет такой стратегии» (``not_found``) от «нечего запускать»
    (``no_profiles``) и от неудачи самого движка (``start_failed``):
    по тексту ошибки такие случаи не разделить.
    """
    from core.strategy_builder import get_strategy_manager

    mgr, fw, cfg = _managers()
    sm = get_strategy_manager()

    strategy = sm.get_strategy(strategy_id)
    if not strategy:
        out = _fail("Стратегия не найдена: %s" % strategy_id, mgr, fw)
        out["error_code"] = "not_found"
        return out

    args = sm.build_nfqws_args(strategy)
    if not args:
        out = _fail("Нет включённых профилей в стратегии", mgr, fw)
        out["error_code"] = "no_profiles"
        return out

    log.info("Применяем стратегию: %s (%s)"
             % (strategy.get("name", ""), strategy_id), source=source)

    apply_fw = cfg.get("firewall", "apply_on_start", default=True)
    if apply_fw:
        fw.remove_rules()
        fw.apply_rules()

    ok = mgr.restart(args) if mgr.is_running() else mgr.start(args)
    if not ok:
        # Правила без движка — снимаем, как start() (старый движок
        # restart() уже остановил, нового нет).
        if apply_fw:
            fw.remove_rules()
        out = _fail("Не удалось запустить nfqws2 со стратегией", mgr, fw)
        out["error_code"] = "start_failed"
        return out

    previous_id = cfg.get("strategy", "current_id")
    cfg.set("strategy", "current_id", strategy_id)
    cfg.set("strategy", "current_name", strategy.get("name", ""))
    cfg.save()

    # Автозапуск помнит стратегию, а не «ту, что активна»: без
    # пересборки после перезагрузки роутера поднялась бы предыдущая.
    # На systemd regenerate() — no-op (стратегия читается из конфига).
    if cfg.get("autostart", "enabled", default=False):
        try:
            from core.autostart_manager import get_autostart_manager
            get_autostart_manager().regenerate()
        except Exception as e:                  # noqa: BLE001 — граница
            log.warning("Не удалось обновить автозапуск: %s" % e,
                        source=source)

    log.success("Стратегия применена: %s" % strategy.get("name", ""),
                source=source)
    return _done(mgr, fw,
                 strategy={"id": strategy_id,
                           "name": strategy.get("name", "")},
                 previous_id=previous_id,
                 strategy_args=args)


@_guarded
def clear_strategy(source: str = "control") -> dict:
    """Забыть применённую стратегию и остановить движок.

    Нужна откату: если до применения стратегии не было выбрано ничего,
    вернуть «как было» — это именно пустой ``current_id`` и
    остановленный движок, а не запуск предыдущей (её не было).
    """
    mgr, fw, cfg = _managers()
    cfg.set("strategy", "current_id", None)
    cfg.set("strategy", "current_name", None)
    cfg.save()
    log.info("Применённая стратегия сброшена", source=source)

    nfqws_ok = mgr.stop()
    fw.remove_rules()
    if not nfqws_ok:
        return _fail("Не удалось полностью остановить nfqws2", mgr, fw)
    return _done(mgr, fw)


def reload_lists(reason: str = "") -> dict:
    """SIGHUP работающему nfqws2: перечитать хостлисты и ipset'ы.

    Это НЕ перезапуск: соединения не рвутся, аргументы движка остаются
    прежними. Подменять одно другим нельзя — «перезапуск не помог»
    звучит совсем иначе, чем «перезапуска не было».
    """
    from core.nfqws_reload import reload_lists as sighup
    return sighup(reason)


# ───────────────────────────── частности ────────────────────────────

def _managers():
    """Три менеджера, которые нужны каждой функции модуля."""
    from core.config_manager import get_config_manager
    from core.firewall import get_firewall_manager
    from core.nfqws_manager import get_nfqws_manager
    return (get_nfqws_manager(), get_firewall_manager(),
            get_config_manager())


def _as_args(value):
    """Аргументы движка из списка или строки; ``None`` — «не заданы»."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.split()
    return [str(a) for a in value]


def _done(mgr, fw, **extra) -> dict:
    out = {"ok": True, "error": "", "nfqws": _status(mgr),
           "firewall": _status(fw)}
    out.update(extra)
    return out


def _fail(error, mgr, fw, **extra) -> dict:
    out = {"ok": False, "error": error, "nfqws": _status(mgr),
           "firewall": _status(fw)}
    out.update(extra)
    return out


def _status(manager) -> dict:
    """Статус менеджера, который сам может и не опроситься.

    Статус нужен именно в отказе (что с движком сейчас), и второе
    исключение внутри отказа лишило бы вызывающего и его.
    """
    try:
        return manager.get_status()
    except Exception as e:                      # noqa: BLE001 — граница
        return {"error": "%s: %s" % (type(e).__name__, e)}
