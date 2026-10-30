# core/update_checker.py
"""
Unified Update Checker: проверка обновлений ВСЕХ бинарников за один запрос.

Проверяет:
  - zapret2 (nfqws2)
  - sing-box
  - mihomo
  - AmneziaWG
  - GUI (zapret-gui)
  - usque (WARP/MASQUE)
  - tg-ws-proxy-go (Telegram, основной)
  - tg-mtproxy-client (Telegram, MIPS)
  - opera-proxy

Фоновый процесс проверяет по расписанию (default 24h).
Последние результаты кешируются в RAM.
"""

import json
import os
import re
import threading
import time
import urllib.request

from core.log_buffer import log


# Интервал проверки по умолчанию (часы)
DEFAULT_CHECK_INTERVAL_HOURS = 24

# Минимум между проверками. Один check_all() — это ~9 обращений к GitHub
# API, а неавторизованный лимит там 60 запросов в час. При interval_hours=0
# (значение приходит из общего /api/config без всякой валидации) `wait(0)`
# возвращался мгновенно и цикл сваливался в непрерывный опрос GitHub —
# мгновенный бан по rate-limit и бесполезная нагрузка на роутер.
MIN_CHECK_INTERVAL_HOURS = 1
MAX_CHECK_INTERVAL_HOURS = 24 * 30


def _sane_interval_hours(value) -> float:
    """Интервал в разумных пределах; мусор → значение по умолчанию."""
    try:
        hours = float(value)
    except (TypeError, ValueError):
        return DEFAULT_CHECK_INTERVAL_HOURS
    if hours != hours:                      # NaN
        return DEFAULT_CHECK_INTERVAL_HOURS
    return max(MIN_CHECK_INTERVAL_HOURS, min(hours, MAX_CHECK_INTERVAL_HOURS))

# Кешированные результаты
_results = {}
_results_lock = threading.Lock()
_last_check = 0
# MR-96: кеш последних успешных версий по репо — не затирается при ошибках GitHub
_last_known_latest = {}
_last_known_lock = threading.Lock()
# MR-96: флаг — был ли хоть один успешный GitHub API запрос за последний check_all() цикл
_github_any_success = False


def check_all() -> dict:
    """
    Проверить обновления для всех бинарников.
    Возвращает {ok, results: [{name, installed, current, latest, has_update, ...}], ...}
    """
    global _results, _last_check, _github_any_success

    _github_any_success = False
    results = []

    # zapret2
    results.append(_check_zapret())

    # sing-box
    results.append(_check_singbox())

    # mihomo
    results.append(_check_mihomo())

    # AmneziaWG
    results.append(_check_awg())

    # GUI
    results.append(_check_gui())

    # usque (WARP)
    results.append(_check_usque())
    # tg-ws-proxy-go
    results.append(_check_tgwsproxy())
    # tg-mtproxy-client
    results.append(_check_tgproto())
    # opera-proxy
    results.append(_check_opera())
    # geneva_c (второй движок обхода DPI)
    results.append(_check_geneva())

    # Единое правило страницы «Обновления»: обновлять можно только то, что
    # УСТАНОВЛЕНО. Каждый инсталлятор считает has_update сам, и стоит одному
    # забыть про эту проверку — у неустановленной программы версия пустая,
    # «последняя» непустая, и в таблице загорается «← доступно» с кнопкой
    # «Обновить» для того, чего на роутере нет (discussion #102: так вели
    # себя sing-box и mihomo). Гейт здесь делает страницу честной независимо
    # от частных ошибок в инсталляторах.
    for r in results:
        _finalize_row(r)

    updates_count = sum(1 for r in results if r.get("has_update"))

    _log_installed_transitions(results)

    with _results_lock:
        _results = {
            "ok": True,
            "results": results,
            "updates_count": updates_count,
            "incomplete": _incomplete_rows(results),
            "checked_at": int(time.time()),
        }
        _last_check = time.time()

    return _results


def _short(text: str, limit: int = 200) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _incomplete_rows(results: list) -> list:
    """Строки, у которых «последнюю» узнать не удалось.

    Признак per-row: глобальный _github_any_success гасится одним удачным
    запросом (теги opera/usque), и частичный сбой не был виден нигде.
    """
    return [r.get("display_name") or r.get("name") for r in results
            if r.get("latest_source") == "unknown"]


def _finalize_row(r: dict) -> dict:
    """Общие для всех строк правки после частной проверки."""
    if r.get("has_update") and not r.get("installed"):
        r["has_update"] = False
    if not r.get("error"):
        r.pop("error", None)
    # Пустая «последняя» без пометки читалась как «обновлений нет», хотя
    # на деле источник не ответил (DNS, обрыв ответа). Строку, которая
    # сама не назвала источник, помечаем «источник не ответил» и
    # переносим причину в подпись — ⚠ с подсказкой при наведении на
    # телефоне не видно.
    if not r.get("latest") and not r.get("latest_source"):
        r["latest_source"] = "unknown"
        if r.get("error") and not r.get("note"):
            r["note"] = ("последнюю версию узнать не удалось: %s"
                         % _short(r["error"]))
    if (r.get("installed") and not (r.get("current") or "").strip()
            and not r.get("note")):
        r["note"] = ("установленную версию узнать не удалось — бинарник"
                     " не ответил на запрос версии (таймаут или ошибка"
                     " запуска, подробности в журнале)")
    # Время файла, по которому программа считается установленной. Ответ на
    # «я ничего не ставил, а лампочка горит» (discussion #102) — это дата
    # появления файла: по ней видно, когда и, значит, чем он там оказался.
    # Она же — отпечаток для сверки кеша с диском (_revalidate_row).
    p = r.get("path") or ""
    if p and _binary_alive(p):
        mtime = _path_mtime(p)
        if mtime:
            r["path_mtime"] = mtime
    r["checked_at"] = int(time.time())
    return r


# Частная проверка каждой строки — для пересчёта одной строки после
# установки, без полного прохода по всем движкам.
_CHECKERS = {
    "zapret2": lambda: _check_zapret(),
    "singbox": lambda: _check_singbox(),
    "mihomo": lambda: _check_mihomo(),
    "awg": lambda: _check_awg(),
    "gui": lambda: _check_gui(),
    "usque": lambda: _check_usque(),
    "tgwsproxy": lambda: _check_tgwsproxy(),
    "tgproto": lambda: _check_tgproto(),
    "opera": lambda: _check_opera(),
    "geneva": lambda: _check_geneva(),
}

_refreshing = set()
_refreshing_lock = threading.Lock()


def refresh_component(name: str) -> dict:
    """Пересчитать одну строку кеша сейчас же. {} — строки нет в кеше.

    Кеш живёт до следующего полного прохода (до суток), а установка
    меняет «текущую» немедленно: без пересчёта страница после «Обновить»
    продолжала показывать доустановочную версию и «← доступно».
    """
    fn = _CHECKERS.get(name)
    if not fn:
        return {}
    with _results_lock:
        rows = (_results or {}).get("results") or []
        if not any(r.get("name") == name for r in rows):
            return {}
    row = _finalize_row(fn())
    with _results_lock:
        if not _results:
            return row
        rows = [row if r.get("name") == name else r
                for r in (_results.get("results") or [])]
        _results["results"] = rows
        _results["updates_count"] = sum(1 for r in rows if r.get("has_update"))
        _results["incomplete"] = _incomplete_rows(rows)
    return row


def schedule_refresh(name: str) -> bool:
    """Пересчитать строку в фоне (вызывают установщики). False — не нужно.

    Фоном — потому что частная проверка ходит в GitHub, а установщик не
    должен ждать её, чтобы отчитаться об успехе.
    """
    if name not in _CHECKERS:
        return False
    with _results_lock:
        if not _results:
            return False        # проверки ещё не было — пересчитывать нечего
    with _refreshing_lock:
        if name in _refreshing:
            return False
        _refreshing.add(name)

    def _run():
        try:
            refresh_component(name)
        except Exception as e:
            log.warning("update-checker: пересчёт %s: %s" % (name, e),
                        source="update_checker")
        finally:
            with _refreshing_lock:
                _refreshing.discard(name)

    threading.Thread(target=_run, daemon=True,
                     name="update-refresh-%s" % name).start()
    return True


def _binary_alive(path: str) -> bool:
    """Лежит ли по пути исполняемый непустой файл ПРЯМО СЕЙЧАС.

    Условие то же, по которому детекторы считают программу установленной
    (файл + право на исполнение + ненулевой размер), — иначе сверка
    расходилась бы с самой проверкой.
    """
    try:
        return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK) \
            and os.path.getsize(path) > 0
    except OSError:
        return False


def _path_mtime(path: str) -> int:
    """mtime файла (0 — не прочитался)."""
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0


def _log_installed_transitions(results: list) -> None:
    """Отметить в логе появление и пропажу бинарников между проверками.

    Лампочка «Установлен» может зажечься сама — не потому, что GUI врёт,
    а потому, что файл действительно появился (обрыв установки, чужой
    пакет, остатки старой версии). Разобраться постфактум было нечем:
    таблица показывает состояние, но не момент и не путь. Теперь в логе
    остаются отметка времени и путь — с ними видно, что именно GUI нашёл.
    """
    with _results_lock:
        prev = {r.get("name"): r for r in ((_results or {}).get("results") or [])}
    if not prev:
        return
    for r in results:
        was = prev.get(r.get("name"))
        if was is None:
            continue
        if bool(was.get("installed")) == bool(r.get("installed")):
            continue
        if r.get("installed"):
            log.info("update-checker: %s появился: %s%s"
                     % (r.get("name"), r.get("path") or "путь неизвестен",
                        (" (%s)" % r.get("current")) if r.get("current") else ""),
                     source="update_checker")
        else:
            log.info("update-checker: %s пропал (был %s)"
                     % (r.get("name"), was.get("path") or "путь неизвестен"),
                     source="update_checker")


def _revalidate_row(row: dict) -> dict:
    """Сверить строку результата с диском.

    Проверка ходит в GitHub и потому кешируется на сутки, но «установлен»
    — факт локальный: файл, найденный вчера, мог исчезнуть. Отдавать его
    из кеша значит показывать «Установлен: Да» для программы, которой на
    роутере уже нет, — ровно то, чем страница «Обновления» спорила с
    собственной страницей установки компонента (discussion #102).
    """
    r = dict(row)
    path = r.get("path") or ""
    if not r.get("installed") or not path:
        return r
    if _binary_alive(path):
        # Файл на месте, но мог смениться (обновили на странице движка,
        # через opkg, руками): тогда «текущая» и «доступно» в кеше —
        # про прежний файл. Пересчитываем строку в фоне и честно
        # говорим, что она устарела, а не показываем старое как факт.
        old = r.get("path_mtime") or 0
        if old and _path_mtime(path) not in (0, old):
            r["has_update"] = False
            r["stale"] = True
            schedule_refresh(r.get("name") or "")
        return r
    r["installed"] = False
    r["has_update"] = False
    r["current"] = ""
    r["path"] = ""
    r["path_mtime"] = 0
    # Показываем, что именно исчезло: иначе после самокоррекции строка
    # выглядит так, будто GUI и не находил ничего.
    r["vanished_path"] = path
    return r


def get_cached_results() -> dict:
    """Кешированные результаты последней проверки, сверенные с диском.

    Сверка дешёвая — один stat на строку, сеть не трогаем: «последняя
    версия» остаётся из кеша, а «установлен» отвечает за состояние на
    сейчас.
    """
    with _results_lock:
        cached = _results
    if not cached:
        return {"ok": True, "results": [], "updates_count": 0, "checked_at": 0}

    results = [_revalidate_row(r) for r in (cached.get("results") or [])]
    out = dict(cached)
    out["results"] = results
    out["updates_count"] = sum(1 for r in results if r.get("has_update"))
    return out


def _check_zapret() -> dict:
    """Проверить zapret2."""
    try:
        from core.zapret_installer import get_zapret_installer
        inst = get_zapret_installer()
        installed = inst.get_installed_version()
        latest = inst.get_latest_version()
        return {
            "name": "zapret2",
            "display_name": "zapret2 (nfqws2)",
            "installed": installed.get("installed", False),
            "current": installed.get("version", ""),
            "latest": latest.get("version", ""),
            "has_update": bool(latest.get("version") and
                               installed.get("version") and
                               latest["version"] != installed["version"]),
            # binary_path приходит из конфига и заполнен всегда — как
            # «что нашли» он годится только при installed.
            "path": (installed.get("binary_path", "")
                     if installed.get("installed") else ""),
            "error": latest.get("error") or "",
        }
    except Exception as e:
        return {"name": "zapret2", "display_name": "zapret2",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_singbox() -> dict:
    """Проверить sing-box."""
    try:
        from core.singbox_installer import get_singbox_installer
        inst = get_singbox_installer()
        result = inst.check_for_updates()
        return {
            "name": "singbox",
            "display_name": "sing-box",
            "installed": result.get("installed", {}).get("installed", False),
            "current": result.get("installed", {}).get("version", ""),
            "latest": result.get("latest", {}).get("version", ""),
            "has_update": result.get("has_update", False),
            "path": result.get("installed", {}).get("path", ""),
            # Без ok манифест/релиз не получен — причина уходит в строку,
            # а не теряется (раньше оставалось только «–»).
            "error": ("" if result.get("ok") else
                      result.get("error") or "источник не ответил"),
        }
    except Exception as e:
        return {"name": "singbox", "display_name": "sing-box",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_mihomo() -> dict:
    """Проверить mihomo."""
    try:
        from core.mihomo_installer import get_mihomo_installer
        inst = get_mihomo_installer()
        result = inst.check_for_updates()
        return {
            "name": "mihomo",
            "display_name": "mihomo",
            "installed": result.get("installed", {}).get("installed", False),
            "current": result.get("installed", {}).get("version", ""),
            "latest": result.get("latest", {}).get("version", ""),
            "has_update": result.get("has_update", False),
            "path": result.get("installed", {}).get("path", ""),
            # Без ok манифест/релиз не получен — причина уходит в строку,
            # а не теряется (раньше оставалось только «–»).
            "error": ("" if result.get("ok") else
                      result.get("error") or "источник не ответил"),
        }
    except Exception as e:
        return {"name": "mihomo", "display_name": "mihomo",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_awg() -> dict:
    """Проверить AmneziaWG.

    Ключи берём ровно те, что отдаёт `check_for_updates()`. Раньше здесь
    читались несуществующие: `installed.version` (на деле `go_version`),
    `latest.version` (плоские `latest_go`/`latest_tag`) и `has_update`
    (на деле `update_available`). Из-за этого на странице «Обновления»
    AmneziaWG всегда показывал «–» и никогда не предлагал обновление,
    хотя своя страница AWG ту же новую версию видела — она читает
    правильные поля.
    """
    try:
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        result = inst.check_for_updates()
        if not result.get("ok"):
            return {"name": "awg", "display_name": "AmneziaWG",
                    "installed": False, "current": "", "latest": "",
                    "has_update": False,
                    "error": result.get("error") or "нет манифеста"}
        inst_info = result.get("installed") or {}
        row = {
            "name": "awg",
            "display_name": "AmneziaWG",
            "installed": bool(inst_info.get("installed")),
            "current": inst_info.get("go_version") or "",
            "latest": result.get("latest_go") or "",
            "latest_source": "our",
            "has_update": bool(result.get("update_available")),
            # У AWG два бинарника; показываем ведущий (amneziawg-go), а
            # если установка записана только в settings — путь пустой.
            "path": inst_info.get("amneziawg_go") or inst_info.get("awg") or "",
        }
        if inst_info.get("installed") and inst_info.get("external"):
            # Чужая установка (пакет Entware и т.п.): «текущая» — версия
            # пакета или самого бинарника, «последняя» — версия нашей
            # сборки, шкалы разные. Обновлением это не считаем и говорим
            # почему, иначе «v0.2.16-1 → 3.1.20260828» горело бы вечно.
            src = inst_info.get("go_version_source") or ""
            row["external"] = "opkg" if src == "opkg" else "external"
            row["version_source"] = src
            row["has_update"] = False
            row["note"] = ("внешняя установка%s: версии в разных шкалах,"
                           " сравнивать не с чем. Заменить нашей сборкой"
                           " можно на странице AmneziaWG — файлы пакета"
                           " будут перезаписаны" % (
                               " (пакет amneziawg-go)" if src == "opkg"
                               else ""))
        return row
    except Exception as e:
        return {"name": "awg", "display_name": "AmneziaWG",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_gui() -> dict:
    """Проверить GUI (zapret-gui)."""
    try:
        from core.gui_updater import get_gui_updater
        updater = get_gui_updater()
        installed = updater.get_installed_version()
        latest = updater.get_latest_version()
        return {
            "name": "gui",
            "display_name": "Zapret Web-GUI",
            "installed": True,
            "current": installed.get("version", ""),
            "latest": latest.get("version", ""),
            "has_update": bool(latest.get("version") and
                               installed.get("version") and
                               latest["version"] != installed["version"]),
            "error": latest.get("error") or "",
        }
    except Exception as e:
        return {"name": "gui", "display_name": "Zapret Web-GUI",
                "installed": True, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_usque() -> dict:
    """Проверить usque (WARP/MASQUE)."""
    try:
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        env = mgr.detect()
        # Источник — НАША сборка (релизы `usque-bin-<версия>` в этом же
        # репозитории), ровно откуда ставит установщик. Раньше спрашивали
        # `side-effect-tm/usque-keenetic` — это давно лишь ЗАПАСНОЙ источник,
        # который отстаёт от самого usque: его последний релиз 0.3.0 несёт
        # usque 4.2.0. В итоге при установленной 4.2.1 «последней» значилась
        # 0.3.0, и GUI предлагал обновиться назад.
        latest, status = _our_build_latest("usque")
        current = env.get("version", "")
        row = {
            "name": "usque",
            "display_name": "usque (WARP/MASQUE)",
            "installed": env.get("installed", False),
            "current": current,
            "latest": latest,
            "latest_source": "our" if latest else "unknown",
            "has_update": _is_newer(latest, current),
            # Путь, по которому найден бинарник. «Установлен: Да» у usque —
            # это ровно «в одном из стандартных каталогов лежит исполняемый
            # файл usque»; когда пользователь его не ставил, единственный
            # способ разобраться — увидеть, что именно нашлось. Поэтому
            # путь печатается прямо в строке таблицы, а не прячется в
            # подсказке (discussion #102).
            "path": env.get("binary", ""),
        }
        if not latest and status == "not_found":
            # Нашей сборки нет — установщик поставит пакет usque-keenetic
            # (legacy_source): у него своя шкала версий.
            row["latest_source"] = "upstream"
            row["note"] = ("сборка usque-bin-* не найдена — установщик"
                           " поставит запасной пакет usque-keenetic")
        if env.get("installed"):
            _mark_usque_package(row)
        return row
    except Exception as e:
        return {"name": "usque", "display_name": "usque (WARP/MASQUE)",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _strip_build_prefix(name: str, value: str) -> str:
    """'tgproto-bin-v20260802-fe773fa' → '20260802-fe773fa'.

    Наши сборки живут под тэгами <name>-bin-v<версия>, и по разные
    стороны сравнения одно и то же может прийти как полный тэг и как
    голая версия. Без нормализации «обновление доступно» горело бы
    всегда.
    """
    from core.ext_binary_installer import BINARIES
    v = (value or "").strip()
    prefix = (BINARIES.get(name) or {}).get("release_prefix") or ""
    if prefix and v.startswith(prefix):
        v = v[len(prefix):]
    return v.lstrip("vV")


def _our_build_latest(name: str) -> tuple:
    """Версия последней НАШЕЙ сборки бинарника и статус поиска.

    Это и есть «последняя» с точки зрения пользователя: именно её
    поставит кнопка «Установить». Ищем ТЕМ ЖЕ github_release_by_prefix(),
    что и установщик (_install_from_manifest), — с общим окном выборки.
    Раньше здесь был list_releases() с окном 30 релизов против 50 у
    установщика: сборка opera-bin-v1.28.0 лежала 48-й, проверка её не
    видела и подставляла апстрим 1.30.0, а кнопка ставила 1.28.0.

    Статус: "ok" | "not_found" (сеть ответила, сборки нет — установщик
    уйдёт на legacy_source) | "error" (не узнали; апстрим подставлять
    нельзя — неизвестно, что поставит кнопка) | "" (у бинарника нет
    своих сборок).
    """
    global _github_any_success
    try:
        from core.ext_binary_installer import (BINARIES,
                                               github_release_by_prefix)
        cfg = BINARIES.get(name) or {}
        prefix = cfg.get("release_prefix") or ""
        repo = cfg.get("repo") or ""
        if not prefix or not repo:
            return "", ""
        rel = github_release_by_prefix(repo, prefix) or {}
        tag = rel.get("tag_name") or ""
        if tag.startswith(prefix):
            _github_any_success = True
            return _strip_build_prefix(name, tag), "ok"
        return "", ("not_found" if rel.get("not_found") else "error")
    except Exception:
        return "", "error"


def _mark_usque_package(row: dict) -> None:
    """Пометить usque, файлом которого владеет пакет Entware.

    usque-keenetic кладёт бинарник ровно в /opt/usr/bin/usque — туда же,
    куда ставит наша сборка. Когда сам бинарник версию не называет,
    usque_manager берёт версию ПАКЕТА (0.3.0), а «последняя» — версия
    usque в нашей сборке (4.2.1): шкалы разные, и 4.2.1 > 0.3.0 звало
    «обновиться» вечно. Плюс наша установка перезапишет файл пакета, а
    `opkg upgrade` потом вернёт пакетный.
    """
    try:
        from core.ext_binary_installer import _pkg_version
        pkg_v = (_pkg_version("usque-keenetic") or "").lstrip("vV")
    except Exception:
        pkg_v = ""
    if not pkg_v:
        return
    row["external"] = "opkg"
    current = (row.get("current") or "").lstrip("vV")
    if current and current == pkg_v:
        # Версия взята у пакета, а не у бинарника — сравнивать не с чем.
        row["version_source"] = "opkg"
        row["has_update"] = False
        row["note"] = ("%s — версия пакета usque-keenetic, %s — версия"
                       " usque в нашей сборке; шкалы разные. Установка"
                       " нашей сборки перезапишет файл пакета, а"
                       " `opkg upgrade` вернёт пакетный" % (
                           pkg_v, row.get("latest") or "–"))
    else:
        row["version_source"] = "binary"
        row["note"] = ("файл принадлежит пакету usque-keenetic %s:"
                       " установка нашей сборки его перезапишет, а"
                       " `opkg upgrade` вернёт пакетный" % pkg_v)


def _check_tgproto() -> dict:
    """Проверить tg-mtproxy-client."""
    try:
        from core.tgproxy_manager import get_mtproxy_client_manager
        mgr = get_mtproxy_client_manager()
        detect = mgr.detect()
        latest, status = _our_build_latest("tgproto")
        # Установленное могло быть записано как полный тэг сборки —
        # приводим обе стороны к одному виду.
        current = _strip_build_prefix("tgproto", detect.get("version") or "")
        row = {
            "name": "tgproto",
            "display_name": "tg-mtproxy-client",
            "installed": detect.get("installed", False),
            "current": current,
            "latest": latest,
            "latest_source": "our" if latest else "unknown",
            "has_update": bool(latest and current and latest != current),
            "path": detect.get("path", ""),
        }
        if not latest:
            if status == "not_found":
                # Установщик уйдёт на запасной источник, а тот закреплён
                # на rolling-тэге (BINARIES['tgproto']['legacy_source']) —
                # «последняя» ровно он, а не /releases/latest апстрима,
                # который мог отдать чужой релиз или пустоту («–» при
                # кнопке «Установить»). Номера версии у rolling-сборки нет,
                # поэтому обновлением её не считаем.
                from core.ext_binary_installer import BINARIES
                legacy = (BINARIES.get("tgproto") or {}).get(
                    "legacy_source") or {}
                row["latest"] = legacy.get("release_tag") or ""
                row["latest_source"] = "upstream"
                row["has_update"] = False
                row["note"] = ("наша сборка tgproto-bin-* не найдена —"
                               " установщик поставит rolling-сборку %s"
                               " без номера версии"
                               % (legacy.get("repo") or "апстрима"))
            else:
                row["note"] = ("не удалось узнать последнюю сборку"
                               " (GitHub недоступен)")
        return row
    except Exception as e:
        return {"name": "tgproto", "display_name": "tg-mtproxy-client",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_tgwsproxy() -> dict:
    """Проверить tg-ws-proxy-go (основной Telegram-движок)."""
    try:
        from core.ext_binary_installer import (BINARIES,
                                               _pkg_version_matches_tag)
        from core.tgproxy_manager import get_tgwsproxy_manager
        mgr = get_tgwsproxy_manager()
        detect = mgr.detect()
        current = detect.get("version", "")

        # «Последняя» — та версия, которую реально поставит кнопка, а не та,
        # что лежит в /releases/latest. Движок ЗАКРЕПЛЁН на 0.9.3: начиная с
        # v1.0.0 апстрим переписан с Go на Python и стал десктопным GUI — в
        # его релизах нет ни .ipk, ни .apk для роутера (см. BINARIES
        # ['tgwsproxy'] и docs/upstream.json → hold). Пока сюда подставлялся
        # апстримный тег, страница «Обновления» звала обновиться на v1.4.0, а
        # установщик честно отвечал «актуальная версия 0.9.3 уже установлена»
        # — обновление, которого нет (discussion #102).
        cfg = BINARIES.get("tgwsproxy") or {}
        pinned = (cfg.get("release_tag") or "").strip()
        upstream = _github_latest("spatiumstas/tg-ws-proxy-go")
        latest = pinned or upstream

        res = {
            "name": "tgwsproxy",
            "display_name": "tg-ws-proxy-go",
            "installed": detect.get("installed", False),
            "current": current,
            "latest": latest,
            # Движок ставится ПАКЕТОМ, и opkg/apk хранят версию с ревизией
            # сборки (`0.9.3-1`, `0.9.3-r1`), а тег релиза — без неё
            # (`0.9.3`). Прямое сравнение строк держало кнопку «Обновить»
            # вечно зажжённой на уже актуальной версии (issue #272).
            "has_update": bool(latest and current and
                               not _pkg_version_matches_tag(current, latest)),
            # Движок ставится пакетом; «что нашли» — его init.d-скрипт,
            # по нему же detect() и считает пакет установленным.
            "path": detect.get("path", ""),
        }
        if pinned:
            # Показываем и то, что версия закреплена, и апстримный тег —
            # иначе «у них 1.4.0, а у меня 0.9.3» выглядит как проглоченная
            # ошибка проверки.
            res["pinned"] = True
            res["latest_source"] = "pinned"
            res["upstream_latest"] = upstream
            res["pin_reason"] = ("апстрим с v1.0.0 — десктопное приложение"
                                 " без сборок для роутера")
        return res
    except Exception as e:
        return {"name": "tgwsproxy", "display_name": "tg-ws-proxy-go",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_opera() -> dict:
    """Проверить opera-proxy."""
    try:
        from core.opera_proxy_manager import get_opera_proxy_manager
        mgr = get_opera_proxy_manager()
        env = mgr.detect()
        # «Последняя» — та, которую реально поставит кнопка: наша сборка.
        # Апстрим — только когда сеть ответила, а сборки нет (туда же
        # уйдёт установщик через legacy_source, он ставит ПОСЛЕДНИЙ
        # релиз апстрима). При сбое поиска апстрим не подставляем: так
        # страница и обещала 1.30.0, пока кнопка ставила нашу 1.28.0.
        latest, status = _our_build_latest("opera")
        source = "our" if latest else "unknown"
        note = ""
        if not latest and status == "not_found":
            latest = _github_latest("Alexey71/opera-proxy")
            source = "upstream" if latest else "unknown"
            note = ("сборка opera-bin-* не найдена — установщик поставит"
                    " релиз апстрима Alexey71/opera-proxy")
        elif not latest:
            note = "не удалось узнать последнюю сборку (GitHub недоступен)"
        current = _strip_build_prefix("opera", env.get("version") or "")
        row = {
            "name": "opera",
            "display_name": "opera-proxy",
            "installed": env.get("installed", False),
            "current": current,
            "latest": latest,
            "latest_source": source,
            "has_update": _is_newer(latest, current),
            "path": env.get("binary", ""),
        }
        if note:
            row["note"] = note
        return row
    except Exception as e:
        return {"name": "opera", "display_name": "opera-proxy",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def geneva_release_info(current: str = "") -> dict:
    """Что поставит кнопка geneva и есть ли смысл её предлагать.

    «Последняя» — ЗАКРЕПЛЁННЫЙ релиз из BINARIES['geneva']: sha256 в
    манифесте сверены именно для него, и установщик ставит его же.
    Апстримный тег показываем рядом, чтобы «у них новее» не выглядело
    проглоченной ошибкой. Сборка не из релиза (версия — хэш коммита,
    `3477eee`) обновлением не считается: сравнивать её не с чем.
    """
    from core.ext_binary_installer import BINARIES
    cfg = BINARIES.get("geneva") or {}
    pinned = (cfg.get("release_tag") or "").strip()
    latest = pinned.lstrip("vV")
    current = (current or "").strip().lstrip("vV")
    # Строго «1.0.0»: хэш «3477eee» начинается с цифр, и _version_tuple
    # принял бы его за версию 3477.
    release_build = bool(re.match(r"^\d+\.\d+(\.\d+)*$", current))
    return {
        "latest": latest,
        "tag": pinned,
        "release_build": release_build,
        "has_update": bool(current and release_build
                           and _is_newer(latest, current)),
    }


def _check_geneva() -> dict:
    """Проверить geneva_c."""
    try:
        from core.geneva_manager import get_geneva_manager
        det = get_geneva_manager().detect()
        current = det.get("version", "") or ""
        info = geneva_release_info(current)
        upstream = _github_latest("avatarDD/geneva_c")
        row = {
            "name": "geneva",
            "display_name": "geneva_c (движок обхода)",
            "installed": det.get("installed", False),
            "current": current,
            "latest": info["latest"],
            "has_update": info["has_update"],
            "path": det.get("binary", ""),
            "pinned": True,
            "latest_source": "pinned",
            "upstream_latest": upstream,
            "pin_reason": "sha256 сверены для этой версии",
        }
        if det.get("installed") and current and not info["release_build"]:
            row["note"] = ("установлена сборка не из релиза (%s) — "
                           "сравнивать с релизом не с чем" % current)
        elif det.get("installed") and not det.get("proto_ok"):
            row["note"] = det.get("hint") or "несовместимая версия geneva"
        return row
    except Exception as e:
        return {"name": "geneva", "display_name": "geneva_c (движок обхода)",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _version_tuple(v: str):
    """Числовой ключ версии; None — не разбирается."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)", (v or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _is_newer(latest: str, current: str) -> bool:
    """Есть ли смысл предлагать обновление.

    Сравниваем ЧИСЛАМИ, а не `!=`. Простое неравенство строк даёт две
    беды: предлагает «обновиться» на версию старше (usque 4.2.1 → 0.3.0)
    и срабатывает на разнице записи одной и той же версии. Если версии
    не разбираются как числа — откатываемся на строгое неравенство,
    чтобы не потерять обновление там, где формат нестандартный.
    """
    if not latest or not current:
        return False
    lv, cv = _version_tuple(latest), _version_tuple(current)
    if lv is None or cv is None:
        return latest.strip() != current.strip()
    return lv > cv


def _github_latest(repo: str) -> str:
    """Получить/latest tag из GitHub releases.

    MR-96: при сетевой ошибке возвращает последнее известное значение
    (из _last_known_latest) вместо пустой строки, чтобы не затирать кеш.
    """
    global _last_known_latest, _github_any_success
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    req = urllib.request.Request(url, headers={"User-Agent": "zapret-gui/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10.0) as r:
            body = r.read().decode("utf-8", "replace")
            data = json.loads(body or "{}")
            tag = data.get("tag_name", "")
            result = tag.lstrip("v") if tag else ""
            if result:
                with _last_known_lock:
                    _last_known_latest[repo] = result
                _github_any_success = True
            return result
    except Exception:
        # MR-96: при ошибке возвращаем последнее известное значение
        with _last_known_lock:
            return _last_known_latest.get(repo, "")


# ─────── background checker ───────

# (движок, версия), о которых уже сообщили в Telegram за время работы.
_notified_updates = set()


def _notify_updates(result: dict) -> None:
    """Уведомить о новых версиях — по разу на версию."""
    fresh = []
    for r in (result or {}).get("results") or []:
        if not r.get("has_update") and not r.get("update_available"):
            continue
        key = (r.get("name"), r.get("latest"))
        if key in _notified_updates:
            continue
        _notified_updates.add(key)
        fresh.append("%s %s → %s" % (r.get("display_name") or r.get("name"),
                                     r.get("current") or "?",
                                     r.get("latest") or "?"))
    if fresh:
        from core import notify
        notify.event("update", "⬆️ Обновления: %s" % "; ".join(fresh))


class UpdateCheckerDaemon:
    """Фоновый процесс: проверяет обновления по расписанию."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()
        self._stale_check = False
        self._checking = False  # идёт ли сейчас check_all() (для UI-поллинга)

    def reconfigure(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        if cfg.get("update_checker", "enabled", default=False):
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            # Своё событие на каждый запуск. С общим получалась гонка:
            # _stop() выставлял флаг, но не дожидался потока, а следующий
            # _start() сразу его сбрасывал — старый цикл просыпался с уже
            # чистым флагом и работал рядом с новым. Каждый цикл делает
            # ~9 запросов к GitHub API, лимит которого 60 в час, поэтому
            # дубль быстро упирался в rate-limit. Через API это
            # достижимо парой кликов: /api/updates/stop → /start.
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            t = threading.Thread(target=self._run_loop, args=(stop_evt,),
                                 name="update-checker", daemon=True)
            t.start()
            self._thread = t
            log.info("update-checker: запущен", source="update_checker")

    def _stop(self):
        with self._lock:
            if not self._thread:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("update-checker: остановлен", source="update_checker")

    def _run_loop(self, stop_evt=None):
        if stop_evt is None:
            stop_evt = self._stop_evt
        # Даём роутеру 60 секунд на инициализацию сетевых интерфейсов
        if stop_evt.wait(60.0):
            return

        while not stop_evt.is_set():
            # Значение по умолчанию до try: иначе падение на чтении
            # конфига оставило бы interval_h неопределённым.
            interval_h = DEFAULT_CHECK_INTERVAL_HOURS
            try:
                from core.config_manager import get_config_manager
                cfg = get_config_manager()
                interval_h = _sane_interval_hours(
                    cfg.get("update_checker", "interval_hours",
                            default=DEFAULT_CHECK_INTERVAL_HOURS))
                with self._lock:
                    self._checking = True
                try:
                    result = check_all()
                finally:
                    with self._lock:
                        self._checking = False
                # MR-96: если ни один GitHub API запрос не удался — данные устарели
                with self._lock:
                    self._stale_check = not _github_any_success
                updates = result.get("updates_count", 0)
                if updates:
                    log.info("update-checker: найдено %d обновлений" % updates,
                             source="update_checker")
                    _notify_updates(result)
            except Exception as e:
                with self._lock:
                    self._stale_check = True
                log.warning("update-checker: %s" % e, source="update_checker")
            stop_evt.wait(interval_h * 3600)

    def check_now(self) -> bool:
        """Разовая немедленная проверка в фоне (для кнопки в UI).

        Не зависит от расписания демона и его 60s-инициализации, но
        уважает in-flight guard (MR-58): параллельные check_all() спавнят
        18+ curl и упираются в GitHub rate-limit 60 req/h.

        Возвращает True, если проверка запущена; False — если уже идёт.
        """
        with self._lock:
            if self._checking:
                return False
            self._checking = True

        def _run():
            try:
                check_all()
                with self._lock:
                    self._stale_check = not _github_any_success
            except Exception as e:
                with self._lock:
                    self._stale_check = True
                log.warning("update-checker check_now: %s" % e,
                            source="update_checker")
            finally:
                with self._lock:
                    self._checking = False

        threading.Thread(target=_run, daemon=True,
                         name="update-check-now").start()
        return True

    def get_status(self):
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
            stale_check = self._stale_check
            checking = self._checking
        status = {"running": running, "stale_check": stale_check,
                  "checking": checking}
        if stale_check:
            status["warning"] = "⚠️ Невозможно проверить обновления"
        return status


_checker = None
_checker_lock = threading.Lock()


def get_update_checker() -> UpdateCheckerDaemon:
    global _checker
    if _checker is None:
        with _checker_lock:
            if _checker is None:
                _checker = UpdateCheckerDaemon()
    return _checker
