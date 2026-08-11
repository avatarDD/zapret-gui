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

    # Единое правило страницы «Обновления»: обновлять можно только то, что
    # УСТАНОВЛЕНО. Каждый инсталлятор считает has_update сам, и стоит одному
    # забыть про эту проверку — у неустановленной программы версия пустая,
    # «последняя» непустая, и в таблице загорается «← доступно» с кнопкой
    # «Обновить» для того, чего на роутере нет (discussion #102: так вели
    # себя sing-box и mihomo). Гейт здесь делает страницу честной независимо
    # от частных ошибок в инсталляторах.
    for r in results:
        if r.get("has_update") and not r.get("installed"):
            r["has_update"] = False

    updates_count = sum(1 for r in results if r.get("has_update"))

    with _results_lock:
        _results = {
            "ok": True,
            "results": results,
            "updates_count": updates_count,
            "checked_at": int(time.time()),
        }
        _last_check = time.time()

    return _results


def get_cached_results() -> dict:
    """Получить кешированные результаты последней проверки."""
    with _results_lock:
        if _results:
            return _results
    return {"ok": True, "results": [], "updates_count": 0, "checked_at": 0}


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
        return {
            "name": "awg",
            "display_name": "AmneziaWG",
            "installed": bool(inst_info.get("installed")),
            "current": inst_info.get("go_version") or "",
            "latest": result.get("latest_go") or "",
            "has_update": bool(result.get("update_available")),
        }
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
        latest = _latest_from_our_release("usque")
        return {
            "name": "usque",
            "display_name": "usque (WARP/MASQUE)",
            "installed": env.get("installed", False),
            "current": env.get("version", ""),
            "latest": latest,
            "has_update": _is_newer(latest, env.get("version", "")),
            # Путь, по которому найден бинарник. «Установлен: Да» у usque —
            # это ровно «в одном из стандартных каталогов лежит исполняемый
            # файл usque»; когда пользователь его не ставил, единственный
            # способ разобраться — увидеть, что именно нашлось.
            "path": env.get("binary", ""),
        }
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


def _our_build_latest(name: str) -> str:
    """Версия последней НАШЕЙ сборки бинарника ('' — сборок ещё нет).

    Это и есть «последняя» с точки зрения пользователя: именно её
    поставит кнопка «Установить». Спрашивать latest у апстрима значило
    бы обещать версию, которую установщик не поставит.
    """
    try:
        from core.ext_binary_installer import BINARIES, list_releases
        cfg = BINARIES.get(name) or {}
        if not cfg.get("release_prefix"):
            return ""
        rels = list_releases(name)
        if not rels.get("ok") or not rels.get("releases"):
            return ""
        return _strip_build_prefix(name, rels["releases"][0]["tag"])
    except Exception:
        return ""


def _check_tgproto() -> dict:
    """Проверить tg-mtproxy-client."""
    try:
        from core.tgproxy_manager import get_mtproxy_client_manager
        mgr = get_mtproxy_client_manager()
        detect = mgr.detect()
        # Сначала наша сборка; если её ещё нет, установщик уходит на
        # запасной источник — тогда и «последняя» должна быть оттуда.
        latest = _our_build_latest("tgproto")
        if not latest:
            latest = _github_latest("necronicle/z2k")
        # Установленное могло быть записано как полный тэг сборки —
        # приводим обе стороны к одному виду.
        current = _strip_build_prefix("tgproto", detect.get("version") or "")
        return {
            "name": "tgproto",
            "display_name": "tg-mtproxy-client",
            "installed": detect.get("installed", False),
            "current": current,
            "latest": latest,
            "has_update": bool(latest and current and latest != current),
        }
    except Exception as e:
        return {"name": "tgproto", "display_name": "tg-mtproxy-client",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _check_tgwsproxy() -> dict:
    """Проверить tg-ws-proxy-go (основной Telegram-движок)."""
    try:
        from core.ext_binary_installer import _pkg_version_matches_tag
        from core.tgproxy_manager import get_tgwsproxy_manager
        mgr = get_tgwsproxy_manager()
        detect = mgr.detect()
        latest = _github_latest("spatiumstas/tg-ws-proxy-go")
        current = detect.get("version", "")
        # Движок ставится ПАКЕТОМ, и opkg/apk хранят версию с ревизией
        # сборки (`0.9.3-1`, `0.9.3-r1`), а тег релиза — без неё
        # (`0.9.3`). Прямое сравнение строк держало кнопку «Обновить»
        # вечно зажжённой на уже актуальной версии (issue #272).
        return {
            "name": "tgwsproxy",
            "display_name": "tg-ws-proxy-go",
            "installed": detect.get("installed", False),
            "current": current,
            "latest": latest,
            "has_update": bool(latest and current and
                               not _pkg_version_matches_tag(current, latest)),
        }
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
        # То же правило, что и у tgproto: «последняя» — та, которую
        # реально поставит кнопка. Наша сборка, а если её ещё нет —
        # апстрим (туда же уйдёт и установщик через legacy_source).
        latest = _our_build_latest("opera")
        if not latest:
            latest = _github_latest("Alexey71/opera-proxy")
        current = _strip_build_prefix("opera", env.get("version") or "")
        return {
            "name": "opera",
            "display_name": "opera-proxy",
            "installed": env.get("installed", False),
            "current": current,
            "latest": latest,
            "has_update": bool(latest and current and latest != current),
        }
    except Exception as e:
        return {"name": "opera", "display_name": "opera-proxy",
                "installed": False, "current": "", "latest": "",
                "has_update": False, "error": str(e)}


def _latest_from_our_release(name: str) -> str:
    """Версия последнего НАШЕГО релиза бинарника `name`.

    Мы собираем часть движков сами и публикуем как `<name>-bin-<версия>`
    в собственном репозитории — установщик берёт их именно оттуда
    (`BINARIES[name]["release_prefix"]`). Спрашивать вместо этого чужой
    репозиторий-донор неверно: он живёт своей жизнью и отстаёт, отчего
    «последняя» версия оказывается старше установленной.
    """
    try:
        from core.ext_binary_installer import (BINARIES,
                                               github_release_by_prefix)
        cfg = BINARIES.get(name) or {}
        prefix = cfg.get("release_prefix") or ""
        repo = cfg.get("repo") or ""
        if not prefix or not repo:
            return ""
        rel = github_release_by_prefix(repo, prefix) or {}
        tag = rel.get("tag_name") or ""
        return tag[len(prefix):].lstrip("v") if tag.startswith(prefix) else ""
    except Exception:
        return ""


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
