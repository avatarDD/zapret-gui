# core/server_pool.py
"""
Пул прокси-серверов из публичных источников.

Идея (отличается от core/subscription_manager.py, где каждая приватная
подписка → свой конфиг): здесь много ПУБЛИЧНЫХ источников-«свалок»
(тысячи бесплатных ключей) сливаются в ОДИН пул, дедуплицируются,
опционально прогоняются тестером (core/proxy_tester.py), обрезаются до
top-N и оборачиваются в urltest-группу. Получается один конфиг
`server-pool`, в котором sing-box сам бесшовно переключается между
живыми серверами.

Ключевые свойства (надёжность):
  * «не затирать при пустом» — у каждого источника есть last-good кэш
    (отдельный JSON рядом с settings.json). Если источник вернул ошибку
    или 0 ключей — берём его прошлый успешный набор, а не выкидываем.
  * лимиты на размер/число серверов (защита от мусора и от раздувания
    конфига на роутере со слабым CPU).
  * редактируемый список источников + набор рекомендованных пресетов.

settings.json layout:
    {
      "singbox": {
        "pool": {
          "sources": {
            "<sid>": {"name","url","format","enabled"}
          },
          "interval_hours": 12,
          "group": "urltest",
          "cap": 100,
          "health_filter": false,
          "target": "cloudflare",
          "transport": ""|"awg[:iface]"|"singbox[:конфиг]"|"mihomo[:конфиг]",
          "last_refresh": 0,
          "last_status": "",
          "last_error": "",
          "last_count": 0
        }
      }
    }
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse

from core.log_buffer import log


POOL_CONFIG_NAME = "server-pool"

DEFAULT_INTERVAL_HOURS = 12
DEFAULT_CAP            = 100
MAX_CAP               = 300
DEFAULT_GROUP         = "urltest"
DEFAULT_TARGET        = "cloudflare"
# Параллельный фетч источников пула: иначе N «свалок» по 20с таймаута
# фетчатся последовательно (N×20с) и блокируют фоновый PoolRefresher.
POOL_FETCH_WORKERS    = 6

# Рекомендованные публичные источники (пользователь может добавить
# одним кликом и потом редактировать/удалять). Это «свалки» бесплатных
# ключей — качество низкое, поэтому здравая дефолтная связка:
# health_filter=ON + urltest.
BUILTIN_PRESETS = [
    {
        "name": "Epodonios v2ray-configs (all)",
        "url": "https://raw.githubusercontent.com/Epodonios/"
               "v2ray-configs/main/All_Configs_Sub.txt",
        "format": "auto",
    },
    {
        "name": "ebrasha free-v2ray-public-list",
        "url": "https://raw.githubusercontent.com/ebrasha/"
               "free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt",
        "format": "auto",
    },
    {
        "name": "igareck vpn-configs-for-russia",
        # configs.txt в репозитории нет (404). Актуальный файл «чёрных
        # списков» — BLACK_VLESS_RUS.txt (issue #149/#166).
        "url": "https://raw.githubusercontent.com/igareck/"
               "vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
        "format": "auto",
    },
    {
        "name": "kort0881 vless-configs-russia",
        # vless.txt в корне больше нет (404) — репозиторий переехал на
        # mirror-файлы. Рабочий список — mermeroo_only_new_for_mirror.txt.
        "url": "https://raw.githubusercontent.com/kort0881/"
               "vpn-vless-configs-russia/main/mermeroo_only_new_for_mirror.txt",
        "format": "auto",
    },
]

_lock = threading.Lock()


# ─────── settings access ───────

def _load_pool() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load() or {}
    except Exception:
        return {}
    sb = cfg.get("singbox") or {}
    if not isinstance(sb, dict):
        return {}
    pool = sb.get("pool") or {}
    return pool if isinstance(pool, dict) else {}


def _save_pool(pool: dict):
    try:
        from core.config_manager import get_config_manager
    except Exception as e:
        log.warning("server_pool: settings unavailable: %s" % e,
                    source="singbox")
        return
    cm = get_config_manager()
    # ВАЖНО: не делаем `cm.load() or {}` — пустой (но валидный) dict
    # ложноотрицателен и оторвал бы нас от живого _config.
    cfg = cm.load()
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("singbox", {})["pool"] = pool
    try:
        cm.save()
    except Exception as e:
        log.warning("server_pool: save: %s" % e, source="singbox")


def get_settings() -> dict:
    """Сводные настройки пула (без секции sources) — для UI."""
    pool = _load_pool()
    return {
        "interval_hours": int(pool.get("interval_hours") or DEFAULT_INTERVAL_HOURS),
        "group":          pool.get("group") or DEFAULT_GROUP,
        "cap":            int(pool.get("cap") or DEFAULT_CAP),
        "health_filter":  bool(pool.get("health_filter")),
        "target":         pool.get("target") or DEFAULT_TARGET,
        "transport":      pool.get("transport") or "",
        "last_refresh":   int(pool.get("last_refresh") or 0),
        "last_status":    pool.get("last_status") or "",
        "last_error":     pool.get("last_error") or "",
        "last_count":     int(pool.get("last_count") or 0),
        "config_name":    POOL_CONFIG_NAME,
    }


def update_settings(**kw) -> dict:
    with _lock:
        pool = _load_pool()
        if "interval_hours" in kw and kw["interval_hours"] is not None:
            pool["interval_hours"] = max(1, int(kw["interval_hours"]))
        if "group" in kw and kw["group"] in ("urltest", "selector"):
            pool["group"] = kw["group"]
        if "cap" in kw and kw["cap"] is not None:
            pool["cap"] = max(1, min(MAX_CAP, int(kw["cap"])))
        if "health_filter" in kw and kw["health_filter"] is not None:
            pool["health_filter"] = bool(kw["health_filter"])
        if "target" in kw and kw["target"]:
            pool["target"] = str(kw["target"])
        if "transport" in kw and kw["transport"] is not None:
            # Транспорт скачивания источников ('' = напрямую). Неизвестную
            # спеку не сохраняем.
            from core.subscription_manager import _norm_transport
            pool["transport"] = _norm_transport(kw["transport"])
        _save_pool(pool)
    get_pool_refresher().reconfigure()
    return {"ok": True}


# ─────── sources CRUD ───────

def _sources() -> dict:
    pool = _load_pool()
    src = pool.get("sources") or {}
    return src if isinstance(src, dict) else {}


def list_sources() -> list:
    out = []
    for sid, s in _sources().items():
        if isinstance(s, dict):
            out.append(dict(s, id=sid))
    out.sort(key=lambda s: (s.get("name") or s.get("id") or ""))
    return out


def presets() -> list:
    """Рекомендованные источники (для кнопок «добавить» в UI)."""
    existing = {s.get("url") for s in list_sources()}
    return [dict(p, added=(p["url"] in existing)) for p in BUILTIN_PRESETS]


def add_source(name: str, url: str, *, fmt: str = "auto",
               enabled: bool = True) -> dict:
    if not name or not url:
        return {"ok": False, "error": "Нужны name и url"}
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "URL должен быть http:// или https://"}
    # os.urandom, а не uuid: на Entware python3-light без модуля uuid
    sid = "src-" + os.urandom(4).hex()
    with _lock:
        pool = _load_pool()
        sources = pool.get("sources")
        if not isinstance(sources, dict):
            sources = {}
        # Дедуп по URL — не плодим один и тот же источник.
        for s in sources.values():
            if isinstance(s, dict) and s.get("url") == url.strip():
                return {"ok": False, "error": "Источник с таким URL уже есть"}
        sources[sid] = {
            "name": name.strip(),
            "url": url.strip(),
            "format": fmt if fmt in ("auto", "uri", "clash",
                                     "singbox-json") else "auto",
            "enabled": bool(enabled),
        }
        pool["sources"] = sources
        _save_pool(pool)
    get_pool_refresher().reconfigure()
    return {"ok": True, "id": sid}


def update_source(sid: str, **kw) -> dict:
    with _lock:
        pool = _load_pool()
        sources = pool.get("sources") or {}
        if sid not in sources or not isinstance(sources[sid], dict):
            return {"ok": False, "error": "Источник не найден"}
        s = sources[sid]
        for k in ("name", "url", "format"):
            if k in kw and kw[k] is not None:
                s[k] = str(kw[k]).strip()
        if "enabled" in kw and kw["enabled"] is not None:
            s["enabled"] = bool(kw["enabled"])
        pool["sources"] = sources
        _save_pool(pool)
    get_pool_refresher().reconfigure()
    return {"ok": True, "id": sid}


def remove_source(sid: str) -> dict:
    with _lock:
        pool = _load_pool()
        sources = pool.get("sources") or {}
        if sid in sources:
            del sources[sid]
            pool["sources"] = sources
            _save_pool(pool)
        # Чистим last-good кэш этого источника.
        cache = _load_cache()
        if sid in cache:
            del cache[sid]
            _save_cache(cache)
    get_pool_refresher().reconfigure()
    return {"ok": True}


# ─────── last-good cache (don't-clobber-on-empty) ───────

def _cache_path() -> str:
    try:
        from core.config_manager import get_config_manager
        cfg_dir = os.path.dirname(get_config_manager().config_path)
    except Exception:
        cfg_dir = "/tmp"
    return os.path.join(cfg_dir, ".server_pool_cache.json")


def _load_cache() -> dict:
    path = _cache_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict):
    path = _cache_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except OSError as e:
        log.warning("server_pool: cache save: %s" % e, source="singbox")


# ─────── dedup ───────

def _ident(ob: dict) -> tuple:
    """Ключ дедупликации сервера: тип+host+port+креды."""
    cred = (ob.get("uuid") or ob.get("password") or ob.get("id") or "")
    return (ob.get("type"), ob.get("server"),
            ob.get("server_port"), cred)


def dedup_outbounds(outbounds: list) -> list:
    """Убрать дубликаты и гарантировать уникальность tag'ов."""
    seen_ident = set()
    seen_tags = set()
    out = []
    for ob in outbounds:
        if not isinstance(ob, dict) or not ob.get("type"):
            continue
        ident = _ident(ob)
        if ident in seen_ident:
            continue
        seen_ident.add(ident)
        tag = ob.get("tag") or "out"
        base, i = tag, 2
        while tag in seen_tags:
            tag = "%s-%d" % (base, i)
            i += 1
        ob = dict(ob, tag=tag)
        seen_tags.add(tag)
        out.append(ob)
    return out


# ─────── refresh ───────

def refresh_pool(progress_cb=None) -> dict:
    """
    Скачать все включённые источники, слить → дедуп → (опц.) тест →
    cap → собрать конфиг `server-pool` с urltest-группой.

    Инвариант «не затирать при пустом»: источник, который не отдал
    ключей, заменяется своим last-good набором. Если ВЕСЬ агрегат
    пустой (и кэша нет) — конфиг не перезаписываем.

    progress_cb(phase, done, total) — опциональный колбэк прогресса:
      phase ∈ {"fetch","test","build"}.
    """
    from core.subscription_manager import fetch_outbounds

    def _report(phase, done, total):
        if progress_cb:
            try:
                progress_cb(phase, done, total)
            except Exception:
                pass

    settings = get_settings()
    sources = list_sources()
    enabled = [s for s in sources if s.get("enabled")]
    if not enabled:
        return {"ok": False, "error": "Нет включённых источников"}

    cache = _load_cache()
    per_source = []
    aggregate = []

    _report("fetch", 0, len(enabled))
    transport = settings.get("transport") or ""

    # Фетчим источники ПАРАЛЛЕЛЬНО (сеть, до 20с на источник), но результаты
    # обрабатываем в порядке источников — детерминизм + никаких гонок на
    # cache/aggregate/per_source.
    import concurrent.futures
    fetched = {}
    done = 0
    workers = min(POOL_FETCH_WORKERS, len(enabled))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fetch_outbounds, s["url"],
                          s.get("format") or "auto",
                          transport=transport): s for s in enabled}
        for fu in concurrent.futures.as_completed(futs):
            s = futs[fu]
            try:
                fetched[s["id"]] = fu.result()
            except Exception as e:
                fetched[s["id"]] = {"outbounds": [], "error": str(e)}
            done += 1
            _report("fetch", done, len(enabled))

    for s in enabled:
        sid = s["id"]
        res = fetched.get(sid) or {"outbounds": [], "error": "пусто"}
        obs = res.get("outbounds") or []
        used_cache = False
        if not obs:
            cached = (cache.get(sid) or {}).get("outbounds") or []
            if cached:
                obs = cached
                used_cache = True
            per_source.append({
                "id": sid, "name": s.get("name"),
                "count": len(obs), "used_cache": used_cache,
                "error": res.get("error") or "пусто",
            })
        else:
            cache[sid] = {"outbounds": obs, "count": len(obs),
                          "fetched_at": int(time.time())}
            per_source.append({
                "id": sid, "name": s.get("name"),
                "count": len(obs), "used_cache": False, "error": "",
            })
        aggregate.extend(obs)

    _save_cache(cache)

    aggregate = dedup_outbounds(aggregate)
    if not aggregate:
        _record(ok=False, error="агрегат пуст (и кэш пуст)", count=0)
        return {"ok": False, "error": "Не удалось собрать ни одного сервера",
                "sources": per_source}

    total_before_filter = len(aggregate)
    cap = settings["cap"]

    # Опциональный health-filter — оставляем только живые, по latency.
    tested = None
    if settings["health_filter"]:
        try:
            from core.proxy_tester import run_outbound_tests
            tested = run_outbound_tests(
                aggregate, target=settings["target"],
                max_servers=min(MAX_CAP, max(cap * 2, cap)),
                progress_cb=lambda ph, d, t: _report("test", d, t))
            alive_tags = [r["tag"] for r in tested.get("results", [])
                          if r.get("alive")]
            by_tag = {o["tag"]: o for o in aggregate}
            aggregate = [by_tag[t] for t in alive_tags if t in by_tag]
        except Exception as e:
            log.warning("server_pool health-filter: %s" % e, source="singbox")

    aggregate = aggregate[:cap]

    if not aggregate:
        _record(ok=False, error="после фильтра не осталось живых", count=0)
        return {"ok": False,
                "error": "После теста не осталось живых серверов",
                "sources": per_source,
                "tested": (tested.get("summary") if tested else None)}

    # Сборка конфига с группой.
    _report("build", 0, 1)
    try:
        _build_and_save(aggregate, settings["group"])
    except Exception as e:
        _record(ok=False, error="save: %s" % e, count=len(aggregate))
        return {"ok": False, "error": "Сборка конфига: %s" % e}

    _report("build", 1, 1)
    _record(ok=True, error="", count=len(aggregate))
    log.success("server-pool: собран из %d источников, серверов %d "
                "(до фильтра %d)" % (len(enabled), len(aggregate),
                                     total_before_filter),
                source="singbox")
    return {
        "ok": True,
        "config": POOL_CONFIG_NAME,
        "count": len(aggregate),
        "total_before_filter": total_before_filter,
        "sources": per_source,
        "tested": (tested.get("summary") if tested else None),
    }


def _build_and_save(outbounds: list, group: str):
    from core.singbox_config import (
        make_minimal_config, render_conf,
        make_urltest_outbound, make_selector_outbound,
    )
    from core.singbox_manager import get_singbox_manager

    cfg = make_minimal_config()
    cfg["outbounds"] = [
        o for o in cfg.get("outbounds", [])
        if not (o.get("type") == "direct" and o.get("tag") == "proxy-out")
    ]
    tags = [o["tag"] for o in outbounds if o.get("tag")]
    group_tag = "auto"
    if group_tag in tags:
        group_tag = "auto-pool"
    if group == "selector":
        grp = make_selector_outbound(group_tag, tags)
    else:
        grp = make_urltest_outbound(group_tag, tags)
    cfg["outbounds"] = [grp] + outbounds + cfg["outbounds"]
    cfg["route"]["rules"] = [{"inbound": ["mixed-in"], "outbound": group_tag}]
    cfg["route"]["final"] = "direct"

    res = get_singbox_manager().save_config(POOL_CONFIG_NAME,
                                            text=render_conf(cfg))
    if not res.get("ok"):
        raise RuntimeError(res.get("error") or "save failed")

    # Если инстанс пула запущен — перезапустим, чтобы подхватил новый пул.
    try:
        mgr = get_singbox_manager()
        if mgr.is_running(POOL_CONFIG_NAME):
            mgr.restart(POOL_CONFIG_NAME)
    except Exception as e:
        log.warning("server-pool restart: %s" % e, source="singbox")


def _record(*, ok: bool, error: str, count: int):
    with _lock:
        pool = _load_pool()
        pool["last_refresh"] = int(time.time())
        pool["last_status"] = "ok" if ok else "error"
        pool["last_error"] = error
        if ok:
            pool["last_count"] = count
        _save_pool(pool)


# ─────── async refresh job (для UI: запустил → опрашиваешь прогресс) ───

class _RefreshJob:
    """Один фоновый прогон сборки пула с прогрессом (fetch/test/build)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._result: dict = {}
        self._progress = {"phase": "", "done": 0, "total": 0}

    def running(self) -> bool:
        with self._lock:
            return self._running

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._result = {}
            self._progress = {"phase": "fetch", "done": 0, "total": 0}

        def _cb(phase, done, total):
            with self._lock:
                self._progress = {"phase": phase, "done": done, "total": total}

        def _run():
            try:
                res = refresh_pool(progress_cb=_cb)
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            with self._lock:
                self._result = res
                self._running = False

        threading.Thread(target=_run, name="pool-refresh",
                         daemon=True).start()
        return True

    def status(self) -> dict:
        with self._lock:
            return {
                "running": self._running,
                "result": self._result,
                "progress": dict(self._progress),
            }


_refresh_job = _RefreshJob()


def get_refresh_job() -> _RefreshJob:
    return _refresh_job


# ─────── background refresher ───────

class PoolRefresher:
    """Фоновой поток: раз в минуту проверяет, не пора ли пересобрать пул."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()

    def reconfigure(self):
        if [s for s in list_sources() if s.get("enabled")]:
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="pool-refresher", daemon=True)
            t.start()
            self._thread = t
            log.info("pool-refresher: запущен", source="singbox")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("pool-refresher: остановлен", source="singbox")

    def _run_loop(self):
        while not self._stop_evt.wait(60):
            try:
                self._tick()
            except Exception as e:
                log.warning("pool-refresher tick: %s" % e, source="singbox")

    def _tick(self):
        s = get_settings()
        interval = int(s.get("interval_hours") or DEFAULT_INTERVAL_HOURS)
        last = int(s.get("last_refresh") or 0)
        if (int(time.time()) - last) < interval * 3600:
            return
        log.info("server-pool: автообновление", source="singbox")
        refresh_pool()

    def get_status(self) -> dict:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {"running": running,
                "sources": len([s for s in list_sources()
                                if s.get("enabled")])}


_refresher = None
_refresher_lock = threading.Lock()


def get_pool_refresher() -> PoolRefresher:
    global _refresher
    if _refresher is None:
        with _refresher_lock:
            if _refresher is None:
                _refresher = PoolRefresher()
                _refresher.reconfigure()
    return _refresher
