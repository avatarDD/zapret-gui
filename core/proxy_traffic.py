# core/proxy_traffic.py
"""
Учёт трафика, прокачанного через каждый прокси-сервер (per-outbound).

Идея — как у Throne `Stats::trafficLooper`: пока инстанс sing-box
запущен, фоновый трекер периодически опрашивает его Clash API
`GET /connections` и накапливает upload/download по тегу outbound'а
(сервера), через который реально шёл трафик. Полученные суммы
показываются в колонке «Трафик» на странице «Прокси» и служат ключом
сортировки «по объёму прокачанного трафика».

Откуда берём endpoint: НЕ трогаем общий путь запуска sing-box —
просто читаем (read-only) конфиги запущенных инстансов и достаём
`experimental.clash_api.external_controller` + secret. Если у конфига
clash_api не настроен, трафик по нему не считается (UI предложит
включить clash_api одной кнопкой — см. api/singbox.py).

Clash API `/connections` отдаёт:
    {"connections": [
        {"id": "...", "upload": <bytes>, "download": <bytes>,
         "chains": ["<node-tag>", "<group-tag>", ...], ...}, ...]}
`chains[0]` — реальный узел (сервер), через который вышел трафик;
последующие элементы — группы (selector/urltest). Аккумулируем по
`chains[0]`, пропуская служебные direct/block/dns.

Счётчики Clash по соединению — кумулятивные и живут только пока
соединение открыто. Поэтому считаем ДЕЛЬТУ между опросами и копим её
в собственные суммы (`_totals`), которые переживают закрытие
соединений и перезапуск GUI (персист в run_dir).
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from core.log_buffer import log


_POLL_INTERVAL = 2.0      # сек между опросами /connections
_HTTP_TIMEOUT  = 2.0      # сек на один HTTP-запрос к Clash API
_SERVICE_TAGS  = {"direct", "block", "dns"}


def _state_path() -> str:
    from core.singbox_platform import detect_singbox_platform
    return os.path.join(detect_singbox_platform().run_dir, "proxy_traffic.json")


def _clash_get(host: str, port: int, secret: str, path: str,
               timeout: float = _HTTP_TIMEOUT) -> tuple:
    """(status, body) запроса к локальному Clash API. 0 — сеть/таймаут."""
    url = "http://%s:%d%s" % (host, int(port), path)
    headers = {"Authorization": "Bearer %s" % secret} if secret else {}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return 0, ""


def running_clash_targets() -> list:
    """
    Запущенные конфиги sing-box с настроенным clash_api. Для каждого:
      {"config", "host", "port", "secret", "tags": [<real outbound tags>]}.
    Только read-only чтение конфигов — путь запуска не затрагивается.
    """
    out = []
    try:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import (
            clash_api_endpoint, list_user_outbound_tags)
        mgr = get_singbox_manager()
        for c in mgr.list_configs():
            if not c.get("running"):
                continue
            res = mgr.get_config(c["name"])
            if not res.get("ok"):
                continue
            cfg = res.get("parsed") or {}
            ep = clash_api_endpoint(cfg)
            if not ep:
                continue
            ep["config"] = c["name"]
            ep["tags"] = list_user_outbound_tags(cfg)
            out.append(ep)
    except Exception as e:
        log.warning("proxy_traffic: не удалось перечислить инстансы: %s" % e,
                    source="singbox")
    return out


def running_mihomo_clash_targets() -> list:
    """
    Запущенные конфиги mihomo с external-controller. mihomo — эталонная
    реализация Clash, его `/connections` отдаёт тот же формат, что и
    sing-box clash_api, поэтому трекер общий (см. get_mihomo_traffic_tracker).
    """
    out = []
    try:
        from core.mihomo_manager import get_mihomo_manager
        from core.clash_yaml import parse_yaml
        from core.mihomo_proxies import (
            external_controller_endpoint, proxy_names)
        mgr = get_mihomo_manager()
        for c in mgr.list_configs():
            if not c.get("running"):
                continue
            res = mgr.get_config(c["name"])
            if not res.get("ok"):
                continue
            try:
                cfg = parse_yaml(res.get("text") or "")
            except Exception:
                continue
            ep = external_controller_endpoint(cfg)
            if not ep:
                continue
            ep = dict(ep)
            ep["config"] = c["name"]
            ep["tags"] = proxy_names(cfg)
            out.append(ep)
    except Exception as e:
        log.warning("proxy_traffic(mihomo): не удалось перечислить "
                    "инстансы: %s" % e, source="mihomo")
    return out


def _mihomo_state_path() -> str:
    from core.mihomo_platform import detect_mihomo_platform
    return os.path.join(detect_mihomo_platform().run_dir, "proxy_traffic.json")


def _pick_tag(chains) -> str:
    """Тег реального узла из chains (первый не служебный, обычно chains[0])."""
    if not isinstance(chains, list):
        return ""
    for t in chains:
        if t and t not in _SERVICE_TAGS:
            return t
    return ""


class TrafficTracker:
    """Фоновый накопитель трафика по тегам outbound'ов.

    Параметризуется источником целей и путём состояния — один и тот же
    класс обслуживает и sing-box (clash_api), и mihomo (external-
    controller): формат `/connections` у них совпадает.
    """

    def __init__(self, targets_fn=None, state_path_fn=None):
        self._lock = threading.Lock()
        self._totals: dict = {}    # tag -> {"up","down","seen"}
        self._conn: dict = {}      # endpoint_key -> {conn_id: (up, down)}
        self._thread = None
        self._running = False
        self._targets_fn = targets_fn or running_clash_targets
        self._state_path_fn = state_path_fn or _state_path
        self._load()

    # ─────── persistence ───────

    def _load(self):
        try:
            with open(self._state_path_fn(), "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        totals = data.get("totals") if isinstance(data, dict) else None
        if not isinstance(totals, dict):
            return
        for tag, v in totals.items():
            if isinstance(v, dict):
                self._totals[tag] = {
                    "up":   int(v.get("up") or 0),
                    "down": int(v.get("down") or 0),
                    "seen": float(v.get("seen") or 0),
                }

    def _save(self):
        path = self._state_path_fn()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"totals": self._totals}, f)
            os.replace(tmp, path)
        except OSError:
            pass

    # ─────── loop ───────

    def ensure_running(self):
        """Лениво поднять фоновый поток опроса (идемпотентно)."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._loop, name="proxy-traffic", daemon=True)
            self._thread.start()

    def _loop(self):
        while True:
            try:
                self._poll_all()
            except Exception as e:
                log.warning("proxy_traffic loop: %s" % e, source="singbox")
            time.sleep(_POLL_INTERVAL)

    def _poll_all(self):
        targets = self._targets_fn()
        active_keys = set()
        changed = False
        for t in targets:
            key = "%s:%d" % (t["host"], t["port"])
            active_keys.add(key)
            status, body = _clash_get(
                t["host"], t["port"], t.get("secret", ""), "/connections")
            if status != 200 or not body:
                continue
            try:
                data = json.loads(body)
            except ValueError:
                continue
            conns = data.get("connections") or []
            prev = self._conn.get(key, {})
            cur = {}
            with self._lock:
                for conn in conns:
                    if not isinstance(conn, dict):
                        continue
                    cid = conn.get("id")
                    if not cid:
                        continue
                    up = int(conn.get("upload") or 0)
                    down = int(conn.get("download") or 0)
                    cur[cid] = (up, down)
                    pu, pd = prev.get(cid, (0, 0))
                    # Счётчик соединения только растёт; если меньше —
                    # это новый id (clash переиспользовал) → берём как есть.
                    dup = up - pu if up >= pu else up
                    ddn = down - pd if down >= pd else down
                    if dup <= 0 and ddn <= 0:
                        continue
                    tag = _pick_tag(conn.get("chains") or [])
                    if not tag:
                        continue
                    rec = self._totals.setdefault(
                        tag, {"up": 0, "down": 0, "seen": 0})
                    rec["up"] += max(0, dup)
                    rec["down"] += max(0, ddn)
                    rec["seen"] = time.time()
                    changed = True
            self._conn[key] = cur
        # Соединения исчезнувших endpoint'ов больше не отслеживаем.
        for k in list(self._conn.keys()):
            if k not in active_keys:
                del self._conn[k]
        if changed:
            with self._lock:
                self._save()

    # ─────── public ───────

    def snapshot(self, tags=None) -> dict:
        """Кумулятивные суммы. tags=None — все; иначе только указанные."""
        with self._lock:
            if tags is None:
                return {t: dict(v) for t, v in self._totals.items()}
            return {t: dict(self._totals.get(
                        t, {"up": 0, "down": 0, "seen": 0})) for t in tags}

    def reset(self, tags=None):
        """
        Обнулить суммы (все или указанные). `_conn` НЕ чистим — иначе
        следующий опрос принял бы текущие (докризисные) счётчики
        открытых соединений за новую дельту и насчитал бы лишнее.
        """
        with self._lock:
            if tags is None:
                self._totals = {}
            else:
                for t in tags:
                    self._totals.pop(t, None)
            self._save()


_tracker = None
_mihomo_tracker = None
_tracker_lock = threading.Lock()


def get_traffic_tracker() -> TrafficTracker:
    """Трекер трафика sing-box (clash_api)."""
    global _tracker
    if _tracker is None:
        with _tracker_lock:
            if _tracker is None:
                _tracker = TrafficTracker()
    return _tracker


def get_mihomo_traffic_tracker() -> TrafficTracker:
    """Трекер трафика mihomo (external-controller). Отдельный экземпляр и
    отдельный файл состояния (в run_dir mihomo)."""
    global _mihomo_tracker
    if _mihomo_tracker is None:
        with _tracker_lock:
            if _mihomo_tracker is None:
                _mihomo_tracker = TrafficTracker(
                    targets_fn=running_mihomo_clash_targets,
                    state_path_fn=_mihomo_state_path)
    return _mihomo_tracker
