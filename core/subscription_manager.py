# core/subscription_manager.py
"""
Менеджер подписок: сохранённые URL + автообновление по таймеру.

Закрывает «Karing-совместимый импорт подписок» из TODO. В отличие
от одноразовых `core/subscription_importer.py` и
`core/clash_yaml.py`, здесь храним URL подписки в settings.json
и фоновой поток раз в N часов перетягивает её → перегенерирует
конфиг `imported-subscription-<id>` для каждой подписки.

settings.json layout:
    {
      "singbox": {
        "subscriptions": {
          "<id>": {
            "name":     "MyProvider",
            "url":      "https://example.com/sub?token=...",
            "format":   "auto|uri|clash|singbox-json",
            "interval_hours": 6,
            "last_refresh": 1234567890,
            "last_status": "ok|error",
            "last_error":  "...",
            "last_outbounds": 12
          }
        }
      }
    }
"""

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid as _uuid

from core.log_buffer import log


DEFAULT_INTERVAL_HOURS = 6
HTTP_TIMEOUT           = 20
MAX_DOWNLOAD_BYTES     = 5 * 1024 * 1024
USER_AGENT             = "zapret-gui/subscription-manager"


# ─────── settings access ───────

_lock = threading.Lock()


def _load_section() -> dict:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager().load() or {}
    except Exception:
        return {}
    sb = cfg.get("singbox") or {}
    if not isinstance(sb, dict):
        return {}
    subs = sb.get("subscriptions") or {}
    if not isinstance(subs, dict):
        return {}
    return subs


def _save_section(subs: dict):
    try:
        from core.config_manager import get_config_manager, save_config
    except Exception as e:
        log.warning("subscription_manager: settings unavailable: %s" % e,
                    source="singbox")
        return
    cfg = get_config_manager().load() or {}
    if not isinstance(cfg, dict):
        cfg = {}
    cfg.setdefault("singbox", {})["subscriptions"] = subs
    try:
        save_config()
    except Exception as e:
        log.warning("subscription_manager: save: %s" % e, source="singbox")


# ─────── CRUD subscriptions ───────

def list_subscriptions() -> list:
    """Список подписок (без секретов в URL — URL отдаём как есть,
    SPA сама может скрыть `?token=`)."""
    subs = _load_section()
    out = []
    for sid, sub in subs.items():
        if not isinstance(sub, dict):
            continue
        out.append(dict(sub, id=sid))
    out.sort(key=lambda s: (s.get("name") or s.get("id") or ""))
    return out


def get_subscription(sid: str) -> dict:
    subs = _load_section()
    s = subs.get(sid)
    if not isinstance(s, dict):
        return {}
    return dict(s, id=sid)


def add_subscription(name: str, url: str, *,
                     fmt: str = "auto",
                     interval_hours: int = DEFAULT_INTERVAL_HOURS) -> dict:
    if not name or not url:
        return {"ok": False, "error": "Нужны name и url"}
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "URL должен быть http:// или https://"}

    sid = "sub-" + _uuid.uuid4().hex[:8]
    with _lock:
        subs = _load_section()
        subs[sid] = {
            "name":           name.strip(),
            "url":            url.strip(),
            "format":         fmt if fmt in ("auto", "uri", "clash",
                                              "singbox-json") else "auto",
            "interval_hours": max(1, int(interval_hours)),
            "last_refresh":   0,
            "last_status":    "",
            "last_error":     "",
            "last_outbounds": 0,
        }
        _save_section(subs)

    # Перезапускаем фоновой поток (если был запущен) — он подхватит
    # новый interval в следующем тике.
    get_refresher().reconfigure()
    return {"ok": True, "id": sid}


def update_subscription(sid: str, **kwargs) -> dict:
    with _lock:
        subs = _load_section()
        if sid not in subs or not isinstance(subs[sid], dict):
            return {"ok": False, "error": "Подписка не найдена"}
        sub = subs[sid]
        for k in ("name", "url", "format", "interval_hours"):
            if k in kwargs and kwargs[k] is not None:
                sub[k] = kwargs[k]
        _save_section(subs)
    get_refresher().reconfigure()
    return {"ok": True, "id": sid}


def remove_subscription(sid: str) -> dict:
    with _lock:
        subs = _load_section()
        if sid not in subs:
            return {"ok": True, "noop": True}
        del subs[sid]
        _save_section(subs)

    # Параллельно удалим связанный sing-box-конфиг.
    try:
        from core.singbox_manager import get_singbox_manager
        get_singbox_manager().delete_config(_config_name_for(sid))
    except Exception:
        pass

    get_refresher().reconfigure()
    return {"ok": True}


# ─────── refresh ───────

def refresh_one(sid: str) -> dict:
    """
    Force-refresh одной подписки. Скачивает, парсит, сохраняет
    sing-box-конфиг `imported-subscription-<sid>`.
    """
    sub = get_subscription(sid)
    if not sub:
        return {"ok": False, "error": "Подписка не найдена"}

    try:
        text = _fetch(sub["url"])
    except RuntimeError as e:
        _record_refresh(sid, ok=False, error=str(e))
        return {"ok": False, "error": str(e)}

    fmt = sub.get("format") or "auto"
    outbounds, source_fmt = _parse_payload(text, fmt)
    if not outbounds:
        msg = "В подписке не нашлось outbound'ов"
        _record_refresh(sid, ok=False, error=msg)
        return {"ok": False, "error": msg, "format": source_fmt}

    # Собираем sing-box-конфиг с этими outbound'ами + минимальным route
    try:
        from core.singbox_config import make_minimal_config, render_conf
        from core.singbox_manager import get_singbox_manager
        cfg = make_minimal_config()
        # Удалим placeholder direct-outbound с tag='proxy-out' — мы
        # его заменим первым реальным outbound'ом.
        first_tag = outbounds[0].get("tag") or "out"
        cfg["outbounds"] = [
            o for o in cfg.get("outbounds", [])
            if not (o.get("type") == "direct" and o.get("tag") == "proxy-out")
        ]
        cfg["outbounds"] = outbounds + cfg["outbounds"]
        # route.rules: всё, что пришло на mixed-in, → первый outbound.
        cfg["route"]["rules"] = [
            {"inbound": ["mixed-in"], "outbound": first_tag},
        ]
        cfg["route"]["final"] = "direct"

        config_name = _config_name_for(sid)
        save_res = get_singbox_manager().save_config(
            config_name, text=render_conf(cfg))
    except Exception as e:
        _record_refresh(sid, ok=False, error="save: %s" % e)
        return {"ok": False, "error": "save: %s" % e}

    if not save_res.get("ok"):
        _record_refresh(sid, ok=False,
                        error="save: %s" % save_res.get("error"))
        return {"ok": False, "error": save_res.get("error", "save failed")}

    _record_refresh(sid, ok=True, count=len(outbounds))
    log.info("subscription %s: обновлено, %d outbound'ов (%s)"
             % (sid, len(outbounds), source_fmt), source="singbox")
    return {
        "ok": True,
        "id": sid,
        "config": config_name,
        "format": source_fmt,
        "outbounds": len(outbounds),
    }


def refresh_all() -> dict:
    """Force-refresh всех подписок (для UI-кнопки)."""
    results = []
    for sub in list_subscriptions():
        results.append({"id": sub["id"],
                        "result": refresh_one(sub["id"])})
    return {"ok": True, "refreshed": results}


def _record_refresh(sid: str, *, ok: bool, count: int = 0,
                    error: str = ""):
    with _lock:
        subs = _load_section()
        if sid not in subs:
            return
        subs[sid]["last_refresh"]   = int(time.time())
        subs[sid]["last_status"]    = "ok" if ok else "error"
        subs[sid]["last_error"]     = error
        if ok:
            subs[sid]["last_outbounds"] = count
        _save_section(subs)


def _config_name_for(sid: str) -> str:
    return "imported-subscription-%s" % sid


# ─────── fetch + parse ───────

def _fetch(url: str) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            raw = r.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP %s" % e.code)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise RuntimeError("сеть: %s" % e)
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise RuntimeError("подписка > %d МБ"
                           % (MAX_DOWNLOAD_BYTES // (1024 * 1024)))
    return raw.decode("utf-8", errors="replace")


def _parse_payload(text: str, fmt: str):
    """
    Распознать формат и развернуть в (outbounds: list, source_fmt: str).

    fmt:
      - 'auto'         — пробуем все
      - 'uri'          — base64/plain text-URI лист (как
                          subscription_importer.extract_items)
      - 'clash'        — YAML с секцией proxies
      - 'singbox-json' — готовый sing-box JSON, вытащим outbounds
    """
    if fmt == "auto":
        # Эвристика порядок:
        #   1) если стартует с `{` → singbox-json
        #   2) если есть `\nproxies:` → clash
        #   3) иначе → uri-list (base64 или plain)
        t = text.lstrip()
        if t.startswith("{"):
            return _parse_singbox_json(text), "singbox-json"
        if "proxies:" in text and not t.startswith("vless://") \
                and not t.startswith("trojan://"):
            return _parse_clash(text), "clash"
        return _parse_uri_list(text), "uri"

    if fmt == "clash":
        return _parse_clash(text), "clash"
    if fmt == "singbox-json":
        return _parse_singbox_json(text), "singbox-json"
    return _parse_uri_list(text), "uri"


def _parse_clash(text: str):
    from core.clash_yaml import parse_clash_yaml
    r = parse_clash_yaml(text)
    if not r.get("ok"):
        return []
    return r.get("outbounds") or []


def _parse_singbox_json(text: str):
    """
    Принимаем либо целый sing-box-config (берём outbounds),
    либо просто массив outbound'ов.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return [o for o in data
                if isinstance(o, dict) and o.get("type")]
    if isinstance(data, dict):
        obs = data.get("outbounds") or []
        if isinstance(obs, list):
            return [o for o in obs
                    if isinstance(o, dict) and o.get("type")]
    return []


def _parse_uri_list(text: str):
    """Преобразовать text-URI-list (или base64) в sing-box outbound'ы."""
    from core.subscription_importer import extract_items
    from core.singbox_subscription import uri_to_outbound

    outbounds = []
    seen_tags = set()
    for it in extract_items(text):
        if it.get("type") != "uri":
            continue
        r = uri_to_outbound(it["value"])
        if not r.get("ok"):
            continue
        ob = r["outbound"]
        tag = ob.get("tag") or "out"
        base = tag
        i = 2
        while tag in seen_tags:
            tag = "%s-%d" % (base, i)
            i += 1
        ob["tag"] = tag
        seen_tags.add(tag)
        outbounds.append(ob)
    return outbounds


# ─────── background refresher ───────

class SubscriptionRefresher:
    """
    Фоновой поток — раз в минуту проверяет subscriptions и вызывает
    refresh_one() для тех, у кого `last_refresh + interval` уже
    наступил.
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._thread   = None
        self._stop_evt = threading.Event()

    def reconfigure(self):
        """Запустить, если есть хоть одна подписка; иначе остановить."""
        subs = _load_section()
        if subs:
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(
                target=self._run_loop,
                name="subscription-refresher",
                daemon=True,
            )
            t.start()
            self._thread = t
            log.info("subscription-refresher: запущен", source="singbox")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("subscription-refresher: остановлен", source="singbox")

    def _run_loop(self):
        # Каждую минуту проверяем кого пора рефрешить.
        while not self._stop_evt.wait(60):
            try:
                self._tick()
            except Exception as e:
                log.warning("refresher tick: %s" % e, source="singbox")

    def _tick(self):
        now = int(time.time())
        for sub in list_subscriptions():
            interval = int(sub.get("interval_hours") or DEFAULT_INTERVAL_HOURS)
            last = int(sub.get("last_refresh") or 0)
            if (now - last) < interval * 3600:
                continue
            log.info("subscription %s: автообновление" % sub["id"],
                     source="singbox")
            try:
                refresh_one(sub["id"])
            except Exception as e:
                log.warning("subscription %s autorefresh: %s"
                            % (sub["id"], e), source="singbox")

    def get_status(self) -> dict:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {"running": running, "count": len(_load_section())}


# ─────── singleton ───────

_refresher = None
_refresher_lock = threading.Lock()


def get_refresher() -> SubscriptionRefresher:
    global _refresher
    if _refresher is None:
        with _refresher_lock:
            if _refresher is None:
                _refresher = SubscriptionRefresher()
                _refresher.reconfigure()
    return _refresher
