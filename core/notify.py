# core/notify.py
"""
Уведомления в Telegram: «сайт перестал открываться», «туннель
перезапущен», «стратегию откатили», «вышло обновление».

## Зачем

Обход ломается тогда, когда человек не смотрит в GUI. Узнаёт он об этом
от домашних. Здесь события роутера уходят в чат Telegram (приём
nfqws2-ui).

## Очередь

Telegram сам бывает недоступен — ровно тогда, когда сломался обход.
Поэтому сообщение не отправляется на месте, а встаёт в очередь
(``<config_dir>/notify-queue.json``, переживает перезапуск), и фоновый
поток отправляет её по порядку с паузой между попытками. Сообщение
старше :data:`MAX_AGE` выбрасывается: через сутки «сайт не открывается»
уже не новость. Одинаковый текст чаще раза в :data:`DEDUP_SEC` не
ставится.

## Через что

``notify.telegram.transport`` — та же спека, что у скачиваний
(``core.download_transport``): напрямую, через AWG-интерфейс,
sing-box или mihomo. ``notify.telegram.proxy`` — свой HTTP-прокси
(``http://host:port``), если задан, важнее транспорта.

## Секреты

Токен бота — в ``notify.telegram.token``: ключ ``token`` маскируется
везде, где маскируются секреты (``core.mcp.redact``), и в журнал не
пишется — ошибки отправки чистятся от него.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from core.log_buffer import log

API = "https://api.telegram.org"
# Сколько держать недоставленное, сек.
MAX_AGE = 24 * 3600
# Не ставить одинаковый текст чаще, сек.
DEDUP_SEC = 600
# Предел очереди (старые уходят первыми).
MAX_QUEUE = 50
# Пауза между попытками, если Telegram не ответил, сек.
RETRY_SEC = 60
TIMEOUT = 15

# Виды событий и их подписи для страницы настроек.
EVENTS = {
    "site_down":  "Сайт перестал открываться",
    "site_up":    "Сайт снова открывается",
    "tunnel":     "Туннель или прокси перезапущен сторожем",
    "wan":        "Пропал или вернулся интернет у провайдера",
    "safe_apply": "Применение стратегии с проверкой откачено",
    "known_good": "Правка туннелей или маршрутов что-то сломала",
    "autopick":   "Автоподбор стратегии",
    "update":     "Вышло обновление",
}

_lock = threading.RLock()
_wake = threading.Event()
_worker = None
_recent = {}            # текст → ts постановки (защита от повторов)


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


def settings() -> dict:
    tg = _cfg().get("notify", "telegram", default={}) or {}
    events = _cfg().get("notify", "events", default={}) or {}
    return {"enabled": bool(tg.get("enabled")),
            "token": str(tg.get("token") or "").strip(),
            "chat_id": str(tg.get("chat_id") or "").strip(),
            "transport": str(tg.get("transport") or "").strip(),
            "proxy": str(tg.get("proxy") or "").strip(),
            "events": {k: bool(events.get(k, True)) for k in EVENTS}}


def _queue_path() -> str:
    return os.path.join(_cfg().config_dir, "notify-queue.json")


def _load_queue() -> list:
    try:
        with open(_queue_path(), encoding="utf-8") as f:
            data = json.load(f)
        return [m for m in data if isinstance(m, dict)] \
            if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_queue(queue: list) -> None:
    from core.safe_io import atomic_write_json
    atomic_write_json(_queue_path(), queue[-MAX_QUEUE:])


# ─────────────────────────── постановка ────────────────────────────

def _host() -> str:
    """Имя роутера (без get_system_info — тот ещё гоняет ``ip route``)."""
    try:
        with open("/etc/hostname", encoding="utf-8") as f:
            name = f.read().strip()
        if name:
            return name
    except OSError:
        pass
    import platform
    return platform.node() or ""


def event(kind: str, text: str, dedup: bool = True) -> bool:
    """Поставить уведомление, если включено и этот вид не выключен.

    Безопасно звать откуда угодно: ничего не бросает и не ждёт сети.
    ``dedup=False`` — для источника, который сам шлёт только переходы
    состояния (healthcheck): там одинаковый текст через пять минут —
    новое событие, а не повтор.
    """
    try:
        st = settings()
        if not st["enabled"] or not st["token"] or not st["chat_id"]:
            return False
        if not st["events"].get(kind, True):
            return False
        now = time.time()
        with _lock:
            for k in [k for k, ts in _recent.items()
                      if now - ts > DEDUP_SEC]:
                _recent.pop(k, None)
            if dedup:
                if text in _recent:
                    return False
                _recent[text] = now
            queue = _load_queue()
            queue.append({"ts": now, "kind": kind, "text": text})
            _save_queue(queue)
        _ensure_worker()
        _wake.set()
        return True
    except Exception as e:                          # noqa: BLE001 — граница
        log.warning("уведомление не поставлено: %s" % e, source="notify")
        return False


# ─────────────────────────── отправка ────────────────────────────

def _opener(st: dict):
    if st["proxy"]:
        return urllib.request.build_opener(urllib.request.ProxyHandler(
            {"http": st["proxy"], "https": st["proxy"]}))
    from core.download_transport import build_opener
    return build_opener(st["transport"]) or urllib.request.build_opener()


class Rejected(RuntimeError):
    """Telegram ответил 400 — не примет это сообщение никогда (длина,
    разметка). Повторять бессмысленно, держать в голове очереди —
    значит задержать всё, что за ним."""


def _call(st: dict, method: str, payload: dict | None = None) -> dict:
    """Вызов Bot API. Ошибка — RuntimeError без токена в тексте."""
    url = "%s/bot%s/%s" % (API, st["token"], method)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json"} if data else {})
    try:
        with _opener(st).open(req, timeout=TIMEOUT) as r:
            body = json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8", "replace") or "{}")
        except ValueError:
            body = {}
        cls = Rejected if e.code == 400 and method == "sendMessage" \
            else RuntimeError
        raise cls("Telegram: %s %s" % (
            e.code, body.get("description") or e.reason)) from None
    except Exception as e:                          # noqa: BLE001
        raise RuntimeError(_scrub(str(e) or type(e).__name__,
                                  st["token"])) from None
    if not body.get("ok"):
        raise RuntimeError("Telegram: %s" % (body.get("description")
                                             or "ответ без ok"))
    return body


def _scrub(text: str, token: str) -> str:
    return text.replace(token, "<token>") if token else text


def format_text(text: str, host: str = "") -> str:
    """Подпись роутера + текст (чистая функция)."""
    head = "zapret-gui" + (" · %s" % host if host else "")
    return "%s\n%s" % (head, text)


def send_now(text: str, st: dict | None = None) -> dict:
    """Отправить сразу, мимо очереди (кнопка «Проверить»)."""
    st = st or settings()
    if not st["token"] or not st["chat_id"]:
        return {"ok": False, "error": "не заданы токен бота и chat_id"}
    try:
        _call(st, "sendMessage", {
            "chat_id": st["chat_id"], "text": format_text(text, _host()),
            "disable_web_page_preview": True})
        return {"ok": True}
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}


def find_chats(st: dict | None = None) -> dict:
    """Чаты, писавшие боту (getUpdates), — чтобы не искать chat_id вручную.

    Сначала напишите боту что-нибудь (или добавьте его в группу).
    """
    st = st or settings()
    if not st["token"]:
        return {"ok": False, "error": "не задан токен бота"}
    try:
        body = _call(st, "getUpdates", {"limit": 50, "timeout": 0})
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "chats": chats_from_updates(body.get("result"))}


def chats_from_updates(updates) -> list:
    """Чистая функция: [{id, title}] без повторов, последние первыми."""
    seen, out = set(), []
    for u in reversed(updates or []):
        msg = (u.get("message") or u.get("channel_post")
               or u.get("my_chat_member") or u.get("edited_message") or {})
        chat = msg.get("chat") or {}
        cid = chat.get("id")
        if cid is None or cid in seen:
            continue
        seen.add(cid)
        title = (chat.get("title") or " ".join(
            x for x in (chat.get("first_name"), chat.get("last_name")) if x)
            or ("@" + chat["username"] if chat.get("username") else ""))
        out.append({"id": str(cid), "title": title or str(cid),
                    "type": chat.get("type", "")})
    return out


_flush_lock = threading.Lock()


def flush() -> dict:
    """Отправить очередь по порядку; первая неудача — стоп до следующей
    попытки (порядок сообщений важнее скорости).

    Одновременно — одна отправка (поток и кнопка «отправить сейчас»
    иначе отправили бы голову очереди дважды). Сообщение, которое
    Telegram отверг (400), выбрасывается, а не держит очередь.
    """
    if not _flush_lock.acquire(blocking=False):
        return {"ok": True, "sent": 0, "busy": True,
                "pending": len(_load_queue())}
    try:
        return _flush()
    finally:
        _flush_lock.release()


def _drop(msg: dict) -> None:
    with _lock:
        queue = [m for m in _load_queue()
                 if not (m.get("ts") == msg["ts"]
                         and m.get("text") == msg["text"])]
        _save_queue(queue)


def _flush() -> dict:
    st = settings()
    sent, error = 0, ""
    if not st["enabled"] or not st["token"] or not st["chat_id"]:
        return {"ok": True, "sent": 0, "pending": len(_load_queue())}
    host = _host()
    while True:
        with _lock:
            queue = _load_queue()
            now = time.time()
            fresh = [m for m in queue if now - float(m.get("ts", 0)) < MAX_AGE]
            if len(fresh) != len(queue):
                _save_queue(fresh)
            if not fresh:
                break
            msg = fresh[0]
        when = time.strftime("%H:%M", time.localtime(msg["ts"]))
        late = " (%s)" % when if time.time() - msg["ts"] > 120 else ""
        try:
            _call(st, "sendMessage", {
                "chat_id": st["chat_id"],
                "text": format_text(msg["text"] + late, host),
                "disable_web_page_preview": True})
        except Rejected as e:
            log.warning("уведомление отвергнуто и выброшено: %s" % e,
                        source="notify")
            _drop(msg)
            continue
        except RuntimeError as e:
            error = str(e)
            break
        _drop(msg)
        sent += 1
    return {"ok": not error, "sent": sent, "error": error,
            "pending": len(_load_queue())}


def status() -> dict:
    queue = _load_queue()
    return {"ok": True, "pending": len(queue),
            "oldest": queue[0]["ts"] if queue else None,
            "last_error": _last_error["text"], "events": EVENTS}


_last_error = {"text": ""}


def _run() -> None:
    while True:
        _wake.wait(RETRY_SEC)
        _wake.clear()
        try:
            res = flush()
            if res.get("error") and res["error"] != _last_error["text"]:
                log.warning("уведомления: не отправлено (%s), в очереди %d"
                            % (res["error"], res["pending"]),
                            source="notify")
            _last_error["text"] = res.get("error") or ""
        except Exception as e:                      # noqa: BLE001 — граница
            log.warning("уведомления: %s" % e, source="notify")


def _ensure_worker() -> None:
    global _worker
    with _lock:
        if _worker and _worker.is_alive():
            return
        _worker = threading.Thread(target=_run, name="notify", daemon=True)
        _worker.start()


def start() -> None:
    """Из загрузки приложения: дослать то, что не ушло до перезапуска."""
    if _load_queue():
        _ensure_worker()
        _wake.set()
