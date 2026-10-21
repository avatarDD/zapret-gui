# core/notify_bot.py
"""
Двусторонний бот Telegram: кнопки под уведомлениями и команды.

## Зачем

Уведомление «автообнаружение добавило домен» или «правка туннелей
сломала сайты» приходит на телефон, а исправлять — идти в GUI. Здесь
под таким сообщением кнопки («Отменить», «Исключить», «Вернуть рабочую
точку»), а команды ``/status`` и ``/report`` отвечают, что
с роутером, не открывая GUI (приём Tachyon).

## Как

* Включается ``notify.telegram.interactive`` (по умолчанию выключен:
  бот читает ``getUpdates`` долгим опросом, а у кого-то тот же бот уже
  обслуживает другой скрипт).
* Кнопка несёт не действие, а **квитанцию** — случайный токен, выданный
  в момент отправки (:func:`receipt`). Квитанции живут в памяти
  :data:`RECEIPT_TTL`; нажатие по устаревшей кнопке (перезапуск, сутки
  прошли, уже нажата) отвечает «устарела», а не делает что попало.
* Слушается только чат ``chat_id``, и только отправители из
  ``allowed_users``; пустой список — в личном чате только его владелец
  (id пользователя совпадает с ``chat_id``), в группе — никто.
* Действия — :data:`ACTIONS`, только обратимые и узкие. Перезапусков,
  shell и прочего нет.
"""

from __future__ import annotations

import secrets
import threading
import time

from core.log_buffer import log

RECEIPT_TTL = 24 * 3600
POLL_TIMEOUT = 25
ERROR_PAUSE = 30
MAX_REPLY = 3500
PREFIX = "zg:"

_lock = threading.Lock()
_receipts = {}          # token → {"action", "arg", "ts"}
_thread = None
_state = {"offset": 0, "last_error": ""}


# ─────────────────────────── действия ───────────────────────────────

def _smart_undo(arg):
    from core import smart_detect
    r = smart_detect.undo(arg)
    if not r.get("ok"):
        return "Не вышло: %s" % r.get("error", "")
    return "↩️ %s убран из списка" % r["entry"]


def _smart_exclude(arg):
    from core import smart_detect
    r = smart_detect.exclude(arg)
    if not r.get("ok"):
        return "Не вышло: %s" % r.get("error", "")
    return "🚫 %s убран из списка и больше не будет добавляться" % r["entry"]


def _known_good_rollback(_arg):
    from core import known_good
    r = known_good.rollback(reason="кнопка Telegram")
    if r.get("ok"):
        return "↩️ Вернул рабочую точку: %s" % (
            ", ".join(r.get("restored") or []) or "всё уже совпадало")
    return "Вернул с ошибками: %s" % r.get("error", "")


ACTIONS = {
    "smart_undo": _smart_undo,
    "smart_exclude": _smart_exclude,
    "known_good_rollback": _known_good_rollback,
}


# ─────────────────────────── квитанции ───────────────────────────────

def receipt(action: str, arg: str = "") -> str:
    """Выдать квитанцию на кнопку → ``callback_data`` (≤ 64 байт)."""
    now = time.time()
    token = secrets.token_hex(8)
    with _lock:
        for t in [t for t, r in _receipts.items()
                  if now - r["ts"] > RECEIPT_TTL]:
            _receipts.pop(t, None)
        _receipts[token] = {"action": action, "arg": arg, "ts": now}
    return PREFIX + token


def redeem(data: str):
    """Погасить квитанцию: ``(action, arg)`` или None (чужая/устарела)."""
    if not str(data or "").startswith(PREFIX):
        return None
    token = data[len(PREFIX):]
    with _lock:
        rec = _receipts.pop(token, None)
    if not rec or time.time() - rec["ts"] > RECEIPT_TTL:
        return None
    return rec["action"], rec["arg"]


# ─────────────────────────── доступ ─────────────────────────────────

def authorized(chat_id, user_id, st: dict) -> bool:
    """Чистая функция: слушаемся ли этого отправителя в этом чате."""
    if str(chat_id) != str(st.get("chat_id") or ""):
        return False
    allowed = [str(u) for u in (st.get("allowed_users") or [])]
    if allowed:
        return str(user_id) in allowed
    # Без списка — только личный чат с владельцем.
    return str(user_id) == str(chat_id)


# ─────────────────────────── команды ────────────────────────────────

HELP = ("Команды:\n"
        "/status — всё ли работает\n"
        "/report — отчёт для помощи (адреса сайтов замаскированы)\n"
        "/help — эта справка")


def _status_text() -> str:
    from api.status import dashboard_status
    from core.dashboard_brief import brief
    data = dashboard_status()
    b = brief(data)
    icon = {"ok": "✅", "warn": "⚠️", "bad": "❌"}.get(b.get("level"), "ℹ️")
    lines = ["%s %s" % (icon, b.get("line", ""))]
    for key, title in (("nfqws", "Обход"), ("vpn", "Туннели"),
                       ("monitoring", "Мониторинг")):
        blk = (b.get("blocks") or {}).get(key) or {}
        if blk.get("text"):
            lines.append("%s: %s" % (title, blk["text"]))
    try:
        from core import reachability
        wan = reachability.status()
        if wan.get("outage_since"):
            lines.append("🌐 Интернет у провайдера пропал")
    except Exception:                               # noqa: BLE001
        pass
    return "\n".join(lines)


def _report_text() -> str:
    from core import help_report
    text = help_report.build(show_sites=False).get("text", "")
    if len(text) > MAX_REPLY:
        text = text[:MAX_REPLY] + "\n… (обрезано; полный отчёт — в GUI, " \
                                  "«Помощь → Отчёт»)"
    return text


COMMANDS = {"/status": _status_text, "/report": _report_text,
            "/help": lambda: HELP, "/start": lambda: HELP}


def command_reply(text: str):
    """Ответ на команду или None (не команда). ``/status@bot`` — тоже."""
    word = (text or "").strip().split(maxsplit=1)
    if not word:
        return None
    cmd = word[0].split("@", 1)[0].lower()
    fn = COMMANDS.get(cmd)
    if fn is None:
        return None if not cmd.startswith("/") else \
            "Не знаю такой команды.\n" + HELP
    try:
        return fn()
    except Exception as e:                          # noqa: BLE001 — граница
        return "Не вышло: %s" % e


# ─────────────────────────── разбор обновлений ──────────────────────

def _api(st: dict, method: str, payload: dict, timeout=None) -> dict:
    from core import notify
    if timeout is None:
        return notify._call(st, method, payload)
    return notify._call(st, method, payload, timeout=timeout)


def _send(st: dict, text: str) -> None:
    from core import notify
    _api(st, "sendMessage", {"chat_id": st["chat_id"],
                             "text": notify.format_text(text,
                                                        notify._host()),
                             "disable_web_page_preview": True})


def handle_update(u: dict, st: dict) -> str:
    """Одно обновление → что сделали (для журнала и тестов)."""
    cb = u.get("callback_query")
    if cb:
        msg = cb.get("message") or {}
        chat = (msg.get("chat") or {}).get("id")
        user = (cb.get("from") or {}).get("id")
        if not authorized(chat, user, st):
            _api(st, "answerCallbackQuery", {
                "callback_query_id": cb.get("id"),
                "text": "Нет доступа"})
            return "denied"
        got = redeem(cb.get("data"))
        if got is None or got[0] not in ACTIONS:
            _api(st, "answerCallbackQuery", {
                "callback_query_id": cb.get("id"),
                "text": "Кнопка устарела"})
            return "stale"
        action, arg = got
        _api(st, "answerCallbackQuery", {"callback_query_id": cb.get("id"),
                                         "text": "Выполняю…"})
        try:
            result = ACTIONS[action](arg)
        except Exception as e:                      # noqa: BLE001 — граница
            result = "Не вышло: %s" % e
        # Кнопки под исходным сообщением больше не нужны.
        try:
            _api(st, "editMessageReplyMarkup", {
                "chat_id": chat, "message_id": msg.get("message_id"),
                "reply_markup": {"inline_keyboard": []}})
        except RuntimeError:
            pass
        _send(st, result)
        log.info("бот Telegram: %s — %s" % (action, result), source="notify")
        return action
    msg = u.get("message") or {}
    text = msg.get("text") or ""
    if not text.startswith("/"):
        return "ignored"
    chat = (msg.get("chat") or {}).get("id")
    user = (msg.get("from") or {}).get("id")
    if not authorized(chat, user, st):
        return "denied"
    reply = command_reply(text)
    if reply:
        _send(st, reply)
    return "command"


# ─────────────────────────── опрос ──────────────────────────────────

def _settings() -> dict:
    from core import notify
    return notify.settings()


def active(st: dict) -> bool:
    return bool(st.get("enabled") and st.get("interactive")
                and st.get("token") and st.get("chat_id"))


def poll_once(st: dict) -> int:
    """Один долгий опрос ``getUpdates``. Возвращает число обновлений."""
    body = _api(st, "getUpdates", {
        "offset": _state["offset"], "timeout": POLL_TIMEOUT,
        "allowed_updates": ["message", "callback_query"]},
        timeout=POLL_TIMEOUT + 10)
    updates = body.get("result") or []
    for u in updates:
        _state["offset"] = max(_state["offset"],
                               int(u.get("update_id") or 0) + 1)
        try:
            handle_update(u, st)
        except Exception as e:                      # noqa: BLE001 — граница
            log.warning("бот Telegram: %s" % e, source="notify")
    return len(updates)


def _run() -> None:
    global _thread
    try:
        while True:
            st = _settings()
            if not active(st):
                return
            try:
                poll_once(st)
                _state["last_error"] = ""
            except Exception as e:                  # noqa: BLE001 — граница
                err = str(e)
                if err != _state["last_error"]:
                    log.warning("бот Telegram: %s" % err, source="notify")
                _state["last_error"] = err
                time.sleep(ERROR_PAUSE)
    finally:
        with _lock:
            _thread = None


def start() -> None:
    """Поднять опрос, если бот включён (загрузка и сохранение настроек)."""
    global _thread
    if not active(_settings()):
        return
    with _lock:
        if _thread is not None:
            return
        _thread = threading.Thread(target=_run, name="notify-bot",
                                   daemon=True)
        _thread.start()


def status() -> dict:
    with _lock:
        running = _thread is not None
        receipts = len(_receipts)
    return {"running": running, "receipts": receipts,
            "last_error": _state["last_error"]}
