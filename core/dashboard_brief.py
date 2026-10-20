# core/dashboard_brief.py
"""
«Кратко» на главной: одна строка «всё ли работает» и итог каждого блока.

## Зачем

Главная показывает десяток карточек, и чтобы понять «работает ли обход»,
их надо прочитать все. Здесь из того же ответа ``/api/dashboard/status``
собирается вердикт: одна строка сверху, у каждого блока — итог в
заголовке, а блок с проблемой страница раскрывает сама (приём
nfqws2-ui).

Чистая функция: на вход — словарь ответа дашборда, на выход — уровни и
тексты. Новых опросов устройства она не делает.

## Уровни

* ``bad`` — обход сейчас не работает или сайт из мониторинга не
  открывается: движок остановлен при выбранной стратегии, zapret2 не
  установлен, рядом другой обходчик DPI, «нет связи».
* ``warn`` — работает, но есть что поправить: стратегия не выбрана,
  автозапуск выключен (после перезагрузки обход не поднимется).
* ``ok`` — всё в порядке.
"""

from __future__ import annotations

LEVELS = ("ok", "warn", "bad")
# Сколько имён сайтов перечислять в строке, остальное — «и ещё N».
MAX_NAMES = 3


def _worse(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def _names(items: list) -> str:
    head = ", ".join(items[:MAX_NAMES])
    rest = len(items) - MAX_NAMES
    return head + (" и ещё %d" % rest if rest > 0 else "")


def _nfqws_block(st: dict, rivals: list) -> tuple:
    """(уровень, итог, проблемы) блока «Обход DPI»."""
    problems = []
    nfq = st.get("nfqws") or {}
    strategy = st.get("strategy") or {}
    zapret = st.get("zapret") or {}
    autostart = st.get("autostart") or {}
    running = bool(nfq.get("running"))
    chosen = bool(strategy.get("id"))

    if rivals:
        problems.append(("bad", "работает другой обходчик DPI (%s): он "
                         "меняет те же пакеты, что nfqws2, и стратегия "
                         "срабатывает через раз — оставьте что-то одно"
                         % _names([r.get("name") or "?" for r in rivals]),
                         "diagnostics"))
    if zapret and not zapret.get("installed", True):
        problems.append(("bad", "zapret2 не установлен", "zapret"))
    elif not chosen:
        problems.append(("warn", "стратегия не выбрана", "strategies"))
    elif not running:
        # Положительный код — движок упал сам; отрицательный (сигнал) или
        # пусто — его остановили, обхода нет, но это не авария.
        code = nfq.get("exit_code")
        crashed = isinstance(code, int) and code > 0
        problems.append(("bad" if crashed else "warn",
                         "nfqws2 %s" % ("упал (код выхода %d)" % code
                                        if crashed else "остановлен"),
                         "control"))
    if running and not autostart.get("enabled") \
            and autostart.get("method") != "unsupported":
        problems.append(("warn", "автозапуск выключен — после "
                         "перезагрузки обход не поднимется", "autostart"))

    level = "ok"
    for lv, _t, _p in problems:
        level = _worse(level, lv)
    if running and chosen:
        text = "nfqws2 работает, стратегия «%s»" % (
            strategy.get("name") or strategy.get("id"))
    elif running:
        text = "nfqws2 работает"
    elif chosen:
        text = "nfqws2 остановлен"
    else:
        text = "обход DPI не настроен"
    return level, text, problems


def _vpn_block(data: dict) -> tuple:
    """Туннели: что поднято. Остановленный профиль — не проблема:
    пользователь мог выключить его сам."""
    up = []
    for key, title in (("awg", "AmneziaWG"), ("singbox", "sing-box"),
                       ("mihomo", "mihomo")):
        eng = data.get(key) or {}
        if eng.get("active"):
            names = [n for n in eng.get("names") or [] if n]
            up.append("%s%s" % (title, " (%s)" % ", ".join(names)
                                if names else ""))
    if any(c.get("active") for c in data.get("warp") or []
           if isinstance(c, dict)):
        up.append("WARP/MASQUE")
    if (data.get("opera") or {}).get("running"):
        up.append("Opera Proxy")
    tg = data.get("tgproxy") or {}
    if tg.get("any_running"):
        up.append("Telegram")
    configured = any((data.get(k) or {}).get("total")
                     for k in ("awg", "singbox", "mihomo")) \
        or bool(data.get("warp"))
    problems = _foreign_problems(data.get("foreign") or {})
    level = "warn" if problems else "ok"
    if up:
        return level, "подняты: " + ", ".join(up), problems
    return level, ("туннели не подняты" if configured
                   else "туннели не настроены"), problems


_ENGINE_TITLES = {"usque": "usque", "singbox": "sing-box",
                  "mihomo": "mihomo", "awg": "AmneziaWG",
                  "opera": "Opera Proxy", "tgproxy": "Telegram-прокси"}


def _foreign_problems(foreign: dict) -> list:
    """Сторонние экземпляры движков (core/foreign_services.summary)."""
    out = []
    engines = foreign.get("engines") or {}
    if engines:
        out.append(("warn", "работают или включены в автозапуск сторонние "
                    "экземпляры туннелей (%s) — GUI ими не управляет"
                    % _names([_ENGINE_TITLES.get(k, k)
                              for k in sorted(engines)]),
                    "foreign-services"))
    if foreign.get("conflicts"):
        out.append(("warn", "несколько сервисов претендуют на одно имя "
                    "интерфейса — после перезагрузки поднимется только "
                    "первый", "foreign-services"))
    return out


def _monitor_block(data: dict) -> tuple:
    hc = data.get("healthcheck") or {}
    if not hc.get("enabled"):
        return "ok", "мониторинг сайтов выключен", []
    history = hc.get("history") or []
    last = history[-1] if history else None
    if not last:
        return "ok", "мониторинг включён, проверок ещё не было", []
    total = int(last.get("total") or 0)
    ok = int(last.get("ok") or 0)
    if not total:
        return "ok", "мониторинг включён, но сайтов в нём нет", []
    if last.get("global_outage"):
        return "bad", "не открывается ни один сайт", [(
            "bad", "не открывается ни один сайт из мониторинга — похоже, "
            "нет связи или обход не запущен", "diagnostics")]
    failed = [r.get("display") or r.get("service") or "?"
              for r in last.get("results") or [] if not r.get("ok")]
    if failed:
        return "bad", "открываются %d из %d" % (ok, total), [(
            "bad", "не открываются: %s" % _names(failed), "strategies")]
    return "ok", "открываются все %d" % total, []


def brief(data: dict) -> dict:
    """Итог дашборда. ``data`` — ответ ``/api/dashboard/status``."""
    data = data or {}
    st = data.get("status") or {}
    blocks = {}
    problems = []
    for key, (level, text, probs) in (
            ("nfqws", _nfqws_block(st, data.get("rivals") or [])),
            ("vpn", _vpn_block(data)),
            ("monitoring", _monitor_block(data))):
        blocks[key] = {"level": level, "text": text}
        problems += [{"level": lv, "text": t, "page": p, "block": key}
                     for lv, t, p in probs]
    level = "ok"
    for p in problems:
        level = _worse(level, p["level"])
    bad = [p["text"] for p in problems if p["level"] == "bad"]
    warn = [p["text"] for p in problems if p["level"] == "warn"]
    if bad:
        line = "Есть проблема: " + "; ".join(bad)
    elif warn:
        line = "Работает, но: " + "; ".join(warn)
    else:
        line = "Всё работает: " + blocks["nfqws"]["text"]
        if blocks["monitoring"]["text"].startswith("открываются"):
            line += "; сайты из мониторинга " + blocks["monitoring"]["text"]
    return {"level": level, "line": line, "blocks": blocks,
            "problems": problems}
