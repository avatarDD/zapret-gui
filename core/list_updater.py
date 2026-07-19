# core/list_updater.py
"""
Курируемые удалённые списки доменов + автообновление по URL.

Идея заимствована из podkop / getdomains: вместо того чтобы заставлять
пользователя вручную набивать сотни доменов, даём готовые community-
списки (YouTube, Meta, Discord, Telegram, X, «вся заблокировка внутри
РФ»), которые добавляются в named-lists одним кликом и обновляются по
таймеру. Дальше они переиспользуются единым слоем маршрутизации
(назначение → метод): «домены из списка → туннель/nfqws2».

Источник по умолчанию — itdoginfo/allow-domains (raw-формат: по домену
на строку), тот же, что использует экосистема podkop/getdomains.

Семантика обновления (надёжность):
  * MERGE с сохранением ручных правок. Храним снимок прошлого remote
    (`_remote`); ручные добавления (то, чего не было в прошлом remote)
    сохраняются, а записи, удалённые в upstream, уходят.
  * «не затирать при пустом» — пустой/ошибочный ответ НЕ меняет
    содержимое списка (как в server_pool / catalog_updater).

Списки с заполненным `source_url` считаются управляемыми и попадают под
автообновление. Списки без URL (чисто пользовательские) обновлятель не
трогает.

Транспорт скачивания (задача №7): одна настройка на подсистему —
`lists.transport` в settings.json ('', 'awg[:iface]', 'singbox[:конфиг]',
'mihomo[:конфиг]', см. core/download_transport). Применяется ко всем
управляемым спискам; GitHub-URL дополнительно проходят через зеркало
(install.mirror), как у установщиков. Недоступный транспорт — честная
ошибка в last_error, содержимое списка не затирается.
"""

from __future__ import annotations

import threading
import time
import urllib.error

from core.log_buffer import log
from core import named_lists


DEFAULT_INTERVAL_HOURS = 12
HTTP_TIMEOUT           = 20
MAX_DOWNLOAD_BYTES     = 4 * 1024 * 1024
USER_AGENT             = "zapret-gui/list-updater"

_BASE = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"

# Курируемые пресеты (community-списки доменов). Пользователь добавляет
# одним кликом; список редактируемый — можно добавить свой URL.
CURATED_PRESETS = [
    # ─── Сервисы ───
    {
        "name": "YouTube",
        "url": _BASE + "/Services/youtube.lst",
        "description": "Домены YouTube / googlevideo.",
        "category": "services",
    },
    {
        "name": "Meta (Instagram/Facebook)",
        "url": _BASE + "/Services/meta.lst",
        "description": "Домены Meta: Instagram, Facebook, WhatsApp.",
        "category": "services",
    },
    {
        "name": "Twitter / X",
        "url": _BASE + "/Services/twitter.lst",
        "description": "Домены X (бывш. Twitter).",
        "category": "services",
    },
    {
        "name": "Discord",
        "url": _BASE + "/Services/discord.lst",
        "description": "Домены Discord (включая voice/CDN).",
        "category": "services",
    },
    {
        "name": "Telegram",
        "url": _BASE + "/Services/telegram.lst",
        "description": "Домены Telegram.",
        "category": "services",
    },
    {
        "name": "TikTok",
        "url": _BASE + "/Services/tiktok.lst",
        "description": "Домены TikTok.",
        "category": "services",
    },
    {
        "name": "Netflix",
        "url": _BASE + "/Services/netflix.lst",
        "description": "Домены Netflix.",
        "category": "services",
    },
    {
        "name": "Cloudflare CDN",
        "url": _BASE + "/Services/cloudflare.lst",
        "description": "Домены Cloudflare CDN.",
        "category": "services",
    },
    {
        "name": "Google Meet",
        "url": _BASE + "/Services/google-meet.lst",
        "description": "Домены Google Meet.",
        "category": "services",
    },
    # ─── Страны ───
    {
        "name": "Россия — вся заблокировка (inside)",
        "url": _BASE + "/Russia/inside-raw.lst",
        "description": "Сводный список ресурсов, заблокированных внутри РФ "
                       "(itdoginfo/allow-domains).",
        "category": "countries",
    },
    {
        "name": "Россия — за рубежом (outside)",
        "url": _BASE + "/Russia/outside-raw.lst",
        "description": "Российские сервисы для доступа из-за рубежа.",
        "category": "countries",
    },
    {
        "name": "Украина — внутри (inside)",
        "url": _BASE + "/Ukraine/inside-raw.lst",
        "description": "Заблокированные в Украине ресурсы.",
        "category": "countries",
    },
]


_lock = threading.Lock()


# ─────── транспорт скачивания (настройка подсистемы) ───────

def get_transport() -> str:
    """Транспорт скачивания управляемых списков ('' = напрямую)."""
    try:
        from core.config_manager import get_config_manager
        v = get_config_manager().get("lists", "transport", default="")
        return str(v or "").strip()
    except Exception:
        return ""


def set_transport(transport: str) -> dict:
    """Сохранить транспорт (переживает рестарт GUI)."""
    t = str(transport or "").strip()
    if t in ("direct",):
        t = ""
    if t:
        from core.download_transport import is_valid_spec
        if not is_valid_spec(t):
            return {"ok": False, "error": "Неизвестный транспорт '%s'" % t}
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cm.set("lists", "transport", t)
        cm.save()
    except Exception as e:
        return {"ok": False, "error": "settings: %s" % e}
    return {"ok": True, "transport": t}


# ─────── presets / creation ───────

def presets() -> list:
    """Курируемые пресеты с пометкой, добавлен ли уже такой URL."""
    existing = {(it.get("source_url") or "")
                for it in named_lists.list_all()}
    return [dict(p, added=(p["url"] in existing)) for p in CURATED_PRESETS]


def is_safe_url(url: str) -> bool:
    """Проверка URL на безопасность против SSRF."""
    import re
    import socket
    import ipaddress
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False

        # Защита от инъекций управляющих символов в хост
        if any(c in host for c in "\r\n\t /\\#?@"):
            return False

        # Проверка формата хоста
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}[a-zA-Z0-9]$", host):
            return False

        # Если хост является IP-адресом напрямую
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass

        # Проверка резолвинга на приватные диапазоны IP
        try:
            addrinfo = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
            for family, _, _, _, sockaddr in addrinfo:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return False
        except Exception:
            pass

        return True
    except Exception:
        return False


def add_from_url(url: str, *, name: str = "", description: str = "",
                 interval_hours: int = DEFAULT_INTERVAL_HOURS,
                 refresh_now: bool = True) -> dict:
    """
    Создать управляемый named-list по URL и (опц.) сразу подтянуть.
    Имя по умолчанию берём из URL.
    """
    url = (url or "").strip()
    # MR-63: Защита от SSRF
    if not is_safe_url(url):
        return {"ok": False, "error": "Недопустимый или небезопасный URL (SSRF block)"}

    # Дедуп по source_url.
    for it in named_lists.list_all():
        if (it.get("source_url") or "") == url:
            return {"ok": False, "error": "Список с таким URL уже есть",
                    "id": it.get("id")}

    if not name:
        name = url.rstrip("/").split("/")[-1] or "Список"

    res = named_lists.create(name, description=description, source_url=url)
    if not res.get("ok"):
        # Имя занято — добавим суффикс из хвоста URL.
        res = named_lists.create("%s (%s)" % (name, url.split("/")[-1]),
                                 description=description, source_url=url)
        if not res.get("ok"):
            return res

    list_id = res["list"]["id"]
    named_lists.update_fields(list_id, {
        "interval_hours": max(1, int(interval_hours)),
        "auto_managed": True,
        "last_refresh": 0, "last_status": "", "last_error": "",
    })

    out = {"ok": True, "id": list_id}
    if refresh_now:
        out["refresh"] = refresh_one(list_id)
    get_list_refresher().reconfigure()
    return out


def add_preset(url: str) -> dict:
    p = next((x for x in CURATED_PRESETS if x["url"] == url), None)
    if not p:
        return {"ok": False, "error": "Неизвестный пресет"}
    return add_from_url(p["url"], name=p["name"],
                        description=p.get("description", ""))


# ─────── fetch + merge ───────

def _fetch(url: str, transport: str = "") -> str:
    # Зеркало (install.mirror) — GitHub-списки itdoginfo часто
    # недоступны напрямую; транспорт — через core/download_transport.
    from core.binary_installer import resolve_url
    from core.download_transport import urlopen_via
    try:
        with urlopen_via(resolve_url(url), transport=transport,
                         timeout=HTTP_TIMEOUT,
                         headers={"User-Agent": USER_AGENT}) as r:
            raw = r.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP %s" % e.code)
    except RuntimeError:
        raise   # транспорт недоступен — сообщение уже человекочитаемое
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise RuntimeError("сеть: %s" % e)
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise RuntimeError("список > %d МБ"
                           % (MAX_DOWNLOAD_BYTES // (1024 * 1024)))
    return raw.decode("utf-8", errors="replace")


def merge_preserving_manual(current: dict, remote: dict,
                            prev_remote: dict) -> dict:
    """
    Слить remote в текущий список, сохранив ручные правки.

    manual = current − prev_remote  (то, что добавил пользователь сверх
    прошлого remote). Результат = remote ∪ manual (remote вперёд),
    записи, исчезнувшие из upstream, уходят (если их не добавляли вручную).

    Чистая функция — тестируется без I/O.
    """
    def _merge(cur, rem, prev):
        prev_set = set(prev or [])
        cur_list = list(cur or [])
        rem_list = list(rem or [])
        manual = [x for x in cur_list if x not in prev_set]
        seen, out = set(), []
        for x in rem_list + manual:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "domains": _merge(current.get("domains"), remote.get("domains"),
                          prev_remote.get("domains")),
        "cidrs": _merge(current.get("cidrs"), remote.get("cidrs"),
                        prev_remote.get("cidrs")),
    }


def refresh_one(list_id: str) -> dict:
    item = named_lists.get(list_id)
    if not item:
        return {"ok": False, "error": "Список не найден"}
    url = (item.get("source_url") or "").strip()
    if not url:
        return {"ok": False, "error": "У списка нет source_url"}

    # Per-list transport: если у списка задан свой транспорт — используем его,
    # иначе — глобальный lists.transport.
    list_transport = (item.get("transport") or "").strip()
    transport = list_transport if list_transport else get_transport()

    try:
        text = _fetch(url, transport=transport)
    except RuntimeError as e:
        named_lists.update_fields(list_id, {
            "last_refresh": int(time.time()),
            "last_status": "error", "last_error": str(e)})
        return {"ok": False, "error": str(e)}

    remote = named_lists.parse_entries(text)
    if not remote["domains"] and not remote["cidrs"]:
        # Не затираем при пустом ответе.
        named_lists.update_fields(list_id, {
            "last_refresh": int(time.time()),
            "last_status": "empty",
            "last_error": "пустой список — текущее содержимое сохранено"})
        return {"ok": False, "error": "Пустой список (не затёрто)",
                "preserved": True}

    current = {"domains": list(item.get("domains") or []),
               "cidrs": list(item.get("cidrs") or [])}
    prev_remote = item.get("_remote") or {"domains": [], "cidrs": []}
    merged = merge_preserving_manual(current, remote, prev_remote)

    named_lists.update_fields(list_id, {
        "domains": merged["domains"],
        "cidrs": merged["cidrs"],
        "_remote": remote,
        "last_refresh": int(time.time()),
        "last_status": "ok",
        "last_error": "",
        "last_count": len(merged["domains"]) + len(merged["cidrs"]),
    })
    log.info("list %s: обновлён, доменов %d, cidr %d"
             % (list_id, len(merged["domains"]), len(merged["cidrs"])),
             source="lists")
    return {"ok": True, "id": list_id,
            "domains": len(merged["domains"]),
            "cidrs": len(merged["cidrs"])}


def refresh_all() -> dict:
    results = []
    for it in named_lists.list_all():
        if (it.get("source_url") or "").strip():
            results.append({"id": it["id"],
                            "result": refresh_one(it["id"])})
    return {"ok": True, "refreshed": results}


def managed_lists() -> list:
    """Списки под автообновлением (с source_url)."""
    return [it for it in named_lists.list_all()
            if (it.get("source_url") or "").strip()]


# ─────── background refresher ───────

class ListRefresher:
    """Фоновой поток: раз в минуту обновляет управляемые списки по их
    индивидуальному интервалу."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop_evt = threading.Event()

    def reconfigure(self):
        if managed_lists():
            self._start()
        else:
            self._stop()

    def _start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            t = threading.Thread(target=self._run_loop,
                                 name="list-refresher", daemon=True)
            t.start()
            self._thread = t
            log.info("list-refresher: запущен", source="lists")

    def _stop(self):
        with self._lock:
            if self._thread is None:
                return
            self._stop_evt.set()
            self._thread = None
            log.info("list-refresher: остановлен", source="lists")

    def _run_loop(self):
        while not self._stop_evt.wait(60):
            try:
                self._tick()
            except Exception as e:
                log.warning("list-refresher tick: %s" % e, source="lists")

    def _tick(self):
        now = int(time.time())
        for it in managed_lists():
            interval = int(it.get("interval_hours") or DEFAULT_INTERVAL_HOURS)
            last = int(it.get("last_refresh") or 0)
            if (now - last) < interval * 3600:
                continue
            log.info("list %s: автообновление" % it["id"], source="lists")
            try:
                refresh_one(it["id"])
            except Exception as e:
                log.warning("list %s autorefresh: %s" % (it["id"], e),
                            source="lists")

    def get_status(self) -> dict:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
        return {"running": running, "managed": len(managed_lists())}


_refresher = None
_refresher_lock = threading.Lock()


def get_list_refresher() -> ListRefresher:
    global _refresher
    if _refresher is None:
        with _refresher_lock:
            if _refresher is None:
                _refresher = ListRefresher()
                _refresher.reconfigure()
    return _refresher
