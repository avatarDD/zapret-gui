# api/mcp.py
"""
HTTP-транспорт MCP-сервера.

    POST   /api/mcp            — JSON-RPC (один запрос или батч)
    GET    /api/mcp            — 405 + Allow: POST (SSE живёт отдельно)
    DELETE /api/mcp            — 405 + Allow: POST
    GET    /api/mcp/info       — метаданные для UI, локально и без токена
    GET    /api/mcp/sse        — legacy-SSE: поток ответов (S14)
    POST   /api/mcp/messages   — legacy-SSE: запросы, ответ уходит в поток

Точка живёт в том же веб-сервере, что и GUI: адрес, порт и TLS — это
``gui.host``/``gui.port``. При ``gui.host=127.0.0.1`` MCP доступен только
с самого роутера — самый безопасный режим, и он же по умолчанию.

**Основной транспорт — без состояния.** ``Mcp-Session-Id`` выдаётся на
``initialize`` и принимается обратно, но сервер на нём ничего не держит:
роутер перезагружается чаще, чем живёт сессия модели.

**Legacy-SSE (``mcp.transports.sse``, по умолчанию выключен)** — это
старая схема «два канала» из ревизии ``2024-11-05``: поток отдаёт первым
событием ``event: endpoint`` с адресом, куда слать запросы, запросы
уходят POST-ом на него и получают ``202``, а ответы приезжают обратно в
поток. Нужен ровно потому, что часть живых клиентов (сборки LM Studio,
старые Cline) ничего другого не умеют. Состояние (очередь ответов) —
в ``core/mcp/session.py``, и оно существует только ради доставки:
диспетчер тот же самый.

Флаг транспорта читается на каждом запросе — включение и выключение SSE
не требует перезапуска GUI. То же и с основным транспортом:
``mcp.transports.http=false`` закрывает ``POST /api/mcp`` (503 + Retry-
After), но не трогает ни страницу MCP (``/api/mcp/ui/*`` — отдельная
дверь под авторизацией GUI), ни stdio-мост, который зовёт диспетчер
напрямую. Выключив транспорт, от управления не отрезаешься.
"""

import json
import queue
import time
import uuid

from bottle import request, response

from core.mcp import (audit, auth, permissions, prompts, registry,
                      resources, server)
from core.mcp import session as mcp_session


# Заголовок, которым клиент сообщает ревизию спеки (обязателен после
# initialize — см. спеку MCP, раздел про HTTP-транспорт).
PROTOCOL_HEADER = "MCP-Protocol-Version"
SESSION_HEADER = "Mcp-Session-Id"

# Куда legacy-SSE просит слать запросы (это значение уезжает клиенту
# первым событием потока).
MESSAGES_PATH = "/api/mcp/messages"

_JSON_CT = "application/json; charset=utf-8"


def register(app):

    @app.route("/api/mcp", method="POST")
    def api_mcp_rpc():
        """Единственная рабочая точка MCP: JSON-RPC поверх HTTP POST."""
        response.content_type = _JSON_CT

        # 0. Транспорт выключен настройкой — отказ ДО авторизации:
        #    неотличимо от «нет такой точки» для того, кто подбирает
        #    токен, и понятно тому, кто сам его выключил.
        if not auth.http_enabled():
            return _http_disabled()

        # 1. Доступ: bind → Origin → токен → рейт-лимит.
        headers = _Headers(request.environ)
        decision = auth.check(
            method="POST",
            remote_addr=request.environ.get("REMOTE_ADDR", ""),
            headers=headers,
            auth_pair=_basic_auth(),
        )
        if not decision.ok:
            return _refuse(decision)

        # 2. Ревизия спеки. Заголовка может не быть (первый initialize,
        #    старые клиенты) — это не ошибка; ошибка — заголовок с
        #    версией, которой мы не знаем.
        version = (headers.get(PROTOCOL_HEADER, "") or "").strip()
        refusal = _version_refusal(version)
        if refusal is not None:
            return refusal

        # 3. Тело.
        refusal = _content_type_refusal()
        if refusal is not None:
            return refusal

        raw = request.body.read() if request.body else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError) as e:
            response.status = 200  # ошибка JSON-RPC едет с кодом 200
            return _body(server.parse_error(str(e)))

        if payload is None:
            return _body(server.parse_error("тело пустое"))

        # 4. Сессия: выдаём на initialize, принимаем обратно, ничего на
        #    ней не держим.
        session_id = (headers.get(SESSION_HEADER, "") or "").strip()
        if not session_id:
            session_id = uuid.uuid4().hex
        response.set_header(SESSION_HEADER, session_id)

        answer = server.dispatch(payload, {
            "permissions": auth.permissions(),
            "session_id": session_id,
            "subject": decision.subject,
            # Адрес вызывающего нужен журналу (core/mcp/audit.py): без
            # него в нём не видно, кто именно менял настройки.
            "remote_addr": request.environ.get("REMOTE_ADDR", ""),
            "protocol_version": version or server.PROTOCOL_VERSION,
        })

        if answer is None:
            # Тело состояло только из уведомлений — отвечать нечем.
            response.status = 202
            return b""
        return _body(answer)

    @app.route("/api/mcp", method="GET")
    def api_mcp_get():
        """SSE-канала здесь нет — и это не поломка, а свойство точки."""
        if not auth.http_enabled():
            return _http_disabled()
        return _method_not_allowed(
            "GET /api/mcp не поддерживается: основной транспорт работает "
            "без SSE, все вызовы идут через POST /api/mcp. Это не ошибка "
            "сервера — клиенту достаточно POST. Клиентам, умеющим только "
            "старую схему, — GET /api/mcp/sse (включается "
            "mcp.transports.sse)."
        )

    @app.route("/api/mcp", method="DELETE")
    def api_mcp_delete():
        """Сессию нечего удалять: сервер без состояния."""
        return _method_not_allowed(
            "DELETE /api/mcp не поддерживается: сервер не хранит сессий, "
            "закрывать нечего. Mcp-Session-Id выдаётся для совместимости "
            "и ни на что не влияет."
        )

    # ───────────────────────── legacy-SSE (S14) ─────────────────────
    #
    # Схема ревизии 2024-11-05: поток отдаёт адрес, запросы идут на него
    # POST-ом, ответы приезжают в поток. Два канала вместо одного — не
    # наш выбор, а условие совместимости с клиентами, которые умеют
    # только так.

    @app.route("/api/mcp/sse", method="GET")
    def api_mcp_sse():
        """Поток ответов legacy-SSE: ``event: endpoint``, затем сообщения."""
        if not mcp_session.sse_enabled():
            return _sse_disabled()

        headers = _Headers(request.environ)
        decision = auth.check(
            method="GET",
            remote_addr=request.environ.get("REMOTE_ADDR", ""),
            headers=headers,
            auth_pair=_basic_auth(),
        )
        if not decision.ok:
            return _refuse(decision)

        # Сессию заводим ДО генератора: после первого yield заголовки
        # уже ушли клиенту, и честного отказа не выйдет.
        try:
            sess = mcp_session.open_session(
                subject=decision.subject,
                remote_addr=request.environ.get("REMOTE_ADDR", ""))
        except mcp_session.TooManySessions as e:
            limit = e.args[0] if e.args else mcp_session.max_sessions()
            response.status = 429
            response.set_header("Retry-After", "30")
            response.content_type = _JSON_CT
            return _body({
                "ok": False,
                "error": "открыто уже %s SSE-сессий (mcp.limits."
                         "max_sessions); закройте лишний клиент или "
                         "поднимите лимит" % limit,
                "max_sessions": limit,
            })

        # Заголовки — до входа в генератор (как в api/logs.py).
        response.content_type = "text/event-stream"
        response.set_header("Cache-Control", "no-cache")
        response.set_header("X-Accel-Buffering", "no")
        response.set_header(SESSION_HEADER, sess.id)
        return _sse_stream(sess)

    @app.route(MESSAGES_PATH, method="POST")
    def api_mcp_messages():
        """Запрос legacy-SSE: ``202`` сразу, ответ — в поток сессии."""
        response.content_type = _JSON_CT
        if not mcp_session.sse_enabled():
            return _sse_disabled()

        headers = _Headers(request.environ)
        decision = auth.check(
            method="POST",
            remote_addr=request.environ.get("REMOTE_ADDR", ""),
            headers=headers,
            auth_pair=_basic_auth(),
        )
        if not decision.ok:
            return _refuse(decision)

        session_id = _session_param(headers)
        sess = mcp_session.get(session_id)
        if sess is None:
            # 404, а не 400: для клиента это «поток закрылся, открой
            # заново», и именно так он себя и ведёт.
            response.status = 404
            return _body({
                "ok": False,
                "error": "сессия %s не найдена: поток SSE закрыт или "
                         "истёк — откройте GET /api/mcp/sse заново"
                         % (_safe(session_id) or "<не указана>"),
                "sessions": mcp_session.count(),
            })

        version = (headers.get(PROTOCOL_HEADER, "") or "").strip()
        refusal = _version_refusal(version)
        if refusal is not None:
            return refusal
        refusal = _content_type_refusal()
        if refusal is not None:
            return refusal

        raw = request.body.read() if request.body else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError) as e:
            # Ошибка разбора тоже уезжает в поток: клиент этой схемы
            # читает ответы только оттуда, а не из тела POST.
            return _deliver(sess, server.parse_error(str(e)))
        if payload is None:
            return _deliver(sess, server.parse_error("тело пустое"))

        answer = server.dispatch(payload, {
            "permissions": auth.permissions(),
            "session_id": sess.id,
            "subject": decision.subject,
            "remote_addr": request.environ.get("REMOTE_ADDR", ""),
            "protocol_version": version or server.PROTOCOL_VERSION,
            "transport": "sse",
            # Сам объект сессии, а не только её id: подписка на ресурсы
            # (S18) живёт в очереди этого потока, и диспетчеру нужен
            # именно он — id пришлось бы искать обратно по реестру.
            "session": sess,
        })
        return _deliver(sess, answer)

    @app.route("/api/mcp/info")
    def api_mcp_info():
        """Метаданные для страницы настроек: включён ли, что разрешено.

        Без токена — иначе UI не покажет, что MCP выключен, пока токен
        не заведён. Зато только с самого роутера: снаружи это разведка
        (видно, какие разрешения открыты). Страница MCP (S15) ходит не
        сюда, а в ``/api/mcp/ui/state``: она открыта из браузера на
        LAN-адресе и под общей авторизацией GUI.
        """
        response.content_type = _JSON_CT
        remote = request.environ.get("REMOTE_ADDR", "")
        if not auth.is_local_address(remote):
            response.status = 403
            return _body({"ok": False,
                          "error": "/api/mcp/info доступен только с самого "
                                   "роутера"})
        return _body(info_payload())


def info_payload() -> dict:
    """Сводка о сервере: то же тело, что отдаёт ``/api/mcp/info``.

    Вынесено из обработчика, потому что ровно эти поля нужны странице
    MCP, а собирать их в JS из нескольких вызовов нельзя: на слабом
    роутере страница будет мигать (задание S15, «Грабли»).
    """
    cfg = auth.settings()
    perms = auth.permissions()
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled")),
        "active": auth.is_enabled(),
        # Сам токен не отдаём никогда — только факт, что он задан.
        "token_set": bool(cfg.get("token")),
        "allow_gui_auth": bool(cfg.get("allow_gui_auth")),
        "bind": cfg.get("bind", "inherit"),
        "transports": cfg.get("transports", {}),
        "permissions": perms,
        # Разрешение может стоять, но не действовать: experiments без
        # control/probes выключен. UI обязан показывать именно это,
        # иначе пользователь видит включённый флаг и выключенные
        # инструменты (модель разрешений — core/mcp/permissions.py).
        "permissions_effective": permissions.effective(perms),
        "permissions_info": permissions.describe(perms),
        "limits": cfg.get("limits", {}),
        "protocol_version": server.PROTOCOL_VERSION,
        "supported_protocol_versions":
            list(server.SUPPORTED_PROTOCOL_VERSIONS),
        "gui_version": _gui_version(),
        "tools_total": len(server.all_tools()),
        "tools_available": len(server.available_tools(perms)),
        "tools_by_scope": registry.scope_counts(perms),
        # Справочники и сценарии разрешений не требуют: их число
        # показывает UI, и по нему видно, что клиент подключился к
        # полноценному серверу, а не к пустой заглушке.
        # Журнал и снимки: страница MCP показывает, ведётся ли
        # журнал и есть ли что откатывать (`mcp_undo_last`).
        "audit": {
            "enabled": audit.is_enabled(),
            "keep": audit.keep(),
            "path": audit.journal_path(),
            "undoable": len(audit.snapshots()),
        },
        "resources": len(resources.list_resources()),
        "prompts": len(prompts.list_prompts()),
        "endpoint": "/api/mcp",
        # Legacy-SSE: включён ли и сколько потоков открыто прямо
        # сейчас. Мёртвая сессия на роутере со 128 МБ — это утечка,
        # и число на странице MCP делает её видимой.
        "sse": {
            "enabled": mcp_session.sse_enabled(),
            "endpoint": "/api/mcp/sse",
            "messages": MESSAGES_PATH,
            "sessions": mcp_session.count(),
            "max_sessions": mcp_session.max_sessions(),
            "keepalive_sec": mcp_session.KEEPALIVE_SEC,
            "idle_timeout_sec": mcp_session.IDLE_TIMEOUT_SEC,
            # Подписка на ресурсы (S18) существует здесь и на
            # stdio-мосте: у stateless-HTTP канала для уведомлений нет.
            "subscribe": True,
            "max_subscriptions": mcp_session.MAX_SUBSCRIPTIONS,
        },
    }


# ─────────────────────── legacy-SSE: помощники ──────────────────────

def _sse_stream(sess):
    """Генератор потока: адрес для запросов, затем ответы и keep-alive.

    Любое исключение подавляется: вылетев из WSGI-callable, оно пишет в
    stderr «Critical error while processing request» и не закрывает
    сессию — а незакрытая сессия на роутере со 128 МБ это утечка. Выход
    из генератора по любой причине проходит через ``finally``.
    """
    try:
        # Первым событием — адрес, куда слать запросы. Это и есть весь
        # смысл первой половины схемы: клиент узнаёт его отсюда.
        yield _sse_event("%s?session=%s" % (MESSAGES_PATH, sess.id),
                         event="endpoint", raw=True)
        last_ping = time.time()
        while True:
            sess.touch()
            # Смена разрешений = смена набора инструментов. Опрос на
            # круге keep-alive ловит и config_set, и правку в UI, и
            # ручную правку settings.json.
            mcp_session.poll_permissions()
            # Подписки на ресурсы (S18): сверяем отпечатки тех, чей
            # период истёк, и шлём notifications/resources/updated.
            mcp_session.poll_resources()
            try:
                message = sess.get(
                    timeout=mcp_session.stream_wait(sess))
            except queue.Empty:
                # С подпиской круг учащается, а пинг — нет: он нужен
                # прокси по дороге, а не клиенту.
                now = time.time()
                if now - last_ping >= mcp_session.KEEPALIVE_SEC:
                    last_ping = now
                    yield ": keep-alive\n\n"
                continue
            sess.sent += 1
            yield _sse_event(message, event="message")
    except (GeneratorExit, BrokenPipeError, ConnectionResetError, OSError):
        # Клиент отключился — штатный конец потока.
        pass
    except Exception:                           # noqa: BLE001 — граница
        try:
            from core.log_buffer import log
            log.error("MCP: SSE-поток оборван ошибкой", source="mcp")
        except Exception:
            pass
    finally:
        mcp_session.close(sess)


def _sse_event(data, event=None, raw=False):
    """Собрать SSE-событие.

    ``raw=True`` — ``data`` уже строка (адрес в ``event: endpoint``
    передаётся текстом, а не JSON: так сказано в спеке ревизии
    2024-11-05).
    """
    lines = []
    if event:
        lines.append("event: %s" % event)
    if raw:
        payload = str(data)
    else:
        try:
            payload = json.dumps(data, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            payload = "{}"
    # Перевод строки внутри data разорвал бы событие надвое.
    payload = payload.replace("\r", " ").replace("\n", " ")
    lines.append("data: %s" % payload)
    lines.append("")
    lines.append("")
    return "\n".join(lines)


def _deliver(sess, answer):
    """Положить ответ в поток сессии и отдать ``202``.

    Ответа в теле POST нет и быть не может: клиент этой схемы читает
    только поток. Переполненная очередь — это клиент, который поток не
    читает: честнее сказать 503, чем молча потерять ответ.
    """
    if answer is None:
        # Тело состояло только из уведомлений — отвечать нечем.
        response.status = 202
        return b""
    if not sess.put(answer):
        response.status = 503
        return _body({
            "ok": False,
            "error": "очередь сессии переполнена: SSE-поток не читают; "
                     "переоткройте GET /api/mcp/sse",
            "pending": sess.pending(),
        })
    response.status = 202
    return b""


def _session_param(headers) -> str:
    """Идентификатор сессии из query или заголовка.

    Сами мы отдаём ``?session=``, но клиенты, собранные по старым SDK,
    шлют ``sessionId``; заголовок принимаем за компанию — он ничего не
    стоит, а разбирательство «почему 404» стоит вечера.
    """
    for name in ("session", "sessionId", "session_id"):
        try:
            value = request.query.get(name)
        except Exception:                       # noqa: BLE001 — граница
            value = None
        if value:
            return str(value).strip()
    return (headers.get(SESSION_HEADER, "") or "").strip()


def _http_disabled():
    """Отказ, когда ``mcp.transports.http`` выключен.

    503, а не 404: точка существует и вернётся, как только транспорт
    включат обратно, — клиенту есть смысл повторить, а не считать
    сервер несуществующим.
    """
    response.status = 503
    response.set_header("Retry-After", "60")
    response.content_type = _JSON_CT
    return _body({
        "ok": False,
        "error": "основной транспорт MCP выключен: mcp.transports.http="
                 "false. Включить — на странице «MCP-сервер» в GUI "
                 "(она работает независимо от этого флага) или в "
                 "settings.json.",
        "transports": {"http": False, "sse": mcp_session.sse_enabled()},
        "hint": "stdio-мост (zapret-gui mcp --stdio) этим флагом не "
                "закрывается: он зовёт диспетчер напрямую",
    })


def _sse_disabled():
    """Отказ, когда ``mcp.transports.sse`` выключен."""
    response.status = 404
    response.content_type = _JSON_CT
    return _body({
        "ok": False,
        "error": "legacy-SSE выключен: включите mcp.transports.sse в "
                 "настройках MCP. Основной транспорт — POST /api/mcp — "
                 "работает всегда.",
        "endpoint": "/api/mcp",
    })


# ───────────────────────────── помощники ────────────────────────────

class _Headers:
    """Регистронезависимый доступ к заголовкам, устойчивый к мусору.

    ``bottle.request.headers`` декодирует значение как latin-1 → utf-8
    и бросает ``UnicodeError`` на байтах, которые не складываются в
    UTF-8. Для точки, куда каждый желающий шлёт ``Authorization``, это
    означает 500 вместо честного 401: достаточно одного неверного
    байта в токене. Здесь битое значение превращается в замену, а не в
    исключение, — решение о доступе всё равно примет ``auth.check``.
    """

    __slots__ = ("_data",)

    def __init__(self, environ):
        self._data = {}
        for key, value in (environ or {}).items():
            if not key.startswith("HTTP_") or not isinstance(value, str):
                continue
            self._data[key[5:].replace("_", "-").lower()] = _decode(value)

    def get(self, name, default=""):
        return self._data.get(str(name).lower(), default)


def _decode(value: str) -> str:
    """Вернуть заголовок как текст, не падая на неверных байтах."""
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        try:
            return value.encode("latin-1", "replace").decode("utf-8",
                                                             "replace")
        except UnicodeError:
            return value


def _basic_auth():
    """Разобранная Basic-пара или None (bottle бросает на мусоре)."""
    try:
        return request.auth
    except Exception:
        return None



def _version_refusal(version):
    """Отказ по неизвестной ревизии спеки или ``None``.

    Заголовка может не быть (первый initialize, старые клиенты) — это
    не ошибка; ошибка — версия, которой мы не знаем.
    """
    if not version or version in server.SUPPORTED_PROTOCOL_VERSIONS:
        return None
    response.status = 400
    response.content_type = _JSON_CT
    return _body({
        "ok": False,
        "error": "неподдерживаемая ревизия MCP: %s" % _safe(version),
        "supported": list(server.SUPPORTED_PROTOCOL_VERSIONS),
    })


def _content_type_refusal():
    """Отказ по чужому Content-Type или ``None``."""
    ctype = (request.content_type or "").split(";")[0].strip().lower()
    if not ctype or ctype == "application/json":
        return None
    response.status = 415
    response.content_type = _JSON_CT
    return _body({
        "ok": False,
        "error": "ожидается Content-Type: application/json (получено %s)"
                 % _safe(ctype),
    })


def _refuse(decision):
    """Отдать отказ авторизации с нужным кодом и заголовками."""
    response.status = decision.status
    for name, value in (decision.headers or {}).items():
        response.set_header(name, value)
    return _body({"ok": False, "error": decision.error,
                  "reason": decision.reason})


def _method_not_allowed(text):
    response.status = 405
    response.set_header("Allow", "POST")
    response.content_type = _JSON_CT
    return _body({"ok": False, "error": text, "allow": ["POST"]})


def _body(payload):
    """Сериализовать тело в UTF-8 байты.

    Bottle отдаёт тело как байты и считает Content-Length по ним: если
    вернуть str с кириллицей, длина разъедется с содержимым и клиент
    получит обрезанный JSON.
    """
    return json.dumps(payload, ensure_ascii=False,
                      default=str).encode("utf-8")


def _gui_version():
    from core.version import GUI_VERSION
    return GUI_VERSION


def _safe(text, limit=80):
    """Обрезать внешнюю строку перед вставкой в текст ответа."""
    text = (text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"
