# core/ndms/rci_client.py
"""
HTTP-клиент к Keenetic Router Control Interface (RCI).

RCI слушает на http://localhost:79/rci/ и принимает:
  - GET  http://localhost:79/rci/<path>   — прочитать состояние
                                            (например `show/version`)
  - POST http://localhost:79/rci/         — выполнить мутацию
                                            (JSON-дерево NDMS-CLI)

Авторизация: при запросе с самого роутера (127.0.0.1) — не требуется.
Это и есть основной use-case: мы крутимся внутри Entware на том же
устройстве, что и сам Keenetic.

Зависимости — только stdlib (urllib). Никаких новых пакетов.
"""

import json
import threading
import urllib.error
import urllib.request

from core.log_buffer import log


DEFAULT_BASE_URL = "http://localhost:79/rci"
DEFAULT_TIMEOUT = 10           # секунды, отдельный запрос
PROBE_TIMEOUT   = 3            # для is_available — быстрая проверка


class NdmsRciClient:
    """Тонкая обёртка над HTTP RCI Keenetic'а."""

    def __init__(self, base_url: str = "", timeout: float = 0):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout  = float(timeout) if timeout else DEFAULT_TIMEOUT
        self._lock      = threading.Lock()
        self._available = None   # тернарный кэш: None | True | False
        self._version_cache = ""

    # ─────── низкоуровневые HTTP-операции ───────

    def _request(self, method: str, path: str = "", payload=None,
                 timeout: float = 0):
        """
        Единая точка для всех RCI-вызовов.

        Возвращает (ok: bool, data: dict|list|None, err: str).
        """
        url = self.base_url
        if path:
            url = self.base_url + "/" + path.lstrip("/")
        if method == "POST":
            # POST идёт на корень, payload — JSON-дерево
            url = self.base_url + "/"

        body = None
        headers = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        try:
            req = urllib.request.Request(
                url, data=body, method=method, headers=headers)
            with urllib.request.urlopen(
                    req, timeout=timeout or self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return True, {}, ""
                text = raw.decode("utf-8", errors="replace")
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    # Некоторые RCI-эндпоинты могут отдавать пустой 200
                    # или plain-text — это всё ещё «успех».
                    return True, {"raw": text}, ""
                return True, data, ""
        except urllib.error.HTTPError as e:
            # 404/4xx/5xx — НЕ exception, это «команда не сработала»,
            # но соединение прошло. Тело может содержать описание.
            try:
                raw = e.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = {"raw": raw}
            except Exception:
                data = None
            return False, data, "HTTP %s" % e.code
        except urllib.error.URLError as e:
            return False, None, "URLError: %s" % e.reason
        except (OSError, TimeoutError) as e:
            return False, None, "OSError: %s" % e

    def get(self, path: str, timeout: float = 0):
        """GET <base>/<path>. Возвращает разобранный JSON или None."""
        ok, data, _err = self._request("GET", path=path, timeout=timeout)
        return data if ok else None

    def post(self, payload, timeout: float = 0) -> dict:
        """
        POST mutation. Возвращает dict с ключами:
            ok:   bool
            data: ответ NDMS (как пришёл)
            error: строка с описанием ошибки (если ok=False)
        """
        ok, data, err = self._request("POST", payload=payload, timeout=timeout)
        if ok:
            # NDMS обычно возвращает массив объектов со статусами вида
            # [{"status": [{"status": "ok", "message": "..."}]}].
            # Считаем команду неуспешной, если в ответе есть status="error".
            status_err = _scan_error_in_status(data)
            if status_err:
                return {"ok": False, "data": data, "error": status_err}
            return {"ok": True, "data": data}
        return {"ok": False, "data": data, "error": err}

    # ─────── high-level helpers ───────

    def is_available(self, force: bool = False) -> bool:
        """
        Доступен ли RCI прямо сейчас.

        Кэшируется до перезапуска. Принудительный re-probe — force=True.
        Делаем быстрый GET /rci/show/version: на Keenetic'е возвращается
        JSON с полями title/sandbox/etc.
        """
        with self._lock:
            if self._available is not None and not force:
                return self._available

            ok, data, _err = self._request(
                "GET", path="show/version", timeout=PROBE_TIMEOUT)
            if not ok or not isinstance(data, dict):
                self._available = False
                return False

            # Минимальная валидация ответа: должна быть какая-то
            # содержательная инфа (title/release/sandbox/ndm).
            has_marker = any(k in data for k in (
                "title", "release", "sandbox", "ndm",
                "build", "version", "architecture"))
            self._available = bool(has_marker)
            if self._available:
                # Запомним строку версии для логов и UI
                self._version_cache = (
                    str(data.get("title") or data.get("release") or
                        data.get("version") or "")
                )
                log.info("NDMS RCI доступен (%s)" %
                         (self._version_cache or "?"),
                         source="ndms")
            return self._available

    def version(self) -> str:
        """Кэшированная строка версии прошивки. '' если RCI недоступен."""
        if self._available is None:
            self.is_available()
        return self._version_cache

    # ─────── мутации общего назначения ───────

    def save_running_config(self) -> dict:
        """
        Сохранить running-config в startup ('system configuration save').

        В awg-manager это делается отдельным вызовом после батча мутаций
        — иначе изменения теряются при перезагрузке роутера.
        """
        return self.post({"system": {"configuration": {"save": True}}})


# ─────── helpers ───────

def _scan_error_in_status(data) -> str:
    """
    Пробежаться по ответу NDMS и собрать первую status=error.

    Формат ответа Keenetic'а — лес объектов с полем "status":
    либо плоский dict {"status": "ok|error", "message": "..."}, либо
    [{"status": [{"status": "...", ...}]}] от nested-команд.
    """
    def _walk(node):
        if isinstance(node, dict):
            s = node.get("status")
            if isinstance(s, str) and s.lower() in ("error", "critical"):
                return str(node.get("message") or "NDMS error")
            for v in node.values():
                r = _walk(v)
                if r:
                    return r
        elif isinstance(node, list):
            for it in node:
                r = _walk(it)
                if r:
                    return r
        return ""
    try:
        return _walk(data) or ""
    except Exception:
        return ""


# ─────── singleton ───────

_client = None
_client_lock = threading.Lock()


def get_rci_client() -> NdmsRciClient:
    """Глобальный синглтон RCI-клиента."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = NdmsRciClient()
    return _client


def is_ndms_available(force: bool = False) -> bool:
    """
    Финальная проверка «можно ли использовать NDMS на этой платформе».

    Условия:
      1. Платформа — Keenetic (детект через `awg_detector`).
      2. RCI отвечает HTTP 200 на /rci/show/version с осмысленным JSON.

    На любой другой платформе всегда False — без сетевого probe.
    """
    # Ленивый импорт, чтобы не дёргать тяжёлый detector до фактического
    # вызова.
    try:
        from core.awg_detector import get_awg_detector
        from core.awg_platform import is_keenetic
        if not is_keenetic(get_awg_detector().detect_platform()):
            return False
    except Exception:
        return False

    return get_rci_client().is_available(force=force)
