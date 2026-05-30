# core/proxy_tester.py
"""
Тестер доступности прокси-серверов (outbound'ов sing-box).

Гибридная схема (две фазы):

  Фаза 1 — TCP-отсев. Параллельный TCP-connect до `server:server_port`
    каждого outbound'а с коротким таймаутом. Мёртвые (сервер не
    отвечает на самом эндпоинте) отсеиваются сразу — это дёшево и
    отбрасывает основную массу нерабочих ключей из публичных свалок.

  Фаза 2 — e2e через движок (Clash API). Для выживших поднимаем
    одноразовый sing-box со всеми кандидатами + selector + включённым
    `experimental.clash_api`, и дёргаем
        GET /proxies/<tag>/delay?url=<target>&timeout=<ms>
    — sing-box реально открывает соединение к target (Cloudflare/Amazon)
    ЧЕРЕЗ этот прокси и возвращает задержку. Это честная проверка, что
    через сервер открывается крупное облако, а не просто «порт жив».

Если бинарь sing-box не установлен — фаза 2 пропускается, отдаём
результаты только TCP-отсева (graceful degrade).

Целевые «крупные облака» (которые в РФ часто под блокировкой, поэтому
доступность через прокси показательна):
  - cloudflare → http://cp.cloudflare.com/generate_204  (отдаёт 204)
  - google     → http://www.gstatic.com/generate_204
  - amazon     → https://aws.amazon.com/

Чистые помощники (build_test_config / parse_delay / resolve_target /
tcp_prefilter) тестируются без I/O и без бинаря.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.log_buffer import log


# ─────── target presets ───────

TARGET_PRESETS = {
    "cloudflare": "http://cp.cloudflare.com/generate_204",
    "google":     "http://www.gstatic.com/generate_204",
    "amazon":     "https://aws.amazon.com/",
}
DEFAULT_TARGET = "cloudflare"

# Лимиты/таймауты
_TCP_TIMEOUT      = 3.0      # сек на TCP-connect (фаза 1)
_TCP_WORKERS      = 32
_E2E_WORKERS      = 16
_DEFAULT_E2E_MS   = 5000     # таймаут одного delay-замера (мс)
_MAX_SERVERS      = 200      # потолок числа серверов за один прогон
_CLASH_BOOT_WAIT  = 10.0     # сек ждём, пока поднимется clash_api


def resolve_target(target: str) -> str:
    """Имя пресета ('cloudflare'/'amazon'/'google') или готовый URL → URL."""
    if not target:
        return TARGET_PRESETS[DEFAULT_TARGET]
    t = target.strip()
    if t in TARGET_PRESETS:
        return TARGET_PRESETS[t]
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return TARGET_PRESETS.get(t, TARGET_PRESETS[DEFAULT_TARGET])


# ─────── phase 1: TCP prefilter ───────

def _tcp_connect_ok(host: str, port: int, timeout: float) -> tuple:
    """(ok, latency_ms|None). Чистый TCP-connect без TLS."""
    if not host or not (0 < int(port) < 65536):
        return False, None
    t0 = time.time()
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except (OSError, socket.timeout, ValueError):
        return False, None
    try:
        sock.close()
    except OSError:
        pass
    return True, int((time.time() - t0) * 1000)


def tcp_prefilter(outbounds: list, *, timeout: float = _TCP_TIMEOUT,
                  workers: int = _TCP_WORKERS, on_done=None) -> dict:
    """
    Параллельный TCP-отсев. Возвращает {tag: (ok, latency_ms)} для
    каждого outbound'а с тегом и server/server_port.

    on_done(done, total) — опциональный колбэк прогресса, вызывается по
    мере завершения каждой пробы.
    """
    targets = []
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        tag = ob.get("tag")
        host = ob.get("server")
        port = ob.get("server_port")
        if tag and host and port:
            targets.append((tag, host, port))

    results: dict = {}
    total = len(targets)
    if not targets:
        return results

    def _job(item):
        tag, host, port = item
        ok, ms = _tcp_connect_ok(host, port, timeout)
        return tag, ok, ms

    done = 0
    with ThreadPoolExecutor(max_workers=min(workers, total)) as ex:
        futs = [ex.submit(_job, t) for t in targets]
        for fut in as_completed(futs):
            tag, ok, ms = fut.result()
            results[tag] = (ok, ms)
            done += 1
            if on_done:
                try:
                    on_done(done, total)
                except Exception:
                    pass
    return results


# ─────── phase 2: build throwaway clash_api config ───────

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def build_test_config(outbounds: list, *, clash_port: int,
                      clash_secret: str, mixed_port: int) -> dict:
    """
    Собрать одноразовый sing-box-конфиг для замеров: все кандидаты +
    selector + mixed-inbound + clash_api. Чистая функция (тестируется).
    """
    tags = [o.get("tag") for o in outbounds if isinstance(o, dict)
            and o.get("tag")]
    group = {
        "type": "selector",
        "tag": "test-select",
        "outbounds": tags or ["direct"],
        "default": tags[0] if tags else "direct",
    }
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in",
            "listen": "127.0.0.1", "listen_port": int(mixed_port),
        }],
        "outbounds": list(outbounds) + [
            group,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rules": [{"inbound": ["mixed-in"], "outbound": "test-select"}],
            "final": "direct",
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:%d" % int(clash_port),
                "secret": clash_secret,
            }
        },
    }


def parse_delay(status: int, body: str) -> dict:
    """
    Разобрать ответ Clash API `/proxies/<tag>/delay`.
    Успех: HTTP 200 + {"delay": <ms>}. Иначе — ошибка с сообщением.
    """
    try:
        data = json.loads(body) if body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    if status == 200 and isinstance(data, dict) and "delay" in data:
        try:
            return {"ok": True, "latency_ms": int(data["delay"])}
        except (TypeError, ValueError):
            return {"ok": True, "latency_ms": None}
    msg = ""
    if isinstance(data, dict):
        msg = data.get("message") or data.get("error") or ""
    return {"ok": False, "error": msg or ("HTTP %d" % status)}


# ─────── phase 2: orchestration (needs binary) ───────

def _clash_get(port: int, secret: str, path: str, timeout: float) -> tuple:
    """(status, body). Запрос к локальному Clash API."""
    url = "http://127.0.0.1:%d%s" % (port, path)
    headers = {}
    if secret:
        headers["Authorization"] = "Bearer %s" % secret
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return 0, str(e)


def _wait_clash_ready(port: int, secret: str, deadline: float) -> bool:
    while time.time() < deadline:
        status, _ = _clash_get(port, secret, "/version", timeout=1.5)
        if status == 200:
            return True
        time.sleep(0.3)
    return False


def _singbox_binary() -> str:
    try:
        from core.singbox_detector import get_singbox_detector
        info = get_singbox_detector().detect_binary()
        return (info or {}).get("path") or ""
    except Exception:
        return ""


def _e2e_delays(outbounds: list, target_url: str, timeout_ms: int,
                binary: str, on_done=None) -> dict:
    """
    Поднять одноразовый sing-box, замерить delay каждого outbound'а
    через Clash API. Возвращает {tag: {ok, latency_ms|error}}.

    on_done(done, total) — опциональный колбэк прогресса.
    """
    tags = [o.get("tag") for o in outbounds if isinstance(o, dict)
            and o.get("tag")]
    if not tags:
        return {}

    clash_port = _free_port()
    mixed_port = _free_port()
    secret = secrets.token_hex(8)
    cfg = build_test_config(outbounds, clash_port=clash_port,
                            clash_secret=secret, mixed_port=mixed_port)

    tmp_dir = tempfile.mkdtemp(prefix="zapret-proxytest-")
    cfg_path = os.path.join(tmp_dir, "test.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    out: dict = {}
    popen = None
    try:
        popen = subprocess.Popen(
            [binary, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not _wait_clash_ready(clash_port, secret,
                                 time.time() + _CLASH_BOOT_WAIT):
            log.warning("proxy_tester: clash_api не поднялся вовремя",
                        source="singbox")
            return {t: {"ok": False, "error": "движок не запустился"}
                    for t in tags}

        delay_path = "/proxies/%s/delay?timeout=%d&url=%s"
        q_target = urllib.request.quote(target_url, safe="")
        # delay-таймаут + запас на сетевой round-trip к локальному API.
        http_to = (timeout_ms / 1000.0) + 3.0

        def _job(tag):
            path = delay_path % (urllib.request.quote(tag, safe=""),
                                 timeout_ms, q_target)
            status, body = _clash_get(clash_port, secret, path, http_to)
            return tag, parse_delay(status, body)

        total = len(tags)
        done = 0
        with ThreadPoolExecutor(
                max_workers=min(_E2E_WORKERS, total)) as ex:
            futs = [ex.submit(_job, t) for t in tags]
            for fut in as_completed(futs):
                tag, res = fut.result()
                out[tag] = res
                done += 1
                if on_done:
                    try:
                        on_done(done, total)
                    except Exception:
                        pass
    finally:
        if popen is not None:
            try:
                popen.terminate()
                popen.wait(timeout=3)
            except Exception:
                try:
                    popen.kill()
                except Exception:
                    pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return out


# ─────── public API ───────

def test_outbounds(outbounds: list, *, target: str = DEFAULT_TARGET,
                   timeout_ms: int = _DEFAULT_E2E_MS,
                   tcp_prefilter_enabled: bool = True,
                   max_servers: int = _MAX_SERVERS,
                   binary: str = None, progress_cb=None) -> dict:
    """
    Протестировать список outbound'ов. Возвращает:
      {
        "ok": True,
        "target": "<url>",
        "engine_used": bool,         # была ли фаза 2 (e2e)
        "results": [
          {"tag","server","port","type","alive","latency_ms",
           "stage": "tcp"|"e2e", "error"}
        ],
        "summary": {"total","alive","dead"}
      }
    """
    obs = [o for o in (outbounds or [])
           if isinstance(o, dict) and o.get("tag")][:max_servers]
    target_url = resolve_target(target)

    if not obs:
        return {"ok": True, "target": target_url, "engine_used": False,
                "results": [], "summary": {"total": 0, "alive": 0, "dead": 0}}

    meta = {o["tag"]: o for o in obs}

    def _report(phase, done, total):
        if progress_cb:
            try:
                progress_cb(phase, done, total)
            except Exception:
                pass

    # Фаза 1 — TCP-отсев.
    if tcp_prefilter_enabled:
        _report("tcp", 0, len(obs))
        tcp = tcp_prefilter(
            obs, on_done=lambda d, t: _report("tcp", d, t))
    else:
        tcp = {o["tag"]: (True, None) for o in obs}

    survivors = [meta[t] for t, (ok, _ms) in tcp.items() if ok]

    # Фаза 2 — e2e через движок (если есть бинарь и есть кого тестить).
    bin_path = binary if binary is not None else _singbox_binary()
    e2e: dict = {}
    engine_used = False
    if bin_path and survivors:
        try:
            _report("e2e", 0, len(survivors))
            e2e = _e2e_delays(survivors, target_url, timeout_ms, bin_path,
                              on_done=lambda d, t: _report("e2e", d, t))
            engine_used = True
        except Exception as e:
            log.warning("proxy_tester e2e: %s" % e, source="singbox")
            e2e = {}

    results = []
    for ob in obs:
        tag = ob["tag"]
        tcp_ok, tcp_ms = tcp.get(tag, (False, None))
        if not tcp_ok:
            results.append({
                "tag": tag, "server": ob.get("server"),
                "port": ob.get("server_port"), "type": ob.get("type"),
                "alive": False, "latency_ms": None,
                "stage": "tcp", "error": "сервер не отвечает (TCP)",
            })
            continue
        if engine_used and tag in e2e:
            r = e2e[tag]
            results.append({
                "tag": tag, "server": ob.get("server"),
                "port": ob.get("server_port"), "type": ob.get("type"),
                "alive": bool(r.get("ok")),
                "latency_ms": r.get("latency_ms"),
                "stage": "e2e",
                "error": "" if r.get("ok") else (r.get("error") or "недоступно"),
            })
        else:
            # Только TCP (нет бинаря или фаза 2 не сработала).
            results.append({
                "tag": tag, "server": ob.get("server"),
                "port": ob.get("server_port"), "type": ob.get("type"),
                "alive": True, "latency_ms": tcp_ms,
                "stage": "tcp", "error": "",
            })

    # Сортируем: живые сначала, по возрастанию задержки.
    results.sort(key=lambda r: (
        not r["alive"],
        r["latency_ms"] if r["latency_ms"] is not None else 1 << 30,
    ))

    alive = sum(1 for r in results if r["alive"])
    return {
        "ok": True,
        "target": target_url,
        "engine_used": engine_used,
        "results": results,
        "summary": {"total": len(results), "alive": alive,
                    "dead": len(results) - alive},
    }


# ─────── async job wrapper (для UI: запустил → опрашиваешь) ───────

class _TestJob:
    """Один фоновый прогон тестирования (для длинных списков)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._result: dict = {}
        self._started_at = 0.0
        self._progress = {"phase": "", "done": 0, "total": 0}

    def running(self) -> bool:
        with self._lock:
            return self._running

    def start(self, outbounds: list, **kw) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._result = {}
            self._started_at = time.time()
            self._progress = {"phase": "tcp", "done": 0,
                              "total": len(outbounds or [])}

        def _progress_cb(phase, done, total):
            with self._lock:
                self._progress = {"phase": phase, "done": done,
                                  "total": total}

        def _run():
            try:
                res = test_outbounds(outbounds, progress_cb=_progress_cb, **kw)
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            with self._lock:
                self._result = res
                self._running = False

        threading.Thread(target=_run, name="proxy-tester",
                         daemon=True).start()
        return True

    def status(self) -> dict:
        with self._lock:
            return {
                "running": self._running,
                "result": self._result,
                "started_at": self._started_at,
                "progress": dict(self._progress),
            }


_job = _TestJob()


def get_test_job() -> _TestJob:
    return _job
