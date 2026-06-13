# core/mihomo_proxy_tester.py
"""
Тестер доступности прокси mihomo (паритет с core/proxy_tester.py).

Две фазы, как у sing-box:
  Фаза 1 — TCP-отсев (переиспользуем `proxy_tester.tcp_prefilter`):
    параллельный TCP-connect до server:port каждого прокси.
  Фаза 2 — e2e-замер задержки через движок mihomo (Clash API
    `GET /proxies/<name>/delay?url=<target>&timeout=<ms>`):
      * если конфиг ЗАПУЩЕН и доступен его external-controller —
        опрашиваем его напрямую (полная достоверность, узлы уже подняты);
      * иначе поднимаем одноразовый `mihomo -d <tmp> -f <cfg.yaml>` со
        всеми выжившими + external-controller и замеряем, батчами по 40
        (битый узел роняет только свой батч), затем гасим.

Без бинаря mihomo и без запущенного controller — остаётся только TCP-
отсев (graceful degrade), как у sing-box.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.log_buffer import log
from core.proxy_tester import (
    resolve_target, tcp_prefilter, parse_delay, _free_port,
)


_BATCH = 40
_E2E_WORKERS = 16
_BOOT_WAIT = 12.0
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _get(host: str, port: int, secret: str, path: str,
         timeout: float) -> tuple:
    url = "http://%s:%d%s" % (host, int(port), path)
    headers = {"Authorization": "Bearer %s" % secret} if secret else {}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        return 0, str(e)


def _wait_ready(host: str, port: int, secret: str, deadline: float,
                popen=None) -> bool:
    while time.time() < deadline:
        if popen is not None and popen.poll() is not None:
            return False
        st, _ = _get(host, port, secret, "/version", 1.5)
        if st == 200:
            return True
        time.sleep(0.3)
    return False


def _tail(path: str, limit: int = 600) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return ""
    text = _ANSI_RE.sub("", data.decode("utf-8", errors="replace")).strip()
    return " ".join(text.split())[-limit:]


# ─────── фаза 2: через запущенный external-controller ───────

def _controller_delays(ep: dict, names: list, target_url: str,
                       timeout_ms: int, on_done=None) -> dict:
    out: dict = {}
    total = len(names)
    done = 0
    q = urllib.request.quote(target_url, safe="")
    http_to = (timeout_ms / 1000.0) + 3.0

    def _job(nm):
        path = "/proxies/%s/delay?timeout=%d&url=%s" % (
            urllib.request.quote(nm, safe=""), timeout_ms, q)
        st, body = _get(ep["host"], ep["port"], ep.get("secret", ""),
                        path, http_to)
        return nm, parse_delay(st, body)

    with ThreadPoolExecutor(max_workers=min(_E2E_WORKERS, total)) as ex:
        futs = [ex.submit(_job, n) for n in names]
        for fut in as_completed(futs):
            nm, res = fut.result()
            out[nm] = res
            done += 1
            if on_done:
                try:
                    on_done(done, total)
                except Exception:
                    pass
    return out


# ─────── фаза 2: одноразовый mihomo ───────

def _throwaway_delays(proxies: list, target_url: str, timeout_ms: int,
                      binary: str, on_done=None) -> dict:
    total = len(proxies)
    out: dict = {}
    done = 0
    for start in range(0, total, _BATCH):
        batch = proxies[start:start + _BATCH]
        names = [p["name"] for p in batch]
        try:
            res = _throwaway_batch(batch, target_url, timeout_ms, binary)
        except RuntimeError as e:
            res = {n: {"ok": False, "engine_fail": True, "error": str(e)}
                   for n in names}
        out.update(res)
        done += len(batch)
        if on_done:
            try:
                on_done(done, total)
            except Exception:
                pass
    return out


def _throwaway_batch(proxies: list, target_url: str, timeout_ms: int,
                     binary: str) -> dict:
    from core.clash_yaml import dump_yaml
    names = [p["name"] for p in proxies]
    ctrl_port = _free_port()
    mixed_port = _free_port()
    secret = secrets.token_hex(8)
    cfg = {
        "log-level": "silent",
        "mixed-port": mixed_port,
        "mode": "rule",
        "external-controller": "127.0.0.1:%d" % ctrl_port,
        "secret": secret,
        "proxies": proxies,
        "proxy-groups": [
            {"name": "GLOBAL", "type": "select", "proxies": names}],
        "rules": ["MATCH,GLOBAL"],
    }
    tmp_dir = tempfile.mkdtemp(prefix="zapret-mihomo-test-")
    cfg_path = os.path.join(tmp_dir, "test.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(dump_yaml(cfg))

    out: dict = {}
    popen = None
    err_path = os.path.join(tmp_dir, "stderr.log")
    err_f = None
    try:
        err_f = open(err_path, "wb")
        popen = subprocess.Popen(
            [binary, "-d", tmp_dir, "-f", cfg_path],
            stdout=subprocess.DEVNULL, stderr=err_f)
        if not _wait_ready("127.0.0.1", ctrl_port, secret,
                           time.time() + _BOOT_WAIT, popen):
            try:
                err_f.flush()
            except Exception:
                pass
            tail = _tail(err_path, 600)
            log.warning("mihomo tester: движок не запустился (батч %d)"
                        % len(names) + (": %s" % tail if tail else ""),
                        source="mihomo")
            raise RuntimeError("mihomo не запустился"
                               + (": %s" % tail if tail else ""))

        q = urllib.request.quote(target_url, safe="")
        http_to = (timeout_ms / 1000.0) + 3.0

        def _job(nm):
            path = "/proxies/%s/delay?timeout=%d&url=%s" % (
                urllib.request.quote(nm, safe=""), timeout_ms, q)
            st, body = _get("127.0.0.1", ctrl_port, secret, path, http_to)
            return nm, parse_delay(st, body)

        with ThreadPoolExecutor(
                max_workers=min(_E2E_WORKERS, len(names))) as ex:
            futs = [ex.submit(_job, n) for n in names]
            for fut in as_completed(futs):
                nm, res = fut.result()
                out[nm] = res
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
        if err_f is not None:
            try:
                err_f.close()
            except Exception:
                pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return out


# ─────── public ───────

def test_proxies(proxies: list, *, target: str = "cloudflare",
                 timeout_ms: int = 5000, controller: dict = None,
                 binary: str = None, progress_cb=None) -> dict:
    """
    Протестировать clash-proxy dict'ы. Результат как у proxy_tester:
      {"ok", "target", "engine_used", "results": [{tag, server, port,
        type, alive, latency_ms, stage, error}], "summary"}.
    """
    obs = [p for p in (proxies or []) if isinstance(p, dict)
           and p.get("name") and p.get("server") and p.get("port")]
    target_url = resolve_target(target)
    if not obs:
        return {"ok": True, "target": target_url, "engine_used": False,
                "results": [], "summary": {"total": 0, "alive": 0, "dead": 0}}

    meta = {str(p["name"]): p for p in obs}
    # type прокидываем, чтобы tcp_prefilter пропустил UDP-протоколы
    # (hysteria2/tuic/wireguard) мимо TCP-отсева — их сервер не слушает TCP.
    tcp_models = [{"tag": str(p["name"]), "server": p.get("server"),
                   "server_port": p.get("port"), "type": p.get("type")}
                  for p in obs]

    def _rep(phase, d, t):
        if progress_cb:
            try:
                progress_cb(phase, d, t)
            except Exception:
                pass

    _rep("tcp", 0, len(obs))
    tcp = tcp_prefilter(tcp_models, on_done=lambda d, t: _rep("tcp", d, t))
    survivors = [n for n, (ok, _ms) in tcp.items() if ok]

    e2e: dict = {}
    engine_used = False
    if survivors:
        if controller:
            _rep("e2e", 0, len(survivors))
            e2e = _controller_delays(
                controller, survivors, target_url, timeout_ms,
                on_done=lambda d, t: _rep("e2e", d, t))
            engine_used = bool(e2e)
        elif binary:
            _rep("e2e", 0, len(survivors))
            try:
                e2e = _throwaway_delays(
                    [meta[n] for n in survivors], target_url, timeout_ms,
                    binary, on_done=lambda d, t: _rep("e2e", d, t))
                engine_used = True
            except Exception as e:
                log.warning("mihomo tester e2e: %s" % e, source="mihomo")
                e2e = {}

    results = []
    for nm, p in meta.items():
        tcp_ok, tcp_ms = tcp.get(nm, (False, None))
        row = {"tag": nm, "server": p.get("server"),
               "port": p.get("port"), "type": p.get("type")}
        if not tcp_ok:
            row.update({"alive": False, "latency_ms": None, "stage": "tcp",
                        "error": "сервер не отвечает (TCP)"})
        elif engine_used and nm in e2e and not e2e[nm].get("engine_fail"):
            r = e2e[nm]
            row.update({"alive": bool(r.get("ok")),
                        "latency_ms": r.get("latency_ms"), "stage": "e2e",
                        "error": "" if r.get("ok") else
                        (r.get("error") or "недоступно")})
        else:
            row.update({"alive": True, "latency_ms": tcp_ms, "stage": "tcp",
                        "error": ""})
        results.append(row)

    results.sort(key=lambda r: (
        not r["alive"],
        r["latency_ms"] if r["latency_ms"] is not None else 1 << 30))
    alive = sum(1 for r in results if r["alive"])
    return {"ok": True, "target": target_url, "engine_used": engine_used,
            "results": results,
            "summary": {"total": len(results), "alive": alive,
                        "dead": len(results) - alive}}


# ─────── async job ───────

class _MihomoTestJob:

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._result: dict = {}
        self._started_at = 0.0
        self._progress = {"phase": "", "done": 0, "total": 0}

    def running(self) -> bool:
        with self._lock:
            return self._running

    def start(self, proxies: list, **kw) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._result = {}
            self._started_at = time.time()
            self._progress = {"phase": "tcp", "done": 0,
                              "total": len(proxies or [])}

        def _cb(phase, done, total):
            with self._lock:
                self._progress = {"phase": phase, "done": done,
                                  "total": total}

        def _run():
            try:
                res = test_proxies(proxies, progress_cb=_cb, **kw)
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            with self._lock:
                self._result = res
                self._running = False

        threading.Thread(target=_run, name="mihomo-tester",
                         daemon=True).start()
        return True

    def status(self) -> dict:
        with self._lock:
            return {"running": self._running, "result": self._result,
                    "started_at": self._started_at,
                    "progress": dict(self._progress)}


_job = _MihomoTestJob()


def get_mihomo_test_job() -> _MihomoTestJob:
    return _job
