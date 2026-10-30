#!/usr/bin/env python3
"""
Заглушка бинарника geneva (avatarDD/geneva_c v1.0.0) для тестов.

Повторяет то, на что опирается core/geneva_manager.py: подкоманды
version / check / library / db / fw / run / evolve / eval, события JSONL
(docs/PROTOCOL.md, proto 1) и управляющий unix-сокет `run -c unix:PATH`.
Каждый вызов дописывается в файл из GENEVA_STUB_CALLS.

Поведение задаётся окружением:
  GENEVA_STUB_PROTO       версия протокола в `version --json` (1)
  GENEVA_STUB_RUN_FAIL    код выхода `run` сразу после старта
  GENEVA_STUB_BASELINE    "open" — цель не заблокирована (exit 7)
  GENEVA_STUB_GEN_DELAY   пауза на поколение, с (0.05)
  GENEVA_STUB_IGNORE_TERM 1 — `run` не выходит по SIGTERM (проверка SIGKILL)
"""

import json
import os
import signal
import socket
import sys
import threading
import time

ARGS = sys.argv[1:]

calls = os.environ.get("GENEVA_STUB_CALLS")
if calls:
    with open(calls, "a") as f:
        f.write(" ".join(ARGS) + "\n")


def opt(name, default=None):
    if name in ARGS:
        i = ARGS.index(name)
        if i + 1 < len(ARGS):
            return ARGS[i + 1]
    return default


class Events:
    def __init__(self, path):
        self.f = open(path, "a") if path else None

    def emit(self, ev, **kw):
        if not self.f:
            return
        kw = dict({"ts": time.time(), "ev": ev}, **kw)
        self.f.write(json.dumps(kw) + "\n")
        self.f.flush()


def valid(strategy):
    s = strategy.strip()
    return s.startswith("[") or s.startswith("\\/")


def canon(strategy):
    s = " ".join(strategy.split())
    return s if "\\/" in s else s + " \\/"


stop = threading.Event()


def on_term(signum, frame):
    stop.set()


def cmd_version():
    print(json.dumps({"version": "1.0.0", "proto": int(
        os.environ.get("GENEVA_STUB_PROTO", "1")), "os": "linux",
        "arch": "x86_64", "features": ["nfqueue", "nft", "iptables"]}))
    return 0


def cmd_check():
    s = ARGS[-1]
    if not valid(s) or "bogus" in s:
        print(json.dumps({"ok": False, "error": "line 1: unknown action"}))
        return 3
    print(json.dumps({"ok": True, "strategy": canon(s), "actions": 1}))
    return 0


def cmd_library():
    print(json.dumps([
        {"strategy": "\\/", "country": "china", "test": "http",
         "success": 3},
        {"strategy": "[TCP:flags:PA]-duplicate-| \\/", "country": "china",
         "test": "http", "success": 98},
        {"strategy": "[TCP:flags:S]-drop-| \\/", "country": "iran",
         "test": "https", "success": 50},
    ]))
    return 0


def cmd_db():
    path = opt("--db")
    try:
        with open(path) as f:
            sys.stdout.write(f.read())
    except OSError:
        return 6
    return 0


def serve_control(path, ev, state):
    try:
        os.unlink(path)
    except OSError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        with conn:
            buf = b""
            conn.settimeout(1.0)
            try:
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                continue
            try:
                req = json.loads(buf.split(b"\n", 1)[0].decode())
            except ValueError:
                continue
            ans = handle(req, ev, state)
            ans["id"] = req.get("id")
            conn.sendall((json.dumps(ans) + "\n").encode())
    srv.close()
    try:
        os.unlink(path)
    except OSError:
        pass


def handle(req, ev, state):
    cmd = req.get("cmd")
    if cmd == "status":
        return {"ok": True, "state": state["state"], "firewall": "iptables",
                "uptime_ms": int((time.time() - state["t0"]) * 1000),
                "strategy": state["strategy"]}
    if cmd == "stats":
        return {"ok": True, "pkts_out": 120, "pkts_in": 80, "triggered": 7,
                "modified": 7, "dropped": 0, "injected": 7,
                "send_errors": 0, "out_trees": [
                    {"tree": state["strategy"].split(" \\/")[0],
                     "fired": 7}], "in_trees": []}
    if cmd == "set_strategy":
        s = req.get("strategy", "")
        if not valid(s):
            return {"ok": False, "error": "parse error"}
        state["strategy"] = canon(s)
        ev.emit("strategy", strategy=state["strategy"])
        return {"ok": True}
    if cmd in ("pause", "resume"):
        state["state"] = "paused" if cmd == "pause" else "running"
        ev.emit("state", state=state["state"])
        return {"ok": True, "state": state["state"]}
    if cmd == "stop":
        stop.set()
        return {"ok": True}
    return {"ok": False, "error": "unknown command"}


def cmd_run():
    ev = Events(opt("-e"))
    with open(opt("-f")) as f:
        strategy = f.read().strip()
    ev.emit("start", mode="run", proto=1, pid=os.getpid(),
            queue=int(opt("-q", "310")), ports=opt("-p"))
    fail = os.environ.get("GENEVA_STUB_RUN_FAIL")
    if fail:
        ev.emit("error", where="nfqueue", message="no NFQUEUE support")
        ev.emit("exit", code=int(fail), reason="error")
        return int(fail)
    if os.environ.get("GENEVA_STUB_IGNORE_TERM") != "1":
        signal.signal(signal.SIGTERM, on_term)
    else:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    state = {"state": "running", "t0": time.time(), "strategy": strategy}
    ctl = opt("-c", "")
    t = None
    if ctl.startswith("unix:"):
        t = threading.Thread(target=serve_control,
                             args=(ctl[5:], ev, state), daemon=True)
        t.start()
    ev.emit("strategy", strategy=strategy)
    ev.emit("ready", firewall="iptables")
    while not stop.wait(0.1):
        pass
    if t:
        t.join(2)
    ev.emit("exit", code=0, reason="signal")
    return 0


def cmd_evolve():
    signal.signal(signal.SIGTERM, on_term)
    ev = Events(opt("-e"))
    gens = int(opt("--generations", "3"))
    ckpt = opt("--checkpoint")
    db = opt("--db")
    target = opt("--target", "")
    delay = float(os.environ.get("GENEVA_STUB_GEN_DELAY", "0.05"))
    gen = 0
    resume = "--resume" in ARGS
    if resume:
        with open(ckpt) as f:
            gen = json.load(f)["gen"]
    ev.emit("start", mode="evolve", proto=1, pid=os.getpid(),
            population=int(opt("--population", "4")), generations=gens,
            target=target, resume=resume)
    if not resume:
        if os.environ.get("GENEVA_STUB_BASELINE") == "open":
            ev.emit("baseline", blocked=False, outcome="ok")
            ev.emit("exit", code=7, reason="not_blocked")
            return 7
        ev.emit("baseline", blocked=True, outcome="reset")
    best = "[TCP:flags:PA]-duplicate-| \\/"
    while gen < gens:
        with open(ckpt + ".tmp", "w") as f:
            json.dump({"gen": gen}, f)
        os.replace(ckpt + ".tmp", ckpt)
        if stop.is_set():
            ev.emit("exit", code=0, reason="signal")
            return 0
        ev.emit("eval", strategy=best, fitness=380, outcome="ok")
        ev.emit("eval", strategy="[TCP:flags:S]-drop-| \\/", fitness=-400,
                outcome="reset")
        ev.emit("generation", gen=gen, best_fitness=380, avg_fitness=-10,
                unique=4, best=best)
        time.sleep(delay)
        gen += 1
    if db:
        with open(db, "a") as f:
            f.write(json.dumps({"s": best, "t": target, "runs": 2, "ok": 2,
                                "fit_sum": 760, "fit_best": 380}) + "\n")
    ev.emit("result", best=[{"strategy": best, "avg_fitness": 380,
                             "runs": 2}])
    ev.emit("exit", code=0, reason="done")
    return 0


def cmd_eval():
    ev = Events(opt("-e"))
    with open(opt("-f")) as f:
        items = [line.strip() for line in f if line.strip()]
    ev.emit("start", mode="eval", proto=1, pid=os.getpid())
    for i, s in enumerate(items):
        ok = i == 0
        ev.emit("eval", strategy=s, fitness=380 if ok else -400,
                outcome="ok" if ok else "reset", runs=1)
    ev.emit("exit", code=0, reason="done")
    return 0


def main():
    if not ARGS:
        return 2
    sub = ARGS[0]
    if sub == "version":
        return cmd_version()
    if sub == "check":
        return cmd_check()
    if sub == "library":
        return cmd_library()
    if sub == "db":
        return cmd_db()
    if sub == "fw":
        return 0
    if sub == "run":
        return cmd_run()
    if sub == "evolve":
        return cmd_evolve()
    if sub == "eval":
        return cmd_eval()
    return 2


if __name__ == "__main__":
    sys.exit(main())
