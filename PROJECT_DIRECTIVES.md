# Project Directives — zapret-gui

## Invariants & Core Conventions (CoderManual)
- Entry point: [app.py](file:///D:/netcreaze/zapret-gui/app.py) (web mode / CLI dispatch).
- No external HTTP libs: use `urllib` with timeouts (no `requests` package).
- Config: save via `get_config_manager().save()`; do NOT use `save_config()`.
- Background workers: register `reconfigure()` in `app.py` boot-hooks.
- Testability: separate I/O from pure logic; mock config manager in tests.
- Package paths: update active files AND their copies in `build/data/.../`.

## Known Pitfalls (Top 5)
1. **Wrong Go Flags:** `tg-ws-proxy-go` needs `--cfproxy-domain`/`--cfproxy-worker-domain`. `mtproxy-client` needs `--tunnel-url`/`--tunnel-secret`.
2. **Double-Tunnel Routing:** Use hostroutes (/32 & /128) via outer tunnel dev; do not use overlapping/vague `ip rule`.
3. **Teleproxy Deprecated:** Replaced by `tg-ws-proxy-go` & `tg-mtproxy-client`.
4. **Stored XSS in JS:** Do not use inline HTML event handlers. Bind dynamically.
5. **Zombie Processes:** Always call `.wait()` on spawned subprocesses.
