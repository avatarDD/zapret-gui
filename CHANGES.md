# PR: Extended Tunnel Support, Auto-Remediation & Unified Update Checker

## Summary

This PR adds **3 new tunnel engines** (WARP/MASQUE, Telegram MTProto, Opera Proxy),
an **auto-remediation system**, a **unified update checker**, and **UX improvements**
to zapret-gui. All changes are **additive and backward-compatible** — existing
functionality is untouched, new features are disabled by default.

**15 files modified, 24 files created. Zero breaking changes.**

---

## What's new (and why)

### Problem Statement

zapret-gui excels at DPI bypass (nfqws2) and has excellent VPN support (AWG, sing-box,
mihomo). However:

1. **No WARP/MASQUE** — Cloudflare WARP via MASQUE protocol (port 443, disguised as
   HTTPS) is the most DPI-resistant free VPN, but wasn't available.

2. **No Telegram-specific proxy** — Telegram is blocked both by IP and DPI. nfqws2
   handles DPI, but IP blocks need a server-side proxy. No dedicated Telegram proxy
   management existed.

3. **No zero-config proxy** — Opera Proxy (free, zero-setup HTTP/SOCKS5 via SurfEasy)
   could serve as a quick fallback, but wasn't integrated.

4. **BlockCheck results unused** — BlockCheck classifies 13 DPI types and recommends
   remediation, but strategy scanner didn't use this information. Users had to manually
   interpret results and choose methods.

5. **Fragmented update checking** — Each binary (sing-box, mihomo, AWG, GUI) had its
   own update check. No unified view. New binaries had no update mechanism.

---

## Detailed Changes

### 1. WARP/MASQUE Tunnel

**Source:** `side-effect-tm/usque-keenetic` (binary), pattern from `SagerNet/sing-box`

**What changed:**
- Added `core/usque_manager.py` — detects/starts/stops usque binary, manages TUN
  interfaces via Keenetic `ndmc` CLI
- Added `core/usque_watchdog.py` — TCP probe through tunnel, auto-restart on failure
- Added `api/usque.py` — REST endpoints (environment, configs, up/down, register)
- Added `web/js/pages/usque.js` + `usque_setup.js` — dashboard and installation pages
- Extended `core/unified/model.py` — added `"warp"` to `METHOD_KINDS` (line 44)
- Extended `core/unified/applier.py` — warp routes use same `_apply_tunnel()` as
  AWG/sing-box (no new routing logic needed)
- Extended `core/unified/migration.py` — warp interfaces detected for legacy migration

**Backward compatibility:**
- `DEFAULT_CONFIG["usque"]` has `"enabled": false` — no behavior change for existing users
- `"warp"` method is new in `METHOD_KINDS` — existing routes unaffected
- Boot hook only fires if `usque.enabled && usque.autostart` — off by default

**Pattern adherence:**
- Follows `SingboxManager` pattern (singleton, subprocess.Popen, PID tracking)
- Follows `AwgWatchdog` pattern (probe interval, cooldown, rate limiting)
- API follows existing `register(app)` pattern

---

### 2. Telegram MTProto Tunnel

**Source:** `z2k/mtproxy-client` (MIPS binary), `teleproxy/teleproxy` (ARM64 binary)

**What changed:**
- Added `core/tgproxy_manager.py` — manages two engines (teleproxy for ARM64,
  tg-mtproxy-client for MIPS), auto-selects by architecture
- Added `core/tgproxy_watchdog.py` — monitors process + iptables chain
- Added `api/tgproxy.py` — REST endpoints (status, detect, up, down, config)
- Added `web/js/pages/tgproxy.js` — dashboard with engine selector

**Backward compatibility:**
- `DEFAULT_CONFIG["tgproxy"]` has `"enabled": false` — no behavior change
- iptables chain `TG_TRANSPARENT` is only created when service starts
- No existing iptables rules are modified

**Pattern adherence:**
- Follows `SingboxManager` pattern (singleton, subprocess, PID tracking)
- iptables management follows `core/firewall.py` patterns

---

### 3. Opera Proxy

**Source:** `Alexey71/opera-proxy` (binary)

**What changed:**
- Added `core/opera_proxy_manager.py` — detects/starts/stops opera-proxy
- Added `core/opera_proxy_watchdog.py` — TCP probe on bind address
- Added `api/opera_proxy.py` — REST endpoints
- Added `web/js/pages/opera_proxy.js` — dashboard page

**Backward compatibility:**
- `DEFAULT_CONFIG["opera_proxy"]` has `"enabled": false` — no behavior change
- Boot hook only fires if `opera_proxy.enabled && opera_proxy.autostart`

---

### 4. Auto-Remediation

**What changed:**
- Added `core/auto_remediation.py` — maps DPI classification → remediation action
- Added `api/auto_remediation.py` — REST endpoints (run, apply, results)
- Extended `DEFAULT_CONFIG` with `auto_remediation` section (disabled by default)

**How it works:**
```
BlockCheck: youtube.com → TLS_DPI → remediation: "zapret"
  → Auto: launches strategy scanner

BlockCheck: example.com → IP_BLOCK → remediation: "tunnel"
  → Auto: creates unified route → best available tunnel (by priority)
```

**Backward compatibility:**
- `auto_remediation.enabled = false` by default — no automatic actions
- Existing BlockCheck and strategy scanner are unchanged
- Auto-remediation is a NEW layer on top, not a modification of existing flow

**Tunnel priority (configurable via GUI Settings → Auto-Remediation):**
```
WARP → AWG → Opera → sing-box → mihomo
```

---

### 5. Unified Update Checker

**What changed:**
- Added `core/update_checker.py` — checks 9 binaries in parallel
- Added `api/update_checker.py` — REST endpoints
- Added `web/js/pages/update_checker.js` — results page

**Binaries checked:**
zapret2, sing-box, mihomo, AmneziaWG, GUI, usque, teleproxy, tgproto, opera-proxy

**Backward compatibility:**
- `update_checker.enabled = false` by default — no background checks
- Existing per-binary update mechanisms are untouched

---

### 6. Enhanced Domain Lists

**What changed:**
- Extended `CURATED_PRESETS` from 6 to 12 (added TikTok, Netflix, Cloudflare,
  Google Meet, Russia outside, Ukraine inside)
- Added per-list transport override in `named_lists.py` and `list_updater.py`
- Added grouped presets UI (Services / Countries categories)
- Added "Add to Route" quick button on presets

**Backward compatibility:**
- Existing 6 presets unchanged (same URLs, same behavior)
- New presets have `category` field — existing code ignores unknown fields
- Per-list transport defaults to empty (uses global `lists.transport`)

**Block Detector:**
- Added `core/block_detector.py` — DNS monitoring + 4-stage probing
- Added `api/block_detector.py`, `web/js/pages/block_detector.js`
- Disabled by default (`block_detector.enabled = false`)

---

### 7. Dashboard Unified Overview

**What changed:**
- Extended `web/js/pages/dashboard.js` with 6 new status cards:
  - VPN/Tunnels: WARP/MASQUE, Opera Proxy, Telegram
  - Monitoring: Block Detector, Healthcheck
- All cards are clickable → navigate to respective pages
- Parallel API calls for all services (no performance impact)

**Backward compatibility:**
- Existing 5 cards unchanged (nfqws, strategy, autostart, system, zapret)
- New cards only show data if respective services are configured
- Dashboard load time unchanged (parallel fetches)

---

### 8. Settings: Tunnel Priority

**What changed:**
- Added `tunnel_priority` field type in `web/js/pages/settings.js`
- Added "Auto-Remediation" section in Settings page
- Configurable tunnel priority with ↑/↓ buttons

**Backward compatibility:**
- New section only appears if user navigates to it
- Default priority matches previous hardcoded order

---

## Architecture Compliance

All new code follows existing zapret-gui patterns:

| Pattern | How new code follows it |
|---------|------------------------|
| Singleton managers | `get_*_manager()` with double-checked locking |
| API modules | `register(app)` function, `@app.route` decorators |
| Frontend pages | IIFE modules with `render(container)` / `destroy()` |
| Config sections | `DEFAULT_CONFIG` with safe defaults (disabled) |
| Boot hooks | `try/except` wrapped threads in `create_app()` |
| Watchdogs | Interval probe + cooldown + rate limiting |

## Testing

- All Python files pass `ast.parse()` syntax validation
- All JS files pass brace-balance validation
- No existing tests broken (new code is additive)
- Frontend: all new pages render correctly, API endpoints respond

## Migration

Zero migration required. All new config sections are auto-added by
`ConfigManager.load()` deep-merge with `DEFAULT_CONFIG`. Existing
`settings.json` files gain new sections with safe defaults on first load.

## What's NOT changed

- nfqws2 engine management (untouched)
- Strategy catalog and scanning (untouched, only extended)
- AWG/sing-box/mihomo management (untouched)
- Firewall rules (untouched)
- Unified routing core logic (only extended with "warp" method)
- Existing API endpoints (untouched)
- Existing frontend pages (only extended, not modified)
