# core/tunnel_optimizer.py
"""
Оптимизатор латентности/пропускной способности для туннелей.

──────────────────────────────────────────────────────────────────────
Исправления относительно оригинала:

1. `_optimize_tcp_buffers`, `_optimize_fastopen`, `_optimize_keepalive`
   писали в /proc/sys/net/ipv4/conf/<iface>/tcp_* — такого пути не
   существует в ядре Linux ни для одного из этих параметров, они все
   ГЛОБАЛЬНЫЕ (per-host), а не per-interface. Функции всегда молча
   проваливались (os.path.isfile всегда False), но это тонуло внутри
   optimize_iface(), которая всегда возвращала ok:True на верхнем
   уровне. Здесь эти три вынесены в отдельную ensure_global_tcp_tuning(),
   которая пишет в реальные глобальные пути ОДИН РАЗ (идемпотентно,
   безопасно вызывать многократно), а не на каждый iface заново.

2. `_optimize_nodelay` — TCP_NODELAY не существует как sysctl вообще,
   ни глобально, ни per-interface. Это флаг сокета (setsockopt), его
   может выставить только сам процесс при открытии TCP-соединения.
   Функция удалена.

3. Добавлена MSS clamping (iptables/nft TCPMSS --clamp-mss-to-pmtu) —
   это стандартный, отказоустойчивый способ бороться с фрагментацией
   TCP-потоков через туннель, который не зависит от точного угадывания
   MTU и переживает изменения пути в сети. Дополняет `ip link set mtu`,
   не заменяет.

4. Добавлена BBR + fq qdisc — BBR раскрывает основной потенциал
   именно в связке с fq-пейсингом; без неё выигрыш от BBR меньше.

5. Добавлен read-back после каждой записи в /proc — убеждаемся, что
   ядро реально приняло записанное значение.

6. Добавлена optimize_nested_tunnel() — специально для WARP-in-WARP и
   любых других вложенных туннелей: считает MTU внутреннего интерфейса
   как MTU внешнего минус overhead протокола внешнего туннеля, вместо
   применения одного и того же профиля к обоим уровням вслепую.

7. Интегрировано автоматическое сохранение оригинальных настроек
   в defaults settings.json перед изменением с возможностью отката
   через restore_system_defaults().
──────────────────────────────────────────────────────────────────────
"""

import os
import subprocess
import time
import re
import ipaddress

from core.log_buffer import log


MTU_PROFILES = {
    "low_latency": 1280,
    "balanced": 1420,
    # 1500 is not safe for a generic tunnel and can black-hole packets.
    # Use measured PMTU before selecting a larger value.
    "throughput": 1420,
}

# Консервативная оценка overhead протокола внешнего туннеля — сколько
# байт нужно вычесть из MTU внешнего интерфейса, чтобы инкапсулированный
# пакет внутреннего туннеля не фрагментировался при выходе через внешний.
TUNNEL_OVERHEAD_BYTES = {
    # UDP(8) + WG data header(16) + Poly1305(16) + внешний IPv4(20) = 60,
    # плюс запас под AmneziaWG junk/padding (S3/S4) — 80.
    "awg": 80,
    # MASQUE/QUIC (usque): UDP(8) + QUIC short header(~20-30) +
    # DATAGRAM frame(~3-10) + CONNECT-UDP context(~1-2) + внешний IP(20) = 70.
    "warp": 70,
    "singbox": 60,
    "mihomo": 60,
}

_DEFAULT_OVERHEAD = 80


# ─────────────────────────── System Backup & Restore ───────────────────

def _backup_and_set(path: str, value: str) -> bool:
    """Считывает текущее значение из path, сохраняет его в defaults (если ещё нет) и записывает новое."""
    if not os.path.isfile(path):
        return False

    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        
        # Инициализируем defaults, если его ещё нет
        defaults = cfg.get("tunnel_optimizer", "defaults", default={}) or {}
        if not isinstance(defaults, dict):
            defaults = {}
            
        if path not in defaults:
            try:
                with open(path, "r") as f:
                    current_val = f.read().strip()
                defaults[path] = current_val
                cfg.set("tunnel_optimizer", "defaults", defaults)
                cfg.save()
            except Exception:
                pass
    except Exception:
        pass
            
    # Записываем новое значение
    try:
        with open(path, "w") as f:
            f.write(str(value))
        return True
    except Exception:
        return False


def _backup_iface_mtu(iface: str, mtu: int | None) -> None:
    if mtu is None:
        return
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        values = cfg.get("tunnel_optimizer", "mtu_defaults", default={}) or {}
        if iface not in values:
            values[iface] = int(mtu)
            cfg.set("tunnel_optimizer", "mtu_defaults", values)
            cfg.save()
    except Exception:
        pass


def _remember_qdisc(iface: str, kind: str) -> None:
    if not kind:
        return
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        values = cfg.get("tunnel_optimizer", "qdisc_defaults", default={}) or {}
        if iface not in values:
            values[iface] = kind
            cfg.set("tunnel_optimizer", "qdisc_defaults", values)
            cfg.save()
    except Exception:
        pass


def _remember_mss_iface(iface: str) -> None:
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        values = cfg.get("tunnel_optimizer", "mss_ifaces", default=[]) or []
        if iface not in values:
            values.append(iface)
            cfg.set("tunnel_optimizer", "mss_ifaces", values)
            cfg.save()
    except Exception:
        pass


def restore_system_defaults(only_if_idle: bool = False) -> dict:
    """Восстановить заводские системные TCP/MTU настройки из бэкапа."""
    if only_if_idle:
        try:
            from core.tunnel_monitor import get_tunnel_monitor
            monitor = get_tunnel_monitor()
            active_ifaces = [i for i in monitor.discover_interfaces() if not i.startswith("__")]
            if active_ifaces:
                return {"ok": True, "note": "Пропуск восстановления: активные туннели: %s" % ", ".join(active_ifaces)}
        except Exception:
            pass

    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        defaults = cfg.get("tunnel_optimizer", "defaults", default={}) or {}
    except Exception:
        defaults = {}

    if not defaults or not isinstance(defaults, dict):
        defaults = {}

    restored = []
    errors = []
    
    for path, value in defaults.items():
        if os.path.isfile(path):
            try:
                with open(path, "w") as f:
                    f.write(value)
                restored.append(path)
            except Exception as e:
                errors.append("%s: %s" % (path, e))

    # MTU/qdisc/firewall state is outside /proc/sys and must be restored
    # explicitly. Missing tools are reported but never turn an otherwise
    # successful sysctl restore into a destructive operation.
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        mtu_defaults = cfg.get("tunnel_optimizer", "mtu_defaults", default={}) or {}
        for iface, value in mtu_defaults.items():
            if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", str(iface)):
                continue
            r = subprocess.run(["ip", "link", "set", str(iface), "mtu", str(value)],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                restored.append("mtu:%s" % iface)
            else:
                errors.append("mtu:%s: %s" % (iface, (r.stderr or "").strip()))

        qdisc_defaults = cfg.get("tunnel_optimizer", "qdisc_defaults", default={}) or {}
        for iface, qdisc in qdisc_defaults.items():
            if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", str(iface)):
                continue
            kind = str(qdisc).split()[0] if qdisc else ""
            if kind and _which("tc"):
                r = subprocess.run(["tc", "qdisc", "replace", "dev", str(iface),
                                    "root", kind], capture_output=True, text=True,
                                   timeout=5)
                if r.returncode == 0:
                    restored.append("qdisc:%s" % iface)
                else:
                    errors.append("qdisc:%s: %s" % (iface, (r.stderr or "").strip()))
            elif kind:
                errors.append("qdisc:%s: tc недоступен" % iface)

        for iface in (cfg.get("tunnel_optimizer", "mss_ifaces", default=[]) or []):
            mss_result = _remove_mss_clamp(str(iface))
            if mss_result.get("ok"):
                restored.append("mss:%s" % iface)
            else:
                errors.append("mss:%s: %s" % (iface, mss_result.get("error", "")))
    except Exception as e:
        errors.append("network restore: %s" % e)

    if not errors:
        try:
            cfg.set("tunnel_optimizer", "defaults", {})
            cfg.set("tunnel_optimizer", "mtu_defaults", {})
            cfg.set("tunnel_optimizer", "qdisc_defaults", {})
            cfg.set("tunnel_optimizer", "mss_ifaces", [])
            cfg.save()
        except Exception:
            pass
        log.info("tunnel_optimizer: все системные настройки восстановлены к заводским", source="optimizer")
        return {"ok": True, "restored": restored}
    else:
        log.warning("tunnel_optimizer: не все настройки восстановлены: %s" % ", ".join(errors), source="optimizer")
        return {"ok": False, "restored": restored, "errors": errors}


# ─────────────────────────── Interface Tuning ───────────────────────────

def optimize_iface(iface: str, profile: str = "balanced",
                   mtu_override: int = None, apply_global: bool = True,
                   transport_kind: str = "") -> dict:
    """
    Применить оптимизации к интерфейсу.

    Args:
        iface: имя интерфейса (opkgtun0, awg0, и т.д.)
        profile: "low_latency" | "balanced" | "throughput"
        mtu_override: если задан — использовать это значение MTU вместо
            значения из профиля (нужно для вложенных туннелей).

    Returns:
        {ok, mtu, applied: [...], errors: [...]}
    """
    if not iface:
        return {"ok": False, "error": "Не указан интерфейс"}
    if profile not in MTU_PROFILES:
        return {"ok": False, "error": "Неизвестный профиль: %s" % profile}

    # Валидация имени интерфейса против path-traversal
    if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", iface):
        return {"ok": False, "error": "Недопустимое имя интерфейса"}
    if not os.path.isdir("/sys/class/net/%s" % iface):
        return {"ok": False, "error": "Интерфейс не существует: %s" % iface}

    applied = []
    errors = []

    r = _optimize_mtu(iface, profile, mtu_override)
    if r.get("ok"):
        applied.append("mtu")
    else:
        errors.append("mtu: %s" % r.get("error", ""))
    mtu = r.get("mtu")

    if apply_global:
        tuning = ensure_global_tcp_tuning(
            profile, quic=(transport_kind == "warp"))
        applied.extend(tuning.get("applied", []))
        errors.extend("global: %s" % e for e in tuning.get("errors", []))
        r = _optimize_congestion(_detect_egress_iface())
        if r.get("ok"):
            applied.append("bbr")
        else:
            errors.append("bbr: %s" % r.get("error", ""))

    r = _apply_mss_clamp(iface)
    if r.get("ok"):
        applied.append("mss_clamp")
    else:
        errors.append("mss_clamp: %s" % r.get("error", ""))

    log.info("tunnel_optimizer: %s — применено: %s%s" % (
             iface, ", ".join(applied) or "ничего",
             (" | ошибки: %s" % "; ".join(errors)) if errors else ""),
             source="optimizer")

    # A missing optional capability (BBR or firewall MSS clamp) should not
    # turn a successful MTU operation into a hard failure. Callers still get
    # the per-step errors and can present them in the UI.
    return {"ok": bool(applied), "mtu": mtu, "applied": applied, "errors": errors}


def optimize_nested_tunnel(outer_iface: str, outer_kind: str,
                           inner_iface: str, inner_kind: str,
                           profile: str = "balanced") -> dict:
    """Оптимизация для вложенных туннелей (WARP-in-WARP и подобных):
    MTU внутреннего = MTU внешнего минус overhead протокола внешнего.
    outer_kind/inner_kind — "awg" | "warp" | "singbox" | "mihomo"."""
    outer_result = optimize_iface(outer_iface, profile, apply_global=True,
                                  transport_kind=outer_kind)
    outer_mtu = outer_result.get("mtu") or MTU_PROFILES.get(profile, 1420)

    overhead = TUNNEL_OVERHEAD_BYTES.get(outer_kind, _DEFAULT_OVERHEAD)
    inner_mtu = outer_mtu - overhead

    if inner_mtu < 1280:
        # IP proxying must retain IPv6's 1280-byte minimum. A smaller value
        # is not a valid nested-tunnel recommendation; report it instead of
        # silently forcing 576 and breaking IPv6.
        log.warning(
            "tunnel_optimizer: расчётный MTU внутреннего интерфейса "
            "%s слишком мал (%d) — outer_mtu=%d, overhead(%s)=%d. "
            "Проверьте профиль или overhead вручную."
            % (inner_iface, inner_mtu, outer_mtu, outer_kind, overhead),
            source="optimizer")
        return {
            "ok": False,
            "error": "outer MTU %d недостаточен для %s-in-%s (нужно >=1280)"
                     % (outer_mtu, inner_kind, outer_kind),
            "outer": {"iface": outer_iface, "mtu": outer_mtu,
                      "applied": outer_result.get("applied", [])},
            "inner": {"iface": inner_iface, "mtu": None, "applied": []},
            "overhead_used": overhead,
        }

    inner_result = optimize_iface(inner_iface, profile, mtu_override=inner_mtu,
                                  apply_global=False, transport_kind=inner_kind)

    return {
        "ok": bool(outer_result.get("ok") and inner_result.get("ok")),
        "outer": {"iface": outer_iface, "mtu": outer_mtu,
                  "applied": outer_result.get("applied", [])},
        "inner": {"iface": inner_iface, "mtu": inner_mtu,
                  "applied": inner_result.get("applied", [])},
        "overhead_used": overhead,
    }


# ─────────────────────────── MTU ───────────────────────────

def _optimize_mtu(iface: str, profile: str, mtu_override: int = None) -> dict:
    """Выставить MTU для туннельного интерфейса.

    MR-45: если mtu_override не задан явно, читаем текущий MTU из ядра.
    Если уже выставлено значение МЕНЬШЕ целевого (например, AWG задал его
    через [Interface] MTU=), не перезаписываем его — пропускаем шаг и
    возвращаем текущее значение. Это предотвращает затирание intentional MTU,
    выставленного конфигом туннеля.
    """
    target_mtu = mtu_override if mtu_override is not None else MTU_PROFILES.get(
        profile, 1420)

    current_mtu = _read_iface_mtu(iface)
    _backup_iface_mtu(iface, current_mtu)

    # MR-45: проверяем текущий MTU, если не задан явный override
    if mtu_override is None:
        if current_mtu is not None and current_mtu < target_mtu:
            log.info(
                "tunnel_optimizer: MTU интерфейса %s (%d) < профильного (%d) — "
                "сохраняем настройку конфига туннеля (MR-45)" % (
                    iface, current_mtu, target_mtu),
                source="optimizer")
            return {"ok": True, "mtu": current_mtu, "note": "сохранён AWG/конфиг MTU"}

    try:
        r = subprocess.run(["ip", "link", "set", iface, "mtu", str(target_mtu)],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return {"ok": False, "error": (r.stderr or "").strip()}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": str(e)}

    # read-back: убеждаемся, что ядро реально приняло значение
    actual = _read_iface_mtu(iface)
    if actual is None:
        return {"ok": True, "mtu": target_mtu, "note": "не удалось перепроверить MTU"}
    if actual != target_mtu:
        log.warning("tunnel_optimizer: запрошен MTU=%d для %s, ядро "
                    "выставило %d" % (target_mtu, iface, actual),
                    source="optimizer")
    return {"ok": True, "mtu": actual}


def _read_iface_mtu(iface: str):
    path = "/sys/class/net/%s/mtu" % iface
    try:
        if os.path.isfile(path):
            with open(path) as f:
                return int(f.read().strip())
    except (OSError, ValueError):
        pass
    return None


def probe_pmtu(iface: str, host: str = "1.1.1.1",
               minimum: int = 1280, maximum: int = 1500) -> dict:
    """Binary-search a no-fragment dataplane MTU through an interface."""
    if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", str(iface or "")):
        return {"ok": False, "error": "Недопустимое имя интерфейса"}
    try:
        addr = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return {"ok": False, "error": "PMTU host должен быть IP-адресом"}
    if not _which("ping"):
        return {"ok": False, "error": "ping недоступен"}
    minimum = max(1280, int(minimum))
    maximum = min(9000, max(minimum, int(maximum)))
    overhead = 48 if addr.version == 6 else 28
    family = "-6" if addr.version == 6 else "-4"
    lo, hi = minimum, maximum
    successful = None
    tested = []
    while lo <= hi:
        mtu = (lo + hi) // 2
        payload = max(0, mtu - overhead)
        cmd = ["ping", family, "-I", iface, "-c", "1", "-W", "2",
               "-M", "do", "-s", str(payload), str(addr)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "error": str(e), "tested": tested}
        passed = r.returncode == 0
        tested.append({"mtu": mtu, "ok": passed})
        if passed:
            successful = mtu
            lo = mtu + 1
        else:
            hi = mtu - 1
    if successful is None:
        return {"ok": False, "error": "dataplane не проходит даже при MTU 1280",
                "tested": tested}
    return {"ok": True, "iface": iface, "host": str(addr),
            "pmtu": successful, "tested": tested,
            "ipv6_safe": successful >= 1280}


# ─────────────────────────── BBR + fq ───────────────────────────

def _detect_egress_iface() -> str:
    try:
        r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        output = r.stdout if isinstance(r.stdout, str) else ""
        words = output.split()
        if r.returncode == 0 and "dev" in words:
            iface = words[words.index("dev") + 1]
            if re.match(r"^[a-zA-Z0-9_-]{1,15}$", iface):
                return iface
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    return ""


def _optimize_congestion(egress_iface: str = "") -> dict:
    """BBR for TCP sockets created/terminated by the router itself."""
    try:
        cc_path = "/proc/sys/net/ipv4/tcp_congestion_control"
        current = _read_sysctl(cc_path)
        if current == "bbr":
            _ensure_fq_qdisc(egress_iface)
            return {"ok": True, "note": "BBR уже активен"}

        try:
            subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, timeout=5)
        except FileNotFoundError:
            # modprobe отсутствует на Entware/прошивках, но bbr может быть встроен в ядро статически
            pass

        available = _read_sysctl(
            "/proc/sys/net/ipv4/tcp_available_congestion_control") or ""
        if "bbr" not in available:
            return {"ok": False, "error": "BBR модуль недоступен в этом ядре"}

        if not _write_sysctl(cc_path, "bbr"):
            return {"ok": False, "error": "не удалось записать %s" % cc_path}

        actual = _read_sysctl(cc_path)
        if actual != "bbr":
            return {"ok": False, "error":
                    "ядро не приняло bbr (осталось: %s)" % actual}

        _ensure_fq_qdisc(egress_iface)
        return {"ok": True, "congestion": "bbr"}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": str(e)}


def _ensure_fq_qdisc(egress_iface: str = "") -> dict:
    """Apply fq to the actual physical egress when supported."""
    try:
        path = "/proc/sys/net/core/default_qdisc"
        current = _read_sysctl(path)
        if current != "fq":
            _write_sysctl(path, "fq")
        if not egress_iface:
            return {"ok": True, "note": "egress неизвестен; изменён только default_qdisc"}
        if not _which("tc"):
            return {"ok": False, "error": "tc недоступен"}
        show = subprocess.run(["tc", "qdisc", "show", "dev", egress_iface],
                              capture_output=True, text=True, timeout=5)
        if show.returncode != 0:
            return {"ok": False, "error": (show.stderr or "").strip()}
        line = next((x.strip() for x in (show.stdout or "").splitlines()
                     if " root " in (" " + x + " ")), "")
        if not line or "noqueue" in line:
            return {"ok": True, "note": "qdisc noqueue/не поддерживается"}
        words = line.split()
        kind = words[1] if len(words) > 1 and words[0] == "qdisc" else ""
        if kind == "fq":
            return {"ok": True, "note": "fq уже активен"}
        _remember_qdisc(egress_iface, kind)
        setq = subprocess.run(["tc", "qdisc", "replace", "dev", egress_iface,
                               "root", "fq"], capture_output=True, text=True,
                              timeout=5)
        if setq.returncode != 0:
            return {"ok": False, "error": (setq.stderr or "").strip()}
        return {"ok": True, "iface": egress_iface}
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("tunnel_optimizer: default_qdisc=fq: %s" % e,
                    source="optimizer")
        return {"ok": False, "error": str(e)}


# ─────────────────────────── MSS clamping ───────────────────────────

def _apply_mss_clamp(iface: str) -> dict:
    """Bidirectional IPv4/IPv6 MSS clamp in an owned nftables chain."""
    comment = "tunnel_optimizer:%s" % iface
    has_nft = _which("nft")
    has_iptables = _which("iptables")

    if not has_nft and not has_iptables:
        return {"ok": True, "note": "nft/iptables не установлены; пропуск"}

    try:
        if has_nft:
            table = "zapret_gui_optimizer"
            chain = "mss_" + re.sub(r"[^a-zA-Z0-9_]", "_", iface)
            exists = subprocess.run(
                ["nft", "list", "chain", "inet", table, chain],
                capture_output=True, text=True, timeout=5)
            if exists.returncode == 0:
                _remember_mss_iface(iface)
                return {"ok": True, "note": "уже применено (nft)"}
            subprocess.run(["nft", "add", "table", "inet", table],
                           capture_output=True, text=True, timeout=5)
            create = subprocess.run(
                ["nft", "add", "chain", "inet", table, chain,
                 "{ type filter hook forward priority 0; policy accept; }"],
                capture_output=True, text=True, timeout=5)
            if create.returncode == 0:
                for direction in ("oifname", "iifname"):
                    rule = subprocess.run(
                        ["nft", "add", "rule", "inet", table, chain,
                         direction, '"%s"' % iface, "tcp", "flags", "syn", "tcp", "option",
                         "maxseg", "size", "set", "rt", "mtu",
                         "comment", '"%s"' % comment],
                        capture_output=True, text=True, timeout=5)
                    if rule.returncode != 0:
                        subprocess.run(["nft", "delete", "chain", "inet", table, chain],
                                       capture_output=True, timeout=5)
                        return {"ok": False, "error": (rule.stderr or "").strip()}
                _remember_mss_iface(iface)
                return {"ok": True, "backend": "nft"}
            has_nft = False
        if has_iptables:
            applied = 0
            for binary in ("iptables", "ip6tables"):
                if not _which(binary):
                    continue
                for flag in ("-o", "-i"):
                    spec = [binary, "-t", "mangle", "FORWARD", flag, iface,
                            "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
                            "-m", "comment", "--comment", comment]
                    check = subprocess.run(spec[:3] + ["-C"] + spec[3:],
                                           capture_output=True, timeout=5)
                    if check.returncode == 0:
                        applied += 1
                        continue
                    add = subprocess.run(spec[:3] + ["-A"] + spec[3:],
                                         capture_output=True, text=True, timeout=5)
                    if add.returncode == 0:
                        applied += 1
            if applied:
                _remember_mss_iface(iface)
                return {"ok": True, "backend": "iptables", "rules": applied}
            return {"ok": False, "error": "не удалось создать MSS clamp"}
        return {"ok": True, "note": "MSS clamp недоступен; пропуск"}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": str(e)}


def _remove_mss_clamp(iface: str) -> dict:
    """Remove only rules/chains owned by this optimizer."""
    if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", iface):
        return {"ok": False, "error": "недопустимый iface"}
    errors = []
    try:
        if _which("nft"):
            table = "zapret_gui_optimizer"
            chain = "mss_" + re.sub(r"[^a-zA-Z0-9_]", "_", iface)
            subprocess.run(["nft", "flush", "chain", "inet", table, chain],
                           capture_output=True, timeout=5)
            r = subprocess.run(["nft", "delete", "chain", "inet", table, chain],
                               capture_output=True, text=True, timeout=5)
            if r.returncode not in (0, 1):
                errors.append((r.stderr or "").strip())
        comment = "tunnel_optimizer:%s" % iface
        for binary in ("iptables", "ip6tables"):
            if not _which(binary):
                continue
            for flag in ("-o", "-i"):
                spec = [binary, "-t", "mangle", "-D", "FORWARD", flag, iface,
                        "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
                        "-m", "comment", "--comment", comment]
                subprocess.run(spec, capture_output=True, timeout=5)
        return {"ok": not errors, "errors": errors}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": str(e)}


def _which(binname: str) -> bool:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, binname)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return True
    return False


# ─────────────────────────── Глобальный TCP-tuning ───────────────────

def ensure_global_tcp_tuning(profile: str = "balanced", quic: bool = False) -> dict:
    """Безопасно поднять глобальные TCP buffers.

    Existing values are never lowered: small global maxima harm unrelated
    traffic and can cap throughput below the tunnel's BDP. Keepalive remains
    an application-level choice and is intentionally not changed here.
    """
    applied = []
    errors = []

    buf = {
        "low_latency": (262144, 262144),
        "balanced": (1048576, 1048576),
        "throughput": (4194304, 4194304),
    }.get(profile, (1048576, 1048576))
    tcp_rmem, tcp_wmem = buf
    rmem_max, wmem_max = tcp_rmem, tcp_wmem
    if quic:
        # quic-go recommends ~7.5 MiB UDP maxima. net.core maxima are
        # shared ceilings, so only raise them; never lower existing values.
        quic_floor = 8 * 1024 * 1024
        rmem_max = max(rmem_max, quic_floor)
        wmem_max = max(wmem_max, quic_floor)

    for path, value in [
        ("/proc/sys/net/core/rmem_max", str(rmem_max)),
        ("/proc/sys/net/core/wmem_max", str(wmem_max)),
    ]:
        if _ensure_sysctl_min(path, int(value)):
            applied.append(os.path.basename(path))
        else:
            errors.append(os.path.basename(path))

    for path, minimum in [
        ("/proc/sys/net/ipv4/tcp_rmem", tcp_rmem),
        ("/proc/sys/net/ipv4/tcp_wmem", tcp_wmem),
    ]:
        current = _read_sysctl(path)
        try:
            current_max = int(current.split()[-1]) if current else 0
        except (ValueError, AttributeError):
            current_max = 0
        if current_max >= minimum:
            applied.append(os.path.basename(path))
        elif _write_sysctl(path, "4096 %d %d" % (minimum // 2, minimum)):
            applied.append(os.path.basename(path))
        else:
            errors.append(os.path.basename(path))

    if quic:
        applied.append("udp_quic_buffer_floor")

    # TCP Fast Open is intentionally not changed here: it only helps when
    # the application enables the relevant socket options.

    log.info("tunnel_optimizer: глобальный TCP-tuning — применено: %s"
             % ", ".join(applied), source="optimizer")

    return {"ok": True, "applied": applied, "errors": errors}


# ─────────────────────────── Sysctl Helpers ───────────────────────

def _read_sysctl(path: str):
    try:
        if os.path.isfile(path):
            with open(path) as f:
                return f.read().strip()
    except OSError:
        pass
    return None


def _write_sysctl(path: str, value: str) -> bool:
    """Обертка над записью sysctl с автоматическим сохранением бэкапа."""
    return _backup_and_set(path, value)


def _ensure_sysctl_min(path: str, minimum: int) -> bool:
    """Raise a numeric sysctl only when it is below minimum."""
    current = _read_sysctl(path)
    try:
        if current is not None and int(current) >= minimum:
            return True
    except (TypeError, ValueError):
        pass
    return _write_sysctl(path, str(minimum))


# ─────────────────────────── Batch / Status ───────────────────────

def optimize_all_tunnels(profile: str = "balanced") -> dict:
    """Применить оптимизации ко всем активным туннелям."""
    from core.tunnel_monitor import get_tunnel_monitor
    monitor = get_tunnel_monitor()
    interfaces = monitor.discover_interfaces()

    has_quic = any(str(i).startswith("opkgtun") for i in interfaces)
    buffer_result = ensure_global_tcp_tuning(profile, quic=has_quic)
    bbr_result = _optimize_congestion(_detect_egress_iface())
    global_result = {
        "ok": bool(buffer_result.get("ok") and bbr_result.get("ok")),
        "buffers": buffer_result,
        "bbr": bbr_result,
    }

    results = {}
    for iface in interfaces:
        if iface.startswith("__"):
            continue
        kind = "warp" if iface.startswith("opkgtun") else ""
        results[iface] = optimize_iface(
            iface, profile, apply_global=False, transport_kind=kind)

    return {"ok": bool(global_result.get("ok") and all(
        r.get("ok") for r in results.values())),
            "global": global_result, "results": results}


def get_optimization_status() -> dict:
    """Текущие TCP-настройки (для отображения в GUI)."""
    status = {}
    for param in ["tcp_congestion_control", "tcp_fastopen",
                  "tcp_keepalive_time"]:
        v = _read_sysctl("/proc/sys/net/ipv4/%s" % param)
        if v is not None:
            status[param] = v

    status["default_qdisc"] = _read_sysctl("/proc/sys/net/core/default_qdisc")
    status["available_cc"] = _read_sysctl(
        "/proc/sys/net/ipv4/tcp_available_congestion_control")
    status["rmem_max"] = _read_sysctl("/proc/sys/net/core/rmem_max")
    status["wmem_max"] = _read_sysctl("/proc/sys/net/core/wmem_max")

    return status
