# core/selfcheck.py
"""
Самодиагностика zapret-gui: проверка зависимостей, окружения и прогон
юнит-тестов ПРЯМО на устройстве (роутер/ПК), с выводом в лог GUI.

Зачем: dev-окружение не всегда совпадает с боевым (классический пример —
там нет модуля `bottle`, и api-тесты прогнать нельзя). Этот модуль
позволяет проверить ВСЁ на целевой системе, где GUI реально работает.

Секции:
  • python      — версия интерпретатора, модули (bottle — критичный,
                  yaml — опциональный, stdlib-санити);
  • tools       — системные утилиты (ip, iptables/nft, ipset, dnsmasq,
                  curl/wget, opkg/systemctl) с уровнями важности;
  • engines     — движки (zapret2/nfqws2, AWG, sing-box, mihomo):
                  установлен/версия/путь — через штатные детекторы;
  • config      — каталог конфига (путь/запись/место), settings.json,
                  web/ и tests/ рядом с приложением;
  • network     — DNS-резолв (информативно: нет сети ≠ сломан GUI);
  • tests       — `python -m unittest discover` подпроцессом с таймаутом
                  и разбором итога (Ran N / OK / FAILED ...).

Уровни чеков: ok | warn | fail | info. Итог ok=True, если нет fail
(и тесты, если запускались, прошли).

Использование:
  - GUI: Диагностика → «Самодиагностика» (api/diagnostics.py →
    start_async()/status(), фоновый поток);
  - CLI (работает даже когда GUI не стартует, например без bottle):
        python3 -m core.selfcheck             # всё, включая тесты
        python3 -m core.selfcheck --no-tests  # только окружение
        python3 -m core.selfcheck --pattern "test_unified_*.py"
        python3 -m core.selfcheck --json      # машиночитаемый вывод

НИКАКИХ импортов bottle на уровне модуля — это принципиально.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

from core.log_buffer import log


# Корень установки (где лежат app.py, core/, web/, tests/).
INSTALL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TESTS_TIMEOUT = 900  # сек на полный прогон юнит-тестов (роутеры медленные)


# ─────────────────────── примитивы ───────────────────────────────────

def _check(name, ok, details="", level=None):
    """Единица результата. level по умолчанию из ok: ok|fail."""
    return {
        "name": name,
        "ok": bool(ok),
        "level": level or ("ok" if ok else "fail"),
        "details": str(details or ""),
    }


def _section(name, title, checks):
    return {"name": name, "title": title, "checks": checks}


def _which(binary):
    return shutil.which(binary) or ""


def _run(args, timeout=10, cwd=None):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


# ─────────────────────── секции ──────────────────────────────────────

def check_python() -> dict:
    checks = []
    ver = "%d.%d.%d" % sys.version_info[:3]
    py_ok = sys.version_info >= (3, 8)
    checks.append(_check("Python", py_ok, "%s (%s)" % (ver, sys.executable),
                         level="ok" if py_ok else "fail"))

    # bottle — без него web-GUI не стартует (а вот CLI-самодиагностика
    # работает — ради этого модуль и не импортирует bottle сам).
    try:
        import bottle  # noqa: F401
        checks.append(_check("модуль bottle", True,
                             "версия %s" % getattr(bottle, "__version__", "?")))
    except ImportError:
        checks.append(_check(
            "модуль bottle", False,
            "не установлен — web-GUI не запустится и api-тесты упадут "
            "(opkg install python3-bottle / pip install bottle)"))

    # yaml — опциональный (нужен для round-trip правок clash-конфигов).
    try:
        import yaml  # noqa: F401
        checks.append(_check("модуль PyYAML", True, "есть"))
    except ImportError:
        checks.append(_check(
            "модуль PyYAML", True,
            "нет — mihomo-функции работают, кроме удаления прокси "
            "из таблицы (честный отказ)", level="warn"))

    # stdlib-санити: на некоторых прошивках python собран без ssl/sqlite.
    for mod, why in (("ssl", "TLS-пробы мониторинга, DoH, подписки"),
                     ("socket", "вся сеть"),
                     ("ipaddress", "разбор CIDR"),
                     ("sqlite3", "не используется, но полезно знать")):
        try:
            __import__(mod)
            checks.append(_check("stdlib %s" % mod, True, "есть"))
        except ImportError:
            lvl = "warn" if mod == "sqlite3" else "fail"
            checks.append(_check("stdlib %s" % mod, mod == "sqlite3",
                                 "ОТСУТСТВУЕТ — %s" % why, level=lvl))
    return _section("python", "Python и модули", checks)


def check_system_tools() -> dict:
    checks = []

    def tool(binary, required, why, version_args=None):
        path = _which(binary)
        if path:
            details = path
            if version_args:
                rc, out, err = _run([binary] + version_args, timeout=5)
                first = (out or err).strip().splitlines()
                if rc in (0, 1, 2) and first:
                    details += " · " + first[0][:80]
            checks.append(_check(binary, True, details))
        else:
            lvl = "fail" if required else ("warn" if why else "info")
            checks.append(_check(binary, not required,
                                 ("не найден — %s" % why) if why else "не найден",
                                 level=lvl))

    tool("ip", True, "без iproute2 не работает ни маршрутизация, ни AWG",
         ["-V"])
    tool("iptables", False, "", ["--version"])
    tool("ip6tables", False, "", ["--version"])
    tool("nft", False, "", ["--version"])
    tool("ipset", False, "", ["--version"])
    tool("dnsmasq", False, "", ["--version"])
    tool("curl", False, "", ["--version"])
    tool("wget", False, "")
    tool("opkg", False, "")        # Entware/OpenWrt
    tool("systemctl", False, "")   # десктопный Linux

    # Сводные проверки «хотя бы один из»:
    have_fw = bool(_which("iptables") or _which("nft"))
    checks.append(_check(
        "firewall-бэкенд (iptables или nft)", have_fw,
        "есть" if have_fw else
        "нет ни iptables, ни nft — NFQUEUE/masquerade/DSCP работать не будут",
        level="ok" if have_fw else "fail"))
    have_set = bool(_which("ipset") or _which("nft"))
    checks.append(_check(
        "set-бэкенд (ipset или nft)", True,
        "есть" if have_set else
        "нет ни ipset, ни nft — доменная маршрутизация через dnsmasq недоступна",
        level="ok" if have_set else "warn"))
    return _section("tools", "Системные утилиты", checks)


def check_engines() -> dict:
    checks = []

    # zapret2 / nfqws2
    try:
        from core.zapret_installer import get_zapret_installer
        z = get_zapret_installer().get_installed_version()
        if z.get("installed"):
            checks.append(_check("zapret2 / nfqws2", True,
                                 "%s · %s" % (z.get("version") or "?",
                                              z.get("binary_path") or "")))
        else:
            checks.append(_check("zapret2 / nfqws2", True,
                                 "не установлен (раздел «Zapret2»)",
                                 level="info"))
    except Exception as e:
        checks.append(_check("zapret2 / nfqws2", True,
                             "детект упал: %s" % e, level="warn"))

    # AWG
    try:
        from core.awg_detector import get_awg_detector
        rep = get_awg_detector().get_environment_report()
        existing = rep.get("existing") or {}
        plat = rep.get("platform") or {}
        tun = rep.get("tun") or {}
        if existing.get("binary_awg_go"):
            extra = (" · awg: %s" % existing["binary_awg"]
                     if existing.get("binary_awg") else " · утилиты awg нет")
            checks.append(_check("AmneziaWG (amneziawg-go)", True,
                                 existing["binary_awg_go"] + extra))
        else:
            checks.append(_check("AmneziaWG (amneziawg-go)", True,
                                 "не установлен (раздел AWG → Установка)",
                                 level="info"))
        tun_ok = bool(tun.get("available", True))
        checks.append(_check(
            "TUN-устройство", tun_ok,
            "/dev/net/tun: %s, модуль ядра: %s"
            % ("есть" if tun.get("device") else "нет",
               "загружен" if tun.get("kernel_module") else "не виден"),
            level="ok" if tun_ok else "warn"))
        if plat:
            checks.append(_check(
                "платформа", True,
                "%s · firewall=%s" % (plat.get("name") or "?",
                                      plat.get("firewall_backend") or "n/a"),
                level="info"))
    except Exception as e:
        checks.append(_check("AmneziaWG (amneziawg-go)", True,
                             "детект упал: %s" % e, level="warn"))

    # sing-box
    try:
        from core.singbox_detector import get_singbox_detector
        b = get_singbox_detector().detect_binary()
        if b.get("installed"):
            checks.append(_check("sing-box", True,
                                 "%s · %s" % (b.get("version") or "?",
                                              b.get("path") or "")))
        else:
            checks.append(_check("sing-box", True,
                                 "не установлен (раздел sing-box → Установка)",
                                 level="info"))
    except Exception as e:
        checks.append(_check("sing-box", True, "детект упал: %s" % e,
                             level="warn"))

    # mihomo
    try:
        from core.mihomo_detector import get_mihomo_detector
        b = get_mihomo_detector().detect_binary()
        if b.get("installed"):
            checks.append(_check("mihomo", True,
                                 "%s · %s" % (b.get("version") or "?",
                                              b.get("path") or "")))
        else:
            checks.append(_check("mihomo", True,
                                 "не установлен (раздел mihomo → Установка)",
                                 level="info"))
    except Exception as e:
        checks.append(_check("mihomo", True, "детект упал: %s" % e,
                             level="warn"))

    return _section("engines", "Движки", checks)


def check_config() -> dict:
    checks = []
    try:
        from core.config_manager import get_config_manager
        cm = get_config_manager()
        cfg_path = getattr(cm, "path", "") or ""
        cfg_dir = os.path.dirname(cfg_path) if cfg_path else ""
        checks.append(_check("settings.json", bool(cfg_path),
                             cfg_path or "путь не определён"))

        if cfg_path and os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    json.load(f)
                checks.append(_check("settings.json валиден", True, "JSON ок"))
            except Exception as e:
                checks.append(_check("settings.json валиден", False, str(e)))

        if cfg_dir:
            if not os.path.isdir(cfg_dir):
                checks.append(_check(
                    "каталог конфига записываем", False,
                    "%s не существует — настройки не сохранятся "
                    "(проверьте, смонтирован ли носитель)" % cfg_dir))
            else:
                probe = os.path.join(cfg_dir, ".selfcheck_probe")
                try:
                    with open(probe, "w") as f:
                        f.write("ok")
                    os.remove(probe)
                    checks.append(_check("каталог конфига записываем", True,
                                         cfg_dir))
                except OSError as e:
                    checks.append(_check("каталог конфига записываем", False,
                                         "%s: %s" % (cfg_dir, e)))
            try:
                st = os.statvfs(cfg_dir)
                free_mb = st.f_bavail * st.f_frsize / (1024 * 1024)
                low = free_mb < 5
                checks.append(_check(
                    "свободное место (конфиг)", not low,
                    "%.1f MB" % free_mb, level="warn" if low else "ok"))
            except OSError:
                pass
    except Exception as e:
        checks.append(_check("config_manager", False, str(e)))

    web_dir = os.path.join(INSTALL_DIR, "web")
    checks.append(_check(
        "каталог web/", os.path.isdir(web_dir),
        web_dir if os.path.isdir(web_dir) else
        "не найден — статика GUI отдаваться не будет"))
    tests_dir = os.path.join(INSTALL_DIR, "tests")
    has_tests = os.path.isdir(tests_dir)
    checks.append(_check(
        "каталог tests/", True,
        tests_dir if has_tests else "не найден — юнит-тесты недоступны",
        level="ok" if has_tests else "warn"))
    return _section("config", "Конфигурация и файлы", checks)


def check_network() -> dict:
    """DNS-резолв с таймаутом. Информативно: нет сети ≠ сломан GUI."""
    checks = []
    result = {}

    def _resolve():
        import socket
        try:
            infos = socket.getaddrinfo("example.com", 443)
            result["ips"] = sorted({i[4][0] for i in infos})
        except OSError as e:
            result["error"] = str(e)

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(5)
    if t.is_alive():
        checks.append(_check("DNS-резолв example.com", True,
                             "таймаут 5с — резолвер не отвечает",
                             level="warn"))
    elif result.get("ips"):
        checks.append(_check("DNS-резолв example.com", True,
                             ", ".join(result["ips"][:4])))
    else:
        checks.append(_check("DNS-резолв example.com", True,
                             result.get("error", "пусто"), level="warn"))
    return _section("network", "Сеть", checks)


# ─────────────────────── юнит-тесты ──────────────────────────────────

# "Ran 1178 tests in 1.029s" / "OK (skipped=2)" / "FAILED (errors=24)"
_RAN_RE = re.compile(r"^Ran (\d+) tests? in ([\d.]+)s", re.M)
_FAILED_RE = re.compile(r"^FAILED \(([^)]*)\)", re.M)
_OK_RE = re.compile(r"^OK(?: \(([^)]*)\))?\s*$", re.M)


def parse_unittest_output(output: str) -> dict:
    """
    Разобрать хвост вывода unittest в {ran, duration, ok, failures,
    errors, skipped, summary}. Числа из 'FAILED (failures=1, errors=2,
    skipped=3)' раскладываются по ключам.
    """
    res = {"ran": 0, "duration": 0.0, "ok": False,
           "failures": 0, "errors": 0, "skipped": 0, "summary": ""}
    m = _RAN_RE.search(output or "")
    if m:
        res["ran"] = int(m.group(1))
        res["duration"] = float(m.group(2))
    m_ok = _OK_RE.search(output or "")
    m_fail = _FAILED_RE.search(output or "")
    detail = ""
    if m_fail:
        detail = m_fail.group(1) or ""
        res["ok"] = False
    elif m_ok:
        detail = m_ok.group(1) or ""
        res["ok"] = True
    for part in detail.split(","):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip()
            try:
                v = int(v.strip())
            except ValueError:
                continue
            if k in res:
                res[k] = v
    res["summary"] = ("OK" if res["ok"] else "FAILED") + \
        (" (%s)" % detail if detail else "")
    return res


def run_unit_tests(pattern: str = "", timeout: int = TESTS_TIMEOUT) -> dict:
    """
    Прогнать юнит-тесты подпроцессом из каталога установки.
    Возвращает {ok, ran, failures, errors, skipped, duration, summary,
    tail} либо {ok: False, error} при невозможности запуска.
    """
    tests_dir = os.path.join(INSTALL_DIR, "tests")
    if not os.path.isdir(tests_dir):
        return {"ok": False, "skipped_run": True,
                "error": "каталог tests/ не найден (%s)" % tests_dir}
    args = [sys.executable, "-m", "unittest", "discover",
            "-s", "tests", "-p", pattern or "test_*.py"]
    rc, out, err = _run(args, timeout=timeout, cwd=INSTALL_DIR)
    output = (out or "") + "\n" + (err or "")
    if rc == 124:
        return {"ok": False, "error": "таймаут %dс" % timeout,
                "tail": output[-2000:]}
    parsed = parse_unittest_output(output)
    parsed["returncode"] = rc
    # Хвост вывода: при провале — побольше контекста.
    tail_lines = output.strip().splitlines()
    keep = 60 if not parsed["ok"] else 5
    parsed["tail"] = "\n".join(tail_lines[-keep:])
    if parsed["ran"] == 0 and rc != 0:
        parsed["ok"] = False
        parsed["summary"] = parsed["summary"] or \
            "тесты не запустились (rc=%d)" % rc
    return parsed


# ─────────────────────── оркестрация ─────────────────────────────────

def run_all(include_tests: bool = True, tests_pattern: str = "",
            progress_cb=None) -> dict:
    """
    Полный прогон самодиагностики. Каждая секция и итог пишутся в лог
    (source=selfcheck): warn/fail-чеки — log.warning, чтобы попасть и
    в персистентный лог.
    """
    started = time.time()
    log.info("самодиагностика: старт (тесты: %s)"
             % ("да" if include_tests else "нет"), source="selfcheck")

    sections = []
    steps = [check_python, check_system_tools, check_engines,
             check_config, check_network]
    for fn in steps:
        if progress_cb:
            progress_cb(fn.__name__)
        try:
            sec = fn()
        except Exception as e:
            sec = _section(fn.__name__, fn.__name__,
                           [_check(fn.__name__, False,
                                   "секция упала: %s" % e)])
        sections.append(sec)
        for c in sec["checks"]:
            line = "%s: %s — %s" % (sec["title"], c["name"],
                                    c["details"] or c["level"])
            if c["level"] in ("fail", "warn"):
                log.warning("самодиагностика: " + line, source="selfcheck")
            else:
                log.info("самодиагностика: " + line, source="selfcheck")

    tests = None
    if include_tests:
        if progress_cb:
            progress_cb("unit_tests")
        log.info("самодиагностика: прогон юнит-тестов "
                 "(может занять несколько минут на роутере)...",
                 source="selfcheck")
        tests = run_unit_tests(pattern=tests_pattern)
        if tests.get("ok"):
            log.info("самодиагностика: тесты OK — %d за %.1fс%s"
                     % (tests.get("ran", 0), tests.get("duration", 0),
                        (" (%s)" % tests["summary"]) if tests.get("summary")
                        else ""),
                     source="selfcheck")
        else:
            log.warning("самодиагностика: тесты FAILED — %s; хвост:\n%s"
                        % (tests.get("summary") or tests.get("error", "?"),
                           tests.get("tail", "")[-1500:]),
                        source="selfcheck")

    counts = {"ok": 0, "warn": 0, "fail": 0, "info": 0}
    for sec in sections:
        for c in sec["checks"]:
            counts[c["level"]] = counts.get(c["level"], 0) + 1
    ok = counts["fail"] == 0 and (tests is None or bool(tests.get("ok")))

    result = {
        "ok": ok,
        "started_at": int(started),
        "duration": round(time.time() - started, 1),
        "sections": sections,
        "tests": tests,
        "summary": counts,
    }
    msg = ("самодиагностика: завершена за %.1fс — ok=%d, warn=%d, fail=%d%s"
           % (result["duration"], counts["ok"], counts["warn"],
              counts["fail"],
              ("; тесты: %s" % (tests.get("summary") or tests.get("error")))
              if tests else ""))
    (log.success if ok else log.warning)(msg, source="selfcheck")
    return result


# ─────────────────────── фоновый запуск (для API) ────────────────────

_state = {"running": False, "progress": "", "result": None, "started_at": 0}
_state_lock = threading.Lock()

_PROGRESS_TITLES = {
    "check_python": "Python и модули",
    "check_system_tools": "Системные утилиты",
    "check_engines": "Движки",
    "check_config": "Конфигурация",
    "check_network": "Сеть",
    "unit_tests": "Юнит-тесты (может занять минуты)",
}


def start_async(include_tests: bool = True, tests_pattern: str = "") -> dict:
    """Запустить самодиагностику в фоне. Один прогон за раз."""
    with _state_lock:
        if _state["running"]:
            return {"ok": False, "error": "Самодиагностика уже идёт"}
        _state.update(running=True, progress="запуск",
                      started_at=int(time.time()))

    def _progress(step):
        with _state_lock:
            _state["progress"] = _PROGRESS_TITLES.get(step, step)

    def _worker():
        try:
            res = run_all(include_tests=include_tests,
                          tests_pattern=tests_pattern,
                          progress_cb=_progress)
        except Exception as e:
            log.error("самодиагностика упала: %s" % e, source="selfcheck")
            res = {"ok": False, "error": str(e)}
        with _state_lock:
            _state["result"] = res
            _state["running"] = False
            _state["progress"] = ""

    threading.Thread(target=_worker, daemon=True,
                     name="selfcheck").start()
    return {"ok": True, "started": True}


def status() -> dict:
    with _state_lock:
        return {
            "ok": True,
            "running": _state["running"],
            "progress": _state["progress"],
            "started_at": _state["started_at"],
            "result": _state["result"],
        }


# ─────────────────────── CLI ─────────────────────────────────────────

_LEVEL_MARKS = {"ok": "✓", "warn": "⚠", "fail": "✗", "info": "·"}


def _main(argv) -> int:
    include_tests = "--no-tests" not in argv
    as_json = "--json" in argv
    pattern = ""
    if "--pattern" in argv:
        i = argv.index("--pattern")
        if i + 1 < len(argv):
            pattern = argv[i + 1]

    result = run_all(include_tests=include_tests, tests_pattern=pattern)

    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    print("Самодиагностика zapret-gui (%s)" % INSTALL_DIR)
    for sec in result["sections"]:
        print("\n[%s]" % sec["title"])
        for c in sec["checks"]:
            mark = _LEVEL_MARKS.get(c["level"], "?")
            print("  %s %-34s %s" % (mark, c["name"], c["details"]))
    t = result.get("tests")
    if t is not None:
        print("\n[Юнит-тесты]")
        if t.get("error"):
            print("  ✗ %s" % t["error"])
        else:
            print("  %s %s — %d тестов за %.1fс"
                  % ("✓" if t.get("ok") else "✗",
                     t.get("summary", ""), t.get("ran", 0),
                     t.get("duration", 0)))
            if not t.get("ok") and t.get("tail"):
                print("  ── хвост вывода ──")
                for line in t["tail"].splitlines():
                    print("  " + line)
    s = result["summary"]
    print("\nИтог: %s — ok=%d, warn=%d, fail=%d (%.1fс)"
          % ("ВСЁ В ПОРЯДКЕ" if result["ok"] else "ЕСТЬ ПРОБЛЕМЫ",
             s["ok"], s["warn"], s["fail"], result["duration"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
