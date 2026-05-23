# core/routing/dnsmasq_integration.py
"""
Интеграция с dnsmasq для domain-based selective routing.

Dnsmasq может на лету добавлять резолвящиеся IP в ipset (директива
`ipset=...`) или в nftables-set (`nftset=...`, доступно с
dnsmasq >= 2.87). Это даёт возможность маршрутизировать трафик
по доменам без полного списка их IP заранее.

Этот модуль умеет:
  * детектить dnsmasq и его основной конфиг
  * добавлять (один раз!) include на наш управляемый файл
  * писать управляемый файл с ipset=/nftset= директивами
  * перезагружать dnsmasq через SIGHUP

ВАЖНО: основной dnsmasq.conf никогда полностью не переписывается —
только append-once с маркером.
"""

import os
import re
import signal
import subprocess
import time

from core.log_buffer import log


# Маркер, по которому ищем наш include в основном dnsmasq.conf.
INCLUDE_MARKER = "# zapret-gui-awg-routing managed include"

# Имя управляемого файла. Лежит либо в conf-dir, либо рядом с
# основным dnsmasq.conf.
MANAGED_FILENAME = "zapret-gui-awg-routing.conf"


# ───────────────────────── helpers ──────────────────────────────────

def _run(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def _read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except (IOError, OSError):
        return ""


def _which(name):
    rc, out, _e = _run(["which", name])
    return out.strip() if rc == 0 and out.strip() else ""


# ───────────────────────── core integration ─────────────────────────

class DnsmasqIntegration:
    """Тонкий слой над dnsmasq. Без зависимостей кроме subprocess."""

    # Кандидаты для основного конфига dnsmasq, в порядке предпочтения.
    CONFIG_CANDIDATES = (
        "/opt/etc/dnsmasq.conf",   # Entware (Keenetic)
        "/etc/dnsmasq.conf",       # OpenWrt, обычный Linux
    )

    # Кандидаты для conf-dir (куда естественно класть include-файлы).
    CONFDIR_CANDIDATES = (
        "/opt/etc/dnsmasq.d",
        "/etc/dnsmasq.d",
    )

    def __init__(self):
        self._cached_status = None

    # ─────── detect ───────

    def find_main_config(self):
        """Путь к основному dnsmasq.conf или ''."""
        for p in self.CONFIG_CANDIDATES:
            if os.path.isfile(p):
                return p
        return ""

    def find_confdir(self, main_conf=""):
        """
        Куда положить наш managed файл. Берём conf-dir рядом с main_conf,
        иначе — параллельный /etc/dnsmasq.d / /opt/etc/dnsmasq.d.
        Создаём директорию по требованию.
        """
        if main_conf:
            base = os.path.dirname(main_conf)
            cand = os.path.join(base, "dnsmasq.d")
            return cand
        for d in self.CONFDIR_CANDIDATES:
            return d
        return "/etc/dnsmasq.d"

    def managed_file_path(self, main_conf=""):
        return os.path.join(self.find_confdir(main_conf), MANAGED_FILENAME)

    def get_pid(self):
        """PID dnsmasq или 0.

        На современном Debian/Ubuntu /var/run — symlink на /run, но на
        некоторых сборках (контейнеры, snap, NixOS) symlink'а нет, либо
        путь к pid-файлу выбран дистрибутивом иначе. Чтобы preflight
        в domain_rule не отваливался ложным «pid не найден», смотрим
        обе ветки и в конце даём широкий pgrep-фолбэк.
        """
        for pidfile in ("/opt/var/run/dnsmasq.pid",
                        "/var/run/dnsmasq.pid",
                        "/var/run/dnsmasq/dnsmasq.pid",
                        "/run/dnsmasq.pid",
                        "/run/dnsmasq/dnsmasq.pid"):
            txt = _read_file(pidfile).strip()
            if txt and txt.isdigit():
                pid = int(txt)
                if os.path.isdir("/proc/%d" % pid):
                    return pid
        # Фолбэк через pgrep. Сначала -x (exact comm), затем -f
        # (полный command-line) — для случаев, когда dnsmasq запущен
        # через wrapper и `comm` отличается от "dnsmasq".
        for args in (["pgrep", "-x", "dnsmasq"],
                     ["pgrep", "-f", "(^|/)dnsmasq( |$)"]):
            rc, out, _e = _run(args)
            if rc == 0 and out.strip():
                try:
                    return int(out.strip().splitlines()[0])
                except ValueError:
                    continue
        # Финальный фолбэк через systemctl — на чисто systemd-системах,
        # где pid-файла может не быть совсем (Type=notify без PIDFile=).
        rc, out, _e = _run(["systemctl", "show", "dnsmasq",
                            "--property=MainPID", "--value"], timeout=3)
        if rc == 0:
            txt = (out or "").strip()
            if txt.isdigit() and txt != "0":
                pid = int(txt)
                if os.path.isdir("/proc/%d" % pid):
                    return pid
        return 0

    def get_version(self):
        """Версия dnsmasq как 'X.Y' (str) или ''."""
        rc, out, _e = _run(["dnsmasq", "--version"], timeout=3)
        if rc != 0 or not out:
            return ""
        m = re.search(r"version\s+([0-9]+\.[0-9]+)", out, re.I)
        return m.group(1) if m else ""

    def supports_nftset(self):
        """
        Директива nftset= появилась в dnsmasq 2.87. Проверяем через
        --help dhcp (без рестарта) или версию.
        """
        rc, out, _e = _run(["dnsmasq", "--help", "dhcp"], timeout=3)
        # В справке встречается строка про nftset
        if rc == 0 and "nftset" in (out or "").lower():
            return True
        ver = self.get_version()
        if not ver:
            return False
        try:
            major, minor = ver.split(".", 1)
            return (int(major), int(minor)) >= (2, 87)
        except (ValueError, IndexError):
            return False

    def status(self):
        """Полный отчёт о состоянии dnsmasq на этой машине."""
        main_conf = self.find_main_config()
        pid = self.get_pid()
        version = self.get_version()
        binary = _which("dnsmasq")
        managed = self.managed_file_path(main_conf)
        include_present = self._main_has_include(main_conf, managed) if main_conf else False
        return {
            "available":        bool(binary),
            "binary":           binary,
            "version":          version,
            "running":          pid > 0,
            "pid":              pid,
            "main_config":      main_conf,
            "confdir":          self.find_confdir(main_conf) if main_conf else "",
            "managed_file":     managed,
            "include_present":  include_present,
            "supports_nftset":  self.supports_nftset() if binary else False,
        }

    # ─────── include management ───────

    def _main_has_include(self, main_conf, managed_path):
        if not main_conf or not os.path.isfile(main_conf):
            return False
        text = _read_file(main_conf)
        if INCLUDE_MARKER in text:
            return True
        # Учтём вариант, когда подключена вся conf-dir
        confdir = os.path.dirname(managed_path)
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#") or "=" not in s:
                continue
            key, _eq, val = s.partition("=")
            key = key.strip()
            val = val.strip().split(",", 1)[0]
            if key == "conf-file" and os.path.abspath(val) == os.path.abspath(managed_path):
                return True
            if key == "conf-dir" and os.path.abspath(val) == os.path.abspath(confdir):
                return True
        return False

    def ensure_include(self):
        """
        Гарантировать, что основной dnsmasq.conf подключает наш файл.
        Никогда не переписывает существующее содержимое — только
        append-once с маркером.
        """
        main_conf = self.find_main_config()
        if not main_conf:
            return {"ok": False, "error": "dnsmasq.conf не найден"}

        managed = self.managed_file_path(main_conf)
        confdir = os.path.dirname(managed)

        # Создаём conf-dir и пустой managed, если их нет.
        try:
            os.makedirs(confdir, exist_ok=True)
        except OSError as e:
            return {"ok": False, "error": "Не удалось создать %s: %s" % (confdir, e)}

        if not os.path.isfile(managed):
            try:
                with open(managed, "w") as f:
                    f.write("# Managed by zapret-gui — do not edit by hand.\n")
            except (IOError, OSError) as e:
                return {"ok": False, "error": "Не удалось создать %s: %s" % (managed, e)}

        if self._main_has_include(main_conf, managed):
            return {"ok": True, "added": False, "main_config": main_conf,
                    "managed_file": managed}

        # Append-once.
        try:
            with open(main_conf, "a") as f:
                f.write("\n%s\nconf-file=%s\n" % (INCLUDE_MARKER, managed))
        except (IOError, OSError) as e:
            return {"ok": False, "error": "Не удалось обновить %s: %s" % (main_conf, e)}

        log.info("dnsmasq: include добавлен в %s" % main_conf, source="routing")
        return {"ok": True, "added": True, "main_config": main_conf,
                "managed_file": managed}

    # ─────── managed file write/read ───────

    def write_managed_file(self, blocks):
        """
        Перезаписать managed-файл целиком.

        blocks — список dict:
            {
                "rule_id":   str,
                "set_kind":  "ipset" | "nftset",
                "set_name":  str,
                "nft_table": str (только для nftset),
                "nft_family": str (только для nftset, обычно 'inet'),
                "domains":   [str, ...],
            }

        Файл генерируется детерминированно — diff минимальный.
        """
        main_conf = self.find_main_config()
        managed = self.managed_file_path(main_conf)
        try:
            os.makedirs(os.path.dirname(managed), exist_ok=True)
        except OSError as e:
            return {"ok": False, "error": "Не удалось создать dir: %s" % e}

        lines = [
            "# Managed by zapret-gui — do not edit by hand.",
            "# Generated at %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
            "",
        ]
        for blk in blocks:
            lines.append("# rule %s" % blk.get("rule_id", "?"))
            kind = (blk.get("set_kind") or "ipset").lower()
            doms = [d.strip() for d in (blk.get("domains") or []) if d.strip()]
            if not doms:
                lines.append("# (no domains)\n")
                continue

            if kind == "nftset":
                fam   = blk.get("nft_family") or "inet"
                table = blk.get("nft_table") or "awg_routing"
                name  = blk.get("set_name") or ""
                # dnsmasq directive: nftset=/dom1/dom2/<family>#<table>#<set>
                joined = "/".join(doms)
                lines.append("nftset=/%s/%s#%s#%s" % (joined, fam, table, name))
            else:  # ipset
                name = blk.get("set_name") or ""
                # dnsmasq directive: ipset=/dom1/dom2/<set>
                joined = "/".join(doms)
                lines.append("ipset=/%s/%s" % (joined, name))
            lines.append("")

        text = "\n".join(lines).rstrip() + "\n"
        try:
            with open(managed, "w") as f:
                f.write(text)
        except (IOError, OSError) as e:
            return {"ok": False, "error": "Запись %s: %s" % (managed, e)}
        return {"ok": True, "managed_file": managed, "bytes": len(text)}

    # ─────── reload ───────

    def reload(self):
        """SIGHUP в dnsmasq, чтобы он перечитал конфиг."""
        pid = self.get_pid()
        if pid > 0:
            try:
                os.kill(pid, signal.SIGHUP)
                log.info("dnsmasq: SIGHUP → pid %d" % pid, source="routing")
                return {"ok": True, "pid": pid}
            except (ProcessLookupError, PermissionError, OSError) as e:
                log.warning("dnsmasq: kill -HUP %d не сработал: %s" % (pid, e),
                            source="routing")

        # Фолбэк через killall (на embedded busybox)
        rc, _o, err = _run(["killall", "-HUP", "dnsmasq"])
        if rc == 0:
            return {"ok": True, "pid": 0}
        return {"ok": False, "error": err.strip() or "dnsmasq не запущен"}
