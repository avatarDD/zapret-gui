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

import glob
import json
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

# Marker-файл auto-setup: фиксируем, ЧТО мы поменяли в системе,
# чтобы потом точно так же откатить.
SETUP_STATE_FILE = "/var/lib/zapret-gui/dnsmasq-auto-setup.json"


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
        # Предпочитаем СУЩЕСТВУЮЩИЙ conf-dir; иначе — тот, чей родитель
        # записываемый (сможем mkdir); иначе — последний кандидат как
        # запасной. Раньше безусловный `return d` всегда брал первого
        # кандидата (обычно /opt/etc/dnsmasq.d), даже если его нет, а
        # fallthrough был мёртвым кодом.
        candidates = list(self.CONFDIR_CANDIDATES) or ["/etc/dnsmasq.d"]
        for d in candidates:
            if os.path.isdir(d):
                return d
        for d in candidates:
            parent = os.path.dirname(d.rstrip("/")) or "/"
            if os.path.isdir(parent) and os.access(parent, os.W_OK):
                return d
        return candidates[-1]

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

    def _compile_options(self):
        """
        Множество compile-time опций из `dnsmasq --version` (lowercase).

        dnsmasq печатает строку «Compile time options: IPv6 ... ipset
        nftset ...»; ОТКЛЮЧЁННАЯ на сборке опция идёт с префиксом `no-`
        (`no-nftset`, `no-ipset`). Возвращаем набор токенов, чтобы можно
        было точно (а не подстрокой) проверить наличие фичи.
        """
        rc, out, _e = _run(["dnsmasq", "--version"], timeout=3)
        if rc != 0 or not out:
            return set()
        opts = set()
        for line in out.splitlines():
            if "compile time options" in line.lower():
                _, _, rest = line.partition(":")
                for tok in re.split(r"[\s,]+", rest.strip().lower()):
                    if tok:
                        opts.add(tok)
        return opts

    def supports_nftset(self):
        """
        Поддержка директивы `nftset=` — это КОМПАЙЛ-ТАЙМ фича
        (HAVE_NFTSET), а НЕ просто версия. dnsmasq без неё отвергает
        `nftset=` и НЕ стартует («recompile with HAVE_NFTSET defined»),
        роняя весь DNS. Поэтому проверяем по «Compile time options»:
        enabled = токен `nftset`, disabled = `no-nftset`.

        (Старый код брал `"nftset" in output` — но это True и для
        `no-nftset`; плюс версия >= 2.87 ≠ наличие HAVE_NFTSET. Из-за
        ложного + мы писали `nftset=` в managed-файл, и dnsmasq падал.)
        """
        return "nftset" in self._compile_options()

    def supports_ipset(self):
        """
        Поддержка `ipset=` — тоже компайл-тайм (HAVE_IPSET). Та же логика,
        что и у supports_nftset: токен `ipset` присутствует и это не
        `no-ipset`.
        """
        return "ipset" in self._compile_options()

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
            "supports_ipset":   self.supports_ipset() if binary else False,
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
                # dnsmasq directive: nftset=/dom1/dom2/<spec>/<spec>...
                # Каждый <spec> = family#table#set. У нас два set'а: v4 и v6
                # (имя v6 = v4 + "6"). Если перечислять только v4-set, dnsmasq
                # NIKAGDA не запишет AAAA-IP в v6-set (и весь IPv6-трафик
                # пользователя через AWG не пойдёт — браузеры предпочитают v6).
                # Поэтому всегда эмитим оба set'а в одной директиве.
                joined = "/".join(doms)
                spec_v4 = "%s#%s#%s" % (fam, table, name)
                spec_v6 = "%s#%s#%s6" % (fam, table, name)
                lines.append("nftset=/%s/%s/%s" %
                             (joined, spec_v4, spec_v6))
            else:  # ipset
                name = blk.get("set_name") or ""
                # dnsmasq directive: ipset=/dom1/dom2/<set4>,<set6>.
                # Перечисляем И v4-, И v6-set (имя v6 = name+"6", он реально
                # создаётся в domain_rule). Без v6-имени dnsmasq никогда не
                # запишет AAAA-IP → весь IPv6-трафик к домену идёт мимо
                # туннеля (браузеры предпочитают v6). dnsmasq кладёт каждый
                # адрес в set с совпадающим семейством.
                joined = "/".join(doms)
                lines.append("ipset=/%s/%s,%s6" % (joined, name, name))
            lines.append("")

        text = "\n".join(lines).rstrip() + "\n"
        # MR-24: Атомарная запись во избежание повреждения файла при сбоях питания/uninstall/OOM
        tmp_managed = managed + ".tmp"
        try:
            with open(tmp_managed, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp_managed, managed)
        except (IOError, OSError) as e:
            try:
                os.remove(tmp_managed)
            except OSError:
                pass
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

    # ─────── auto-setup (Debian/Ubuntu) ───────

    def plan_auto_setup(self) -> dict:
        """
        Сухая прогонка: что мы СДЕЛАЕМ при auto_setup, без побочек.

        Возвращает структуру со списком шагов и текущим состоянием,
        чтобы UI мог показать пользователю «вот это поменяется».
        """
        # На системах без systemd (Keenetic/Entware, старый OpenWrt)
        # dnsmasq запускается init-скриптом, а не systemctl. Весь
        # systemd-план там неприменим и давал пустой список шагов —
        # из-за чего кнопка «Настроить» отвечала «менять нечего», а
        # dnsmasq так и не стартовал.
        if not _which("systemctl"):
            return self._plan_init_based()

        steps = []
        warnings = []

        # systemctl-based авто-setup имеет смысл только если у нас есть
        # юнит dnsmasq.service. Один лишь бинарь /usr/local/bin/dnsmasq
        # ничего не даст — `systemctl enable dnsmasq` упадёт с «Unit
        # dnsmasq.service does not exist». Поэтому проверяем именно
        # существование юнита, а не PATH.
        has_unit   = self._has_dnsmasq_service()
        has_binary = bool(_which("dnsmasq"))
        if not has_unit:
            apt = _which("apt-get") or _which("apt")
            if apt:
                steps.append({
                    "id":   "install_dnsmasq",
                    "what": ("Установить пакет dnsmasq через apt-get"
                             " (бинарь %s уже есть, но systemd-юнит"
                             " отсутствует)" % "найден"
                             if has_binary else
                             "Установить пакет dnsmasq через apt-get"),
                    "cmd":  "%s install -y dnsmasq" % apt,
                })
            else:
                warnings.append(
                    "Нет ни systemd-юнита dnsmasq.service, ни apt-get/apt"
                    " — нужно поставить пакет dnsmasq вручную для вашего"
                    " дистрибутива.")

        resolved_running = self._systemctl_is_active("systemd-resolved")
        if resolved_running and self._read_stub_listener() != "no":
            steps.append({
                "id":   "disable_stub_listener",
                "what": "В /etc/systemd/resolved.conf выставить"
                        " DNSStubListener=no (порт 53 освободится"
                        " для dnsmasq)",
                "cmd":  "edit /etc/systemd/resolved.conf",
            })
            steps.append({
                "id":   "restart_resolved",
                "what": "systemctl restart systemd-resolved",
                "cmd":  "systemctl restart systemd-resolved",
            })

        # /etc/resolv.conf нужно направить на 127.0.0.1 НЕЗАВИСИМО от того,
        # отключён ли уже stub-listener (он мог быть отключён в прошлый
        # setup, но resolv.conf тогда мы криво подсовывали на upstream).
        # Проверяем по содержимому файла, а не по флагу stub.
        if not self._resolv_conf_points_at_dnsmasq():
            steps.append({
                "id":   "point_resolv_to_dnsmasq",
                "what": "Заменить /etc/resolv.conf на"
                        " «nameserver 127.0.0.1» — иначе системные"
                        " запросы пойдут мимо dnsmasq (на upstream"
                        " через resolved), и ipset/nftset просто"
                        " не наполнятся при резолве 2ip.ru и т.п.",
                "cmd":  "write /etc/resolv.conf",
            })

        # dnsmasq.conf: если файла нет — создадим минимальный.
        # Если есть и это НАШ файл без user=root — допишем директиву,
        # чтобы dnsmasq не дропал CAP_NET_ADMIN на Debian (без него
        # запись в nftset тихо проваливается).
        main_conf = self.find_main_config()
        config_will_change = False
        if not main_conf:
            steps.append({
                "id":   "create_dnsmasq_conf",
                "what": "Создать /etc/dnsmasq.conf с минимальной"
                        " конфигурацией (port=53, upstream=1.1.1.1)",
                "cmd":  "write /etc/dnsmasq.conf",
            })
            config_will_change = True
        else:
            try:
                with open(main_conf, "r") as f:
                    cur_text = f.read()
                if ("Создан zapret-gui" in cur_text
                        and "user=root" not in cur_text):
                    steps.append({
                        "id":   "create_dnsmasq_conf",
                        "what": "Добавить user=root в %s (без него dnsmasq"
                                " на Debian теряет CAP_NET_ADMIN и не"
                                " пишет в nftset)" % main_conf,
                        "cmd":  "append /etc/dnsmasq.conf",
                    })
                    config_will_change = True
            except (IOError, OSError):
                pass

        # Если поменяли конфиг и dnsmasq уже запущен — нужен полный
        # restart (SIGHUP не применяет смену user=).
        if config_will_change and self._systemctl_is_active("dnsmasq"):
            steps.append({
                "id":   "restart_dnsmasq",
                "what": "systemctl restart dnsmasq (применить новый"
                        " user=root и подцепить CAP_NET_ADMIN)",
                "cmd":  "systemctl restart dnsmasq",
            })

        # Включить и стартануть dnsmasq.
        # ВАЖНО: enable/start добавляем только если юнит уже есть ИЛИ
        # запланирована его установка через apt — иначе на выполнении
        # получим «Unit dnsmasq.service does not exist» и весь setup
        # пойдёт красным.
        will_have_unit = has_unit or any(
            s["id"] == "install_dnsmasq" for s in steps
        )
        if will_have_unit:
            if not has_unit or not self._systemctl_is_enabled("dnsmasq"):
                steps.append({
                    "id":   "enable_dnsmasq",
                    "what": "systemctl enable dnsmasq",
                    "cmd":  "systemctl enable dnsmasq",
                })
            if not has_unit or not self._systemctl_is_active("dnsmasq"):
                steps.append({
                    "id":   "start_dnsmasq",
                    "what": "systemctl start dnsmasq",
                    "cmd":  "systemctl start dnsmasq",
                })

        return {
            "ok":        True,
            "steps":     steps,
            "warnings":  warnings,
            "applicable": bool(steps),
            "have_systemctl": bool(_which("systemctl")),
        }

    def auto_setup(self) -> dict:
        """
        Реально настраивает dnsmasq для работы рядом с systemd-resolved.

        Делает то, что показывает plan_auto_setup(). Безопасно вызывать
        повторно — каждый шаг идемпотентен. Каждое успешное изменение
        системы (бэкап файла, enable юнита) пишется в state-файл, чтобы
        revert() мог точно так же откатиться.

        На не-systemd системах (OpenWrt, Entware) этот метод ничего не
        делает — там dnsmasq уже основной резолвер.
        """
        if not _which("systemctl"):
            # Не systemd: запускаем dnsmasq init-скриптом (Keenetic/Entware).
            return self._auto_setup_init_based()

        state = self._load_state() or {
            "applied_at":          int(time.time()),
            "resolved_conf_backup": "",
            "resolv_conf_backup":   "",
            "resolv_conf_was_link": False,
            "resolv_conf_link_target": "",
            "we_created_dnsmasq_conf": False,
            "dnsmasq_was_active":      self._systemctl_is_active("dnsmasq"),
            "dnsmasq_was_enabled":     self._systemctl_is_enabled("dnsmasq"),
            "stub_listener_was":       self._read_stub_listener(),
        }

        results = []
        plan = self.plan_auto_setup()

        for step in plan["steps"]:
            sid = step["id"]
            res = None
            if sid == "install_dnsmasq":
                res = self._step_install_dnsmasq()
            elif sid == "disable_stub_listener":
                res = self._step_disable_stub_listener()
                if res.get("ok") and res.get("backup"):
                    state["resolved_conf_backup"] = res["backup"]
            elif sid == "restart_resolved":
                res = self._step_restart_unit("systemd-resolved")
            elif sid == "point_resolv_to_dnsmasq":
                res = self._step_point_resolv_to_dnsmasq()
                if res.get("ok") and not res.get("skipped"):
                    state["resolv_conf_was_link"] = res.get("was_link", False)
                    state["resolv_conf_link_target"] = res.get(
                        "previous_target", "")
                    if res.get("backup"):
                        state["resolv_conf_backup"] = res["backup"]
            elif sid == "create_dnsmasq_conf":
                res = self._step_create_default_dnsmasq_conf()
                if res.get("ok") and not res.get("skipped"):
                    state["we_created_dnsmasq_conf"] = True
            elif sid == "enable_dnsmasq":
                res = self._step_enable_unit("dnsmasq")
            elif sid == "start_dnsmasq":
                res = self._step_start_unit("dnsmasq")
            elif sid == "restart_dnsmasq":
                res = self._step_restart_unit("dnsmasq")
            if res is not None:
                results.append(res)

        final = self.status()
        ok = all(r.get("ok") for r in results) and final.get("running")

        # Сохраняем marker, только если хоть что-то реально поменяли —
        # иначе revert будет «откатывать пустоту» и трогать чужой setup.
        if any(not r.get("skipped") for r in results):
            self._save_state(state)

        log.info(
            "dnsmasq auto_setup: %d шагов, %s, dnsmasq.pid=%s" % (
                len(results),
                "ok" if ok else "ошибки",
                final.get("pid"),
            ),
            source="routing",
        )
        return {
            "ok":      bool(ok),
            "steps":   results,
            "status":  final,
        }

    def revert(self) -> dict:
        """
        Откатить всё, что сделал последний auto_setup. Симметричный
        teardown по marker-файлу. Идемпотентно: если state нет —
        возвращает skipped, ничего не трогая.
        """
        state = self._load_state()
        if not state:
            return {"ok": True, "skipped": True,
                    "reason": "auto-setup не применялся — нечего откатывать"}

        results = []
        sctl = _which("systemctl")

        # 1) Остановить dnsmasq, если МЫ его запустили
        if sctl and not state.get("dnsmasq_was_active"):
            rc, _o, err = _run([sctl, "stop", "dnsmasq"], timeout=15)
            results.append({"step": "stop_dnsmasq",
                            "ok": rc == 0 or "not loaded" in (err or "").lower(),
                            "error": (err or "").strip() if rc != 0 else ""})

        # 2) Disable юнит, если он не был enabled до нас
        if sctl and not state.get("dnsmasq_was_enabled"):
            rc, _o, err = _run([sctl, "disable", "dnsmasq"], timeout=10)
            results.append({"step": "disable_dnsmasq",
                            "ok": rc == 0 or "not loaded" in (err or "").lower(),
                            "error": (err or "").strip() if rc != 0 else ""})

        # 3) Снести /etc/dnsmasq.conf, если МЫ его создали
        if state.get("we_created_dnsmasq_conf"):
            path = "/etc/dnsmasq.conf"
            try:
                if os.path.isfile(path):
                    os.remove(path)
                results.append({"step": "remove_dnsmasq_conf", "ok": True,
                                "path": path})
            except OSError as e:
                results.append({"step": "remove_dnsmasq_conf", "ok": False,
                                "error": str(e)})

        # 4) Восстановить /etc/resolv.conf из бэкапа
        bak = state.get("resolv_conf_backup") or ""
        if bak and os.path.exists(bak):
            try:
                path = "/etc/resolv.conf"
                if os.path.islink(path) or os.path.isfile(path):
                    os.remove(path)
                os.rename(bak, path)
                results.append({"step": "restore_resolv_conf", "ok": True})
            except OSError as e:
                results.append({"step": "restore_resolv_conf", "ok": False,
                                "error": str(e)})
        elif state.get("resolv_conf_was_link") and state.get(
                "resolv_conf_link_target"):
            # Был симлинк — пересоздаём
            try:
                path = "/etc/resolv.conf"
                if os.path.islink(path) or os.path.isfile(path):
                    os.remove(path)
                os.symlink(state["resolv_conf_link_target"], path)
                results.append({"step": "restore_resolv_conf_symlink",
                                "ok": True,
                                "target": state["resolv_conf_link_target"]})
            except OSError as e:
                results.append({"step": "restore_resolv_conf_symlink",
                                "ok": False, "error": str(e)})

        # 5) Восстановить /etc/systemd/resolved.conf из бэкапа
        bak = state.get("resolved_conf_backup") or ""
        if bak and os.path.exists(bak):
            try:
                path = "/etc/systemd/resolved.conf"
                with open(bak, "rb") as src, open(path, "wb") as dst:
                    dst.write(src.read())
                os.remove(bak)
                results.append({"step": "restore_resolved_conf", "ok": True})
            except (IOError, OSError) as e:
                results.append({"step": "restore_resolved_conf", "ok": False,
                                "error": str(e)})

        # 6) Рестартануть systemd-resolved, чтобы он подобрал старый
        #    конфиг и снова занял :53/stub.
        if sctl:
            rc, _o, err = _run([sctl, "restart", "systemd-resolved"],
                                timeout=15)
            results.append({"step": "restart_resolved",
                            "ok": rc == 0,
                            "error": (err or "").strip() if rc != 0 else ""})

        # 7) Удалить marker
        try:
            os.remove(SETUP_STATE_FILE)
        except OSError:
            pass

        ok = all(r.get("ok") for r in results)
        log.info(
            "dnsmasq revert: %d шагов, %s" %
            (len(results), "ok" if ok else "ошибки"),
            source="routing",
        )
        return {"ok": bool(ok), "steps": results, "status": self.status()}

    def is_applied(self) -> bool:
        """Применён ли auto_setup (т.е. есть ли state-файл)."""
        return os.path.isfile(SETUP_STATE_FILE)

    def revert_if_applied(self) -> dict:
        """Wrapper: revert() только если state-файл существует."""
        if not self.is_applied():
            return {"ok": True, "skipped": True}
        return self.revert()

    def _load_state(self):
        if not os.path.isfile(SETUP_STATE_FILE):
            return None
        try:
            with open(SETUP_STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (IOError, OSError, ValueError):
            return None

    def _save_state(self, state: dict) -> None:
        try:
            os.makedirs(os.path.dirname(SETUP_STATE_FILE), exist_ok=True)
            with open(SETUP_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
        except (IOError, OSError) as e:
            log.warning("Не удалось сохранить dnsmasq auto-setup state: %s" % e,
                        source="routing")

    # ─────── shaped low-level steps ───────

    def _has_dnsmasq_service(self) -> bool:
        """
        Есть ли в системе юнит dnsmasq.service? `systemctl cat` отвечает
        быстро и НЕ требует, чтобы сервис был запущен — нам важен сам
        факт наличия .service-файла, чтобы потом мочь его enable/start.
        """
        sctl = _which("systemctl")
        if not sctl:
            return False
        rc, _o, _e = _run([sctl, "cat", "--", "dnsmasq.service"], timeout=3)
        return rc == 0

    def _systemctl_is_active(self, unit: str) -> bool:
        sctl = _which("systemctl")
        if not sctl:
            return False
        rc, out, _e = _run([sctl, "is-active", unit], timeout=3)
        return rc == 0 and (out or "").strip() == "active"

    def _systemctl_is_enabled(self, unit: str) -> bool:
        sctl = _which("systemctl")
        if not sctl:
            return False
        rc, out, _e = _run([sctl, "is-enabled", unit], timeout=3)
        # is-enabled может возвращать "enabled" / "alias" / "static" — все ОК.
        if rc != 0:
            return False
        v = (out or "").strip()
        return v in ("enabled", "alias", "static", "enabled-runtime")

    def _resolv_conf_points_at_dnsmasq(self) -> bool:
        """
        Достоверно ли /etc/resolv.conf направляет запросы на dnsmasq
        (т.е. 127.0.0.1)? Симлинк resolv.conf на stub-resolv.conf
        (127.0.0.53) и на /run/systemd/resolve/resolv.conf (upstream)
        оба считаются «не на dnsmasq».
        """
        path = "/etc/resolv.conf"
        try:
            with open(path, "r") as f:
                text = f.read()
        except (IOError, OSError):
            return False
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.lower().startswith("nameserver"):
                _, _, ns = s.partition(" ")
                ns = ns.strip()
                if ns == "127.0.0.1" or ns == "::1":
                    return True
                return False
        return False

    def _read_stub_listener(self) -> str:
        """
        Прочитать текущее значение DNSStubListener из resolved.conf.
        Возвращает 'yes' / 'no' / '' (если не определено / файла нет).
        """
        path = "/etc/systemd/resolved.conf"
        try:
            with open(path, "r") as f:
                for line in f:
                    s = line.strip()
                    if s.startswith("#") or "=" not in s:
                        continue
                    key, _, val = s.partition("=")
                    if key.strip().lower() == "dnsstublistener":
                        return val.strip().lower()
        except (IOError, OSError):
            pass
        return ""  # по умолчанию systemd-resolved слушает на 127.0.0.53

    # ─────── non-systemd (Keenetic/Entware, старый OpenWrt) ───────

    def _find_init_script(self) -> str:
        """
        Путь к init-скрипту dnsmasq на не-systemd системах.

        Entware (Keenetic) кладёт его как /opt/etc/init.d/S56dnsmasq,
        классический OpenWrt/Linux — /etc/init.d/dnsmasq.
        """
        candidates = []
        candidates.extend(sorted(glob.glob("/opt/etc/init.d/S*dnsmasq*")))
        candidates.extend(sorted(glob.glob("/opt/etc/init.d/*dnsmasq*")))
        candidates.append("/etc/init.d/dnsmasq")
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return ""

    def _plan_init_based(self) -> dict:
        """
        План настройки для систем без systemd: убедиться, что наш
        include подключён, и запустить dnsmasq init-скриптом.
        """
        steps = []
        warnings = []

        status = self.status()
        has_binary = bool(status.get("binary")) or bool(_which("dnsmasq"))
        if not has_binary:
            warnings.append(
                "dnsmasq не установлен. Поставьте пакет (на Keenetic/Entware:"
                " opkg install dnsmasq-full) и повторите.")
            return {"ok": True, "steps": [], "warnings": warnings,
                    "applicable": False, "have_systemctl": False}

        main_conf = self.find_main_config()
        managed = self.managed_file_path(main_conf)

        if main_conf and not self._main_has_include(main_conf, managed):
            steps.append({
                "id":   "ensure_include",
                "what": "Добавить include нашего файла правил в %s" % main_conf,
                "cmd":  "append %s" % main_conf,
            })

        if not status.get("running"):
            init_script = self._find_init_script()
            if init_script:
                steps.append({
                    "id":   "start_dnsmasq_init",
                    "what": "Запустить dnsmasq: %s start" % init_script,
                    "cmd":  "%s start" % init_script,
                })
            else:
                warnings.append(
                    "dnsmasq установлен, но init-скрипт не найден"
                    " (/opt/etc/init.d/S*dnsmasq). Запустите dnsmasq вручную.")

        return {"ok": True, "steps": steps, "warnings": warnings,
                "applicable": bool(steps), "have_systemctl": False}

    def _auto_setup_init_based(self) -> dict:
        """Выполнить план _plan_init_based (без systemd)."""
        plan = self._plan_init_based()
        results = []
        for step in plan.get("steps", []):
            sid = step["id"]
            if sid == "ensure_include":
                r = self.ensure_include()
                results.append({"step": "ensure_include",
                                "ok": bool(r.get("ok")),
                                "error": r.get("error", "")})
            elif sid == "start_dnsmasq_init":
                results.append(self._step_start_init_script())

        final = self.status()
        ok = all(r.get("ok") for r in results) and final.get("running")
        fail_detail = "; ".join(
            "%s: %s" % (r.get("step"), r.get("error") or r.get("stderr") or "?")
            for r in results if not r.get("ok"))
        log.info(
            "dnsmasq init-setup: %d шагов, %s, dnsmasq.pid=%s%s" % (
                len(results), "ok" if ok else "ошибки", final.get("pid"),
                (" — " + fail_detail) if fail_detail else ""),
            source="routing",
        )
        return {"ok": bool(ok), "steps": results, "status": final,
                "warnings": plan.get("warnings", [])}

    def _step_start_init_script(self) -> dict:
        script = self._find_init_script()
        if not script:
            return {"step": "start_dnsmasq_init", "ok": False,
                    "error": "init-скрипт dnsmasq не найден"}
        rc, out, err = _run([script, "start"], timeout=20)
        # init-скрипты часто возвращают 0 даже при неудаче (порт занят и
        # т.п.) — достоверный признак успеха только наличие живого pid.
        time.sleep(0.7)
        pid = self.get_pid()
        ok = pid > 0
        error = ""
        if not ok:
            # Самая частая причина на Keenetic — :53 уже занят штатным DNS
            # роутера (ndnsmasq/ndm). Проверим и дадим внятный текст.
            occ = self._port53_listener()
            cfg_err = self._dnsmasq_config_error()
            parts = []
            if (err or "").strip():
                parts.append((err or "").strip())
            if cfg_err:
                parts.append(cfg_err)
            if occ:
                parts.append(
                    "порт 53 уже слушает другой процесс (%s) — на Keenetic"
                    " это штатный DNS роутера, и Entware-dnsmasq не может"
                    " занять :53. Нужно либо освободить :53, либо запускать"
                    " dnsmasq на другом порту (ручная настройка)." % occ)
            error = "; ".join(parts) or "dnsmasq не поднялся (pid=0)"
        return {
            "step":    "start_dnsmasq_init",
            "ok":      ok,
            "command": "%s start" % script,
            "stdout":  (out or "")[-1000:],
            "stderr":  (err or "")[-1000:] if not ok else "",
            "error":   error,
            "pid":     pid,
        }

    def _port53_listener(self) -> str:
        """
        Кто слушает :53. Возвращает краткое описание ('udp 127.0.0.1:53'
        и т.п.) или '' если порт свободен / не удалось определить.
        Без сторонних зависимостей: парсим /proc/net/{udp,tcp}.
        """
        found = []
        for proto, path in (("udp", "/proc/net/udp"),
                            ("tcp", "/proc/net/tcp")):
            txt = _read_file(path)
            for line in txt.splitlines()[1:]:
                cols = line.split()
                if len(cols) < 4:
                    continue
                local = cols[1]  # HEX_IP:HEX_PORT
                st = cols[3]
                if ":" not in local:
                    continue
                port_hex = local.rsplit(":", 1)[1]
                try:
                    port = int(port_hex, 16)
                except ValueError:
                    continue
                if port != 53:
                    continue
                # для tcp интересен только LISTEN (st == 0A)
                if proto == "tcp" and st.upper() != "0A":
                    continue
                found.append(proto)
                break
        return "/".join(sorted(set(found))) + " :53" if found else ""

    def _dnsmasq_config_error(self) -> str:
        """Прогнать `dnsmasq --test`, вернуть текст ошибки конфига или ''."""
        main = self.find_main_config()
        args = ["dnsmasq", "--test"]
        if main:
            args += ["-C", main]
        rc, out, err = _run(args, timeout=5)
        if rc == 127:  # бинарь dnsmasq не найден — это не ошибка конфига
            return ""
        blob = (err or "") + (out or "")
        if rc != 0 and blob.strip():
            return "конфиг: %s" % blob.strip()[:300]
        return ""

    def _step_install_dnsmasq(self) -> dict:
        apt = _which("apt-get") or _which("apt")
        if not apt:
            return {"step": "install_dnsmasq", "ok": False,
                    "error": "apt-get/apt не найден"}
        # Без TTY ставим неинтерактивно. dnsmasq на Debian при установке
        # пытается слушать порт 53 — это нормально, дальше мы освободим
        # его через DNSStubListener=no и рестартанём.
        env = {"DEBIAN_FRONTEND": "noninteractive"}
        rc, out, err = _run(
            [apt, "install", "-y", "--no-install-recommends", "dnsmasq"],
            timeout=180,
        )
        ok = rc == 0
        return {
            "step":    "install_dnsmasq",
            "ok":      ok,
            "command": "%s install -y dnsmasq" % apt,
            "stdout":  (out or "")[-2000:],
            "stderr":  (err or "")[-2000:] if not ok else "",
        }

    def _step_disable_stub_listener(self) -> dict:
        path = "/etc/systemd/resolved.conf"
        # backup
        backup = path + ".zapret-gui.bak"
        try:
            if os.path.isfile(path) and not os.path.isfile(backup):
                with open(path, "rb") as src, open(backup, "wb") as dst:
                    dst.write(src.read())
        except (IOError, OSError) as e:
            return {"step": "disable_stub_listener", "ok": False,
                    "error": "backup %s: %s" % (path, e)}

        try:
            if os.path.isfile(path):
                with open(path, "r") as f:
                    text = f.read()
            else:
                text = "[Resolve]\n"
        except (IOError, OSError) as e:
            return {"step": "disable_stub_listener", "ok": False,
                    "error": "read %s: %s" % (path, e)}

        new = _set_resolved_option(text, "DNSStubListener", "no")
        try:
            with open(path, "w") as f:
                f.write(new)
        except (IOError, OSError) as e:
            return {"step": "disable_stub_listener", "ok": False,
                    "error": "write %s: %s" % (path, e)}
        return {"step": "disable_stub_listener", "ok": True,
                "backup": backup}

    def _step_point_resolv_to_dnsmasq(self) -> dict:
        """
        Записать в /etc/resolv.conf «nameserver 127.0.0.1».

        Это критично для domain-routing: чтобы dnsmasq мог наполнить
        ipset/nftset при резолве 2ip.ru и т.п., системные DNS-запросы
        должны прилетать ИМЕННО к нему. Если /etc/resolv.conf указывает
        на upstream (DHCP-DNS или resolved-stub'у), приложения резолвят
        домены минуя dnsmasq — и весь domain-routing работает только
        «на бумаге».

        Сохраняем оригинал в …/resolv.conf.zapret-gui.bak для revert.
        Если оригинал был симлинком — запоминаем target, чтобы пересоздать.
        """
        path = "/etc/resolv.conf"
        was_link = False
        prev_target = ""
        backup_path = ""

        # Если уже правильно — ничего не трогаем
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "r") as f:
                    cur = f.read()
                if "nameserver 127.0.0.1" in cur \
                        and "zapret-gui" in cur:
                    return {"step": "point_resolv_to_dnsmasq", "ok": True,
                            "skipped": True,
                            "reason": "/etc/resolv.conf уже указывает на 127.0.0.1"}
        except (IOError, OSError):
            pass

        try:
            if os.path.islink(path):
                was_link = True
                prev_target = os.readlink(path)
                os.remove(path)
            elif os.path.isfile(path):
                bak = path + ".zapret-gui.bak"
                if not os.path.exists(bak):
                    os.rename(path, bak)
                    backup_path = bak
                else:
                    os.remove(path)
            content = (
                "# Generated by zapret-gui (dnsmasq auto-setup)\n"
                "# Revert: остановите последний AWG-интерфейс или нажмите\n"
                "# «Откатить настройку dnsmasq» в Routing.\n"
                "nameserver 127.0.0.1\n"
                "options edns0 trust-ad\n"
            )
            with open(path, "w") as f:
                f.write(content)
            return {"step": "point_resolv_to_dnsmasq", "ok": True,
                    "was_link": was_link,
                    "previous_target": prev_target,
                    "backup": backup_path}
        except OSError as e:
            return {"step": "point_resolv_to_dnsmasq", "ok": False,
                    "error": str(e)}

    def _step_create_default_dnsmasq_conf(self) -> dict:
        path = "/etc/dnsmasq.conf"
        if os.path.isfile(path):
            # Если это НАШ файл (с маркером «Создан zapret-gui») — можем
            # дописать недостающие директивы при апгрейде версии (например
            # user=root, которая нужна для CAP_NET_ADMIN на Debian).
            # Чужой файл не трогаем.
            try:
                with open(path, "r") as f:
                    cur = f.read()
                if "Создан zapret-gui" in cur and "user=root" not in cur:
                    with open(path, "a") as f:
                        f.write(
                            "\n# Добавлено zapret-gui ретроактивно:\n"
                            "# без user=root на Debian dnsmasq дропает\n"
                            "# CAP_NET_ADMIN и не пишет в nftset.\n"
                            "user=root\n"
                            "group=root\n"
                        )
                    return {"step": "create_dnsmasq_conf", "ok": True,
                            "updated": True, "path": path}
            except (IOError, OSError) as e:
                return {"step": "create_dnsmasq_conf", "ok": False,
                        "error": "update %s: %s" % (path, e)}
            return {"step": "create_dnsmasq_conf", "ok": True,
                    "skipped": True,
                    "reason": "файл уже есть, не перезаписываем"}
        content = (
            "# Создан zapret-gui при auto-setup dnsmasq.\n"
            "# Минимальная конфигурация: слушаем 127.0.0.1+::1, пересылаем апстрим.\n"
            "port=53\n"
            "bind-interfaces\n"
            "listen-address=127.0.0.1,::1\n"
            "no-resolv\n"
            "server=1.1.1.1\n"
            "server=1.0.0.1\n"
            "server=2606:4700:4700::1111\n"
            "server=2606:4700:4700::1001\n"
            "cache-size=1000\n"
            "# user=root: без drop-privs у dnsmasq остаётся CAP_NET_ADMIN,\n"
            "# и nftset=/.../inet#awg_routing#... не отваливается тихо.\n"
            "# На Debian default-пакет ставит user=dnsmasq, и без явного\n"
            "# CAP_NET_ADMIN в systemd-юните запись в nftset проваливается.\n"
            "user=root\n"
            "group=root\n"
        )
        try:
            with open(path, "w") as f:
                f.write(content)
            return {"step": "create_dnsmasq_conf", "ok": True,
                    "path": path}
        except (IOError, OSError) as e:
            return {"step": "create_dnsmasq_conf", "ok": False,
                    "error": str(e)}

    def _step_restart_unit(self, unit: str) -> dict:
        sctl = _which("systemctl")
        rc, _o, err = _run([sctl, "restart", unit], timeout=15)
        return {"step": "restart_%s" % unit,
                "ok": rc == 0,
                "error": (err or "").strip() if rc != 0 else ""}

    def _step_start_unit(self, unit: str) -> dict:
        sctl = _which("systemctl")
        rc, _o, err = _run([sctl, "start", unit], timeout=15)
        return {"step": "start_%s" % unit,
                "ok": rc == 0,
                "error": (err or "").strip() if rc != 0 else ""}

    def _step_enable_unit(self, unit: str) -> dict:
        sctl = _which("systemctl")
        rc, _o, err = _run([sctl, "enable", unit], timeout=10)
        return {"step": "enable_%s" % unit,
                "ok": rc == 0,
                "error": (err or "").strip() if rc != 0 else ""}


def _set_resolved_option(text: str, key: str, value: str) -> str:
    """
    Заменить (или добавить) опцию в [Resolve]-секции systemd-resolved.conf.

    Идемпотентно: если ключ уже стоит в нужном значении — текст не
    меняется. Сохраняет комментарии и пустые строки.
    """
    lines = text.splitlines(keepends=True)
    out = []
    in_resolve = False
    key_lower = key.lower()
    replaced = False
    have_resolve_section = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_resolve = (stripped.lower() == "[resolve]")
            if in_resolve:
                have_resolve_section = True
            out.append(line)
            continue
        if in_resolve and not replaced and "=" in stripped \
                and not stripped.startswith("#") and not stripped.startswith(";"):
            k = stripped.partition("=")[0].strip().lower()
            if k == key_lower:
                out.append("%s=%s\n" % (key, value))
                replaced = True
                continue
        # Закомментированную опцию `#DNSStubListener=yes` — раскомментим
        # с нужным значением (типичная заготовка от пакета).
        if in_resolve and not replaced and stripped.startswith("#"):
            inner = stripped.lstrip("#").strip()
            if "=" in inner:
                k = inner.partition("=")[0].strip().lower()
                if k == key_lower:
                    out.append("%s=%s\n" % (key, value))
                    replaced = True
                    continue
        out.append(line)

    if not replaced:
        if not have_resolve_section:
            if out and not out[-1].endswith("\n"):
                out.append("\n")
            out.append("[Resolve]\n")
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append("%s=%s\n" % (key, value))

    return "".join(out)
