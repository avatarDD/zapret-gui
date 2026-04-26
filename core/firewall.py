# core/firewall.py
"""
Менеджер правил Firewall для перенаправления трафика в NFQUEUE.

Поддерживает iptables (Keenetic, старые OpenWrt) и nftables (OpenWrt 22+).
Правила адаптированы из zapret2 common/ipt.sh / common/nft.sh:
  - POSTROUTING -o $IFACE_WAN для исходящего трафика
  - Раздельные правила IPv4 (iptables) и IPv6 (ip6tables)
  - Поддержка нескольких WAN-интерфейсов через пробел

Использование:
    from core.firewall import get_firewall_manager
    fw = get_firewall_manager()
    fw.apply_rules()
    fw.remove_rules()
    fw.get_status()
"""

import os
import re
import shutil
import subprocess
import threading

from core.log_buffer import log


# Имя таблицы nftables
NFT_TABLE = "zapret_gui"

# Маркер комментария iptables для поиска и удаления
IPT_COMMENT = "zapret-gui"


def _detect_wan_from_routes():
    """
    Определить WAN-интерфейс по default route.
    Аналог логики zapret2: sed /proc/net/route | grep dest 00000000.
    """
    ifaces = set()
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split("\t")
                if (len(parts) >= 8
                        and parts[1] == "00000000"
                        and parts[7] == "00000000"):
                    ifaces.add(parts[0])
    except (IOError, OSError):
        pass

    if not ifaces:
        try:
            r = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    m = re.search(r"dev\s+(\S+)", line)
                    if m:
                        ifaces.add(m.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return sorted(ifaces)


def _detect_wan6_from_routes():
    """Определить WAN6-интерфейс по IPv6 default route."""
    ifaces = set()
    try:
        r = subprocess.run(
            ["ip", "-6", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.split("\n"):
                m = re.search(r"dev\s+(\S+)", line)
                if m:
                    ifaces.add(m.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return sorted(ifaces)


class FirewallManager:
    """
    Управление правилами firewall для NFQUEUE.

    Автоопределяет тип (iptables/nftables), получает WAN-интерфейсы
    из конфига (с fallback на auto-detect) и применяет/снимает правила.
    """

    # Кэш формы -w флага по бинарнику. iptables ≥1.6 принимает «-w SECONDS»,
    # iptables ≤1.4.x (Entware/Keenetic) — только «-w» без значения.
    _wait_flag_cache: dict = {}

    def __init__(self):
        self._lock = threading.Lock()
        self._applied = False
        self._fw_type = None          # "iptables" | "nftables" | None
        self._rules_info = []         # Для UI

    # ─────────────────────────── public API ───────────────────────────

    def detect_fw_type(self) -> str:
        """Определить тип firewall: iptables / nftables / None."""
        if self._fw_type:
            return self._fw_type

        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        fw_cfg = cfg.get("firewall", "type", default="auto")

        if fw_cfg in ("iptables", "nftables"):
            self._fw_type = fw_cfg
        else:
            self._fw_type = self._auto_detect()

        log.info("Тип firewall: %s" % (self._fw_type or "не определён"),
                 source="firewall")
        return self._fw_type

    def apply_rules(self, queue_num=None, ports_tcp=None,
                    ports_udp=None, mark=None) -> bool:
        """
        Применить правила NFQUEUE с привязкой к WAN-интерфейсам.

        Параметры берутся из аргументов или конфига.
        WAN-интерфейсы берутся из config.interfaces.wan/wan6
        с fallback на авто-определение по таблице маршрутов.
        """
        with self._lock:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            qnum = queue_num or int(cfg.get("nfqws", "queue_num", default=300))
            tcp = ports_tcp or cfg.get("nfqws", "ports_tcp", default="80,443")
            udp = ports_udp or cfg.get("nfqws", "ports_udp", default="443")
            fwmark = mark or cfg.get("nfqws", "desync_mark",
                                     default="0x40000000")
            tcp_pkt = int(cfg.get("nfqws", "tcp_pkt_out", default=20))
            udp_pkt = int(cfg.get("nfqws", "udp_pkt_out", default=5))
            disable_ipv6 = cfg.get("nfqws", "disable_ipv6", default=True)

            # WAN-интерфейсы из конфига или auto-detect
            wan4 = self._get_wan_interfaces(cfg, "wan")
            wan6 = None if disable_ipv6 else self._get_wan_interfaces(cfg, "wan6")

            # Fallback: wan6 = wan4 (как в zapret2: IFACE_WAN6 = IFACE_WAN)
            if wan6 is not None and not wan6:
                wan6 = wan4

            fw_type = self.detect_fw_type()
            if not fw_type:
                log.error("Тип firewall не определён", source="firewall")
                return False

            # Снимаем старые правила
            self._remove_rules_locked(fw_type)

            wan_info = ", ".join(wan4) if wan4 else "все"
            log.info("Применяем правила %s (WAN: %s)..." % (fw_type, wan_info),
                     source="firewall")

            try:
                if fw_type == "iptables":
                    ok = self._apply_iptables(
                        qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt,
                        wan4, wan6
                    )
                else:
                    ok = self._apply_nftables(
                        qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt,
                        wan4, wan6
                    )

                if ok:
                    self._applied = True
                    log.success("Правила firewall применены", source="firewall")
                else:
                    log.error("Ошибка при применении правил", source="firewall")
                return ok

            except Exception as e:
                log.error("Исключение при применении правил: %s" % e,
                          source="firewall")
                return False

    def remove_rules(self) -> bool:
        """Снять все правила NFQUEUE, установленные GUI."""
        with self._lock:
            fw_type = self.detect_fw_type()
            if not fw_type:
                return True
            return self._remove_rules_locked(fw_type)

    def get_rules(self) -> list:
        """Получить текущие NFQUEUE-правила из системы."""
        fw_type = self.detect_fw_type()
        if not fw_type:
            return []
        try:
            if fw_type == "iptables":
                return self._get_iptables_rules()
            else:
                return self._get_nftables_rules()
        except Exception as e:
            log.warning("Не удалось получить правила: %s" % e,
                        source="firewall")
            return []

    def is_applied(self) -> bool:
        """Применены ли правила GUI."""
        rules = self.get_rules()
        has_rules = any(IPT_COMMENT in r or NFT_TABLE in r for r in rules)
        self._applied = has_rules
        return has_rules

    def get_status(self) -> dict:
        """Полный статус для API."""
        fw_type = self.detect_fw_type()
        applied = self.is_applied()
        rules = self.get_rules() if applied else []

        return {
            "type": fw_type,
            "applied": applied,
            "rules": rules,
            "rules_count": len(rules),
        }

    # ──────────────── WAN interfaces ────────────────

    @staticmethod
    def _get_wan_interfaces(cfg, role):
        """
        Получить список WAN-интерфейсов из конфига или авто-определить.

        Args:
            cfg:  ConfigManager
            role: "wan" или "wan6"

        Returns:
            list[str] — имена интерфейсов (пустой = все интерфейсы)
        """
        val = cfg.get("interfaces", role, default="")
        if isinstance(val, str):
            val = val.strip()

        if val:
            return val.split()

        # Auto-detect
        if role == "wan6":
            detected = _detect_wan6_from_routes()
            if detected:
                return detected
            # Fallback wan6 → wan будет в apply_rules
            return []
        else:
            return _detect_wan_from_routes()

    # ──────────────── auto-detect fw type ────────────────

    @staticmethod
    def _auto_detect() -> str:
        """Автоопределение: iptables vs nftables."""
        has_ipt = shutil.which("iptables") is not None
        has_nft = shutil.which("nft") is not None

        if has_ipt and not has_nft:
            return "iptables"
        if has_nft and not has_ipt:
            return "nftables"
        # Обе — предпочитаем iptables (совместимость с Keenetic/Entware)
        if has_ipt:
            return "iptables"
        if has_nft:
            return "nftables"

        log.warning("Ни iptables, ни nft не найдены!", source="firewall")
        return None

    # ──────────────── iptables implementation ────────────────

    def _apply_iptables(self, qnum, ports_tcp, ports_udp,
                        fwmark, tcp_pkt, udp_pkt,
                        wan4_ifaces, wan6_ifaces) -> bool:
        """
        Применить правила iptables с привязкой к WAN-интерфейсам.

        Для каждого WAN-интерфейса создаётся отдельное правило `-o $iface`.
        Если список пуст — правило без -o (перехват на всех интерфейсах).
        IPv4: iptables, IPv6: ip6tables.
        """
        rules = []
        ok = True

        # --- IPv4 (iptables) ---
        ok &= self._apply_ipt_family(
            "iptables", qnum, ports_tcp, ports_udp,
            fwmark, tcp_pkt, udp_pkt, wan4_ifaces, rules
        )

        # --- IPv6 (ip6tables) ---
        if wan6_ifaces is not None:
            ok &= self._apply_ipt_family(
                "ip6tables", qnum, ports_tcp, ports_udp,
                fwmark, tcp_pkt, udp_pkt, wan6_ifaces, rules
            )

        self._rules_info = rules
        return ok

    def _apply_ipt_family(self, ipt_cmd, qnum, ports_tcp, ports_udp,
                          fwmark, tcp_pkt, udp_pkt, wan_ifaces, rules):
        """
        Применить правила для одного семейства (iptables / ip6tables).

        Аналог zapret2 _fw_nfqws_post4 / _fw_nfqws_post6:
          - Если wan_ifaces не пуст: для каждого -o $iface отдельное правило
          - Если пуст: правило без -o (все интерфейсы)
        """
        ok = True
        family_tag = "IPv4" if ipt_cmd == "iptables" else "IPv6"

        # Проверяем доступность команды
        if not shutil.which(ipt_cmd):
            log.warning("%s не найден, пропускаем %s" % (ipt_cmd, family_tag),
                        source="firewall")
            return True  # Не ошибка — просто нет поддержки

        # Для каждого WAN или без -o
        oif_list = wan_ifaces if wan_ifaces else [None]

        for oif in oif_list:
            oif_args = ["-o", oif] if oif else []
            oif_tag = " -o %s" % oif if oif else " (все)"

            # 1) ACCEPT для помеченных (не зацикливать)
            cmd = [
                ipt_cmd, "-t", "mangle", "-I", "POSTROUTING",
            ] + oif_args + [
                "-m", "mark", "--mark", "%s/%s" % (fwmark, fwmark),
                "-m", "comment", "--comment", IPT_COMMENT,
                "-j", "ACCEPT"
            ]
            if self._run_cmd(cmd):
                rules.append("%s ACCEPT mark%s" % (family_tag, oif_tag))
            else:
                ok = False

            # 2) TCP → NFQUEUE
            if ports_tcp:
                cmd = [
                    ipt_cmd, "-t", "mangle", "-A", "POSTROUTING",
                ] + oif_args + [
                    "-p", "tcp",
                    "-m", "multiport", "--dports", ports_tcp,
                    "-m", "connbytes", "--connbytes-dir=original",
                    "--connbytes-mode=packets",
                    "--connbytes", "1:%d" % tcp_pkt,
                    "-m", "comment", "--comment", IPT_COMMENT,
                    "-j", "NFQUEUE",
                    "--queue-num", str(qnum),
                    "--queue-bypass"
                ]
                if self._run_cmd(cmd):
                    rules.append("%s TCP %s → NFQUEUE %d%s" % (
                        family_tag, ports_tcp, qnum, oif_tag))
                else:
                    ok = False

            # 3) UDP → NFQUEUE
            if ports_udp:
                cmd = [
                    ipt_cmd, "-t", "mangle", "-A", "POSTROUTING",
                ] + oif_args + [
                    "-p", "udp",
                    "-m", "multiport", "--dports", ports_udp,
                    "-m", "connbytes", "--connbytes-dir=original",
                    "--connbytes-mode=packets",
                    "--connbytes", "1:%d" % udp_pkt,
                    "-m", "comment", "--comment", IPT_COMMENT,
                    "-j", "NFQUEUE",
                    "--queue-num", str(qnum),
                    "--queue-bypass"
                ]
                if self._run_cmd(cmd):
                    rules.append("%s UDP %s → NFQUEUE %d%s" % (
                        family_tag, ports_udp, qnum, oif_tag))
                else:
                    ok = False

        return ok

    def _remove_iptables(self) -> bool:
        """Удалить все правила iptables/ip6tables с комментарием zapret-gui."""
        ok = True
        for ipt_cmd in ("iptables", "ip6tables"):
            if not shutil.which(ipt_cmd):
                continue
            ok &= self._remove_ipt_family(ipt_cmd)
        self._rules_info = []
        return ok

    def _remove_ipt_family(self, ipt_cmd) -> bool:
        """Удалить правила одного семейства (несколько проходов)."""
        for _ in range(20):
            found = False
            try:
                result = subprocess.run(
                    [ipt_cmd, "-t", "mangle", "-L", "POSTROUTING",
                     "--line-numbers", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    break

                for line in reversed(result.stdout.splitlines()):
                    if IPT_COMMENT in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            self._run_cmd([
                                ipt_cmd, "-t", "mangle",
                                "-D", "POSTROUTING", parts[0]
                            ])
                            found = True
            except Exception:
                break

            if not found:
                break

        return True

    def _get_iptables_rules(self) -> list:
        """Получить текущие NFQUEUE-правила iptables + ip6tables."""
        rules = []
        for ipt_cmd in ("iptables", "ip6tables"):
            if not shutil.which(ipt_cmd):
                continue
            try:
                result = subprocess.run(
                    [ipt_cmd, "-t", "mangle", "-L", "POSTROUTING",
                     "-n", "-v", "--line-numbers"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "NFQUEUE" in line or IPT_COMMENT in line:
                            rules.append(line.strip())
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        return rules

    # ──────────────── nftables implementation ────────────────

    def _apply_nftables(self, qnum, ports_tcp, ports_udp,
                        fwmark, tcp_pkt, udp_pkt,
                        wan4_ifaces, wan6_ifaces) -> bool:
        """
        Применить правила nftables с привязкой к WAN-интерфейсам.

        В nftables правила inet-семейства работают для обоих протоколов.
        Фильтр интерфейса: `oifname { "eth0", "eth1" }`.
        """
        cmds = []

        # Создаём таблицу и цепочку
        cmds.append("add table inet %s" % NFT_TABLE)
        cmds.append(
            "add chain inet %s postrouting "
            "{ type filter hook postrouting priority 150 ; }" % NFT_TABLE
        )

        # Собираем уникальные WAN-интерфейсы для oifname
        all_wan = set(wan4_ifaces or [])
        if wan6_ifaces:
            all_wan.update(wan6_ifaces)
        oif_filter = ""
        if all_wan:
            if len(all_wan) == 1:
                # Один интерфейс — без фигурных скобок
                oif_filter = "oifname %s " % list(all_wan)[0]
            else:
                # Несколько — множество nft
                oif_filter = "oifname { %s } " % ", ".join(sorted(all_wan))

        # ACCEPT для помеченных пакетов
        cmds.append(
            "add rule inet %s postrouting %s"
            "meta mark and %s == %s accept" % (
                NFT_TABLE, oif_filter, fwmark, fwmark)
        )

        # TCP → NFQUEUE
        if ports_tcp:
            ports_nft = "{ %s }" % ports_tcp
            cmds.append(
                "add rule inet %s postrouting %s"
                "tcp dport %s ct original packets 1-%d "
                "queue num %d bypass" % (
                    NFT_TABLE, oif_filter, ports_nft, tcp_pkt, qnum)
            )

        # UDP → NFQUEUE
        if ports_udp:
            ports_nft = "{ %s }" % ports_udp
            cmds.append(
                "add rule inet %s postrouting %s"
                "udp dport %s ct original packets 1-%d "
                "queue num %d bypass" % (
                    NFT_TABLE, oif_filter, ports_nft, udp_pkt, qnum)
            )

        ok = True
        rules = []
        for cmd in cmds:
            if self._run_cmd(["nft"] + cmd.split()):
                rules.append("nft " + cmd)
            else:
                ok = False

        self._rules_info = rules
        return ok

    def _remove_nftables(self) -> bool:
        """Удалить таблицу nftables."""
        result = self._run_cmd(["nft", "delete", "table", "inet", NFT_TABLE])
        self._rules_info = []
        return result

    def _get_nftables_rules(self) -> list:
        """Получить текущие правила nftables."""
        rules = []
        try:
            result = subprocess.run(
                ["nft", "list", "table", "inet", NFT_TABLE],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("table") and line != "}":
                        rules.append(line)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return rules

    # ──────────────── dispatcher ────────────────

    def _remove_rules_locked(self, fw_type) -> bool:
        """Снять правила (вызывается под lock)."""
        log.info("Снимаем правила firewall (%s)..." % fw_type,
                 source="firewall")
        try:
            if fw_type == "iptables":
                ok = self._remove_iptables()
            else:
                ok = self._remove_nftables()

            if ok:
                self._applied = False
                log.info("Правила firewall сняты", source="firewall")
            else:
                log.warning("Возможны проблемы при снятии правил",
                            source="firewall")
            return ok
        except Exception as e:
            log.error("Ошибка при снятии правил: %s" % e, source="firewall")
            return False

    # ──────────────── utils ────────────────

    @classmethod
    def _iptables_wait_flag(cls, ipt_path: str) -> list:
        """Подобрать форму -w для конкретного бинарника iptables/ip6tables.

        Возвращает один из вариантов:
          ["-w", "5"]  — современный iptables (≥1.6), таймаут 5 секунд
          ["-w"]       — старый iptables (Entware/Keenetic 1.4.x), boolean
          []           — `-w` совсем не поддерживается; шансов меньше, но
                         продолжаем без него (есть риск xtables-lock).

        Результат кэшируется по абсолютному пути бинарника.
        """
        cached = cls._wait_flag_cache.get(ipt_path)
        if cached is not None:
            return list(cached)

        flag: list = []
        try:
            res = subprocess.run(
                [ipt_path, "--help"],
                capture_output=True, text=True, timeout=3,
            )
            help_text = (res.stdout or "") + (res.stderr or "")
            # iptables ≥1.6: "  --wait -w [seconds]" / "-w[SECONDS]" / похожее
            if re.search(r"-w\s*\[\s*seconds?\s*\]", help_text, re.IGNORECASE):
                flag = ["-w", "5"]
            # iptables 1.4.x: "--wait -w  wait for the xtables lock"
            elif re.search(r"--wait\b|\b-w\b", help_text):
                flag = ["-w"]
            else:
                flag = []
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            flag = []

        cls._wait_flag_cache[ipt_path] = list(flag)
        log.debug(
            "iptables wait flag для %s: %s" % (
                ipt_path, " ".join(flag) or "(не поддерживается)"
            ),
            source="firewall",
        )
        return list(flag)

    @staticmethod
    def _run_cmd(cmd) -> bool:
        """Выполнить команду. True если успешно.

        Для iptables/ip6tables подмешиваем `-w` сразу после имени бинарника:
        иначе сканер, быстро снимающий и применяющий правила, упирается в
        xtables-lock и получает «Another app is currently holding the xtables
        lock». Старые сборки iptables (Entware/Keenetic, 1.4.x) принимают
        `-w` как **boolean без аргумента** — `-w 5` для них означает «ждать
        + первая позиционная опция = 5», что отдаёт «Bad argument `5'».
        Поэтому форму выбираем по детекции (см. _iptables_wait_flag).
        """
        is_iptables = (
            cmd and os.path.basename(cmd[0]) in ("iptables", "ip6tables")
        )
        if is_iptables and "-w" not in cmd:
            wait_flag = FirewallManager._iptables_wait_flag(cmd[0])
            cmd = [cmd[0]] + wait_flag + cmd[1:]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()

                # Runtime-fallback: старые iptables (Entware/Keenetic 1.4.x)
                # принимают «-w» только как boolean. Если сейчас передали
                # `-w 5` и получили «Bad argument `5'» — понижаем форму до
                # «-w» и пробуем ещё раз. Кэш снижается до конца жизни
                # процесса.
                if (is_iptables and "Bad argument" in stderr
                        and "-w" in cmd and "5" in cmd):
                    log.info(
                        "iptables не принимает «-w 5», переходим на «-w»",
                        source="firewall",
                    )
                    FirewallManager._wait_flag_cache[cmd[0]] = ["-w"]
                    fixed = [a for a in cmd if a != "5"]
                    try:
                        result = subprocess.run(
                            fixed, capture_output=True, text=True, timeout=10,
                        )
                        if result.returncode == 0:
                            return True
                        stderr = result.stderr.strip()
                        cmd = fixed
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        pass

                if "No such file" not in stderr \
                        and "does not exist" not in stderr:
                    log.warning("Команда %s: %s" % (
                        " ".join(cmd[:3]) + "...", stderr
                    ), source="firewall")
                return False
            return True
        except subprocess.TimeoutExpired:
            log.error("Таймаут: %s" % " ".join(cmd[:3]), source="firewall")
            return False
        except FileNotFoundError:
            log.error("Не найдена: %s" % cmd[0], source="firewall")
            return False


# === Глобальный экземпляр ===

_fw_manager = None
_fw_lock = threading.Lock()


def get_firewall_manager() -> FirewallManager:
    """Получить глобальный экземпляр FirewallManager."""
    global _fw_manager
    if _fw_manager is None:
        with _fw_lock:
            if _fw_manager is None:
                _fw_manager = FirewallManager()
    return _fw_manager
