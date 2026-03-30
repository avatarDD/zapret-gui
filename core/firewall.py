import os
import re
import shutil
import subprocess
import threading
from core.log_buffer import log
NFT_TABLE = "zapret_gui"
IPT_COMMENT = "zapret-gui"
def _detect_wan_from_routes():
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
    def __init__(self):
        self._lock = threading.Lock()
        self._applied = False
        self._fw_type = None          # "iptables" | "nftables" | None
        self._rules_info = []
    def detect_fw_type(self) -> str:
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
            wan4 = self._get_wan_interfaces(cfg, "wan")
            wan6 = None if disable_ipv6 else self._get_wan_interfaces(cfg, "wan6")
            if wan6 is not None and not wan6:
                wan6 = wan4
            fw_type = self.detect_fw_type()
            if not fw_type:
                log.error("Тип firewall не определён", source="firewall")
                return False
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
        with self._lock:
            fw_type = self.detect_fw_type()
            if not fw_type:
                return True
            return self._remove_rules_locked(fw_type)
    def get_rules(self) -> list:
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
        rules = self.get_rules()
        has_rules = any(IPT_COMMENT in r or NFT_TABLE in r for r in rules)
        self._applied = has_rules
        return has_rules
    def get_status(self) -> dict:
        fw_type = self.detect_fw_type()
        applied = self.is_applied()
        rules = self.get_rules() if applied else []
        return {
            "type": fw_type,
            "applied": applied,
            "rules": rules,
            "rules_count": len(rules),
        }
    @staticmethod
    def _get_wan_interfaces(cfg, role):
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
            return []
        else:
            return _detect_wan_from_routes()
    @staticmethod
    def _auto_detect() -> str:
        has_ipt = shutil.which("iptables") is not None
        has_nft = shutil.which("nft") is not None
        if has_ipt and not has_nft:
            return "iptables"
        if has_nft and not has_ipt:
            return "nftables"
        if has_ipt:
            return "iptables"
        if has_nft:
            return "nftables"
        log.warning("Ни iptables, ни nft не найдены!", source="firewall")
        return None
    def _apply_iptables(self, qnum, ports_tcp, ports_udp,
                        fwmark, tcp_pkt, udp_pkt,
                        wan4_ifaces, wan6_ifaces) -> bool:
        rules = []
        ok = True
        ok &= self._apply_ipt_family(
            "iptables", qnum, ports_tcp, ports_udp,
            fwmark, tcp_pkt, udp_pkt, wan4_ifaces, rules
        )
        if wan6_ifaces is not None:
            ok &= self._apply_ipt_family(
                "ip6tables", qnum, ports_tcp, ports_udp,
                fwmark, tcp_pkt, udp_pkt, wan6_ifaces, rules
            )
        self._rules_info = rules
        return ok
    def _apply_ipt_family(self, ipt_cmd, qnum, ports_tcp, ports_udp,
                          fwmark, tcp_pkt, udp_pkt, wan_ifaces, rules):
        ok = True
        family_tag = "IPv4" if ipt_cmd == "iptables" else "IPv6"
        if not shutil.which(ipt_cmd):
            log.warning("%s не найден, пропускаем %s" % (ipt_cmd, family_tag),
                        source="firewall")
            return True
        oif_list = wan_ifaces if wan_ifaces else [None]
        for oif in oif_list:
            oif_args = ["-o", oif] if oif else []
            oif_tag = " -o %s" % oif if oif else " (все)"
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
        ok = True
        for ipt_cmd in ("iptables", "ip6tables"):
            if not shutil.which(ipt_cmd):
                continue
            ok &= self._remove_ipt_family(ipt_cmd)
        self._rules_info = []
        return ok
    def _remove_ipt_family(self, ipt_cmd) -> bool:
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
    def _apply_nftables(self, qnum, ports_tcp, ports_udp,
                        fwmark, tcp_pkt, udp_pkt,
                        wan4_ifaces, wan6_ifaces) -> bool:
        cmds = []
        cmds.append("add table inet %s" % NFT_TABLE)
        cmds.append(
            "add chain inet %s postrouting "
            "{ type filter hook postrouting priority 150 ; }" % NFT_TABLE
        )
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
        if ports_tcp:
            ports_nft = "{ %s }" % ports_tcp
            cmds.append(
                "add rule inet %s postrouting %s"
                "tcp dport %s ct original packets 1-%d "
                "queue num %d bypass" % (
                    NFT_TABLE, oif_filter, ports_nft, tcp_pkt, qnum)
            )
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
        result = self._run_cmd(["nft", "delete", "table", "inet", NFT_TABLE])
        self._rules_info = []
        return result
    def _get_nftables_rules(self) -> list:
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
    def _remove_rules_locked(self, fw_type) -> bool:
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
    @staticmethod
    def _run_cmd(cmd) -> bool:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
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
_fw_manager = None
_fw_lock = threading.Lock()
def get_firewall_manager() -> FirewallManager:
    global _fw_manager
    if _fw_manager is None:
        with _fw_lock:
            if _fw_manager is None:
                _fw_manager = FirewallManager()
    return _fw_manager
