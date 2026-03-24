# core/firewall.py
"""
Менеджер правил Firewall для перенаправления трафика в NFQUEUE.

Поддерживает iptables (Keenetic, старые OpenWrt) и nftables (OpenWrt 22+).
Правила адаптированы из zapret2 common/ipt.sh / common/nft.sh.

Использование:
    from core.firewall import get_firewall_manager
    fw = get_firewall_manager()
    fw.apply_rules()
    fw.remove_rules()
    fw.get_status()
"""

import os
import shutil
import subprocess
import threading

from core.log_buffer import log


# Имя цепочки/таблицы для nftables
NFT_TABLE = "zapret_gui"

# Комментарий-маркер для iptables правил (для поиска и удаления)
IPT_COMMENT = "zapret-gui"


class FirewallManager:
    """
    Управление правилами firewall для NFQUEUE.

    Автоопределяет тип (iptables / nftables), применяет и снимает правила.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._applied = False
        self._fw_type = None          # "iptables" | "nftables" | None
        self._rules_info = []         # Список применённых правил (для UI)

    # ─────────────────────────── public API ───────────────────────────

    def detect_fw_type(self) -> str:
        """
        Определить тип firewall.

        Returns:
            "iptables" | "nftables" | None
        """
        if self._fw_type:
            return self._fw_type

        from core.config_manager import get_config_manager
        cfg = get_config_manager()

        fw_cfg = cfg.get("firewall", "type", default="auto")

        if fw_cfg == "iptables":
            self._fw_type = "iptables"
        elif fw_cfg == "nftables":
            self._fw_type = "nftables"
        elif fw_cfg == "auto":
            self._fw_type = self._auto_detect()
        else:
            self._fw_type = self._auto_detect()

        log.info("Тип firewall: %s" % (self._fw_type or "не определён"),
                 source="firewall")
        return self._fw_type

    def apply_rules(self, queue_num: int = None, ports_tcp: str = None,
                    ports_udp: str = None, mark: str = None) -> bool:
        """
        Применить правила NFQUEUE.

        Args:
            queue_num: Номер очереди NFQUEUE (default из конфига).
            ports_tcp:  TCP порты, через запятую (default из конфига).
            ports_udp:  UDP порты, через запятую (default из конфига).
            mark:       Метка fwmark для обхода зацикливания.

        Returns:
            True если правила применены.
        """
        with self._lock:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()

            qnum = queue_num or int(cfg.get("nfqws", "queue_num", default=300))
            tcp = ports_tcp or cfg.get("nfqws", "ports_tcp", default="80,443")
            udp = ports_udp or cfg.get("nfqws", "ports_udp", default="443")
            fwmark = mark or cfg.get("nfqws", "desync_mark",
                                     default="0x40000000")

            # Параметры connbytes из конфига
            tcp_pkt = int(cfg.get("nfqws", "tcp_pkt_out", default=20))
            udp_pkt = int(cfg.get("nfqws", "udp_pkt_out", default=5))

            # Определяем тип FW
            fw_type = self.detect_fw_type()
            if not fw_type:
                log.error("Тип firewall не определён — невозможно "
                          "применить правила", source="firewall")
                return False

            # Сначала снимаем старые правила (если есть)
            self._remove_rules_locked(fw_type)

            log.info("Применяем правила firewall (%s)..." % fw_type,
                     source="firewall")

            try:
                if fw_type == "iptables":
                    ok = self._apply_iptables(
                        qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt
                    )
                else:
                    ok = self._apply_nftables(
                        qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt
                    )

                if ok:
                    self._applied = True
                    log.success("Правила firewall применены", source="firewall")
                else:
                    log.error("Ошибка при применении правил firewall",
                              source="firewall")
                return ok

            except Exception as e:
                log.error("Исключение при применении правил: %s" % e,
                          source="firewall")
                return False

    def remove_rules(self) -> bool:
        """
        Снять все правила NFQUEUE, установленные GUI.

        Returns:
            True если правила сняты.
        """
        with self._lock:
            fw_type = self.detect_fw_type()
            if not fw_type:
                return True
            return self._remove_rules_locked(fw_type)

    def get_rules(self) -> list:
        """
        Получить текущие NFQUEUE-правила из системы.

        Returns:
            Список строк с правилами.
        """
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
        # Перепроверяем реальное состояние
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

    # ──────────────── auto-detect ────────────────

    def _auto_detect(self) -> str:
        """Автоопределение: iptables vs nftables."""
        # Проверяем наличие команд
        has_ipt = shutil.which("iptables") is not None
        has_nft = shutil.which("nft") is not None

        if has_ipt and not has_nft:
            return "iptables"
        if has_nft and not has_ipt:
            return "nftables"

        # Обе есть — предпочитаем iptables (совместимость с Keenetic)
        if has_ipt:
            return "iptables"
        if has_nft:
            return "nftables"

        log.warning("Ни iptables, ни nft не найдены!", source="firewall")
        return None

    # ──────────────── iptables implementation ────────────────

    def _apply_iptables(self, qnum, ports_tcp, ports_udp,
                        fwmark, tcp_pkt, udp_pkt) -> bool:
        """Применить правила iptables."""
        rules = []
        ok = True

        # 1) Правило ACCEPT для помеченных пакетов (не зацикливать)
        cmd_mark = [
            "iptables", "-t", "mangle", "-I", "POSTROUTING",
            "-m", "mark", "--mark", "%s/%s" % (fwmark, fwmark),
            "-m", "comment", "--comment", IPT_COMMENT,
            "-j", "ACCEPT"
        ]
        if self._run_cmd(cmd_mark):
            rules.append("ACCEPT mark %s" % fwmark)
        else:
            ok = False

        # 2) TCP → NFQUEUE
        if ports_tcp:
            cmd_tcp = [
                "iptables", "-t", "mangle", "-I", "POSTROUTING",
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
            if self._run_cmd(cmd_tcp):
                rules.append("TCP %s → NFQUEUE %d" % (ports_tcp, qnum))
            else:
                ok = False

        # 3) UDP → NFQUEUE
        if ports_udp:
            cmd_udp = [
                "iptables", "-t", "mangle", "-I", "POSTROUTING",
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
            if self._run_cmd(cmd_udp):
                rules.append("UDP %s → NFQUEUE %d" % (ports_udp, qnum))
            else:
                ok = False

        self._rules_info = rules
        return ok

    def _remove_iptables(self) -> bool:
        """Удалить все правила iptables с комментарием zapret-gui."""
        ok = True
        # Итерируем по правилам mangle POSTROUTING и удаляем наши
        # Делаем несколько проходов (т.к. номера строк сдвигаются)
        for _ in range(10):
            found = False
            try:
                result = subprocess.run(
                    ["iptables", "-t", "mangle", "-L", "POSTROUTING",
                     "--line-numbers", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    break

                # Парсим строки, ищем наш комментарий
                for line in reversed(result.stdout.splitlines()):
                    if IPT_COMMENT in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            num = parts[0]
                            del_cmd = [
                                "iptables", "-t", "mangle",
                                "-D", "POSTROUTING", num
                            ]
                            self._run_cmd(del_cmd)
                            found = True
            except Exception:
                break

            if not found:
                break

        self._rules_info = []
        return ok

    def _get_iptables_rules(self) -> list:
        """Получить текущие NFQUEUE-правила iptables."""
        rules = []
        try:
            result = subprocess.run(
                ["iptables", "-t", "mangle", "-L", "POSTROUTING",
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
                        fwmark, tcp_pkt, udp_pkt) -> bool:
        """Применить правила nftables."""
        cmds = []

        # Создаём таблицу и цепочку
        cmds.append("nft add table inet %s" % NFT_TABLE)
        cmds.append(
            "nft add chain inet %s postrouting "
            "{ type filter hook postrouting priority 150 \\; }" % NFT_TABLE
        )

        # ACCEPT для помеченных пакетов
        cmds.append(
            "nft add rule inet %s postrouting "
            "meta mark and %s == %s accept" % (NFT_TABLE, fwmark, fwmark)
        )

        # TCP → NFQUEUE
        if ports_tcp:
            ports_nft = "{ %s }" % ports_tcp
            cmds.append(
                "nft add rule inet %s postrouting "
                "tcp dport %s ct original packets 1-%d "
                "queue num %d bypass" % (
                    NFT_TABLE, ports_nft, tcp_pkt, qnum
                )
            )

        # UDP → NFQUEUE
        if ports_udp:
            ports_nft = "{ %s }" % ports_udp
            cmds.append(
                "nft add rule inet %s postrouting "
                "udp dport %s ct original packets 1-%d "
                "queue num %d bypass" % (
                    NFT_TABLE, ports_nft, udp_pkt, qnum
                )
            )

        ok = True
        rules = []
        for cmd in cmds:
            if self._run_cmd(cmd.split()):
                rules.append(cmd)
            else:
                ok = False

        self._rules_info = rules
        return ok

    def _remove_nftables(self) -> bool:
        """Удалить таблицу nftables."""
        cmd = ["nft", "delete", "table", "inet", NFT_TABLE]
        result = self._run_cmd(cmd)
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
                    if line and not line.startswith("table") \
                            and not line == "}":
                        rules.append(line)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return rules

    # ──────────────── dispatcher ────────────────

    def _remove_rules_locked(self, fw_type) -> bool:
        """Снять правила (вызывается под lock или из apply_rules)."""
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

    @staticmethod
    def _run_cmd(cmd: list) -> bool:
        """Выполнить команду. True если успешно."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                stderr = result.stderr.strip()
                # Не логируем "table not found" при удалении
                if "No such file" not in stderr \
                        and "does not exist" not in stderr:
                    log.warning("Команда %s: %s" % (
                        " ".join(cmd[:3]) + "...", stderr
                    ), source="firewall")
                return False
            return True
        except subprocess.TimeoutExpired:
            log.error("Таймаут команды: %s" % " ".join(cmd[:3]),
                      source="firewall")
            return False
        except FileNotFoundError:
            log.error("Команда не найдена: %s" % cmd[0], source="firewall")
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


