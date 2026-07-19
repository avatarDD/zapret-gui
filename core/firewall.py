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


def _nft_port_set(spec: str) -> str:
    """
    Преобразовать iptables/multiport-список портов в nftables-синтаксис.

    Диапазоны в nft записываются через дефис (`3478-3481`), тогда как
    iptables-multiport и наш конфиг используют двоеточие (`3478:3481`).
    Без конверсии nft падает с «Could not resolve service: Servname not
    supported for ai_socktype» (issue #101).

      "443,3478:3481,5349"  →  "443, 3478-3481, 5349"
    """
    parts = []
    for tok in str(spec or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        parts.append(tok.replace(":", "-"))
    return ", ".join(parts)


# При запуске от обычного пользователя на Debian/Ubuntu (`python3 app.py`)
# в PATH отсутствуют /sbin и /usr/sbin, где живут iptables/nft. Из-за
# этого shutil.which() и subprocess не находят бинарники, и весь модуль
# работает «в холостую» с ошибкой "Ни iptables, ни nft не найдены".
# Дополняем PATH общеизвестными sbin-каталогами один раз при импорте.
def _ensure_sbin_in_path():
    extra = ["/usr/local/sbin", "/usr/sbin", "/sbin"]
    cur = os.environ.get("PATH", "")
    parts = cur.split(os.pathsep) if cur else []
    added = [d for d in extra if d not in parts and os.path.isdir(d)]
    if added:
        os.environ["PATH"] = os.pathsep.join(parts + added)


_ensure_sbin_in_path()


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

    # Кэш поддержки матча `-m comment` (xt_comment) по бинарнику. На
    # Entware/Keenetic это отдельный пакет iptables-mod-comment, которого
    # часто нет — тогда КАЖДОЕ правило с `-m comment` падает с
    # «No chain/target/match by that name» и обход не поднимается (issue #151).
    # При положительном детекте отсутствия — переходим на именованные цепочки.
    _comment_support_cache: dict = {}

    # Кэш поддержки матчей/целей, которые на Entware/Keenetic нередко вынесены
    # в отдельные (часто отсутствующие и неустанавливаемые через opkg) модули
    # ядра:
    #   multiport → iptables-mod-multiport (xt_multiport)
    #   connbytes → iptables-mod-conntrack-extra (xt_connbytes)
    #   NFQUEUE   → iptables-mod-nfqueue (xt_NFQUEUE / nfnetlink_queue)
    # Без них правила с этими матчами/целью падали с «No chain/target/match by
    # that name», и обход не поднимался даже после фикса `-m comment` — ровно
    # 9 правил из 14 (все порт-зависимые) (issue #151). Деградируем:
    #   нет multiport → список портов бьём на отдельные --dport/--sport;
    #   нет connbytes → выкидываем ограничитель первых пакетов;
    #   нет NFQUEUE   → обход через iptables невозможен (громкая ошибка).
    _multiport_support_cache: dict = {}
    _connbytes_support_cache: dict = {}
    _nfqueue_support_cache: dict = {}

    def __init__(self):
        self._lock = threading.Lock()
        self._applied = False
        self._fw_type = None          # "iptables" | "nftables" | None
        self._rules_info = []         # Для UI
        # Доп. параметры для PREROUTING / NAT / TCP-флагов (заполняется в
        # apply_rules). Дефолты — на случай прямого вызова _apply_* в тестах.
        self._extra = {
            "tcp_pkt_in": 10,
            "udp_pkt_in": 3,
            "mark_exclude": "0x20000000",
        }

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
            tcp_pkt_in = int(cfg.get("nfqws", "tcp_pkt_in", default=10))
            udp_pkt_in = int(cfg.get("nfqws", "udp_pkt_in", default=3))
            mark_exclude = cfg.get("nfqws", "desync_mark_postnat",
                                   default="0x20000000")
            disable_ipv6 = cfg.get("nfqws", "disable_ipv6", default=True)
            # Параметры ответного направления и исключения — для PREROUTING /
            # NAT MASQUERADE / TCP-флагов (паритет с nfqws2-keenetic).
            self._extra = {
                "tcp_pkt_in": tcp_pkt_in,
                "udp_pkt_in": udp_pkt_in,
                "mark_exclude": mark_exclude,
            }

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
                    # Тюнинг conntrack: без be_liberal ядро отбрасывает
                    # out-of-window сегменты, которые порождает десинхронизация
                    # (split/disorder/fake с badseq) — обход не срабатывает.
                    self._apply_sysctl_tuning()
                    # Персистентность на роутере: сохранить рантайм-конфиг и
                    # установить ndm/hotplug-хуки, чтобы правила переживали
                    # flush системного firewall (Keenetic NDMS / OpenWrt fw3).
                    self._ensure_persistence(
                        qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt,
                        tcp_pkt_in, udp_pkt_in, mark_exclude,
                        disable_ipv6, wan4, wan6,
                    )
                else:
                    log.error("Ошибка при применении правил", source="firewall")
                return ok

            except Exception as e:
                log.error("Исключение при применении правил: %s" % e,
                          source="firewall")
                return False

    @staticmethod
    def _apply_sysctl_tuning():
        """Настроить conntrack под десинхронизацию (как nfqws2-keenetic).

        net.netfilter.nf_conntrack_tcp_be_liberal=1 — не дропать пакеты вне TCP
        window (десинк намеренно их шлёт). nf_conntrack_checksum=0 — не считать
        контрольные суммы (nfqws2 их портит намеренно, badsum). Best-effort.
        """
        for key, val in (
            ("net.netfilter.nf_conntrack_tcp_be_liberal", "1"),
            ("net.netfilter.nf_conntrack_checksum", "0"),
        ):
            try:
                subprocess.run(["sysctl", "-w", "%s=%s" % (key, val)],
                               capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

    @staticmethod
    def _ensure_persistence(qnum, tcp, udp, fwmark, tcp_pkt, udp_pkt,
                            tcp_pkt_in, udp_pkt_in, mark_exclude,
                            disable_ipv6, wan4, wan6):
        """Записать рантайм-конфиг firewall и установить хуки (только роутер).

        На обычных хостах (systemd/desktop) ndm/hotplug отсутствуют — тогда
        ничего не делаем. Хуки no-op'ят, пока nfqws2 не запущен (проверяют PID).
        """
        try:
            from core import firewall_persistence as fp
            if not (fp.is_keenetic() or fp.is_openwrt_hotplug()):
                return
            ifaces = set(wan4 or [])
            if wan6:
                ifaces.update(wan6)
            params = {
                "queue_num": qnum,
                "ports_tcp": tcp,
                "ports_udp": udp,
                "tcp_pkt_out": tcp_pkt,
                "udp_pkt_out": udp_pkt,
                "pkt_in": max(int(tcp_pkt_in), int(udp_pkt_in), 1),
                "mark_processed": "%s/%s" % (fwmark, fwmark),
                "mark_exclude": "%s/%s" % (mark_exclude, mark_exclude),
                "ipv6_enabled": "0" if disable_ipv6 else "1",
                "wan_ifaces": " ".join(sorted(ifaces)),
            }
            fp.write_runtime_conf(params)
            fp.install_hooks()
        except Exception as e:
            log.warning("Персистентность firewall не настроена: %s" % e,
                        source="firewall")

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
        return self._rules_applied(self.get_rules())

    def _rules_applied(self, rules) -> bool:
        """Вычислить applied по списку правил и сохранить под локом
        (запись _applied — под тем же локом, что и в apply/remove)."""
        has_rules = any(IPT_COMMENT in r or NFT_TABLE in r for r in rules)
        with self._lock:
            self._applied = has_rules
        return has_rules

    def get_status(self) -> dict:
        """Полный статус для API."""
        fw_type = self.detect_fw_type()
        # Один вызов get_rules вместо двух (is_applied + повтор): get_rules
        # шеллит наружу, дважды на каждый poll статуса — лишняя нагрузка.
        rules = self.get_rules()
        applied = self._rules_applied(rules)
        return {
            "type": fw_type,
            "applied": applied,
            "rules": rules if applied else [],
            "rules_count": len(rules) if applied else 0,
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

    def _ipt_probe_rule(self, ipt_cmd, probe_args) -> bool:
        """Можно ли добавить правило `probe_args` (есть ли матч/цель в ядре).

        Создаёт одноразовую цепочку в таблице filter (она есть всегда и вне
        тракта трафика), пытается добавить туда правило и смотрит на «No chain/
        target/match by that name». Возвращает False ТОЛЬКО при таком явном
        вердикте; при любой иной ошибке или невозможности проверить — True (не
        ломаем рабочий путь). За собой пробную цепочку чистит.
        """
        wait = FirewallManager._iptables_wait_flag(ipt_cmd)
        probe = "ZGUI_PROBE"

        def _raw(args):
            try:
                return subprocess.run(
                    [ipt_cmd] + wait + args,
                    capture_output=True, text=True, timeout=5,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                return None

        available = True
        _raw(["-t", "filter", "-N", probe])
        add = _raw(["-t", "filter", "-A", probe] + probe_args)
        if (add is not None and add.returncode != 0
                and "No chain/target/match" in (add.stderr or "")):
            available = False
        _raw(["-t", "filter", "-F", probe])
        _raw(["-t", "filter", "-X", probe])
        return available

    def _feature_supported(self, ipt_cmd, cache, probe_args, warn=None) -> bool:
        """Кэшируемый детект матча/цели (см. _ipt_probe_rule).

        `warn % ipt_cmd` логируется один раз — при первом обнаружении
        отсутствия. Результат кэшируется по бинарнику.
        """
        if ipt_cmd in cache:
            return cache[ipt_cmd]
        ok = self._ipt_probe_rule(ipt_cmd, probe_args)
        cache[ipt_cmd] = ok
        if not ok and warn:
            log.warning(warn % ipt_cmd, source="firewall")
        return ok

    def _comment_supported(self, ipt_cmd) -> bool:
        """Доступен ли матч `-m comment` (xt_comment) у этого iptables.

        На Entware/Keenetic это отдельный модуль (пакет iptables-mod-comment),
        которого часто нет. Без него каждое правило с `-m comment` падает с
        «No chain/target/match by that name», и весь обход не поднимается
        (issue #151) — тогда мы кладём правила в именованные цепочки nfqws_*
        без комментариев. Переключаемся ТОЛЬКО при положительном детекте
        отсутствия матча.
        """
        return self._feature_supported(
            ipt_cmd, FirewallManager._comment_support_cache,
            ["-m", "comment", "--comment", "zgui", "-j", "RETURN"],
            warn="%s: матч `-m comment` недоступен (нет пакета "
                 "iptables-mod-comment?). Правила пойдут в именованные цепочки "
                 "nfqws_* без комментариев (issue #151).",
        )

    def _multiport_supported(self, ipt_cmd) -> bool:
        """Доступен ли матч `-m multiport` (xt_multiport).

        Если нет — список портов нельзя задать одним правилом; бьём его на
        отдельные правила `--dport/--sport` (нативный матч tcp/udp понимает и
        одиночный порт, и диапазон X:Y) (issue #151).
        """
        return self._feature_supported(
            ipt_cmd, FirewallManager._multiport_support_cache,
            ["-p", "tcp", "-m", "multiport", "--dports", "80,443",
             "-j", "RETURN"],
            warn="%s: матч `-m multiport` недоступен (нет "
                 "iptables-mod-multiport?). Списки портов разбиваем на "
                 "отдельные правила --dport/--sport (issue #151).",
        )

    def _connbytes_supported(self, ipt_cmd) -> bool:
        """Доступен ли матч `-m connbytes` (xt_connbytes).

        Если нет — выкидываем ограничитель «первые N пакетов»; в очередь пойдут
        все пакеты целевых портов (дороже по CPU, но обход работает; cutoff
        внутри nfqws2 всё равно отрабатывает) (issue #151).
        """
        return self._feature_supported(
            ipt_cmd, FirewallManager._connbytes_support_cache,
            ["-p", "tcp", "-m", "connbytes", "--connbytes-dir=original",
             "--connbytes-mode=packets", "--connbytes", "1:5", "-j", "RETURN"],
            warn="%s: матч `-m connbytes` недоступен (нет "
                 "iptables-mod-conntrack-extra?). Ограничитель первых пакетов "
                 "отключён — в очередь идут все пакеты целевых портов "
                 "(issue #151).",
        )

    def _nfqueue_supported(self, ipt_cmd) -> bool:
        """Доступна ли цель NFQUEUE (xt_NFQUEUE / nfnetlink_queue).

        Без неё ядро физически не может отдать пакеты в nfqws2 — обход через
        iptables невозможен (issue #151). Детект — единственный, по которому
        мы прекращаем накат правил (см. _apply_ipt_family).
        """
        return self._feature_supported(
            ipt_cmd, FirewallManager._nfqueue_support_cache,
            ["-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass"],
        )

    def _ensure_named_chain(self, ipt_cmd, table, hook, name) -> None:
        """Создать/очистить нашу цепочку `name` и подцепить её к `hook`.

        Идемпотентно: цепочка создаётся (если нет) и флашится; лишние
        дублирующие переходы из hook снимаются, затем ставится один переход
        в начало hook. Снимается всё это потом в _remove_ipt_named_chain.
        Используется, когда `-m comment` недоступен (issue #151).
        """
        wait = FirewallManager._iptables_wait_flag(ipt_cmd)

        def _raw(args):
            try:
                return subprocess.run(
                    [ipt_cmd] + wait + args,
                    capture_output=True, text=True, timeout=5,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                return None

        _raw(["-t", table, "-N", name])   # создать (может уже существовать — ок)
        _raw(["-t", table, "-F", name])   # очистить от прошлых правил
        for _ in range(10):               # снять старые переходы (анти-дубли)
            chk = _raw(["-t", table, "-C", hook, "-j", name])
            if not chk or chk.returncode != 0:
                break
            _raw(["-t", table, "-D", hook, "-j", name])
        _raw(["-t", table, "-I", hook, "-j", name])  # один переход в начало hook

    def _apply_ipt_family(self, ipt_cmd, qnum, ports_tcp, ports_udp,
                          fwmark, tcp_pkt, udp_pkt, wan_ifaces, rules):
        """
        Применить правила для одного семейства (iptables / ip6tables).

        Портировано из nfqws2-keenetic (_firewall_start). На каждый WAN
        (или без привязки, если список пуст) вешаются правила на ОБА
        направления:
          • POSTROUTING (исходящий): RETURN для исключённых меток,
            NFQUEUE для первых N пакетов соединения + по TCP-флагам fin/rst;
          • NAT POSTROUTING (только IPv4): MASQUERADE для пакетов, которые
            переписал nfqws2 (иначе пакеты с новым адресом отбрасываются);
          • PREROUTING (входящий/ответы): RETURN для исключённых и уже
            обработанных, NFQUEUE по reply-connbytes + TCP-флагам syn,ack/fin/rst.

        Все правила помечаются комментарием IPT_COMMENT — по нему же чистятся.
        """
        ok = True
        family_tag = "IPv4" if ipt_cmd == "iptables" else "IPv6"

        # Проверяем доступность команды
        if not shutil.which(ipt_cmd):
            log.warning("%s не найден, пропускаем %s" % (ipt_cmd, family_tag),
                        source="firewall")
            return True  # Не ошибка — просто нет поддержки

        mark_proc = "%s/%s" % (fwmark, fwmark)
        mark_excl_raw = self._extra.get("mark_exclude", "0x20000000")
        mark_excl = "%s/%s" % (mark_excl_raw, mark_excl_raw)
        tcp_pkt_in = self._extra.get("tcp_pkt_in", 10)
        udp_pkt_in = self._extra.get("udp_pkt_in", 3)
        do_nat = (ipt_cmd == "iptables")  # MASQUERADE только для IPv4

        # NFQUEUE — фундаментальная цель: без неё ядро не отдаёт пакеты в
        # nfqws2 и обход не работает в принципе. Если её нет — громко сообщаем
        # и не накатываем ничего (иначе все порт-правила тихо падают). Детект
        # консервативен (False только на явное «No chain/target/match»), потому
        # ему можно доверять (issue #151).
        if not self._nfqueue_supported(ipt_cmd):
            log.error(
                "%s: цель NFQUEUE недоступна — нет модуля ядра xt_NFQUEUE / "
                "nfnetlink_queue. Перенаправление трафика в nfqws2 невозможно, "
                "обход работать не будет. Догрузите модуль ядра NFQUEUE (на "
                "Keenetic — соответствующий компонент netfilter) либо перейдите "
                "на nftables (issue #151)." % ipt_cmd,
                source="firewall",
            )
            return False

        # multiport / connbytes на Entware/Keenetic тоже бывают недоступны —
        # тогда деградируем (см. _multiport_supported / _connbytes_supported).
        use_multiport = self._multiport_supported(ipt_cmd)
        use_connbytes = self._connbytes_supported(ipt_cmd)

        # На Entware/Keenetic матч `-m comment` (xt_comment) — отдельный
        # пакет iptables-mod-comment, которого может не быть. Тогда КАЖДОЕ
        # правило падало с «No chain/target/match by that name» и обход не
        # поднимался (issue #151). Если матч недоступен — кладём правила в
        # именованные цепочки nfqws_* (их снимает _remove_ipt_named_chain),
        # без `-m comment`. Если доступен — поведение прежнее (правила прямо
        # во встроенных цепочках, помечены комментарием).
        use_comment = self._comment_supported(ipt_cmd)
        if use_comment:
            post_chain, pre_chain, nat_chain = (
                "POSTROUTING", "PREROUTING", "POSTROUTING")
            post_first = "-I"   # ACCEPT-processed — первым во встроенной цепочке

            def _comment():
                return ["-m", "comment", "--comment", IPT_COMMENT]
        else:
            post_chain, pre_chain, nat_chain = (
                "nfqws_post", "nfqws_pre", "nfqws_nat")
            post_first = "-A"   # свежая цепочка: порядок = порядок добавления

            def _comment():
                return []

            self._ensure_named_chain(ipt_cmd, "mangle", "POSTROUTING", post_chain)
            self._ensure_named_chain(ipt_cmd, "mangle", "PREROUTING", pre_chain)
            if do_nat:
                self._ensure_named_chain(ipt_cmd, "nat", "POSTROUTING", nat_chain)

        def _nfq():
            return ["-j", "NFQUEUE", "--queue-num", str(qnum), "--queue-bypass"]

        def _port_bases(prefix, proto, direction, ports):
            """Базовые правила под список портов.

            С `-m multiport` — одно правило на весь список. Без него — по
            одному правилу на каждый токен через нативный `--dport/--sport`
            (он понимает и одиночный порт, и диапазон вида `3478:3481`).
            `direction` — "dports" (исходящие) или "sports" (ответные).
            """
            if use_multiport:
                return [prefix + ["-p", proto, "-m", "multiport",
                                  "--%s" % direction, ports]]
            single = "--dport" if direction == "dports" else "--sport"
            bases = []
            for tok in str(ports).split(","):
                tok = tok.strip()
                if tok:
                    bases.append(prefix + ["-p", proto, single, tok])
            return bases

        def _connbytes_args(conn_dir, limit):
            """Ограничитель «первые N пакетов»; пусто, если connbytes нет."""
            if not use_connbytes:
                return []
            return ["-m", "connbytes", "--connbytes-dir=%s" % conn_dir,
                    "--connbytes-mode=packets", "--connbytes", "1:%d" % limit]

        # Для каждого WAN или без привязки к интерфейсу
        oif_list = wan_ifaces if wan_ifaces else [None]

        for oif in oif_list:
            oif_args = ["-o", oif] if oif else []
            iif_args = ["-i", oif] if oif else []
            tag = (" %s" % oif) if oif else " (все)"

            # ───────── POSTROUTING (исходящий) ─────────
            # 1) ACCEPT для уже обработанных (не зацикливаем)
            if self._run_cmd(
                [ipt_cmd, "-t", "mangle", post_first, post_chain] + oif_args
                + ["-m", "mark", "--mark", mark_proc] + _comment()
                + ["-j", "ACCEPT"]
            ):
                rules.append("%s ACCEPT processed%s" % (family_tag, tag))
            else:
                ok = False

            # 2) RETURN для исключённых соединений
            self._run_cmd(
                [ipt_cmd, "-t", "mangle", "-A", post_chain] + oif_args
                + ["-m", "connmark", "--mark", mark_excl] + _comment()
                + ["-j", "RETURN"]
            )

            # 3) TCP → NFQUEUE (первые N пакетов + fin/rst)
            if ports_tcp:
                prefix = [ipt_cmd, "-t", "mangle", "-A", post_chain] + oif_args
                logged = False
                for base in _port_bases(prefix, "tcp", "dports", ports_tcp):
                    if self._run_cmd(base + _connbytes_args("original", tcp_pkt)
                                     + _comment() + _nfq()):
                        if not logged:
                            rules.append("%s TCP %s → NFQUEUE %d%s" % (
                                family_tag, ports_tcp, qnum, tag))
                            logged = True
                    else:
                        ok = False
                    self._run_cmd(base + ["--tcp-flags", "fin", "fin"]
                                  + _comment() + _nfq())
                    self._run_cmd(base + ["--tcp-flags", "rst", "rst"]
                                  + _comment() + _nfq())

            # 4) UDP → NFQUEUE
            if ports_udp:
                prefix = [ipt_cmd, "-t", "mangle", "-A", post_chain] + oif_args
                logged = False
                for base in _port_bases(prefix, "udp", "dports", ports_udp):
                    if self._run_cmd(base + _connbytes_args("original", udp_pkt)
                                     + _comment() + _nfq()):
                        if not logged:
                            rules.append("%s UDP %s → NFQUEUE %d%s" % (
                                family_tag, ports_udp, qnum, tag))
                            logged = True
                    else:
                        ok = False

            # ───────── NAT POSTROUTING (только IPv4) ─────────
            # nfqws2 переписывает адреса → повторный MASQUERADE для UDP.
            if do_nat:
                if self._run_cmd(
                    [ipt_cmd, "-t", "nat", "-A", nat_chain] + oif_args
                    + ["-m", "mark", "--mark", mark_proc, "-p", "udp"]
                    + _comment() + ["-j", "MASQUERADE"]
                ):
                    rules.append("%s NAT MASQUERADE udp%s" % (family_tag, tag))

            # ───────── PREROUTING (входящий / ответы) ─────────
            # RETURN для исключённых и уже обработанных
            self._run_cmd(
                [ipt_cmd, "-t", "mangle", "-A", pre_chain] + iif_args
                + ["-m", "connmark", "--mark", mark_excl] + _comment()
                + ["-j", "RETURN"]
            )
            self._run_cmd(
                [ipt_cmd, "-t", "mangle", "-A", pre_chain] + iif_args
                + ["-m", "mark", "--mark", mark_proc] + _comment()
                + ["-j", "RETURN"]
            )
            if ports_tcp:
                prefix = [ipt_cmd, "-t", "mangle", "-A", pre_chain] + iif_args
                for base in _port_bases(prefix, "tcp", "sports", ports_tcp):
                    # Reply-path NFQUEUE функционально обязателен (обход в
                    # обратную сторону) — гейтим ok, иначе полупримененный
                    # ruleset рапортуется как успех (см. #28).
                    if not self._run_cmd(base + _connbytes_args("reply", tcp_pkt_in)
                                         + _comment() + _nfq()):
                        ok = False
                    self._run_cmd(base + ["--tcp-flags", "syn,ack", "syn,ack"]
                                  + _comment() + _nfq())
                    self._run_cmd(base + ["--tcp-flags", "fin", "fin"]
                                  + _comment() + _nfq())
                    self._run_cmd(base + ["--tcp-flags", "rst", "rst"]
                                  + _comment() + _nfq())
            if ports_udp:
                prefix = [ipt_cmd, "-t", "mangle", "-A", pre_chain] + iif_args
                for base in _port_bases(prefix, "udp", "sports", ports_udp):
                    if not self._run_cmd(base + _connbytes_args("reply", udp_pkt_in)
                                         + _comment() + _nfq()):
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

    # Цепочки, в которые мы добавляем правила (таблица, цепочка).
    _IPT_CHAINS = (
        ("mangle", "POSTROUTING"),
        ("mangle", "PREROUTING"),
        ("nat", "POSTROUTING"),
    )

    # Именованные цепочки персистентного режима (reapply-хук создаёт их
    # вместо вставки правил по комментарию). Чистим их тоже, чтобы после
    # flush+reapply не оставались осиротевшие цепочки. (таблица, цепочка-хук,
    # имя нашей цепочки).
    _IPT_NAMED_CHAINS = (
        ("mangle", "POSTROUTING", "nfqws_post"),
        ("mangle", "PREROUTING", "nfqws_pre"),
        ("nat", "POSTROUTING", "nfqws_nat"),
    )

    def _remove_ipt_family(self, ipt_cmd) -> bool:
        """Удалить правила одного семейства из всех наших цепочек."""
        ok = True
        for table, chain in self._IPT_CHAINS:
            if not self._remove_ipt_chain(ipt_cmd, table, chain):
                ok = False
        # Снести именованные цепочки персистентного режима, если остались.
        for table, hook, name in self._IPT_NAMED_CHAINS:
            if not self._remove_ipt_named_chain(ipt_cmd, table, hook, name):
                ok = False
        return ok

    def _remove_ipt_named_chain(self, ipt_cmd, table, hook, name) -> bool:
        """Отцепить и удалить именованную цепочку nfqws_* (best-effort).

        Тихо выходим, если цепочки нет (обычный случай в GUI-режиме без
        reapply) — чтобы не сыпать предупреждениями на каждый stop.
        """
        if not shutil.which(ipt_cmd):
            return True
        try:
            exists = subprocess.run(
                [ipt_cmd, "-w", "-t", table, "-L", name, "-n"],
                capture_output=True, text=True, timeout=5,
            ).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False
        if not exists:
            return True

        ok = True
        # Снять переходы из hook-цепочки (могут быть дубли).
        for _ in range(10):
            r = subprocess.run(
                [ipt_cmd, "-w", "-t", table, "-C", hook, "-j", name],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                break
            if not self._run_cmd([ipt_cmd, "-t", table, "-D", hook, "-j", name]):
                ok = False
        # Очистить и удалить саму цепочку.
        if not self._run_cmd([ipt_cmd, "-t", table, "-F", name]):
            ok = False
        if not self._run_cmd([ipt_cmd, "-t", table, "-X", name]):
            ok = False
        return ok

    def _remove_ipt_chain(self, ipt_cmd, table, chain) -> bool:
        """Удалить все правила с комментарием IPT_COMMENT из одной цепочки."""
        ok = True
        for _ in range(20):
            found = False
            try:
                result = subprocess.run(
                    [ipt_cmd, "-t", table, "-L", chain,
                     "--line-numbers", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    break

                for line in reversed(result.stdout.splitlines()):
                    if IPT_COMMENT in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            if not self._run_cmd([
                                ipt_cmd, "-t", table,
                                "-D", chain, parts[0]
                            ]):
                                ok = False
                            found = True
            except Exception:
                return False

            if not found:
                break
        return ok

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
        Применить правила nftables (паритет с iptables-путём).

        В inet-таблице создаём три цепочки:
          • postrouting (исходящий): RETURN для исключённых, NFQUEUE первых N
            пакетов + по TCP-флагам fin/rst;
          • prerouting (входящий/ответы): RETURN исключённых и обработанных,
            NFQUEUE по reply-пакетам + TCP-флагам syn,ack/fin/rst;
          • nat postrouting: MASQUERADE для пакетов, переписанных nfqws2.
        Фильтр интерфейса: `oifname { "eth0", "eth1" }` / `iifname ...`.
        """
        mark_excl_raw = self._extra.get("mark_exclude", "0x20000000")
        tcp_pkt_in = self._extra.get("tcp_pkt_in", 10)
        udp_pkt_in = self._extra.get("udp_pkt_in", 3)

        # Собираем уникальные WAN-интерфейсы
        all_wan = set(wan4_ifaces or [])
        if wan6_ifaces:
            all_wan.update(wan6_ifaces)

        def _iface(kw):
            if not all_wan:
                return ""
            # Имена — строго в кавычках: имя, начинающееся с цифры
            # (6in4-he_net, 6to4-wan, 6rd-*), nft-лексер без кавычек читает
            # как число+строку → «syntax error, unexpected string» на каждом
            # правиле. Кавычки доходят до nft как есть: команда уходит
            # argv-списком без shell, nft склеивает аргументы и лексит заново.
            quoted = ['"%s"' % i for i in sorted(all_wan)]
            if len(quoted) == 1:
                return "%s %s " % (kw, quoted[0])
            return "%s { %s } " % (kw, ", ".join(quoted))

        oif = _iface("oifname")
        iif = _iface("iifname")
        tcp_ports = "{ %s }" % _nft_port_set(ports_tcp) if ports_tcp else None
        udp_ports = "{ %s }" % _nft_port_set(ports_udp) if ports_udp else None

        cmds = []
        cmds.append("add table inet %s" % NFT_TABLE)
        cmds.append("add chain inet %s postrouting "
                    "{ type filter hook postrouting priority 150 ; }" % NFT_TABLE)
        cmds.append("add chain inet %s prerouting "
                    "{ type filter hook prerouting priority -150 ; }" % NFT_TABLE)
        cmds.append("add chain inet %s natpost "
                    "{ type nat hook postrouting priority 100 ; }" % NFT_TABLE)

        # ─── postrouting (исходящий) ───
        # EXCLUDE — это CONNMARK (ставится на conntrack), поэтому матчим
        # `ct mark`, а не пакетный `meta mark` (иначе на пакетах без
        # восстановленной метки исключённое соединение повторно попадёт в
        # очередь — расхождение с iptables-путём, где стоит -m connmark).
        cmds.append("add rule inet %s postrouting %sct mark and %s == %s return"
                    % (NFT_TABLE, oif, mark_excl_raw, mark_excl_raw))
        cmds.append("add rule inet %s postrouting %smeta mark and %s == %s return"
                    % (NFT_TABLE, oif, fwmark, fwmark))
        if tcp_ports:
            cmds.append("add rule inet %s postrouting %stcp dport %s "
                        "ct original packets 1-%d queue num %d bypass"
                        % (NFT_TABLE, oif, tcp_ports, tcp_pkt, qnum))
            cmds.append("add rule inet %s postrouting %stcp dport %s "
                        "tcp flags fin queue num %d bypass"
                        % (NFT_TABLE, oif, tcp_ports, qnum))
            cmds.append("add rule inet %s postrouting %stcp dport %s "
                        "tcp flags rst queue num %d bypass"
                        % (NFT_TABLE, oif, tcp_ports, qnum))
        if udp_ports:
            cmds.append("add rule inet %s postrouting %sudp dport %s "
                        "ct original packets 1-%d queue num %d bypass"
                        % (NFT_TABLE, oif, udp_ports, udp_pkt, qnum))

        # ─── prerouting (входящий/ответы) ───
        # EXCLUDE — connmark (см. коммент в postrouting): матчим `ct mark`.
        cmds.append("add rule inet %s prerouting %sct mark and %s == %s return"
                    % (NFT_TABLE, iif, mark_excl_raw, mark_excl_raw))
        cmds.append("add rule inet %s prerouting %smeta mark and %s == %s return"
                    % (NFT_TABLE, iif, fwmark, fwmark))
        if tcp_ports:
            cmds.append("add rule inet %s prerouting %stcp sport %s "
                        "ct reply packets 1-%d queue num %d bypass"
                        % (NFT_TABLE, iif, tcp_ports, tcp_pkt_in, qnum))
            cmds.append("add rule inet %s prerouting %stcp sport %s "
                        "tcp flags syn,ack queue num %d bypass"
                        % (NFT_TABLE, iif, tcp_ports, qnum))
        if udp_ports:
            cmds.append("add rule inet %s prerouting %sudp sport %s "
                        "ct reply packets 1-%d queue num %d bypass"
                        % (NFT_TABLE, iif, udp_ports, udp_pkt_in, qnum))

        # ─── nat postrouting: MASQUERADE для переписанных nfqws2 пакетов ───
        cmds.append("add rule inet %s natpost %smeta mark and %s == %s "
                    "meta l4proto udp masquerade"
                    % (NFT_TABLE, oif, fwmark, fwmark))

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
        """Удалить таблицу nftables. Отсутствие таблицы — не ошибка."""
        result = self._run_cmd(["nft", "delete", "table", "inet", NFT_TABLE])
        if not result:
            # delete падает и когда таблицы просто нет (первый запуск после
            # ребута, прошлый apply не дошёл до конца) — снимать было нечего,
            # не пугаем «Возможны проблемы при снятии правил».
            try:
                probe = subprocess.run(
                    ["nft", "list", "table", "inet", NFT_TABLE],
                    capture_output=True, text=True, timeout=5,
                )
                result = probe.returncode != 0
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
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
