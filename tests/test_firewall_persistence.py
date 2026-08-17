# tests/test_firewall_persistence.py
"""Тесты персистентности firewall-правил (ndm/hotplug-хуки + reapply)."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from core import firewall_persistence as fp


def _sh_ok(text):
    sh = shutil.which("sh")
    if not sh:
        return True  # нет sh — пропускаем проверку
    return subprocess.run([sh, "-n"], input=text, text=True,
                          capture_output=True).returncode == 0


class TestGeneratedScripts(unittest.TestCase):

    def test_reapply_script_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_reapply_script()))

    def test_ndm_hook_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_ndm_hook()))

    def test_hotplug_hook_valid_shell(self):
        self.assertTrue(_sh_ok(fp.build_hotplug_hook()))

    def test_shared_funcs_valid_shell(self):
        # Функции должны быть валидны при заданных переменных.
        prelude = (
            'QUEUE_NUM=300\nPORTS_TCP="80,443"\nPORTS_UDP="443"\n'
            'MAX_PKT_OUT=20\nMAX_PKT_OUT_UDP=5\n'
            'MARK_PROCESSED="0x40000000/0x40000000"\n'
            'MARK_EXCLUDE="0x20000000/0x20000000"\n'
            'IPV6_ENABLED=0\nWAN_IFACES="eth0"\n'
        )
        self.assertTrue(_sh_ok(prelude + fp.FIREWALL_SH_FUNCTIONS))

    def test_ndm_hook_filters_table(self):
        body = fp.build_ndm_hook()
        self.assertIn("mangle", body)
        self.assertIn("nat", body)
        self.assertIn("reapply", body)

    def test_hooks_check_pidfiles(self):
        for body in (fp.build_ndm_hook(), fp.build_hotplug_hook()):
            self.assertIn(fp.AUTOSTART_PID_FILE, body)
            self.assertIn(fp.GUI_PID_FILE, body)


class TestRunConf(unittest.TestCase):

    def test_render_contains_all_keys(self):
        conf = fp.render_run_conf({
            "queue_num": 300, "ports_tcp": "80,443", "ports_udp": "443",
            "tcp_pkt_out": 20, "udp_pkt_out": 5, "pkt_in": 15,
            "mark_processed": "0x40000000/0x40000000",
            "mark_exclude": "0x20000000/0x20000000",
            "ipv6_enabled": "0", "wan_ifaces": "eth0",
        })
        for key in ("QUEUE_NUM", "PORTS_TCP", "PORTS_UDP", "MAX_PKT_OUT",
                    "MARK_PROCESSED", "MARK_EXCLUDE", "WAN_IFACES"):
            self.assertIn(key + "=", conf)


class TestInstallRemove(unittest.TestCase):

    def test_install_and_remove_in_tempdirs(self):
        with tempfile.TemporaryDirectory() as d:
            ndm = os.path.join(d, "ndm", "100-zapret-gui.sh")
            hot = os.path.join(d, "hotplug", "90-zapret-gui")
            with mock.patch.object(fp, "NDM_HOOK_PATH", ndm), \
                 mock.patch.object(fp, "HOTPLUG_HOOK_PATH", hot), \
                 mock.patch.object(fp, "is_keenetic", return_value=True), \
                 mock.patch.object(fp, "is_openwrt_hotplug", return_value=True):
                res = fp.install_hooks()
                self.assertTrue(res["ndm"])
                self.assertTrue(res["hotplug"])
                self.assertTrue(os.path.isfile(ndm))
                self.assertTrue(os.path.isfile(hot))
                # Исполняемый бит выставлен.
                self.assertTrue(os.access(ndm, os.X_OK))

                rem = fp.remove_hooks()
                self.assertIn(ndm, rem["removed"])
                self.assertFalse(os.path.isfile(ndm))

    def test_install_noop_when_not_router(self):
        with mock.patch.object(fp, "is_keenetic", return_value=False), \
             mock.patch.object(fp, "is_openwrt_hotplug", return_value=False):
            res = fp.install_hooks()
            self.assertEqual(res["installed"], [])


# Фейковый iptables: пробные правила (-A ZGUI_PROBE) проваливаются с
# «No chain/target/match» для матчей/цели, помеченных как недоступные через
# env FAKE_NO_{MULTIPORT,CONNBYTES,NFQUEUE}; реальные правила печатаются как
# «RULE: …». Цепочечные команды (-N/-F/-X/-C) и переходы — всегда успех.
_FAKE_IPTABLES = r"""
iptables() {
    case " $* " in
      *" -A ZGUI_PROBE "*)
        case " $* " in
          *" -m multiport "*) [ "$FAKE_NO_MULTIPORT" = 1 ] && { echo "iptables: No chain/target/match by that name." >&2; return 1; } ;;
          *" -m connbytes "*) [ "$FAKE_NO_CONNBYTES" = 1 ] && { echo "iptables: No chain/target/match by that name." >&2; return 1; } ;;
          *" NFQUEUE "*) [ "$FAKE_NO_NFQUEUE" = 1 ] && { echo "iptables: No chain/target/match by that name." >&2; return 1; } ;;
        esac
        return 0 ;;
      *" -N "*|*" -F "*|*" -X "*|*" -C "*) return 0 ;;
      *) echo "RULE: $*"; return 0 ;;
    esac
}
"""

_SHELL_PRELUDE = (
    'QUEUE_NUM=300\nPORTS_TCP="80,443,8443"\nPORTS_UDP="443,3478:3481"\n'
    'MAX_PKT_OUT=20\nMAX_PKT_OUT_UDP=5\nMAX_PKT_IN=10\n'
    'MARK_PROCESSED="0x40000000/0x40000000"\n'
    'MARK_EXCLUDE="0x20000000/0x20000000"\n'
    'IPV6_ENABLED=0\nWAN_IFACES="eth3"\n'
)


def _run_shell_firewall(no_multiport=0, no_connbytes=0, no_nfqueue=0):
    """Запустить shell `firewall_iptables` с фейковым iptables; вернуть строки
    реально накатанных правил (без префикса RULE:)."""
    sh = shutil.which("sh")
    if not sh:
        return None
    env = dict(os.environ,
               FAKE_NO_MULTIPORT=str(no_multiport),
               FAKE_NO_CONNBYTES=str(no_connbytes),
               FAKE_NO_NFQUEUE=str(no_nfqueue))
    script = (_SHELL_PRELUDE + _FAKE_IPTABLES
              + fp.FIREWALL_SH_FUNCTIONS + "\nfirewall_iptables\n")
    r = subprocess.run([sh], input=script, text=True,
                       capture_output=True, env=env)
    return [ln[len("RULE: "):] for ln in r.stdout.splitlines()
            if ln.startswith("RULE: ")]


@unittest.skipUnless(shutil.which("sh"), "нет sh")
class TestShellDegradation(unittest.TestCase):
    """issue #151: shell-путь (автозапуск S99zapret + reapply-хук) должен так же
    деградировать при отсутствии multiport / connbytes / NFQUEUE на Keenetic."""

    def test_all_available_uses_multiport_and_connbytes(self):
        rules = _run_shell_firewall()
        self.assertTrue(any("-m multiport" in r for r in rules))
        self.assertTrue(any("connbytes" in r for r in rules))
        self.assertTrue(any("NFQUEUE --queue-num 300" in r for r in rules))

    def test_no_multiport_splits_into_per_port_rules(self):
        rules = _run_shell_firewall(no_multiport=1)
        self.assertFalse(any("multiport" in r for r in rules))
        self.assertTrue(any(r.endswith("--dport 80 -j NFQUEUE "
                                       "--queue-num 300 --queue-bypass")
                            or "--dport 80 " in (r + " ") for r in rules))
        self.assertTrue(any("--sport 443 " in (r + " ") for r in rules))
        # диапазон сохраняется как нативный X:Y
        self.assertTrue(any("--dport 3478:3481" in r for r in rules))

    def test_no_connbytes_drops_limiter(self):
        rules = _run_shell_firewall(no_connbytes=1)
        self.assertFalse(any("connbytes" in r for r in rules))
        # но NFQUEUE-перехват остаётся
        self.assertTrue(any("NFQUEUE" in r for r in rules))

    def test_no_multiport_and_connbytes_together(self):
        rules = _run_shell_firewall(no_multiport=1, no_connbytes=1)
        self.assertFalse(any("multiport" in r for r in rules))
        self.assertFalse(any("connbytes" in r for r in rules))
        self.assertTrue(any("NFQUEUE" in r for r in rules))
        self.assertTrue(any("MASQUERADE" in r for r in rules))

    def test_no_nfqueue_emits_no_rules(self):
        rules = _run_shell_firewall(no_nfqueue=1)
        self.assertEqual(rules, [])


# Фейковый nft: печатает всё, что ему передали, склеивая argv через пробел —
# ровно как это делает настоящий nft перед разбором.
_FAKE_NFT = r"""
nft() { echo "NFT: $*"; return 0; }
"""

_NFT_PRELUDE = (
    'QUEUE_NUM=300\nPORTS_TCP="80,443,2053:2087"\nPORTS_UDP="443,3478:3481"\n'
    'MAX_PKT_OUT=20\nMAX_PKT_OUT_UDP=5\nMAX_PKT_IN=10\n'
    'MARK_PROCESSED="0x40000000/0x40000000"\n'
    'MARK_EXCLUDE="0x20000000/0x20000000"\n'
    'IPV6_ENABLED=0\n'
)


def _run_shell_backend(backend, wan="eth3", command="apply_firewall",
                       have_iptables=True, have_nft=True,
                       iptables_is_shim=False):
    """Прогнать shell-функции с фейковыми nft/iptables.

    Возвращает (nft_cmds, ipt_cmds) — что ушло в каждый бэкенд.
    """
    sh = shutil.which("sh")
    if not sh:
        return None, None

    # command -v должен видеть ровно то, что просим: подменяем его.
    stub_cmdv = (
        'command() {\n'
        '    if [ "$1" = "-v" ]; then\n'
        '        case "$2" in\n'
        '            iptables|ip6tables) [ "%s" = "1" ] && echo /sbin/$2 && return 0; return 1 ;;\n'
        '            nft) [ "%s" = "1" ] && echo /usr/sbin/nft && return 0; return 1 ;;\n'
        '        esac\n'
        '    fi\n'
        '    return 1\n'
        '}\n'
        % ("1" if have_iptables else "0", "1" if have_nft else "0")
    )
    # `iptables --version` — по нему shell отличает legacy от nft-шима.
    # `-C` отвечает «правила нет» (иначе снятие переходов зациклилось бы —
    # ровно та петля, которую в _fw_unhook ограничивает счётчик).
    stub_ver = (
        'iptables() {\n'
        '    if [ "$1" = "--version" ]; then echo "iptables v1.8.10 (%s)"; return 0; fi\n'
        '    case " $* " in\n'
        '      *" -C "*) return 1 ;;\n'
        '      *" -N "*|*" -F "*|*" -X "*|*" -A ZGUI_PROBE "*) return 0 ;;\n'
        '      *) echo "IPT: $*"; return 0 ;;\n'
        '    esac\n'
        '}\n'
        'ip6tables() { iptables "$@"; }\n'
        % ("nf_tables" if iptables_is_shim else "legacy")
    )

    script = (_NFT_PRELUDE
              + 'WAN_IFACES="%s"\nFW_BACKEND="%s"\n' % (wan, backend)
              + _FAKE_NFT + stub_ver + stub_cmdv
              + fp.FIREWALL_SH_FUNCTIONS + "\n%s\n" % command)
    r = subprocess.run([sh], input=script, text=True, capture_output=True)
    out = r.stdout.splitlines()
    return ([ln[len("NFT: "):] for ln in out if ln.startswith("NFT: ")],
            [ln[len("IPT: "):] for ln in out if ln.startswith("IPT: ")])


@unittest.skipUnless(shutil.which("sh"), "нет sh")
class TestShellNftables(unittest.TestCase):
    """Shell-путь обязан уметь nftables.

    Раньше он знал только iptables, поэтому на OpenWrt с fw4 хук после
    `nft flush ruleset` не возвращал ничего: на чистом nft-образе iptables
    нет вовсе, а где есть — это шим мимо таблицы, которой владеет fw4.
    Обход оставался «запущенным» без единого правила.
    """

    def _nft(self, **kw):
        nft, _ipt = _run_shell_backend("nftables", **kw)
        return nft

    def test_creates_table_and_three_chains(self):
        cmds = self._nft()
        self.assertIn("add table inet zapret_gui", cmds)
        for chain, spec in (
            ("postrouting", "type filter hook postrouting priority 150"),
            ("prerouting", "type filter hook prerouting priority -150"),
            ("natpost", "type nat hook postrouting priority 100"),
        ):
            self.assertTrue(
                any(("add chain inet zapret_gui %s" % chain) in c and spec in c
                    for c in cmds), "нет цепочки %s" % chain)

    def test_chain_spec_has_bare_semicolon(self):
        # issue #4: экранированный `\;` доезжает до nft буквально и валит
        # разбор — точка с запятой должна быть обычным символом.
        for c in self._nft():
            self.assertNotIn("\\;", c)

    def test_queue_rules_both_directions(self):
        cmds = self._nft()
        self.assertTrue(any("postrouting" in c and "tcp dport" in c
                            and "queue num 300 bypass" in c for c in cmds))
        self.assertTrue(any("prerouting" in c and "tcp sport" in c
                            and "queue num 300 bypass" in c for c in cmds))
        self.assertTrue(any("udp dport" in c for c in cmds))
        self.assertTrue(any("udp sport" in c for c in cmds))

    def test_masquerade_rule(self):
        self.assertTrue(any("natpost" in c and "masquerade" in c
                            for c in self._nft()))

    def test_port_ranges_use_dash(self):
        # issue #101: в nft диапазон — через дефис, иначе «Could not resolve
        # service: Servname not supported for ai_socktype».
        cmds = [c for c in self._nft() if "dport" in c or "sport" in c]
        self.assertTrue(cmds)
        for c in cmds:
            self.assertNotIn(":", c)
        self.assertTrue(any("2053-2087" in c for c in cmds))
        self.assertTrue(any("3478-3481" in c for c in cmds))

    def test_marks_without_iptables_mask(self):
        # В firewall.run метки лежат в форме MARK/MASK — nft нужен голый MARK.
        for c in self._nft():
            self.assertNotIn("0x40000000/0x40000000", c)
            self.assertNotIn("0x20000000/0x20000000", c)
        self.assertTrue(any("meta mark and 0x40000000 == 0x40000000"
                            in c for c in self._nft()))

    def test_iface_names_quoted(self):
        # issue #226: имя, начинающееся с цифры, без кавычек ломает лексер.
        cmds = [c for c in self._nft(wan="eth3 6in4-he_net")
                if "ifname" in c]
        self.assertTrue(cmds)
        for c in cmds:
            self.assertIn('{ "eth3", "6in4-he_net" }', c)

    def test_single_iface_without_braces(self):
        cmds = [c for c in self._nft(wan="br-wan") if "ifname" in c]
        self.assertTrue(cmds)
        for c in cmds:
            self.assertIn('oifname "br-wan"' if "oifname" in c
                          else 'iifname "br-wan"', c)

    def test_no_ifaces_no_filter(self):
        cmds = self._nft(wan="")
        self.assertTrue(cmds)
        self.assertFalse(any("ifname" in c for c in cmds))

    def test_table_recreated_not_appended(self):
        # Реаплай после flush'а не должен копить дубли: таблица сносится
        # целиком перед пересозданием.
        cmds = self._nft()
        self.assertLess(cmds.index("add table inet zapret_gui"),
                        cmds.index("add chain inet zapret_gui postrouting "
                                   "{ type filter hook postrouting "
                                   "priority 150 ; }"))
        self.assertIn("delete table inet zapret_gui", cmds)

    def test_stop_deletes_table(self):
        nft, _ipt = _run_shell_backend("nftables", command="firewall_stop")
        self.assertIn("delete table inet zapret_gui", nft)


@unittest.skipUnless(shutil.which("sh"), "нет sh")
class TestShellBackendChoice(unittest.TestCase):
    """Выбор бэкенда в shell — тем же правилом, что в firewall.py::_auto_detect."""

    def test_explicit_nftables_skips_iptables(self):
        nft, ipt = _run_shell_backend("nftables")
        self.assertTrue(nft)
        self.assertEqual(ipt, [], "на nft-бэкенде iptables трогать нельзя")

    def test_explicit_iptables_skips_nft(self):
        nft, ipt = _run_shell_backend("iptables")
        self.assertTrue(ipt)
        self.assertEqual(nft, [])

    def test_auto_only_nft(self):
        nft, ipt = _run_shell_backend("", have_iptables=False)
        self.assertTrue(nft)
        self.assertEqual(ipt, [])

    def test_auto_only_iptables(self):
        nft, ipt = _run_shell_backend("", have_nft=False)
        self.assertTrue(ipt)
        self.assertEqual(nft, [])

    def test_auto_both_legacy_prefers_iptables(self):
        nft, ipt = _run_shell_backend("")
        self.assertTrue(ipt)
        self.assertEqual(nft, [])

    def test_auto_iptables_shim_prefers_nft(self):
        # OpenWrt 22+/fw4: iptables — шим iptables-nft, пишущий в тот же
        # backend, которым владеет fw4 (issue #236).
        nft, ipt = _run_shell_backend("", iptables_is_shim=True)
        self.assertTrue(nft)
        self.assertEqual(ipt, [])

    def test_stop_clears_both_backends(self):
        # Бэкенд мог смениться с прошлого старта — иначе правила «прошлого»
        # останутся висеть навсегда. Снимаем оба, какой бы ни был текущий.
        nft, _ipt = _run_shell_backend("iptables", command="firewall_stop")
        self.assertIn("delete table inet zapret_gui", nft)
        nft, _ipt = _run_shell_backend("nftables", command="firewall_stop")
        self.assertIn("delete table inet zapret_gui", nft)


if __name__ == "__main__":
    unittest.main()
