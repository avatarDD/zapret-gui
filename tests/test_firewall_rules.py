# tests/test_firewall_rules.py
"""Тесты состава правил FirewallManager (iptables / nftables).

Не выполняем реальные iptables-команды — перехватываем _run_cmd и проверяем,
что после портирования из nfqws2-keenetic появились правила обоих направлений,
NAT MASQUERADE и обработка TCP-флагов.
"""

import unittest
from unittest import mock

from core.firewall import FirewallManager


def _capture_iptables(fw):
    """Запустить _apply_ipt_family для iptables, вернуть список команд (списки)."""
    captured = []

    def fake_run(cmd):
        captured.append(cmd)
        return True

    with mock.patch.object(fw, "_run_cmd", side_effect=fake_run), \
            mock.patch.object(fw, "_comment_supported", return_value=True), \
            mock.patch.object(fw, "_multiport_supported", return_value=True), \
            mock.patch.object(fw, "_connbytes_supported", return_value=True), \
            mock.patch.object(fw, "_nfqueue_supported", return_value=True), \
            mock.patch("core.firewall.shutil.which", return_value="/sbin/iptables"):
        rules = []
        fw._apply_ipt_family(
            "iptables", 300, "80,443", "443",
            "0x40000000", 20, 5, ["eth0"], rules,
        )
    return captured


class TestIptablesRules(unittest.TestCase):

    def setUp(self):
        self.fw = FirewallManager()
        self.cmds = _capture_iptables(self.fw)
        self.flat = [" ".join(c) for c in self.cmds]

    def test_has_postrouting_and_prerouting(self):
        self.assertTrue(any("POSTROUTING" in c for c in self.flat))
        self.assertTrue(any("PREROUTING" in c for c in self.flat))

    def test_has_nat_masquerade(self):
        nat = [c for c in self.flat if "nat" in c and "MASQUERADE" in c]
        self.assertTrue(nat, "ожидалось NAT MASQUERADE правило")

    def test_has_tcp_flag_rules(self):
        self.assertTrue(any("--tcp-flags syn,ack syn,ack" in c for c in self.flat))
        self.assertTrue(any("--tcp-flags fin fin" in c for c in self.flat))
        self.assertTrue(any("--tcp-flags rst rst" in c for c in self.flat))

    def test_has_mark_exclude_return(self):
        ret = [c for c in self.flat if "connmark" in c and "RETURN" in c]
        self.assertTrue(ret, "ожидался RETURN для MARK_EXCLUDE")

    def test_reply_connbytes_in_prerouting(self):
        pre_reply = [c for c in self.flat
                     if "PREROUTING" in c and "connbytes-dir=reply" in c]
        self.assertTrue(pre_reply)

    def test_outgoing_uses_dports_incoming_uses_sports(self):
        post = [c for c in self.flat if "POSTROUTING" in c and "multiport" in c]
        pre = [c for c in self.flat if "PREROUTING" in c and "multiport" in c]
        self.assertTrue(all("--dports" in c for c in post))
        self.assertTrue(all("--sports" in c for c in pre))


class TestIptablesNoCommentFallback(unittest.TestCase):
    """issue #151: если матч `-m comment` недоступен (нет iptables-mod-comment
    на Entware/Keenetic), правила КАЖДОЕ падали с «No chain/target/match» и
    обход не поднимался. Теперь правила идут в именованные цепочки nfqws_*
    без `-m comment`."""

    def setUp(self):
        self.fw = FirewallManager()
        self.captured = []
        with mock.patch.object(
                self.fw, "_run_cmd",
                side_effect=lambda c: self.captured.append(c) or True), \
                mock.patch.object(self.fw, "_comment_supported",
                                  return_value=False), \
                mock.patch.object(self.fw, "_multiport_supported",
                                  return_value=True), \
                mock.patch.object(self.fw, "_connbytes_supported",
                                  return_value=True), \
                mock.patch.object(self.fw, "_nfqueue_supported",
                                  return_value=True), \
                mock.patch.object(self.fw, "_ensure_named_chain") as ens, \
                mock.patch("core.firewall.shutil.which",
                           return_value="/sbin/iptables"):
            fw_rules = []
            self.fw._apply_ipt_family(
                "iptables", 300, "80,443", "443",
                "0x40000000", 20, 5, ["eth0"], fw_rules,
            )
            self.ensure_calls = ens.call_args_list
        self.flat = [" ".join(c) for c in self.captured]

    def test_rules_go_to_named_chains(self):
        self.assertTrue(any("nfqws_post" in c for c in self.flat))
        self.assertTrue(any("nfqws_pre" in c for c in self.flat))
        self.assertTrue(any("nfqws_nat" in c for c in self.flat))

    def test_no_comment_match_used(self):
        self.assertFalse(
            any("comment" in c for c in self.flat),
            "в no-comment режиме не должно быть `-m comment`")

    def test_no_builtin_chains_touched(self):
        # Правила (через _run_cmd) идут только в наши цепочки; во встроенные
        # POSTROUTING/PREROUTING ходит лишь jump из _ensure_named_chain (замокан).
        self.assertFalse(any(" POSTROUTING " in (" " + c + " ")
                             for c in self.flat))
        self.assertFalse(any(" PREROUTING " in (" " + c + " ")
                             for c in self.flat))

    def test_still_has_nfqueue_and_masquerade(self):
        self.assertTrue(any("NFQUEUE" in c for c in self.flat))
        self.assertTrue(any("MASQUERADE" in c for c in self.flat))

    def test_named_chains_were_ensured(self):
        names = {call.args[3] for call in self.ensure_calls}
        self.assertEqual(names, {"nfqws_post", "nfqws_pre", "nfqws_nat"})


class TestCommentProbe(unittest.TestCase):
    """Детект `-m comment`: запасной путь включаем ТОЛЬКО при положительном
    обнаружении отсутствия матча; иначе — как раньше (comment-режим)."""

    def setUp(self):
        FirewallManager._comment_support_cache.clear()
        self.fw = FirewallManager()

    def tearDown(self):
        FirewallManager._comment_support_cache.clear()

    def _run_with(self, add_rc, add_stderr):
        class _R:
            def __init__(self, rc, err=""):
                self.returncode, self.stderr, self.stdout = rc, err, ""

        def fake(cmd, **kw):
            # cmd = [ipt, -w?, -t, filter, ACTION, ...]
            if "-A" in cmd:
                return _R(add_rc, add_stderr)
            return _R(0)

        with mock.patch("core.firewall.subprocess.run", side_effect=fake), \
                mock.patch.object(FirewallManager, "_iptables_wait_flag",
                                  return_value=["-w"]):
            return self.fw._comment_supported("iptables")

    def test_unsupported_when_no_chain_target_match(self):
        self.assertFalse(self._run_with(
            1, "iptables: No chain/target/match by that name."))

    def test_supported_when_probe_rule_accepted(self):
        self.assertTrue(self._run_with(0, ""))

    def test_supported_when_failure_is_unrelated(self):
        # иная ошибка (например, нет прав) → не ломаем рабочий путь
        self.assertTrue(self._run_with(1, "Permission denied"))


def _apply_with_caps(multiport, connbytes, nfqueue, ports_tcp="80,443",
                     ports_udp="443,3478:3481"):
    """Прогнать _apply_ipt_family с заданной доступностью матчей/цели.

    Возвращает (ok, плоский список строк-команд). comment-режим включён
    (правила во встроенных цепочках), чтобы не отвлекаться на named-chains.
    """
    fw = FirewallManager()
    captured = []
    with mock.patch.object(fw, "_run_cmd",
                           side_effect=lambda c: captured.append(c) or True), \
            mock.patch.object(fw, "_comment_supported", return_value=True), \
            mock.patch.object(fw, "_multiport_supported", return_value=multiport), \
            mock.patch.object(fw, "_connbytes_supported", return_value=connbytes), \
            mock.patch.object(fw, "_nfqueue_supported", return_value=nfqueue), \
            mock.patch("core.firewall.shutil.which", return_value="/sbin/iptables"):
        rules = []
        ok = fw._apply_ipt_family(
            "iptables", 300, ports_tcp, ports_udp,
            "0x40000000", 20, 5, ["eth0"], rules,
        )
    return ok, [" ".join(c) for c in captured]


class TestIptablesNoMultiportConnbytesFallback(unittest.TestCase):
    """issue #151: на Keenetic/Entware матчи `-m multiport` / `-m connbytes`
    нередко недоступны и неустановимы через opkg. Тогда после фикса `-m comment`
    падали ровно 9 порт-зависимых правил из 14. Теперь порты бьются на отдельные
    --dport/--sport, а ограничитель connbytes выкидывается."""

    def setUp(self):
        self.ok, self.flat = _apply_with_caps(
            multiport=False, connbytes=False, nfqueue=True)

    def test_no_multiport_match(self):
        self.assertFalse(any("multiport" in c for c in self.flat),
                         "без xt_multiport не должно быть `-m multiport`")

    def test_no_connbytes_match(self):
        self.assertFalse(any("connbytes" in c for c in self.flat),
                         "без xt_connbytes не должно быть `-m connbytes`")

    def test_per_port_rules_emitted(self):
        # каждый TCP-порт получает своё правило --dport/--sport
        self.assertTrue(any("--dport 80 " in (c + " ") for c in self.flat))
        self.assertTrue(any("--dport 443 " in (c + " ") for c in self.flat))
        self.assertTrue(any("--sport 80 " in (c + " ") for c in self.flat))
        self.assertTrue(any("--sport 443 " in (c + " ") for c in self.flat))

    def test_udp_range_preserved_as_native_range(self):
        # диапазон портов остаётся диапазоном (нативный матч понимает X:Y)
        self.assertTrue(any("--dport 3478:3481" in c for c in self.flat))
        self.assertTrue(any("--sport 3478:3481" in c for c in self.flat))

    def test_nfqueue_still_present(self):
        self.assertTrue(any("NFQUEUE" in c for c in self.flat))

    def test_tcp_flags_still_present_per_port(self):
        self.assertTrue(any("--dport 80 --tcp-flags fin fin" in c
                            for c in self.flat))
        self.assertTrue(any("--sport 443 --tcp-flags syn,ack syn,ack" in c
                            for c in self.flat))


class TestIptablesNfqueueMissingAborts(unittest.TestCase):
    """issue #151: если цели NFQUEUE нет — обход невозможен, правила не льём."""

    def setUp(self):
        self.ok, self.flat = _apply_with_caps(
            multiport=True, connbytes=True, nfqueue=False)

    def test_returns_false(self):
        self.assertFalse(self.ok)

    def test_no_rules_emitted(self):
        # ни одного NFQUEUE/MASQUERADE-правила — выходим до их наката
        self.assertFalse(any("NFQUEUE" in c for c in self.flat))
        self.assertFalse(any("MASQUERADE" in c for c in self.flat))


class TestIptablesMultiportOnlyMissing(unittest.TestCase):
    """connbytes есть, multiport нет — connbytes сохраняется на каждом
    раздробленном правиле."""

    def setUp(self):
        self.ok, self.flat = _apply_with_caps(
            multiport=False, connbytes=True, nfqueue=True)

    def test_connbytes_kept_on_split_rules(self):
        cb = [c for c in self.flat if "connbytes" in c]
        self.assertTrue(cb)
        # connbytes-правила тоже без multiport
        self.assertFalse(any("multiport" in c for c in cb))


class TestFeatureProbe(unittest.TestCase):
    """Обобщённый детект матча/цели: False ТОЛЬКО на «No chain/target/match»."""

    def setUp(self):
        self.fw = FirewallManager()

    def _probe(self, add_rc, add_stderr):
        class _R:
            def __init__(self, rc, err=""):
                self.returncode, self.stderr, self.stdout = rc, err, ""

        def fake(cmd, **kw):
            return _R(add_rc, add_stderr) if "-A" in cmd else _R(0)

        with mock.patch("core.firewall.subprocess.run", side_effect=fake), \
                mock.patch.object(FirewallManager, "_iptables_wait_flag",
                                  return_value=["-w"]):
            return self.fw._ipt_probe_rule(
                "iptables", ["-j", "NFQUEUE", "--queue-num", "0",
                             "--queue-bypass"])

    def test_unavailable_on_no_chain_target_match(self):
        self.assertFalse(self._probe(
            1, "iptables: No chain/target/match by that name."))

    def test_available_on_success(self):
        self.assertTrue(self._probe(0, ""))

    def test_available_on_unrelated_error(self):
        self.assertTrue(self._probe(2, "Permission denied (you must be root)"))


class TestNftablesRules(unittest.TestCase):

    def setUp(self):
        self.fw = FirewallManager()
        captured = []

        def fake_run(cmd):
            captured.append(" ".join(cmd))
            return True

        with mock.patch.object(self.fw, "_run_cmd", side_effect=fake_run):
            self.fw._apply_nftables(
                300, "80,443", "443", "0x40000000", 20, 5,
                ["eth0"], None,
            )
        self.flat = captured

    def test_three_chains_created(self):
        joined = "\n".join(self.flat)
        self.assertIn("postrouting", joined)
        self.assertIn("prerouting", joined)
        self.assertIn("natpost", joined)

    def test_has_masquerade(self):
        self.assertTrue(any("masquerade" in c for c in self.flat))

    def test_has_tcp_flags(self):
        joined = "\n".join(self.flat)
        self.assertIn("tcp flags syn,ack", joined)


    def test_port_ranges_use_dash_not_colon(self):
        """Регрессия #101: nft диапазоны портов — через дефис."""
        fw = FirewallManager()
        captured = []
        with mock.patch.object(fw, "_run_cmd",
                               side_effect=lambda c: captured.append(" ".join(c)) or True):
            fw._apply_nftables(
                300, "80,443", "443,3478:3481,19294:19344,49152:65535",
                "0x40000000", 20, 5, ["eth0"], None)
        joined = "\n".join(captured)
        self.assertIn("3478-3481", joined)
        self.assertIn("19294-19344", joined)
        self.assertIn("49152-65535", joined)
        # старого двоеточного синтаксиса в udp dport/sport быть не должно
        self.assertNotIn("3478:3481", joined)


class TestNftablesIfaceQuoting(unittest.TestCase):
    """Регрессия: имя интерфейса, начинающееся с цифры (6in4-he_net,
    6in4-route64 — туннели на OpenWrt), без кавычек ломает nft-лексер:
    «Error: syntax error, unexpected string» на КАЖДОМ правиле с
    oifname/iifname → обход не поднимается. nft принимает любое имя
    строковым литералом в кавычках."""

    @staticmethod
    def _capture(wan4, wan6=None):
        fw = FirewallManager()
        captured = []
        with mock.patch.object(
                fw, "_run_cmd",
                side_effect=lambda c: captured.append(" ".join(c)) or True):
            fw._apply_nftables(
                300, "80,443", "443", "0x40000000", 20, 5, wan4, wan6)
        return [c for c in captured if "ifname" in c]

    def test_digit_leading_ifaces_quoted_in_set(self):
        rules = self._capture(["br-wan"], ["6in4-he_net", "6in4-route64"])
        self.assertTrue(rules)
        for c in rules:
            self.assertIn('"6in4-he_net"', c)
            self.assertIn('"6in4-route64"', c)
            self.assertIn('"br-wan"', c)
            # ни одного вхождения имени без открывающей кавычки
            self.assertNotRegex(c, r'[^"]6in4-')

    def test_single_iface_also_quoted(self):
        rules = self._capture(["6in4-wan"])
        self.assertTrue(rules)
        for c in rules:
            self.assertRegex(c, r'[oi]ifname "6in4-wan" ')


class TestAutoDetectFwType(unittest.TestCase):
    """Регрессия issue #236: на OpenWrt (fw4) `iptables` — это шим iptables-nft
    поверх nftables, поэтому при обеих доступных утилитах надо работать нативно
    через nft, а не через iptables-путь (который конфликтует с fw4)."""

    def _detect(self, has_ipt, has_nft, ipt_is_shim):
        def which(name):
            if name == "iptables":
                return "/usr/sbin/iptables" if has_ipt else None
            if name == "nft":
                return "/usr/sbin/nft" if has_nft else None
            return None

        with mock.patch("core.firewall.shutil.which", side_effect=which), \
                mock.patch.object(FirewallManager, "_iptables_is_nft_shim",
                                  return_value=ipt_is_shim):
            return FirewallManager._auto_detect()

    def test_only_iptables(self):
        self.assertEqual(self._detect(True, False, False), "iptables")

    def test_only_nft(self):
        self.assertEqual(self._detect(False, True, False), "nftables")

    def test_both_legacy_iptables_prefers_iptables(self):
        # Keenetic/Entware: настоящий iptables — оставляем iptables.
        self.assertEqual(self._detect(True, True, False), "iptables")

    def test_both_iptables_is_nft_shim_prefers_nft(self):
        # OpenWrt 22+/fw4: iptables — шим → работаем через nft.
        self.assertEqual(self._detect(True, True, True), "nftables")


class TestNftablesStatusApplied(unittest.TestCase):
    """Регрессия issue #235: на nftables статус всегда был «не активен».

    _get_nftables_rules отбрасывал строку `table inet zapret_gui {` —
    единственную с именем таблицы, — а _rules_applied ищет именно её.
    Итог: правила стоят, GUI показывает «Firewall: не активен».
    """

    _NFT_OUTPUT = (
        "table inet zapret_gui {\n"
        "\tchain postrouting {\n"
        "\t\ttype filter hook postrouting priority 150; policy accept;\n"
        '\t\toifname "wan" ct mark and 0x20000000 == 0x20000000 return\n'
        '\t\toifname "wan" tcp dport { 80, 443 } ct original packets 1-20 '
        "queue num 300 bypass\n"
        "\t}\n"
        "}\n"
    )

    def _rules(self):
        fw = FirewallManager()

        class _R:
            returncode = 0
            stdout = TestNftablesStatusApplied._NFT_OUTPUT

        with mock.patch("core.firewall.subprocess.run", return_value=_R()):
            return fw, fw._get_nftables_rules()

    def test_table_line_kept(self):
        _fw, rules = self._rules()
        self.assertTrue(any("zapret_gui" in r for r in rules))

    def test_rules_applied_true(self):
        fw, rules = self._rules()
        self.assertTrue(fw._rules_applied(rules))


class TestIptablesStatusNamedChains(unittest.TestCase):
    """Регрессия: firewall, поднятый shell-путём, читался как «не активен».

    Правила nfqws2 лежат либо во встроенных цепочках с комментарием
    `zapret-gui` (Python-путь), либо в именованных цепочках nfqws_* без
    комментария — так их ставят автозапуск S99zapret и reapply-хук
    персистентности (а также Python-путь на системах без xt_comment,
    issue #151). Статус читал только mangle POSTROUTING и требовал
    комментарий, поэтому во втором случае GUI показывал «Firewall: не
    активен» с пустым списком, пока пользователь не перезапустит обход.
    """

    # `iptables -t mangle -L nfqws_post -n -v --line-numbers`
    _NAMED_CHAIN = (
        "Chain nfqws_post (1 references)\n"
        "num   pkts bytes target     prot opt in     out     source"
        "               destination\n"
        "1        0     0 RETURN     0    --  *      eth0    0.0.0.0/0"
        "            0.0.0.0/0            connmark match 0x20000000\n"
        "2        1    52 NFQUEUE    6    --  *      eth0    0.0.0.0/0"
        "            0.0.0.0/0            multiport dports 80,443 "
        "NFQUEUE num 300 bypass\n"
    )

    # Встроенная цепочка: виден только переход в нашу цепочку — ни слова
    # NFQUEUE, ни комментария.
    _BUILTIN_WITH_JUMP = (
        "Chain POSTROUTING (policy ACCEPT 2 packets, 104 bytes)\n"
        "num   pkts bytes target     prot opt in     out     source"
        "               destination\n"
        "1        3   156 nfqws_post  0    --  *      *       0.0.0.0/0"
        "            0.0.0.0/0\n"
    )

    _EMPTY_CHAIN = (
        "Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)\n"
        "num   pkts bytes target     prot opt in     out     source"
        "               destination\n"
    )

    def _rules(self, hooked=True, chain_exists=True):
        """Свести iptables к одной живой цепочке mangle/nfqws_post."""
        def fake_run(cmd, **_kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            r = _R()
            # ip6tables в этом сценарии не участвует
            if cmd[0] != "iptables":
                r.returncode = 1
                return r
            if "-C" in cmd:            # проверка перехода из hook-цепочки
                r.returncode = 0 if hooked else 1
                return r
            if "-L" not in cmd:
                return r
            chain = cmd[cmd.index("-L") + 1]
            if chain == "nfqws_post":
                if not chain_exists:
                    r.returncode = 1
                    return r
                r.stdout = self._NAMED_CHAIN
            elif chain == "POSTROUTING":
                r.stdout = self._BUILTIN_WITH_JUMP
            elif chain in ("nfqws_pre", "nfqws_nat"):
                r.returncode = 1
            else:
                r.stdout = self._EMPTY_CHAIN
            return r

        fw = FirewallManager()
        with mock.patch("core.firewall.subprocess.run", side_effect=fake_run), \
                mock.patch("core.firewall.shutil.which",
                           side_effect=lambda n: "/sbin/iptables"
                           if n == "iptables" else None):
            return fw, fw._get_iptables_rules()

    def test_named_chain_rules_found(self):
        _fw, rules = self._rules()
        self.assertTrue(rules, "правила из nfqws_post должны попасть в статус")
        self.assertTrue(any("NFQUEUE num 300" in r for r in rules))

    def test_named_chain_rules_marked_applied(self):
        fw, rules = self._rules()
        self.assertTrue(fw._rules_applied(rules))

    def test_chain_name_visible_in_output(self):
        _fw, rules = self._rules()
        self.assertTrue(all(r.startswith("[ip4 mangle/nfqws_post]")
                            for r in rules))

    def test_orphan_chain_not_counted(self):
        # Цепочка есть, но перехода из POSTROUTING нет — трафик её не видит.
        fw, rules = self._rules(hooked=False)
        self.assertEqual(rules, [])
        self.assertFalse(fw._rules_applied(rules))

    def test_no_chain_no_rules(self):
        fw, rules = self._rules(chain_exists=False)
        self.assertEqual(rules, [])
        self.assertFalse(fw._rules_applied(rules))


class TestIptablesStatusCommentChains(unittest.TestCase):
    """Обычный путь: правила во встроенных цепочках с комментарием."""

    _POSTROUTING = (
        "Chain POSTROUTING (policy ACCEPT 2 packets, 104 bytes)\n"
        "num   pkts bytes target     prot opt in     out     source"
        "               destination\n"
        "1        0     0 NFQUEUE    6    --  *      eth0    0.0.0.0/0"
        "            0.0.0.0/0            multiport dports 80,443 "
        "/* zapret-gui */ NFQUEUE num 300 bypass\n"
        "2        7   402 MASQUERADE  0   --  *      eth0    0.0.0.0/0"
        "            0.0.0.0/0            /* podkop */\n"
    )

    def _rules(self, stdout):
        def fake_run(cmd, **_kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            r = _R()
            if cmd[0] != "iptables" or "-L" not in cmd:
                r.returncode = 1
                return r
            table = cmd[cmd.index("-t") + 1]
            chain = cmd[cmd.index("-L") + 1]
            r.stdout = stdout if (table, chain) == ("mangle", "POSTROUTING") \
                else ""
            return r

        fw = FirewallManager()
        with mock.patch("core.firewall.subprocess.run", side_effect=fake_run), \
                mock.patch("core.firewall.shutil.which",
                           side_effect=lambda n: "/sbin/iptables"
                           if n == "iptables" else None):
            return fw, fw._get_iptables_rules()

    def test_commented_rule_found(self):
        fw, rules = self._rules(self._POSTROUTING)
        self.assertEqual(len(rules), 1)
        self.assertIn("NFQUEUE num 300", rules[0])
        self.assertTrue(fw._rules_applied(rules))

    def test_foreign_rules_ignored(self):
        # Чужое правило без нашего комментария не должно давать «активен»:
        # иначе самолечение (reapply_if_missing) сочтёт firewall целым.
        foreign = self._POSTROUTING.replace("/* zapret-gui */", "/* podkop */")
        fw, rules = self._rules(foreign)
        self.assertEqual(rules, [])
        self.assertFalse(fw._rules_applied(rules))


class TestReapplyIfMissing(unittest.TestCase):
    """nfqws2 работает, а правил нет — GUI обязан вернуть их сам.

    Раньше boot-инициализация выходила раньше проверки firewall, если
    nfqws2 уже запущен (типичный случай после самообновления GUI: сервис
    перезапускается, nfqws2 переживает рестарт), и правила приходилось
    возвращать руками — перезапуском обхода.
    """

    def _run(self, running, applied, apply_ok=True, apply_on_start=True):
        import core.firewall as fwmod

        calls = {"apply": 0}
        fw = FirewallManager()

        def _apply():
            calls["apply"] += 1
            return apply_ok

        cfg = mock.Mock()
        cfg.get.return_value = apply_on_start
        nfqws = mock.Mock()
        nfqws.is_running.return_value = running

        with mock.patch.object(fw, "is_applied", return_value=applied), \
                mock.patch.object(fw, "apply_rules", side_effect=_apply), \
                mock.patch.object(fwmod, "get_firewall_manager",
                                  return_value=fw), \
                mock.patch.dict("sys.modules", {
                    "core.nfqws_manager": mock.Mock(
                        get_nfqws_manager=lambda: nfqws),
                    "core.config_manager": mock.Mock(
                        get_config_manager=lambda: cfg),
                }):
            return fwmod.reapply_if_missing(), calls

    def test_reapplies_when_running_without_rules(self):
        res, calls = self._run(running=True, applied=False)
        self.assertTrue(res["reapplied"])
        self.assertEqual(calls["apply"], 1)

    def test_noop_when_rules_present(self):
        res, calls = self._run(running=True, applied=True)
        self.assertFalse(res["reapplied"])
        self.assertEqual(calls["apply"], 0)

    def test_noop_when_nfqws_stopped(self):
        res, calls = self._run(running=False, applied=False)
        self.assertFalse(res["reapplied"])
        self.assertEqual(calls["apply"], 0)

    def test_respects_apply_on_start_off(self):
        res, calls = self._run(running=True, applied=False,
                               apply_on_start=False)
        self.assertFalse(res["reapplied"])
        self.assertFalse(res["checked"])
        self.assertEqual(calls["apply"], 0)

    def test_reports_apply_failure(self):
        res, calls = self._run(running=True, applied=False, apply_ok=False)
        self.assertFalse(res["reapplied"])
        self.assertEqual(calls["apply"], 1)


class TestNftPortSet(unittest.TestCase):

    def test_converts_colon_to_dash(self):
        from core.firewall import _nft_port_set
        self.assertEqual(_nft_port_set("443,3478:3481,5349"),
                         "443, 3478-3481, 5349")

    def test_single_port(self):
        from core.firewall import _nft_port_set
        self.assertEqual(_nft_port_set("443"), "443")

    def test_strips_blanks(self):
        from core.firewall import _nft_port_set
        self.assertEqual(_nft_port_set("443, , 80:90,"), "443, 80-90")

if __name__ == "__main__":
    unittest.main()
