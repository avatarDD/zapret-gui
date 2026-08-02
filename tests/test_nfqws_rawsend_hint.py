# tests/test_nfqws_rawsend_hint.py
"""
Issue #280: nfqws2 сыплет `rawsend: sendto (1278): Operation not permitted`
на каждый фейковый пакет. Строка ничего не объясняет, а обход при этом
молча не работает — «движок запущен, а сайты не открываются».

EPERM на raw-сокете возвращает netfilter: локально сгенерированный пакет
дропнут в OUTPUT. Значит, режет чужое правило фаервола, и GUI должен
сказать это один раз, показав найденных кандидатов.
"""

import unittest
from unittest import mock

import core.log_buffer as log_buffer
from core.nfqws_manager import NFQWSManager


class _Manager:
    """Менеджер без __init__ (тот лезет за PID-файлом и в конфиг)."""

    def __enter__(self):
        self.mgr = NFQWSManager.__new__(NFQWSManager)
        self.mgr._rawsend_explained = False
        self.mgr._debug = False
        self.warnings = []
        self._patches = [
            mock.patch.object(log_buffer.log, "warning",
                              side_effect=lambda m, **k: self.warnings.append(m)),
            mock.patch.object(log_buffer.log, "error",
                              side_effect=lambda m, **k: None),
            mock.patch.object(log_buffer.log, "debug",
                              side_effect=lambda m, **k: None),
            mock.patch.object(log_buffer.log, "info",
                              side_effect=lambda m, **k: None),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False

    def hints(self):
        return [w for w in self.warnings if "EPERM" in w]


def _no_suspects():
    return []


class TestRawsendHint(unittest.TestCase):

    def test_hint_emitted_once_per_run(self):
        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(_no_suspects)), _Manager() as m:
            for _ in range(5):
                m.mgr._log_nfqws_line(
                    "rawsend: sendto (1278): Operation not permitted")
            self.assertEqual(len(m.hints()), 1)

    def test_hint_repeats_after_restart(self):
        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(_no_suspects)), _Manager() as m:
            m.mgr._log_nfqws_line("rawsend: sendto: Operation not permitted")
            with mock.patch.object(NFQWSManager, "_remove_pid_file",
                                   lambda self: None):
                m.mgr._cleanup()
            m.mgr._log_nfqws_line("rawsend: sendto: Operation not permitted")
            self.assertEqual(len(m.hints()), 2)

    def test_unrelated_lines_do_not_trigger(self):
        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(_no_suspects)), _Manager() as m:
            for line in ("rawsend: ok",
                         "sendto failed: Network unreachable",
                         "error: profile not found",
                         "loading lua zapret-lib.lua"):
                m.mgr._log_nfqws_line(line)
            self.assertEqual(m.hints(), [])

    def test_found_rules_are_quoted_in_hint(self):
        rules = ["nft: ct state invalid drop",
                 "iptables-save: -A FORWARD -m conntrack "
                 "--ctstate INVALID -j DROP"]
        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(lambda: rules)), _Manager() as m:
            m.mgr._log_nfqws_line(
                "rawsend: sendto (1278): Operation not permitted")
            hint = m.hints()[0]
        self.assertIn("ct state invalid drop", hint)
        self.assertIn("--ctstate INVALID -j DROP", hint)

    def test_manual_commands_when_nothing_found(self):
        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(_no_suspects)), _Manager() as m:
            m.mgr._log_nfqws_line(
                "rawsend: sendto (1278): Operation not permitted")
            hint = m.hints()[0]
        self.assertIn("nft list ruleset", hint)
        self.assertIn("iptables-save", hint)

    def test_broken_firewall_probe_does_not_break_logging(self):
        def boom():
            raise OSError("nft missing")

        with mock.patch.object(NFQWSManager, "_rawsend_suspects",
                               staticmethod(boom)), _Manager() as m:
            m.mgr._log_nfqws_line(
                "rawsend: sendto (1278): Operation not permitted")
            self.assertEqual(len(m.hints()), 1)


class TestRawsendSuspects(unittest.TestCase):

    def test_picks_only_dropping_invalid_rules(self):
        nft_out = (
            "table inet fw4 {\n"
            "  chain forward {\n"
            "    ct state invalid drop comment \"!fw4: drop invalid\"\n"
            "    ct state established,related accept\n"
            "  }\n"
            "}\n")
        ipt_out = ("-A FORWARD -m conntrack --ctstate INVALID -j DROP\n"
                   "-A FORWARD -m conntrack --ctstate RELATED -j ACCEPT\n")

        def fake_run(cmd, **kw):
            out = nft_out if cmd[0] == "nft" else ipt_out
            return mock.Mock(returncode=0, stdout=out, stderr="")

        with mock.patch("core.nfqws_manager.shutil.which",
                        side_effect=lambda b: "/usr/sbin/" + b), \
             mock.patch("core.nfqws_manager.subprocess.run",
                        side_effect=fake_run):
            found = NFQWSManager._rawsend_suspects()

        self.assertEqual(len(found), 2, found)
        self.assertTrue(any("ct state invalid drop" in f for f in found))
        self.assertTrue(any("--ctstate INVALID -j DROP" in f for f in found))
        self.assertFalse(any("accept" in f.lower() for f in found))

    def test_absent_tools_are_skipped(self):
        with mock.patch("core.nfqws_manager.shutil.which", return_value=None):
            self.assertEqual(NFQWSManager._rawsend_suspects(), [])


if __name__ == "__main__":
    unittest.main()
