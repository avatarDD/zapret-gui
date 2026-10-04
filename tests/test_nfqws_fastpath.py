"""--fastpath-workaround: только бинарнику, который знает опцию.

Опция есть лишь в сборке nfqws2-keenetic (патч tls-reasm-fastpath поверх
zapret2 v1.0.5.2). Штатный nfqws2 bol-van с незнакомой опцией не стартует,
поэтому её наличие проверяется по `-?` самого бинарника.
"""

import os
import shutil
import stat
import tempfile
import unittest

from core.nfqws_manager import NFQWSManager


def _fake_binary(dirpath, with_option):
    path = os.path.join(dirpath, "nfqws2")
    extra = (" --fastpath-workaround=0|1|auto\\t\\t\\t; hardware fastpath "
             "workaround for TLS reassembly (default : 0)\\n"
             if with_option else "")
    with open(path, "w") as f:
        f.write("#!/bin/sh\nprintf ' --qnum=<nfqueue_number>\\n%s'\n"
                "exit 1\n" % extra)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


class _Cfg:
    def __init__(self, mode="auto"):
        self.mode = mode

    def get(self, section, key=None, default=None):
        if (section, key) == ("nfqws", "fastpath_workaround"):
            return self.mode
        if (section, key) == ("zapret", "lua_path"):
            return "/nonexistent"
        if (section, key) == ("interfaces", "wan"):
            return "eth0"
        return default


class TestFastpathWorkaround(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nfqws-fp-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _argv(self, with_option, strategy, mode="auto"):
        d = tempfile.mkdtemp(dir=self.tmp)
        binary = _fake_binary(d, with_option)
        mgr = NFQWSManager.__new__(NFQWSManager)
        return mgr.compose_command(strategy, binary=binary, cfg=_Cfg(mode))

    def test_patched_binary_gets_auto(self):
        argv = self._argv(True, ["--filter-tcp=443"])
        self.assertIn("--fastpath-workaround=auto", argv)
        # Глобальная опция — до профилей стратегии.
        self.assertLess(argv.index("--fastpath-workaround=auto"),
                        argv.index("--filter-tcp=443"))

    def test_stock_binary_gets_nothing(self):
        argv = self._argv(False, ["--filter-tcp=443"])
        self.assertFalse([a for a in argv if "fastpath" in a])

    def test_mode_off(self):
        argv = self._argv(True, ["--filter-tcp=443"], mode="0")
        self.assertFalse([a for a in argv if "fastpath" in a])

    def test_strategy_value_wins_on_patched(self):
        argv = self._argv(True, ["--fastpath-workaround=1",
                                 "--filter-tcp=443"])
        self.assertEqual([a for a in argv if "fastpath" in a],
                         ["--fastpath-workaround=1"])

    def test_strategy_option_stripped_on_stock(self):
        argv = self._argv(False, ["--fastpath-workaround", "auto",
                                  "--filter-tcp=443",
                                  "--fastpath-workaround=1"])
        self.assertFalse([a for a in argv if "fastpath" in a])
        self.assertNotIn("auto", argv)
        self.assertIn("--filter-tcp=443", argv)

    def test_missing_binary(self):
        mgr = NFQWSManager.__new__(NFQWSManager)
        argv = mgr.compose_command(["--filter-tcp=443"],
                                   binary="/nonexistent/nfqws2", cfg=_Cfg())
        self.assertFalse([a for a in argv if "fastpath" in a])


if __name__ == "__main__":
    unittest.main()
