# tests/test_strategy_list_modes.py
"""Тесты режимов списков (filter.mode) при сборке аргументов стратегии.

Поведение (после отказа от автоподстановки other.txt): include-список
``other.txt`` НЕ подмешивается автоматически НИ в одном режиме — стратегия по
умолчанию применяется ко всему трафику под ``--filter-*``. Остаётся только
предохранитель ``--hostlist-exclude=netrogat.txt`` под ``filter.protect_excluded``
(по умолчанию True), кроме режима ipset.
"""

import os
import tempfile
import unittest

from core.config_manager import get_config_manager
from core.strategy_builder import get_strategy_manager


class TestListFlagModes(unittest.TestCase):

    def setUp(self):
        self.cfg = get_config_manager()
        self.cfg.load()
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "other.txt"), "w") as f:
            f.write("youtube.com\n")
        with open(os.path.join(self.d, "netrogat.txt"), "w") as f:
            f.write("vk.com\n")
        self.cfg.set("zapret", "lists_path", self.d)
        self.cfg.set("filter", "protect_excluded", True)
        self.sm = get_strategy_manager()

    def _flags(self, mode):
        self.cfg.set("filter", "mode", mode)
        return self.sm._compute_list_flags()

    # ── ключевой инвариант: include other.txt НЕ подмешивается нигде ──
    def test_no_other_include_in_any_mode(self):
        for mode in ("none", "hostlist", "autohostlist", "ipset"):
            flags = self._flags(mode)
            self.assertFalse(
                any(f.startswith("--hostlist=") for f in flags),
                "include --hostlist= не должен появляться в режиме %s: %r"
                % (mode, flags))

    def test_none_mode_exclude_only(self):
        # none + protect(default) → только exclude netrogat, без include/auto.
        flags = self._flags("none")
        self.assertTrue(any(f.startswith("--hostlist-exclude=") for f in flags))
        self.assertFalse(any(f.startswith("--hostlist=") for f in flags))
        self.assertFalse(any("--hostlist-auto=" in f for f in flags))

    def test_hostlist_mode_is_alias_of_none(self):
        self.assertEqual(self._flags("hostlist"), self._flags("none"))

    def test_autohostlist_mode_adds_auto_no_include(self):
        flags = self._flags("autohostlist")
        self.assertTrue(any(f.startswith("--hostlist-auto=") for f in flags))
        self.assertTrue(any(f.startswith("--hostlist-exclude=") for f in flags))
        self.assertFalse(any(f.startswith("--hostlist=") for f in flags))

    def test_ipset_mode_empty(self):
        self.assertEqual(self._flags("ipset"), [])

    def test_protect_excluded_off_none_is_empty(self):
        self.cfg.set("filter", "protect_excluded", False)
        self.assertEqual(self._flags("none"), [])

    # ── _inject_list_flags ──
    def test_inject_respects_existing_hostlist(self):
        args = ["--filter-tcp=443", "--hostlist=/x/custom.txt",
                "--lua-desync=multisplit"]
        out = self.sm._inject_list_flags(
            args, ["--hostlist-exclude=/y/netrogat.txt"])
        self.assertEqual(out, args)  # не трогаем — профиль сам задал список

    def test_inject_after_filter(self):
        args = ["--filter-tcp=443", "--lua-desync=multisplit"]
        out = self.sm._inject_list_flags(
            args, ["--hostlist-exclude=/y/netrogat.txt"])
        self.assertEqual(out[0], "--filter-tcp=443")
        self.assertEqual(out[1], "--hostlist-exclude=/y/netrogat.txt")

    def test_explicit_path_backward_compat(self):
        # Явный hostlist_path (как у сканера) → один --hostlist=<path>.
        path = os.path.join(self.d, "other.txt")
        strategy = {
            "id": "t", "name": "t", "profiles": [
                {"id": "p1", "args": "--filter-tcp=443 --lua-desync=multisplit",
                 "enabled": True}
            ],
        }
        args = self.sm.build_nfqws_args(strategy, hostlist_path=path)
        hl = [a for a in args if a.startswith("--hostlist=")]
        self.assertEqual(len(hl), 1)
        self.assertIn(path, hl[0])


if __name__ == "__main__":
    unittest.main()
