# tests/test_strategy_state.py
"""Парсинг и атомарная модификация state.tsv (z2k-state-persist.lua format).

Формат файла — TSV с заголовками-комментариями (`# key\thost\tstrategy\tts`).
Мы умеем читать и удалять записи; писать новые — задача nfqws2/Lua, не Python.
"""

import os
import tempfile
import unittest


class TestParseFormat(unittest.TestCase):

    def setUp(self):
        from core import strategy_state
        self.ss = strategy_state

    def test_parses_valid_row(self):
        e = self.ss._parse_line("default\tyoutube.com\t2\t1704067200")
        self.assertEqual(e["key"], "default")
        self.assertEqual(e["host"], "youtube.com")
        self.assertEqual(e["strategy"], 2)
        self.assertEqual(e["ts"], 1704067200)

    def test_skips_comments_and_blanks(self):
        self.assertIsNone(self.ss._parse_line("# header"))
        self.assertIsNone(self.ss._parse_line(""))
        self.assertIsNone(self.ss._parse_line("   "))

    def test_normalizes_host_lowercase_and_trailing_dot(self):
        e = self.ss._parse_line("yt_tcp\tYouTube.com.\t3\t1704000000")
        self.assertEqual(e["host"], "youtube.com")

    def test_rejects_too_few_columns(self):
        self.assertIsNone(self.ss._parse_line("default\tyoutube.com\t2"))

    def test_rejects_non_numeric_strategy(self):
        self.assertIsNone(self.ss._parse_line("k\th\twhat\t100"))

    def test_serialize_round_trip_matches_lua_header(self):
        out = self.ss._serialize([
            {"key": "yt_tcp", "host": "youtube.com",
             "strategy": 2, "ts": 1704067200},
        ])
        lines = out.splitlines()
        # Lua пишет ровно эти два комментария — должен совпадать байт-в-байт.
        self.assertEqual(lines[0], "# z2k autocircular state (persisted circular nstrategy)")
        self.assertEqual(lines[1], "# key\thost\tstrategy\tts")
        self.assertEqual(lines[2], "yt_tcp\tyoutube.com\t2\t1704067200")


class TestStateOperations(unittest.TestCase):

    def setUp(self):
        from core import strategy_state
        self.ss = strategy_state
        # Изолируем тест: переопределяем каталог через env
        self.tmpdir = tempfile.mkdtemp(prefix="zg-state-")
        self._prev_env = os.environ.get("Z2K_STATE_DIR_OVERRIDE")
        os.environ["Z2K_STATE_DIR_OVERRIDE"] = self.tmpdir
        # Также подмена fallback, чтобы не задеть /tmp общую систему
        self._prev_fallback = self.ss.STATE_FILE_FALLBACK
        self.ss.STATE_FILE_FALLBACK = os.path.join(self.tmpdir, "fallback.tsv")
        self.state_file = os.path.join(self.tmpdir, "state.tsv")
        self._write_state([
            "# z2k autocircular state (persisted circular nstrategy)",
            "# key\thost\tstrategy\tts",
            "default\tyoutube.com\t2\t1704067200",
            "yt_tcp\tyoutube.com\t3\t1704067210",
            "yt_tcp\tgooglevideo.com\t1\t1704067205",
            "rkn_tcp\trutracker.org\t5\t1704067300",
        ])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        if self._prev_env is None:
            os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
        else:
            os.environ["Z2K_STATE_DIR_OVERRIDE"] = self._prev_env
        self.ss.STATE_FILE_FALLBACK = self._prev_fallback

    def _write_state(self, lines):
        with open(self.state_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def test_list_entries_returns_all_4_rows(self):
        entries = self.ss.list_entries()
        self.assertEqual(len(entries), 4)
        hosts = sorted({e["host"] for e in entries})
        self.assertEqual(hosts, ["googlevideo.com", "rutracker.org", "youtube.com"])

    def test_list_entries_sorted_by_host(self):
        entries = self.ss.list_entries()
        sorted_pairs = [(e["host"], e["key"]) for e in entries]
        self.assertEqual(sorted_pairs, sorted(sorted_pairs))

    def test_summary_counts_by_key(self):
        s = self.ss.get_summary()
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["by_key"], {"default": 1, "yt_tcp": 2, "rkn_tcp": 1})
        self.assertEqual(s["last_ts"], 1704067300)
        self.assertTrue(s["state_dir_exists"])

    def test_clear_all_writes_empty_with_header(self):
        result = self.ss.clear_all()
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"], 4)
        # После сброса list_entries пуст, но файл остался с заголовком
        self.assertEqual(self.ss.list_entries(), [])
        with open(self.state_file, "r", encoding="utf-8") as f:
            txt = f.read()
        self.assertIn("# key\thost\tstrategy\tts", txt)

    def test_clear_host_removes_only_that_host(self):
        result = self.ss.clear_host("youtube.com")
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"], 2)
        remaining = self.ss.list_entries()
        self.assertEqual(len(remaining), 2)
        hosts = {e["host"] for e in remaining}
        self.assertNotIn("youtube.com", hosts)
        self.assertEqual(hosts, {"googlevideo.com", "rutracker.org"})

    def test_clear_host_normalizes_input(self):
        """Удаление работает по lowercase+stripped имени."""
        result = self.ss.clear_host("YouTube.com.")
        self.assertEqual(result["removed"], 2)

    def test_clear_key_removes_only_that_key(self):
        result = self.ss.clear_key("yt_tcp")
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"], 2)
        remaining = self.ss.list_entries()
        keys = {e["key"] for e in remaining}
        self.assertNotIn("yt_tcp", keys)

    def test_clear_host_empty_input_fails(self):
        result = self.ss.clear_host("")
        self.assertFalse(result["ok"])

    def test_clear_key_empty_input_fails(self):
        result = self.ss.clear_key("")
        self.assertFalse(result["ok"])

    def test_list_entries_merge_picks_newer_ts(self):
        # В fallback пишем ту же запись с БОЛЕЕ свежим ts — должна победить.
        with open(self.ss.STATE_FILE_FALLBACK, "w", encoding="utf-8") as f:
            f.write("# header\n")
            f.write("# key\thost\tstrategy\tts\n")
            f.write("default\tyoutube.com\t9\t1704999999\n")
        entries = self.ss.list_entries()
        # (default, youtube.com) теперь strategy=9, ts=1704999999
        match = [e for e in entries if e["key"] == "default"
                 and e["host"] == "youtube.com"]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]["strategy"], 9)
        self.assertEqual(match[0]["ts"], 1704999999)

    def test_list_entries_empty_when_no_file(self):
        os.remove(self.state_file)
        self.assertEqual(self.ss.list_entries(), [])


class TestEnvOverride(unittest.TestCase):

    def test_get_state_dir_respects_env(self):
        from core import strategy_state
        prev = os.environ.get("Z2K_STATE_DIR_OVERRIDE")
        try:
            os.environ["Z2K_STATE_DIR_OVERRIDE"] = "/custom/state"
            self.assertEqual(strategy_state.get_state_dir(), "/custom/state")
            self.assertEqual(
                strategy_state.get_state_file(), "/custom/state/state.tsv")
        finally:
            if prev is None:
                os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
            else:
                os.environ["Z2K_STATE_DIR_OVERRIDE"] = prev

    def test_get_state_dir_default(self):
        from core import strategy_state
        prev = os.environ.pop("Z2K_STATE_DIR_OVERRIDE", None)
        try:
            self.assertEqual(
                strategy_state.get_state_dir(),
                strategy_state.DEFAULT_STATE_DIR)
        finally:
            if prev is not None:
                os.environ["Z2K_STATE_DIR_OVERRIDE"] = prev


if __name__ == "__main__":
    unittest.main()
