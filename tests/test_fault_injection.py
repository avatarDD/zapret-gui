# tests/test_fault_injection.py
"""
Отказы окружения (приём Tachyon, ``tests/fault_*.sh``): кончившийся
диск, битые файлы состояния, чужой процесс на месте PID из pid-файла,
протухший lock, упавший поток-сторож, отсутствующая или зависшая
команда, оборванная сеть.

Обычные тесты проверяют логику на правильных данных; здесь — что
модуль, у которого из-под ног выбили диск, процесс или сеть, не теряет
данные, не падает целиком и не врёт о результате. Каждый тест вносит
ровно один отказ и смотрит на последствия.
"""

import errno
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock


def _enospc(*_a, **_k):
    raise OSError(errno.ENOSPC, "No space left on device")


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="zg-fault-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.dir, name)


# ─────────────────────────── диск кончился ──────────────────────────

class TestDiskFull(TmpDir):
    def test_atomic_write_keeps_old_file_and_leaves_no_temp(self):
        from core import safe_io
        p = self.path("state.json")
        safe_io.atomic_write_json(p, {"v": 1})
        with mock.patch.object(safe_io.os, "fsync", side_effect=_enospc):
            with self.assertRaises(OSError):
                safe_io.atomic_write_json(p, {"v": 2})
        with open(p) as f:
            self.assertEqual(json.load(f), {"v": 1})
        self.assertEqual(sorted(os.listdir(self.dir)), ["state.json"])

    def test_config_save_reports_failure_and_keeps_file(self):
        from core.config_manager import ConfigManager
        cm = ConfigManager(config_dir=self.dir)
        cm.load()
        cm.set("gui", "port", 8123)
        self.assertTrue(cm.save())
        cm.set("gui", "port", 9999)
        with mock.patch("core.safe_io.os.fsync", side_effect=_enospc):
            self.assertFalse(cm.save())
        with open(cm.path) as f:
            self.assertEqual(json.load(f)["gui"]["port"], 8123)

    def test_quota_state_write_failure_is_not_fatal(self):
        from core import device_quota as dq
        with mock.patch.object(dq, "_state_path",
                               return_value=self.path("q.json")), \
                mock.patch("core.safe_io.os.fsync", side_effect=_enospc):
            dq._write_state({"date": "2026-10-21"})     # не бросает

    def test_bot_offset_write_failure_is_not_fatal(self):
        from core import notify_bot
        with mock.patch.object(notify_bot, "_offset_path",
                               return_value=self.path("bot.json")), \
                mock.patch("core.safe_io.os.fsync", side_effect=_enospc):
            notify_bot._save_offset("token", 42)

    def test_notify_event_survives_full_disk(self):
        from core import notify
        st = {"enabled": True, "token": "t", "chat_id": "1",
              "events": {"tunnel": True}}
        with mock.patch.object(notify, "settings", return_value=st), \
                mock.patch.object(notify, "_queue_path",
                                  return_value=self.path("q.json")), \
                mock.patch("core.safe_io.os.fsync", side_effect=_enospc), \
                mock.patch.object(notify, "_ensure_worker",
                                  create=True):
            notify.event("tunnel", "проверка диска %f" % time.time())

    def test_dns_autoselect_does_not_claim_unsaved_choice(self):
        from core import dns_bench as db
        cm = mock.Mock()
        cm.get.side_effect = lambda *k, default=None: (
            [] if k[-1] == "rules" else default)
        cm.save.return_value = False
        with mock.patch.object(db, "_cfg", return_value=cm), \
                mock.patch.object(db, "benchmark", return_value={
                    "ok": True, "best": "quad9", "rows": [1]}):
            r = db.autoselect()
        self.assertFalse(r["ok"])
        self.assertIn("сохран", r["error"])
        # И время выбора не сдвинулось: перезамер не отложен на сутки.
        set_calls = [c.args for c in cm.set.call_args_list]
        self.assertEqual(set_calls[-1][:2], ("dns_routing", "auto_server_at"))
        self.assertEqual(set_calls[-1][2], 0)


# ─────────────────────────── битые файлы ────────────────────────────

class TestCorruptFiles(TmpDir):
    GARBAGE = (b"", b"{", b"\xff\xfe\x00garbage", b"[1, 2, 3]", b"null",
               b'"str"')

    def test_settings_json_corrupt_is_preserved_not_overwritten(self):
        from core.config_manager import ConfigManager
        for blob in self.GARBAGE[1:]:
            with self.subTest(blob=blob):
                for name in os.listdir(self.dir):
                    os.remove(self.path(name))
                with open(self.path("settings.json"), "wb") as f:
                    f.write(blob)
                cm = ConfigManager(config_dir=self.dir)
                cm.load()                                   # не падает
                self.assertIsInstance(cm.get("gui"), dict)  # дефолты
                cm.save()
                kept = [n for n in os.listdir(self.dir)
                        if n.startswith("settings.json.broken")]
                self.assertEqual(len(kept), 1, os.listdir(self.dir))
                with open(self.path(kept[0]), "rb") as f:
                    self.assertEqual(f.read(), blob)

    def test_section_of_wrong_type_falls_back_to_default(self):
        from core.config_manager import ConfigManager
        for bad in ({"zapret": "x"}, {"nfqws": None}, {"gui": []}):
            with self.subTest(bad=bad):
                with open(self.path("settings.json"), "w") as f:
                    json.dump(bad, f)
                cm = ConfigManager(config_dir=self.dir)
                cm.load()
                key = next(iter(bad))
                self.assertIsInstance(cm.get(key), dict)

    def test_no_backup_possible_blocks_save(self):
        from core.config_manager import ConfigManager
        with open(self.path("settings.json"), "wb") as f:
            f.write(b"{broken")
        cm = ConfigManager(config_dir=self.dir)
        with mock.patch("core.config_manager.atomic_write_bytes",
                        side_effect=_enospc):
            cm.load()
        self.assertFalse(cm.save())
        with open(self.path("settings.json"), "rb") as f:
            self.assertEqual(f.read(), b"{broken")
        # Файл починили руками — запись снова разрешена.
        with open(self.path("settings.json"), "w") as f:
            json.dump({}, f)
        cm.load()
        self.assertTrue(cm.save())

    def test_broken_path_gets_random_password(self):
        from core.config_manager import DEFAULT_CONFIG, ConfigManager
        with open(self.path("settings.json"), "wb") as f:
            f.write(b"{broken")
        cm = ConfigManager(config_dir=self.dir)
        cm.load()
        self.assertNotEqual(cm.get("gui", "auth_password"),
                            DEFAULT_CONFIG["gui"]["auth_password"])

    def test_other_process_does_not_copy_again(self):
        from core.config_manager import ConfigManager
        with open(self.path("settings.json"), "wb") as f:
            f.write(b"{broken")
        ConfigManager(config_dir=self.dir).load()
        ConfigManager(config_dir=self.dir).load()       # «другой процесс»
        kept = [n for n in os.listdir(self.dir) if ".broken" in n]
        self.assertEqual(len(kept), 1)

    def test_frequent_loads_copy_broken_file_once(self):
        from core.config_manager import ConfigManager
        with open(self.path("settings.json"), "wb") as f:
            f.write(b"{oops")
        cm = ConfigManager(config_dir=self.dir)
        fake_time = mock.Mock()
        fake_time.strftime.side_effect = ["t1", "t2", "t3"]
        with mock.patch("core.config_manager.time", fake_time):
            for _ in range(3):
                cm.load()
        kept = [n for n in os.listdir(self.dir) if ".broken" in n]
        self.assertEqual(kept, ["settings.json.broken-t1"])

    def _check_reader(self, patch_target, attr, reader, empty):
        for blob in self.GARBAGE:
            with self.subTest(reader=reader.__qualname__, blob=blob):
                p = self.path("state")
                with open(p, "wb") as f:
                    f.write(blob)
                with mock.patch.object(patch_target, attr, return_value=p):
                    self.assertEqual(reader(), empty)

    def test_state_readers_tolerate_garbage(self):
        from core import device_quota, known_good, notify, smart_detect
        self._check_reader(known_good, "_state_path", known_good._read, {})
        self._check_reader(smart_detect, "_path", smart_detect._read, {})
        self._check_reader(device_quota, "_state_path",
                           device_quota._read_state, {})
        self._check_reader(notify, "_queue_path", notify._load_queue, [])

    def test_bot_offset_garbage(self):
        from core import notify_bot
        for blob in self.GARBAGE + (b'{"bot": "x", "offset": "abc"}',):
            with self.subTest(blob=blob):
                p = self.path("bot.json")
                with open(p, "wb") as f:
                    f.write(blob)
                with mock.patch.object(notify_bot, "_offset_path",
                                       return_value=p):
                    self.assertEqual(notify_bot._load_offset("t"), 0)

    def test_quota_with_garbage_state_starts_clean(self):
        from core import device_quota as dq
        p = self.path("q.json")
        for state in ('{"date": 5, "used": [1], "extra": "x"}',
                      '{"used": {"a": 1e400, "b": "x", "c": 7}, '
                      '"extra": {"k": Infinity}, "notified": [1, "c"]}'):
            with self.subTest(state=state):
                with open(p, "w") as f:
                    f.write(state)
                with mock.patch.object(dq, "_state_path", return_value=p):
                    q = dq.DeviceQuota()
                self.assertEqual(q._extra, {})
                self.assertIn(q._used, ({}, {"c": 7}))


# ─────────────────────────── чужой PID ───────────────────────────────

class TestReusedPid(unittest.TestCase):
    """PID из pid-файла пережил перезагрузку и достался другому процессу:
    «жив» не значит «наш»."""

    def test_mihomo(self):
        from core import mihomo_manager
        self.assertFalse(mihomo_manager._pid_alive(os.getpid()))

    def test_awg(self):
        from core import awg_manager
        self.assertFalse(awg_manager._pid_is_our_daemon(os.getpid(), "wg0"))

    def test_dead_pid(self):
        from core import mihomo_manager
        p = subprocess.Popen(["true"])
        p.wait()
        self.assertFalse(mihomo_manager._pid_alive(p.pid))


# ─────────────────────────── протухший lock ─────────────────────────

class TestStaleLock(TmpDir):
    def test_empty_and_old_locks_are_stolen(self):
        from core import strategy_state as ss
        target = self.path("state.tsv")
        for content in ("", "garbage", str(int(time.time()) - 3600)):
            with self.subTest(content=content):
                with open(target + ss.LOCK_SUFFIX, "w") as f:
                    f.write(content)
                lock = ss._acquire_lock(target, timeout=0.2)
                self.assertIsNotNone(lock)
                ss._release_lock(lock)
                self.assertFalse(os.path.exists(lock))

    def test_fresh_lock_is_respected(self):
        from core import strategy_state as ss
        target = self.path("state.tsv")
        with open(target + ss.LOCK_SUFFIX, "w") as f:
            f.write(str(int(time.time())))
        self.assertIsNone(ss._acquire_lock(target, timeout=0.2))


# ─────────────────────────── упавший поток ──────────────────────────

class TestWorkerSurvivesCrash(unittest.TestCase):
    """Сторож, у которого тик бросил исключение, обязан жить дальше:
    поток, умерший молча, — это квоты, которые больше не считаются."""

    def _run_loop(self, start, stop, tick_patch, ticks=3):
        calls = []

        def boom(*_a, **_k):
            calls.append(1)
            if len(calls) >= ticks:
                stop()
            raise RuntimeError("сбой тика")

        with tick_patch(boom):
            t = start()
            t.join(5)
        self.assertGreaterEqual(len(calls), ticks)
        self.assertFalse(t.is_alive())

    def test_device_quota_loop(self):
        from core import device_quota as dq
        with mock.patch.object(dq, "_read_state", return_value={}):
            q = dq.DeviceQuota()
        with mock.patch.object(dq, "TICK_SEC", 0.01):
            self._run_loop(
                lambda: (q.start(), q._thread)[1], q._stop.set,
                lambda f: mock.patch.object(q, "tick", side_effect=f))

    def test_known_good_loop(self):
        from core import known_good as kg
        with mock.patch.object(kg, "TICK_SEC", 0.01):
            self._run_loop(
                lambda: _thread(kg._loop), kg._stop.set,
                lambda f: mock.patch.object(kg, "tick", side_effect=f))
        kg._stop.clear()

    def test_dns_bench_loop(self):
        from core import dns_bench as db
        with mock.patch.object(db, "TICK_SEC", 0.01):
            self._run_loop(
                lambda: _thread(db._loop), db._stop.set,
                lambda f: mock.patch.object(db, "tick", side_effect=f))
        db._stop.clear()

    def test_notify_bot_poll_error_pauses_not_dies(self):
        from core import notify_bot as nb
        st = {"enabled": True, "interactive": True, "token": "t",
              "chat_id": "1"}
        polls = []

        def poll(_st):
            polls.append(1)
            if len(polls) >= 3:
                st["enabled"] = False       # выключили бота — поток выходит
            raise RuntimeError("сеть упала")

        with mock.patch.object(nb, "_settings", side_effect=lambda: st), \
                mock.patch.object(nb, "poll_once", side_effect=poll), \
                mock.patch.object(nb, "ERROR_PAUSE", 0.01):
            nb._run()
        self.assertEqual(len(polls), 3)
        self.assertEqual(nb._state["last_error"], "сеть упала")


def _thread(target):
    t = threading.Thread(target=target, daemon=True)
    t.start()
    return t


# ─────────────────────── нет или зависла команда ────────────────────

class TestMissingCommands(unittest.TestCase):
    def test_quota_firewall_missing(self):
        from core import device_quota as dq
        with mock.patch.object(dq, "_read_state", return_value={}):
            q = dq.DeviceQuota()
        with mock.patch.object(q, "_fw_type", return_value="nftables"), \
                mock.patch.object(dq, "_run",
                                  return_value=(127, "", "nft: not found")):
            q._install({"4": ["192.168.1.7"], "6": []}, {"4": [], "6": []})
        self.assertIn("not found", q._last_error)
        self.assertIsNone(q._installed)         # следующий тик повторит

    def test_lan_probe_ip_hangs_still_cleans(self):
        from core import lan_probe as lp
        cleaned = []

        def fake_run(args, timeout=10, input_text=None):
            if args[:3] == ["ip", "netns", "del"]:
                cleaned.append(1)
                return 0, "", ""
            if args[:3] == ["ip", "netns", "add"]:
                return 124, "", "timeout"
            return 0, "", ""

        with mock.patch.object(lp, "availability", return_value={
                "ok": True, "bridge": "br-lan", "router": "10.0.0.1/24"}), \
                mock.patch.object(lp, "child_probe", return_value=[]), \
                mock.patch.object(lp, "_run", side_effect=fake_run), \
                mock.patch.object(lp.shutil, "rmtree"), \
                mock.patch("core.device_schedule.read_neighbors",
                           return_value=[]):
            r = lp.run(["a.com"])
        self.assertFalse(r["ok"])
        self.assertEqual(len(cleaned), 2)

    def test_device_schedule_run_timeout(self):
        from core import device_schedule as ds
        with mock.patch.object(ds.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("nft",
                                                                     10)):
            rc, _, err = ds._run(["nft", "list", "ruleset"])
        self.assertEqual(rc, 127)
        self.assertIn("timed out", err)


# ─────────────────────────── оборванная сеть ────────────────────────

class _Resp:
    def __init__(self, data):
        self.data = data

    def read(self, n=-1):
        return self.data[:n] if n >= 0 else self.data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestNetworkFaults(unittest.TestCase):
    def test_subscription_oversized_answer_rejected(self):
        from core import subscription_manager as sm
        big = b"x" * (sm.MAX_DOWNLOAD_BYTES + 10)
        with mock.patch("core.download_transport.urlopen_via",
                        return_value=_Resp(big)):
            with self.assertRaises(RuntimeError):
                sm._fetch("https://prov/sub")

    def test_subscription_connection_reset(self):
        from core import subscription_manager as sm
        with mock.patch("core.download_transport.urlopen_via",
                        side_effect=ConnectionResetError(104, "reset")):
            with self.assertRaises(RuntimeError):
                sm._fetch("https://prov/sub")

    def test_leak_check_without_network_is_incomplete_not_ok(self):
        from core import leak_check as lc
        with mock.patch.object(lc, "_get",
                               side_effect=OSError("Network unreachable")), \
                mock.patch.object(lc, "_tunnels", return_value=[]), \
                mock.patch.object(lc, "_resolve"):
            r = lc.run()
        self.assertEqual(r["level"], "incomplete")
        self.assertFalse(r["complete"])

    def test_dns_bench_without_network_picks_nothing(self):
        from core import dns_bench as db
        with mock.patch.object(db, "candidates", return_value=[
                {"id": "google", "name": "G", "ip": "8.8.8.8",
                 "doh": "https://dns.google/dns-query", "dot": ""}]), \
                mock.patch("core.block_detector.doh_resolve",
                           return_value=[]), \
                mock.patch.object(db, "udp_query", side_effect=OSError("x")), \
                mock.patch.object(db, "doh_query", side_effect=OSError("x")):
            r = db.benchmark()
        self.assertTrue(r["ok"])
        self.assertEqual(r["best"], "")
        self.assertIn("hint", r)


if __name__ == "__main__":
    unittest.main()
