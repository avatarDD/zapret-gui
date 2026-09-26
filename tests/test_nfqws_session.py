# tests/test_nfqws_session.py
"""
Общий мьютекс на движок: захват, снимок состояния и возврат «как было».

Что здесь стережётся.

**Занято — это ответ, а не зависание.** Захват с ``timeout=0`` обязан
сразу сказать, КТО держит движок и с какого времени: из этого строятся
тексты отказов в UI и в инструментах MCP.

**Мьютекс не залипает.** Исключение внутри ``with``, повторный
``release()``, лок от умершего процесса — ни один из этих случаев не
имеет права запереть движок навсегда: обход после такого не запустить
ни кнопкой, ни автозапуском.

**Восстановление идемпотентно.** Сканер и движок экспериментов вызывают
``restore()`` из ``finally``, иногда дважды подряд; второй вызов не
должен ни поднимать движок заново, ни снимать чужие правила.

Менеджеры подменяются: тест, реально дёргающий iptables и поднимающий
nfqws2, портит машину, на которой его запустили.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from core import nfqws_control, nfqws_session
from core.nfqws_session import (OWNER_EXPERIMENT, OWNER_SCANNER, NfqwsSession,
                                SessionBusy, get_nfqws_session)


class FakeNFQWS:
    """Движок, который слушается и помнит, о чём его просили."""

    def __init__(self, running=False, args=None):
        self.running = running
        self.args = list(args or [])
        self.calls = []

    def is_running(self):
        return self.running

    def start(self, args=None):
        self.calls.append(("start", args))
        self.args = list(args or [])
        self.running = True
        return True

    def stop(self):
        self.calls.append(("stop", None))
        self.running = False
        return True

    def restart(self, args=None):
        self.calls.append(("restart", args))
        self.args = list(args or [])
        self.running = True
        return True

    def get_last_args(self):
        return list(self.args)

    def get_pid(self):
        return 4242 if self.running else None

    def get_status(self):
        return {"running": self.running, "pid": self.get_pid(),
                "last_args": list(self.args), "exit_code": None}


class FakeFirewall:
    """Правила, которые встают и снимаются без участия ядра."""

    def __init__(self, applied=False):
        self.applied = applied
        self.calls = []

    def is_applied(self):
        return self.applied

    def apply_rules(self, *a, **kw):
        self.calls.append("apply")
        self.applied = True
        return True

    def remove_rules(self):
        self.calls.append("remove")
        self.applied = False
        return True

    def get_status(self):
        return {"type": "iptables", "applied": self.applied,
                "rules": ["-A OUTPUT -j NFQUEUE"] if self.applied else [],
                "rules_count": 1 if self.applied else 0}


class FakeConfig:
    """Конфиг ровно с теми ключами, которые читает сессия."""

    def __init__(self, strategy_id="old-one"):
        self.values = {("strategy", "current_id"): strategy_id,
                       ("strategy", "current_name"): "Старая",
                       ("firewall", "apply_on_start"): True}
        self.saved = 0

    def get(self, *parts, **kw):
        return self.values.get(tuple(parts), kw.get("default"))

    def set(self, *args):
        self.values[tuple(args[:-1])] = args[-1]

    def save(self):
        self.saved += 1
        return True


class SessionCase(unittest.TestCase):
    """Своя сессия, свой каталог настроек, подменённые менеджеры."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="zapret-session-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self._env("ZAPRET_GUI_CONFIG_DIR", self.dir)

        self.session = NfqwsSession()
        self.nfqws = FakeNFQWS()
        self.firewall = FakeFirewall()
        self.cfg = FakeConfig()
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))

    def _env(self, name, value):
        saved = os.environ.get(name)
        self.addCleanup(lambda: (os.environ.__setitem__(name, saved)
                                 if saved is not None
                                 else os.environ.pop(name, None)))
        os.environ[name] = value

    def _patch(self, module, name, value):
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, value)

    @property
    def lock_path(self):
        return os.path.join(self.dir, nfqws_session.LOCK_NAME)

    def hold_elsewhere(self, owner=OWNER_SCANNER, reason="подбор"):
        """Занять сессию из ДРУГОГО потока и отпустить в конце теста."""
        taken, done = threading.Event(), threading.Event()

        def worker():
            with self.session.acquire(owner=owner, timeout=0,
                                      reason=reason):
                taken.set()
                done.wait(5)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(done.set)
        self.assertTrue(taken.wait(5), "поток не успел занять сессию")
        return done


class TestAcquire(SessionCase):
    """Захват, освобождение и честный отказ."""

    def test_free_session_has_no_holder(self):
        self.assertEqual(self.session.holder(), {})
        self.assertFalse(self.session.held_by_me())

    def test_acquire_names_owner_and_frees_after(self):
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            holder = self.session.holder()
            self.assertEqual(holder["owner"], OWNER_SCANNER)
            self.assertGreaterEqual(holder["held_sec"], 0)
            self.assertEqual(holder["pid"], os.getpid())
            self.assertTrue(self.session.held_by_me())
        self.assertEqual(self.session.holder(), {})

    def test_busy_refusal_names_owner_and_time(self):
        self.hold_elsewhere(owner=OWNER_SCANNER, reason="подбор для ya.ru")
        with self.assertRaises(SessionBusy) as ctx:
            self.session.claim(OWNER_EXPERIMENT, timeout=0)
        self.assertEqual(ctx.exception.holder["owner"], OWNER_SCANNER)
        text = str(ctx.exception)
        self.assertIn("подбор стратегий", text)
        self.assertIn("подбор для ya.ru", text)
        self.assertIn("уже", text)

    def test_zero_timeout_does_not_wait(self):
        self.hold_elsewhere()
        started = time.monotonic()
        with self.assertRaises(SessionBusy):
            self.session.claim(OWNER_EXPERIMENT, timeout=0)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_timeout_waits_for_release(self):
        done = self.hold_elsewhere()
        threading.Timer(0.1, done.set).start()
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=5):
            self.assertEqual(self.session.holder()["owner"],
                             OWNER_EXPERIMENT)

    def test_exception_inside_with_frees_the_lock(self):
        with self.assertRaises(ValueError):
            with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
                raise ValueError("проба упала")
        self.assertEqual(self.session.holder(), {})
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            pass

    def test_second_release_does_not_free_the_next_owner(self):
        hold = self.session.claim(OWNER_SCANNER, timeout=0)
        hold.release()
        self.assertTrue(hold.released)

        other = self.session.claim(OWNER_EXPERIMENT, timeout=0)
        hold.release()          # повторный release прежнего держателя
        self.assertEqual(self.session.holder()["owner"], OWNER_EXPERIMENT)
        other.release()
        self.assertEqual(self.session.holder(), {})

    def test_nested_acquire_by_same_thread(self):
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            with self.session.acquire(owner="ui", timeout=0):
                pass
            # Внутренний выход не отпускает движок наружу.
            self.assertEqual(self.session.holder()["owner"],
                             OWNER_EXPERIMENT)
        self.assertEqual(self.session.holder(), {})

    def test_singleton(self):
        self.assertIs(get_nfqws_session(), get_nfqws_session())


class TestProcessLock(SessionCase):
    """Межпроцессная часть: файл рядом с settings.json."""

    def test_lock_file_lands_next_to_settings(self):
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0,
                                  reason="подбор"):
            self.assertTrue(os.path.exists(self.lock_path))
            record = json.load(open(self.lock_path))
            self.assertEqual(record["owner"], OWNER_SCANNER)
            self.assertEqual(record["pid"], os.getpid())
            self.assertNotIn("thread", record)
        self.assertFalse(os.path.exists(self.lock_path))

    def test_live_foreign_lock_blocks_and_is_named(self):
        # Родительский процесс заведомо жив и заведомо не мы.
        self._write_lock(pid=os.getppid(), owner=OWNER_EXPERIMENT)
        holder = self.session.holder()
        self.assertEqual(holder["owner"], OWNER_EXPERIMENT)
        self.assertEqual(holder["pid"], os.getppid())
        with self.assertRaises(SessionBusy):
            self.session.claim(OWNER_SCANNER, timeout=0)

    def test_dead_process_lock_is_stolen(self):
        self._write_lock(pid=_dead_pid(), owner=OWNER_EXPERIMENT)
        self.assertEqual(self.session.holder(), {})
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            self.assertEqual(self.session.holder()["owner"], OWNER_SCANNER)

    def test_stale_lock_of_live_process_is_stolen(self):
        self._write_lock(pid=os.getppid(), owner=OWNER_EXPERIMENT,
                         since=time.time() - nfqws_session.STALE_SEC - 60)
        self.assertEqual(self.session.holder(), {})
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            pass

    def test_lock_from_previous_boot_is_stolen(self):
        # Роутер перезагрузили посреди подбора: PID из файла теперь
        # занят чужим живым процессом, но загрузка уже другая.
        self._write_lock(pid=os.getppid(), owner=OWNER_SCANNER,
                         boot_id="00000000-0000-0000-0000-000000000000")
        if not nfqws_session._boot_id():
            self.skipTest("нет /proc/sys/kernel/random/boot_id")
        self.assertEqual(self.session.holder(), {})
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            pass

    def test_lock_of_this_boot_still_blocks(self):
        self._write_lock(pid=os.getppid(), owner=OWNER_SCANNER,
                         boot_id=nfqws_session._boot_id())
        with self.assertRaises(SessionBusy):
            self.session.claim(OWNER_EXPERIMENT, timeout=0)

    def test_taken_lock_records_boot_id(self):
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            record = json.load(open(self.lock_path))
        self.assertEqual(record.get("boot_id"), nfqws_session._boot_id())

    def test_our_own_leftover_is_stolen(self):
        # Процесс упал и поднялся с тем же pid: в памяти захвата нет.
        self._write_lock(pid=os.getpid(), owner=OWNER_SCANNER)
        self.assertEqual(self.session.holder(), {})
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            pass

    def test_broken_lock_does_not_block(self):
        with open(self.lock_path, "w") as f:
            f.write("{не json")
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            self.assertEqual(self.session.holder()["owner"], OWNER_SCANNER)

    def test_missing_config_dir_degrades_to_process_lock(self):
        self._env("ZAPRET_GUI_CONFIG_DIR",
                  os.path.join(self.dir, "нет-такого", "каталога"))
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            self.assertEqual(self.session.holder()["owner"], OWNER_SCANNER)
        self.assertEqual(self.session.holder(), {})

    def test_foreign_lock_is_not_removed_on_release(self):
        with self.session.acquire(owner=OWNER_SCANNER, timeout=0):
            self._write_lock(pid=os.getppid(), owner=OWNER_EXPERIMENT)
        self.assertTrue(os.path.exists(self.lock_path))

    def _write_lock(self, pid, owner, since=None, boot_id=None):
        record = {"owner": owner, "reason": "", "pid": pid,
                  "since": time.time() if since is None else since}
        if boot_id is not None:
            record["boot_id"] = boot_id
        with open(self.lock_path, "w") as f:
            json.dump(record, f)


class TestSnapshot(SessionCase):
    """Снимок состояния: движок, правила и активная стратегия."""

    def test_snapshot_reads_engine_firewall_and_strategy(self):
        self.nfqws = FakeNFQWS(running=True, args=["--filter-tcp=443"])
        self.firewall = FakeFirewall(applied=True)
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))

        snap = self.session.snapshot()
        self.assertTrue(snap["nfqws_running"])
        self.assertEqual(snap["nfqws_args"], ["--filter-tcp=443"])
        self.assertEqual(snap["nfqws_pid"], 4242)
        self.assertTrue(snap["firewall_applied"])
        self.assertEqual(snap["firewall_type"], "iptables")
        self.assertEqual(snap["firewall_rules_count"], 1)
        self.assertEqual(snap["strategy_id"], "old-one")
        self.assertEqual(snap["strategy_name"], "Старая")

    def test_snapshot_of_stopped_engine(self):
        snap = self.session.snapshot()
        self.assertFalse(snap["nfqws_running"])
        self.assertIsNone(snap["nfqws_pid"])
        self.assertFalse(snap["firewall_applied"])

    def test_snapshot_survives_silent_managers(self):
        """Менеджер без половины методов — не повод уронить захват."""
        self._patch(nfqws_control, "_managers",
                    lambda: (object(), object(), self.cfg))
        snap = self.session.snapshot()
        self.assertFalse(snap["nfqws_running"])
        self.assertEqual(snap["nfqws_args"], [])


class TestRestore(SessionCase):
    """Возврат «как было» — и повторный возврат тоже."""

    def _running_snapshot(self):
        self.nfqws = FakeNFQWS(running=True, args=["--filter-tcp=443"])
        self.firewall = FakeFirewall(applied=True)
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))
        return self.session.snapshot()

    def test_restores_engine_and_rules(self):
        snap = self._running_snapshot()
        self.nfqws.stop()
        self.firewall.remove_rules()
        self.nfqws.calls, self.firewall.calls = [], []

        result = self.session.restore(snap)
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.nfqws.running)
        self.assertEqual(self.nfqws.args, ["--filter-tcp=443"])
        self.assertTrue(self.firewall.applied)
        self.assertEqual(sorted(result["changed"]), ["firewall", "nfqws"])

    def test_restore_is_idempotent(self):
        snap = self._running_snapshot()
        self.nfqws.stop()
        self.firewall.remove_rules()
        self.session.restore(snap)
        self.nfqws.calls, self.firewall.calls = [], []

        again = self.session.restore(snap)
        self.assertTrue(again["ok"])
        self.assertEqual(again["changed"], [])
        self.assertEqual(self.nfqws.calls, [])
        self.assertEqual(self.firewall.calls, [])

    def test_restores_stopped_engine_and_removes_rules(self):
        snap = self.session.snapshot()          # всё выключено
        self.nfqws.start(["--чужое"])
        self.firewall.apply_rules()

        result = self.session.restore(snap)
        self.assertTrue(result["ok"])
        self.assertFalse(self.nfqws.running)
        self.assertFalse(self.firewall.applied)

    def test_rebuilds_args_when_engine_was_started_by_autostart(self):
        """Аргументов нет — поднимаем активную стратегию, не голый nfqws2."""
        self.nfqws = FakeNFQWS(running=True, args=[])
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))
        snap = self.session.snapshot()
        self.nfqws.stop()

        import core.strategy_builder as builder
        self._patch(builder, "active_strategy_args",
                    lambda source="": ["--dpi-desync=fake"])
        self.session.restore(snap)
        self.assertEqual(self.nfqws.args, ["--dpi-desync=fake"])

    def test_restores_active_strategy_id(self):
        snap = self.session.snapshot()
        self.cfg.set("strategy", "current_id", "эксперимент")
        result = self.session.restore(snap)
        self.assertIn("strategy", result["changed"])
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old-one")
        self.assertEqual(self.cfg.saved, 1)

    def test_restore_reports_failure_instead_of_raising(self):
        snap = self._running_snapshot()
        self.nfqws.stop()

        def boom(args=None):
            raise OSError("нет бинарника")

        self.nfqws.start = boom
        result = self.session.restore(snap)
        self.assertFalse(result["ok"])
        self.assertIn("нет бинарника", result["error"])


class TestApplyTemporary(SessionCase):
    """Временное применение argv — только с захваченной сессией."""

    def test_refuses_without_hold(self):
        with self.assertRaises(RuntimeError):
            self.session.apply_temporary(["--filter-tcp=443"])

    def test_applies_under_hold(self):
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            result = self.session.apply_temporary(["--filter-tcp=80"])
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.nfqws.running)
        self.assertEqual(self.nfqws.args, ["--filter-tcp=80"])


class TestControlIntegration(SessionCase):
    """`core/nfqws_control` живёт под тем же мьютексом."""

    def setUp(self):
        super().setUp()
        # Инструменты и роуты зовут синглтон, а не нашу сессию.
        self._patch(nfqws_session, "_session", self.session)
        self._patch(nfqws_control, "active_strategy_args",
                    lambda: ["--filter-tcp=443"])

    def test_owner_names_match_busy_vocabulary(self):
        """`busy()` узнаёт сканер по имени владельца — имена обязаны
        совпадать, иначе отказ потеряет и текст, и подсказку."""
        self.assertEqual(nfqws_control.BUSY_SCANNER, OWNER_SCANNER)
        self.assertEqual(nfqws_control.BUSY_BLOCKCHECK,
                         nfqws_session.OWNER_BLOCKCHECK)

    def test_busy_reports_session_holder(self):
        self.hold_elsewhere(owner=OWNER_SCANNER)
        holder = nfqws_control.busy()
        self.assertEqual(holder["who"], OWNER_SCANNER)
        self.assertIn("подбор стратегий", holder["reason"])

    def test_own_hold_is_not_busy(self):
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            self.assertEqual(nfqws_control.busy(), {})

    def test_start_refuses_while_scanner_holds_engine(self):
        self.hold_elsewhere(owner=OWNER_SCANNER)
        result = nfqws_control.start()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "busy")
        self.assertEqual(result["busy"], OWNER_SCANNER)
        self.assertIn("подбор стратегий", result["error"])
        self.assertEqual(self.nfqws.calls, [])
        self.assertEqual(self.firewall.calls, [])

    def test_holder_may_call_control(self):
        with self.session.acquire(owner=OWNER_EXPERIMENT, timeout=0):
            result = nfqws_control.start(["--filter-tcp=443"],
                                         source="experiment")
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.nfqws.running)

    def test_control_releases_after_call(self):
        nfqws_control.start(["--filter-tcp=443"])
        self.assertEqual(self.session.holder(), {})


class TestScannerIntegration(SessionCase):
    """Сканер держит тот же мьютекс и тем же снимком возвращает «как было».

    Поведение сканера при этом не меняется: сохранение и восстановление
    просто переехали в общий модуль.
    """

    def setUp(self):
        super().setUp()
        self._patch(nfqws_session, "_session", self.session)
        from core.strategy_scanner import StrategyScanner
        self.scanner = StrategyScanner()

    def test_scan_does_not_start_on_a_held_engine(self):
        """Иначе `finally` сканера «вернул бы как было» ЧУЖОЕ состояние."""
        entered = []
        self.scanner._run_scan_locked = lambda: entered.append(True)
        self.hold_elsewhere(owner=OWNER_EXPERIMENT, reason="A/B")

        self.scanner._run_scan()

        self.assertEqual(entered, [])
        status = self.scanner.get_status()
        self.assertEqual(status["status"], "error")
        self.assertIn("занят", status["error"])
        self.assertIn("эксперимент", status["error"])

    def test_scan_holds_the_session_and_frees_it(self):
        seen = {}
        self.scanner._run_scan_locked = (
            lambda: seen.update(holder=self.session.holder()))

        self.scanner._run_scan()

        self.assertEqual(seen["holder"]["owner"], OWNER_SCANNER)
        self.assertEqual(self.session.holder(), {})

    def test_saved_state_comes_from_the_shared_snapshot(self):
        self.nfqws.start(["--filter-tcp=443"])
        self.firewall.apply_rules()

        self.scanner._save_current_state()

        self.assertTrue(self.scanner._saved_nfqws_running)
        self.assertEqual(self.scanner._saved_nfqws_args,
                         ["--filter-tcp=443"])
        self.assertTrue(self.scanner._saved_firewall_applied)
        self.assertEqual(self.scanner._session_snapshot["strategy_id"],
                         "old-one")

    def test_restore_brings_the_engine_back(self):
        self.nfqws.start(["--filter-tcp=443"])
        self.firewall.apply_rules()
        self.scanner._save_current_state()
        self.nfqws.stop()
        self.firewall.remove_rules()

        self.scanner._restore_previous_state()

        self.assertTrue(self.nfqws.running)
        self.assertEqual(self.nfqws.args, ["--filter-tcp=443"])
        self.assertTrue(self.firewall.applied)

    def test_restore_leaves_a_stopped_engine_alone(self):
        """Движка до скана не было — восстанавливать нечего.

        Это поведение сканера с самого начала: «как было» в таком
        случае уже обеспечил `_ensure_cleanup`.
        """
        self.scanner._save_current_state()
        self.nfqws.calls, self.firewall.calls = [], []

        self.scanner._restore_previous_state()

        self.assertEqual(self.nfqws.calls, [])
        self.assertEqual(self.firewall.calls, [])


def _dead_pid() -> int:
    """PID, которого заведомо нет: рождён и похоронен прямо здесь."""
    import subprocess
    proc = subprocess.Popen(["true"])
    proc.wait()
    return proc.pid


if __name__ == "__main__":
    unittest.main()
