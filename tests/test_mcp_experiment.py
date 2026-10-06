# tests/test_mcp_experiment.py
"""
Движок экспериментов: снимок → применение → пробы → гарантированный откат.

Что здесь стережём — по убыванию цены ошибки.

**Состояние возвращается всегда.** Прогон, оборвавшийся по TTL, по
просьбе или на исключении, обязан вернуть движок, правила и выбранную
стратегию к снимку. Эксперимент, оставивший на роутере временную
стратегию, — это не «неудачный тест», это роутер, который назавтра
работает не так, как написано в настройках.

**Дедмен-свитч срабатывает сам.** ``keep_best`` оставляет вариант
применённым, но НЕ подтверждает его: не пришёл ``commit`` — откат.
Гоняем с маленьким `mcp.experiment.default_ttl_sec`, а не `sleep(180)`.

**Снимок переживает выключение питания.** Он лежит на диске рядом с
`settings.json`, и при старте GUI `recover_after_restart()` возвращает
состояние. Это пункт приёмки фичи целиком.

**Занятый движок — отказ, а не драка.** Пока сканер держит общий
мьютекс, эксперимент не стартует и называет держателя.

**Отчёт влезает в лимит ответа.** Его читает модель с ограниченным
контекстом: три варианта на двух целях обязаны помещаться целиком.

Сеть, движок и правила замоканы: тест, который правда поднимает nfqws2,
красен на любой машине без root и зелен там, где сломан код.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from core import nfqws_control, probe_mark, probe_runner, strategy_experiment
from core.mcp import registry
from core.nfqws_session import OWNER_SCANNER, get_nfqws_session
from core.strategy_experiment import get_experiment_runner
from core.testers.probe import PROBE_CODES, ProbeResult


EXPERIMENTS = {"experiments": True, "control": True, "probes": True}

# Сколько ждём фонового прогона в тестах. Прогон замокан целиком, то
# есть идёт миллисекунды; секунды здесь — запас на медленный CI, а не
# ожидание сети.
WAIT_SEC = 20


def data(name, args=None, perms=None):
    return registry.call(name, args or {},
                         EXPERIMENTS if perms is None else perms
                         )["structuredContent"]


class FakeNfqws:
    """Движок, который слушается и запоминает, что с ним делали."""

    def __init__(self, running=False, can_start=True):
        self.running = running
        self.can_start = can_start
        self.args = []
        self.calls = []

    def is_running(self):
        return self.running

    def start(self, args=None):
        self.calls.append(("start", list(args or [])))
        if not self.can_start:
            return False
        self.running = True
        self.args = list(args or [])
        return True

    def stop(self):
        self.calls.append(("stop", []))
        self.running = False
        return True

    def restart(self, args=None):
        self.calls.append(("restart", list(args or [])))
        if not self.can_start:
            return False
        self.running = True
        self.args = list(args or [])
        return True

    def get_status(self):
        return {"running": self.running, "last_args": list(self.args),
                "pid": 4242 if self.running else None}

    def get_last_args(self):
        return list(self.args)

    def get_pid(self):
        return 4242 if self.running else None


class FakeFirewall:
    """Правила перехвата: только факт «стоят / не стоят»."""

    def __init__(self, applied=False):
        self.applied = applied
        self.calls = []

    def apply_rules(self):
        self.calls.append("apply")
        self.applied = True
        return True

    def remove_rules(self):
        self.calls.append("remove")
        self.applied = False
        return True

    def is_applied(self):
        return self.applied

    def get_status(self):
        return {"applied": self.applied, "type": "iptables",
                "rules_count": 4 if self.applied else 0}


class ExperimentCase(unittest.TestCase):
    """Песочница: свой settings.json, свой движок, замоканная сеть."""

    # argv, при котором «цель открывается»; остальные варианты мёртвые.
    GOOD = "--good"

    def setUp(self):
        import core.config_manager as cm

        registry.load_tools()
        self.dir = tempfile.mkdtemp(prefix="mcp-exp-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager

        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        self.addCleanup(self._restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        self.cfg.set("mcp", "permissions", dict(EXPERIMENTS))
        self.tune(stabilize_sec=0, default_ttl_sec=60, repeats=1)

        self.nfqws = FakeNfqws()
        self.firewall = FakeFirewall()
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))
        self._patch(probe_runner, "probe_domain", self.fake_probe)
        self.probed = []
        # Помеченная проба зависит от прав процесса и firewall хоста:
        # по умолчанию её нет, тест на неё включает её сам.
        self._patch(probe_mark, "baseline_mode",
                    lambda firewall=None: {"marked": False, "mark": 0,
                                           "reason": "тест: метки нет"})

        # Синглтон движка общий на процесс: тест обязан отдавать его
        # следующему чистым, иначе «прошлый прогон» протекает в соседний.
        self.addCleanup(self._reset_runner)

    # ── инфраструктура ──

    def _restore_env(self, value):
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
        if value is not None:
            os.environ["ZAPRET_GUI_CONFIG_DIR"] = value

    def _patch(self, module, name, value):
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, value)

    def _reset_runner(self):
        runner = get_experiment_runner()
        runner.stop()
        self.wait_idle(quiet=True)
        strategy_experiment._runner = None

    def tune(self, **values):
        section = dict(self.cfg.get("mcp", "experiment", default={}) or {})
        section.update(values)
        self.cfg.set("mcp", "experiment", section)

    def fake_probe(self, domain, timeout=5, port=443, **kw):
        self.probed.append((domain, list(self.nfqws.args),
                            self.nfqws.running))
        ok = self.nfqws.running and self.GOOD in self.nfqws.args
        return ProbeResult(domain=domain, code="ok" if ok else "tls_rst",
                           detail="фейк",
                           latency_ms=100.0 if ok else 0.0,
                           bytes_read=70000 if ok else 0,
                           resolved_ips=["1.2.3.4"])

    # ── ожидания ──

    def wait_awaiting(self):
        """Дождаться фазы «вариант оставлен, ждём commit»."""
        runner = get_experiment_runner()
        for _ in range(int(WAIT_SEC / 0.02)):
            status = runner.get_status()
            if status["awaiting_commit"]:
                return status
            if status["state"] != strategy_experiment.STATE_RUNNING:
                self.fail("прогон завершился, не дойдя до ожидания commit: "
                          "%s" % status)
            time.sleep(0.02)
        self.fail("прогон не дошёл до ожидания commit")

    def wait_idle(self, quiet=False):
        """Дождаться конца прогона."""
        runner = get_experiment_runner()
        for _ in range(int(WAIT_SEC / 0.02)):
            status = runner.get_status()
            if status["state"] != strategy_experiment.STATE_RUNNING:
                return status
            time.sleep(0.02)
        if quiet:
            return get_experiment_runner().get_status()
        self.fail("прогон не завершился")

    def start(self, **kwargs):
        kwargs.setdefault("variants", [
            {"label": "A", "args": ["--filter-tcp=443", self.GOOD]},
            {"label": "B", "args": ["--filter-tcp=443", "--bad"]},
        ])
        kwargs.setdefault("targets", ["a.example", "b.example"])
        kwargs.setdefault("repeats", 1)
        result = get_experiment_runner().start(**kwargs)
        self.assertTrue(result.get("ok"), result)
        return result


class TestFullCycle(ExperimentCase):
    """Снимок → baseline → варианты → отчёт → возврат."""

    def test_state_returns_to_the_snapshot(self):
        # До прогона движок работал со своей стратегией и правилами.
        self.nfqws.running = True
        self.nfqws.args = ["--filter-tcp=443", "--original"]
        self.firewall.applied = True

        self.start()
        self.wait_idle()

        self.assertTrue(self.nfqws.running)
        self.assertEqual(self.nfqws.args, ["--filter-tcp=443", "--original"])
        self.assertTrue(self.firewall.applied)

    def test_report_names_the_winner_and_explains_the_loser(self):
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()

        self.assertEqual(report["best"], "A")
        self.assertEqual([r["label"] for r in report["ranking"]], ["A", "B"])
        loser = next(v for v in report["variants"] if v["label"] == "B")
        self.assertEqual(loser["success_rate"], 0.0)
        # Провал без объяснения бесполезен: модель должна получить, куда
        # смотреть, а не только цифру 0.
        self.assertTrue(loser["hints"])

    def test_probe_codes_come_from_the_shared_dictionary(self):
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        rows = list(report["baseline"]["per_target"])
        for variant in report["variants"]:
            rows.extend(variant["per_target"])
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(target=row["target"]):
                self.assertIn(row["code"], PROBE_CODES)

    def test_baseline_runs_without_the_engine(self):
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertTrue(report["baseline"]["measured"])
        # Каждая цель измерена по разу на baseline и по разу на вариант.
        baseline_probes = [p for p in self.probed if not p[2]]
        self.assertEqual({p[0] for p in baseline_probes},
                         {"a.example", "b.example"})

    def test_marked_baseline_keeps_the_engine_running(self):
        # Метка проб: baseline меряется мимо очереди, движок для сети не
        # гасится (приём d2k). Помеченная проба видит «обхода нет».
        self.nfqws.running = True
        self.nfqws.args = ["--filter-tcp=443", self.GOOD]
        self._patch(probe_mark, "baseline_mode",
                    lambda firewall=None: {"marked": True,
                                           "mark": 0x10000000,
                                           "reason": "тест"})
        marks = []

        def probe(domain, timeout=5, port=443, **kw):
            marks.append(kw.get("mark", 0))
            if kw.get("mark"):
                return ProbeResult(domain=domain, code="tls_rst",
                                   detail="фейк", resolved_ips=["1.2.3.4"])
            return self.fake_probe(domain, timeout, port)

        self._patch(probe_runner, "probe_domain", probe)
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertEqual(report["baseline"]["method"], "probe_mark")
        self.assertFalse(report["baseline"]["engine_stopped"])
        self.assertEqual(report["baseline"]["open_without_bypass"], [])
        # Первые две пробы (baseline) — с меткой, дальше — без.
        self.assertEqual(marks[:2], [0x10000000, 0x10000000])
        self.assertTrue(all(m == 0 for m in marks[2:]))
        # До первого варианта движок не останавливали: первый вызов —
        # подъём варианта, а не остановка под baseline.
        self.assertTrue(self.nfqws.calls)
        self.assertNotEqual(self.nfqws.calls[0][0], "stop")

    def test_unmarked_baseline_stops_the_engine(self):
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertEqual(report["baseline"]["method"], "engine_stopped")
        self.assertIn("тест", report["baseline"]["method_note"])

    def test_open_target_makes_the_run_untrustworthy(self):
        # Цель, открытая и БЕЗ обхода: сравнивать нечего, и об этом надо
        # сказать прямо — иначе победителем станет вариант-пустышка.
        self._patch(probe_runner, "probe_domain",
                    lambda domain, timeout=5, port=443, **kw: ProbeResult(
                        domain=domain, code="ok", latency_ms=50.0,
                        bytes_read=70000))
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertEqual(sorted(report["baseline"]["open_without_bypass"]),
                         ["a.example", "b.example"])
        self.assertTrue(any("БЕЗ обхода" in w for w in report["warnings"]),
                        report["warnings"])
        # Победителя у такого прогона нет: score считается формулой
        # сканера и сам по себе ненулевой, но чинить было нечего — и
        # выдавать это за находку нельзя.
        self.assertEqual(report["best"], "")
        for variant in report["variants"]:
            with self.subTest(label=variant["label"]):
                self.assertEqual(variant["delta_vs_baseline"]["fixed"], [])

    def test_median_over_repeats_ignores_the_outlier(self):
        # Один выброс по латентности на роутере — норма; среднее он
        # сдвигает, медиана — нет.
        latencies = iter([100.0, 900.0, 110.0])

        def spiky(domain, timeout=5, port=443, **kw):
            return ProbeResult(domain=domain, code="ok",
                               latency_ms=next(latencies, 100.0),
                               bytes_read=70000)

        self._patch(probe_runner, "probe_domain", spiky)
        self.start(variants=[{"label": "A", "args": [self.GOOD]}],
                   targets=["a.example"], repeats=3, baseline=False)
        self.wait_idle()
        report = get_experiment_runner().get_result()
        row = report["variants"][0]["per_target"][0]
        self.assertEqual(row["latency_ms"], 110.0)
        self.assertEqual(row["latency_stat"], "median")


class TestDeadman(ExperimentCase):
    """keep_best оставляет вариант применённым — но не навсегда."""

    def test_keep_best_reverts_without_commit(self):
        self.nfqws.running = True
        self.nfqws.args = ["--original"]
        self.tune(default_ttl_sec=2)

        self.start(keep_best=True)
        status = self.wait_awaiting()
        self.assertEqual(status["applied_variant"], "A")
        self.assertIn(self.GOOD, self.nfqws.args)

        final = self.wait_idle()
        self.assertEqual(final["state"], strategy_experiment.STATE_REVERTED)
        self.assertTrue(final["expired"])
        # Главное: временная стратегия НЕ осталась на роутере.
        self.assertEqual(self.nfqws.args, ["--original"])

    def test_commit_keeps_the_variant_and_cancels_the_revert(self):
        self.tune(default_ttl_sec=30)
        self.start(keep_best=True)
        self.wait_awaiting()

        result = get_experiment_runner().commit()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["label"], "A")

        final = self.wait_idle()
        self.assertTrue(final["committed"])
        self.assertEqual(final["state"], strategy_experiment.STATE_FINISHED)
        self.assertIn(self.GOOD, self.nfqws.args)

    def test_commit_can_pick_another_variant(self):
        self.tune(default_ttl_sec=30)
        self.start(keep_best=True)
        self.wait_awaiting()

        result = get_experiment_runner().commit(label="B")
        self.assertTrue(result["ok"], result)
        self.wait_idle()
        self.assertIn("--bad", self.nfqws.args)

    def test_rollback_returns_state_at_once(self):
        self.nfqws.running = True
        self.nfqws.args = ["--original"]
        self.tune(default_ttl_sec=60)

        self.start(keep_best=True)
        self.wait_awaiting()
        result = get_experiment_runner().rollback()
        self.assertTrue(result["ok"], result)

        final = self.wait_idle()
        self.assertEqual(final["state"], strategy_experiment.STATE_REVERTED)
        self.assertEqual(self.nfqws.args, ["--original"])

    def test_commit_without_keep_best_is_refused_with_a_way_out(self):
        self.start(keep_best=False)
        self.wait_idle()
        result = get_experiment_runner().commit()
        self.assertFalse(result["ok"])
        # Отказ обязан называть, что сделать вместо этого.
        self.assertIn("keep_best", result["hint"])

    def test_stop_finishes_the_run_and_returns_state(self):
        self.nfqws.running = True
        self.nfqws.args = ["--original"]
        self.tune(default_ttl_sec=60)
        self.start(keep_best=True)
        self.wait_awaiting()

        result = get_experiment_runner().stop()
        self.assertTrue(result["ok"], result)
        self.wait_idle()
        self.assertEqual(self.nfqws.args, ["--original"])


class TestBusyEngine(ExperimentCase):
    """Пока движок держит кто-то другой, эксперимент не стартует."""

    def test_scanner_holding_the_mutex_refuses_the_start(self):
        session = get_nfqws_session()
        hold = session.claim(owner=OWNER_SCANNER, timeout=0,
                             reason="подбор для ya.ru")
        self.addCleanup(hold.release)

        # Захват из ЭТОГО потока виден чужим потокам как занятость, а
        # эксперимент берёт мьютекс своим рабочим потоком.
        result = get_experiment_runner().start(
            variants=[{"label": "A", "args": [self.GOOD]}],
            targets=["a.example"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["busy"], OWNER_SCANNER)
        self.assertIn("подбор для ya.ru", result["error"])
        # Отчёт предыдущего прогона неудачный старт не стирает.
        self.assertEqual(get_experiment_runner().get_status()["state"],
                         strategy_experiment.STATE_IDLE)

    def test_second_experiment_is_refused_by_name(self):
        self.tune(default_ttl_sec=60)
        first = self.start(keep_best=True)
        self.wait_awaiting()
        second = get_experiment_runner().start(
            variants=[{"label": "C", "args": [self.GOOD]}],
            targets=["a.example"])
        self.assertFalse(second["ok"])
        self.assertEqual(second["run_id"], first["run_id"])


class TestRecovery(ExperimentCase):
    """Выключение питания посреди прогона."""

    def marker(self):
        return os.path.join(self.dir, strategy_experiment.MARKER_NAME)

    def test_snapshot_lands_on_disk_and_is_removed_after(self):
        self.tune(default_ttl_sec=60)
        self.start(keep_best=True)
        self.wait_awaiting()
        self.assertTrue(os.path.exists(self.marker()))

        get_experiment_runner().rollback()
        self.wait_idle()
        self.assertFalse(os.path.exists(self.marker()))

    def test_recovery_restores_the_state_of_an_orphaned_run(self):
        # Так выглядит снимок, оставшийся от процесса, которого больше
        # нет: движок работал со своей стратегией, правила стояли.
        with open(self.marker(), "w", encoding="utf-8") as f:
            json.dump({
                "run_id": "exp-20260101-000000",
                "pid": 999999,
                "started_at": time.time() - 600,
                "ttl_sec": 180,
                "snapshot": {"nfqws_running": True,
                             "nfqws_args": ["--filter-tcp=443",
                                            "--original"],
                             "firewall_applied": True},
            }, f)
        self.nfqws.running = False
        self.firewall.applied = False

        result = strategy_experiment.recover_after_restart()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["recovered"])
        self.assertTrue(self.nfqws.running)
        self.assertEqual(self.nfqws.args, ["--filter-tcp=443", "--original"])
        self.assertTrue(self.firewall.applied)
        # Снимок отработал — второй раз он ничего не должен делать.
        self.assertFalse(os.path.exists(self.marker()))
        self.assertFalse(
            strategy_experiment.recover_after_restart()["recovered"])

    def test_no_marker_is_not_an_error(self):
        result = strategy_experiment.recover_after_restart()
        self.assertTrue(result["ok"])
        self.assertFalse(result["recovered"])


class TestDevMachine(ExperimentCase):
    """Устройство без nfqws2: движок объясняет, а не падает."""

    def test_missing_binary_is_reported_not_raised(self):
        self.cfg.set("zapret", "nfqws_binary", "/nonexistent/nfqws2")
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        for variant in report["variants"]:
            with self.subTest(label=variant["label"]):
                # Бинарника нет — валидацию не провести, и это честное
                # `available: false`, а не «вариант плохой».
                self.assertFalse(variant["validation"]["available"])
                self.assertFalse(variant["skipped"])

    def test_failed_validation_skips_applying_the_variant(self):
        self._patch(strategy_experiment, "_validate",
                    lambda argv: {"available": True, "ok": False,
                                  "returncode": 1,
                                  "output": "unknown option --bad"})
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        for variant in report["variants"]:
            with self.subTest(label=variant["label"]):
                self.assertTrue(variant["skipped"])
                self.assertIn("dry_run_failed",
                              [h["id"] for h in variant["hints"]])
        # Ни одного применения: мёртвый argv до движка не доехал.
        self.assertEqual([c for c in self.nfqws.calls if c[0] == "restart"],
                         [])


class TestTools(ExperimentCase):
    """Инструменты MCP поверх движка."""

    def test_start_status_result_round_trip(self):
        started = data("strategy_experiment_start", {
            "variants": [{"label": "A", "args": [self.GOOD]},
                         {"label": "B", "args": ["--bad"]}],
            "targets": ["a.example", "b.example"],
            "repeats": 1,
        })
        self.assertTrue(started["ok"], started)
        self.assertTrue(started["run_id"])
        self.assertTrue(started["async"])
        self.wait_idle()

        status = data("strategy_experiment_status")
        self.assertTrue(status["ok"])
        self.assertEqual(status["run_id"], started["run_id"])

        result = data("strategy_experiment_result")
        self.assertTrue(result["ok"])
        self.assertEqual(result["best"], "A")
        self.assertEqual(result["items"][0]["label"], "A")
        self.assertIn("note", result)

    def test_result_fits_the_response_limit(self):
        # Приёмка: три варианта на двух целях влезают целиком.
        self.start(variants=[
            {"label": "A", "args": ["--filter-tcp=443", self.GOOD]},
            {"label": "B", "args": ["--filter-tcp=443", "--bad"]},
            {"label": "C", "args": ["--filter-tcp=443", "--other"]},
        ])
        self.wait_idle()
        raw = registry.call("strategy_experiment_result", {}, EXPERIMENTS)
        payload = raw["structuredContent"]
        self.assertFalse(raw["isError"])
        self.assertFalse(payload.get("truncated"), payload.get("hint"))
        self.assertFalse(payload.get("shrunk_to_fit"))
        self.assertEqual(payload["count"], 3)
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        limit = int(self.cfg.get("mcp", "limits",
                                 default={}).get("response_kb", 32)) * 1024
        self.assertLess(size, limit)

    def test_history_lists_past_runs(self):
        self.start(variants=[{"label": "A", "args": [self.GOOD]}],
                   targets=["a.example"])
        self.wait_idle()
        history = data("strategy_experiment_history")
        self.assertTrue(history["ok"])
        self.assertEqual(history["items"][0]["best"], "A")

    def test_commit_with_save_as_needs_strategies_write(self):
        self.tune(default_ttl_sec=60)
        self.start(keep_best=True)
        self.wait_awaiting()
        result = data("strategy_experiment_commit",
                      {"save_as": "from-experiment"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["permission"], "strategies_write")
        get_experiment_runner().rollback()
        self.wait_idle()

    def test_make_active_without_save_as_is_refused(self):
        result = data("strategy_experiment_commit", {"make_active": True})
        self.assertFalse(result["ok"])
        self.assertIn("save_as", result["error"])

    def test_result_without_a_run_is_an_honest_empty(self):
        result = data("strategy_experiment_result")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)
        self.assertIn("reason", result)


class TestMemoryAfterTheRun(ExperimentCase):
    """Память подбора (S18): находка переживает перезапуск GUI.

    Отчёт эксперимента живёт в памяти процесса и умирает вместе с ним —
    поэтому «что открыло этот домен» обязано лечь в файл само, без
    отдельной просьбы. Иначе следующая модель гоняет те же варианты по
    второму кругу.
    """

    def setUp(self):
        super().setUp()
        from core import strategy_memory

        self.memory = strategy_memory
        saved = strategy_memory.network_key
        self.addCleanup(setattr, strategy_memory, "network_key", saved)
        strategy_memory.network_key = lambda refresh=False: {
            "id": "net-test", "iface": "eth9", "gateway": "10.0.0.1",
            "prefix": "203.0.0.0/16"}

    def test_the_winner_is_remembered_by_domain(self):
        self.start()
        self.wait_idle()
        found = self.memory.lookup(["a.example"])
        winners = [i for i in found["items"] if i["wins"]]
        self.assertTrue(winners, found)
        self.assertIn(self.GOOD, winners[0]["args"])

    def test_the_loser_is_remembered_too(self):
        # «Это не работает» — такое же знание, как «это работает»: без
        # него следующий прогон проверит мёртвый вариант заново.
        self.start()
        self.wait_idle()
        items = self.memory.lookup(["a.example"])["items"]
        losers = [i for i in items if i["losses"] and not i["wins"]]
        self.assertTrue(losers, items)
        self.assertIn("--bad", losers[0]["args"])

    def test_report_says_how_much_was_written(self):
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertGreater(report["memory"]["written"], 0)
        self.assertEqual(report["memory"]["network"], "net-test")

    def test_commit_marks_the_variant_as_kept(self):
        self.tune(default_ttl_sec=60)
        self.start(keep_best=True)
        self.wait_awaiting()
        get_experiment_runner().commit()
        self.wait_idle()
        items = self.memory.lookup(["a.example"])["items"]
        kept = [i for i in items if i.get("committed")]
        self.assertTrue(kept, items)
        self.assertIn(self.GOOD, kept[0]["args"])

    def test_a_broken_memory_does_not_break_the_run(self):
        # Память полезна, но эксперимент ценен и без неё.
        def boom(report):
            raise RuntimeError("диск переполнен")

        self._patch(self.memory, "remember_report", boom)
        self.start()
        report = self.wait_idle()
        self.assertNotEqual(report["state"],
                            strategy_experiment.STATE_FAILED)
        self.assertEqual(len(get_experiment_runner()
                             .get_result()["variants"]), 2)


class FakeCaptureRun:
    """Прогон снифера: живой, пока его не остановят.

    Настоящий прогон разбирает дамп в фоновом потоке и гасит
    ``running`` только после разбора — движок эксперимента на это и
    рассчитывает, поэтому подделка ведёт себя так же.
    """

    def __init__(self, run_id, params):
        self.id = run_id
        self.params = params
        self.running = True
        self.error = ""
        self.report = {}


class TestCaptureInsideTheRun(ExperimentCase):
    """Снифер по окну варианта (S18).

    Смысл проверок: дамп обязан идти РОВНО на окне замера и обязан
    оставаться необязательным. Эксперимент меряет стратегию; отсутствие
    tcpdump — это отчёт без картинки, а не упавший прогон.
    """

    # Сводка, которую отдаёт `traffic_capture.summary`: два TTL, один —
    # смертельно низкий. Ровно тот случай, ради которого всё затевалось.
    SUMMARY = {
        "packets": 12,
        "captured_total": 12,
        "sni": ["a.example"],
        "hosts": [],
        "ttl": {"1": 4, "64": 8},
        "flags": {"S": 4, "RST": 1},
        "protocols": {"tls": 6, "tcp": 6},
    }

    def setUp(self):
        super().setUp()
        from core import traffic_capture

        self.capture_starts = []
        self.capture_stops = []
        self.capture_runs = {}
        self.tcpdump = True

        self._patch(traffic_capture, "available", self.fake_available)
        self._patch(traffic_capture, "start", self.fake_start)
        self._patch(traffic_capture, "stop", self.fake_stop)
        self._patch(traffic_capture, "get", self.capture_runs.get)
        self._patch(traffic_capture, "summary",
                    lambda run: dict(self.SUMMARY))

    def fake_available(self):
        if self.tcpdump:
            return {"available": True, "binary": "/opt/sbin/tcpdump"}
        return {"available": False, "reason": "tcpdump на устройстве нет",
                "hint": "поставьте его: package_install(...)"}

    def fake_start(self, **kwargs):
        run_id = "capture-%d" % len(self.capture_starts)
        params = {"iface": "eth3", "port": kwargs.get("port"),
                  "proto": kwargs.get("proto", ""),
                  "filter": "tcp and port %s" % kwargs.get("port")}
        # Движок должен видеть тот же снимок, что и при живом снифере:
        # ярлык прогона + разобранные параметры.
        self.capture_starts.append(dict(params, engine_args=list(
            self.nfqws.args), running=self.nfqws.running))
        self.capture_runs[run_id] = FakeCaptureRun(run_id, params)
        return {"run_id": run_id, "params": params, "running": True}

    def fake_stop(self):
        self.capture_stops.append(True)
        for run in self.capture_runs.values():
            run.running = False
        return {"stopped": True}

    def variants_of(self, report):
        return {item["label"]: item for item in report["variants"]}

    def test_off_by_default(self):
        # Лишний процесс на каждый замер и заметный провайдеру след —
        # это просят осознанно.
        self.start()
        self.wait_idle()
        report = get_experiment_runner().get_result()
        self.assertEqual(self.capture_starts, [])
        for item in report["variants"]:
            self.assertNotIn("capture", item)

    def test_summary_lands_in_every_variant(self):
        self.start(capture=True)
        self.wait_idle()
        report = get_experiment_runner().get_result()
        for label, item in self.variants_of(report).items():
            with self.subTest(variant=label):
                sniffed = item["capture"]
                self.assertTrue(sniffed["measured"])
                self.assertEqual(sniffed["packets"], 12)
                self.assertEqual(sniffed["ttl"], {"1": 4, "64": 8})
                self.assertEqual(sniffed["iface"], "eth3")

    def test_window_matches_the_measurement(self):
        # По дампу на baseline и на каждый вариант, и каждый закрыт:
        # иначе в отчёт варианта B уехали бы пакеты варианта C.
        self.start(capture=True)
        self.wait_idle()
        self.assertEqual(len(self.capture_starts), 3)
        self.assertEqual(len(self.capture_stops), 3)
        # Первый дамп — baseline, и движок на нём остановлен.
        self.assertFalse(self.capture_starts[0]["running"])
        self.assertTrue(self.capture_starts[1]["running"])

    def test_port_is_443_unless_asked(self):
        self.start(capture=True)
        self.wait_idle()
        self.assertEqual(self.capture_starts[0]["port"], 443)
        self.assertEqual(self.capture_starts[0]["proto"], "tcp")

    def test_custom_port_reaches_tcpdump(self):
        self.start(capture=True, capture_port=8443)
        self.wait_idle()
        self.assertEqual(self.capture_starts[0]["port"], 8443)

    def test_hint_reads_the_dump(self):
        self.start(capture=True)
        self.wait_idle()
        report = get_experiment_runner().get_result()
        for label, item in self.variants_of(report).items():
            with self.subTest(variant=label):
                self.assertIn("capture_ttl_too_low",
                              [h["id"] for h in item["hints"]])

    def test_no_tcpdump_does_not_break_the_run(self):
        self.tcpdump = False
        result = self.start(capture=True)
        self.wait_idle()
        self.assertTrue(result["ok"])
        self.assertFalse(result["capture"]["available"])
        self.assertIn("tcpdump", result["capture"]["reason"])
        report = get_experiment_runner().get_result()
        # Прогон отработал целиком, просто без дампа.
        self.assertEqual(len(report["variants"]), 2)
        self.assertEqual(self.capture_starts, [])

    def test_tool_says_out_loud_that_the_sniffer_is_off(self):
        # Молчание модель прочитает как «в сети ничего интересного».
        self.tcpdump = False
        answer = data("strategy_experiment_start", {
            "variants": [{"label": "A", "args": ["--filter-tcp=443",
                                                 self.GOOD]}],
            "targets": ["a.example"], "capture": True})
        self.wait_idle()
        self.assertTrue(answer["ok"])
        self.assertIn("снифер НЕ включился", answer["hint"])

    def test_broken_sniffer_is_reported_not_raised(self):
        from core import traffic_capture

        def boom(**kwargs):
            raise traffic_capture.CaptureError("дамп уже идёт")

        self._patch(traffic_capture, "start", boom)
        self.start(capture=True)
        self.wait_idle()
        report = get_experiment_runner().get_result()
        for item in report["variants"]:
            self.assertFalse(item["capture"]["measured"])
            self.assertIn("дамп уже идёт", item["capture"]["error"])


class TestConcurrency(ExperimentCase):
    """Общий мьютекс держится всем прогоном."""

    def test_engine_is_owned_by_the_experiment_while_it_runs(self):
        self.tune(default_ttl_sec=60)
        self.start(keep_best=True)
        self.wait_awaiting()

        seen = {}

        def rival():
            try:
                get_nfqws_session().claim(owner=OWNER_SCANNER, timeout=0)
                seen["taken"] = True
            except Exception as e:              # noqa: BLE001 — граница
                seen["holder"] = getattr(e, "holder", {})

        thread = threading.Thread(target=rival)
        thread.start()
        thread.join(timeout=5)
        self.assertNotIn("taken", seen)
        self.assertEqual(seen["holder"].get("owner"), "experiment")

        get_experiment_runner().rollback()
        self.wait_idle()


if __name__ == "__main__":
    unittest.main()
