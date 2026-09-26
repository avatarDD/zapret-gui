# tests/test_scanner_improvements.py
"""
Улучшения подбора стратегий: QUIC-проба, правила firewall на весь прогон,
перепроверка лучших, память стратегий, остановка после N рабочих.

Сеть и движок подменены: проверяется логика сканера, а не интернет.
"""

import unittest
from unittest import mock

from core.models import SingleTestResult
from core.models import TestStatus as Status
from core.scan_targets import detect_target
from core.strategy_scanner import StrategyScanner, udp_probe_kind


def _res(status, error="", **raw):
    return SingleTestResult(target="t", test_type="quic", status=status,
                            error=error, latency_ms=20.0, details=error,
                            raw_data=raw)


class TestQuicProbe(unittest.TestCase):
    """UDP-подбор QUIC-цели — настоящим Initial, а не STUN на :19302."""

    def _scanner(self, target="youtube.com", mode="quick"):
        scanner = StrategyScanner()
        scanner._target = target
        scanner._protocol = "udp"
        scanner._mode = mode
        scanner._scan_profile = detect_target(target)
        return scanner

    def test_probe_kind_by_profile(self):
        self.assertEqual(udp_probe_kind(detect_target("youtube.com")), "quic")
        self.assertEqual(udp_probe_kind(detect_target("example.org")), "quic")
        self.assertEqual(udp_probe_kind(detect_target("discord.com")), "stun")

    def test_quic_target_never_uses_stun(self):
        scanner = self._scanner()
        scanner._baseline_by_af = {"ipv4": False}
        with mock.patch("core.testers.quic_tester.test_quic_handshake",
                        return_value=_res(Status.SUCCESS.value)) as quic, \
                mock.patch.object(scanner, "_probe_stun",
                                  side_effect=AssertionError("STUN")):
            probe = scanner._deep_probe()
        self.assertTrue(probe["success"])
        self.assertEqual(probe["test_type"], "quic")
        self.assertEqual(quic.call_args.kwargs["ip_family"], "ipv4")

    def test_quic_timeout_is_a_failure_with_code(self):
        scanner = self._scanner()
        scanner._baseline_by_af = {"ipv4": False}
        with mock.patch("core.testers.quic_tester.test_quic_handshake",
                        return_value=_res(Status.TIMEOUT.value,
                                          "QUIC_TIMEOUT")):
            probe = scanner._deep_probe()
        self.assertFalse(probe["success"])
        self.assertEqual(probe["error"], "QUIC_TIMEOUT")

    def test_quic_open_without_bypass_is_baseline_open(self):
        scanner = self._scanner()
        with mock.patch("core.testers.quic_tester.test_quic_handshake",
                        side_effect=lambda host, **kw: _res(
                            Status.SUCCESS.value
                            if kw["ip_family"] == "ipv4"
                            else Status.SKIPPED.value)):
            opened = scanner._run_baseline_test()
            probe = scanner._deep_probe()
        self.assertTrue(opened)
        self.assertEqual(scanner._baseline_by_af, {"ipv4": True})
        self.assertFalse(probe["success"])
        self.assertEqual(probe["error"], "BASELINE_OPEN")

    def test_quic_baseline_blocked(self):
        scanner = self._scanner()
        with mock.patch("core.testers.quic_tester.test_quic_handshake",
                        return_value=_res(Status.TIMEOUT.value,
                                          "QUIC_TIMEOUT")):
            self.assertFalse(scanner._run_baseline_test())
        self.assertEqual(scanner._baseline_by_af,
                         {"ipv4": False, "ipv6": False})


class _Engine:
    def __init__(self):
        self.running = False

    def start(self, args):
        self.running = True
        return True

    def stop(self):
        self.running = False
        return True

    def is_running(self):
        return self.running

    def get_exit_code(self):
        return None


class _Firewall:
    def __init__(self, applied=True):
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


class TestRulesOncePerScan(unittest.TestCase):
    """Правила стоят весь прогон; на стратегию — только nfqws2."""

    def _probe(self, fw):
        scanner = StrategyScanner()
        scanner._target = "youtube.com"
        scanner._protocol = "tcp"
        scanner._scan_profile = detect_target("youtube.com")
        entry = mock.Mock(section_id="s", source_file="basic.txt",
                          level="basic", label="")
        entry.name = "fake"
        entry.get_args_list.return_value = ["--lua-desync=fake"]
        probe = {"success": True, "latency_ms": 10.0, "error": "",
                 "http_code": 200, "kbps": 100.0, "body_passed": True,
                 "success_rate": 1.0, "score": 5.0, "test_type": "tls+body",
                 "details": "", "per_host": []}
        with mock.patch("core.nfqws_manager.get_nfqws_manager",
                        return_value=_Engine()), \
                mock.patch("core.firewall.get_firewall_manager",
                           return_value=fw), \
                mock.patch.object(scanner, "_build_strategy_args",
                                  return_value=["--lua-desync=fake"]), \
                mock.patch.object(scanner, "_get_stabilization_delay",
                                  return_value=0.0), \
                mock.patch.object(scanner, "_deep_probe",
                                  return_value=probe):
            result = scanner._probe_one_strategy(entry, 0)
        return scanner, result

    def test_rules_are_not_touched_per_strategy(self):
        fw = _Firewall(applied=True)
        _scanner, result = self._probe(fw)
        self.assertTrue(result.success)
        self.assertEqual(fw.calls, [])

    def test_lost_rules_are_put_back(self):
        fw = _Firewall(applied=False)
        scanner, result = self._probe(fw)
        self.assertTrue(result.success)
        self.assertEqual(fw.calls, ["apply"])
        self.assertEqual(scanner._rules_reapplied, 1)


def _entry(sid):
    entry = mock.Mock(section_id=sid, source_file="basic.txt",
                      level="basic", label="", blobs=[])
    entry.name = sid
    entry.get_args_list.return_value = ["--lua-desync=fake"]
    return entry


def _probe(sid, success, score=1.0, latency=50.0, kbps=100.0,
           error=""):
    from core.models import StrategyProbeResult
    return StrategyProbeResult(
        strategy_id=sid, strategy_name=sid, target="youtube.com",
        success=success, latency_ms=latency, throughput_kbps=kbps,
        success_rate=1.0 if success else 0.0, score=score, error=error,
        raw_data={"args_preview": "--filter-tcp=443 --lua-desync=%s" % sid})


class TestConfirmBest(unittest.TestCase):
    """Лучшие находки перепроверяются: медиана, стабильность, UNSTABLE."""

    def _scanner(self):
        scanner = StrategyScanner()
        scanner._target = "youtube.com"
        scanner._protocol = "tcp"
        scanner._entries_by_id = {"good": _entry("good"),
                                  "fluke": _entry("fluke")}
        scanner._results = [_probe("good", True, score=5.0, latency=40.0),
                            _probe("fluke", True, score=9.0)]
        return scanner

    def test_stable_is_confirmed_and_fluke_is_unstable(self):
        scanner = self._scanner()
        again = {"good": [_probe("good", True, latency=60.0),
                          _probe("good", True, latency=50.0)],
                 "fluke": [_probe("fluke", False, error="TCP_16_20"),
                           _probe("fluke", False, error="TCP_16_20")]}

        def reprobe(entry, index):
            return again[entry.section_id].pop(0)

        with mock.patch.object(scanner, "_confirm_settings",
                               return_value=(2, 2)), \
                mock.patch.object(scanner, "_probe_one_strategy",
                                  side_effect=reprobe), \
                mock.patch("core.strategy_scanner.INTER_STRATEGY_DELAY", 0):
            scanner._confirm_best()
        good, fluke = scanner._results[0], scanner._results[1]
        self.assertTrue(good.confirmed)
        self.assertEqual((good.passes, good.checks), (3, 3))
        self.assertEqual(good.latency_ms, 50.0)          # медиана 40/60/50
        self.assertFalse(fluke.success)
        self.assertEqual(fluke.error, "UNSTABLE")
        self.assertEqual((fluke.passes, fluke.checks), (1, 3))
        self.assertEqual(scanner._confirm_progress, 4)

    def test_best_prefers_confirmed_over_higher_score(self):
        scanner = StrategyScanner()
        confirmed = _probe("a", True, score=2.0)
        confirmed.confirmed = True
        scanner._results = [_probe("b", True, score=8.0), confirmed]
        scanner._build_report(0.0, 1.0, False)
        self.assertEqual(scanner.get_results().best_strategy.strategy_id, "a")

    def test_disabled_confirm_does_nothing(self):
        scanner = self._scanner()
        with mock.patch.object(scanner, "_confirm_settings",
                               return_value=(0, 2)), \
                mock.patch.object(scanner, "_probe_one_strategy",
                                  side_effect=AssertionError("проба")):
            scanner._confirm_best()


class TestStopAfter(unittest.TestCase):
    """«До первых рабочих»: перебор останавливается, перепроверка идёт."""

    def test_stops_after_n_working_then_confirms(self):
        scanner = StrategyScanner()
        scanner._target = "youtube.com"
        scanner._protocol = "tcp"
        scanner._mode = "quick"
        scanner._stop_after = 2
        scanner._confirm = True
        entries = [_entry("s%d" % i) for i in range(6)]
        calls = []

        def probe(entry, index):
            calls.append(entry.section_id)
            return _probe(entry.section_id, True)

        with mock.patch.object(scanner, "_check_prerequisites"), \
                mock.patch.object(scanner, "_save_current_state"), \
                mock.patch.object(scanner, "_ensure_tmp_hostlist"), \
                mock.patch.object(scanner, "_select_strategies",
                                  return_value=entries), \
                mock.patch.object(scanner, "_stop_current_nfqws"), \
                mock.patch.object(scanner, "_run_baseline_test",
                                  return_value=False), \
                mock.patch.object(scanner, "_start_scan_rules",
                                  return_value=True), \
                mock.patch.object(scanner, "_probe_one_strategy",
                                  side_effect=probe), \
                mock.patch.object(scanner, "_confirm_best") as confirm, \
                mock.patch.object(scanner, "_remember_findings"), \
                mock.patch.object(scanner, "_ensure_cleanup"), \
                mock.patch.object(scanner, "_restore_previous_state"), \
                mock.patch.object(scanner, "_save_resume_state") as save, \
                mock.patch.object(scanner, "_remove_resume_state") as drop, \
                mock.patch("core.strategy_scanner.INTER_STRATEGY_DELAY", 0):
            scanner._run_scan_locked()
        self.assertEqual(calls, ["s0", "s1"])
        self.assertTrue(scanner._stopped_early)
        confirm.assert_called_once()
        report = scanner.get_results().to_dict()
        self.assertTrue(report["stopped_early"])
        self.assertEqual(report["stop_after"], 2)
        # «Искать дальше»: позиция сохранена ровно за последней
        # проверенной стратегией, resume-файл не удалён.
        save.assert_called_with(2)
        drop.assert_not_called()


class TestMemory(unittest.TestCase):
    """Что уже срабатывало на цели в этой сети — первым; находки — в память."""

    def _scanner(self, start_index=0):
        scanner = StrategyScanner()
        scanner._target = "youtube.com"
        scanner._protocol = "tcp"
        scanner._start_index = start_index
        return scanner

    def test_remembered_go_first(self):
        scanner = self._scanner()
        entries = [_entry(x) for x in ("a", "b", "c", "d")]
        found = {"items": [
            {"strategy_id": "c", "wins": 3, "losses": 0, "stale": False},
            {"strategy_id": "x", "wins": 2, "losses": 0, "stale": False},
            {"strategy_id": "b", "wins": 0, "losses": 2, "stale": False},
            {"strategy_id": "d", "wins": 4, "losses": 0, "stale": True}]}
        with mock.patch("core.strategy_memory.lookup", return_value=found), \
                mock.patch.object(scanner, "_catalog_entry",
                                  return_value=None):
            ordered = scanner._memory_first(entries)
        self.assertEqual([e.section_id for e in ordered],
                         ["c", "a", "b", "d"])
        self.assertEqual(scanner._memory_ids, ["c"])

    def test_resume_uses_saved_memory_order(self):
        scanner = self._scanner(start_index=3)
        entries = [_entry(x) for x in ("a", "b", "c")]
        with mock.patch.object(scanner, "_load_resume_state",
                               return_value={"memory_ids": ["b"]}), \
                mock.patch("core.strategy_memory.lookup",
                           side_effect=AssertionError("свежая память")):
            ordered = scanner._memory_first(entries)
        self.assertEqual([e.section_id for e in ordered], ["b", "a", "c"])

    def test_findings_are_remembered(self):
        scanner = self._scanner()
        scanner._baseline_by_af = {"ipv4": False}
        remembered_fail = _probe("m", False, error="TLS_RESET")
        remembered_fail.from_memory = True
        scanner._results = [_probe("ok", True),
                            _probe("plain", False, error="TLS_RESET"),
                            remembered_fail,
                            _probe("u", False, error="UNSTABLE")]
        with mock.patch("core.strategy_memory.remember") as remember:
            scanner._remember_findings()
        rows = remember.call_args.args[0]
        self.assertEqual({(r["strategy_id"], r["ok"]) for r in rows},
                         {("ok", True), ("m", False), ("u", False)})
        self.assertEqual(remember.call_args.kwargs["source"], "scanner")
        self.assertTrue(all(r["target"] == "youtube.com" for r in rows))

    def test_open_target_is_not_remembered(self):
        scanner = self._scanner()
        scanner._baseline_by_af = {"ipv4": True}
        scanner._results = [_probe("ok", True)]
        with mock.patch("core.strategy_memory.remember") as remember:
            scanner._remember_findings()
        remember.assert_not_called()


if __name__ == "__main__":
    unittest.main()
