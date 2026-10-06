# tests/test_mcp_probes.py
"""
Активные пробы: коды, вердикты, лимиты и возврат движка на место.

Четыре вещи, которые здесь стережём.

**Коды — только из `PROBE_CODES`.** На них построены и вердикт
`probe_compare`, и baseline эксперимента (S10). Свободная строка в этом
поле означает, что следующий читатель будет разбирать её регулярками.

**Все вердикты воспроизводятся.** `bypass_helps`, `no_difference`,
`target_down`, `bypass_hurts` — и отдельно `unknown`: сторона, которую
не удалось измерить, обязана называться неизмеренной, а не отдавать
`ok: false`. Выдуманная вторая половина здесь хуже отсутствующей.

**Движок возвращается в прежнее состояние всегда.** В том числе когда
проба посередине упала: оставить роутер без обхода из-за диагностики
нельзя.

**Лимиты режут запрос до первого пакета.** Модель не должна уметь
запустить пробу по пяти сотням доменов: это не нагрузка на роутер, это
след у провайдера.

Сеть замокана целиком: тест, который правда ходит наружу, красен на
машине без интернета и зелен там, где сломан код.
"""

import unittest

from core import nfqws_control, probe_mark, probe_runner
from core.config_manager import get_config_manager
from core.mcp import registry
from core.testers.probe import PROBE_CODES, ProbeResult


PROBES = {"probes": True}
PROBES_AND_CONTROL = {"probes": True, "control": True}


def data(name, args=None, perms=None):
    return registry.call(name, args or {},
                         PROBES if perms is None else perms
                         )["structuredContent"]


class Perms:
    """Разрешения, которые инструмент спрашивает у конфига по месту.

    `probe_compare` смотрит на `control` сам (карта разрешений до
    обработчика не доходит), поэтому мало передать её в `registry.call`.
    """

    def __init__(self, case, **granted):
        cfg = get_config_manager()
        saved = cfg.get("mcp", "permissions", default={}) or {}
        case.addCleanup(cfg.set, "mcp", "permissions", dict(saved))
        updated = dict(saved)
        updated.update(granted)
        cfg.set("mcp", "permissions", updated)


class FakeEngine:
    """Движок, который слушается и запоминает, что с ним делали."""

    def __init__(self, running=False, can_switch=True):
        self.running_flag = running
        self.can_switch = can_switch
        self.calls = []

    # ── то, что подменяет nfqws_control ──
    def running(self):
        return self.running_flag

    def start(self, source=""):
        self.calls.append("start")
        if not self.can_switch:
            return {"ok": False, "error": "бинарника нет"}
        self.running_flag = True
        return {"ok": True, "error": ""}

    def stop(self, source=""):
        self.calls.append("stop")
        if not self.can_switch:
            return {"ok": False, "error": "не остановился"}
        self.running_flag = False
        return {"ok": True, "error": ""}


class ProbeCase(unittest.TestCase):
    """Общая подмена сети и движка."""

    # domain → код пробы; по умолчанию зависит от состояния движка.
    def setUp(self):
        registry.load_tools()
        self.engine = FakeEngine()
        self.probed = []
        self._patch(nfqws_control, "running", self.engine.running)
        self._patch(nfqws_control, "start", self.engine.start)
        self._patch(nfqws_control, "stop", self.engine.stop)
        self._patch(nfqws_control, "active_strategy_args",
                    lambda: ["--filter-tcp=443"])
        self._patch(probe_runner, "probe_domain", self.fake_probe)
        # Помеченная проба (мимо очереди, core/probe_mark.py) зависит от
        # прав процесса и правил firewall хоста — в тестах её нет, если
        # тест не включил её сам.
        self._patch(probe_mark, "baseline_mode",
                    lambda firewall=None: {"marked": False, "mark": 0,
                                           "reason": "тест: метки нет"})
        # Пауза после переключения движка в тесте не нужна: она про
        # реальный сетевой стек, а не про логику.
        self._limits(settle_sec=0)

    def _patch(self, module, name, value):
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, value)

    def _limits(self, **values):
        cfg = get_config_manager()
        saved = cfg.get("mcp", "probes", default={}) or {}
        self.addCleanup(cfg.set, "mcp", "probes", dict(saved))
        updated = dict(saved)
        updated.update(values)
        cfg.set("mcp", "probes", updated)

    def code_for(self, domain):
        """Что «видит» проба. Переопределяется в тестах."""
        return "ok" if self.engine.running_flag else "tls_rst"

    def fake_probe(self, domain, timeout=5, port=443, **kw):
        self.probed.append((domain, self.engine.running_flag))
        code = self.code_for(domain)
        return ProbeResult(domain=domain, code=code, detail="фейк",
                           latency_ms=120.0 if code == "ok" else 0.0,
                           resolved_ips=["93.184.216.34"])


class TestProbeTargets(ProbeCase):

    def code_for(self, domain):
        return {"open.example": "ok",
                "blocked.example": "tls_rst",
                "gone.example": "dns_block"}.get(domain, "ok")

    def test_codes_come_from_the_shared_dictionary(self):
        result = data("probe_targets", {"targets": ["open.example",
                                                    "blocked.example",
                                                    "gone.example"]})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 3)
        for item in result["items"]:
            with self.subTest(target=item["target"]):
                self.assertIn(item["code"], PROBE_CODES)
                self.assertTrue(item["code_desc"])
                self.assertTrue(item["measured"])

    def test_summary_counts_and_remediation(self):
        result = data("probe_targets", {"targets": ["open.example",
                                                    "blocked.example",
                                                    "gone.example"]})
        self.assertEqual(result["summary"]["total"], 3)
        self.assertEqual(result["summary"]["ok"], 1)
        self.assertEqual(result["summary"]["blocked"], 2)
        # Рекомендация по обходу — не строка из инструмента, а вывод
        # общей таксономии: zapret / tunnel / dns / none.
        self.assertIn("zapret", result["summary"]["by_remediation"])

    def test_engine_is_not_touched(self):
        # Проба не меняет состояние. Инструмент, дёрнувший движок «для
        # чистоты замера», нарушил бы это молча.
        data("probe_targets", {"targets": ["open.example"]})
        self.assertEqual(self.engine.calls, [])

    def test_target_limit_is_enforced_and_explained(self):
        self._limits(max_targets=3)
        targets = ["h%d.example" % i for i in range(8)]
        result = data("probe_targets", {"targets": targets})
        self.assertEqual(result["summary"]["total"], 3)
        self.assertEqual(len(result["rejected"]), 5)
        # «Прислал восемь, проверено три» без причины читается как сбой.
        self.assertIn("max_targets", result["rejected"][0]["reason"])
        self.assertEqual(len({d for d, _ in self.probed}), 3)

    def test_garbage_targets_are_rejected_not_probed(self):
        result = data("probe_targets",
                      {"targets": ["ok.example", "http://ex.com/path",
                                   "ok.example"]})
        self.assertEqual(result["summary"]["total"], 1)
        reasons = {r["reason"] for r in result["rejected"]}
        self.assertTrue(any("хоста" in r for r in reasons))
        self.assertTrue(any("повтор" in r for r in reasons))

    def test_repeats_fold_into_one_verdict_by_majority(self):
        # Домен, открывшийся один раз из трёх, работает нестабильно;
        # называть это «работает» — подсунуть ложную базу сравнения.
        seen = {"n": 0}

        def flaky(domain, timeout=5, port=443, **kw):
            seen["n"] += 1
            code = "ok" if seen["n"] == 1 else "tls_rst"
            return ProbeResult(domain=domain, code=code)

        self._patch(probe_runner, "probe_domain", flaky)
        result = data("probe_targets", {"targets": ["flaky.example"],
                                        "repeats": 3})
        item = result["items"][0]
        self.assertFalse(item["ok"])
        self.assertEqual(item["code"], "tls_rst")
        self.assertEqual(item["attempts"], 3)
        self.assertEqual(item["ok_count"], 1)


class TestProbeCompareMarked(ProbeCase):
    """Движок работает — «без обхода» меряется меткой, движок не трогаем."""

    def setUp(self):
        super().setUp()
        Perms(self, probes=True, control=True)
        self._patch(probe_mark, "baseline_mode",
                    lambda firewall=None: {"marked": True,
                                           "mark": 0x10000000,
                                           "reason": "тест"})
        self.marks = []

    def fake_probe(self, domain, timeout=5, port=443, **kw):
        mark = kw.get("mark", 0)
        self.marks.append(mark)
        code = "tls_rst" if mark else "ok"
        return ProbeResult(domain=domain, code=code, detail="фейк",
                           latency_ms=120.0 if code == "ok" else 0.0,
                           resolved_ips=["93.184.216.34"])

    def test_engine_untouched(self):
        self.engine.running_flag = True
        result = data("probe_compare", {"target": "rutracker.org"},
                      PROBES_AND_CONTROL)
        self.assertEqual(self.engine.calls, [])
        self.assertEqual(result["verdict"], "bypass_helps")
        self.assertEqual(result["without_method"], "probe_mark")
        self.assertFalse(result["engine_toggled"])
        self.assertEqual(self.marks, [0, 0x10000000])

    def test_marked_without_control(self):
        # Метка не меняет состояние устройства — control не нужен.
        self.engine.running_flag = True
        result = data("probe_compare", {"target": "rutracker.org"},
                      PROBES)
        self.assertEqual(result["verdict"], "bypass_helps")
        self.assertEqual(self.engine.calls, [])


class TestProbeCompare(ProbeCase):
    """Четыре вердикта, пятый — честное «не знаю»."""

    def setUp(self):
        super().setUp()
        Perms(self, probes=True, control=True)
        self.verdicts = {}

    def code_for(self, domain):
        return self.verdicts.get(self.engine.running_flag, "ok")

    def compare(self, with_bypass, without_bypass, running=False,
                args=None, perms=None):
        self.verdicts = {True: with_bypass, False: without_bypass}
        self.engine.running_flag = running
        return data("probe_compare",
                    dict({"target": "rutracker.org"}, **(args or {})),
                    perms or PROBES_AND_CONTROL)

    def test_bypass_helps(self):
        result = self.compare("ok", "tls_rst")
        self.assertEqual(result["verdict"], "bypass_helps")
        self.assertTrue(result["with_bypass"]["ok"])
        self.assertEqual(result["without_bypass"]["code"], "tls_rst")
        self.assertTrue(result["verdict_text"])

    def test_no_difference(self):
        self.assertEqual(self.compare("ok", "ok")["verdict"],
                         "no_difference")

    def test_target_down(self):
        result = self.compare("tcp_timeout", "tcp_timeout")
        self.assertEqual(result["verdict"], "target_down")

    def test_bypass_hurts(self):
        result = self.compare("tls_rst", "ok", running=True)
        self.assertEqual(result["verdict"], "bypass_hurts")

    def test_verdict_is_from_the_fixed_set(self):
        result = self.compare("ok", "tls_rst")
        self.assertIn(result["verdict"], probe_runner.VERDICTS)
        for side in ("with_bypass", "without_bypass"):
            self.assertIn(result[side]["code"], PROBE_CODES)

    def test_engine_is_restored_when_it_was_running(self):
        result = self.compare("ok", "tls_rst", running=True)
        self.assertEqual(self.engine.calls, ["stop", "start"])
        self.assertTrue(self.engine.running_flag)
        self.assertTrue(result["restored"])

    def test_engine_is_restored_when_it_was_stopped(self):
        self.compare("ok", "tls_rst", running=False)
        self.assertEqual(self.engine.calls, ["start", "stop"])
        self.assertFalse(self.engine.running_flag)

    def test_engine_is_restored_even_if_the_probe_blows_up(self):
        def explode(*a, **kw):
            raise RuntimeError("проба развалилась")

        self.verdicts = {True: "ok", False: "tls_rst"}
        self.engine.running_flag = True
        calls = {"n": 0}
        original = probe_runner.probe_target

        def once_then_boom(*a, **kw):
            calls["n"] += 1
            if calls["n"] > 1:
                explode()
            return original(*a, **kw)

        self._patch(probe_runner, "probe_target", once_then_boom)
        with self.assertRaises(RuntimeError):
            probe_runner.compare("rutracker.org")
        # Состояние роутера важнее ответа: движок поднят обратно.
        self.assertEqual(self.engine.calls, ["stop", "start"])
        self.assertTrue(self.engine.running_flag)

    def test_without_control_the_second_side_is_not_measured(self):
        Perms(self, probes=True, control=False)
        result = self.compare("ok", "tls_rst", running=True,
                              perms=PROBES)
        self.assertEqual(result["verdict"], "unknown")
        self.assertFalse(result["without_bypass"]["measured"])
        self.assertFalse(result["toggle"]["allowed"])
        self.assertEqual(result["toggle"]["permission"], "control")
        self.assertIn("control", result["toggle"]["hint"])
        # И главное: движок не тронут.
        self.assertEqual(self.engine.calls, [])

    def test_toggle_false_measures_one_side_and_says_so(self):
        result = self.compare("ok", "tls_rst", running=True,
                              args={"toggle": False})
        self.assertEqual(result["verdict"], "unknown")
        self.assertFalse(result["without_bypass"]["measured"])
        self.assertIn("reason", result["without_bypass"])
        self.assertEqual(self.engine.calls, [])

    def test_no_strategy_means_honest_no_bypass(self):
        # dev-машина: движка нет и поднимать нечем. Врать про «с
        # обходом» нельзя — голый nfqws2 это не обход.
        self._patch(nfqws_control, "active_strategy_args", lambda: [])
        result = self.compare("ok", "tls_rst", running=False)
        self.assertEqual(result["verdict"], "unknown")
        self.assertFalse(result["with_bypass"]["measured"])
        self.assertIn("стратеги", result["with_bypass"]["reason"])
        self.assertEqual(self.engine.calls, [])

    def test_engine_that_refuses_to_switch_is_reported(self):
        self.engine.can_switch = False
        result = self.compare("ok", "tls_rst", running=True)
        self.assertEqual(result["verdict"], "unknown")
        self.assertFalse(result["without_bypass"]["measured"])
        self.assertIn("движок", result["without_bypass"]["reason"])

    def test_bad_target_is_refused_before_any_probe(self):
        result = data("probe_compare", {"target": "http://example.com/x"},
                      PROBES_AND_CONTROL)
        self.assertFalse(result["ok"])
        self.assertEqual(self.probed, [])


class TestConnectivityMatrix(unittest.TestCase):
    """Снимок читается всегда, новый прогон — по `probes`."""

    class FakeMatrix:
        def __init__(self):
            self.probes = 0
            self.snapshot = {
                "at": 1700000000, "fresh": False, "took_ms": 12,
                "ifaces": ["awg0"],
                "targets": [{"name": "Cloudflare", "host": "1.1.1.1"}],
                "cells": [{"target": "1.1.1.1", "iface": "awg0",
                           "latency_ms": 42.0, "via_iface": True,
                           "error": "", "level": "good"}],
            }

        def get_snapshot(self):
            return dict(self.snapshot)

        def probe_once(self, ifaces=None):
            self.probes += 1
            snap = dict(self.snapshot)
            snap["fresh"] = True
            return snap

    def setUp(self):
        registry.load_tools()
        from core.connectivity import matrix as matrix_mod
        self.matrix = self.FakeMatrix()
        saved = matrix_mod.get_matrix_manager
        self.addCleanup(setattr, matrix_mod, "get_matrix_manager", saved)
        matrix_mod.get_matrix_manager = lambda: self.matrix

    def test_snapshot_is_read_without_the_permission(self):
        Perms(self, probes=False)
        result = data("connectivity_matrix", {}, {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(self.matrix.probes, 0)
        self.assertFalse(result["probes"]["allowed"])

    def test_refresh_without_permission_runs_nothing_and_says_why(self):
        Perms(self, probes=False)
        result = data("connectivity_matrix", {"refresh": True}, {})
        self.assertEqual(self.matrix.probes, 0)
        self.assertFalse(result["refreshed"])
        self.assertIn("probes", result["probes"]["hint"])

    def test_refresh_with_permission_probes(self):
        Perms(self, probes=True)
        result = data("connectivity_matrix", {"refresh": True}, PROBES)
        self.assertEqual(self.matrix.probes, 1)
        self.assertTrue(result["refreshed"])
        cell = result["items"][0]
        self.assertEqual(cell["iface"], "awg0")
        self.assertTrue(cell["via_iface"])


if __name__ == "__main__":
    unittest.main()


class TestDpiClassify(ProbeCase):
    """dpi_classify: упаковка ответа классификатора и проверка имён."""

    def setUp(self):
        super().setUp()
        Perms(self, probes=True)
        from core.testers import dpi_differential
        self.asked = []

        def fake(domain, **kw):
            self.asked.append((domain, kw.get("control_sni")))
            return {"target": domain, "verdict": "opaque",
                    "verdict_text": "x", "reason": "y",
                    "dpi_classification": "tls_dpi",
                    "remediation": "zapret", "steps": {}}

        self._patch(dpi_differential, "classify", fake)

    def test_verdict_and_hint(self):
        result = data("dpi_classify", {"target": "rutracker.org"}, PROBES)
        self.assertTrue(result["ok"])
        self.assertEqual(result["verdict"], "opaque")
        self.assertIn("фейк", result["hint"])
        self.assertEqual(self.asked, [("rutracker.org", "example.com")])

    def test_bad_names_rejected_before_any_packet(self):
        result = data("dpi_classify", {"target": "http://x y"}, PROBES)
        self.assertFalse(result["ok"])
        result = data("dpi_classify", {"target": "a.org",
                                       "control_sni": "$(reboot)"}, PROBES)
        self.assertFalse(result["ok"])
        self.assertEqual(self.asked, [])
