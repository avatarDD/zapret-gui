# tests/test_strategy_memory.py
"""
Память подбора: «что уже срабатывало здесь» переживает перезапуск GUI.

Почему это вообще тест, а не «сохранили json». Память — это то, с чего
модель НАЧИНАЕТ, и цена ошибки тут не в потерянной записи, а в
неверном совете: запомнили не то — и следующий прогон уверенно проверит
вариант, который ничего не чинил.

Отсюда три инварианта, за которыми следим:

* **вклад, а не успех.** Домен, открытый и БЕЗ обхода, в память не
  попадает: иначе «лучшим» назавтра окажется вариант, который ничего не
  делает;
* **сеть отделена от сети.** Записи чужого провайдера не смешиваются с
  записями текущего — совет «у другого провайдера помогало это» может
  быть полезен, но знанием об этой сети он не является;
* **битый файл — это пустая база, а не падение.** Файл пишет машина, на
  роутере его может обрезать выключением питания, и GUI обязан пережить
  это молча.
"""

import json
import os
import shutil
import tempfile
import time
import unittest

from core import strategy_memory as memory
from core.mcp import registry


NET = {"id": "net-testing", "iface": "eth9", "gateway": "10.0.0.1",
       "prefix": "203.0.0.0/16"}


class MemoryCase(unittest.TestCase):
    """Своя папка конфига: база не должна зависеть от машины."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mem-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        self.addCleanup(self._restore, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        # Сеть подменяем целиком: на машине сборщика её нет, а метка
        # обязана быть стабильной между вызовами теста.
        self.real_network_key = memory.network_key
        self.addCleanup(setattr, memory, "network_key",
                        self.real_network_key)
        memory.network_key = lambda refresh=False: dict(NET)
        memory.reset()

    def _restore(self, value):
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
        if value is not None:
            os.environ["ZAPRET_GUI_CONFIG_DIR"] = value

    def observe(self, target, args, ok=True, **extra):
        return memory.remember([dict({"target": target, "args": args,
                                      "ok": ok}, **extra)])


class TestRecording(MemoryCase):

    def test_win_and_loss_are_counted_separately(self):
        args = ["--filter-tcp=443", "--lua-desync=fake"]
        self.observe("youtube.com", args)
        self.observe("youtube.com", args)
        self.observe("youtube.com", args, ok=False)
        item = memory.lookup(["youtube.com"])["items"][0]
        self.assertEqual((item["wins"], item["losses"]), (2, 1))
        self.assertEqual(item["rate"], round(2 / 3.0, 3))

    def test_different_argv_are_different_records(self):
        self.observe("a.example", ["--one"])
        self.observe("a.example", ["--two"])
        self.assertEqual(memory.lookup(["a.example"])["total"], 2)

    def test_the_better_argv_comes_first(self):
        self.observe("a.example", ["--loser"], ok=False)
        self.observe("a.example", ["--winner"])
        self.observe("a.example", ["--winner"])
        items = memory.lookup(["a.example"])["items"]
        self.assertEqual(items[0]["args"], ["--winner"])

    def test_survives_a_restart(self):
        # Ровно то, ради чего база лежит файлом: отчёты эксперимента
        # живут в памяти процесса, а это — нет.
        self.observe("a.example", ["--x"])
        self.assertTrue(os.path.isfile(memory.path()))
        self.assertEqual(memory.lookup()["total"], 1)

    def test_empty_observation_is_ignored(self):
        self.assertEqual(memory.remember([])["written"], 0)
        self.assertEqual(memory.remember([{"target": "", "args": ["--x"]}]
                                         )["written"], 0)
        self.assertEqual(memory.remember([{"target": "a", "args": []}]
                                         )["written"], 0)

    def test_commit_marks_without_double_counting(self):
        args = ["--keepme"]
        self.observe("a.example", args)
        self.assertEqual(memory.mark_committed(args), 1)
        item = memory.lookup(["a.example"])["items"][0]
        self.assertTrue(item["committed"])
        # Отметка — не наблюдение: счётчики не трогаются.
        self.assertEqual(item["wins"], 1)

    def test_records_do_not_grow_forever(self):
        saved = memory.MAX_RECORDS
        self.addCleanup(setattr, memory, "MAX_RECORDS", saved)
        memory.MAX_RECORDS = 5
        for number in range(12):
            self.observe("host%d.example" % number, ["--x"])
        self.assertLessEqual(memory.lookup(limit=100)["total"], 5)


class TestNetworks(MemoryCase):

    def test_other_network_is_counted_but_not_mixed_in(self):
        self.observe("a.example", ["--here"])
        memory.network_key = lambda refresh=False: dict(NET, id="net-other")
        self.observe("a.example", ["--there"])

        found = memory.lookup(["a.example"])
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["items"][0]["args"], ["--there"])
        self.assertEqual(found["other_networks"], 1)

    def test_other_network_is_shown_only_when_asked(self):
        self.observe("a.example", ["--here"])
        memory.network_key = lambda refresh=False: dict(NET, id="net-other")
        self.assertNotIn("other_items", memory.lookup(["a.example"]))
        found = memory.lookup(["a.example"], all_networks=True)
        self.assertEqual(found["other_items"][0]["args"], ["--here"])

    def test_the_label_is_local_and_stable(self):
        # Ключ считается из интерфейса, шлюза и /16 — в интернет за ним
        # никто не ходит, и два вызова подряд дают одно и то же.
        memory.network_key = self.real_network_key
        real = memory.network_key(refresh=True)
        self.assertTrue(real["id"].startswith("net-"))
        self.assertEqual(real["id"], memory.network_key()["id"])
        # Полного WAN-адреса в метке нет — только блок.
        self.assertNotIn("/32", json.dumps(real))


class TestStaleAndBrokenFile(MemoryCase):

    def test_old_record_is_marked_not_dropped(self):
        self.observe("a.example", ["--x"])
        data = memory.load()
        data["records"][0]["last_seen"] = time.time() - \
            (memory.STALE_DAYS + 3) * 86400
        memory.save(data)
        item = memory.lookup(["a.example"])["items"][0]
        self.assertTrue(item["stale"])
        self.assertGreaterEqual(item["age_days"], memory.STALE_DAYS)

    def test_broken_file_is_an_empty_base(self):
        with open(memory.path(), "w", encoding="utf-8") as handle:
            handle.write("{это не json")
        self.assertEqual(memory.load()["records"], [])
        self.assertEqual(memory.lookup()["total"], 0)
        # И новая запись поверх битого файла ложится нормально.
        self.observe("a.example", ["--x"])
        self.assertEqual(memory.lookup()["total"], 1)

    def test_foreign_version_is_not_parsed_halfway(self):
        with open(memory.path(), "w", encoding="utf-8") as handle:
            json.dump({"version": 99, "records": [{"target": "a"}]}, handle)
        self.assertEqual(memory.load()["records"], [])


class TestFromExperimentReport(MemoryCase):
    """Отчёт эксперимента → наблюдения. Запоминаем вклад, а не успех."""

    def report(self, **extra):
        base = {
            "run_id": "exp-1",
            "baseline": {"measured": True, "per_target": [
                {"target": "closed.example", "ok": False},
                {"target": "open.example", "ok": True},
            ]},
            "variants": [
                {"label": "A", "args": ["--good"], "score": 1.0,
                 "success_rate": 1.0, "per_target": [
                     {"target": "closed.example", "ok": True},
                     {"target": "open.example", "ok": True},
                 ]},
                {"label": "B", "args": ["--bad"], "score": 0.0,
                 "success_rate": 0.0, "per_target": [
                     {"target": "closed.example", "ok": False},
                     {"target": "open.example", "ok": True},
                 ]},
            ],
            "best": "A",
        }
        base.update(extra)
        return base

    def test_only_the_target_that_was_closed_is_remembered(self):
        memory.remember_report(self.report())
        self.assertEqual(memory.targets_known(), ["closed.example"])

    def test_the_winner_and_the_loser_are_both_recorded(self):
        memory.remember_report(self.report())
        items = memory.lookup(["closed.example"])["items"]
        by_args = {tuple(i["args"]): i for i in items}
        self.assertEqual(by_args[("--good",)]["wins"], 1)
        self.assertEqual(by_args[("--bad",)]["losses"], 1)

    def test_a_run_without_baseline_writes_nothing(self):
        # Без baseline вклад варианта неизвестен, и «запомнить на
        # всякий случай» здесь значит копить шум.
        blind = self.report(baseline={"measured": False, "per_target": []})
        result = memory.remember_report(blind)
        self.assertTrue(result["skipped"])
        self.assertEqual(memory.lookup()["total"], 0)

    def test_skipped_variant_is_not_remembered(self):
        report = self.report()
        report["variants"][1]["skipped"] = True
        memory.remember_report(report)
        items = memory.lookup(["closed.example"])["items"]
        self.assertEqual([i["args"] for i in items], [["--good"]])

    def test_committed_run_marks_the_winner(self):
        memory.remember_report(self.report(committed=True))
        items = memory.lookup(["closed.example"])["items"]
        winner = next(i for i in items if i["args"] == ["--good"])
        loser = next(i for i in items if i["args"] == ["--bad"])
        self.assertTrue(winner.get("committed"))
        self.assertFalse(loser.get("committed"))


class TestTool(MemoryCase):
    """Тот же ответ инструментом: ресурсы половина клиентов не читает."""

    def setUp(self):
        super().setUp()
        registry.load_tools()

    def call(self, args=None):
        return registry.call("strategy_memory", args or {},
                             {})["structuredContent"]

    def test_empty_base_explains_itself(self):
        answer = self.call()
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["items"], [])
        self.assertIn("baseline", answer["hint"])

    def test_filter_by_domain(self):
        self.observe("a.example", ["--x"])
        self.observe("b.example", ["--y"])
        answer = self.call({"targets": ["b.example"]})
        self.assertEqual(answer["total"], 1)
        self.assertEqual(answer["items"][0]["target"], "b.example")

    def test_hint_names_what_to_try_first(self):
        self.observe("a.example", ["--winner"])
        answer = self.call({"targets": ["a.example"]})
        self.assertIn("a.example", answer["hint"])
        self.assertIn("strategy_experiment_start", answer["hint"])

    def test_needs_no_permission(self):
        # Домены и argv читаются и так (strategy_list, catalog_search),
        # а секретов здесь нет по построению.
        self.observe("a.example", ["--x"])
        self.assertTrue(self.call()["ok"])

    def test_paging_is_a_window_not_a_prefix(self):
        for number in range(5):
            self.observe("host%d.example" % number, ["--x"])
        first = self.call({"limit": 2})
        second = self.call({"limit": 2, "offset": 2})
        self.assertEqual(first["total"], 5)
        self.assertEqual(len(second["items"]), 2)
        self.assertNotEqual([i["target"] for i in first["items"]],
                            [i["target"] for i in second["items"]])

    def test_network_label_is_not_masked_as_a_secret(self):
        # Поле называлось `key` и уезжало моделью как «***»: по метке
        # она отличает эту сеть от чужой, и маска ломала ровно это.
        answer = self.call()
        self.assertEqual(answer["network"]["id"], NET["id"])



class TestHelpedByStrategy(MemoryCase):
    """«Помогала у вас» в списке стратегий — вместо метки recommended."""

    def test_wins_in_this_network_count(self):
        args = ["--filter-tcp=443", "--lua-desync=fake"]
        self.observe("youtube.com", args, strategy_id="fake_x")
        self.observe("x.com", args, strategy_id="fake_x")
        helped = memory.helped_by_strategy()
        self.assertEqual(helped["fake_x"]["wins"], 2)
        self.assertEqual(sorted(helped["fake_x"]["targets"]),
                         ["x.com", "youtube.com"])
        # Стратегия, которую подбор сохранил как свою, — та же находка.
        self.assertIn("scan_fake_x", helped)

    def test_losing_and_foreign_records_do_not_count(self):
        args = ["--lua-desync=split"]
        self.observe("youtube.com", args, ok=False, strategy_id="bad")
        memory.remember([{"target": "x.com", "args": args, "ok": True,
                          "strategy_id": "foreign"}],
                        network={"id": "other-net"})
        helped = memory.helped_by_strategy()
        self.assertNotIn("bad", helped)
        self.assertNotIn("foreign", helped)



class TestStrategiesApiHelped(unittest.TestCase):
    """/api/strategies отдаёт helped из памяти и снимает его, когда её нет."""

    def test_helped_appears_and_disappears(self):
        from unittest import mock
        from tests._wsgi_client import WSGIClient, build_test_app
        from core.strategy_builder import get_strategy_manager

        client = WSGIClient(build_test_app())
        sid = get_strategy_manager().get_strategies()[0]["id"]
        with mock.patch.object(memory, "helped_by_strategy",
                               return_value={sid: {"wins": 3,
                                                   "targets": ["x.com"]}}):
            data = client.get_json("/api/strategies")
        row = next(s for s in data["strategies"] if s["id"] == sid)
        self.assertEqual(row["helped"], 3)
        self.assertEqual(row["helped_targets"], ["x.com"])
        with mock.patch.object(memory, "helped_by_strategy", return_value={}):
            data = client.get_json("/api/strategies")
        row = next(s for s in data["strategies"] if s["id"] == sid)
        self.assertNotIn("helped", row)


if __name__ == "__main__":
    unittest.main()
