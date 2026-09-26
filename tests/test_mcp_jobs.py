# tests/test_mcp_jobs.py
"""
Асинхронный контракт тяжёлых прогонов: `job_id`, опрос, `offset`, стоп.

Почему это отдельный сторож. Подбор стратегий и blockcheck идут
минутами, а клиент (LM Studio, Cline и совместимые мосты) рвёт
HTTP-запрос через десятки секунд. Единственный работающий вариант —
`*_start` отдаёт ярлык и сразу возвращает управление, а модель
опрашивает `*_status` и `*_output`. «Оптимизация» обратно в синхронный
вызов ломает ровно то, ради чего всё это сделано, — поэтому форма
ответа зафиксирована тестом.

Четыре правила, которые здесь проверяются:

1. `*_start` возвращает `job_id` **сразу** и не ждёт конца прогона;
2. `*_output` отдаёт инкремент: с `offset` приходит только новое, а
   `next_offset` — то, с чем звать в следующий раз;
3. второй тяжёлый старт при занятом движке — `isError` с указанием
   активного `job_id` (иначе модели нечего опрашивать);
4. **ярлык переживает конец прогона**: спросить `*_status` через
   полминуты после завершения — нормальный сценарий, и ответ «задачи
   нет» модель прочитает как «прогон потерян» и запустит ещё один.

Сканер и скрипт blockcheck подменены: настоящие поднимают nfqws2 и
ходят в сеть.
"""

import unittest

from core import blockcheck2 as blockcheck2_mod
from core import nfqws_control
from core import strategy_scanner as scanner_mod
from core.mcp import registry
from core.mcp.tools import _jobs


PROBES = {"probes": True}


def data(name, args=None, perms=None):
    return registry.call(name, args or {},
                         PROBES if perms is None else perms
                         )["structuredContent"]


class FakeScanner:
    """Сканер, который «работает» ровно столько, сколько скажет тест."""

    def __init__(self):
        self.running = False
        self.started_with = None
        self.stopped = 0
        self.resume_index = 42

    def start(self, target="", protocol="tcp", mode="quick",
              start_index=0, dpi_type="", callback=None):
        if self.running:
            return False
        self.running = True
        self.started_with = {"target": target, "protocol": protocol,
                             "mode": mode, "start_index": start_index,
                             "dpi_type": dpi_type}
        return True

    def stop(self):
        self.stopped += 1
        if not self.running:
            return False
        self.running = False
        return True

    def get_resume_index(self, **run):
        self.resume_asked = run
        return self.resume_index

    def get_status(self):
        return {
            "status": "running" if self.running else "completed",
            "progress": 7, "total": 30, "phase": "Проверка стратегий",
            "current_strategy": "multisplit", "target": "youtube.com",
            "protocol": "tcp", "mode": "quick", "error": "",
            "working_count": 2, "failed_count": 5, "success_rate": 28.6,
            "elapsed_seconds": 12.0, "baseline_open": False,
            "baseline_by_af": {},
        }

    def get_results(self):
        return None

    def get_working_strategies(self):
        return []


class FakeBlockcheck2:
    """Скрипт blockcheck: копит строки, отдаёт их по offset."""

    def __init__(self):
        self.running = False
        self.lines = []
        self.stopped = 0
        self.started_with = None

    def start(self, domains=None, params=None, extra_args=None,
              scanlevel=None):
        if self.running:
            return {"ok": False, "error": "blockcheck уже выполняется"}
        self.running = True
        self.started_with = {"domains": domains, "params": params,
                             "scanlevel": scanlevel}
        return {"ok": True, "script": "/opt/zapret2/blockcheck2.sh",
                "cmd": ["/opt/zapret2/blockcheck2.sh"]}

    def stop(self):
        if not self.running:
            return False
        self.running = False
        self.stopped += 1
        return True

    def get_status(self):
        return {"running": self.running, "started": True,
                "script": "/opt/zapret2/blockcheck2.sh",
                "cmd": [], "line_count": len(self.lines),
                "exit_code": None if self.running else 0,
                "elapsed_seconds": 3.0, "error": "",
                "highlights": ["ipv4 rutracker.org is available"],
                "found": [{"test": "multisplit"}]}

    def get_output(self, offset=0):
        offset = max(0, min(offset, len(self.lines)))
        return {"lines": self.lines[offset:], "offset": offset,
                "next_offset": len(self.lines), "running": self.running,
                "exit_code": None if self.running else 0}


class JobCase(unittest.TestCase):
    """Общая подмена прогонов и чистый реестр задач."""

    def setUp(self):
        registry.load_tools()
        _jobs.reset()
        self.addCleanup(_jobs.reset)
        self.scanner = FakeScanner()
        self.blockcheck2 = FakeBlockcheck2()
        self._patch(scanner_mod, "get_strategy_scanner",
                    lambda: self.scanner)
        self._patch(blockcheck2_mod, "get_blockcheck2_runner",
                    lambda: self.blockcheck2)
        # По умолчанию движок свободен: занятость подменяется точечно.
        self._patch(nfqws_control, "busy", dict)

    def _patch(self, module, name, value):
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, value)


class TestStartReturnsAJob(JobCase):

    def test_scan_start_answers_at_once_with_a_job_id(self):
        result = data("scan_start", {"target": "youtube.com",
                                     "mode": "standard"})
        self.assertTrue(result["ok"])
        self.assertTrue(result["job_id"].startswith("scan-"))
        self.assertTrue(result["async"])
        # Прогон при этом ИДЁТ: инструмент вернулся, не дожидаясь конца.
        self.assertTrue(self.scanner.running)
        self.assertEqual(self.scanner.started_with["target"],
                         "youtube.com")
        self.assertEqual(self.scanner.started_with["mode"], "standard")

    def test_resume_asks_the_scanner_where_it_stopped(self):
        result = data("scan_start", {"target": "youtube.com",
                                     "resume": True})
        self.assertEqual(result["resumed_from"], 42)
        self.assertEqual(self.scanner.started_with["start_index"], 42)
        # Позицию сверяют с ЭТИМ прогоном, а не берут любую сохранённую.
        self.assertEqual(self.scanner.resume_asked["target"], "youtube.com")
        self.assertEqual(self.scanner.resume_asked["protocol"], "tcp")

    def test_bad_target_never_reaches_the_scanner(self):
        result = data("scan_start", {"target": "https://youtube.com/x"})
        self.assertFalse(result["ok"])
        self.assertIsNone(self.scanner.started_with)

    def test_blockcheck2_start_maps_arguments_to_env(self):
        result = data("blockcheck2_start",
                      {"domains": ["rutracker.org"], "scanlevel": "quick",
                       "ipv": "4", "repeats": 2, "http3": False})
        self.assertTrue(result["ok"])
        self.assertTrue(result["job_id"].startswith("blockcheck2-"))
        params = self.blockcheck2.started_with["params"]
        self.assertEqual(params["IPVS"], "4")
        self.assertEqual(params["REPEATS"], "2")
        self.assertEqual(params["ENABLE_HTTP3"], "0")
        self.assertEqual(self.blockcheck2.started_with["scanlevel"],
                         "quick")


class TestOneHeavyRunAtATime(JobCase):

    def test_second_start_names_the_active_job(self):
        first = data("scan_start", {"target": "youtube.com"})
        self._patch(nfqws_control, "busy",
                    lambda: {"who": "scanner", "reason": "идёт подбор",
                             "hint": "дождитесь"})
        second = registry.call("scan_start", {"target": "rutracker.org"},
                               PROBES)
        self.assertTrue(second["isError"])
        payload = second["structuredContent"]
        self.assertEqual(payload["busy"], "scanner")
        # Без ярлыка активной задачи модели нечего опрашивать — она
        # запустит ещё один прогон.
        self.assertEqual(payload["job_id"], first["job_id"])

    def test_blockcheck2_refuses_while_the_scanner_holds_the_engine(self):
        scan = data("scan_start", {"target": "youtube.com"})
        self._patch(nfqws_control, "busy",
                    lambda: {"who": "scanner", "reason": "идёт подбор"})
        result = registry.call("blockcheck2_start", {}, PROBES)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["job_id"],
                         scan["job_id"])

    def test_scanner_refusing_by_itself_is_still_a_readable_answer(self):
        # Гонка: `busy()` сказала «свободно», а сканер уже стартовал.
        data("scan_start", {"target": "youtube.com"})
        result = registry.call("scan_start", {"target": "vk.com"}, PROBES)
        self.assertTrue(result["isError"])
        self.assertIn("job_id", result["structuredContent"])


class TestStatusSurvivesTheRun(JobCase):

    def test_status_follows_the_live_run(self):
        job = data("scan_start", {"target": "youtube.com"})
        status = data("scan_status", {"job_id": job["job_id"]}, {})
        self.assertTrue(status["running"])
        self.assertTrue(status["live"])
        self.assertEqual(status["progress"], 7)
        self.assertEqual(status["total"], 30)
        self.assertFalse(status["done"])

    def test_status_answers_after_the_run_has_finished(self):
        job = data("scan_start", {"target": "youtube.com"})
        self.scanner.running = False              # прогон закончился
        status = data("scan_status", {"job_id": job["job_id"]}, {})
        self.assertTrue(status["ok"])
        self.assertTrue(status["done"])
        self.assertFalse(status["running"])
        self.assertGreater(status["finished_at"], 0)

    def test_older_job_is_answered_by_its_own_snapshot(self):
        first = data("scan_start", {"target": "youtube.com"})
        self.scanner.running = False
        data("scan_status", {"job_id": first["job_id"]}, {})   # снимок
        data("scan_start", {"target": "vk.com"})               # новая задача

        old = data("scan_status", {"job_id": first["job_id"]}, {})
        self.assertFalse(old["live"])
        self.assertFalse(old["running"])
        self.assertIn("ЗАВЕРШЁННАЯ", old["job_note"])
        # Живой статус описывает уже ДРУГУЮ задачу: отдавать его под
        # чужим ярлыком значит сказать «твой скан всё ещё идёт».
        fresh = data("scan_status", {}, {})
        self.assertTrue(fresh["live"])
        self.assertNotEqual(fresh["job_id"], old["job_id"])

    def test_unknown_job_id_is_refused_and_lists_the_known_ones(self):
        job = data("scan_start", {"target": "youtube.com"})
        result = registry.call("scan_status", {"job_id": "scan-deadbeef"},
                               {})
        self.assertTrue(result["isError"])
        payload = result["structuredContent"]
        self.assertIn(job["job_id"], payload["known_job_ids"])

    def test_run_started_outside_mcp_is_reported_honestly(self):
        self.scanner.running = True               # запущен из GUI
        status = data("scan_status", {}, {})
        self.assertTrue(status["ok"])
        self.assertFalse(status["job_known"])
        self.assertEqual(status["job_id"], "")
        self.assertIn("не через MCP", status["job_note"])


class TestIncrementalOutput(JobCase):

    def test_output_returns_only_the_new_lines(self):
        data("blockcheck2_start", {})
        self.blockcheck2.lines = ["строка 1", "строка 2"]

        first = data("blockcheck2_output", {}, {})
        self.assertEqual(first["items"], ["строка 1", "строка 2"])
        self.assertEqual(first["total"], 2)
        self.assertFalse(first["truncated"])

        self.blockcheck2.lines.append("строка 3")
        tail = data("blockcheck2_output", {"offset": first["total"]}, {})
        self.assertEqual(tail["items"], ["строка 3"])
        self.assertEqual(tail["offset"], 2)
        self.assertEqual(tail["total"], 3)

    def test_window_is_limited_and_says_where_to_continue(self):
        data("blockcheck2_start", {})
        self.blockcheck2.lines = ["строка %d" % i for i in range(10)]
        result = data("blockcheck2_output", {"limit": 4}, {})
        self.assertEqual(result["count"], 4)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["next_offset"], 4)

    def test_empty_tail_explains_itself(self):
        data("blockcheck2_start", {})
        result = data("blockcheck2_output", {"offset": 0}, {})
        self.assertEqual(result["items"], [])
        self.assertIn("строк", result["reason"])

    def test_output_of_a_superseded_job_is_refused_not_faked(self):
        # Буфер строк держит только последний прогон: отдать его под
        # ярлыком предыдущего значит соврать.
        first = data("blockcheck2_start", {})
        self.blockcheck2.running = False
        data("blockcheck2_start", {})
        result = registry.call("blockcheck2_output",
                               {"job_id": first["job_id"]}, {})
        self.assertTrue(result["isError"])
        self.assertIn("не доступен", result["structuredContent"]["error"])


class TestStop(JobCase):

    def test_scan_stop_asks_the_scanner_and_closes_the_job(self):
        job = data("scan_start", {"target": "youtube.com"})
        result = data("scan_stop")
        self.assertTrue(result["stopped"])
        self.assertEqual(result["job_id"], job["job_id"])
        self.assertFalse(self.scanner.running)
        status = data("scan_status", {"job_id": job["job_id"]}, {})
        self.assertTrue(status["done"])

    def test_stop_without_a_run_is_not_an_error(self):
        result = data("scan_stop")
        self.assertTrue(result["ok"])
        self.assertFalse(result["stopped"])
        self.assertIn("не выполняется", result["hint"])

    def test_blockcheck2_stop_keeps_the_collected_output(self):
        data("blockcheck2_start", {})
        self.blockcheck2.lines = ["строка 1"]
        result = data("blockcheck2_stop")
        self.assertTrue(result["stopped"])
        self.assertEqual(self.blockcheck2.stopped, 1)
        tail = data("blockcheck2_output", {}, {})
        self.assertEqual(tail["items"], ["строка 1"])


class TestMissingRunners(unittest.TestCase):
    """Сканера и скрипта на устройстве может не быть — это ответ."""

    def setUp(self):
        registry.load_tools()
        _jobs.reset()
        self.addCleanup(_jobs.reset)

    def _broken(self, module, name):
        def boom(*a, **kw):
            raise RuntimeError("нет каталогов стратегий")
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, boom)

    def test_scan_status_without_a_scanner_is_an_answer(self):
        self._broken(scanner_mod, "get_strategy_scanner")
        result = data("scan_status", {}, {})
        # `ok: true`: отсутствие сканера — это ответ на вопрос, а не
        # сбой вызова, и переспрашивать его другими словами незачем.
        self.assertTrue(result["ok"])
        self.assertFalse(result["available"])
        self.assertIn("сканер", result["what"])


if __name__ == "__main__":
    unittest.main()
