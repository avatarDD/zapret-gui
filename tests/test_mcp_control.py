# tests/test_mcp_control.py
"""
Управление движком через MCP: разрешение, отказы и честность ответа.

Три вещи, которые здесь стережём.

**Без `control` этих инструментов нет.** Ни в `tools/list`, ни по имени
в обход списка: модель, знающая имя `nfqws_stop`, не должна уметь
выключить обход на устройстве, где управление не открыто.

**Движка нет — это ответ, а не трассировка.** На машине разработчика
нет ни nfqws2, ни iptables. Инструмент, отдающий в этом случае
исключение, бесполезен ровно там, где он нужнее всего: на роутере,
где что-то сломалось.

**SIGHUP — не перезапуск.** `nfqws_reload_lists` обязан говорить, дошёл
ли сигнал: «списки перечитаны» при лежащем движке — это неправда,
из-за которой модель считает правку применённой.

Менеджеры подменяются: тест, реально дёргающий `iptables` и поднимающий
nfqws2, портит машину, на которой его запустили.
"""

import contextlib
import threading
import unittest

from core import nfqws_control, nfqws_session
from core.mcp import registry


CONTROL = {"control": True}

CONTROL_TOOLS = ("nfqws_start", "nfqws_stop", "nfqws_restart",
                 "nfqws_reload_lists", "strategy_apply",
                 "firewall_apply", "firewall_remove")


class FakeNFQWS:
    """Движок, который слушается и честно рассказывает о себе."""

    def __init__(self, running=False, can_start=True):
        self.running = running
        self.can_start = can_start
        self.calls = []
        self.last_args = None

    def is_running(self):
        return self.running

    def start(self, args=None):
        self.calls.append(("start", args))
        self.last_args = args
        self.running = bool(self.can_start)
        return bool(self.can_start)

    def stop(self):
        self.calls.append(("stop", None))
        self.running = False
        return True

    def restart(self, args=None):
        self.calls.append(("restart", args))
        self.last_args = args
        self.running = bool(self.can_start)
        return bool(self.can_start)

    def get_status(self):
        return {"running": self.running, "pid": 4242 if self.running else 0,
                "uptime": 10 if self.running else None,
                "binary": "/opt/zapret2/nfqws2",
                "last_args": self.last_args or [],
                "exit_code": None if self.running else 1}


class FakeFirewall:
    """Правила, которые встают и снимаются без участия ядра."""

    def __init__(self, applied=False, can_apply=True):
        self.applied = applied
        self.can_apply = can_apply
        self.calls = []

    def apply_rules(self, *a, **kw):
        self.calls.append("apply")
        self.applied = bool(self.can_apply)
        return bool(self.can_apply)

    def remove_rules(self):
        self.calls.append("remove")
        self.applied = False
        return True

    def get_status(self):
        return {"type": "iptables", "applied": self.applied,
                "rules": ["-A OUTPUT -j NFQUEUE"] if self.applied else [],
                "rules_count": 1 if self.applied else 0}


class ControlCase(unittest.TestCase):
    """Общая подмена менеджеров и удобные вызовы."""

    def setUp(self):
        registry.load_tools()
        self.nfqws = FakeNFQWS()
        self.firewall = FakeFirewall()
        self.cfg = _FakeConfig()
        self._patch(nfqws_control, "_managers",
                    lambda: (self.nfqws, self.firewall, self.cfg))
        # Сканер и blockcheck на тестовой машине опрашивать незачем:
        # по умолчанию движок свободен.
        self._patch(nfqws_control, "busy", dict)
        self._patch(nfqws_control, "active_strategy_args",
                    lambda: ["--filter-tcp=443"])

    def _patch(self, module, name, value):
        saved = getattr(module, name)
        self.addCleanup(setattr, module, name, saved)
        setattr(module, name, value)

    def call(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             CONTROL if perms is None else perms)

    def data(self, name, args=None, perms=None):
        return self.call(name, args, perms)["structuredContent"]


class _FakeConfig:
    """Конфиг ровно с теми ключами, которые читает nfqws_control."""

    def __init__(self):
        self.values = {("firewall", "apply_on_start"): True,
                       ("strategy", "current_id"): "old-one",
                       ("autostart", "enabled"): False,
                       ("nfqws", "ports_tcp"): "80,443"}
        self.saved = 0

    def get(self, *parts, **kw):
        return self.values.get(tuple(parts), kw.get("default"))

    def set(self, *args):
        self.values[tuple(args[:-1])] = args[-1]

    def save(self):
        self.saved += 1
        return True

    def effective(self):
        return {"gui": {"port": 8080}}


class TestPermission(unittest.TestCase):
    """Без `control` инструментов нет — ни в списке, ни по имени."""

    def setUp(self):
        registry.load_tools()

    def test_not_listed_without_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        for tool in CONTROL_TOOLS:
            with self.subTest(tool=tool):
                self.assertNotIn(tool, names)

    def test_listed_with_permission(self):
        names = {spec.name for spec in registry.available_tools(CONTROL)}
        for tool in CONTROL_TOOLS:
            with self.subTest(tool=tool):
                self.assertIn(tool, names)

    def test_calling_by_name_is_refused(self):
        # Обойти `tools/list`, зная имя, не должно получаться.
        for tool in CONTROL_TOOLS:
            with self.subTest(tool=tool):
                answer = registry.call(tool, {"id": "x", "reason": "x"}, {})
                self.assertTrue(answer["isError"])
                self.assertEqual(
                    answer["structuredContent"]["permission"], "control")

    def test_all_of_them_are_mutating(self):
        for spec in registry.all_tools():
            if spec.name in CONTROL_TOOLS:
                with self.subTest(tool=spec.name):
                    self.assertTrue(spec.mutating)


class TestEngine(ControlCase):
    """Старт, стоп, перезапуск: что уходит в менеджеры и что в ответ."""

    def test_start_applies_rules_then_starts(self):
        payload = self.data("nfqws_start")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["running"])
        self.assertEqual(self.firewall.calls, ["apply"])
        self.assertEqual(self.nfqws.calls[0][0], "start")
        # Аргументы активной стратегии пересобираются, а не берутся из
        # кеша прошлого запуска.
        self.assertEqual(self.nfqws.calls[0][1], ["--filter-tcp=443"])
        self.assertEqual(payload["reverse"], "nfqws_stop")

    def test_failed_start_rolls_the_rules_back(self):
        # Правила без движка — это чёрная дыра: пакеты уходят в очередь,
        # которую никто не читает.
        self.nfqws.can_start = False
        payload = self.data("nfqws_start")
        self.assertFalse(payload["ok"])
        self.assertEqual(self.firewall.calls, ["apply", "remove"])
        self.assertFalse(self.firewall.applied)
        self.assertIn("error", payload)
        self.assertIn("logs_tail", payload["hint"])

    def test_failed_start_still_reports_the_engine(self):
        # «Не удалось запустить» без exit_code не даёт модели ни одного
        # способа понять почему.
        self.nfqws.can_start = False
        payload = self.data("nfqws_start")
        self.assertIn("exit_code", payload)
        self.assertIn("binary", payload)
        self.assertFalse(payload["running"])

    def test_stop_removes_the_rules(self):
        self.nfqws.running = True
        self.firewall.applied = True
        payload = self.data("nfqws_stop")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["running"])
        self.assertIn("remove", self.firewall.calls)
        self.assertFalse(payload["firewall_applied"])

    def test_restart_rebuilds_args(self):
        self.nfqws.running = True
        payload = self.data("nfqws_restart")
        self.assertTrue(payload["ok"])
        self.assertEqual(self.nfqws.calls[0],
                         ("restart", ["--filter-tcp=443"]))
        self.assertEqual(payload["action"], "restart")

    def test_partially_applied_rules_are_rolled_back_too(self):
        # apply_rules() вернул False (часть правил встала, очередь — нет),
        # движок не поднялся: оставшееся — наше, его и снимаем.
        self.firewall.can_apply = False
        self.nfqws.can_start = False
        payload = self.data("nfqws_start")
        self.assertFalse(payload["ok"])
        self.assertEqual(self.firewall.calls, ["apply", "remove"])

    def test_failed_restart_does_not_leave_rules_without_engine(self):
        # Как и у старта: перехват на очередь, которую никто не читает,
        # диагностика называет ошибкой rules_without_engine.
        self.nfqws.running = True
        self.firewall.applied = True
        self.nfqws.can_start = False
        payload = self.data("nfqws_restart")
        self.assertFalse(payload["ok"])
        self.assertEqual(self.firewall.calls, ["remove"])
        self.assertFalse(self.firewall.applied)

    def test_failed_apply_strategy_does_not_leave_rules(self):
        from core import strategy_builder

        class _Strategies:
            def get_strategy(self, sid):
                return {"id": sid, "name": "тест"}

            def build_nfqws_args(self, strategy):
                return ["--filter-tcp=443"]

        self._patch(strategy_builder, "get_strategy_manager", _Strategies)
        self.nfqws.can_start = False
        out = nfqws_control.apply_strategy("s1")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error_code"], "start_failed")
        self.assertEqual(self.firewall.calls, ["remove", "apply", "remove"])
        self.assertFalse(self.firewall.applied)
        # Неудачная стратегия не записывается активной.
        self.assertEqual(self.cfg.values[("strategy", "current_id")],
                         "old-one")

    def test_busy_engine_refuses_instead_of_fighting(self):
        # Сканер сам поднимает и роняет nfqws2: применять поверх него —
        # испортить и скан, и стратегию. S9 заменит эту проверку общим
        # мьютексом внутри busy().
        self._patch(nfqws_control, "busy",
                    lambda: {"who": "scanner", "reason": "идёт скан",
                             "hint": "остановите подбор"})
        for tool in ("nfqws_start", "nfqws_stop", "nfqws_restart"):
            with self.subTest(tool=tool):
                payload = self.data(tool)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["busy"], "scanner")
                self.assertIn("остановите подбор", payload["hint"])
        self.assertEqual(self.nfqws.calls, [])

    def test_missing_binary_is_an_answer_not_a_traceback(self):
        # На устройстве без zapret2 падает сам менеджер.
        def boom():
            raise FileNotFoundError("нет /opt/zapret2/nfqws2")

        self._patch(nfqws_control, "_managers", boom)
        answer = self.call("nfqws_start")
        self.assertTrue(answer["isError"])
        payload = answer["structuredContent"]
        self.assertIn("FileNotFoundError", payload["error"])


class TestReloadLists(ControlCase):
    """SIGHUP — это не перезапуск, и об этом должно быть сказано."""

    def test_signalled(self):
        self._patch(nfqws_control, "reload_lists",
                    lambda reason: {"ok": True, "pids": [111], "error": ""})
        payload = self.data("nfqws_reload_lists", {"reason": "other.txt"})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["signalled"])
        self.assertEqual(payload["pids"], [111])
        self.assertIn("НЕ перезапуск", payload["note"])

    def test_engine_down_is_not_a_lie(self):
        self._patch(nfqws_control, "reload_lists",
                    lambda reason: {"ok": False, "pids": [],
                                    "error": "nfqws2 не запущен"})
        payload = self.data("nfqws_reload_lists")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["signalled"])
        self.assertIn("не запущен", payload["reason"])
        self.assertIn("nfqws_start", payload["hint"])


class TestStrategyApply(ControlCase):
    """Применение стратегии: дифф, снимок и внятные отказы."""

    def setUp(self):
        super().setUp()
        self.strategies = {
            "mine": {"id": "mine", "name": "Моя",
                     "profiles": [{"id": "p1", "args": "--dpi-desync=fake"}]},
        }

    def _patch_strategies(self, args_by_id=None):
        import core.strategy_builder as sb

        store = self.strategies
        argv = args_by_id or {"mine": ["--dpi-desync=fake"]}

        class FakeManager:
            def get_strategy(self, sid):
                return store.get(sid)

            def build_nfqws_args(self, strategy):
                return list(argv.get(strategy["id"], []))

        saved = sb.get_strategy_manager
        self.addCleanup(setattr, sb, "get_strategy_manager", saved)
        sb.get_strategy_manager = lambda: FakeManager()

    def test_unknown_id_says_what_to_do(self):
        self._patch_strategies()
        payload = self.data("strategy_apply", {"id": "nope"})
        self.assertFalse(payload["ok"])
        self.assertIn("strategy_list", payload["hint"])
        self.assertEqual(self.nfqws.calls, [])

    def test_strategy_without_profiles_is_named_as_such(self):
        self._patch_strategies(args_by_id={"mine": []})
        payload = self.data("strategy_apply", {"id": "mine"})
        self.assertFalse(payload["ok"])
        self.assertIn("профил", payload["hint"])

    def test_applies_and_remembers(self):
        self._patch_strategies()
        payload = self.data("strategy_apply", {"id": "mine"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["before"], "old-one")
        self.assertEqual(payload["after"], "mine")
        self.assertTrue(payload["changed"])
        self.assertEqual(self.cfg.get("strategy", "current_id"), "mine")
        self.assertEqual(self.nfqws.calls[0][1], ["--dpi-desync=fake"])

    def test_busy_engine_blocks_apply(self):
        self._patch_strategies()
        self._patch(nfqws_control, "busy",
                    lambda: {"who": "scanner", "reason": "идёт скан"})
        payload = self.data("strategy_apply", {"id": "mine"})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["busy"], "scanner")
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old-one")

    def test_held_mutex_blocks_apply_and_names_the_owner(self):
        """Настоящий мьютекс, а не опрос: `busy()` здесь слепа нарочно.

        Между «спросил, свободно ли» и «применил» сканер успевает
        стартовать. Отказ обязан прийти от самой блокировки — и назвать,
        кто её держит.
        """
        self._patch_strategies()
        with _held_session(self, owner="scanner"):
            payload = self.data("strategy_apply", {"id": "mine"})

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["busy"], "scanner")
        self.assertIn("подбор стратегий", payload["error"])
        self.assertEqual(self.nfqws.calls, [])
        self.assertEqual(self.cfg.get("strategy", "current_id"), "old-one")

    def test_scan_and_apply_cannot_run_together(self):
        """Ровно та драка, ради которой сессия и написана."""
        self._patch_strategies()
        session = nfqws_session.get_nfqws_session()
        with _held_session(self, owner="scanner"):
            self.assertEqual(session.holder()["owner"], "scanner")
            self.assertFalse(self.data("strategy_apply",
                                       {"id": "mine"})["ok"])
            self.assertFalse(self.data("nfqws_start")["ok"])
            self.assertFalse(self.data("nfqws_stop")["ok"])
        # Сканер отпустил — управление снова работает.
        self.assertTrue(self.data("strategy_apply", {"id": "mine"})["ok"])


@contextlib.contextmanager
def _held_session(case, owner="scanner"):
    """Занять общий мьютекс на движок ИЗ ДРУГОГО ПОТОКА.

    Из своего нельзя: захват повторный для того же потока — держатель
    сессии обязан иметь право позвать `core/nfqws_control`.
    """
    session = nfqws_session.get_nfqws_session()
    taken, done = threading.Event(), threading.Event()

    def worker():
        with session.acquire(owner=owner, timeout=0, reason="подбор"):
            taken.set()
            done.wait(5)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    case.assertTrue(taken.wait(5), "поток не успел занять сессию")
    try:
        yield session
    finally:
        done.set()
        thread.join(5)


class TestBusyProbe(unittest.TestCase):
    """`busy()` не должна объявлять движок занятым, когда просто не смогла
    спросить: иначе обход становится не запустить вовсе."""

    def test_unavailable_scanner_means_free(self):
        import core.strategy_scanner as scanner

        saved = scanner.get_strategy_scanner
        self.addCleanup(setattr, scanner, "get_strategy_scanner", saved)

        def boom():
            raise RuntimeError("сканера на этом устройстве нет")

        scanner.get_strategy_scanner = boom
        self.assertEqual(nfqws_control.busy(), {})


if __name__ == "__main__":
    unittest.main()
