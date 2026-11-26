# tests/test_mcp_shell_guards.py
"""
Запреты, подтверждения и дедмен-свитч.

Здесь проверяется не «работает ли», а **обходится ли**:

* запрет матчится по НОРМАЛИЗОВАННОЙ команде, поэтому ``env  rm  -rf /``,
  ``"rm" -rf /``, ``/bin/rm -rf /`` и ``r\\m -rf /`` отклоняются так же,
  как ``rm -rf /``. Наивное сравнение строк обходится за минуту, и
  защита, которую можно обойти за минуту, — декоративная;
* запрет **не снимается подтверждением**: у команд из ``DENY_RULES``
  токена не появляется в принципе;
* токен подтверждения одноразовый и протухает, а исполнить его может
  только то разрешение, которым команду запускали;
* команда, гасящая сеть, без ``guard`` не выполняется **вовсе**, а с
  ``guard`` откатывается сама — в том числе после перезапуска GUI:
  таймер живёт в памяти, снимок дедмена — на диске.

Ни одна проверяемая здесь команда до системы не доходит: опасные
отклоняются, а «сетевые» подменяются безобидными (``true``), чтобы
тест не гасил интерфейс машины, на которой его запустили.
"""

import os
import time
import unittest

from core import shell_exec
from tests._shell_sandbox import Sandbox


FULL = {"shell_full": True}
RO = {"shell_readonly": True}


class TestDenyRules(unittest.TestCase):
    """Запрещённое не выполняется НИКОГДА и ничем не обходится."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    DENIED = (
        "rm -rf /",
        "rm -rf /opt",
        "rm -fr /opt/",
        "mkfs.ext4 /dev/sda1",
        "sysupgrade -n /tmp/firmware.bin",
        "firstboot -y",
        "dd if=/tmp/x of=/dev/mtd0",
        "mtd write /tmp/firmware.bin firmware",
        "passwd root",
        "chmod -R 777 /",
        "chown -R nobody /etc",
    )

    # Те же команды, обёрнутые так, как их напишет модель, которую
    # попросили «обойти фильтр».
    OBFUSCATED = (
        "env  rm   -rf /",
        'env FOO=1 "rm" -rf /',
        "/bin/rm -rf /",
        "busybox rm -rf /opt",
        "sudo rm -rf /",
        "ls /tmp; rm -rf /",
        "r\\m -rf /",
        "  RM   -RF   /  ",
    )

    def test_denied_commands_are_refused(self):
        for command in self.DENIED:
            with self.subTest(command=command):
                self.assertTrue(shell_exec.deny_reason(command),
                                "«%s» должна быть запрещена" % command)

    def test_obfuscated_denied_commands_are_refused_too(self):
        for command in self.OBFUSCATED:
            with self.subTest(command=command):
                self.assertTrue(shell_exec.deny_reason(command),
                                "«%s» обходит запрет" % command)

    def test_normal_commands_are_not_denied(self):
        # Обратная сторона: правило, которое ловит всё, ничем не лучше
        # правила, которое не ловит ничего.
        for command in ("rm -rf /opt/zapret2/tmp/build",
                        "rm /tmp/one-file",
                        "cat /etc/passwd",
                        "grep -r password /opt/etc",
                        "df -h /opt",
                        "opkg list-installed"):
            with self.subTest(command=command):
                self.assertFalse(shell_exec.deny_reason(command),
                                 "«%s» запрещена зря" % command)

    def test_refusal_names_the_rule_and_does_not_offer_confirmation(self):
        result = self.box.data("shell_exec", {"command": "rm -rf /"}, FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["denied"])
        self.assertEqual(result["rule"], "rm_protected_root")
        self.assertNotIn("confirm_token", result)

    def test_denied_command_cannot_be_smuggled_through_argv(self):
        result = self.box.data("shell_exec",
                               {"argv": ["/bin/rm", "-rf", "/opt"]}, FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["denied"])

    def test_deny_rules_have_unique_codes_and_explanations(self):
        codes = [rule["code"] for rule in shell_exec.DENY_RULES]
        self.assertEqual(len(codes), len(set(codes)))
        for rule in shell_exec.DENY_RULES:
            with self.subTest(code=rule["code"]):
                self.assertTrue(rule["why"].strip())


class TestConfirmation(unittest.TestCase):
    """Двухшаговое подтверждение: токен одноразовый и недолгий."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_reboot_needs_a_token(self):
        result = self.box.data("shell_exec", {"command": "reboot"}, FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])
        self.assertTrue(result["confirm_token"].startswith("cf-"))
        self.assertIn("reboot", result["matched_rules"])
        self.assertIn("перезагруз", result["consequences"])

    def test_token_executes_the_command(self):
        first = self.box.data("shell_exec",
                              {"command": "rm -rf %s"
                                          % self.box.path("victim")}, FULL)
        os.makedirs(self.box.path("victim"), exist_ok=True)
        second = self.box.data(
            "shell_confirm", {"confirm_token": first["confirm_token"]},
            FULL)
        self.assertTrue(second["ok"])
        self.assertTrue(second["confirmed"])
        self.assertFalse(os.path.exists(self.box.path("victim")))

    def test_token_is_single_use(self):
        first = self.box.data("shell_exec", {"command": "reboot"}, FULL)
        token = first["confirm_token"]
        record, refusal = shell_exec.take_confirm(token)
        self.assertIsNotNone(record)
        again = self.box.data("shell_confirm", {"confirm_token": token},
                              FULL)
        self.assertFalse(again["ok"])
        self.assertIn("не найдено", again["error"])

    def test_token_expires(self):
        first = self.box.data("shell_exec", {"command": "reboot"}, FULL)
        token = first["confirm_token"]
        # Сдвигаем срок годности, а не ждём минуту.
        shell_exec._CONFIRMS[token]["expires_at"] = time.time() - 1
        result = self.box.data("shell_confirm", {"confirm_token": token},
                               FULL)
        self.assertFalse(result["ok"])
        self.assertIn("просрочен", result["error"])

    def test_confirmation_does_not_grant_permissions(self):
        # Токен, выданный под shell_full, не исполняется тем, у кого
        # только shell_readonly: разрешение проверяется на ОБОИХ шагах.
        first = self.box.data("shell_exec", {"command": "reboot"}, FULL)
        self.box.permissions(shell_readonly=True)
        result = self.box.data(
            "shell_confirm", {"confirm_token": first["confirm_token"]}, RO)
        self.assertFalse(result["ok"])
        self.assertIn("shell_full", result["error"] + result["hint"])

    def test_initialize_explains_the_two_step_contract(self):
        # Двухшаговость не догадываема: без врезки в instructions модель
        # читает отказ с токеном как провал и подбирает «команду
        # попроще».
        from core.mcp import server

        text = server._instructions(["shell_full"], 15)
        self.assertIn("shell_confirm", text)
        self.assertIn("guard", text)
        self.assertNotIn("shell_confirm",
                         server._instructions(["control"], 15))

    def test_confirm_without_arguments_explains_itself(self):
        result = self.box.data("shell_confirm", {}, FULL)
        self.assertFalse(result["ok"])
        self.assertIn("confirm_token", result["hint"])


class TestGuard(unittest.TestCase):
    """Дедмен-свитч: сетевую команду без него не выполняем."""

    def setUp(self):
        self.box = Sandbox(self, FULL)
        self.flag = self.box.path("reverted")

    def revert(self) -> str:
        return "touch %s" % self.flag

    def test_network_command_without_guard_is_refused(self):
        result = self.box.data("shell_exec", {"command": "iptables -F"},
                               FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_guard"])
        self.assertIn("firewall_flush", result["matched_rules"])
        self.assertNotIn("confirm_token", result)

    def test_interface_down_needs_a_guard_too(self):
        for command in ("ip link set eth0 down",
                        "ifconfig eth0 down",
                        "/etc/init.d/dropbear stop"):
            with self.subTest(command=command):
                result = self.box.data("shell_exec", {"command": command},
                                       FULL)
                self.assertFalse(result["ok"])
                self.assertTrue(result.get("need_guard"))

    def test_guard_with_a_denied_revert_is_refused(self):
        result = self.box.data(
            "shell_exec",
            {"command": "iptables -F",
             "guard": {"revert_cmd": "rm -rf /"}}, FULL)
        self.assertFalse(result["ok"])
        self.assertIn("revert_cmd", result["error"])

    def test_guarded_command_arms_the_dead_man(self):
        result = self._run_guarded(ttl=30)
        self.assertTrue(result["ok"])
        self.assertTrue(result["run_id"].startswith("sh-"))
        self.assertEqual(result["guard_expires_in"], 30)
        armed = [g["run_id"] for g in shell_exec.armed_guards()]
        self.assertIn(result["run_id"], armed)

    def test_confirmation_cancels_the_revert(self):
        result = self._run_guarded(ttl=30)
        cancelled = self.box.data("shell_confirm",
                                  {"run_id": result["run_id"]}, FULL)
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(shell_exec.armed_guards(), [])
        self.assertFalse(os.path.exists(self.flag))

    def test_revert_fires_when_nobody_confirms(self):
        result = self._run_guarded(ttl=10)
        # Таймер ждать не обязательно: срабатывание идемпотентно и
        # вызывается тем же кодом, что и таймер.
        fired = shell_exec.fire_guard(result["run_id"])
        self.assertTrue(fired["fired"])
        self.assertTrue(os.path.exists(self.flag))
        entry = shell_exec.get_guard(result["run_id"])
        self.assertEqual(entry["state"], "fired")

    def test_revert_fires_only_once(self):
        result = self._run_guarded(ttl=10)
        shell_exec.fire_guard(result["run_id"])
        os.remove(self.flag)
        again = shell_exec.fire_guard(result["run_id"])
        self.assertFalse(again["fired"])
        self.assertFalse(os.path.exists(self.flag))

    def test_guard_survives_a_gui_restart(self):
        # Таймер живёт в памяти процесса: если бы дедмен держался только
        # на нём, падение GUI оставляло бы роутер без связи навсегда.
        result = self._run_guarded(ttl=10)
        shell_exec.reset_guards()                 # «процесс перезапустили»
        shell_exec._update_guard(result["run_id"],
                                 expires_at=time.time() - 1)
        recovered = shell_exec.recover_guards(source="test")
        self.assertIn(result["run_id"], recovered["fired"])
        self.assertTrue(os.path.exists(self.flag))

    def test_live_guard_is_rearmed_after_restart(self):
        result = self._run_guarded(ttl=60)
        shell_exec.reset_guards()
        recovered = shell_exec.recover_guards(source="test")
        self.assertIn(result["run_id"], recovered["rearmed"])
        self.assertFalse(os.path.exists(self.flag))

    def test_timer_is_really_armed(self):
        result = self._run_guarded(ttl=30)
        timer = shell_exec._TIMERS.get(result["run_id"])
        self.assertIsNotNone(timer)
        self.assertTrue(timer.is_alive())
        self.assertEqual(int(timer.interval), 30)

    def test_timer_fires_by_itself(self):
        # Тот же секундомер, что в приёмке на устройстве, только TTL
        # короткий: заряжаем дедмен напрямую (потолок «не меньше 10 с»
        # живёт в проверке аргумента, а не в самом таймере).
        armed = shell_exec.arm_guard(
            {"revert_cmd": self.revert(), "ttl_sec": 1}, "тестовая команда")
        # Бюджет 15 с, а не 4: под полной загрузкой CPU (весь набор
        # pytest одновременно) секундомер-поток бывало голодал дольше
        # секунды. Ждём именно state="fired", а не файл-флаг: флаг
        # создаёт сама revert_cmd внутри _run_sync, а "fired" ставится
        # уже ПОСЛЕ её возврата (shell_exec.py:1742-1743) — если ждать
        # флаг, assert ловит промежуточное "firing".
        state = ""
        for _ in range(60):
            entry = shell_exec.get_guard(armed["run_id"])
            state = entry.get("state") if entry else ""
            if state == "fired":
                break
            time.sleep(0.25)
        self.assertEqual(state, "fired",
                         "дедмен не дошёл до «fired» за 15 с")
        self.assertTrue(os.path.exists(self.flag),
                        "revert_cmd не выполнился по TTL")

    def test_guard_file_lives_next_to_settings(self):
        # /tmp на роутере — tmpfs: дедмен, положенный туда, исчезает
        # ровно при той перезагрузке, ради которой он и заводился.
        self._run_guarded(ttl=30)
        self.assertEqual(os.path.dirname(shell_exec.guards_path()),
                         self.box.dir)
        self.assertTrue(os.path.exists(shell_exec.guards_path()))

    def _run_guarded(self, ttl):
        """Пройти оба шага для «сетевой» команды (сама команда — true)."""
        first = self.box.data(
            "shell_exec",
            {"command": "iptables -F", "timeout_sec": 10,
             "guard": {"revert_cmd": self.revert(), "ttl_sec": ttl}}, FULL)
        self.assertTrue(first["need_confirm"])
        # Настоящую команду до системы не доводим: подменяем её на
        # безобидную, сохраняя весь остальной путь (guard, подтверждение).
        record = shell_exec._CONFIRMS[first["confirm_token"]]
        record["payload"]["argv"] = ["true"]
        record["payload"]["mode"] = "argv"
        record["payload"]["display"] = "iptables -F (подменено в тесте)"
        return self.box.data("shell_confirm",
                             {"confirm_token": first["confirm_token"]},
                             FULL)


if __name__ == "__main__":
    unittest.main()
