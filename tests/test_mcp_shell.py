# tests/test_mcp_shell.py
"""
Исполнение команд: что выполняется, как, и чего команда НЕ видит.

Пять вещей, ради которых этот файл существует:

* **safe-список действительно список, а не намерение.** Под
  ``shell_readonly`` выполняется ``df -h`` и не выполняется ``rm``,
  ``iptables -F`` или ``ip link set … down`` — причём отказ называет,
  какого разрешения не хватает;
* **``sh -c`` под ``shell_readonly`` недоступен.** Пайп, редирект,
  подстановка — это уже произвольное исполнение, и разбирать «а этот
  пайп безобидный» мы не будем;
* **таймаут прибивает команду**, а не ждёт её вечно: клиент MCP рвёт
  соединение раньше, чем зависшая команда надумает завершиться;
* **обрезка сохраняет ХВОСТ.** В хвосте вывода ошибка, в шапке —
  приветствие;
* **окружение и stdin.** В ``env`` команды нет ни одной переменной
  процесса GUI (там токены и пути), а ``stdin`` закрыт — иначе первая
  же интерактивная программа повиснет до таймаута.

Настоящих ``iptables`` и пакетных менеджеров тест не трогает: всё, что
он запускает, — это ``sh``, ``cat``, ``df`` и ``sleep``.
"""

import os
import unittest

from core import shell_exec
from tests._shell_sandbox import Sandbox


RO = {"shell_readonly": True}
FULL = {"shell_full": True}


class TestSafeList(unittest.TestCase):
    """Что разрешено под ``shell_readonly`` — и что нет."""

    def setUp(self):
        self.box = Sandbox(self, RO)

    def test_safe_command_runs(self):
        result = self.box.data("shell_exec", {"command": "df -h"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["returncode"], 0)
        self.assertIn("/", result["output"])
        self.assertTrue(result["safe_list"])
        self.assertEqual(result["mode"], "argv")

    def test_argv_form_runs_too(self):
        result = self.box.data("shell_exec", {"argv": ["uname", "-a"]})
        self.assertTrue(result["ok"])
        self.assertTrue(result["output"].strip())

    def test_unknown_command_is_refused_with_the_missing_permission(self):
        result = self.box.data("shell_exec", {"command": "rm /tmp/nope"})
        self.assertFalse(result["ok"])
        self.assertIn("rm", result["error"])
        self.assertIn("shell_full", result["hint"])

    def test_write_form_of_a_safe_command_is_refused(self):
        # `ip` читающая — в списке; `ip link set … down` меняет систему.
        result = self.box.data(
            "shell_exec", {"argv": ["ip", "link", "set", "eth0", "down"]})
        self.assertFalse(result["ok"])
        self.assertIn("set", result["error"])
        self.assertIn("shell_full", result["error"] + result["hint"])

    def test_dangerous_flag_of_a_safe_command_is_refused(self):
        result = self.box.data("shell_exec", {"argv": ["iptables", "-F"]})
        self.assertFalse(result["ok"])
        self.assertIn("-F", result["error"])

    def test_required_flag_is_enforced(self):
        # `ping` без -c пингует вечно и держит синхронный вызов до
        # таймаута — safe-список требует счётчик.
        self.assertFalse(
            shell_exec.check_safe(["ping", "example.com"])["safe"])
        self.assertTrue(
            shell_exec.check_safe(["ping", "-c", "2", "example.com"])["safe"])

    def test_clustered_flags_are_understood(self):
        # `iptables -nvL` — идиоматическая форма, и она обязана
        # проходить, а `-nvF` — нет.
        self.assertTrue(shell_exec.check_safe(["iptables", "-nvL"])["safe"])
        self.assertFalse(shell_exec.check_safe(["iptables", "-nvF"])["safe"])

    def test_attached_value_flags_are_understood(self):
        for argv in (["top", "-n1"], ["top", "-n", "1"],
                     ["tail", "-n", "50", "/etc/hostname"],
                     ["head", "-20", "/etc/hostname"]):
            with self.subTest(argv=argv):
                self.assertTrue(shell_exec.check_safe(argv)["safe"])


class TestShellMode(unittest.TestCase):
    """Произвольная строка — только под ``shell_full``."""

    def setUp(self):
        self.box = Sandbox(self, RO)

    def test_pipe_is_refused_under_readonly(self):
        result = self.box.data("shell_exec",
                               {"command": "cat /etc/hostname | wc -l"})
        self.assertFalse(result["ok"])
        self.assertIn("метасимвол", result["error"])
        self.assertIn("shell_full", result["hint"])

    def test_redirect_is_refused_under_readonly(self):
        result = self.box.data("shell_exec",
                               {"command": "echo hi > /tmp/zapret-test"})
        self.assertFalse(result["ok"])
        self.assertFalse(os.path.exists("/tmp/zapret-test"))

    def test_substitution_is_refused_under_readonly(self):
        result = self.box.data("shell_exec",
                               {"command": "echo $(id -u)"})
        self.assertFalse(result["ok"])

    def test_pipe_runs_under_full(self):
        self.box.permissions(shell_full=True)
        result = self.box.data("shell_exec",
                               {"command": "printf 'a\\nb\\n' | wc -l"},
                               FULL)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "shell")
        self.assertEqual(result["output"].strip(), "2")

    def test_full_implies_readonly(self):
        # Включённый shell_full открывает и safe-список: иначе
        # пользователь видит галочку и половину неработающих
        # инструментов.
        self.box.permissions(shell_full=True)
        result = self.box.data("shell_exec", {"command": "df -h"}, FULL)
        self.assertTrue(result["ok"])


class TestExecution(unittest.TestCase):
    """Правила исполнения: таймаут, обрезка, окружение, stdin."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_timeout_kills_the_command(self):
        result = self.box.data("shell_exec",
                               {"argv": ["sleep", "30"], "timeout_sec": 1},
                               FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["timed_out"])
        self.assertLess(result["duration_ms"], 10000)
        self.assertIn("timeout_sec", result["hint"])

    def test_truncation_keeps_the_tail(self):
        self.box.cfg.set("mcp", "shell",
                         dict(self.box.cfg.get("mcp", "shell"),
                              output_kb=1))
        result = self.box.data(
            "shell_exec",
            {"command": "i=0; while [ $i -lt 4000 ]; do "
                        "echo LINE$i; i=$((i+1)); done"}, FULL)
        self.assertTrue(result["ok"])
        self.assertTrue(result["truncated"])
        lines = result["output"].splitlines()
        self.assertEqual(lines[-1], "LINE3999")
        self.assertNotIn("LINE0", lines)
        self.assertIn("ХВОСТ", result["output_note"])

    def test_environment_has_no_gui_variables(self):
        os.environ["ZAPRET_TEST_MARKER"] = "must-not-leak"
        self.addCleanup(os.environ.pop, "ZAPRET_TEST_MARKER", None)
        result = self.box.data("shell_exec", {"command": "env"}, FULL)
        self.assertTrue(result["ok"])
        self.assertNotIn("ZAPRET_TEST_MARKER", result["output"])
        self.assertNotIn("must-not-leak", result["output"])
        self.assertIn("PATH=", result["output"])
        self.assertIn("LANG=C", result["output"])

    def test_stdin_is_closed(self):
        # `cat` без файла читает stdin: с открытым stdin он повис бы до
        # таймаута, с /dev/null — завершается сразу и пустым.
        result = self.box.data("shell_exec",
                               {"argv": ["cat"], "timeout_sec": 5}, FULL)
        self.assertTrue(result["ok"])
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["output"], "")

    def test_nonzero_exit_is_an_answer_not_an_error(self):
        # `grep`, ничего не нашедший, возвращает 1 — ошибкой ВЫЗОВА это
        # не является, иначе модель начнёт «чинить» исправное.
        call = self.box.call("shell_exec",
                             {"command": "grep nope /etc/hostname"}, FULL)
        self.assertFalse(call["isError"])
        self.assertEqual(call["structuredContent"]["returncode"], 1)

    def test_working_directory_is_honoured(self):
        result = self.box.data("shell_exec", {"command": "pwd"}, FULL)
        self.assertEqual(result["output"].strip(), self.box.dir)
        self.assertEqual(result["workdir"], self.box.dir)

    def test_output_is_marked_untrusted(self):
        result = self.box.data("shell_exec", {"command": "df -h"}, FULL)
        self.assertIn("untrusted", result["note"])


class TestAsyncJobs(unittest.TestCase):
    """Долгая команда: ярлык сразу, вывод по частям."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_job_returns_id_immediately_and_streams_output(self):
        start = self.box.data(
            "shell_exec_async",
            {"command": "for i in 1 2 3; do echo tick$i; sleep 0.2; done",
             "label": "тик"}, FULL)
        self.assertTrue(start["ok"])
        self.assertTrue(start["async"])
        job_id = start["job_id"]

        deadline = 0
        while deadline < 100:
            status = self.box.data("shell_job_status", {"job_id": job_id},
                                   FULL)
            if status["done"]:
                break
            deadline += 1
            _sleep(0.1)
        self.assertTrue(status["done"])
        self.assertEqual(status["returncode"], 0)

        first = self.box.data("shell_job_output",
                              {"job_id": job_id, "offset": 0}, FULL)
        self.assertIn("tick1", first["output"])
        rest = self.box.data("shell_job_output",
                             {"job_id": job_id,
                              "offset": first["next_offset"]}, FULL)
        self.assertEqual(rest["output"], "")
        self.assertEqual(rest["next_offset"], first["next_offset"])

    def test_finished_job_keeps_answering(self):
        # Модель спрашивает статус и через полминуты после конца:
        # «задачи нет» она прочитает как «прогон потерян».
        start = self.box.data("shell_exec_async", {"command": "echo done"},
                              FULL)
        _wait_done(self, start["job_id"])
        status = self.box.data("shell_job_status",
                               {"job_id": start["job_id"]}, FULL)
        self.assertTrue(status["done"])
        self.assertEqual(status["returncode"], 0)

    def test_unknown_job_id_lists_the_known_ones(self):
        result = self.box.data("shell_job_status", {"job_id": "sh-nope"},
                               FULL)
        self.assertFalse(result["ok"])
        self.assertIn("known_job_ids", result)

    def test_stop_kills_the_job(self):
        start = self.box.data("shell_exec_async",
                              {"command": "sleep 60"}, FULL)
        stopped = self.box.data("shell_job_stop",
                                {"job_id": start["job_id"]}, FULL)
        self.assertTrue(stopped["ok"])
        _wait_done(self, start["job_id"])
        status = self.box.data("shell_job_status",
                               {"job_id": start["job_id"]}, FULL)
        self.assertTrue(status["done"])
        self.assertTrue(status["stopped"])

    def test_max_jobs_is_enforced(self):
        self.box.cfg.set("mcp", "shell",
                         dict(self.box.cfg.get("mcp", "shell"), max_jobs=1))
        first = self.box.data("shell_exec_async", {"command": "sleep 5"},
                              FULL)
        self.assertTrue(first["ok"])
        second = self.box.data("shell_exec_async", {"command": "sleep 5"},
                               FULL)
        self.assertFalse(second["ok"])
        self.assertIn("max_jobs", second["error"])
        self.box.data("shell_job_stop", {"job_id": first["job_id"]}, FULL)


class TestJournal(unittest.TestCase):
    """Журнал аудита отвечает «что получилось», а не только «что звали»."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_return_code_and_output_head_are_journalled(self):
        import json

        self.box.data("shell_exec", {"command": "echo hello"}, FULL)
        path = os.path.join(self.box.dir, "mcp-audit.jsonl")
        with open(path, encoding="utf-8") as f:
            entries = [json.loads(line) for line in f if line.strip()]
        entry = [e for e in entries if e["tool"] == "shell_exec"][-1]
        self.assertEqual(entry["result"]["returncode"], 0)
        self.assertIn("hello", entry["result"]["output_head"])
        self.assertTrue(entry["mutating"])


class TestReadonlyDiagnostics(unittest.TestCase):
    """Сетевая диагностика под ``shell_readonly`` — и её границы.

    Расширение safe-списка ради ``ip route get … mark``, ``tc``,
    ``find`` и пробного ``wget`` не должно открыть запись: у iproute2
    и tc глаголы сокращаются (``ip r d`` = ``ip route delete``), nft
    разбирает argv как скрипт, ``date ММДДччмм`` ставит время.
    """

    def safe(self, *argv):
        return shell_exec.check_safe(list(argv))["safe"]

    def test_route_lookup_with_mark_is_allowed(self):
        self.assertTrue(self.safe("ip", "route", "get", "1.1.1.1", "from",
                                  "192.168.1.10", "iif", "br-lan", "mark",
                                  "0x40000000"))
        self.assertTrue(self.safe("ip", "-j", "rule", "show"))
        self.assertTrue(self.safe("ip", "-s", "link"))

    def test_abbreviated_write_verbs_are_refused(self):
        for argv in (("ip", "r", "d", "default"),
                     ("ip", "route", "a", "10.0.0.0/8", "dev", "lo"),
                     ("ip", "a", "a", "10.0.0.1/24", "dev", "br-lan"),
                     ("ip", "link", "s", "eth0", "mtu", "100"),
                     ("ip", "route", "prepend", "default", "dev", "lo"),
                     ("ip", "-b", "route"),
                     ("ip", "-n", "route", "a", "a", "1.2.3.4/32"),
                     ("tc", "qdisc", "a", "dev", "eth0", "root", "netem"),
                     ("tc", "-b", "qdisc")):
            self.assertFalse(self.safe(*argv), argv)

    def test_tc_reads(self):
        self.assertTrue(self.safe("tc", "-s", "qdisc", "show", "dev",
                                  "eth0"))
        self.assertTrue(self.safe("tc", "filter", "show", "dev", "eth0",
                                  "ingress"))
        self.assertFalse(self.safe("tc", "exec", "bpf"))

    def test_nft_script_injection_is_refused(self):
        self.assertTrue(self.safe("nft", "-a", "list", "chain", "inet",
                                  "fw4", "mangle_prerouting"))
        self.assertFalse(self.safe("nft", "list", "ruleset;flush",
                                   "ruleset"))
        self.assertFalse(self.safe("nft", "list", "ruleset\nflush"))
        self.assertFalse(self.safe("nft", "list", "table inet x"))

    def test_log_patterns_may_contain_spaces(self):
        self.assertTrue(self.safe("logread", "-l", "50", "-e",
                                  "Oct 28 19:2"))
        self.assertTrue(self.safe("grep", "-e", "no usable address",
                                  "/tmp/x"))
        self.assertFalse(self.safe("logread", "-e", "a\nb"))

    def test_logread_n_points_to_the_readonly_form(self):
        verdict = shell_exec.check_safe(["logread", "-n", "50"])
        self.assertFalse(verdict["safe"])
        self.assertIn("-l N", verdict["reason"])
        self.assertNotIn("shell_full", verdict["reason"])

    def test_pipe_refusal_points_to_filter(self):
        result = shell_exec.run_command("logread | tail -n 20")
        self.assertFalse(result["ok"])
        self.assertIn("filter", result["hint"])

    def test_date_cannot_set_the_clock(self):
        self.assertTrue(self.safe("date", "+%s"))
        self.assertFalse(self.safe("date", "0101000025"))

    def test_find_is_read_only(self):
        self.assertTrue(self.safe("find", "/opt", "-maxdepth", "3",
                                  "-name", "*.py", "-type", "f"))
        for flag in ("-exec", "-execdir", "-ok", "-delete", "-fprint",
                     "-fls"):
            self.assertFalse(self.safe("find", "/", flag, "x"), flag)

    def test_fetch_only_to_nowhere(self):
        self.assertTrue(self.safe("wget", "-q", "-O", "/dev/null", "-T",
                                  "5", "https://example.com"))
        self.assertTrue(self.safe("wget", "--spider", "http://x"))
        self.assertTrue(self.safe("uclient-fetch", "-O-", "http://x"))
        self.assertFalse(self.safe("wget", "http://x"))
        self.assertFalse(self.safe("wget", "-O", "/etc/passwd",
                                   "http://x"))
        self.assertFalse(self.safe("wget", "-P", "/tmp", "http://x"))
        self.assertTrue(self.safe("curl", "-s", "-o", "/dev/null", "-w",
                                  "%{http_code} %{time_total}",
                                  "https://example.com"))
        self.assertFalse(self.safe("curl", "-o", "/tmp/x", "http://x"))
        self.assertFalse(self.safe("curl", "--output=/tmp/x", "http://x"))
        self.assertFalse(self.safe("curl", "-w", "%output{/tmp/x}",
                                   "http://x"))


class TestOutputFilter(unittest.TestCase):
    """``filter`` — замена ``| grep | tail`` без оболочки."""

    def setUp(self):
        self.box = Sandbox(self, RO)
        lines = []
        for i in range(5000):
            tag = "dnsmasq[1]: failed" if i % 10 == 0 else "kernel: ok"
            lines.append("%05d %s" % (i, tag))
        self.path = self.box.write("log.txt", "\n".join(lines) + "\n")

    def run_filter(self, flt):
        return self.box.data("shell_exec", {"argv": ["cat", self.path],
                                            "filter": flt})

    def test_filter_sees_the_whole_output_not_the_truncated_tail(self):
        result = self.run_filter({"include": ["dnsmasq"],
                                  "count_only": True})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["filter"]["lines_seen"], 5000)
        self.assertEqual(result["filter"]["lines_matched"], 500)
        self.assertEqual(result["output"], "")

    def test_tail_head_and_exclude(self):
        tail = self.run_filter({"include": ["DNSMASQ"], "ignore_case": True,
                                "tail": 2})
        self.assertEqual(tail["output"].splitlines(),
                         ["04980 dnsmasq[1]: failed",
                          "04990 dnsmasq[1]: failed"])
        head = self.run_filter({"exclude": ["dnsmasq"], "head": 1})
        self.assertEqual(head["output"], "00001 kernel: ok\n")

    def test_bad_filter_is_refused(self):
        result = self.box.data("shell_exec", {"argv": ["cat", self.path],
                                              "filter": {"head": 1,
                                                         "tail": 1}})
        self.assertFalse(result["ok"])

    def test_async_job_is_filtered_too(self):
        start = self.box.data("shell_exec_async",
                              {"argv": ["cat", self.path],
                               "filter": {"include": ["failed"],
                                          "tail": 1}})
        job = _wait_done(self, start["job_id"])
        self.assertEqual(job["filter"]["lines_matched"], 500)
        out = shell_exec.job_output(start["job_id"])
        self.assertEqual(out["output"], "04990 dnsmasq[1]: failed\n")


def _sleep(seconds):
    import time
    time.sleep(seconds)


def _wait_done(case, job_id, tries=100):
    for _ in range(tries):
        job = shell_exec.job_status(job_id)
        if job.get("done"):
            return job
        _sleep(0.05)
    case.fail("задача %s не завершилась" % job_id)


if __name__ == "__main__":
    unittest.main()
