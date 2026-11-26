# tests/test_diagnostics_conflicts.py
"""Тесты детекции конфликтов окружения (core/diagnostics.evaluate_conflicts)."""

import unittest
from unittest import mock

import os

from core.diagnostics import (
    evaluate_conflicts, evaluate_foreign_installs, attribute_nfqws_owner,
    _KNOWN_TOOL_MARKERS, _FOREIGN_NFQWS_INSTALLS,
)


class TestEvaluateConflicts(unittest.TestCase):

    def test_no_conflicts(self):
        self.assertEqual(evaluate_conflicts(set(), set()), [])

    def test_getdomains_marker(self):
        w = evaluate_conflicts({"/opt/etc/init.d/S99getdomains"}, set())
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "getdomains")
        self.assertIn("getdomains", w[0]["title"])
        self.assertTrue(w[0]["hint"])

    def test_foreign_daemon(self):
        w = evaluate_conflicts(set(), {"xray"})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "proc-xray")

    def test_combined(self):
        w = evaluate_conflicts(
            {"/usr/bin/podkop", "/opt/sbin/xkeen"},
            {"redsocks"})
        ids = {x["id"] for x in w}
        self.assertEqual(ids, {"podkop", "xkeen", "proc-redsocks"})

    def test_unrelated_paths_ignored(self):
        self.assertEqual(
            evaluate_conflicts({"/usr/bin/python3", "/opt/zapret2/bin"},
                               {"sing-box", "mihomo"}),
            [])

    def test_custom_markers(self):
        markers = ({"id": "x", "name": "X", "paths": ("/a",), "hint": "h"},)
        w = evaluate_conflicts({"/a"}, set(), markers=markers, daemons={})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "x")

    def test_marker_structure_valid(self):
        # Каждый встроенный маркер имеет обязательные поля.
        for m in _KNOWN_TOOL_MARKERS:
            self.assertTrue(m["id"] and m["name"] and m["paths"] and m["hint"])


class TestForeignZapretInstalls(unittest.TestCase):
    """Сторонние сборки zapret (issue #349).

    Отличаются от конфликтов окружения тем, что делят с нами ДВИЖОК и
    очередь NFQUEUE. Человек сносит такую сборку, остатки продолжают
    поднимать nfqws2, а «Диагностика» показывала безымянный PID.
    """

    def test_installed_build_is_an_error_with_its_init_script(self):
        w = evaluate_foreign_installs({"/opt/etc/init.d/S99zapret2"})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "install-z2k")
        self.assertEqual(w[0]["severity"], "error")
        self.assertIn("S99zapret2", w[0]["hint"])

    def test_leftovers_without_init_script_are_a_warning(self):
        w = evaluate_foreign_installs(
            {"/opt/etc/ndm/netfilter.d/000-zapret2.sh"})
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["severity"], "warning")
        self.assertIn("Остатки", w[0]["title"])

    def test_leftovers_name_the_files_that_revive_the_engine(self):
        # Главная жалоба: «удалил, а процесс снова есть». Подсказка
        # обязана назвать хуки, которые его поднимают.
        w = evaluate_foreign_installs(
            {"/opt/etc/init.d/S99z2k-scheduler",
             "/opt/etc/ndm/netfilter.d/000-zapret2.sh"})
        self.assertIn("/opt/etc/init.d/S99z2k-scheduler", w[0]["hint"])

    def test_nothing_found_nothing_reported(self):
        self.assertEqual(evaluate_foreign_installs(set()), [])

    def test_our_own_paths_are_not_a_foreign_install(self):
        # Наш автозапуск — S99zapret и хук 100-zapret-gui.sh.
        self.assertEqual(
            evaluate_foreign_installs({"/opt/etc/init.d/S99zapret",
                                       "/opt/etc/ndm/netfilter.d/100-zapret-gui.sh",
                                       "/opt/zapret2/nfq2/nfqws2"}),
            [])

    def test_foreign_autostart_script_is_reported_separately(self):
        w = evaluate_foreign_installs(
            set(), foreign_autostart="/opt/etc/init.d/S99zapret")
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["id"], "install-foreign-autostart")
        self.assertIn("S99zapret", w[0]["hint"])

    def test_install_table_structure_valid(self):
        for inst in _FOREIGN_NFQWS_INSTALLS:
            self.assertTrue(inst["id"] and inst["name"] and inst["paths"])
            self.assertTrue(inst["hint"])
            # init обязан быть среди paths, иначе «установлено» не
            # отличить от «остались файлы».
            self.assertIn(inst["init"], inst["paths"])


class TestAttributeNfqwsOwner(unittest.TestCase):
    """Кому принадлежит посторонний nfqws2."""

    def test_pidfile_name_gives_away_the_upstream_style_init(self):
        # Движок у всех один (/opt/zapret2/nfq2/nfqws2), поэтому имя
        # PID-файла — единственная зацепка, когда файлов на диске уже нет.
        owner = attribute_nfqws_owner(
            "/opt/zapret2/nfq2/nfqws2 --pidfile=/var/run/nfqws2_1.pid", set())
        self.assertIsNotNone(owner)
        self.assertEqual(owner["id"], "z2k")

    def test_marker_on_disk_gives_away_the_owner(self):
        owner = attribute_nfqws_owner(
            "/opt/zapret2/nfq2/nfqws2 --qnum=200",
            {"/opt/etc/init.d/S99zapret2"})
        self.assertEqual(owner["id"], "z2k")

    def test_unknown_process_has_no_owner(self):
        self.assertIsNone(
            attribute_nfqws_owner("/usr/sbin/nfqws --qnum=200", set()))

    def test_empty_cmdline_does_not_crash(self):
        self.assertIsNone(attribute_nfqws_owner(None, None))


class TestOurOwnScanIsNotAConflict(unittest.TestCase):
    """nfqws2, запущенный НАШИМ подбором стратегии, — не конфликт.

    blockcheck2.sh и сканер поднимают движок под собой; nfqws_manager их
    отфильтровывает, а «Диагностика» — нет, и во время скана страница
    показывала собственную работу GUI как стороннюю систему.
    """

    def test_descendant_of_gui_is_filtered_out(self):
        import os
        import subprocess
        import tempfile
        import shutil
        import sys
        import time
        from core.diagnostics import check_nfqws_conflicts

        tmp = tempfile.mkdtemp()
        try:
            fake = os.path.join(tmp, "nfqws2")
            # Жертва — копия Питона под видом nfqws2: comm процесса будет
            # «nfqws2», и копия живёт под чужим именем на любой машине.
            # (Копия /bin/sleep на dev-боксах с multicall coreutils
            # мгновенно умирает: «coreutils: unknown program».)
            shutil.copy(sys.executable, fake)
            # Внук в своей сессии — ровно так запускается blockcheck2.
            proc = subprocess.Popen(
                ["sh", "-c", "%s -c 'import time; time.sleep(10)'" % fake],
                preexec_fn=os.setsid)
            try:
                time.sleep(0.3)
                result = check_nfqws_conflicts()
                pids = {c["pid"] for c in result["conflicts"]}
                self.assertNotIn(proc.pid, pids)
                self.assertGreaterEqual(result["scan_children"], 1)
            finally:
                proc.kill()
                proc.wait()
                # Внук переживает kill родителя — добиваем по группе.
                try:
                    os.killpg(proc.pid, 9)
                except OSError:
                    pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestForeignAutostartDetection(unittest.TestCase):
    """Чужой S99zapret отличается от нашего маркером внутри файла."""

    def _script(self, body):
        import tempfile
        path = tempfile.mktemp()
        with open(path, "w") as f:
            f.write(body)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_our_script_is_not_foreign(self):
        from core import diagnostics
        path = self._script("#!/bin/sh\n# zapret-gui:nfqws-autostart\n")
        with mock.patch.object(diagnostics, "_OUR_AUTOSTART_SCRIPT", path):
            self.assertIsNone(diagnostics._foreign_autostart_script())

    def test_script_without_marker_is_foreign(self):
        from core import diagnostics
        path = self._script("#!/bin/sh\n# zapret keenetic init\n")
        with mock.patch.object(diagnostics, "_OUR_AUTOSTART_SCRIPT", path):
            self.assertEqual(diagnostics._foreign_autostart_script(), path)

    def test_missing_script_is_not_foreign(self):
        from core import diagnostics
        with mock.patch.object(diagnostics, "_OUR_AUTOSTART_SCRIPT",
                               "/nonexistent/S99zapret"):
            self.assertIsNone(diagnostics._foreign_autostart_script())


if __name__ == "__main__":
    unittest.main()


class TestSystemInfoExtras(unittest.TestCase):
    """Диски и наличие утилит в «Системной информации».

    Раньше при отсутствии `ip` поля адресов/шлюза/интерфейсов молча
    оставались пустыми, и было непонятно — так и надо или что-то сломано.
    А свободного места не показывалось вовсе, хотя забитая флешка на
    роутере — штатная причина «не ставится / не сохраняется».
    """

    def test_disk_usage_shape(self):
        from core.diagnostics import _get_disk_usage
        disks = _get_disk_usage()
        self.assertIsInstance(disks, list)
        for d in disks:
            for key in ("label", "path", "total_mb", "free_mb", "used_percent"):
                self.assertIn(key, d)
            self.assertGreater(d["total_mb"], 0)
            self.assertGreaterEqual(d["used_percent"], 0)
            self.assertLessEqual(d["used_percent"], 100)
            self.assertLessEqual(d["free_mb"], d["total_mb"])

    def test_disk_usage_deduplicates_same_filesystem(self):
        # /opt и каталог конфига обычно на одном разделе — не дублируем.
        from core.diagnostics import _get_disk_usage
        disks = _get_disk_usage()
        paths = [d["path"] for d in disks]
        self.assertEqual(len(paths), len(set(paths)))


class TestWanIpValue(unittest.TestCase):
    """`wan_ip` — это локальный src-адрес, и он не должен нести оформление."""

    def test_returns_empty_string_when_unavailable(self):
        from core.system_info import _get_wan_ip
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertEqual(_get_wan_ip(), "")

    def test_no_dash_placeholder_in_data(self):
        # Раньше возвращался символ «—» — оформление в данных, из-за чего
        # его нельзя было отличить от реального значения.
        from core.system_info import _get_wan_ip
        with mock.patch("subprocess.run", side_effect=OSError):
            self.assertNotIn("—", _get_wan_ip())

    def test_parses_src_from_ip_route(self):
        from core.system_info import _get_wan_ip
        out = mock.Mock(returncode=0,
                        stdout="8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 0")
        with mock.patch("subprocess.run", return_value=out):
            self.assertEqual(_get_wan_ip(), "192.168.1.50")

    def test_truncated_output_does_not_crash(self):
        from core.system_info import _get_wan_ip
        out = mock.Mock(returncode=0, stdout="8.8.8.8 dev eth0 src")
        with mock.patch("subprocess.run", return_value=out):
            self.assertEqual(_get_wan_ip(), "")


class TestSystemInfoArch(unittest.TestCase):
    """Архитектура должна совпадать с той, по которой ставятся сборки.

    `platform.machine()` (=`uname -m`) на MIPS отдаёт "mips" и для
    little-, и для big-endian — из-за этого «Диагностика» показывала
    `mips` там, где страницы установки правильно определяли `mipsel`.
    """

    def test_arch_matches_installer_detection(self):
        from core import system_info
        from core.ext_binary_installer import detect_arch
        info = system_info.get_system_info()
        self.assertEqual(info["arch"], detect_arch())

    def test_raw_uname_is_still_reported(self):
        import platform
        from core import system_info
        info = system_info.get_system_info()
        self.assertEqual(info["arch_uname"], platform.machine())

    def test_mips_router_reports_mipsel_not_mips(self):
        from core import system_info
        with mock.patch("core.ext_binary_installer.detect_arch",
                        return_value="mipsel"), \
             mock.patch("platform.machine", return_value="mips"):
            info = system_info.get_system_info()
        self.assertEqual(info["arch"], "mipsel")
        self.assertEqual(info["arch_uname"], "mips")

    def test_falls_back_to_uname_when_detection_fails(self):
        from core import system_info
        with mock.patch("core.ext_binary_installer.detect_arch",
                        side_effect=OSError("нет uname")), \
             mock.patch("platform.machine", return_value="armv7l"):
            info = system_info.get_system_info()
        self.assertEqual(info["arch"], "armv7l")
