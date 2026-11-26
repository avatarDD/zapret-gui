# tests/test_installer_cross_fs.py
"""
Установка бинарника через границу файловых систем.

Регрессия: install_binary при разных ФС падал на обновлении ЗАПУЩЕННОГО
бинарника. os.replace возвращал EXDEV, дальше шёл shutil.move → copy+unlink,
то есть открытие целевого пути на запись, и ядро отдавало ETXTBSY
(«Text file busy»).

Сценарий реальный: на Keenetic /tmp — tmpfs в ОЗУ, /opt — флешка, а
workbase() выбирает рабочий каталог по свободному месту, поэтому src и
dest вполне могут оказаться на разных ФС; обновляемый sing-box/mihomo/usque
в этот момент обычно работает.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from core.binary_installer import install_binary


def _other_fs_dir():
    """Каталог на ФС, отличной от /tmp (иначе тест бессмысленен)."""
    for base in ("/dev/shm", "/run/shm"):
        if not os.path.isdir(base) or not os.access(base, os.W_OK):
            continue
        try:
            d = tempfile.mkdtemp(prefix="zg-src-", dir=base)
        except OSError:
            continue
        return d
    return ""


class TestCrossFsInstall(unittest.TestCase):

    def setUp(self):
        self.dest_dir = tempfile.mkdtemp(prefix="zg-dest-")
        self.src_dir = _other_fs_dir()
        self.proc = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)
        shutil.rmtree(self.dest_dir, ignore_errors=True)
        if self.src_dir:
            shutil.rmtree(self.src_dir, ignore_errors=True)

    def test_replaces_running_binary_across_filesystems(self):
        if not self.src_dir:
            self.skipTest("нет второй ФС для проверки cross-device пути")

        dest = os.path.join(self.dest_dir, "engine")
        # Жертва — копия Питона: настоящий ELF, которому всё равно, как
        # его переименовали. Копия /bin/sleep на dev-боксах с multicall
        # coreutils («unknown program») мгновенно умирает под чужим
        # именем, и тест падал на ровном месте.
        shutil.copy2(sys.executable, dest)
        os.chmod(dest, 0o755)

        # Держим бинарник запущенным — именно это и давало ETXTBSY.
        self.proc = subprocess.Popen(
            [dest, "-c", "import time; time.sleep(30)"])
        time.sleep(0.3)
        self.assertIsNone(self.proc.poll(), "процесс-жертва не запустился")

        src = os.path.join(self.src_dir, "engine-new")
        # Содержимое нового бинарника install_binary не разбирает —
        # только копирует, поэтому генерируем заглушку сами и не
        # зависим от /bin/true, которого в системе может не быть.
        with open(src, "wb") as f:
            f.write(b"stub-not-executed-" + os.urandom(32))
        new_size = os.path.getsize(src)
        if os.stat(src).st_dev == os.stat(dest).st_dev:
            self.skipTest("src и dest оказались на одной ФС")

        res = install_binary(src, dest, backup_old=True)

        self.assertTrue(res.get("ok"), res)
        self.assertEqual(os.path.getsize(dest), new_size,
                         "бинарник не заменён")
        self.assertTrue(os.access(dest, os.X_OK), "потерян бит +x")
        self.assertTrue(os.path.isfile(dest + ".bak"), "нет бэкапа старого")
        # Замена через rename не трогает inode работающего процесса.
        self.assertIsNone(self.proc.poll(), "запущенный процесс умер")
        # Промежуточный файл не должен оставаться в каталоге назначения.
        leftovers = [f for f in os.listdir(self.dest_dir) if ".new-" in f]
        self.assertEqual(leftovers, [], "остался временный файл")


if __name__ == "__main__":
    unittest.main()
