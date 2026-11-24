# tests/test_netrogat_user_layer.py
"""Пользовательский слой исключений netrogat: итог = base + user.

Регрессия discussion #102: обновление GUI разворачивало bundled
netrogat.txt поверх рабочего — и вручную добавленные в «Исключения»
домены пропадали. Архитектура «netrogat.txt := netrogat.base.txt +
netrogat.user.txt» была задекларирована в заголовке base-файла (и
проверялась для БАНДЛА tests/test_netrogat_consistency.py), но в
рантайме её никто не реализовывал.

Теперь контракт действует на всех путях записи:
  * asset_importer ДО синка вытягивает ручные добавления рабочего
    netrogat.txt в netrogat.user.txt (_rescue_netrogat_user), ПОСЛЕ —
    пересобирает итог из base + user (_rebuild_netrogat_final);
  * *.user.txt из бандла никогда не затирает пользовательский слой;
  * hostlist_manager при каждой записи итога (save_hostlist и
    list_lint.fix_list — обе через _write_text) пересчитывает
    netrogat.user.txt := итог − база.
"""

import os
import shutil
import tempfile
import unittest

from core import asset_importer as ai
from core.hostlist_manager import DEFAULT_NETROGAT, get_hostlist_manager


def _write(path, lines):
    """Записать строки в файл (по одной на строку, с финальным \\n)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


class Sandbox(unittest.TestCase):
    """Конфиг в песочнице: lists_path указывает во временный каталог."""

    def setUp(self):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="netrogat-user-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.lists = os.path.join(self.dir, "lists")
        os.makedirs(self.lists)

        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        cm._config_manager.set("zapret", "lists_path", self.lists)

        # SIGHUP-перезагрузку шлёт _write_text: живого движка в тестах
        # нет, подменяем поиск PID, а не сигнал.
        import core.nfqws_reload as reload_mod

        saved_find = reload_mod.find_nfqws_pids
        self.addCleanup(setattr, reload_mod, "find_nfqws_pids", saved_find)
        reload_mod.find_nfqws_pids = lambda: []

    def _read(self, relpath, base=None):
        """Домены файла (без комментариев) или None, если файла нет."""
        path = os.path.join(base or self.lists, relpath)
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return [s for s in (ln.strip() for ln in f)
                    if s and not s.startswith("#")]


class ImporterSandbox(Sandbox):
    """Плюс подменённый bundled import/ в песочнице."""

    def setUp(self):
        super().setUp()
        self.base = tempfile.mkdtemp(prefix="netrogat-runtime-")
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        # Развёрнутые списки живут в <base>/lists — туда же кладём файлы
        # «старой установки», которую обновляет importer.
        self.lists = os.path.join(self.base, "lists")
        os.makedirs(self.lists, exist_ok=True)

        self.import_dir = os.path.join(self.dir, "import")
        for sub in ("bin", "lua", "lists"):
            os.makedirs(os.path.join(self.import_dir, sub))
        saved = {k: getattr(ai, k) for k in
                 ("IMPORT_DIR", "IMPORT_BIN_DIR", "IMPORT_LUA_DIR",
                  "IMPORT_LISTS_DIR")}
        for key, value in saved.items():
            self.addCleanup(setattr, ai, key, value)
        ai.IMPORT_DIR = self.import_dir
        ai.IMPORT_BIN_DIR = os.path.join(self.import_dir, "bin")
        ai.IMPORT_LUA_DIR = os.path.join(self.import_dir, "lua")
        ai.IMPORT_LISTS_DIR = os.path.join(self.import_dir, "lists")

    def _bundle(self, base, user=()):
        """Разложить «новый релиз» в песочный import/lists."""
        lists = ai.IMPORT_LISTS_DIR
        _write(os.path.join(lists, "netrogat.base.txt"), ["# база"] + base)
        _write(os.path.join(lists, "netrogat.txt"), list(base))
        _write(os.path.join(lists, "netrogat.user.txt"), list(user))

    def _run(self):
        return ai.import_runtime_assets(base_path=self.base)


class TestImporterRescue(ImporterSandbox):
    """Обновление GUI не теряет ручные исключения (discussion #102)."""

    def test_manual_additions_survive_update(self):
        # Рабочий роутер: старая база развёрнута, поверх — два ручных
        # домена. Приходит новый релиз с выросшей базой и ПУСТЫМ user.
        _write(os.path.join(self.lists, "netrogat.base.txt"),
               ["a.example", "b.example"])
        _write(os.path.join(self.lists, "netrogat.txt"),
               ["a.example", "b.example", "manual1.ru", "manual2.ru"])
        self._bundle(["a.example", "b.example", "c.example"])

        stats = self._run()

        self.assertEqual(stats["netrogat"]["rescued"], 2)
        self.assertEqual(
            self._read("netrogat.user.txt"), ["manual1.ru", "manual2.ru"])
        self.assertEqual(
            self._read("netrogat.txt"),
            ["a.example", "b.example", "c.example",
             "manual1.ru", "manual2.ru"])

    def test_user_file_never_clobbered_by_bundle(self):
        # Бандл кладёт ПУСТОЙ netrogat.user.txt — он не должен затирать
        # уже существующий пользовательский слой.
        _write(os.path.join(self.lists, "netrogat.base.txt"), ["a.example"])
        _write(os.path.join(self.lists, "netrogat.user.txt"), ["keep.me"])
        self._bundle(["a.example", "new.example"])

        self._run()

        self.assertEqual(self._read("netrogat.user.txt"), ["keep.me"])
        self.assertEqual(self._read("netrogat.txt"),
                         ["a.example", "new.example", "keep.me"])

    def test_rescue_without_deployed_base_falls_back_to_bundle(self):
        # Древняя установка без базы на диске: эталон — новый бандловый
        # base, ручным считается всё, чего в нём нет.
        _write(os.path.join(self.lists, "netrogat.txt"),
               ["a.example", "b.example", "manual.ru"])
        self._bundle(["a.example", "b.example"])

        stats = self._run()

        self.assertEqual(stats["netrogat"]["rescued"], 1)
        self.assertEqual(self._read("netrogat.user.txt"), ["manual.ru"])
        self.assertEqual(self._read("netrogat.txt"),
                         ["a.example", "b.example", "manual.ru"])

    def test_upstream_removal_from_base_dropped(self):
        # Запись, удалённая из базы апстримом, НЕ считается ручной:
        # право менять базу — только у обновлений (upstream wins).
        _write(os.path.join(self.lists, "netrogat.base.txt"),
               ["a.example", "b.example"])
        _write(os.path.join(self.lists, "netrogat.txt"),
               ["a.example", "b.example"])
        _write(os.path.join(self.lists, "netrogat.user.txt"), ["manual.ru"])
        self._bundle(["a.example"])

        self._run()

        self.assertEqual(self._read("netrogat.txt"),
                         ["a.example", "manual.ru"])

    def test_fresh_install_gets_bundle_lists(self):
        self._bundle(["a.example", "b.example"])

        self._run()

        self.assertEqual(self._read("netrogat.txt"),
                         ["a.example", "b.example"])
        self.assertFalse(
            os.path.isfile(os.path.join(self.lists, "netrogat.user.txt")),
            "пустой user-файл из бандла не должен попадать на роутер")

    def test_second_run_is_idempotent(self):
        _write(os.path.join(self.lists, "netrogat.base.txt"), ["a.example"])
        _write(os.path.join(self.lists, "netrogat.txt"),
               ["a.example", "manual.ru"])
        self._bundle(["a.example", "b.example"])
        self._run()
        final_path = os.path.join(self.lists, "netrogat.txt")
        mtime = os.stat(final_path).st_mtime_ns
        content = self._read("netrogat.txt")

        stats = self._run()

        self.assertEqual(stats["netrogat"]["rescued"], 0)
        self.assertFalse(stats["netrogat"]["rebuilt"])
        self.assertEqual(os.stat(final_path).st_mtime_ns, mtime,
                         "повторный импорт не должен трогать netrogat.txt")
        self.assertEqual(self._read("netrogat.txt"), content)


class TestHostlistManagerUserLayer(Sandbox):
    """Правки «Исключений» из GUI поддерживают user-слой.

    База на диске — как на роутере после установки/обновления: равна
    DEFAULT_NETROGAT (инвариант tests/test_netrogat_consistency.py).
    """

    def setUp(self):
        super().setUp()
        _write(os.path.join(self.lists, "netrogat.base.txt"),
               list(DEFAULT_NETROGAT))
        self.hm = get_hostlist_manager()

    def test_get_missing_final_creates_defaults(self):
        domains = self.hm.get_hostlist("netrogat")

        self.assertEqual(domains, list(DEFAULT_NETROGAT))
        self.assertEqual(self._read("netrogat.txt"), list(DEFAULT_NETROGAT))
        self.assertEqual(self._read("netrogat.user.txt"), [])

    def test_save_hostlist_updates_user_layer(self):
        domains = list(DEFAULT_NETROGAT) + ["manual.ru"]

        self.assertTrue(self.hm.save_hostlist("netrogat", domains))

        self.assertEqual(self._read("netrogat.txt"), domains)
        self.assertEqual(self._read("netrogat.user.txt"), ["manual.ru"])

    def test_add_domains_updates_user_layer(self):
        self.hm.save_hostlist("netrogat", DEFAULT_NETROGAT)

        added = self.hm.add_domains("netrogat", ["manual.ru", "second.ru"])

        self.assertEqual(added, 2)
        self.assertEqual(self._read("netrogat.user.txt"),
                         ["manual.ru", "second.ru"])

    def test_remove_domains_updates_user_layer(self):
        self.hm.save_hostlist(
            "netrogat", list(DEFAULT_NETROGAT) + ["manual.ru"])

        removed = self.hm.remove_domains("netrogat", ["manual.ru"])

        self.assertEqual(removed, 1)
        self.assertEqual(self._read("netrogat.user.txt"), [])

    def test_reset_to_defaults_clears_user_layer(self):
        self.hm.save_hostlist(
            "netrogat", list(DEFAULT_NETROGAT) + ["manual.ru"])

        self.assertTrue(self.hm.reset_to_defaults("netrogat"))

        self.assertEqual(self._read("netrogat.txt"), list(DEFAULT_NETROGAT))
        self.assertEqual(self._read("netrogat.user.txt"), [])

    def test_lint_fix_updates_user_layer(self):
        # fix_list пишет «как есть» через _write_text — хук user-слоя
        # обязан жить в общем писателе, а не только в save_hostlist.
        from core.list_lint import fix_list

        self.hm.save_hostlist(
            "netrogat", list(DEFAULT_NETROGAT) + ["*.wild.ru", "manual.ru"])

        result = fix_list("netrogat")

        self.assertTrue(result["ok"])
        # normalize_domain превращает «*.wild.ru» в «wild.ru».
        self.assertEqual(self._read("netrogat.user.txt"),
                         ["wild.ru", "manual.ru"])


if __name__ == "__main__":
    unittest.main()
