# tests/test_asset_importer_classify.py
"""Классификация list-файлов на ipset/ vs lists/ при импорте ассетов.

Регрессия (найдено прогоном winws2_*_game_filter через nfqws2 на v1.0.2):
файл `russia-youtube-rtmps.txt` — это список IP, подключается стратегией через
`--ipset=lists/russia-youtube-rtmps.txt` (резолвится в <base>/ipset/), но его
имя НЕ содержит "ipset", поэтому старая чисто-именная эвристика клала его в
<base>/lists/ → nfqws2 падал: «cannot access ipset file …/ipset/…».

Чинит content-aware классификация (_content_is_ipset): ipset, если ИМЯ говорит
об этом ИЛИ содержимое — список IP/CIDR. Суперсет: доменные списки остаются в
lists/, IP-листы с «обычными» именами уезжают в ipset/.

Плюс инвариант целостности: все list/ipset-файлы, на которые ссылаются
каталоги, реально лежат в bundled import/lists/ (ловит «забыли положить файл»
без бинарника — как пропавшие googlevideo/discord-updates/obsidian/twimg).
"""

import os
import re
import tempfile
import unittest

from core import asset_importer as ai
from core.config_manager import init_config
from core.catalog_loader import get_catalog_manager

_APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMPORT_LISTS = os.path.join(_APP, "import", "lists")


class TestContentIsIpset(unittest.TestCase):

    def _write(self, text):
        fd, p = tempfile.mkstemp(suffix=".txt")
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.unlink, p)
        return p

    def test_ipv4_list_is_ipset(self):
        p = self._write("64.233.161.134\n142.250.0.0/16\n# comment\n8.8.8.8\n")
        self.assertTrue(ai._content_is_ipset(p))

    def test_ipv6_list_is_ipset(self):
        p = self._write("2001:4860:4860::8888\n2606:4700::/32\n")
        self.assertTrue(ai._content_is_ipset(p))

    def test_domain_list_is_not_ipset(self):
        p = self._write("youtube.com\nyoutubekids.com\nggpht.com\n")
        self.assertFalse(ai._content_is_ipset(p))


class TestSyncListsSplitClassification(unittest.TestCase):
    """IP-файл с не-ipset именем уезжает в ipset/, доменный — в lists/."""

    def test_ip_file_without_ipset_name_goes_to_ipset(self):
        src = tempfile.mkdtemp()
        lists_dst = tempfile.mkdtemp()
        ipset_dst = tempfile.mkdtemp()
        for d in (src, lists_dst, ipset_dst):
            self.addCleanup(_rmtree, d)

        with open(os.path.join(src, "russia-youtube-rtmps.txt"), "w") as f:
            f.write("64.233.161.134\n64.233.162.134\n")
        with open(os.path.join(src, "youtube.txt"), "w") as f:
            f.write("youtube.com\nggpht.com\n")

        ai._sync_lists_split(src, lists_dst=lists_dst, ipset_dst=ipset_dst)

        self.assertTrue(
            os.path.isfile(os.path.join(ipset_dst, "russia-youtube-rtmps.txt")),
            "IP-список должен попасть в ipset/")
        self.assertFalse(
            os.path.isfile(os.path.join(lists_dst, "russia-youtube-rtmps.txt")),
            "IP-список НЕ должен попасть в lists/")
        self.assertTrue(
            os.path.isfile(os.path.join(lists_dst, "youtube.txt")),
            "доменный список должен попасть в lists/")


class TestCatalogListRefsBundled(unittest.TestCase):
    """Все --hostlist/--ipset=lists/<file> из каталогов лежат в import/lists/."""

    _REF = re.compile(
        r"^--(?:hostlist|hostlist-exclude|hostlist-auto|ipset|ipset-exclude)"
        r"=lists/(.+)$")

    def test_all_referenced_list_files_present(self):
        init_config()
        cache = get_catalog_manager().load_all()
        bundled = set(os.listdir(_IMPORT_LISTS))
        missing = set()
        for key in cache:
            for e in cache[key]:
                for line in e.get_args_list():
                    for tok in line.split():
                        m = self._REF.match(tok)
                        if m and m.group(1) not in bundled:
                            missing.add(m.group(1))
        self.assertEqual(sorted(missing), [],
                         "каталоги ссылаются на не-bundled list-файлы: %r"
                         % sorted(missing))


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
