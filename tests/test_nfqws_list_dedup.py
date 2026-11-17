"""Повтор одного файла списка в профиле (zapret2 1.0.7).

С 1.0.7 RegisterHostlist/RegisterIpset отказывают на повторной регистрации
того же файла в списке того же типа внутри профиля, и nfqws2 завершается с
кодом 1. NFQWSManager._dedup_list_files убирает такие повторы из argv.
"""

import unittest

from core.nfqws_manager import NFQWSManager

dedup = NFQWSManager._dedup_list_files


class TestDedupListFiles(unittest.TestCase):

    def test_no_repeats_untouched(self):
        args = ["nfqws2", "--hostlist=/l/a.txt", "--hostlist=/l/b.txt",
                "--hostlist-exclude=/l/a.txt", "--ipset=/l/ip.txt",
                "--ipset-exclude=/l/ip.txt", "--lua-desync=fake"]
        # include и exclude — разные коллекции, повтором не считаются
        self.assertIs(dedup(args), args)

    def test_repeat_in_profile_dropped(self):
        args = ["--hostlist=/l/a.txt", "--hostlist-exclude=/l/n.txt",
                "--hostlist=/l/a.txt", "--hostlist-exclude=/l/n.txt",
                "--ipset=/l/ip.txt", "--ipset=/l/ip.txt"]
        self.assertEqual(dedup(args), ["--hostlist=/l/a.txt",
                                       "--hostlist-exclude=/l/n.txt",
                                       "--ipset=/l/ip.txt"])

    def test_same_path_spelled_differently(self):
        args = ["--hostlist=/l/a.txt", "--hostlist=/l/./x/../a.txt"]
        self.assertEqual(dedup(args), ["--hostlist=/l/a.txt"])

    def test_profiles_are_independent(self):
        args = ["--hostlist=/l/a.txt", "--new", "--hostlist=/l/a.txt",
                "--new=two", "--hostlist=/l/a.txt",
                "--template", "--hostlist=/l/a.txt"]
        self.assertIs(dedup(args), args)

    def test_autolist_wins_over_plain_include(self):
        # оба — include-коллекция; автолист свой файл и так читает
        for args in (["--hostlist=/l/auto.txt", "--hostlist-auto=/l/auto.txt"],
                     ["--hostlist-auto=/l/auto.txt", "--hostlist=/l/auto.txt"]):
            self.assertEqual(dedup(args), ["--hostlist-auto=/l/auto.txt"])

    def test_inline_lists_untouched(self):
        args = ["--hostlist-domains=a.com", "--hostlist-domains=a.com",
                "--ipset-ip=1.2.3.4", "--ipset-ip=1.2.3.4"]
        self.assertIs(dedup(args), args)


if __name__ == "__main__":
    unittest.main()
