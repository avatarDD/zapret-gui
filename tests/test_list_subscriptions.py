"""Подписки хостлистов и ipset-файлов nfqws2 на URL
(core/list_subscriptions.py): автообновление с сохранением ручных правок."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from core import list_subscriptions as ls


class FakeManager:
    """Менеджер списков на временном каталоге."""

    def __init__(self, root, kind):
        self.root = root
        self.kind = kind
        self.saved = []

    def _file_path(self, name):
        return os.path.join(self.root, name + ".txt")

    def _validate_name(self, name):
        return bool(name)

    def normalize_domain(self, text):
        t = text.strip().lower()
        return t if "." in t and " " not in t else None

    def _read(self, name):
        try:
            with open(self._file_path(name)) as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    def _write(self, name, items):
        with open(self._file_path(name), "w") as f:
            f.write("\n".join(items) + "\n")
        self.saved.append((name, list(items)))
        return True

    get_hostlist = get_ipset = _read
    save_hostlist = save_ipset = _write


class Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = {}
        self.mgr = {"hostlist": FakeManager(self.tmp, "hostlist"),
                    "ipset": FakeManager(self.tmp, "ipset")}
        patches = [
            mock.patch.object(ls, "_load", side_effect=lambda: dict(self.store)),
            mock.patch.object(ls, "_save",
                              side_effect=lambda s: self.store.clear()
                              or self.store.update(s)),
            mock.patch.object(ls, "_manager",
                              side_effect=lambda k: self.mgr[k]),
            mock.patch("core.list_updater.is_safe_url", return_value=True),
            mock.patch("core.list_updater.get_transport", return_value=""),
            mock.patch("core.list_updater.get_list_refresher"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.remote = "a.com\nb.com\n"
        p = mock.patch("core.list_updater._fetch",
                       side_effect=lambda url, transport="": self.remote)
        p.start()
        self.addCleanup(p.stop)

    def write(self, name, items):
        with open(os.path.join(self.tmp, name + ".txt"), "w") as f:
            f.write("\n".join(items) + "\n")

    def read(self, name):
        return self.mgr["hostlist"]._read(name)


class TestSubscription(Base):

    def test_subscribe_refreshes_and_keeps_manual_entries(self):
        self.write("my", ["manual.org"])
        res = ls.subscribe("hostlist", "my", "https://x/list.txt", 12)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["refresh"]["ok"])
        self.assertEqual(self.read("my"), ["a.com", "b.com", "manual.org"])
        # Источник убрал b.com и добавил c.com: ручная запись осталась.
        self.remote = "a.com\nc.com\n"
        self.assertTrue(ls.refresh("hostlist", "my")["ok"])
        self.assertEqual(self.read("my"), ["a.com", "c.com", "manual.org"])
        sub = ls.get("hostlist", "my")
        self.assertEqual(sub["last_status"], "ok")
        self.assertEqual(sub["interval_hours"], 12)

    def test_empty_answer_preserves_file(self):
        self.write("my", ["keep.org"])
        ls.subscribe("hostlist", "my", "https://x", refresh_now=False)
        self.remote = "# пусто\n"
        res = ls.refresh("hostlist", "my")
        self.assertFalse(res["ok"])
        self.assertTrue(res["preserved"])
        self.assertEqual(self.read("my"), ["keep.org"])
        self.assertEqual(ls.get("hostlist", "my")["last_status"], "empty")

    def test_fetch_error_is_recorded(self):
        self.write("my", ["keep.org"])
        ls.subscribe("hostlist", "my", "https://x", refresh_now=False)
        with mock.patch("core.list_updater._fetch",
                        side_effect=RuntimeError("HTTP 404")):
            res = ls.refresh("hostlist", "my")
        self.assertEqual(res["error"], "HTTP 404")
        self.assertEqual(ls.get("hostlist", "my")["last_error"], "HTTP 404")

    def test_unchanged_answer_does_not_rewrite(self):
        self.write("my", [])
        ls.subscribe("hostlist", "my", "https://x")
        n = len(self.mgr["hostlist"].saved)
        self.assertFalse(ls.refresh("hostlist", "my")["changed"])
        self.assertEqual(len(self.mgr["hostlist"].saved), n)

    def test_ipset_entries_are_validated(self):
        self.write("ipset-x", [])
        self.remote = "10.0.0.1/8\n1.2.3.4\nnot-an-ip\n"
        ls.subscribe("ipset", "ipset-x", "https://x")
        self.assertEqual(self.mgr["ipset"]._read("ipset-x"),
                         ["10.0.0.0/8", "1.2.3.4"])

    def test_missing_list_drops_subscription(self):
        self.write("gone", [])
        ls.subscribe("hostlist", "gone", "https://x", refresh_now=False)
        os.remove(os.path.join(self.tmp, "gone.txt"))
        res = ls.refresh("hostlist", "gone")
        self.assertFalse(res["ok"])
        self.assertEqual(ls.get("hostlist", "gone"), {})

    def test_rename_moves_subscription_and_snapshot(self):
        self.write("old", [])
        ls.subscribe("hostlist", "old", "https://x")
        os.rename(os.path.join(self.tmp, "old.txt"),
                  os.path.join(self.tmp, "new.txt"))
        ls.rename("hostlist", "old", "new")
        self.assertEqual(ls.get("hostlist", "new")["url"], "https://x")
        self.assertTrue(os.path.exists(os.path.join(self.tmp, ".new.remote")))

    def test_tick_respects_interval(self):
        self.write("my", [])
        ls.subscribe("hostlist", "my", "https://x", 6, refresh_now=False)
        with mock.patch.object(ls, "refresh") as refresh:
            self.assertEqual(ls.tick(now=10 ** 9), 1)
            self.store["hostlist:my"]["last_refresh"] = 10 ** 9
            self.assertEqual(ls.tick(now=10 ** 9 + 3600), 0)
            self.assertEqual(ls.tick(now=10 ** 9 + 6 * 3600), 1)
        self.assertEqual(refresh.call_count, 2)

    def test_unsafe_url_refused(self):
        self.write("my", [])
        with mock.patch("core.list_updater.is_safe_url", return_value=False):
            self.assertFalse(ls.subscribe("hostlist", "my",
                                          "file:///etc/passwd")["ok"])


class TestPure(unittest.TestCase):

    def test_merge(self):
        self.assertEqual(ls.merge(["a", "m"], ["a", "b"], ["a"]),
                         ["a", "b", "m"])


if __name__ == "__main__":
    unittest.main()
