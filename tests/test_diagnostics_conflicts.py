# tests/test_diagnostics_conflicts.py
"""Тесты детекции конфликтов окружения (core/diagnostics.evaluate_conflicts)."""

import unittest

from core.diagnostics import evaluate_conflicts, _KNOWN_TOOL_MARKERS


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


if __name__ == "__main__":
    unittest.main()
