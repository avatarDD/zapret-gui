# tests/test_platform_kind.py
"""
Unit-тесты для PlatformKind enum и helper'ов в core/awg_platform.py.
"""

import unittest

from core.awg_platform import (
    PlatformKind,
    AwgPlatform, KeeneticPlatform, OpenWrtPlatform, GenericLinuxPlatform,
    is_keenetic, is_openwrt, is_linux_generic, _kind_of,
)


class TestKindAssignment(unittest.TestCase):

    def test_keenetic(self):
        p = KeeneticPlatform()
        self.assertIs(p.kind, PlatformKind.KEENETIC)

    def test_openwrt(self):
        p = OpenWrtPlatform()
        self.assertIs(p.kind, PlatformKind.OPENWRT)

    def test_linux_generic(self):
        p = GenericLinuxPlatform()
        self.assertIs(p.kind, PlatformKind.LINUX)

    def test_base_unknown(self):
        self.assertIs(AwgPlatform.kind, PlatformKind.UNKNOWN)


class TestHelpers(unittest.TestCase):

    def test_is_keenetic_with_platform(self):
        self.assertTrue(is_keenetic(KeeneticPlatform()))
        self.assertFalse(is_keenetic(OpenWrtPlatform()))
        self.assertFalse(is_keenetic(GenericLinuxPlatform()))

    def test_is_keenetic_with_kind(self):
        self.assertTrue(is_keenetic(PlatformKind.KEENETIC))
        self.assertFalse(is_keenetic(PlatformKind.OPENWRT))

    def test_is_keenetic_with_string(self):
        self.assertTrue(is_keenetic("keenetic"))
        self.assertFalse(is_keenetic("openwrt"))

    def test_is_openwrt(self):
        self.assertTrue(is_openwrt(OpenWrtPlatform()))
        self.assertFalse(is_openwrt(KeeneticPlatform()))

    def test_is_linux_generic(self):
        self.assertTrue(is_linux_generic(GenericLinuxPlatform()))
        self.assertFalse(is_linux_generic(KeeneticPlatform()))

    def test_kind_of_unknown(self):
        self.assertIs(_kind_of("nonsense"), PlatformKind.UNKNOWN)
        self.assertIs(_kind_of(None), PlatformKind.UNKNOWN)


class TestAsDict(unittest.TestCase):

    def test_includes_kind(self):
        d = KeeneticPlatform().as_dict()
        self.assertEqual(d["kind"], "keenetic")

    def test_openwrt(self):
        self.assertEqual(OpenWrtPlatform().as_dict()["kind"], "openwrt")

    def test_linux(self):
        self.assertEqual(GenericLinuxPlatform().as_dict()["kind"], "linux")


if __name__ == "__main__":
    unittest.main()
