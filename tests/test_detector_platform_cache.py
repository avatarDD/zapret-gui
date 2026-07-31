# tests/test_detector_platform_cache.py
"""
Кэш детекта платформы (core/awg_detector).

Причина появления: на Keenetic `_is_keenetic()` пробует `ndmc --help`,
а `detect_keenos_version()` — `ndmc -c "show version"`. Оба вызывались
на КАЖДЫЙ `is_ndms_available()`, а тот сидит на горячих путях (опрос
статуса интерфейсов, wg_discovery, доменные правила). Каждый запуск
ndmc — сессия на /var/run/ndm.core.socket, и системный лог роутера
заполнялся парами «Core::Server: started Session … / Core::Session:
client disconnected» каждые несколько секунд.

Платформа и версия прошивки в пределах процесса не меняются, поэтому
детект кэшируется; `force=True` переспрашивает.
"""

import unittest
from unittest import mock

from core.awg_detector import AwgDetector
from core.awg_platform import PlatformKind


class TestPlatformCache(unittest.TestCase):

    def _keenetic_detector(self):
        """Детектор, который «видит» Keenetic только через ndmc-пробу."""
        det = AwgDetector()
        # /proc/version без «keenetic» — как на реальных KeenOS-сборках,
        # где решает именно ndmc-проба.
        patches = [
            mock.patch("core.awg_detector._read_file", return_value="Linux 4.9-ndm"),
            mock.patch("core.awg_detector.os.path.exists", return_value=True),
            mock.patch("core.awg_detector._cmd_ok", return_value=True),
            mock.patch("core.awg_detector._cmd_out", return_value="title: 5.0.3"),
        ]
        return det, patches

    def test_platform_detected_once(self):
        det, patches = self._keenetic_detector()
        with patches[0], patches[1], patches[2] as m_ok, patches[3] as m_out:
            first = det.detect_platform()
            for _ in range(20):
                det.detect_platform()
            self.assertEqual(first.kind, PlatformKind.KEENETIC)
            # ndmc --help — ровно один раз на все 21 вызов
            self.assertEqual(m_ok.call_count, 1)
            # ndmc -c "show version" — тоже один раз
            self.assertEqual(m_out.call_count, 1)

    def test_same_instance_returned(self):
        det, patches = self._keenetic_detector()
        with patches[0], patches[1], patches[2], patches[3]:
            self.assertIs(det.detect_platform(), det.detect_platform())

    def test_force_reprobes(self):
        det, patches = self._keenetic_detector()
        with patches[0], patches[1], patches[2] as m_ok, patches[3]:
            det.detect_platform()
            det.detect_platform(force=True)
            self.assertEqual(m_ok.call_count, 2)

    def test_version_cached_separately(self):
        det, patches = self._keenetic_detector()
        with patches[0], patches[1], patches[2], patches[3] as m_out:
            self.assertEqual(det.detect_keenos_version(), "5.0.3")
            det.detect_keenos_version()
            self.assertEqual(m_out.call_count, 1)

    def test_non_keenetic_does_not_probe_version(self):
        """На не-Keenetic ndmc не трогаем вовсе."""
        det = AwgDetector()
        with mock.patch("core.awg_detector._read_file", return_value="Linux"), \
             mock.patch("core.awg_detector.os.path.exists", return_value=False), \
             mock.patch("core.awg_detector._cmd_ok") as m_ok, \
             mock.patch("core.awg_detector._cmd_out") as m_out:
            plat = det.detect_platform()
            self.assertEqual(plat.kind, PlatformKind.LINUX)
            self.assertEqual(m_ok.call_count, 0)
            self.assertEqual(m_out.call_count, 0)

    def test_environment_report_force_reprobes_platform(self):
        det, patches = self._keenetic_detector()
        with patches[0], patches[1], patches[2] as m_ok, patches[3], \
             mock.patch.object(det, "_build_report", return_value={"ok": True}):
            det.get_environment_report()
            det.get_environment_report()
            self.assertEqual(m_ok.call_count, 0)   # отчёт замокан
            det.detect_platform()
            self.assertEqual(m_ok.call_count, 1)
            det.get_environment_report(force=True)
            self.assertEqual(m_ok.call_count, 2)


class TestWgDiscoveryCacheOrder(unittest.TestCase):
    """Свежий кэш интерфейсов отдаётся без probe доступности NDMS."""

    def setUp(self):
        from core.ndms import wg_discovery
        wg_discovery.invalidate_cache()

    tearDown = setUp

    def test_second_call_skips_availability_probe(self):
        from core.ndms import wg_discovery
        with mock.patch("core.ndms.is_ndms_available",
                        return_value=True) as m_avail, \
             mock.patch("core.ndms.get_ndms_commands") as m_cmd:
            m_cmd.return_value.list_wireguard_interfaces.return_value = [
                {"name": "Wireguard0"}]
            wg_discovery.list_native_wg_interfaces()
            wg_discovery.list_native_wg_interfaces()
            wg_discovery.list_native_wg_interfaces()
            self.assertEqual(m_avail.call_count, 1)
            self.assertEqual(
                m_cmd.return_value.list_wireguard_interfaces.call_count, 1)


if __name__ == "__main__":
    unittest.main()
