# tests/test_network_env.py
"""
Unit-тесты детекта сетевого окружения (core/network_env): роутер с LAN
или обычный ПК / VPS с одной сетевой картой (локальный режим, задача №5).

Sysfs/procfs подменяются через обёртки модуля (_listdir/_isdir/_exists/
_route_lines) — проверяем чистую логику без рута.
"""

import unittest
from unittest import mock

from core import network_env as net


def _fake_fs(physical=(), bridges=None, virtual=(), wireless=()):
    """
    Сымитировать sysfs: physical — NIC с device-симлинком, bridges —
    {имя: [члены]}, virtual — остальная виртуалка (veth/tun/wg…).
    Возвращает (listdir, isdir, exists) для подмены обёрток модуля.
    """
    bridges = dict(bridges or {})
    names = list(physical) + list(bridges) + list(virtual) + ["lo"]

    def listdir(path):
        if path == net.SYS_NET:
            return sorted(names)
        if path.startswith(net.SYS_NET) and path.endswith("/brif"):
            br = path.split("/")[-2]
            return sorted(bridges.get(br, []))
        return []

    def isdir(path):
        name = path.rstrip("/").split("/")[-1]
        if path.endswith("/bridge"):
            return path.split("/")[-2] in bridges
        if path.startswith(net.SYS_VIRTUAL):
            # мосты тоже виртуальные, но в list_interfaces проверка
            # bridge идёт раньше — здесь это не важно
            return name in bridges or name in virtual
        if path.endswith("/wireless"):
            return path.split("/")[-2] in wireless
        return False

    def exists(path):
        if path.endswith("/device"):
            return path.split("/")[-2] in physical
        return False    # платформенные файлы → generic linux

    return listdir, isdir, exists


class _EnvCase(unittest.TestCase):
    """База: подменённые обёртки + чистый кэш + override=auto."""

    def detect(self, *, physical=(), bridges=None, virtual=(), wireless=(),
               platform=None, override="auto"):
        listdir, isdir, exists = _fake_fs(
            physical=physical, bridges=bridges,
            virtual=virtual, wireless=wireless)
        patches = [
            mock.patch.object(net, "_listdir", listdir),
            mock.patch.object(net, "_isdir", isdir),
            mock.patch.object(net, "_exists", exists),
            mock.patch.object(net, "_route_lines", lambda: []),
            mock.patch.object(net, "_profile_override", lambda: override),
        ]
        if platform is not None:
            patches.append(
                mock.patch.object(net, "_platform_kind", lambda: platform))
        net.reset_cache()
        try:
            for p in patches:
                p.start()
            return net.detect(force=True)
        finally:
            for p in patches:
                p.stop()
            net.reset_cache()


class TestInterfaceClassification(_EnvCase):

    def test_lo_excluded_and_types_split(self):
        listdir, isdir, exists = _fake_fs(
            physical=["eth0", "wlan0"], bridges={"br0": ["eth0"]},
            virtual=["awg0", "veth1"], wireless=["wlan0"])
        with mock.patch.object(net, "_listdir", listdir), \
             mock.patch.object(net, "_isdir", isdir), \
             mock.patch.object(net, "_exists", exists):
            r = net.list_interfaces()
        self.assertEqual(r["physical"], ["eth0", "wlan0"])
        self.assertEqual(r["bridges"], ["br0"])
        self.assertEqual(sorted(r["virtual"]), ["awg0", "veth1"])
        self.assertEqual(r["wireless"], ["wlan0"])
        for group in r.values():
            self.assertNotIn("lo", group)


class TestProfileAuto(_EnvCase):

    def test_pc_single_nic(self):
        r = self.detect(physical=["eth0"])
        self.assertEqual(r["profile"], "pc")
        self.assertEqual(r["profile_auto"], "pc")
        self.assertTrue(r["single_nic"])
        self.assertEqual(r["profile_source"], "auto")

    def test_pc_desktop_with_wifi_not_single(self):
        # Две физические NIC (ethernet + wifi) — всё ещё ПК, но не 1 NIC.
        r = self.detect(physical=["eth0", "wlan0"], wireless=["wlan0"])
        self.assertEqual(r["profile"], "pc")
        self.assertFalse(r["single_nic"])

    def test_docker_bridge_does_not_make_router(self):
        # docker0/virbr0 состоят из veth — это контейнеры на ПК, не LAN.
        r = self.detect(physical=["eth0"],
                        bridges={"docker0": ["veth0a"]}, virtual=["veth0a"])
        self.assertEqual(r["profile"], "pc")
        self.assertEqual(r["lan_bridges"], [])

    def test_handmade_linux_router_by_lan_bridge(self):
        # generic Linux, но LAN-мост с физическим членом — роутер.
        r = self.detect(physical=["eth0", "eth1"],
                        bridges={"br0": ["eth1"]})
        self.assertEqual(r["profile"], "router")
        self.assertEqual(r["lan_bridges"], ["br0"])

    def test_router_platforms_always_router(self):
        for plat in ("keenetic", "openwrt", "entware"):
            r = self.detect(physical=["eth0"], platform=plat)
            self.assertEqual(r["profile"], "router", plat)
            self.assertEqual(r["platform"], plat)

    def test_tunnels_do_not_affect_profile(self):
        # Поднятые awg/tun/wg — виртуальные, профиль не меняют.
        r = self.detect(physical=["eth0"],
                        virtual=["awg0", "singbox-tun", "wg0"])
        self.assertEqual(r["profile"], "pc")
        self.assertTrue(r["single_nic"])


class TestProfileOverride(_EnvCase):

    def test_override_router_on_pc(self):
        r = self.detect(physical=["eth0"], override="router")
        self.assertEqual(r["profile"], "router")
        self.assertEqual(r["profile_auto"], "pc")
        self.assertEqual(r["profile_source"], "override")

    def test_override_pc_on_router_platform(self):
        r = self.detect(physical=["eth0"], platform="keenetic",
                        override="pc")
        self.assertEqual(r["profile"], "pc")
        self.assertEqual(r["profile_auto"], "router")

    def test_override_read_fresh_after_cache(self):
        # Скан железа кэшируется, а override читается каждый раз — смена
        # network.profile в настройках действует без перезапуска.
        listdir, isdir, exists = _fake_fs(physical=["eth0"])
        with mock.patch.object(net, "_listdir", listdir), \
             mock.patch.object(net, "_isdir", isdir), \
             mock.patch.object(net, "_exists", exists), \
             mock.patch.object(net, "_route_lines", lambda: []):
            net.reset_cache()
            with mock.patch.object(net, "_profile_override", lambda: "auto"):
                self.assertEqual(net.detect()["profile"], "pc")
            with mock.patch.object(net, "_profile_override",
                                   lambda: "router"):
                self.assertEqual(net.detect()["profile"], "router")
            net.reset_cache()

    def test_invalid_override_falls_back_to_auto(self):
        fake_cfg = mock.Mock()
        fake_cfg.get.return_value = "weird"
        with mock.patch("core.config_manager.get_config_manager",
                        return_value=fake_cfg):
            self.assertEqual(net._profile_override(), "auto")


class TestDefaultIface(unittest.TestCase):

    def test_parses_proc_net_route(self):
        lines = [
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n",
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
            "eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n",
        ]
        with mock.patch.object(net, "_route_lines", lambda: lines):
            self.assertEqual(net._default_iface(), "eth0")

    def test_no_default_route(self):
        with mock.patch.object(net, "_route_lines", lambda: []):
            self.assertEqual(net._default_iface(), "")


class TestCache(_EnvCase):

    def test_hardware_scan_cached_until_force(self):
        calls = {"n": 0}
        listdir0, isdir, exists = _fake_fs(physical=["eth0"])

        def listdir(path):
            if path == net.SYS_NET:
                calls["n"] += 1
            return listdir0(path)

        with mock.patch.object(net, "_listdir", listdir), \
             mock.patch.object(net, "_isdir", isdir), \
             mock.patch.object(net, "_exists", exists), \
             mock.patch.object(net, "_route_lines", lambda: []), \
             mock.patch.object(net, "_profile_override", lambda: "auto"):
            net.reset_cache()
            net.detect()
            net.detect()
            self.assertEqual(calls["n"], 1)      # второй раз — из кэша
            net.detect(force=True)
            self.assertEqual(calls["n"], 2)      # force → пересканировали
            net.reset_cache()
            net.detect()
            self.assertEqual(calls["n"], 3)      # reset_cache → тоже
            net.reset_cache()

    def test_is_pc_profile_helper(self):
        r = self.detect(physical=["eth0"])
        self.assertEqual(r["profile"], "pc")
        listdir, isdir, exists = _fake_fs(physical=["eth0"])
        with mock.patch.object(net, "_listdir", listdir), \
             mock.patch.object(net, "_isdir", isdir), \
             mock.patch.object(net, "_exists", exists), \
             mock.patch.object(net, "_route_lines", lambda: []), \
             mock.patch.object(net, "_profile_override", lambda: "auto"):
            net.reset_cache()
            self.assertTrue(net.is_pc_profile())
            net.reset_cache()


if __name__ == "__main__":
    unittest.main()
