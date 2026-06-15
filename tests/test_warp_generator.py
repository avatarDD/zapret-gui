# tests/test_warp_generator.py
"""
Unit-тесты для core/warp_generator.py — генерации параметров обфускации.

Главное, что проверяем: сгенерированный WARP-конфиг СОВМЕСТИМ с
ванильным WireGuard-пиром Cloudflare. Серверы WARP не понимают
AmneziaWG-обфускацию заголовков/паддинга, поэтому:
  * S1 = S2 = 0  (паддинг внутри handshake ломает разбор у Cloudflare);
  * H1..H4 = 1,2,3,4  (нестандартный тип сообщения → handshake не проходит);
  * junk-пакеты (Jc/Jmin/Jmax) — единственная обфускация, которую
    ванильный WireGuard игнорирует, поэтому они включены.

Регрессия: раньше генератор ставил случайные H1..H4 (5..0x7FFFFFFF) и
S1/S2 (15..100), из-за чего «чистый WARP»-конфиг вообще не поднимал
туннель против настоящего Cloudflare.
"""

import unittest

from core.warp_generator import generate_obfuscation_params, build_config


class TestWarpObfuscationParams(unittest.TestCase):

    def test_headers_are_standard(self):
        for _ in range(50):
            obf = generate_obfuscation_params()
            self.assertEqual(obf["H1"], 1)
            self.assertEqual(obf["H2"], 2)
            self.assertEqual(obf["H3"], 3)
            self.assertEqual(obf["H4"], 4)

    def test_no_handshake_padding(self):
        for _ in range(50):
            obf = generate_obfuscation_params()
            self.assertEqual(obf["S1"], 0)
            self.assertEqual(obf["S2"], 0)

    def test_junk_enabled_and_positive(self):
        # Jc/Jmin/Jmax обязаны быть положительными — amneziawg-go отвергает 0.
        for _ in range(50):
            obf = generate_obfuscation_params()
            self.assertGreaterEqual(obf["Jc"], 4)
            self.assertLessEqual(obf["Jc"], 12)
            self.assertGreater(obf["Jmin"], 0)
            self.assertGreater(obf["Jmax"], 0)
            self.assertLessEqual(obf["Jmin"], obf["Jmax"])

    def test_build_config_carries_warp_compatible_obfuscation(self):
        account = {"config": {
            "interface": {"addresses": {"v4": "172.16.0.2",
                                        "v6": "2606:4700:110::2"}},
            "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                       "endpoint": {"v4": "162.159.192.1:2408"}}],
        }}
        priv = "qK4xn2cV7g7H4ICm3w4f5G9k2vRl0pZ8H8Y0OqWQS3w="
        cfg = build_config(account, priv)
        iface = cfg["interface"]
        self.assertEqual([iface["H1"], iface["H2"], iface["H3"], iface["H4"]],
                         [1, 2, 3, 4])
        self.assertEqual(iface["S1"], 0)
        self.assertEqual(iface["S2"], 0)
        self.assertGreaterEqual(iface["Jc"], 4)


if __name__ == "__main__":
    unittest.main()
