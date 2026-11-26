# tests/test_mcp_device_connections.py
"""MCP-инструмент device_connections: склейка «устройство → соединения».

Просьба discussion #491 — «почему не работает на том или ином
устройстве» одним вызовом. Все источники (таблица устройств, conntrack,
карта DNS-имён) замоканы: тест проверяет агрегат и подсказки, а не
содержимое /proc.

Формы строк conntrack взяты из tests/test_geneva_auto_observer.py —
реальные, с заменёнными на документационные адресами.
"""

import unittest
from unittest import mock

from core import device_traffic
from core.mcp import registry

# Настоящий читатель — песочница ниже мокает его целиком, а потолок
# надо проверять на живой функции (патчуя только список путей).
REAL_CONNTRACK_LINES = device_traffic.conntrack_lines

LAN = "192.168.1.10"
WAN = "81.200.10.5"
WAN2 = "93.184.216.7"

DEVICES = [
    {"ip": LAN, "mac": "aa:bb:cc:00:00:01", "hostname": "pixel-7",
     "source": "leases+arp", "expires_at": 0, "iface": "br0"},
    {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02", "hostname": "nas",
     "source": "arp", "expires_at": 0, "iface": "br0"},
    # офлайн-хост из NDM: имени нет адреса — соединений быть не может.
    {"ip": "", "mac": "aa:bb:cc:00:00:03", "hostname": "old-tablet",
     "source": "ndm", "expires_at": 0, "iface": ""},
]


def tcp(dst, dport=443, state="ESTABLISHED", unreplied=False, src=LAN):
    unr = " [UNREPLIED]" if unreplied else ""
    return ("ipv4     2 tcp      6 299 %s src=%s dst=%s sport=50432 "
            "dport=%d packets=23 bytes=2779 src=%s dst=%s sport=%d "
            "dport=50432 packets=30 bytes=285130 [ASSURED] mark=0 "
            "zone=0 use=2%s"
            % (state, src, dst, dport, dst, WAN, dport, unr))


def udp(dst, dport=3478, src=LAN):
    return ("ipv4     2 udp      17 25 src=%s dst=%s sport=40000 "
            "dport=%d packets=2 bytes=200 src=%s dst=%s sport=%d "
            "dport=40000 packets=2 bytes=180 [ASSURED] mark=0 zone=0 "
            "use=2" % (src, dst, dport, dst, WAN, dport))


def call(name, args=None):
    """Вызов инструмента с правами только на чтение."""
    return registry.call(name, args or {}, {})["structuredContent"]


class DeviceSandbox(unittest.TestCase):

    def setUp(self):
        registry.load_tools()
        p1 = mock.patch.object(device_traffic, "conntrack_lines",
                                return_value=([], False))
        p1.start()
        self.addCleanup(p1.stop)
        p2 = mock.patch("core.devices_discovery.list_devices",
                        return_value=list(DEVICES))
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch("core.block_detector.ip_names",
                        return_value={WAN2: "cdn.youtube.com"})
        p3.start()
        self.addCleanup(p3.stop)

    def _lines(self, *lines):
        self._set_lines(list(lines))

    def _set_lines(self, lines):
        patcher = mock.patch.object(device_traffic, "conntrack_lines",
                                    return_value=(lines, False))
        patcher.start()
        self.addCleanup(patcher.stop)


class TestDeviceConnections(DeviceSandbox):

    def test_by_ip_full_chain(self):
        # Два соединения на один адрес+порт склеяются, домен берётся
        # из карты DNS-детектора, сортировка — по байтам.
        self._lines(
            tcp(WAN2, 443), tcp(WAN2, 443), tcp(WAN, 443, "SYN_SENT"),
            udp(WAN, 3478),
            # чужое устройство — не должно попасть в ответ
            tcp(WAN, 443, src="192.168.1.20"),
        )

        payload = call("device_connections", {"device": LAN})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["device"]["hostname"], "pixel-7")
        self.assertEqual(payload["total"], 3)
        items = payload["items"]
        labels = [i["label"] for i in items]
        self.assertEqual(labels[0], "cdn.youtube.com")
        self.assertIn(WAN, labels)
        top = items[0]
        self.assertEqual(top["count"], 2)
        self.assertEqual(top["bytes_out"], 5558)
        self.assertTrue(top["domain"])
        syn = [i for i in items if i["state"] == "SYN_SENT"]
        self.assertTrue(syn and syn[0]["syn_sent"])
        self.assertIn("не отвечает", "; ".join(payload["hints"]))
        # Зонд ведём по мёртвой цели, не по самому объёмному.
        self.assertIn("probe_compare", payload["next"][0])
        self.assertIn(WAN, payload["next"][0])
        self.assertIn("SNI", payload["next"][0])
        self.assertIn("traffic_capture_start host=%s port=443" % WAN,
                      payload["next"][1])

    def test_by_name_substring(self):
        self._lines(tcp(WAN, 443))

        payload = call("device_connections", {"device": "PIXEL"})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["device"]["ip"], LAN)

    def test_unknown_device_lists_candidates(self):
        self._lines(tcp(WAN, 443))

        payload = call("device_connections", {"device": "macbook"})

        self.assertFalse(payload["ok"])
        self.assertIn("не найдено", payload["error"])
        # Кандидаты — с адресами: следующий запрос может быть точным.
        self.assertTrue(any("nas" in c for c in payload["candidates"]))
        self.assertTrue(any("192.168.1.20" in c
                            for c in payload["candidates"]))

    def test_ambiguous_name_lists_matches(self):
        # Два устройства с одинаковым именем — отдаём оба С ИХ IP:
        # следующий вызов должен иметь шанс быть точным.
        patcher = mock.patch(
            "core.devices_discovery.list_devices",
            return_value=[DEVICES[0],
                          {"ip": "192.168.1.30", "mac": "aa:bb:cc:00:00:09",
                           "hostname": "pixel-7-old", "source": "arp"}])
        patcher.start()
        self.addCleanup(patcher.stop)

        payload = call("device_connections", {"device": "pixel"})

        self.assertFalse(payload["ok"])
        self.assertIn("неоднозначно", payload["error"])
        self.assertEqual(len(payload["matches"]), 2)
        self.assertIn(LAN, payload["matches"][0])
        self.assertIn("192.168.1.30", payload["matches"][1])

    def test_offline_device_says_no_ip(self):
        payload = call("device_connections", {"device": "old-tablet"})

        self.assertFalse(payload["ok"])
        self.assertIn("не в сети", payload["error"])

    def test_conntrack_missing_reports_reason(self):
        patcher = mock.patch.object(device_traffic, "conntrack_lines",
                                    return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

        payload = call("device_connections", {"device": "pixel"})

        self.assertTrue(payload["ok"])   # устройство-то найдено
        self.assertFalse(payload["sources"]["conntrack"]["available"])
        self.assertEqual(payload["total"], 0)
        self.assertIn("nf_conntrack", payload["reason"])

    def test_pagination_truncated(self):
        self._lines(*[tcp(WAN, 443 + n) for n in range(5)])

        payload = call("device_connections",
                      {"device": LAN, "limit": 2, "offset": 1})

        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["total"], 5)
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["next_offset"], 3)

    def test_empty_query_is_a_client_error(self):
        payload = call("device_connections", {"device": "  "})

        self.assertFalse(payload["ok"])
        self.assertIn("укажите устройство", payload["error"])

    def test_names_source_unavailable_does_not_break_the_list(self):
        p = mock.patch("core.block_detector.ip_names",
                       side_effect=RuntimeError("dns map died"))
        p.start()
        self.addCleanup(p.stop)
        self._lines(tcp(WAN2, 443))

        payload = call("device_connections", {"device": LAN})

        self.assertTrue(payload["ok"])
        self.assertFalse(payload["sources"]["names"]["available"])
        # Адрес остался читаемым даже без домена
        self.assertEqual(payload["items"][0]["label"], WAN2)

    def test_line_without_counters_still_counts_zero(self):
        # Форма Keenetic без packets=/bytes= (счётчики отключены):
        # агрегат не падает, вместо None — нули.
        raw = ("ipv4     2 tcp      6 118 SYN_SENT src=%s dst=%s "
               "sport=61022 dport=443 [UNREPLIED] src=%s dst=%s "
               "sport=443 dport=61022 mark=0 use=2"
               % (LAN, WAN, WAN, WAN))
        self._lines(raw)

        payload = call("device_connections", {"device": LAN})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["total"], 1)
        row = payload["items"][0]
        self.assertEqual(row["bytes_out"], 0)
        self.assertEqual(row["packets_in"], 0)
        self.assertTrue(row["unreplied"])


class TestDeviceConnectionsLimits(DeviceSandbox):
    """Потолок чтения conntrack: на роутере строк — десятки тысяч."""

    def test_table_is_cut_at_max_lines(self):
        patcher = mock.patch.object(
            device_traffic, "conntrack_lines",
            return_value=(["garbage"] * 5, True))
        patcher.start()
        self.addCleanup(patcher.stop)

        payload = call("device_connections", {"device": LAN})

        self.assertTrue(payload["sources"]["conntrack"]["truncated"])

    def test_reader_ceiling_and_missing_file(self):
        # Поведенческий потолок читателя: настоящий файл на диске
        # длиннее лимита обрезается, несуществующий — None. Песочница
        # мокает conntrack_lines целиком — зовем НАСТОЯЩУЮ функцию,
        # патчуя только список путей.
        import os
        import tempfile

        sample = ("ipv4 2 tcp 6 1 ESTABLISHED src=%s dst=%s sport=1 "
                  "dport=443 packets=1 bytes=10 src=%s dst=%s sport=443 "
                  "dport=1 packets=1 bytes=10 mark=0 use=2\n"
                  % (LAN, WAN, WAN, WAN))
        fd, path = tempfile.mkstemp(suffix=".ct")
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write(sample * (device_traffic.MAX_LINES + 5))

        real = REAL_CONNTRACK_LINES
        with mock.patch.object(device_traffic, "_CONNTRACK_FILES",
                               (path,)):
            lines, truncated = real()
        self.assertEqual(len(lines), device_traffic.MAX_LINES)
        self.assertTrue(truncated)

        with mock.patch.object(device_traffic, "_CONNTRACK_FILES",
                               ("/nonexistent/conntrack",)):
            self.assertIsNone(real())


if __name__ == "__main__":
    unittest.main()
