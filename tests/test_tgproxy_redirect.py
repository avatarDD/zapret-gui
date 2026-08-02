"""Тесты заворачивания трафика Telegram на порт резервного движка.

tg-mtproxy-client — прозрачный форвардер: он читает адрес назначения
через SO_ORIGINAL_DST и получает соединения ТОЛЬКО от правил REDIRECT.
Раньше их не ставил никто, и движок не получал ни одного соединения.
"""

import unittest
from unittest import mock

from core import tgproxy_redirect as tr


class _RunRecorder:
    """Подмена _run: пишет argv и всегда отвечает успехом."""

    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on or ()

    def __call__(self, args, timeout=15):
        self.calls.append(list(args))
        for marker in self.fail_on:
            if marker in args:
                return 1, "", "boom"
        return 0, "", ""

    def joined(self):
        return [" ".join(c) for c in self.calls]


class TestIptablesBackend(unittest.TestCase):

    def _apply(self, port=1443, cidrs=("149.154.160.0/20", "91.108.4.0/22")):
        rec = _RunRecorder()
        with mock.patch.object(tr, "_backend", return_value="iptables"), \
             mock.patch.object(tr, "_run", rec):
            res = tr.apply(port, list(cidrs))
        return res, rec

    def test_rules_target_the_engine_port(self):
        res, rec = self._apply(port=1443)
        self.assertTrue(res["ok"], res.get("error"))
        joined = rec.joined()
        self.assertIn("iptables -t nat -A %s -p tcp -d 149.154.160.0/20 "
                      "-j REDIRECT --to-ports 1443" % tr.CHAIN, joined)
        self.assertIn("iptables -t nat -A %s -p tcp -d 91.108.4.0/22 "
                      "-j REDIRECT --to-ports 1443" % tr.CHAIN, joined)

    def test_hooks_cover_both_forwarded_and_local_traffic(self):
        """PREROUTING — трафик LAN-клиентов, OUTPUT — самого роутера.

        Без одного из них половина трафика идёт мимо движка.
        """
        _res, rec = self._apply()
        joined = rec.joined()
        self.assertIn("iptables -t nat -I PREROUTING -j %s" % tr.CHAIN, joined)
        self.assertIn("iptables -t nat -I OUTPUT -j %s" % tr.CHAIN, joined)

    def test_apply_is_idempotent_and_cleans_before_adding(self):
        """Повторный запуск не должен копить дубли правил."""
        _res, rec = self._apply()
        joined = rec.joined()
        first_add = next(i for i, c in enumerate(joined) if " -A %s " % tr.CHAIN in c)
        flush = next(i for i, c in enumerate(joined) if c.endswith("-F %s" % tr.CHAIN))
        self.assertLess(flush, first_add)

    def test_failed_rule_rolls_back(self):
        """Половина правил хуже, чем ни одного: трафик пойдёт вразнобой."""
        rec = _RunRecorder(fail_on=("REDIRECT",))
        with mock.patch.object(tr, "_backend", return_value="iptables"), \
             mock.patch.object(tr, "_run", rec):
            res = tr.apply(1443, ["149.154.160.0/20"])
        self.assertFalse(res["ok"])
        self.assertTrue(any("-X %s" % tr.CHAIN in c for c in rec.joined()))

    def test_remove_detaches_from_both_hooks(self):
        rec = _RunRecorder(fail_on=("-D",))
        with mock.patch.object(tr, "_backend", return_value="iptables"), \
             mock.patch.object(tr, "_run", rec):
            res = tr.remove()
        self.assertTrue(res["ok"])
        joined = rec.joined()
        self.assertTrue(any("-D PREROUTING" in c for c in joined))
        self.assertTrue(any("-D OUTPUT" in c for c in joined))


class TestNftBackend(unittest.TestCase):

    def test_ruleset_has_both_hooks_and_the_port(self):
        captured = {}

        def fake_run(args, input=None, capture_output=None, text=None,
                     timeout=None):
            captured["ruleset"] = input
            return mock.Mock(returncode=0, stderr="")

        with mock.patch.object(tr, "_backend", return_value="nftables"), \
             mock.patch.object(tr, "_run", _RunRecorder()), \
             mock.patch("core.tgproxy_redirect.subprocess.run",
                        side_effect=fake_run):
            res = tr.apply(1443, ["149.154.160.0/20"])

        self.assertTrue(res["ok"], res.get("error"))
        rules = captured["ruleset"]
        self.assertIn("table ip %s" % tr.NFT_TABLE, rules)
        self.assertIn("hook prerouting", rules)
        self.assertIn("hook output", rules)
        self.assertIn("redirect to :1443", rules)
        self.assertIn("149.154.160.0/20", rules)

    def test_nft_error_is_reported_not_swallowed(self):
        with mock.patch.object(tr, "_backend", return_value="nftables"), \
             mock.patch.object(tr, "_run", _RunRecorder()), \
             mock.patch("core.tgproxy_redirect.subprocess.run",
                        return_value=mock.Mock(returncode=1,
                                               stderr="syntax error")):
            res = tr.apply(1443, ["149.154.160.0/20"])
        self.assertFalse(res["ok"])
        self.assertIn("syntax error", res["error"])


class TestGuards(unittest.TestCase):

    def test_rejects_bad_port(self):
        for port in (0, 70000, "abc"):
            self.assertFalse(tr.apply(port, ["149.154.160.0/20"])["ok"], port)

    def test_rejects_garbage_cidrs(self):
        """CIDR уходят в argv iptables — мусор туда попасть не должен."""
        with mock.patch.object(tr, "_backend", return_value="iptables"), \
             mock.patch.object(tr, "_run", _RunRecorder()):
            res = tr.apply(1443, ["; rm -rf /", "not-a-cidr", "2001:db8::/32"])
        self.assertFalse(res["ok"])
        self.assertIn("CIDR", res["error"])

    def test_uses_project_cidr_list_by_default(self):
        from core.tgproxy_manager import TELEGRAM_DC_CIDRS
        rec = _RunRecorder()
        with mock.patch.object(tr, "_backend", return_value="iptables"), \
             mock.patch.object(tr, "_run", rec):
            res = tr.apply(1443)
        self.assertTrue(res["ok"])
        self.assertEqual(res["rules"], len(TELEGRAM_DC_CIDRS))

    def test_no_backend_is_a_clear_error_not_a_silent_success(self):
        with mock.patch.object(tr, "_backend", return_value=""):
            res = tr.apply(1443, ["149.154.160.0/20"])
        self.assertFalse(res["ok"])
        self.assertIn("iptables", res["error"])

    def test_remove_without_backend_is_a_noop_not_a_failure(self):
        with mock.patch.object(tr, "_backend", return_value=""):
            res = tr.remove()
        self.assertTrue(res["ok"])



class TestMutuallyExclusiveWithTunnelRouting(unittest.TestCase):
    """REDIRECT и «Telegram DC через туннель» нельзя включать вместе.

    REDIRECT срабатывает в nat раньше, чем принимается решение о
    маршруте: пакет уходит на локальный порт и до туннеля не доезжает.
    Молча включённые оба выглядят как «настроил туннель, а он не
    используется».
    """

    def test_tunnel_routing_refused_while_redirect_is_active(self):
        from core import tgproxy_manager as tm
        with mock.patch("core.tgproxy_redirect.status",
                        return_value={"ok": True, "backend": "nftables",
                                      "active": True}):
            res = tm.route_telegram_dc_via_tunnel("warp", "opkgtun0")
        self.assertFalse(res["ok"])
        self.assertIn("резервный движок", res["error"])

    def test_tunnel_routing_allowed_when_redirect_is_off(self):
        from core import tgproxy_manager as tm
        with mock.patch("core.tgproxy_redirect.status",
                        return_value={"ok": True, "backend": "nftables",
                                      "active": False}), \
             mock.patch("core.unified.manager.save_route",
                        return_value={"ok": True}) as save:
            res = tm.route_telegram_dc_via_tunnel("warp", "opkgtun0")
        self.assertTrue(res["ok"])
        save.assert_called_once()

if __name__ == "__main__":
    unittest.main()
