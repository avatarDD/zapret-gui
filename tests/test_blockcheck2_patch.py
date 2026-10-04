"""Клон blockcheck2.sh с правками GUI (core/blockcheck2_patch)."""

import os
import shutil
import subprocess
import unittest

from core.blockcheck2_patch import MARK, PATCH_NAMES, PatchError, patch_script


# Фрагменты blockcheck2.sh zapret2 v1.0.5.2 — ровно те места, к которым
# привязаны правки (функции дословно, с табами).
FRAGMENT = '''#!/bin/sh

EXEDIR="$(dirname "$0")"

pktws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws/dvtws params
	local testf=$1 dom="$2" strategy code

	shift; shift;
	echo - $testf ipv$IPV $dom : $PKTWSD $@
	ws_curl_test pktws_start $testf "$dom" "$@"

	code=$?
	[ "$code" = 0 ] && {
		strategy="$@"
		strategy_append_extra_pktws
		report_append "$dom" "$testf ipv${IPV}" "$PKTWSD ${WF:+$WF }$strategy"
	}
	return $code
}

configure_ip_version()
{
	if [ "$IPV" = 6 ]; then
		LOCALHOST=::1
	else
		IPTABLES=iptables
		LOCALHOST=127.0.0.1
	fi
	IPTABLES=ip${IPVV}tables
}
'''


class TestPatch(unittest.TestCase):

    def test_all_patches_applied(self):
        out = patch_script(FRAGMENT, "/opt/zapret2/blockcheck2.sh")
        self.assertTrue(out.startswith("#!/bin/sh\n" + MARK))
        self.assertIn('gui_enough "$testf" "$dom" && return 1', out)
        self.assertIn('gui_found "$testf" "$dom" "$strategy"', out)
        self.assertIn('IPTABLES="$IPTABLES -w"', out)
        # Хелперы — до pktws_curl_test, лимит — первым делом в функции.
        self.assertLess(out.index("gui_enough()"),
                        out.index("pktws_curl_test()\n{"))
        body = out[out.index("pktws_curl_test()\n{"):]
        self.assertLess(body.index("gui_enough"), body.index("shift; shift"))
        self.assertEqual(set(PATCH_NAMES),
                         {"helpers", "stop_after", "found_mark", "ipt_wait"})

    def test_idempotent(self):
        once = patch_script(FRAGMENT)
        self.assertEqual(patch_script(once), once)

    def test_missing_anchor_refuses(self):
        broken = FRAGMENT.replace('[ "$code" = 0 ] && {', 'if [ "$code" = 0 ]; then')
        with self.assertRaises(PatchError) as cm:
            patch_script(broken)
        self.assertEqual(cm.exception.missing, ["found_mark"])
        self.assertIn("found_mark", str(cm.exception))

    @unittest.skipUnless(shutil.which("sh"), "нет sh")
    def test_shell_syntax_and_limit_logic(self):
        out = patch_script(FRAGMENT)
        r = subprocess.run(["sh", "-n", "-c", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Логика лимита: 2 рабочих → третий и дальше пропускаются, с
        # одной строкой-объяснением; другой тест не затронут.
        helpers = out[out.index("# zapret-gui: ── правки"):
                      out.index("# zapret-gui: ── конец правок ──")]
        script = helpers + '''
IPV=4; PKTWSD=nfqws2; GUI_STOP_AFTER=2
for i in 1 2 3 4; do
  gui_enough curl_test_https_tls12 a.example && { echo skip; continue; }
  gui_found curl_test_https_tls12 a.example "--lua-desync=fake:x$i"
done
gui_enough curl_test_https_tls13 a.example || echo free
'''
        r = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        lines = r.stdout.split("\n")
        self.assertEqual(sum("working strategy found" in l for l in lines), 2)
        self.assertEqual(lines.count("skip"), 2)
        self.assertEqual(sum("пропущены" in l for l in lines), 1)
        self.assertIn("free", lines)

    def test_real_script_if_present(self):
        path = os.environ.get("ZAPRET2_BLOCKCHECK2")
        if not path or not os.path.isfile(path):
            self.skipTest("ZAPRET2_BLOCKCHECK2 не задан")
        with open(path, encoding="utf-8") as f:
            out = patch_script(f.read(), path)
        self.assertEqual(out.count(MARK) >= 6, True)


if __name__ == "__main__":
    unittest.main()
