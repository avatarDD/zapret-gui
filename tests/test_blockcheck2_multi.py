"""Мульти-доменный blockcheck2 (core/blockcheck2_multi)."""

import os
import shutil
import stat
import tempfile
import time
import unittest
from unittest import mock

from core import blockcheck2_multi as bm
from tests.test_blockcheck2_patch import FRAGMENT


class TestPure(unittest.TestCase):

    def test_split_domains(self):
        self.assertEqual(
            bm.split_domains("rutracker.org\r\nhttps://YouTube.com/watch\n\n"
                             "a.b, a.b ; bad host!"),
            ["rutracker.org", "youtube.com", "a.b", "bad"])
        self.assertEqual(bm.split_domains(["x.com", "x.com"]), ["x.com"])

    def test_group_by_ips(self):
        doms = ["a.com", "b.com", "c.com", "d.com"]
        ips = {"a.com": {"1.1.1.1"}, "b.com": {"2.2.2.2"},
               "c.com": {"2.2.2.2", "3.3.3.3"}, "d.com": set()}
        self.assertEqual(bm.group_by_ips(doms, ips),
                         [["a.com"], ["b.com", "c.com"], ["d.com"]])


LOG = """\
* script : standard/20-multi.sh
- curl_test_https_tls12 ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=2
[attempt 1] AVAILABLE
[attempt 2] AVAILABLE
[attempt 3] AVAILABLE
!!!!! AVAILABLE !!!!!
!!!!! curl_test_https_tls12: working strategy found for ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=2 !!!!!
* zapret-gui: ok 1/3 curl_test_https_tls12 ipv4 a.com
- curl_test_https_tls12 ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=1
[attempt 1] AVAILABLE
[attempt 2] UNAVAILABLE code=28
[attempt 3] AVAILABLE
UNAVAILABLE code=28
- curl_test_https_tls12 ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=midsld
[attempt 1] UNAVAILABLE code=28
[attempt 2] UNAVAILABLE code=28
[attempt 3] UNAVAILABLE code=28
UNAVAILABLE code=28

* zapret-gui: curl_test_https_tls12 ipv4 a.com : набрано 3 рабочих стратегий из 3 — остальные варианты этого теста пропущены
!!!!! curl_test_https_tls12: working strategy found for ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=2 !!!!!
* SUMMARY
curl_test_https_tls12 ipv4 a.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=2
"""


class TestLineParser(unittest.TestCase):

    def test_blocks(self):
        p = bm.LineParser()
        for line in LOG.splitlines():
            p.feed(line)
        p.close()
        self.assertEqual([(f["ok"], f["total"], f["full"]) for f in p.found],
                         [(3, 3, True), (2, 3, False)])
        self.assertEqual(p.found[0]["label"], "TLS1.2")
        t = p.tests[("curl_test_https_tls12", 4, "a.com")]
        self.assertEqual(t, {"tried": 3, "skipped": True})

    def test_simulate_success_line(self):
        # SIMULATE=1: вердикт «SUCCESS», без попыток — успех по строке
        # «working strategy found» сразу после.
        p = bm.LineParser()
        for line in [
            "- curl_test_http ipv4 a.com : nfqws2 --payload=http_req --lua-desync=fake",
            "SUCCESS",
            "!!!!! curl_test_http: working strategy found for ipv4 a.com : nfqws2 --payload=http_req --lua-desync=fake !!!!!",
        ]:
            p.feed(line)
        self.assertEqual(len(p.found), 1)
        self.assertTrue(p.found[0]["full"])


# Поддельный blockcheck2.sh: настоящие якоря правок + главный цикл,
# который гоняет три «стратегии» на домен через пропатченный
# pktws_curl_test. Первые две успешны, третья — нет; при
# GUI_STOP_AFTER=2 третья не должна даже проверяться.
FAKE_MAIN = r'''
strategy_append_extra_pktws() { :; }
report_append() { :; }
ws_curl_test()
{
	echo "start $3" >>"$TRACE"
	sleep 1
	echo "end $3" >>"$TRACE"
	case "$4 $5" in
		*pos=3*) echo "[attempt 1] UNAVAILABLE code=28"; echo "UNAVAILABLE code=28"; return 28 ;;
	esac
	echo "[attempt 1] AVAILABLE"
	echo "!!!!! AVAILABLE !!!!!"
	return 0
}
IPV=4; PKTWSD=nfqws2
for dom in $DOMAINS; do
	for pos in 1 2 3; do
		pktws_curl_test curl_test_https_tls13 $dom --payload=tls_client_hello --lua-desync=multisplit:pos=$pos
	done
done
exit 0
'''


@unittest.skipUnless(shutil.which("sh"), "нет sh")
class TestRunnerEndToEnd(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bc2m-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.script = os.path.join(self.tmp, "blockcheck2.sh")
        with open(self.script, "w") as f:
            f.write(FRAGMENT + FAKE_MAIN)
        os.chmod(self.script, os.stat(self.script).st_mode | stat.S_IEXEC)
        self.trace = os.path.join(self.tmp, "trace")
        os.environ["TRACE"] = self.trace
        self.addCleanup(os.environ.pop, "TRACE", None)
        for target, value in (
            ("core.blockcheck2.Blockcheck2Runner.find_script",
             staticmethod(lambda: self.script)),
            ("core.blockcheck2_multi._clone_dir", lambda: self.tmp),
            ("core.blockcheck2_multi.resolve_ips",
             lambda d, timeout=3.0: {"10.0.0.%d" % len(d)}),
        ):
            p = mock.patch(target, value)
            p.start()
            self.addCleanup(p.stop)

    def _run(self, **kw):
        r = bm.Blockcheck2MultiRunner()
        res = r.start(pause_bypass=False, **kw)
        self.assertTrue(res["ok"], res)
        deadline = time.time() + 30
        while r.is_running() and time.time() < deadline:
            time.sleep(0.1)
        self.assertFalse(r.is_running())
        return r

    def _trace(self):
        with open(self.trace) as f:
            return [l.split()[0] for l in f.read().split("\n") if l]

    def test_parallel_and_stop_after(self):
        r = self._run(domains="a.com\r\nbb.com", concurrency=2, stop_after=2,
                      params={"REPEATS": "1"})
        st = r.get_status()
        self.assertEqual([j["state"] for j in st["jobs"]], ["done", "done"])
        # Две копии шли одновременно: обе стартовали до первого финиша.
        self.assertEqual(self._trace()[:2], ["start", "start"])
        # По 2 рабочих на домен, третий вариант не проверялся вовсе.
        self.assertEqual(len(self._trace()), 8)
        full = [(f["domain"], f["strategy"]) for f in st["found"] if f["full"]]
        self.assertEqual(sorted(full), sorted([
            ("a.com", "--payload=tls_client_hello --lua-desync=multisplit:pos=1"),
            ("a.com", "--payload=tls_client_hello --lua-desync=multisplit:pos=2"),
            ("bb.com", "--payload=tls_client_hello --lua-desync=multisplit:pos=1"),
            ("bb.com", "--payload=tls_client_hello --lua-desync=multisplit:pos=2"),
        ]))
        out = r.get_output("bb.com")
        self.assertTrue(any("пропущены" in l for l in out["lines"]))

    def test_sequential(self):
        self._run(domains="a.com bb.com", concurrency=1, stop_after=0)
        self.assertEqual(self._trace()[:4], ["start", "end", "start", "end"])

    def test_validation(self):
        r = bm.Blockcheck2MultiRunner()
        self.assertFalse(r.start(domains="")["ok"])
        self.assertFalse(r.start(domains="a.com", params={"DOMAINS": "x"})["ok"])
        self.assertFalse(r.start(domains="a.com", scanlevel="deep")["ok"])
        many = " ".join("d%d.com" % i for i in range(bm.MAX_DOMAINS + 1))
        self.assertFalse(r.start(domains=many)["ok"])


if __name__ == "__main__":
    unittest.main()
