# tests/test_opera_proxy.py
"""
Тесты Opera Proxy: менеджер, watchdog, API.

Гоняем НАСТОЯЩИЙ жизненный цикл процесса против заглушки, которая
повторяет CLI opera-proxy (`-version`, `-list-countries`,
`-bind-address`, …) и считает свои запуски. Так ловятся вещи, которые
не видны в моках:

  * detect() больше не дёргает `-list-countries` — а это сетевая
    регистрация устройства в API SurfEasy, и страница GUI вызывала её
    каждые 3 секунды опросом статуса;
  * проба watchdog'а понимает IPv6 (`[::1]:18080`) — раньше на таком
    bind она всегда возвращала False и watchdog вечно перезапускал
    исправный прокси;
  * вывод процесса, упавшего на старте, попадает в буфер «Лог»;
  * негодные настройки отбиваются на входе, а не превращаются в
    usage-дамп Go-бинарника при следующем запуске.
"""

import os
import shutil
import socket
import stat
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core import opera_proxy_manager as opm
from core import opera_proxy_watchdog as opw


STUB_SRC = textwrap.dedent(
    '''\
    #!@PYTHON@
    """
    Заглушка opera-proxy: тот же CLI и, главное, тот же способ работы —
    HTTP-прокси с методом CONNECT. Поднимается настоящим менеджером,
    так что через неё можно реально прогнать трафик и проверить, что
    проксирование не ломается о наши пайпы и сигналы.
    """
    import argparse
    import os
    import signal
    import socket
    import sys
    import threading
    import time

    with open(os.environ["OPERA_STUB_CALLS"], "a") as f:
        f.write(" ".join(sys.argv[1:]) + "\\n")

    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-version", action="store_true")
    p.add_argument("-list-countries", action="store_true",
                   dest="list_countries")
    p.add_argument("-country", default="EU")
    p.add_argument("-bind-address", default="127.0.0.1:18080", dest="bind")
    p.add_argument("-socks-mode", action="store_true", dest="socks")
    p.add_argument("-proxy-bypass", default="", dest="bypass")
    p.add_argument("-fake-SNI", default="", dest="sni")
    p.add_argument("-verbosity", type=int, default=20)
    args, unknown = p.parse_known_args()
    if unknown:
        sys.stderr.write("unknown flags: %r\\n" % (unknown,))
        sys.exit(2)

    if args.version:
        print("v1.28.0")
        sys.exit(0)

    if args.list_countries:
        if os.environ.get("OPERA_STUB_COUNTRIES_FAIL"):
            sys.stderr.write("api error: registration failed\\n")
            sys.exit(12)
        print("country code,country name")
        print("EU,Europe")
        print("AS,Asia")
        print("AM,America")
        sys.exit(0)

    host, port = args.bind.rsplit(":", 1)
    host = host.strip("[]")
    info = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)[0]
    srv = socket.socket(info[0], socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(info[4])
    except OSError as e:
        sys.stderr.write("bind failed: %s\\n" % e)
        sys.exit(1)
    srv.listen(8)

    _run = [True]

    def _term(_s, _f):
        _run[0] = False
        try:
            srv.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, _term)

    # Логируем как Go-шный log.Printf в настоящем opera-proxy: прямая
    # запись в fd 1 под общим мьютексом, без буферизации Python. Именно
    # поэтому переполненный пайп там останавливает и форвардинг:
    # обработчик соединения встаёт на write() вместе с логгером.
    LOG_LOCK = threading.Lock()

    def logline(text):
        with LOG_LOCK:
            os.write(1, (text + "\\n").encode("utf-8", "replace"))

    logline("INFO listening on %s country=%s socks=%s sni=%s bypass=%s"
            % (args.bind, args.country, args.socks, args.sni, args.bypass))

    def chatter():
        """verbosity=10 у настоящего бинарника — строка на событие."""
        n = 0
        while _run[0] and args.verbosity <= 10:
            for _ in range(200):
                n += 1
                logline("CHATTER %d %s" % (n, "x" * 200))
            time.sleep(0.02)

    threading.Thread(target=chatter, daemon=True).start()

    def pump(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                if args.verbosity <= 10:
                    logline("DEBUG relay %d bytes" % len(chunk))
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(conn):
        """Минимальный HTTP CONNECT-прокси."""
        try:
            head = b""
            while b"\\r\\n\\r\\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            request = head.split(b"\\r\\n", 1)[0].decode("latin-1")
            method, target = (request.split(" ") + ["", ""])[:2]
            if method != "CONNECT":
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\\r\\n\\r\\n")
                return
            thost, _, tport = target.rpartition(":")
            logline("CONNECT %s" % target)
            upstream = socket.create_connection((thost, int(tport)), timeout=5)
            conn.sendall(b"HTTP/1.1 200 Connection established\\r\\n\\r\\n")
            threading.Thread(target=pump, args=(conn, upstream),
                             daemon=True).start()
            pump(upstream, conn)
        except Exception as e:
            logline("ERROR %s" % e)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while _run[0]:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    ''')

STUB = STUB_SRC.replace("@PYTHON@", sys.executable)


def free_port(family=socket.AF_INET, host="127.0.0.1"):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def has_ipv6_loopback() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class _OperaBase(unittest.TestCase):
    """Изолированный конфиг + заглушка вместо opera-proxy."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="opera-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.calls_path = os.path.join(self.tmp, "calls.log")
        os.environ["OPERA_STUB_CALLS"] = self.calls_path
        self.addCleanup(os.environ.pop, "OPERA_STUB_CALLS", None)

        self.binary = os.path.join(self.tmp, "opera-proxy")
        with open(self.binary, "w") as f:
            f.write(STUB)
        os.chmod(self.binary, os.stat(self.binary).st_mode | stat.S_IEXEC)

        self._saved_cm = cm_mod._config_manager
        cm_mod._config_manager = cm_mod.ConfigManager(config_dir=self.tmp)
        cm_mod._config_manager.load()
        self.cfg = cm_mod._config_manager
        self.addCleanup(setattr, cm_mod, "_config_manager", self._saved_cm)

        self.mgr = opm.OperaProxyManager()
        self.mgr._find_binary = lambda: self.binary
        self.addCleanup(self.mgr.stop)

    def calls(self) -> list:
        try:
            with open(self.calls_path) as f:
                return [line.strip() for line in f if line.strip()]
        except OSError:
            return []

    def probe(self, port: int, host: str = "127.0.0.1") -> bool:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except OSError:
            return False


class TestParseBind(unittest.TestCase):

    def test_ipv4(self):
        self.assertEqual(opm.parse_bind("127.0.0.1:18080"),
                         ("127.0.0.1", 18080))

    def test_hostname(self):
        self.assertEqual(opm.parse_bind(" localhost:8080 "),
                         ("localhost", 8080))

    def test_ipv6_bracketed(self):
        self.assertEqual(opm.parse_bind("[::1]:18080"), ("::1", 18080))
        self.assertEqual(opm.parse_bind("[::]:18080"), ("::", 18080))

    def test_rejects_garbage(self):
        for bad in ("", "  ", "18080", "не-адрес", "127.0.0.1:",
                    "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:port",
                    "::1:18080", "[::1]18080", "[]:18080", ":18080"):
            with self.assertRaises(ValueError, msg=bad):
                opm.parse_bind(bad)


class TestValidateSettings(unittest.TestCase):

    def test_normalizes(self):
        clean = opm.validate_settings({
            "country": " eu ", "bind": " 127.0.0.1:18080 ",
            "socks_mode": "true", "verbosity": "10",
            "fake_sni": " www.google.com ", "proxy_bypass": " *.local ",
        })
        self.assertEqual(clean["country"], "EU")
        self.assertEqual(clean["bind"], "127.0.0.1:18080")
        self.assertIs(clean["socks_mode"], True)
        self.assertEqual(clean["verbosity"], 10)
        self.assertEqual(clean["fake_sni"], "www.google.com")
        self.assertEqual(clean["proxy_bypass"], "*.local")

    def test_proxy_bypass_spaces_cleaned(self):
        clean = opm.validate_settings({"proxy_bypass": "a.com, b.com ,*.local"})
        self.assertEqual(clean["proxy_bypass"], "a.com,b.com,*.local")

    def test_ipv6_bind_normalized_back_to_brackets(self):
        self.assertEqual(opm.validate_settings({"bind": "[::1]:18080"})["bind"],
                         "[::1]:18080")

    def test_partial_update_keeps_only_given_keys(self):
        self.assertEqual(list(opm.validate_settings({"country": "AM"})),
                         ["country"])

    def test_rejects(self):
        cases = [
            {"bind": "не-адрес"},
            {"bind": "127.0.0.1:99999"},
            {"country": ""},
            {"country": "EU/../etc"},
            {"verbosity": "abc"},
            {"verbosity": 999},
            {"fake_sni": "плохой домен"},
            {"proxy_bypass": "a b.com,c.com"},
            {"socks_mode": "может быть"},
        ]
        for case in cases:
            with self.assertRaises(ValueError, msg=repr(case)):
                opm.validate_settings(case)


class TestDetect(_OperaBase):

    def test_detect_does_not_hit_surfeasy_api(self):
        """
        detect() зовётся из опроса статуса GUI, selfcheck и update-checker.
        `-list-countries` — регистрация устройства в API: её там быть
        не должно.
        """
        d = self.mgr.detect()
        self.assertTrue(d["installed"])
        self.assertEqual(d["version"], "v1.28.0")
        self.assertEqual(d["countries"], [])
        self.assertEqual([c for c in self.calls() if "list-countries" in c], [])

    def test_version_is_cached(self):
        for _ in range(5):
            self.mgr.detect()
        self.assertEqual(len([c for c in self.calls() if "-version" in c]), 1)

    def test_version_cache_invalidated_on_reinstall(self):
        self.mgr.detect()
        time.sleep(0.01)
        with open(self.binary, "a") as f:      # «переустановили» бинарник
            f.write("\n# rebuilt\n")
        os.utime(self.binary, (time.time() + 5, time.time() + 5))
        self.mgr.detect()
        self.assertEqual(len([c for c in self.calls() if "-version" in c]), 2)

    def test_not_installed(self):
        self.mgr._find_binary = lambda: ""
        d = self.mgr.detect()
        self.assertFalse(d["installed"])
        self.assertEqual(d["countries"], [])

    def test_list_countries_refresh_then_cache(self):
        r = self.mgr.list_countries(refresh=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual([c["code"] for c in r["countries"]],
                         ["EU", "AS", "AM"])
        self.assertFalse(r["cached"])

        # Повторный запрос в пределах анти-дребезга — из кэша, без API.
        r2 = self.mgr.list_countries(refresh=True)
        self.assertTrue(r2["cached"])
        self.assertEqual(len([c for c in self.calls()
                              if "list-countries" in c]), 1)

        # detect() теперь отдаёт закэшированный список.
        self.assertEqual(len(self.mgr.detect()["countries"]), 3)

    def test_list_countries_reports_error(self):
        os.environ["OPERA_STUB_COUNTRIES_FAIL"] = "1"
        self.addCleanup(os.environ.pop, "OPERA_STUB_COUNTRIES_FAIL", None)
        r = self.mgr.list_countries(refresh=True)
        self.assertFalse(r["ok"])
        self.assertIn("registration failed", r["error"])
        self.assertEqual(r["countries"], [])


class TestLifecycle(_OperaBase):

    def test_start_status_stop(self):
        port = free_port()
        bind = "127.0.0.1:%d" % port
        self.cfg.set("opera_proxy", "bind", bind)

        r = self.mgr.start(bind=bind, country="AS", verbosity=30)
        self.assertTrue(r["ok"], r)
        self.assertTrue(self.probe(port))

        st = self.mgr.status()
        self.assertTrue(st["running"])
        self.assertEqual(st["bind"], bind)
        self.assertIs(st["listening"], True)
        self.assertEqual(st["pid"], r["pid"])

        # Аргументы дошли до бинарника ровно те, что просили.
        launch = [c for c in self.calls() if "-bind-address" in c][-1]
        self.assertIn("-country AS", launch)
        self.assertIn("-verbosity 30", launch)
        self.assertNotIn("-socks-mode", launch)

        self.assertTrue(self.mgr.stop()["ok"])
        self.assertFalse(self.mgr.status()["running"])
        self.assertFalse(self.probe(port))

    def test_second_start_refused(self):
        port = free_port()
        self.assertTrue(self.mgr.start(bind="127.0.0.1:%d" % port)["ok"])
        again = self.mgr.start(bind="127.0.0.1:%d" % port)
        self.assertFalse(again["ok"])
        self.assertIn("уже запущен", again["error"])

    def test_optional_flags_passed(self):
        port = free_port()
        self.mgr.start(bind="127.0.0.1:%d" % port, socks_mode=True,
                       fake_sni="www.google.com", proxy_bypass="*.local")
        launch = [c for c in self.calls() if "-bind-address" in c][-1]
        self.assertIn("-socks-mode", launch)
        self.assertIn("-fake-SNI www.google.com", launch)
        self.assertIn("-proxy-bypass *.local", launch)

    def test_failed_start_output_lands_in_log(self):
        """
        Порт занят → «Лог» должен показать причину, а не хвост прошлого,
        удачного запуска.
        """
        port = free_port()
        squat = socket.socket()
        squat.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squat.bind(("127.0.0.1", port))
        squat.listen(1)
        self.addCleanup(squat.close)

        r = self.mgr.start(bind="127.0.0.1:%d" % port)
        self.assertFalse(r["ok"])
        self.assertIn("Address already in use", r["error"])

        log_text = self.mgr.read_log()["log"]
        self.assertIn("Address already in use", log_text)
        self.assertIn("-bind-address 127.0.0.1:%d" % port, log_text)
        self.assertFalse(self.mgr.status()["running"])

    def test_start_rejects_broken_config(self):
        """Мусор из старого settings.json не должен доезжать до Popen."""
        r = self.mgr.start(bind="не-адрес")
        self.assertFalse(r["ok"])
        self.assertIn("bind", r["error"].lower())
        self.assertEqual([c for c in self.calls() if "-bind-address" in c], [])

    def test_survives_gui_restart(self):
        """Новый объект менеджера видит процесс по pid-файлу и гасит его."""
        port = free_port()
        started = self.mgr.start(bind="127.0.0.1:%d" % port)
        self.assertTrue(started["ok"])

        fresh = opm.OperaProxyManager()
        fresh._find_binary = lambda: self.binary
        st = fresh.status()
        self.assertTrue(st["running"])
        self.assertEqual(st["pid"], started["pid"])

        fresh.stop()
        for _ in range(30):
            if not self.probe(port):
                break
            time.sleep(0.1)
        self.assertFalse(self.probe(port))
        self.assertFalse(self.mgr.status()["running"])

    def test_foreign_pid_not_treated_as_ours(self):
        import subprocess
        p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.mgr._write_pid(p.pid)
        self.assertFalse(self.mgr._is_running())

    def test_chatty_process_does_not_block_on_pipe(self):
        """
        Дренаж stdout: без него OS-буфер пайпа (~64 КБ) переполняется,
        opera-proxy блокируется на write() и перестаёт форвардить трафик.
        Заглушка при verbosity=10 сыплет ~1 МБ — процесс обязан остаться
        живым и продолжать принимать соединения.
        """
        port = free_port()
        self.assertTrue(
            self.mgr.start(bind="127.0.0.1:%d" % port, verbosity=10)["ok"])
        proc = self.mgr._process

        deadline = time.time() + 10
        while time.time() < deadline and self.mgr.read_log()["captured"] < 50:
            time.sleep(0.1)

        self.assertIsNone(proc.poll(), "процесс умер под болтливым логом")
        self.assertTrue(self.probe(port), "прокси перестал принимать соединения")
        tail = self.mgr.read_log()
        self.assertGreater(tail["captured"], 0)
        self.assertIn("CHATTER", tail["log"])


class TestProxying(_OperaBase):
    """
    Сквозная проверка проксирования: поднимаем прокси менеджером и
    реально гоняем через него байты методом CONNECT.
    """

    def _echo_server(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        self.addCleanup(srv.close)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        conn.sendall(data)
                except OSError:
                    pass
                finally:
                    conn.close()

        import threading as _th
        t = _th.Thread(target=serve, daemon=True)
        t.start()
        return srv.getsockname()[1]

    def _through_proxy(self, proxy_port, target_port, payload):
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n"
                  % target_port)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            self.assertTrue(chunk, "прокси закрыл соединение на CONNECT")
            head += chunk
        self.assertIn(b"200", head.split(b"\r\n", 1)[0])

        s.sendall(payload)
        got = b""
        s.settimeout(15)
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got

    def test_traffic_flows_through_proxy(self):
        echo_port = self._echo_server()
        proxy_port = free_port()
        self.assertTrue(self.mgr.start(bind="127.0.0.1:%d" % proxy_port)["ok"])

        payload = b"opera" * 1000
        self.assertEqual(self._through_proxy(proxy_port, echo_port, payload),
                         payload)

    def test_traffic_survives_chatty_logging(self):
        """
        Регрессия «прокси зависает под нагрузкой»: при verbosity=10 вывод
        забивает буфер пайпа, и без дренажа процесс встаёт на write() —
        трафик перестаёт ходить. Гоняем 512 КБ на болтливом уровне.
        """
        echo_port = self._echo_server()
        proxy_port = free_port()
        self.assertTrue(self.mgr.start(bind="127.0.0.1:%d" % proxy_port,
                                       verbosity=10)["ok"])
        time.sleep(1.0)                       # даём логу переполнить пайп

        payload = os.urandom(512 * 1024)
        self.assertEqual(self._through_proxy(proxy_port, echo_port, payload),
                         payload)

    def test_stop_closes_listener(self):
        proxy_port = free_port()
        self.assertTrue(self.mgr.start(bind="127.0.0.1:%d" % proxy_port)["ok"])
        self.assertTrue(self.probe(proxy_port))
        self.mgr.stop()
        self.assertFalse(self.probe(proxy_port))


class TestProbe(unittest.TestCase):

    def test_ipv4(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        self.assertTrue(opw.probe_proxy("127.0.0.1:%d" % port, timeout=2))
        self.assertTrue(opw.probe_proxy("0.0.0.0:%d" % port, timeout=2))

    @unittest.skipUnless(has_ipv6_loopback(), "нет IPv6 loopback")
    def test_ipv6(self):
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.bind(("::1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        # Регрессия: rsplit(":", 1) + AF_INET давали False на живом прокси.
        self.assertTrue(opw.probe_proxy("[::1]:%d" % port, timeout=2))

    def test_target_address_resolution(self):
        """
        Куда именно стучимся (проверяемо и без IPv6 в системе):
        скобки снимаются, wildcard заменяется на loopback.
        """
        cases = {
            "[::1]:18080":     ("::1", 18080),
            "[::]:18080":      ("::1", 18080),
            "0.0.0.0:18080":   ("127.0.0.1", 18080),
            "127.0.0.1:18080": ("127.0.0.1", 18080),
        }
        for bind, expected in cases.items():
            with mock.patch("socket.create_connection") as conn:
                self.assertTrue(opw.probe_proxy(bind, timeout=1), bind)
            conn.assert_called_once_with(expected, timeout=1)

    def test_closed_and_malformed(self):
        port = free_port()
        self.assertFalse(opw.probe_proxy("127.0.0.1:%d" % port, timeout=1))
        self.assertFalse(opw.probe_proxy("не-адрес", timeout=1))
        self.assertFalse(opw.probe_proxy("", timeout=1))


class TestWatchdog(_OperaBase):

    def _watchdog(self):
        wd = opw.OperaProxyWatchdog()
        self.addCleanup(wd._stop)
        return wd

    def test_restarts_dead_process(self):
        port = free_port()
        bind = "127.0.0.1:%d" % port
        self.cfg.set("opera_proxy", "bind", bind)
        self.cfg.set("opera_proxy", "enabled", True)
        self.cfg.set("opera_proxy", "autostart", True)
        self.assertTrue(self.mgr.start(bind=bind)["ok"])

        wd = self._watchdog()
        with mock.patch.object(opm, "get_opera_proxy_manager",
                               return_value=self.mgr), \
             mock.patch.object(opw, "_DEFAULT_CONSECUTIVE_FAILURES", 1), \
             mock.patch.object(opw, "_DEFAULT_COOLDOWN_SEC", 0):
            first_pid = self.mgr.status()["pid"]
            os.kill(first_pid, 9)
            time.sleep(0.3)
            wd._tick()

        st = self.mgr.status()
        self.assertTrue(st["running"])
        self.assertNotEqual(st["pid"], first_pid)

    def test_no_restart_loop_on_broken_bind(self):
        """
        Негодный bind: пробой его не проверить. Раньше проба падала в
        False и watchdog перезапускал прокси по кругу.
        """
        port = free_port()
        self.cfg.set("opera_proxy", "enabled", True)
        self.cfg.set("opera_proxy", "autostart", True)
        self.cfg.set("opera_proxy", "bind", "мусор")
        self.assertTrue(self.mgr.start(bind="127.0.0.1:%d" % port)["ok"])

        wd = self._watchdog()
        with mock.patch.object(opm, "get_opera_proxy_manager",
                               return_value=self.mgr), \
             mock.patch.object(opw, "_DEFAULT_CONSECUTIVE_FAILURES", 1), \
             mock.patch.object(opw, "_DEFAULT_COOLDOWN_SEC", 0), \
             mock.patch.object(wd, "_do_restart") as restart:
            for _ in range(3):
                wd._tick()
        restart.assert_not_called()
        self.assertEqual(wd._fail_count, 0)

    def test_stops_itself_when_disabled_in_config(self):
        """Выключили прокси в другой вкладке — watchdog не воскрешает."""
        self.cfg.set("opera_proxy", "enabled", False)
        self.cfg.set("opera_proxy", "autostart", True)
        wd = self._watchdog()
        with mock.patch.object(opm, "get_opera_proxy_manager",
                               return_value=self.mgr), \
             mock.patch.object(wd, "_do_restart") as restart:
            wd._tick()
        restart.assert_not_called()

    def test_reconfigure_gated_by_flags(self):
        wd = self._watchdog()
        self.cfg.set("opera_proxy", "enabled", True)
        self.cfg.set("opera_proxy", "autostart", False)
        wd.reconfigure()
        self.assertFalse(wd.get_status()["running"])

        self.cfg.set("opera_proxy", "autostart", True)
        wd.reconfigure()
        self.assertTrue(wd.get_status()["running"])
        wd._stop()


class TestTunnelMonitorPort(_OperaBase):

    def test_uses_configured_port(self):
        """Раньше порт был захардкожен (18080) — при своём bind нули."""
        port = free_port()
        bind = "127.0.0.1:%d" % port
        self.cfg.set("opera_proxy", "bind", bind)
        self.assertTrue(self.mgr.start(bind=bind)["ok"])

        from core.tunnel_monitor import get_tunnel_monitor
        tm = get_tunnel_monitor()
        with mock.patch.object(tm, "_count_connections",
                               return_value=3) as counter:
            rx, tx = tm._read_opera_stats()
        counter.assert_called_once_with(port)
        self.assertGreater(rx, 0)
        self.assertGreater(tx, 0)

    def test_zero_when_not_listening(self):
        self.cfg.set("opera_proxy", "bind", "127.0.0.1:%d" % free_port())
        from core.tunnel_monitor import get_tunnel_monitor
        self.assertEqual(get_tunnel_monitor()._read_opera_stats(), (0, 0))


class TestCli(_OperaBase):

    def test_start_uses_saved_settings(self):
        """CLI стартовал с дефолтами, игнорируя сохранённые настройки."""
        port = free_port()
        self.cfg.set("opera_proxy", "bind", "127.0.0.1:%d" % port)
        self.cfg.set("opera_proxy", "country", "AM")
        self.cfg.set("opera_proxy", "socks_mode", True)

        from core import cli
        args = cli.build_parser().parse_args(["opera", "start"])
        with mock.patch.object(opm, "get_opera_proxy_manager",
                               return_value=self.mgr), \
             mock.patch("core.opera_proxy_watchdog.get_opera_proxy_watchdog"):
            self.assertEqual(cli._cmd_opera(args), 0)

        launch = [c for c in self.calls() if "-bind-address" in c][-1]
        self.assertIn("-bind-address 127.0.0.1:%d" % port, launch)
        self.assertIn("-country AM", launch)
        self.assertIn("-socks-mode", launch)
        # enabled — то, что читают boot-автозапуск и watchdog.
        self.assertTrue(self.cfg.get("opera_proxy", "enabled"))

        stop_args = cli.build_parser().parse_args(["opera", "stop"])
        with mock.patch.object(opm, "get_opera_proxy_manager",
                               return_value=self.mgr), \
             mock.patch("core.opera_proxy_watchdog.get_opera_proxy_watchdog"):
            self.assertEqual(cli._cmd_opera(stop_args), 0)
        self.assertFalse(self.cfg.get("opera_proxy", "enabled"))


class TestApi(_OperaBase):

    def setUp(self):
        super().setUp()
        from tests._wsgi_client import WSGIClient, build_test_app
        self.client = WSGIClient(build_test_app())
        patcher = mock.patch.object(opm, "get_opera_proxy_manager",
                                    return_value=self.mgr)
        patcher.start()
        self.addCleanup(patcher.stop)
        wd_patcher = mock.patch(
            "core.opera_proxy_watchdog.get_opera_proxy_watchdog")
        wd_patcher.start()
        self.addCleanup(wd_patcher.stop)

    def test_config_roundtrip(self):
        r = self.client.put_json("/api/opera-proxy/config", {
            "country": "am", "bind": "0.0.0.0:18081", "socks_mode": True,
            "verbosity": 10, "autostart": True})
        self.assertEqual(r["_status"], 200, r)
        cfg = self.client.get_json("/api/opera-proxy/config")
        self.assertEqual(cfg["country"], "AM")
        self.assertEqual(cfg["bind"], "0.0.0.0:18081")
        self.assertIs(cfg["socks_mode"], True)
        self.assertEqual(cfg["verbosity"], 10)

    def test_config_rejects_garbage(self):
        for body in ({"bind": "не-адрес"}, {"verbosity": "abc"},
                     {"country": ""}, {"fake_sni": "плохой домен"}):
            r = self.client.put_json("/api/opera-proxy/config", body)
            self.assertEqual(r["_status"], 400, body)
            self.assertFalse(r["ok"])
            self.assertTrue(r["error"])
        # Ничего не сохранилось.
        self.assertEqual(
            self.client.get_json("/api/opera-proxy/config")["bind"],
            "127.0.0.1:18080")

    def test_up_rejects_garbage_override(self):
        r = self.client.post_json("/api/opera-proxy/up", {"bind": "мусор"})
        self.assertEqual(r["_status"], 400)
        self.assertFalse(r["ok"])
        self.assertFalse(self.cfg.get("opera_proxy", "enabled", default=False))

    def test_up_down_toggles_enabled(self):
        port = free_port()
        self.client.put_json("/api/opera-proxy/config",
                             {"bind": "127.0.0.1:%d" % port})
        up = self.client.post_json("/api/opera-proxy/up")
        self.assertTrue(up["ok"], up)
        self.assertTrue(self.cfg.get("opera_proxy", "enabled"))

        st = self.client.get_json("/api/opera-proxy/status")
        self.assertTrue(st["running"])
        self.assertIs(st["listening"], True)

        down = self.client.post_json("/api/opera-proxy/down")
        self.assertTrue(down["ok"])
        self.assertFalse(self.cfg.get("opera_proxy", "enabled"))
        self.assertFalse(
            self.client.get_json("/api/opera-proxy/status")["running"])

    def test_detect_endpoint_is_cheap(self):
        for _ in range(3):
            d = self.client.get_json("/api/opera-proxy/detect")
        self.assertTrue(d["installed"])
        self.assertEqual([c for c in self.calls() if "list-countries" in c], [])

    def test_countries_endpoint(self):
        cached = self.client.get_json("/api/opera-proxy/countries")
        self.assertEqual(cached["countries"], [])
        self.assertEqual([c for c in self.calls() if "list-countries" in c], [])

        fresh = self.client.get_json("/api/opera-proxy/countries?refresh=1")
        self.assertEqual([c["code"] for c in fresh["countries"]],
                         ["EU", "AS", "AM"])
        self.assertEqual(len([c for c in self.calls()
                              if "list-countries" in c]), 1)

    def test_log_endpoint(self):
        port = free_port()
        self.mgr.start(bind="127.0.0.1:%d" % port)
        r = self.client.get_json("/api/opera-proxy/log?lines=10")
        self.assertTrue(r["ok"])
        self.assertIn("-bind-address", r["log"])

    def test_broken_json_body_is_not_500(self):
        status, _ = self.client._call("PUT", "/api/opera-proxy/config",
                                      body="{не json".encode("utf-8"),
                                      content_type="application/json")
        self.assertTrue(status.startswith("200"), status)

    def test_debug_toggle(self):
        r = self.client.post_json("/api/opera-proxy/debug", {"enabled": True})
        self.assertTrue(r["enabled"])
        self.assertTrue(
            self.client.get_json("/api/opera-proxy/debug")["enabled"])
        self.client.post_json("/api/opera-proxy/debug", {"enabled": False})


if __name__ == "__main__":
    unittest.main()
