# core/geneva_auto_probe_cli.py
"""
Проба режима «Авто» для ``geneva eval/evolve --probe exec``.

geneva запускает эту команду на каждый прогон стратегии и подставляет
``{lports}`` — блок исходных портов воркера (``30000-30063``): через
движок оценщика идёт только трафик с этих портов, и стратегия воркера
применяется к нему. Проба та же, что у подтверждения
(:mod:`core.geneva_auto_probes`): загрузка страницы с адреса сервиса или
повтор первых пакетов, — только с порта из блока и без метки обхода.

Ответ geneva — код возврата и вывод (``docs/EVAL.md`` geneva_c, проба
``exec``): 0 — ``ok`` (+400); вывод со словом ``reset`` — ``reset``
(−360); вывод с ``INJECTED`` (``--injected-contains INJECTED``) —
``injected`` (−360); иначе — ``failed`` (−400). Тоньше шкала ``exec`` не
различает: «нет ответа» и «сервер закрыл» здесь обе −400. Отличие от
эталона, где проба встроена в geneva и fitness точнее: точный
``external`` возможен только с одним воркером, а «Авто» ставит скорость
(параллельные воркеры) выше тонкости шкалы.

Запуск — скриптом (``python3 <app>/core/geneva_auto_probe_cli.py …``):
geneva зовёт ``sh -c`` из своего каталога, ``-m`` там не сработал бы.
Первые пакеты для повтора лежат файлом в ОЗУ (``--replay-file``), а не в
командной строке: она пишется в журнал geneva.
"""

import argparse
import os
import sys

if __name__ == "__main__" and __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))


def parse_lports(text: str):
    """``30000-30063`` → ``(30000, 30063)``; одиночный порт тоже."""
    lo, _, hi = str(text or "").partition("-")
    lo = int(lo)
    hi = int(hi) if hi else lo
    if not 1024 <= lo <= hi <= 65535:
        raise ValueError("lports")
    return lo, hi


def verdict(fitness: int, outcome: str):
    """``(код возврата, строка вывода)`` для geneva по итогу пробы."""
    if fitness > 0:
        return 0, "ok"
    if outcome == "injected":
        return 1, "INJECTED"
    if outcome == "reset":
        return 1, "reset"
    return 1, outcome or "failed"


def run(argv) -> int:
    ap = argparse.ArgumentParser(prog="geneva_auto_probe")
    ap.add_argument("--kind", choices=("web", "replay"), required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="")
    ap.add_argument("--tls", type=int, default=1)
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--fresh", default="", choices=("", "stun", "dns"))
    ap.add_argument("--replay-file", default="")
    ap.add_argument("--lports", required=True)
    ap.add_argument("--timeout", type=float, default=0)
    a = ap.parse_args(argv)

    from core import geneva_auto as ga
    from core import geneva_auto_probes as pr

    try:
        ports = parse_lports(a.lports)
    except ValueError:
        print("failed: bad lports %s" % a.lports)
        return 1
    if a.kind == "web":
        kw = {"timeout": a.timeout} if a.timeout else {}
        r = pr.probe_page(a.ip, a.port, a.host or a.ip, tls=bool(a.tls),
                          ports=ports, **kw)
        fit, outcome = pr.page_fitness(r)
        detail = r.text()
    else:
        payloads = []
        if a.replay_file:
            try:
                with open(a.replay_file, "r", encoding="ascii") as f:
                    payloads = ga.from_base64(f.read().strip())
            except OSError as e:
                print("failed: replay file: %s" % e)
                return 1
        kw = {"timeout": a.timeout} if a.timeout else {}
        r = pr.probe_replay(a.ip, a.port, payloads, udp=a.udp,
                            fresh=a.fresh, ports=ports, **kw)
        fit, outcome = pr.replay_fitness(r)
        detail = r.text()
    code, word = verdict(fit, outcome)
    print("%s: %s" % (word, detail))
    return code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
