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
различает: «нет ответа» и «сервер закрыл» здесь обе −400.

С geneva_c 1.2 (фича ``external_workers``) «Авто» этот скрипт не
запускает: та же проба (:func:`measure`) идёт внутри zapret-gui как
``--probe external`` с несколькими воркерами, и geneva получает точный
фитнес. Скрипт остаётся для сборок geneva без этой фичи.

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


def measure(spec: dict, ports):
    """Проба сервиса с блока портов ``ports`` (``(lo, hi)``):
    ``(fitness, outcome, detail)`` по шкале geneva.

    ``spec`` — :func:`core.geneva_auto_search.probe_spec`: ``kind``
    (``web``/``replay``), ``ip``, ``port``, у сайта ``host`` и ``tls``, у
    повтора ``udp``, ``fresh`` и ``payloads`` (байты первых пакетов);
    ``timeout`` — необязательно."""
    from core import geneva_auto_probes as pr
    kw = {"timeout": spec["timeout"]} if spec.get("timeout") else {}
    if spec.get("kind") == "web":
        r = pr.probe_page(spec["ip"], int(spec["port"]),
                          spec.get("host") or spec["ip"],
                          tls=bool(spec.get("tls", True)), ports=ports, **kw)
        fit, outcome = pr.page_fitness(r)
    else:
        r = pr.probe_replay(spec["ip"], int(spec["port"]),
                            spec.get("payloads") or [],
                            udp=bool(spec.get("udp")),
                            fresh=spec.get("fresh") or "", ports=ports, **kw)
        fit, outcome = pr.replay_fitness(r)
    return fit, outcome, r.text()


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

    try:
        ports = parse_lports(a.lports)
    except ValueError:
        print("failed: bad lports %s" % a.lports)
        return 1
    spec = {"kind": a.kind, "ip": a.ip, "port": a.port, "host": a.host,
            "tls": bool(a.tls), "udp": a.udp, "fresh": a.fresh,
            "timeout": a.timeout}
    if a.kind == "replay" and a.replay_file:
        try:
            with open(a.replay_file, "r", encoding="ascii") as f:
                spec["payloads"] = ga.from_base64(f.read().strip())
        except OSError as e:
            print("failed: replay file: %s" % e)
            return 1
    fit, outcome, detail = measure(spec, ports)
    code, word = verdict(fit, outcome)
    print("%s: %s" % (word, detail))
    return code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
