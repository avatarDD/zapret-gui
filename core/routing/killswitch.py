# core/routing/killswitch.py
"""
Kill-switch: не выпускать трафик мимо туннеля, пока туннель лежит.

Зачем. Selective routing устроен так: `ip rule` отправляет пакет в
таблицу интерфейса, а в таблице лежит `default dev <туннель>`. Когда
интерфейс уходит вниз (рестарт по watchdog'у, обрыв, смена конфига),
ядро выкидывает его маршруты, таблица пустеет — и правило перестаёт
что-либо менять: policy-db просто идёт дальше, до `from all lookup main`,
и пакет уходит через провайдера. Снаружи это выглядит как «маршрутизация
работает нестабильно»: на 2ip то адрес туннеля, то свой.

Для правила «весь трафик с устройства — через туннель» это утечка:
пользователь просил туннель, а получил провайдера, и никакого признака
этого нет ни в GUI, ни в логе.

Механика лечения — второй default в той же таблице:

    ip route add default dev <iface> table <T>              # metric 0
    ip route add blackhole default table <T> metric <МНОГО>

Пока интерфейс жив, выигрывает маршрут с меньшей метрикой (туннель).
Как только интерфейс падает, его маршрут исчезает сам, остаётся
blackhole — пакеты дропаются, а не утекают. Поднялся — снова туннель.
Никакой синхронизации с watchdog'ом не нужно.

Выключатель — `routing.killswitch` в settings.json (по умолчанию ВЫКЛ):
это выбор политики, а не баг. Включённый kill-switch означает, что при
лежащем туннеле у устройства пропадает интернет целиком; кому-то нужнее
связь, кому-то — гарантия непротекания. Молча решать за пользователя мы
не вправе, поэтому по умолчанию поведение прежнее, а в диагностике
маршрутизации прямо написано, что kill-switch выключен и чем это
оборачивается.

ВАЖНО: blackhole живёт в ТАБЛИЦЕ, а таблица — на интерфейс. Значит он
накрывает все правила этого интерфейса (device/cidr/domain), а не только
device. Так и задумано: «мимо туннеля не выпускать» — свойство туннеля.
"""

import subprocess

from core.log_buffer import log


# Метрика blackhole-маршрута. Должна быть заведомо больше метрики
# «настоящего» default'а: у IPv4 он ставится с метрикой 0, у IPv6 ядро
# даёт 1024. Берём практический максимум, чтобы blackhole всегда
# проигрывал живому туннелю.
KILLSWITCH_METRIC = 4294967294


def _run(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", "timeout: %s" % e
    except OSError as e:
        return 1, "", str(e)


def enabled() -> bool:
    """Включён ли kill-switch (`routing.killswitch`, по умолчанию нет)."""
    try:
        from core.config_manager import get_config_manager
        return bool(get_config_manager().get("routing", "killswitch",
                                             default=False))
    except Exception:
        return False


def present(table: int, family: str = "-4") -> bool:
    """Стоит ли blackhole-default в таблице."""
    rc, out, _e = _run(["ip", family, "route", "show", "table", str(table)])
    if rc != 0:
        return False
    for line in (out or "").splitlines():
        if line.strip().startswith("blackhole default"):
            return True
    return False


def ensure(table: int, families=("v4",)) -> dict:
    """Поставить blackhole-default в таблицу (идемпотентно).

    Выключенная опция здесь же и УБИРАЕТ прежний blackhole: apply
    случается на каждом подъёме туннеля и на «Переприменить», поэтому
    выключатель начинает действовать без отдельной уборки.
    """
    if not enabled():
        remove(table, families)
        return {"ok": True, "skipped": True, "reason": "выключен"}
    errors = []
    for fam in families:
        family = "-6" if fam == "v6" else "-4"
        if present(table, family):
            continue
        rc, _o, err = _run(["ip", family, "route", "add", "blackhole",
                            "default", "table", str(table),
                            "metric", str(KILLSWITCH_METRIC)])
        if rc != 0 and "File exists" not in (err or ""):
            errors.append("%s: %s" % (fam, err.strip()))
    if errors:
        return {"ok": False, "error": "; ".join(errors), "table": table}
    return {"ok": True, "table": table}


def remove(table: int, families=("v4", "v6")) -> dict:
    """Снять blackhole-default (при выключении/удалении правил)."""
    for fam in families:
        family = "-6" if fam == "v6" else "-4"
        _run(["ip", family, "route", "del", "blackhole", "default",
              "table", str(table), "metric", str(KILLSWITCH_METRIC)])
        # Старые записи могли лечь без явной метрики — подчищаем и их.
        _run(["ip", family, "route", "del", "blackhole", "default",
              "table", str(table)])
    return {"ok": True, "table": table}


def status(table: int, family: str = "-4") -> dict:
    """Состояние для диагностики: включён ли и стоит ли на самом деле."""
    on = enabled()
    return {"enabled": on, "present": present(table, family)}
