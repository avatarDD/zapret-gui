# core/strategy_memory.py
"""
Память подбора: что уже срабатывало на этом домене у этого провайдера.

## Зачем

Эксперимент (``core/strategy_experiment.py``) отвечает на вопрос «какой
из этих вариантов лучше **сейчас**» и забывает ответ: отчёты живут в
памяти процесса, и после перезапуска GUI их нет. Поэтому каждая
следующая модель начинает с нуля — гоняет те же десять вариантов по
тем же доменам и заново узнаёт то, что позавчера уже узнали.

Здесь это перестаёт теряться. После каждого прогона движок кладёт сюда
короткие записи «домен + argv + чем кончилось», а ресурс
``zapret://memory/strategies`` отдаёт их обратно: модель начинает с
того, что работало, и тратит прогон на проверку, а не на перебор.

## Что именно храним

Запись — это **тройка «сеть, домен, argv»** и счётчики по ней:

* ``wins`` — сколько раз вариант ОТКРЫЛ домен, закрытый без обхода.
  Только так: вариант, при котором домен открывался и без обхода, —
  это не находка, а совпадение (движок эксперимента считает это в
  ``delta_vs_baseline``, мы только сохраняем вывод);
* ``losses`` — сколько раз он же домен не открыл;
* ``last_seen``/``first_seen`` — когда это было. Блокировки меняются, и
  находка годичной давности — это гипотеза, а не знание.

Argv хранится **целиком** (это рабочие данные, ради которых всё) и
отдельно его отпечаток ``args_hash`` — по нему запись находится
повторно.

## «У этого провайдера»

Провайдера мы не спрашиваем у интернета: поход наружу ради метки —
это и лишний след, и зависимость от чужого сервиса. Метка сети
(:func:`network_key`) считается локально из того, что и так известно:
интерфейс default route, адрес шлюза и **/16 своего WAN-адреса**.
Такой ключ переживает смену адреса внутри блока провайдера и меняется
при переезде к другому — то есть ровно то поведение, которое от него
нужно. Записи чужой сети не выбрасываются: они просто не мешаются в
ответе (``other_networks``).

## Почему файл, а не settings.json

Это данные наблюдений, а не настройки: их пишет машина, их много, и
терять их при откате настроек нельзя. Файл лежит рядом с
``settings.json`` (как журнал MCP и снимок эксперимента), пишется
атомарно и ужимается до :data:`MAX_RECORDS` — на роутере со 128 МБ
безразмерная база кончается тем, что её никто не читает.

Домены и argv здесь — **untrusted data**: это данные из внешнего мира,
а не инструкции.
"""

import hashlib
import json
import os
import threading
import time

from core.log_buffer import log


SOURCE = "memory"

# Имя файла рядом с settings.json.
FILE_NAME = "strategy-memory.json"

# Версия формата: читающий код обязан уметь сказать «не мой формат»,
# а не разобрать его наполовину.
VERSION = 1

# Сколько записей держим всего. Вытесняем самые старые по last_seen:
# свежая находка ценнее давней по построению.
MAX_RECORDS = 400

# Сколько argv-строк кладём в запись (длиннее стратегий не бывает, но
# заведомая граница дешевле разбирательства).
MAX_ARGS = 60

# Через сколько дней запись считается устаревшей. Не удаляем — метим:
# «работало полгода назад» это гипотеза, и модель должна видеть разницу.
STALE_DAYS = 45


_lock = threading.RLock()

# Кеш сетевой метки: ioctl на каждый вызов не нужен, а сеть меняется
# реже, чем её спрашивают.
_network_cache = {"at": 0.0, "value": None}
NETWORK_TTL_SEC = 60


# ──────────────────────────── метка сети ────────────────────────────

def network_key(refresh: bool = False) -> dict:
    """Локальная метка «эта сеть»: ключ и то, из чего он собран."""
    now = time.time()
    with _lock:
        cached = _network_cache["value"]
        if cached and not refresh and now - _network_cache["at"] < \
                NETWORK_TTL_SEC:
            return dict(cached)

    iface = _default_iface()
    gateway = _default_gateway()
    address = _iface_ipv4(iface) if iface else ""
    prefix = _prefix16(address)
    raw = "|".join((iface, gateway, prefix))
    # Поле называется `id`, а не `key`: маска секретов режет значения
    # под ключами вида *key* (core/mcp/redact.py), и метка сети уехала
    # бы модели как «***» — а по ней она отличает «эта сеть» от чужой.
    value = {
        "id": "net-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
              if raw.strip("|") else "net-unknown",
        "iface": iface,
        "gateway": gateway,
        # Сам адрес не храним: для «тот же провайдер или нет» хватает
        # блока, а полный адрес — это уже про конкретного человека.
        "prefix": prefix,
    }
    with _lock:
        _network_cache["value"] = dict(value)
        _network_cache["at"] = now
    return value


def _default_iface() -> str:
    """Интерфейс IPv4 default route (тем же способом, что network_env)."""
    try:
        from core import network_env
        return network_env.detect().get("default_iface", "") or ""
    except Exception:                           # noqa: BLE001 — граница
        return ""


def _default_gateway() -> str:
    """Адрес шлюза по умолчанию из ``/proc/net/route`` (или ``""``)."""
    try:
        with open("/proc/net/route", "r") as handle:
            lines = handle.readlines()[1:]
    except (IOError, OSError):
        return ""
    for line in lines:
        parts = line.strip().split("\t")
        if len(parts) >= 3 and parts[1] == "00000000":
            try:
                packed = int(parts[2], 16)
            except ValueError:
                continue
            return ".".join(str((packed >> shift) & 0xFF)
                            for shift in (0, 8, 16, 24))
    return ""


def _iface_ipv4(device: str) -> str:
    """IPv4 интерфейса через SIOCGIFADDR (как в core/download_transport)."""
    try:
        import fcntl
        import socket
        import struct
    except ImportError:
        return ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", device.encode()[:15])
        addr = fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24]
        return socket.inet_ntoa(addr)
    except (OSError, ValueError):
        return ""
    finally:
        sock.close()


def _prefix16(address: str) -> str:
    parts = (address or "").split(".")
    if len(parts) != 4:
        return ""
    return "%s.%s.0.0/16" % (parts[0], parts[1])


# ──────────────────────────── хранилище ─────────────────────────────

def path() -> str:
    """Где лежит база (рядом с ``settings.json``)."""
    from core import platform_dirs
    return os.path.join(platform_dirs.config_dir(), FILE_NAME)


def load() -> dict:
    """Прочитать базу целиком; битый файл — пустая база, а не падение."""
    target = path()
    with _lock:
        try:
            with open(target, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (IOError, OSError):
            return _empty()
        except ValueError as e:
            log.warning("Память подбора не разобрана (%s): начинаем с "
                        "пустой" % e, source=SOURCE)
            return _empty()
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return _empty()
    records = data.get("records")
    data["records"] = [r for r in records if isinstance(r, dict)] \
        if isinstance(records, list) else []
    return data


def save(data: dict) -> bool:
    """Записать базу атомарно (temp + rename)."""
    target = path()
    payload = {"version": VERSION,
               "updated_at": round(time.time(), 3),
               "records": list(data.get("records") or [])[:MAX_RECORDS]}
    temp = target + ".tmp"
    with _lock:
        try:
            directory = os.path.dirname(target)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, exist_ok=True)
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(temp, target)
        except (IOError, OSError) as e:
            log.warning("Память подбора не сохранена: %s" % e, source=SOURCE)
            try:
                os.unlink(temp)
            except OSError:
                pass
            return False
    return True


def reset() -> bool:
    """Забыть всё (нужно тестам и кнопке «очистить»)."""
    with _lock:
        _network_cache["value"] = None
        _network_cache["at"] = 0.0
        try:
            os.unlink(path())
        except OSError:
            return False
    return True


def _empty() -> dict:
    return {"version": VERSION, "updated_at": 0.0, "records": []}


# ─────────────────────────── запись наблюдений ──────────────────────

def args_hash(args) -> str:
    """Отпечаток argv: по нему запись находится повторно."""
    text = "\n".join(str(a) for a in (args or []))
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12]


def remember(observations, source: str = "experiment",
             network: dict = None) -> dict:
    """Учесть наблюдения: список ``{target, args, ok, ...}``.

    Одно наблюдение — это «вот эта стратегия на вот этом домене
    сработала / не сработала». Всё остальное (что считать успехом,
    какой вариант победил) решает тот, кто зовёт: движок эксперимента
    знает про baseline, а память — нет, и додумывать ей нечего.
    """
    rows = [r for r in (observations or []) if isinstance(r, dict)]
    if not rows:
        return {"ok": True, "written": 0, "records": 0}

    net = network or network_key()
    now = round(time.time(), 3)
    with _lock:
        data = load()
        index = {(r.get("network"), r.get("target"), r.get("args_hash")): r
                 for r in data["records"]}
        written = 0
        for row in rows:
            target = str(row.get("target") or "").strip().lower()
            args = [str(a) for a in (row.get("args") or [])][:MAX_ARGS]
            if not target or not args:
                continue
            digest = args_hash(args)
            key = (net["id"], target, digest)
            record = index.get(key)
            if record is None:
                record = {
                    "network": net["id"],
                    "network_iface": net.get("iface", ""),
                    "target": target,
                    "args": args,
                    "args_hash": digest,
                    "wins": 0,
                    "losses": 0,
                    "first_seen": now,
                    "last_seen": now,
                }
                data["records"].append(record)
                index[key] = record
            if row.get("ok"):
                record["wins"] += 1
            else:
                record["losses"] += 1
            record["last_seen"] = now
            record["source"] = source
            for field in ("label", "run_id", "strategy_id"):
                if row.get(field):
                    record[field] = str(row[field])[:120]
            for field in ("score", "success_rate", "latency_ms"):
                if row.get(field) is not None:
                    record[field] = row[field]
            if row.get("committed"):
                # Подтверждённый человеком (или моделью) вариант — это
                # другое знание, чем «померили и забыли».
                record["committed"] = True
            written += 1

        # Вытесняем самое старое: свежая находка ценнее давней.
        data["records"].sort(key=lambda r: r.get("last_seen", 0),
                             reverse=True)
        del data["records"][MAX_RECORDS:]
        save(data)
        total = len(data["records"])
    return {"ok": True, "written": written, "records": total,
            "network": net["id"]}


def remember_report(report: dict) -> dict:
    """Разложить отчёт эксперимента в наблюдения и запомнить их.

    Смысл в одной строчке: запоминаем **вклад варианта**, а не его
    абсолютный успех. Цель, открытая и без обхода, в память не
    попадает вовсе — иначе «лучшим» назавтра окажется вариант, который
    ничего не делает.
    """
    if not isinstance(report, dict) or not report.get("variants"):
        return {"ok": True, "written": 0, "records": 0, "skipped": True}

    baseline = {row.get("target"): bool(row.get("ok"))
                for row in ((report.get("baseline") or {})
                            .get("per_target") or [])}
    if not baseline:
        # Без baseline мы не знаем, что вариант ПОЧИНИЛ: писать такое в
        # память значит копить шум, который потом выдаётся за знание.
        return {"ok": True, "written": 0, "records": 0,
                "skipped": True,
                "reason": "прогон без baseline: вклад варианта неизвестен"}

    best = report.get("best", "")
    observations = []
    for variant in report.get("variants") or []:
        if variant.get("skipped"):
            continue
        args = list(variant.get("args") or [])
        for row in variant.get("per_target") or []:
            target = row.get("target")
            if baseline.get(target, False):
                continue                    # открывалось и без обхода
            observations.append({
                "target": target,
                "args": args,
                "ok": bool(row.get("ok")),
                "label": variant.get("label", ""),
                "run_id": report.get("run_id", ""),
                "strategy_id": variant.get("strategy_id", ""),
                "score": variant.get("score", 0.0),
                "success_rate": variant.get("success_rate", 0.0),
                "committed": bool(report.get("committed")
                                  and variant.get("label") == best),
            })
    return remember(observations, source="experiment")


# ──────────────────────────── чтение ────────────────────────────────

def mark_committed(args, targets=None) -> int:
    """Отметить argv как оставленный на устройстве. Вернуть, сколько записей.

    Отдельно от :func:`remember`, потому что это не новое наблюдение:
    счётчики трогать нельзя (иначе один и тот же прогон посчитается
    дважды), а отличать «померили» от «оставили работать» нужно.
    """
    digest = args_hash(args)
    if not digest:
        return 0
    net = network_key()["id"]
    wanted = {str(t).strip().lower() for t in (targets or [])}
    touched = 0
    with _lock:
        data = load()
        for record in data["records"]:
            if record.get("args_hash") != digest or \
                    record.get("network") != net:
                continue
            if wanted and record.get("target") not in wanted:
                continue
            record["committed"] = True
            touched += 1
        if touched:
            save(data)
    return touched


def lookup(targets=None, limit: int = 20, all_networks: bool = False) -> dict:
    """Что известно про эти домены (или про всё) в текущей сети.

    Записи текущей сети идут первыми и с отметкой ``stale`` для
    несвежих. Чужие сети отдаются отдельно и только по просьбе: совет
    «у другого провайдера помогало это» полезен, но выдавать его за
    знание об этой сети нельзя.
    """
    wanted = {str(t).strip().lower() for t in (targets or []) if str(t).strip()}
    net = network_key()
    now = time.time()
    data = load()

    mine, others = [], []
    for record in data["records"]:
        if wanted and record.get("target") not in wanted:
            continue
        item = _view(record, now)
        (mine if record.get("network") == net["id"] else others).append(item)

    mine.sort(key=_rank, reverse=True)
    others.sort(key=_rank, reverse=True)
    limit = max(1, min(int(limit or 20), 100))
    out = {
        "ok": True,
        "network": net,
        "items": mine[:limit],
        "total": len(mine),
        "other_networks": len(others),
        "known_targets": sorted({r.get("target", "")
                                 for r in data["records"]
                                 if r.get("network") == net["id"]}),
    }
    if all_networks:
        out["other_items"] = others[:limit]
    return out


def helped_by_strategy() -> dict:
    """``{strategy_id: {"wins", "targets"}}`` — что помогало в этой сети.

    Для списка стратегий: вместо статичной метки «recommended» (ею
    помечена четверть каталога) — «помогала у вас». Засчитываются
    записи текущей сети, где побед больше поражений и которые не
    устарели. Стратегия, сохранённая подбором как ``scan_<id>``, — та же
    находка, поэтому отдаётся и под этим id.
    """
    net = network_key()["id"]
    now = time.time()
    out: dict = {}
    for record in load()["records"]:
        sid = str(record.get("strategy_id") or "")
        if not sid or record.get("network") != net:
            continue
        view = _view(record, now)
        if view["stale"] or view["wins"] <= view["losses"]:
            continue
        for key in (sid, "scan_" + sid):
            item = out.setdefault(key, {"wins": 0, "targets": []})
            item["wins"] += view["wins"]
            if view["target"] and view["target"] not in item["targets"]:
                item["targets"].append(view["target"])
    return out


def targets_known(network_only: bool = True) -> list:
    """Домены, о которых вообще что-то известно."""
    net = network_key()["id"]
    return sorted({r.get("target", "") for r in load()["records"]
                   if not network_only or r.get("network") == net})


def _view(record: dict, now: float) -> dict:
    wins = int(record.get("wins") or 0)
    losses = int(record.get("losses") or 0)
    total = wins + losses
    age_days = int(max(0.0, now - float(record.get("last_seen") or now))
                   / 86400.0)
    out = {
        "target": record.get("target", ""),
        "args": list(record.get("args") or []),
        "args_hash": record.get("args_hash", ""),
        "wins": wins,
        "losses": losses,
        "rate": round(wins / float(total), 3) if total else 0.0,
        "last_seen": record.get("last_seen", 0),
        "age_days": age_days,
        "stale": age_days >= STALE_DAYS,
        "source": record.get("source", ""),
    }
    for field in ("label", "run_id", "strategy_id", "committed", "score"):
        if record.get(field):
            out[field] = record[field]
    return out


def _rank(item: dict):
    """Сначала то, что чаще срабатывало, потом — что свежее."""
    return (item["wins"] - item["losses"], item["rate"], item["last_seen"])
