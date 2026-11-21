# core/kmod_manager.py
"""
Установка модулей ядра, нужных nfqws2 для NFQUEUE — прямо из GUI.

Зачем: на стоковом OpenWrt модуль `nfnetlink_queue` в прошивку не входит.
Без него nfqws2 не может открыть NFQUEUE и завершается сразу после запуска
(exit code 1) — самый частый «nfqws2 не стартует» на OpenWrt. Чинится это
установкой пары пакетов ядра, но пользователю приходилось лезть в консоль и
угадывать имена пакетов И правильный менеджер (opkg на 24.10 и раньше, apk
на 25.12+ и в SNAPSHOT). Этот модуль:

  • определяет СИСТЕМНЫЙ пакетный менеджер (apk/opkg), НЕ трогая Entware'ский
    /opt/bin/opkg — модули ядра обязаны совпадать с работающим ядром прошивки,
    а Entware ставит user-space пакеты и его feed на kmod-* отвечает «Unknown
    package»;
  • по типу firewall (iptables/nftables) выбирает нужный набор пакетов;
  • ставит их в фоне (обновление индекса + install), best-effort подгружает
    модуль (modprobe) и перепроверяет доступность NFQUEUE — без перезагрузки,
    если получилось;
  • даёт компактную текстовую подсказку (`nfqueue_fix_hint`) для диагностики и
    лога nfqws2.

ВАЖНО про платформы (ничего не ломаем на других):
  • Автоустановка предлагается ТОЛЬКО на настоящем OpenWrt (`/etc/openwrt_release`
    и это не Keenetic). Там ядро и feed версионно согласованы → kmod ставятся.
  • На Keenetic/Entware kmod приходят из прошивки, а не из opkg — автоустановка
    НЕ предлагается, отдаётся текстовая инструкция.
  • На обычном Linux (ПК/VPS) `nfnetlink_queue`, как правило, встроен или
    поднимается `modprobe` — автоустановку пакетов не трогаем.

Никаких импортов bottle. Тяжёлые импорты (diagnostics/firewall/config) —
лениво внутри функций, чтобы не создавать циклы (diagnostics/nfqws_manager
импортируют этот модуль).
"""

import os
import shutil
import subprocess
import threading
import time

from core.log_buffer import log


# ─────────────────────── пакеты и менеджеры ───────────────────────

# Модуль ядра, дающий сам механизм NFQUEUE (nfnetlink_queue). Критичный —
# без него nfqws2 падает с exit 1.
PKG_NFNETLINK_QUEUE = "kmod-nfnetlink-queue"

# Фронтенды к NFQUEUE под конкретный firewall:
#   iptables → цель xt_NFQUEUE (пакет iptables-mod-nfqueue, тянет kmod выше);
#   nftables → выражение `queue` (пакет kmod-nft-queue, тоже тянет kmod выше).
PKG_IPT_NFQUEUE = "iptables-mod-nfqueue"
PKG_NFT_QUEUE = "kmod-nft-queue"

# conntrack — нужен для sysctl nf_conntrack_tcp_be_liberal (десинк шлёт
# out-of-window сегменты). На роутере с NAT он всегда есть, так что установка —
# идемпотентный no-op, но включаем для полноты и чтобы sysctl-нода точно была.
PKG_NF_CONNTRACK = "kmod-nf-conntrack"

# NFLOG — подсистема nfnetlink_log: группы NFLOG, в которые ядро копирует
# пакеты (nfnetlink_queue отдаёт их на обработку и ждёт вердикта, а NFLOG
# только копирует). Нужна детектору geneva (``--ext-auto observe``); в образ
# OpenWrt по умолчанию не входит, и без неё ядро отвечает EINVAL на попытку
# встать на группу — «cannot bind NFLOG group N: Invalid argument».
PKG_NFNETLINK_LOG = "kmod-nfnetlink-log"

# Абсолютные пути СИСТЕМНОГО пакетного менеджера (прошивки), в приоритете.
# /opt/... (Entware) сюда намеренно не входит.
_APK_PATHS = ("/usr/bin/apk", "/sbin/apk", "/bin/apk")
_OPKG_PATHS = ("/bin/opkg", "/usr/bin/opkg", "/sbin/opkg")


def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def detect_pkg_manager():
    """(kind, path) системного пакетного менеджера, либо (None, None).

    kind ∈ {"apk", "opkg"}. На apk-based OpenWrt (25.12+/SNAPSHOT) предпочитаем apk,
    иначе opkg. Никогда не возвращаем Entware'ский /opt/bin/opkg — модули ядра
    должны совпадать с работающим ядром прошивки.
    """
    apk = _first_existing(_APK_PATHS)
    opkg = _first_existing(_OPKG_PATHS)
    # Признак apk-based системы: apk-tools 3.x на OpenWrt держит БД в /etc/apk
    # (или /lib/apk). Если он есть — apk «настоящий», даже когда рядом остался
    # opkg-совместимый шим.
    apk_based = os.path.isdir("/etc/apk") or os.path.isdir("/lib/apk")
    if apk and (apk_based or not opkg):
        return ("apk", apk)
    if opkg:
        return ("opkg", opkg)
    if apk:
        return ("apk", apk)
    return (None, None)


def _platform_kind():
    """keenetic | openwrt | entware | linux — лёгкий файловый детект.

    Реализация одна на всех — core/system_info.platform_kind. Здесь это
    критично: по платформе решается, можно ли ставить модули ядра (на
    Keenetic нельзя), а прежняя копия проверок принимала Keenetic за
    OpenWrt и предлагала несуществующий там opkg-пакет.
    """
    from core.system_info import platform_kind
    return platform_kind()


def _detect_fw_type():
    """iptables | nftables | None — тихо (без логов, в отличие от FirewallManager).

    Уважает ручной override firewall.type из конфига, иначе — по наличию
    бинарей (паритет с FirewallManager._auto_detect: при обоих предпочитаем
    iptables для совместимости с Keenetic/Entware).
    """
    try:
        from core.config_manager import get_config_manager
        v = get_config_manager().get("firewall", "type", default="auto")
        if v in ("iptables", "nftables"):
            return v
    except Exception:
        pass
    has_ipt = shutil.which("iptables") is not None
    has_nft = shutil.which("nft") is not None
    if has_ipt and not has_nft:
        return "iptables"
    if has_nft and not has_ipt:
        return "nftables"
    if has_ipt:
        return "iptables"
    if has_nft:
        return "nftables"
    return None


def required_packages(fw_type):
    """Набор пакетов OpenWrt для работоспособного NFQUEUE под данный firewall.

    Модуль nfnetlink_queue нужен всегда; фронтенд — под конкретный backend.
    При неизвестном backend добавляем фронтенд по фактически имеющемуся бинарю,
    чтобы не тянуть iptables на чисто-nft систему и наоборот.
    """
    pkgs = [PKG_NFNETLINK_QUEUE]
    if fw_type == "iptables":
        pkgs.append(PKG_IPT_NFQUEUE)
    elif fw_type == "nftables":
        pkgs.append(PKG_NFT_QUEUE)
    else:
        if shutil.which("iptables"):
            pkgs.append(PKG_IPT_NFQUEUE)
        if shutil.which("nft"):
            pkgs.append(PKG_NFT_QUEUE)
    pkgs.append(PKG_NF_CONNTRACK)
    return pkgs


def _install_verb(kind):
    """Подкоманда установки: apk add / opkg install."""
    return "add" if kind == "apk" else "install"


def install_command_str(kind, packages):
    """Человекочитаемая команда установки (для UI/лога). '' если менеджер не найден."""
    if not kind or not packages:
        return ""
    return "%s update && %s %s %s" % (
        kind, kind, _install_verb(kind), " ".join(packages))


# ─────────────────────── статус зависимостей ───────────────────────

def _iptables_target_available(fw_type):
    """Есть ли у iptables цель NFQUEUE (xt_NFQUEUE). None — если не применимо."""
    if fw_type != "iptables":
        return None
    ipt = shutil.which("iptables")
    if not ipt:
        return None
    try:
        from core.firewall import FirewallManager
        return FirewallManager()._ipt_probe_rule(
            ipt, ["-j", "NFQUEUE", "--queue-num", "0", "--queue-bypass"])
    except Exception:
        return None


def _nflog_probe():
    """Доступность NFLOG — лениво, чтобы не тянуть diagnostics при импорте."""
    from core.diagnostics import _check_nflog_available
    return _check_nflog_available()


def _nfqueue_probe():
    """Доступность NFQUEUE — лениво, чтобы не тянуть diagnostics при импорте."""
    from core.diagnostics import _check_nfqueue_available
    return _check_nfqueue_available()


# Что чем проверяется после установки и что дёргать через modprobe.
_FLAVORS = {
    "nfqueue": {"probe": _nfqueue_probe, "module": "nfnetlink_queue",
                "title": "NFQUEUE"},
    "nflog": {"probe": _nflog_probe, "module": "nfnetlink_log",
              "title": "NFLOG"},
}


def nflog_required_packages():
    """Пакеты OpenWrt для NFLOG. Один модуль, фронтендов у него нет."""
    return [PKG_NFNETLINK_LOG]


def nflog_deps_status():
    """Статус NFLOG (``nfnetlink_log``) и возможности починки из GUI.

    Нужен детектору geneva (``--ext-auto observe``): он встаёт на группу
    NFLOG, а без подсистемы ядро отвечает ``Invalid argument``.

    Поля те же, что у :func:`nfqueue_deps_status`, кроме сетевых
    (``fw_type``, ``target_available``): у NFLOG один модуль и нет
    фронтендов вроде цели iptables. ``available`` — подсистема уже
    работает (тогда кнопка не нужна).
    """
    platform = _platform_kind()
    kind, path = detect_pkg_manager()
    available = _nflog_probe()
    packages = nflog_required_packages()
    install_command = install_command_str(kind, packages)

    can_auto_install = (platform == "openwrt" and kind is not None)
    reason = ""
    instructions = ""
    if not can_auto_install:
        if platform in ("keenetic", "entware"):
            reason = ("На Keenetic/Entware модуль nfnetlink_log приходит из "
                      "прошивки, а не из opkg (feed отвечает «Unknown "
                      "package»).")
            instructions = (
                "Детектор geneva отключится сам — остальной режим «Авто» "
                "работает и без него. Если нужен детектор, включите NFLOG в "
                "прошивке (компонент netfilter с группой NFLOG).")
        elif platform == "linux":
            reason = ("Обычный Linux: nfnetlink_log обычно встроен в ядро или "
                      "поднимается modprobe.")
            instructions = (
                "Попробуйте загрузить модуль: modprobe nfnetlink_log. Если "
                "модуля нет — доустановьте пакет ядра средствами вашего "
                "дистрибутива. Без него детектор geneva работать не будет.")
        else:
            reason = "Не найден системный пакетный менеджер (apk/opkg)."
            instructions = "Установите модуль NFLOG вручную."

    if not can_auto_install:
        # Команду показываем только там, где она сработает: на Keenetic
        # «opkg install kmod-nfnetlink-log» — заведомая неправда (такого
        # пакета в фиде нет), и предлагать её в интерфейсе нельзя.
        install_command = ""

    return {
        "platform": platform,
        "pkg_manager": kind,
        "pkg_manager_path": path,
        "available": available,
        "packages": packages,
        "install_command": install_command,
        "can_auto_install": can_auto_install,
        "reason": reason,
        "instructions": instructions,
    }


def nflog_ensure_module() -> bool:
    """NFLOG работает? Если нет — один раз пробуем подгрузить модуль.

    Это дорога к совместимости с Linux и Keenetic: там ``nfnetlink_log``
    обычно есть в ядре/прошивке, но не загружен, и без ``modprobe``
    детектор geneva падал бы с `EINVAL`, хотя починка — одна команда.
    Ядро само грузит модуль по алиасу ``nfnetlink-subsys-4`` лишь когда
    подсистема собрана модулем и лежит там, где его ищет kmod; на сборках
    с ``CONFIG_NFNETLINK_LOG=m`` и вычищенным ``modules.dep`` автозагрузка
    не срабатывает.

    Возвращает True, если подсистема доступна (или стала доступна).
    """
    if _nflog_probe():
        return True
    modprobe = shutil.which("modprobe")
    if modprobe:
        rc, out, err = _run([modprobe, "nfnetlink_log"], timeout=10)
        if rc:
            # Причина видна только здесь: «could not insert … Operation not
            # permitted» — нет CAP_SYS_MODULE, «module not found» — модуля
            # нет. Наверх уходит только «нет NFLOG», а подробность — в лог.
            log.debug("NFLOG: modprobe вернул %s: %s"
                      % (rc, (err or out or "").strip()[:200]), source="kmod")
    return _nflog_probe()


def nflog_fix_hint():
    """Компактная подсказка «как включить NFLOG» — для журнала и страницы.

    Безопасна на любой платформе. Поля: can_auto_install, platform,
    pkg_manager, command, log_line, note.
    """
    platform = _platform_kind()
    kind, _ = detect_pkg_manager()
    packages = nflog_required_packages()

    if platform == "openwrt" and kind:
        return {
            "can_auto_install": True,
            "platform": platform,
            "pkg_manager": kind,
            "command": install_command_str(kind, packages),
            "log_line": ("Детектору geneva нужен модуль ядра NFLOG — установите "
                         "его кнопкой «Установить модуль NFLOG» в разделе "
                         "«Обход DPI», режим «Авто»."),
            "note": ("На OpenWrt модуль NFLOG (nfnetlink_log) в образ по "
                     "умолчанию не входит."),
        }
    if platform in ("keenetic", "entware"):
        return {
            "can_auto_install": False,
            "platform": platform,
            "pkg_manager": kind,
            "command": "",
            "log_line": ("Модуль NFLOG (nfnetlink_log) приходит из прошивки, а "
                         "не из opkg — без него детектор geneva отключён."),
            "note": "Через opkg модули ядра на Keenetic не ставятся.",
        }
    return {
        "can_auto_install": False,
        "platform": platform,
        "pkg_manager": kind,
        "command": "modprobe nfnetlink_log",
        "log_line": ("Загрузите модуль ядра: modprobe nfnetlink_log — без него "
                     "детектор geneva отключён."),
        "note": "На обычном Linux nfnetlink_log обычно встроен в ядро.",
    }


def nfqueue_deps_status():
    """Полный статус готовности NFQUEUE и возможности починки из GUI.

    Returns dict:
      platform, pkg_manager, pkg_manager_path, fw_type,
      nfqueue_available (модуль nfnetlink_queue),
      target_available (цель iptables NFQUEUE; None для nft/неизвестного),
      packages, install_command,
      can_auto_install (True только на настоящем OpenWrt с найденным менеджером),
      reason (почему нельзя авто-ставить — если can_auto_install=False),
      instructions (текстовая инструкция для ручной починки).
    """
    from core.diagnostics import _check_nfqueue_available

    platform = _platform_kind()
    kind, path = detect_pkg_manager()
    fw_type = _detect_fw_type()
    nfqueue_available = _check_nfqueue_available()
    target_available = _iptables_target_available(fw_type)
    packages = required_packages(fw_type)
    install_command = install_command_str(kind, packages)

    can_auto_install = (platform == "openwrt" and kind is not None)
    reason = ""
    instructions = ""
    if not can_auto_install:
        if platform in ("keenetic", "entware"):
            reason = ("На Keenetic/Entware модуль NFQUEUE приходит из прошивки, "
                      "а не из opkg (feed отвечает «Unknown package»).")
            instructions = (
                "Модуль NFQUEUE должен быть в прошивке. Установите/включите в "
                "прошивке компонент netfilter с поддержкой NFQUEUE (или "
                "используйте прошивку/образ, где он есть). Через opkg модули "
                "ядра на Keenetic не ставятся.")
        elif platform == "linux":
            reason = ("Обычный Linux: nfnetlink_queue обычно встроен в ядро "
                      "или поднимается modprobe.")
            instructions = (
                "Попробуйте загрузить модуль: modprobe nfnetlink_queue. Если "
                "модуля нет — доустановьте пакет ядра средствами вашего "
                "дистрибутива. В контейнере без netfilter обход невозможен.")
        else:
            reason = "Не найден системный пакетный менеджер (apk/opkg)."
            instructions = install_command or "Установите модуль NFQUEUE вручную."

    return {
        "platform": platform,
        "pkg_manager": kind,
        "pkg_manager_path": path,
        "fw_type": fw_type,
        "nfqueue_available": nfqueue_available,
        "target_available": target_available,
        "packages": packages,
        "install_command": install_command,
        "can_auto_install": can_auto_install,
        "reason": reason,
        "instructions": instructions,
    }


def nfqueue_fix_hint():
    """Компактная подсказка «как починить NFQUEUE» — для диагностики и лога.

    Безопасна на любой платформе. Поля: can_auto_install, platform,
    pkg_manager, command, log_line (одна строка для лога), note.
    """
    platform = _platform_kind()
    kind, _ = detect_pkg_manager()
    fw_type = _detect_fw_type()
    packages = required_packages(fw_type)

    if platform == "openwrt" and kind:
        cmd = install_command_str(kind, packages)
        return {
            "can_auto_install": True,
            "platform": platform,
            "pkg_manager": kind,
            "command": cmd,
            "log_line": ("Установите модули ядра: %s — или одной кнопкой в GUI: "
                         "Диагностика → Firewall → «Установить модули NFQUEUE»."
                         % cmd),
            "note": ("На OpenWrt модуль NFQUEUE (nfnetlink_queue) не входит в "
                     "прошивку по умолчанию."),
        }
    if platform in ("keenetic", "entware"):
        return {
            "can_auto_install": False,
            "platform": platform,
            "pkg_manager": kind,
            "command": "",
            "log_line": ("На Keenetic/Entware модуль NFQUEUE приходит из "
                         "прошивки, а не из opkg — включите соответствующий "
                         "компонент netfilter в прошивке."),
            "note": "Через opkg модули ядра на Keenetic не ставятся.",
        }
    return {
        "can_auto_install": False,
        "platform": platform,
        "pkg_manager": kind,
        "command": "modprobe nfnetlink_queue",
        "log_line": ("Загрузите модуль ядра: modprobe nfnetlink_queue "
                     "(в контейнере без netfilter обход невозможен)."),
        "note": "На обычном Linux nfnetlink_queue обычно встроен в ядро.",
    }


# ─────────────────────── фоновая установка ───────────────────────

_state = {"running": False, "progress": "", "result": None, "started_at": 0}
# Установка NFLOG — своим набором полей, но под ТЕМ ЖЕ замком: пакетный
# менеджер один, и две установки разом — это гонка за индекс пакетов.
_nflog_state = {"running": False, "progress": "", "result": None,
                "started_at": 0}
_states = {"nfqueue": _state, "nflog": _nflog_state}
_state_lock = threading.Lock()


def _run(cmd, timeout=180):
    """subprocess с таймаутом → (rc, out, err). rc=None при ошибке запуска."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except (FileNotFoundError, OSError) as e:
        return None, "", str(e)


def _set_progress(text, flavor="nfqueue"):
    with _state_lock:
        _states[flavor]["progress"] = text


def _do_install(kind, path, packages, flavor="nfqueue"):
    """Синхронная установка (вызывается из фонового потока)."""
    spec = _FLAVORS[flavor]
    verb = _install_verb(kind)
    log.info("Установка модулей %s (%s): %s"
             % (spec["title"], kind, " ".join(packages)), source="kmod")
    output = []

    # 1) обновляем индекс пакетов (нужна сеть)
    _set_progress("обновление индекса пакетов", flavor)
    rc_u, out_u, err_u = _run([path, "update"], timeout=120)
    output.append("$ %s update\n%s" % (kind, (out_u or "") + (err_u or "")))

    # 2) собственно установка
    _set_progress("установка пакетов", flavor)
    rc, out, err = _run([path, verb] + list(packages), timeout=180)
    output.append("$ %s %s %s\n%s"
                  % (kind, verb, " ".join(packages), (out or "") + (err or "")))
    install_ok = (rc == 0)

    # 3) best-effort подгружаем модуль сразу (без перезагрузки), если он ещё
    #    не активен. Пакеты OpenWrt обычно грузят kmod в postinst сами.
    _set_progress("загрузка модуля", flavor)
    modprobe = shutil.which("modprobe")
    if modprobe:
        _run([modprobe, spec["module"]], timeout=10)

    # 4) перепроверяем доступность — по признаку подсистемы, а не по rc
    after = spec["probe"]()

    ok = install_ok and after
    result = {
        "ok": ok,
        "install_ok": install_ok,
        "install_rc": rc,
        "available": after,
        "packages": list(packages),
        "pkg_manager": kind,
        "flavor": flavor,
        "needs_reboot": bool(install_ok and not after),
        "output": ("\n\n".join(output))[-6000:],
    }
    if flavor == "nfqueue":
        # имя поля с прежних времён: его читают тесты и старые клиенты
        result["nfqueue_available"] = after

    title = spec["title"]
    if ok:
        if flavor == "nfqueue":
            log.success("Модули NFQUEUE установлены, NFQUEUE доступен. "
                        "Перезапустите обход (стратегию), чтобы nfqws2 "
                        "поднялся.", source="kmod")
        else:
            log.success("Модуль NFLOG установлен — детектор geneva включится "
                        "на следующем срезе режима «Авто».", source="kmod")
    elif result["needs_reboot"]:
        log.warning("Пакеты установлены, но %s ещё не активен — обычно "
                    "помогает перезагрузка роутера." % title, source="kmod")
    else:
        log.error("Не удалось установить модули %s (rc=%s). Подробности "
                  "в выводе установки." % (title, rc), source="kmod")
    return result


def _deps_status(flavor):
    return nfqueue_deps_status() if flavor == "nfqueue" else nflog_deps_status()


def install_async(flavor="nfqueue"):
    """Запустить установку модулей в фоне. Один прогон за раз.

    Перед стартом сервер-сайд повторно проверяет can_auto_install — отказ на
    неподходящей платформе (Keenetic/Entware/Linux), чтобы кнопка из GUI не
    запустила заведомо бесполезный opkg на Keenetic.

    ``flavor``: ``"nfqueue"`` (nfqws2, по умолчанию) или ``"nflog"``
    (детектор geneva, режим «Авто»).
    """
    flavor = flavor if flavor in _FLAVORS else "nfqueue"
    state = _states[flavor]
    # Резервируем слот под локом СРАЗУ (running=True), до медленной проверки
    # статуса — иначе два быстрых POST могли бы оба пройти проверку «не идёт»
    # и запустить по потоку. Если платформа не подходит — откатываем флаг.
    with _state_lock:
        if any(s["running"] for s in _states.values()):
            return {"ok": False, "error": "Установка уже идёт"}
        state.update(running=True, progress="проверка платформы", result=None,
                     started_at=int(time.time()))

    status = _deps_status(flavor)
    if not status["can_auto_install"]:
        with _state_lock:
            state.update(running=False, progress="")
        return {"ok": False,
                "error": (status.get("reason")
                          or "Автоустановка недоступна на этой платформе"),
                "status": status}

    kind = status["pkg_manager"]
    path = status["pkg_manager_path"]
    packages = status["packages"]

    with _state_lock:
        state["progress"] = "запуск"

    def _worker():
        try:
            res = _do_install(kind, path, packages, flavor)
        except Exception as e:  # noqa: BLE001 — не роняем поток
            res = {"ok": False, "error": str(e)}
            log.error("Установка модулей %s прервана: %s"
                      % (_FLAVORS[flavor]["title"], e), source="kmod")
        with _state_lock:
            state["result"] = res
            state["running"] = False
            state["progress"] = ""

    threading.Thread(target=_worker, daemon=True, name="kmod-install").start()
    return {"ok": True, "started": True}


def install_status(flavor="nfqueue"):
    """Прогресс/результат фоновой установки (``flavor`` — см. install_async)."""
    state = _states[flavor if flavor in _FLAVORS else "nfqueue"]
    with _state_lock:
        return {
            "ok": True,
            "running": state["running"],
            "progress": state["progress"],
            "started_at": state["started_at"],
            "result": state["result"],
        }
