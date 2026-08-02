# api/usque.py
"""
API-модуль управления WARP/MASQUE (usque).

Эндпоинты:
  GET  /api/usque/environment  — детект бинарника
  GET  /api/usque/version      — версия + проверка обновлений
  POST /api/usque/register     — регистрация WARP-сессии
  GET  /api/usque/configs      — список профилей
  POST /api/usque/configs/<name>/up    — старт туннеля
  POST /api/usque/configs/<name>/down  — стоп
  GET  /api/usque/configs/<name>/status
  POST /api/usque/configs/<name>/remove
"""

import os
import re

from bottle import request

from core.log_buffer import log

# Тег релиза уходит в URL GitHub API — пускать туда произвольную строку
# (слэши, «..») нельзя.
_re_tag = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _version_from_tag(tag: str) -> str:
    """usque-bin-v4.2.1 → 4.2.1 (тэг нашей сборки кодирует версию usque)."""
    t = str(tag or "").strip()
    for prefix in ("usque-bin-", "usque-"):
        if t.startswith(prefix):
            t = t[len(prefix):]
            break
    return t.lstrip("vV")


def _remember_installed_tag(res: dict) -> None:
    """Запомнить тег установленного ПАКЕТА usque-keenetic.

    Версия, которую печатает сам бинарник (`usque version` → 4.2.0), и тег
    пакета (v0.3.0) — разные вещи, и сравнивать их между собой бессмысленно.
    Тег известен только здесь, в момент установки; без него /api/usque/version
    не может честно ответить, есть ли обновление.
    """
    tag = str(res.get("tag") or res.get("version") or "").strip()
    if not tag:
        return
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("usque", "installed_tag", tag)
        cfg.save()
    except Exception as e:
        log.warning("usque: не удалось сохранить installed_tag: %s" % e,
                    source="usque")


def register(app):
    """Зарегистрировать API-маршруты usque в Bottle-приложении."""

    @app.route("/api/usque/environment", method="GET")
    def usque_environment():
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        env = mgr.detect()

        # Проверяем наличие usque-keenetic в opkg (для установки).
        # `opkg info <неизвестный-пакет>` завершается с кодом 0 и пустым
        # выводом, поэтому по коду возврата судить нельзя — нужен
        # непосредственно заголовок "Package:" в stdout.
        opkg_available = False
        try:
            import subprocess
            r = subprocess.run(["opkg", "info", "usque-keenetic"],
                               capture_output=True, text=True, timeout=5)
            opkg_available = (r.returncode == 0
                              and "package:" in (r.stdout or "").lower())
        except Exception:
            pass

        env["opkg_available"] = opkg_available

        # Платформа / TUN / firewall для карточки «Окружение» (SetupUI).
        # Свойства хоста (kind/firewall/TUN) не специфичны для AWG —
        # переиспользуем общий детектор платформы.
        try:
            from core.awg_detector import get_awg_detector
            plat = get_awg_detector().detect_platform().as_dict()
            # binary_dir у usque свой — поправим косметику (expert-only).
            plat["binary_dir"] = (os.path.dirname(env["binary"])
                                  if env.get("binary") else "/opt/usr/bin")
            env["platform"] = plat
            env["tun"] = {"available": bool(plat.get("tun_available"))}
        except Exception as e:
            env.setdefault("platform", {})
            env.setdefault("tun", {"available": False})
            env["platform_error"] = str(e)

        # SetupUI (usque_setup.js) ждёт binary как объект {installed, version,
        # path}, а не строку-путь — иначе страница установки всегда показывает
        # «не установлен». Плоские installed/version/arch сохраняем: их читает
        # основная страница usque.js. binary_dir выше вычислен по строке-пути.
        #
        # binary.version — версия самого usque (4.2.1). SetupUI сравнивает
        # её с «В релизе», а там теперь версия из тэга НАШЕЙ сборки
        # (usque-bin-v4.2.1) — то есть то же пространство нумерации.
        # Раньше «В релизе» брался из тэга стороннего пакета (v0.3.0), и
        # сравнение версий из разных систем давало вечное «доступно
        # обновление».
        bin_path = env.get("binary") if isinstance(env.get("binary"), str) else ""
        try:
            from core.config_manager import get_config_manager
            installed_tag = get_config_manager().get(
                "usque", "installed_tag", default="") or ""
        except Exception:
            installed_tag = ""
        env["binary"] = {
            "installed": bool(env.get("installed")),
            "version": env.get("version", ""),
            "tag": installed_tag,
            "path": bin_path,
        }
        env["ready"] = bool(env.get("installed"))
        return env

    @app.route("/api/usque/version", method="GET")
    def usque_version():
        from core.usque_manager import get_usque_manager
        from core.config_manager import get_config_manager
        mgr = get_usque_manager()
        env = mgr.detect()
        cfg = get_config_manager()
        # Теперь usque собираем мы сами, и тэг релиза кодирует версию
        # самого usque (usque-bin-v4.2.1). Поэтому «установлено» и
        # «в релизе» — величины ОДНОГО пространства, и их сравнение
        # наконец осмысленно. Раньше сравнивались версия движка (4.2.0) и
        # тэг стороннего пакета usque-keenetic (v0.3.0) — числа из разных
        # систем нумерации, и «доступно обновление» горело всегда.
        installed_ver = env.get("version", "")
        latest_tag, latest_ver = "", ""
        try:
            from core.ext_binary_installer import list_releases
            rels = list_releases("usque")
            if rels.get("ok") and rels.get("releases"):
                latest_tag = rels["releases"][0]["tag"]
                latest_ver = _version_from_tag(latest_tag)
        except Exception as e:
            # Нет сети — молчим про обновления, а не выдумываем их.
            log.debug("usque version: список релизов недоступен: %s" % e,
                      source="usque")

        def _norm(v):
            return str(v or "").strip().lstrip("vV")

        has_update = bool(latest_ver and installed_ver
                          and _norm(latest_ver) != _norm(installed_ver))
        return {
            "ok": True,
            "installed": {
                "installed": bool(env.get("installed")),
                "version": installed_ver,
                "arch": env.get("arch", ""),
                "tag": cfg.get("usque", "installed_tag", default="") or "",
            },
            "latest": {"tag": latest_tag, "version": latest_ver},
            "has_update": has_update,
            "installed_tag": cfg.get("usque", "installed_tag",
                                     default="") or "",
        }

    @app.route("/api/usque/register", method="POST")
    def usque_register():
        import re
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        data = request.json or {}
        config_name = data.get("name", "warp-default")

        # MR-08: валидация config_name против path-traversal → root RCE
        # config_name="../../etc/init.d/S99evil" → usque пишет .conf туда
        # → S99* автозапускается при буте → RCE
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", config_name):
            return {"ok": False, "error": "Недопустимое имя конфига (только a-z A-Z 0-9 _ -)"}

        config_dir = mgr._config_dir()
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "%s.conf" % config_name)

        # Дополнительная проверка через realpath (защита от symlink-атак)
        real_config_dir = os.path.realpath(config_dir)
        real_config_path = os.path.realpath(config_path)
        if not real_config_path.startswith(real_config_dir + os.sep):
            return {"ok": False, "error": "path traversal denied"}

        device_name = str(data.get("device_name") or "").strip()[:64]
        if device_name and not re.match(r"^[\w .:-]{1,64}$", device_name,
                                        re.UNICODE):
            return {"ok": False, "error": "Недопустимое имя устройства"}
        team_token = str(data.get("team_token") or "").strip()

        # Через что идти к api.cloudflareclient.com. Там, где провайдер
        # режет его напрямую, это единственный способ вообще получить
        # сессию — но обход на роутере обычно уже поднят.
        transport = str(data.get("transport") or "").strip()
        if transport:
            from core.download_transport import is_valid_spec
            if not is_valid_spec(transport):
                return {"ok": False,
                        "error": "Неизвестный транспорт: %s" % transport}

        return mgr.register(config_path, device_name=device_name,
                            team_token=team_token, transport=transport)

    @app.route("/api/usque/configs/import", method="POST")
    def usque_config_import():
        """
        Импорт ГОТОВОГО usque-конфига (JSON).

        Конфиги AmneziaWG сюда не подходят и подойти не могут: usque —
        клиент MASQUE (HTTP/3), а не WireGuard, и ключи у них разных
        алгоритмов. Понятное сообщение об этом отдаёт import_config().
        """
        import re as _re
        from core.usque_manager import get_usque_manager
        data = request.json or {}
        name = str(data.get("name") or "").strip()
        if not _re.match(r"^[A-Za-z0-9_-]{1,64}$", name):
            return {"ok": False,
                    "error": "Недопустимое имя конфига (только a-z A-Z 0-9 _ -)"}
        return get_usque_manager().import_config(name,
                                                 str(data.get("text") or ""))

    # ─────── настройки ───────
    #
    # До появления этих эндпоинтов usque.enabled / usque.autostart /
    # usque.watchdog.* нельзя было выставить из GUI вообще, хотя именно от
    # них зависят автоподъём туннеля после перезагрузки
    # (_apply_usque_autostart_on_boot требует enabled И autostart) и
    # сторожевой перезапуск. Оба по умолчанию false — то есть обещанные в
    # справке автозапуск и watchdog были недостижимы.

    _TRANSPORT_PROFILES = ("performance", "restricted", "auto")

    def _usque_settings_payload(cfg):
        wd = cfg.get("usque", "watchdog", default={}) or {}
        return {
            "enabled": bool(cfg.get("usque", "enabled", default=False)),
            "autostart": bool(cfg.get("usque", "autostart", default=False)),
            "default_sni": cfg.get("usque", "default_sni", default="") or "",
            "transport_profile": cfg.get("usque", "transport_profile",
                                         default="performance"),
            "http2_enable": bool(cfg.get("usque", "http2_enable",
                                         default=False)),
            "watchdog": {
                "enabled": bool(wd.get("enabled", False)),
                "interval_sec": int(wd.get("interval_sec", 60) or 60),
                "probe_host": wd.get("probe_host", "1.1.1.1") or "1.1.1.1",
                "probe_port": int(wd.get("probe_port", 443) or 443),
            },
        }

    @app.route("/api/usque/settings", method="GET")
    def usque_settings_get():
        from core.config_manager import get_config_manager
        return {"ok": True, "settings": _usque_settings_payload(
            get_config_manager())}

    @app.route("/api/usque/settings", method="POST")
    def usque_settings_set():
        import re as _re
        from core.config_manager import get_config_manager
        try:
            body = request.json or {}
        except Exception:
            body = {}
        cfg = get_config_manager()

        for key in ("enabled", "autostart", "http2_enable"):
            if key in body:
                cfg.set("usque", key, bool(body[key]))

        if "transport_profile" in body:
            prof = str(body.get("transport_profile") or "").strip()
            if prof not in _TRANSPORT_PROFILES:
                return {"ok": False,
                        "error": "transport_profile: допустимы %s"
                                 % ", ".join(_TRANSPORT_PROFILES)}
            cfg.set("usque", "transport_profile", prof)

        if "default_sni" in body:
            sni = str(body.get("default_sni") or "").strip()
            # Пустая строка = «не маскировать». Иначе — доменное имя:
            # оно уходит в usque как `-s <sni>`, мусор там бесполезен.
            if sni and not _re.match(
                    r"^(?=.{1,253}$)[A-Za-z0-9]"
                    r"(?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$",
                    sni):
                return {"ok": False,
                        "error": "SNI должен быть доменным именем"
                                 " (например ozon.ru) или пустым"}
            cfg.set("usque", "default_sni", sni)

        wd = body.get("watchdog")
        if isinstance(wd, dict):
            if "enabled" in wd:
                cfg.set("usque", "watchdog", "enabled", bool(wd["enabled"]))
            if "interval_sec" in wd:
                try:
                    iv = int(wd["interval_sec"])
                except (TypeError, ValueError):
                    return {"ok": False,
                            "error": "interval_sec должен быть числом"}
                cfg.set("usque", "watchdog", "interval_sec",
                        max(10, min(iv, 3600)))
            if "probe_host" in wd:
                cfg.set("usque", "watchdog", "probe_host",
                        str(wd["probe_host"] or "").strip() or "1.1.1.1")
            if "probe_port" in wd:
                try:
                    port = int(wd["probe_port"])
                except (TypeError, ValueError):
                    return {"ok": False,
                            "error": "probe_port должен быть числом"}
                if not 1 <= port <= 65535:
                    return {"ok": False,
                            "error": "probe_port вне диапазона 1..65535"}
                cfg.set("usque", "watchdog", "probe_port", port)

        cfg.save()

        # Watchdog сам решит, запускаться ему или останавливаться:
        # он смотрит и usque.enabled, и usque.watchdog.enabled.
        try:
            from core.usque_watchdog import get_usque_watchdog
            get_usque_watchdog().reconfigure()
        except Exception as e:
            log.warning("usque settings: watchdog reconfigure: %s" % e,
                        source="usque")

        return {"ok": True, "settings": _usque_settings_payload(cfg)}

    @app.route("/api/usque/debug", method="GET")
    def usque_debug_get():
        from core.usque_manager import debug_enabled
        return {"ok": True, "enabled": debug_enabled()}

    @app.route("/api/usque/debug", method="POST")
    def usque_debug_set():
        from core.config_manager import get_config_manager
        try:
            body = request.json or {}
        except Exception:
            body = {}
        cfg = get_config_manager()
        cfg.set("usque", "debug_log", bool(body.get("enabled")))
        cfg.save()
        from core.usque_manager import debug_enabled
        return {"ok": True, "enabled": debug_enabled(),
                "note": "Глубина буфера меняется при следующем запуске"
                        " туннеля"}

    @app.route("/api/usque/configs/<name>/log", method="GET")
    def usque_config_log(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        target = next((c for c in mgr.list_configs()
                       if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}
        if not target.get("iface"):
            return {"ok": True, "iface": "", "log": "", "captured": 0,
                    "message": "Туннель не запускался в этом сеансе GUI"}
        try:
            lines = int(request.query.get("lines") or 200)
        except (TypeError, ValueError):
            lines = 200
        return mgr.read_log(target["iface"], lines=lines)

    @app.route("/api/usque/watchdog/status", method="GET")
    def usque_watchdog_status():
        try:
            from core.usque_watchdog import get_usque_watchdog
            return {"ok": True, "status": get_usque_watchdog().get_status()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    @app.route("/api/usque/configs", method="GET")
    def usque_configs():
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()
        return {"ok": True, "configs": mgr.list_configs()}

    @app.route("/api/usque/configs/<name>/up", method="POST")
    def usque_config_up(name):
        from core.usque_manager import get_usque_manager
        from core.config_manager import get_config_manager
        mgr = get_usque_manager()
        cfg = get_config_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        sni = cfg.get("usque", "default_sni", default="")
        http2 = cfg.get("usque", "http2_enable", default=False)
        iface = target.get("iface") or mgr.allocate_iface("opkgtun")
        if not iface:
            return {"ok": False, "error": "Не удалось выделить интерфейс usque"}
        profile = "restricted" if http2 else cfg.get(
            "usque", "transport_profile", default="performance")
        return mgr.start(iface, target["path"],
                         sni=sni, transport_profile=profile)

    @app.route("/api/usque/configs/<name>/down", method="POST")
    def usque_config_down(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        if not target.get("iface"):
            return {"ok": True, "message": "уже остановлен"}
        return mgr.stop(target["iface"])

    @app.route("/api/usque/configs/<name>/status", method="GET")
    def usque_config_status(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        if not target.get("iface"):
            return {"running": False, "iface": "", "pid": None,
                    "iface_exists": False, "diagnostic": ""}
        return mgr.status(target["iface"])

    @app.route("/api/usque/configs/<name>/remove", method="POST")
    def usque_config_remove(name):
        from core.usque_manager import get_usque_manager
        mgr = get_usque_manager()

        configs = mgr.list_configs()
        target = next((c for c in configs if c["name"] == name), None)
        if not target:
            return {"ok": False, "error": "Конфиг '%s' не найден" % name}

        # Останавливаем если активен
        if target["active"]:
            mgr.stop(target["iface"])

        # Удаляем файл
        try:
            if os.path.isfile(target["path"]):
                os.remove(target["path"])
        except Exception as e:
            return {"ok": False, "error": str(e)}

        return {"ok": True}

    @app.route("/api/usque/environment/refresh", method="POST")
    def usque_environment_refresh():
        return usque_environment()

    @app.route("/api/usque/install/status", method="GET")
    def usque_install_status():
        from core.ext_binary_installer import get_operation_status
        return {"ok": True, "progress": get_operation_status("usque")}

    @app.route("/api/usque/releases", method="GET")
    def usque_releases():
        """Список релизов usque-keenetic — для выбора версии в SetupUI.

        Без этого маршрута страница установки показывала «список релизов
        недоступен: method not allowed» и выбрать версию было нельзя.
        """
        from core.ext_binary_installer import list_releases
        transport = (request.params.get("transport") or "").strip()
        force = request.params.get("force") in ("1", "true", "True")
        try:
            return list_releases("usque", transport=transport, force=force)
        except Exception as e:
            return {"ok": False, "error": str(e)}

    @app.route("/api/usque/install", method="POST")
    def usque_install():
        import threading
        from core.ext_binary_installer import install_binary_by_name, _operation_status

        try:
            body = request.json or {}
        except Exception:
            body = {}
        tag = str(body.get("tag") or "").strip()
        transport = str(body.get("transport") or "").strip()
        if tag and not _re_tag.match(tag):
            return {"ok": False, "error": "Недопустимый тег релиза"}
        if transport:
            from core.download_transport import is_valid_spec
            if not is_valid_spec(transport):
                return {"ok": False,
                        "error": "Неизвестный транспорт: %s" % transport}

        name = "usque"
        _operation_status[name] = {"status": "starting", "progress": 0, "message": "Запуск установки..."}

        def _cb(stage, pct, label):
            _operation_status[name] = {"status": stage, "progress": pct, "message": label}

        def _run():
            try:
                res = install_binary_by_name(name, progress_cb=_cb, tag=tag,
                                             transport=transport)
                if res.get("ok"):
                    _remember_installed_tag(res)
                    _operation_status[name] = {"status": "done", "progress": 100, "message": "Установка завершена"}
                else:
                    _operation_status[name] = {"status": "error", "progress": 0, "message": res.get("error", "Ошибка")}
            except Exception as e:
                _operation_status[name] = {"status": "error", "progress": 0, "message": str(e)}

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "progress": _operation_status[name]}

    @app.route("/api/usque/install/local", method="POST")
    def usque_install_local():
        """Установка из локального файла (.ipk) — multipart-поле `file`.

        Нужна ровно тем, у кого GitHub недоступен и туннеля для обхода
        ещё нет: скачать пакет можно на другом устройстве.
        """
        from api._install_upload import handle_single_upload
        from core.ext_binary_installer import install_local_file

        def _install(path, orig_name):
            res = install_local_file("usque", path, orig_name)
            if res.get("ok"):
                _remember_installed_tag(res)
            return res

        return handle_single_upload(_install)

    @app.route("/api/usque/uninstall", method="POST")
    def usque_uninstall():
        from core.ext_binary_installer import uninstall_binary
        return uninstall_binary("usque")
