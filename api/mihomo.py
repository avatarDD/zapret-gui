# api/mihomo.py
"""
REST API для mihomo (Clash.Meta). По структуре повторяет api/singbox.py.

  GET    /api/mihomo/environment
  POST   /api/mihomo/environment/refresh
  GET    /api/mihomo/install/status
  POST   /api/mihomo/install               — body: {arch?, tag?, transport?}
  POST   /api/mihomo/install/local         — multipart: file (gz/tar.gz/ELF)
  GET    /api/mihomo/releases              — ?transport=&force=1
  POST   /api/mihomo/uninstall
  GET    /api/mihomo/version

  GET    /api/mihomo/configs
  POST   /api/mihomo/configs               — body: {name, text}
  GET    /api/mihomo/configs/<name>
  PUT    /api/mihomo/configs/<name>        — body: {text}
  DELETE /api/mihomo/configs/<name>
  POST   /api/mihomo/configs/<name>/up
  POST   /api/mihomo/configs/<name>/down
  POST   /api/mihomo/configs/<name>/restart
  GET    /api/mihomo/configs/<name>/status
  POST   /api/mihomo/configs/<name>/validate   — mihomo -t -f <file>

  GET    /api/mihomo/autostart
  POST   /api/mihomo/autostart/<name>      — body: {"enabled": bool}
  POST   /api/mihomo/autostart/regenerate
  POST   /api/mihomo/autostart/remove
  POST   /api/mihomo/autostart/apply
"""

import re
import threading
from bottle import request, response


INSTALL_API_WAIT = 8


def _str_list(v):
    """Нормализовать вход формы в список строк: массив либо строка
    (разделители — пробелы/запятые/переводы строк)."""
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        return [s.strip() for s in re.split(r"[\s,]+", v) if s.strip()]
    return []


def _load_cfg(name):
    """(mgr, res, cfg|None). res — ответ get_config; cfg — разобранный YAML."""
    from core.mihomo_manager import get_mihomo_manager
    from core.clash_yaml import parse_yaml
    mgr = get_mihomo_manager()
    res = mgr.get_config(name)
    if not res.get("ok"):
        return mgr, res, None
    try:
        cfg = parse_yaml(res.get("text") or "")
    except Exception:
        cfg = {}
    return mgr, res, (cfg if isinstance(cfg, dict) else {})


def _resolve_test_proxies(body):
    """
    Источник прокси для теста: имя конфига `config` (+ опц. `names`
    — подмножество). Возвращает (proxies|None, controller_ep|None).
    Полные proxy-dict'ы достаём из конфига (для одноразового движка);
    если конфиг запущен — отдаём ещё и его external-controller (тест
    идёт через уже поднятые узлы).
    """
    from core import mihomo_proxies as mp
    name = (body.get("config") or "").strip()
    if not name:
        return None, None
    mgr, res, cfg = _load_cfg(name)
    if not res.get("ok"):
        return [], None
    proxies = mp.list_proxies(cfg or {})
    names = body.get("names")
    if isinstance(names, list) and names:
        ns = {str(n) for n in names}
        proxies = [p for p in proxies if str(p.get("name")) in ns]
    ep = mp.external_controller_endpoint(cfg or {}) \
        if mgr.is_running(name) else None
    return proxies, ep


def register(app):

    # ─────── environment / install ────────────────────────────────

    @app.route("/api/mihomo/environment")
    def mihomo_environment():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_detector import get_mihomo_detector
        return get_mihomo_detector().get_environment_report()

    @app.route("/api/mihomo/environment/refresh", method="POST")
    def mihomo_environment_refresh():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_detector import get_mihomo_detector
        return get_mihomo_detector().get_environment_report(force=True)

    @app.route("/api/mihomo/install/status")
    def mihomo_install_status():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        return {"ok": True,
                "progress": get_mihomo_installer().get_operation_status()}

    @app.route("/api/mihomo/install", method="POST")
    def mihomo_install():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = (body.get("arch") or "").strip()
        tag  = (body.get("tag")  or "").strip()
        transport = (body.get("transport") or "").strip()

        from core.mihomo_installer import get_mihomo_installer
        installer = get_mihomo_installer()
        result_box = {}
        done = threading.Event()

        def _run():
            try:
                result_box["result"] = installer.install(
                    arch=arch, tag=tag, transport=transport)
            except Exception as e:
                result_box["result"] = {"ok": False, "error": str(e)}
            finally:
                done.set()

        threading.Thread(target=_run, daemon=True).start()
        if done.wait(timeout=INSTALL_API_WAIT):
            return result_box.get("result") or {"ok": False,
                                                "error": "no result"}
        return {"ok": True, "in_progress": True,
                "progress": installer.get_operation_status()}

    @app.route("/api/mihomo/install/local", method="POST")
    def mihomo_install_local():
        """Установка из локального файла: multipart-поле `file`."""
        response.content_type = "application/json; charset=utf-8"
        from api._install_upload import handle_single_upload
        from core.mihomo_installer import get_mihomo_installer
        return handle_single_upload(
            lambda path, name: get_mihomo_installer().install_local(
                path, orig_name=name))

    @app.route("/api/mihomo/releases")
    def mihomo_releases():
        """Список релизов MetaCubeX/mihomo для выбора версии."""
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        transport = (request.params.get("transport") or "").strip()
        force = request.params.get("force") in ("1", "true", "True")
        try:
            return get_mihomo_installer().list_releases(
                transport=transport, force=force)
        except Exception as e:
            response.status = 502
            return {"ok": False, "error": str(e)}

    @app.route("/api/mihomo/uninstall", method="POST")
    def mihomo_uninstall():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        try:
            return get_mihomo_installer().uninstall()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/mihomo/version")
    def mihomo_version():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_installer import get_mihomo_installer
        try:
            return get_mihomo_installer().check_for_updates()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── configs ──────────────────────────────────────────────

    @app.route("/api/mihomo/configs")
    def mihomo_configs():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return {"ok": True, "configs": get_mihomo_manager().list_configs()}

    @app.route("/api/mihomo/configs", method="POST")
    def mihomo_configs_create():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        text = body.get("text") or ""
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().save_config(name, text=text)

    @app.route("/api/mihomo/configs/<name>")
    def mihomo_configs_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().get_config(name)
        if not res.get("ok"):
            response.status = 404
        return res

    @app.route("/api/mihomo/configs/<name>", method="PUT")
    def mihomo_configs_put(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().save_config(name, text=body.get("text") or "")

    @app.route("/api/mihomo/configs/<name>", method="DELETE")
    def mihomo_configs_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().delete_config(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/mihomo/configs/<name>/up", method="POST")
    def mihomo_configs_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().up(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/mihomo/configs/<name>/down", method="POST")
    def mihomo_configs_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().down(name)

    @app.route("/api/mihomo/configs/<name>/restart", method="POST")
    def mihomo_configs_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().restart(name)

    @app.route("/api/mihomo/configs/<name>/status")
    def mihomo_configs_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return {"ok": True, "status": get_mihomo_manager().status(name)}

    @app.route("/api/mihomo/configs/<name>/validate", method="POST")
    def mihomo_configs_validate(name):
        response.content_type = "application/json; charset=utf-8"
        # Опциональный body {text}: проверить несохранённое содержимое
        # редактора. Без него — проверяется сохранённый на диск конфиг.
        try:
            body = request.json or {}
        except Exception:
            body = {}
        text = body.get("text") if isinstance(body, dict) else None
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().validate_via_binary(name, text=text)

    @app.route("/api/mihomo/configs/<name>/log")
    def mihomo_configs_log(name):
        """Хвост лог-файла инстанса — «видно, почему не работает»."""
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        try:
            lines = int(request.query.get("lines") or 200)
        except (TypeError, ValueError):
            lines = 200
        res = get_mihomo_manager().read_log(name, lines)
        if not res.get("ok"):
            response.status = 400
        return res

    # ─────── режим отладки ─────────────────────────────────────────

    @app.route("/api/mihomo/debug")
    def mihomo_debug_get():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_manager import get_mihomo_manager
        return get_mihomo_manager().get_debug()

    @app.route("/api/mihomo/debug", method="POST")
    def mihomo_debug_set():
        """Вкл/выкл режим отладки (log-level=debug при следующем запуске)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.mihomo_manager import get_mihomo_manager
        res = get_mihomo_manager().set_debug(bool(body.get("enabled")))
        if not res.get("ok"):
            response.status = 500
        return res

    # ─────── прокси-таблица ────────────────────────────────────────

    @app.route("/api/mihomo/configs/<name>/proxies")
    def mihomo_proxies_list(name):
        """
        Прокси конфига для таблицы: [{name,type,server,port}] + активный
        узел/группы из запущенного external-controller (если доступен).
        """
        response.content_type = "application/json; charset=utf-8"
        from core import mihomo_proxies as mp
        mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        running = mgr.is_running(name)
        ep = mp.external_controller_endpoint(cfg or {})
        active, groups, controller_live = "", [], False
        if running and ep:
            live = mp.controller_proxies(ep)
            if live.get("ok"):
                controller_live = True
                active = live.get("active") or ""
                groups = live.get("groups") or []
        return {"ok": True, "proxies": mp.proxy_rows(cfg or {}),
                "active": active, "groups": groups, "running": running,
                "controller": ep is not None,
                "controller_live": controller_live,
                "select_groups": mp.select_group_names(cfg or {})}

    @app.route("/api/mihomo/configs/<name>/activate", method="POST")
    def mihomo_configs_activate(name):
        """
        Пустить трафик через выбранный прокси: PUT /proxies/<group> на
        external-controller (живое переключение, как metacubexd). Требует
        запущенного инстанса с external-controller — у mihomo выбор узла
        хранится в рантайме, не в YAML.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        tag = (body.get("name") or body.get("tag") or "").strip()
        if not tag:
            response.status = 400
            return {"ok": False, "error": "Не указан прокси (name)"}
        from core import mihomo_proxies as mp
        mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        if not mgr.is_running(name):
            return {"ok": False, "needs_running": True, "error":
                    "Запустите конфиг — у mihomo прокси переключается на "
                    "лету через external-controller."}
        ep = mp.external_controller_endpoint(cfg or {})
        if not ep:
            return {"ok": False, "needs_controller": True, "error":
                    "У конфига нет external-controller — включите "
                    "управление кнопкой и перезапустите конфиг."}
        return mp.controller_activate(ep, tag)

    @app.route("/api/mihomo/configs/<name>/enable-controller",
               method="POST")
    def mihomo_enable_controller(name):
        """
        Идемпотентно добавить `external-controller` + `secret` в конфиг
        (нужно для учёта трафика, теста через движок и переключения).
        Свободный порт на 127.0.0.1, secret генерим. Если запущен —
        нужен перезапуск.
        """
        response.content_type = "application/json; charset=utf-8"
        import secrets as _secrets
        from core import mihomo_proxies as mp
        from core.proxy_tester import _free_port
        mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        ep = mp.external_controller_endpoint(cfg or {})
        if ep:
            return {"ok": True, "already": True, "port": ep["port"],
                    "running": mgr.is_running(name)}
        port = _free_port()
        new_text = mp.enable_external_controller_text(
            res.get("text") or "", "127.0.0.1", port, _secrets.token_hex(8))
        save = mgr.save_config(name, text=new_text)
        if not save.get("ok"):
            response.status = 500
            return save
        return {"ok": True, "port": port, "running": mgr.is_running(name),
                "needs_restart": mgr.is_running(name)}

    @app.route("/api/mihomo/configs/<name>/proxies/delete-bulk",
               method="POST")
    def mihomo_proxies_delete_bulk(name):
        """Удалить выбранные прокси (body: {names:[...]}). Round-trip —
        требует PyYAML (иначе отказ, чтобы не повредить конфиг)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        names = [str(n) for n in (body.get("names") or []) if n]
        if not names:
            response.status = 400
            return {"ok": False, "error": "Не переданы names"}
        from core import mihomo_proxies as mp
        mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        present = set(mp.proxy_names(cfg or {}))
        r = mp.safe_mutate(res.get("text") or "",
                           lambda c: mp.remove_proxies(c, names))
        if not r.get("ok"):
            # needs_pyyaml — это не ошибка сервера: 200 с понятным телом,
            # чтобы фронт показал подсказку (API.post бросает на не-2xx).
            response.status = 200 if r.get("needs_pyyaml") else 400
            return r
        save = mgr.save_config(name, text=r["text"])
        if not save.get("ok"):
            response.status = 500
            return save
        deleted = sorted(present & set(names))
        return {"ok": True, "deleted": deleted,
                "skipped": sorted(set(names) - present)}

    @app.route("/api/mihomo/configs/<name>/import-links", method="POST")
    def mihomo_import_links(name):
        """Вставка серверов из буфера (Ctrl+V): share-URI → clash-proxy,
        дозапись в `proxies:` (аддитивно, работает и без PyYAML)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        text_in = (body.get("text") or "").strip()
        if not text_in:
            response.status = 400
            return {"ok": False, "error": "Пустой текст"}
        from core.subscription_importer import extract_items
        from core.clash_yaml import uri_to_clash_proxy
        from core import mihomo_proxies as mp
        mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        new, errors = [], 0
        for it in extract_items(text_in):
            if not isinstance(it, dict) or it.get("type") != "uri":
                continue
            uri = it.get("value")
            if not uri:
                continue
            r = uri_to_clash_proxy(uri)
            if r.get("ok") and r.get("proxy"):
                new.append(r["proxy"])
            else:
                errors += 1
        if not new:
            return {"ok": False, "errors": errors,
                    "error": "Не нашлось валидных серверов в тексте"}
        existing = set(mp.proxy_names(cfg or {}))
        added, renamed = 0, 0
        for p in new:
            nm = str(p.get("name") or "proxy")
            if nm in existing:
                base, n = nm, 2
                while ("%s-%d" % (base, n)) in existing:
                    n += 1
                nm = "%s-%d" % (base, n)
                p["name"] = nm
                renamed += 1
            existing.add(nm)
            added += 1
        new_text = mp.append_proxies_text(res.get("text") or "", new)
        if new_text == (res.get("text") or ""):
            return {"ok": False, "error":
                    "Не удалось дописать прокси (нестандартный блок "
                    "proxies). Отредактируйте YAML вручную."}
        save = mgr.save_config(name, text=new_text)
        if not save.get("ok"):
            response.status = 500
            return save
        return {"ok": True, "added": added, "renamed": renamed,
                "errors": errors}

    @app.route("/api/mihomo/export-links", method="POST")
    def mihomo_export_links():
        """Копирование прокси в буфер (Ctrl+C): clash-proxy → share-URI.
        body: {config, names?}."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("config") or "").strip()
        if not name:
            response.status = 400
            return {"ok": False, "error": "Укажите config"}
        from core.clash_yaml import clash_proxy_to_uri
        from core import mihomo_proxies as mp
        _mgr, res, cfg = _load_cfg(name)
        if not res.get("ok"):
            response.status = 404
            return res
        proxies = mp.list_proxies(cfg or {})
        names = body.get("names")
        if isinstance(names, list) and names:
            ns = {str(n) for n in names}
            proxies = [p for p in proxies if str(p.get("name")) in ns]
        links = [u for u in (clash_proxy_to_uri(p) for p in proxies) if u]
        return {"ok": True, "text": "\n".join(links), "count": len(links)}

    # ─────── маршрутизация (домены / устройства / весь трафик) ──────

    @app.route("/api/mihomo/routing/options")
    def mihomo_routing_options():
        """Данные для формы маршрутизации: версия, gvisor, списки, конфиги."""
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_routing import build_options
        return build_options()

    @app.route("/api/mihomo/routing/domain/build", method="POST")
    def mihomo_routing_domain_build():
        """Собрать+сохранить конфиг доменной маршрутизации (проверка mihomo -t).
        body: name, proxy_link|proxy_config, hostlists[], lists[], domains[],
        cidrs[], route_all, stack, mtu, reject_quic, group_type."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.mihomo_routing import build_domain_route_and_save
        res = build_domain_route_and_save(
            name=(body.get("name") or "mihomo-domains"),
            proxy_link=(body.get("proxy_link") or ""),
            proxy_config=(body.get("proxy_config") or ""),
            hostlists=_str_list(body.get("hostlists")),
            lists=_str_list(body.get("lists")),
            domains=_str_list(body.get("domains")),
            cidrs=_str_list(body.get("cidrs")),
            route_all=bool(body.get("route_all")),
            stack=(body.get("stack") or ""),
            mtu=int(body.get("mtu") or 1500),
            reject_quic=bool(body.get("reject_quic")),
            group_type=(body.get("group_type") or "select"),
        )
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/mihomo/routing/source/build", method="POST")
    def mihomo_routing_source_build():
        """Собрать+сохранить конфиг по устройствам / весь трафик (kernel-стек).
        body: name, proxy_link|proxy_config, source_ips[], route_all, stack,
        mtu, reject_quic, group_type."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.mihomo_routing import build_source_route_and_save
        res = build_source_route_and_save(
            name=(body.get("name") or "mihomo-devices"),
            proxy_link=(body.get("proxy_link") or ""),
            proxy_config=(body.get("proxy_config") or ""),
            source_ips=_str_list(body.get("source_ips")),
            route_all=bool(body.get("route_all")),
            stack=(body.get("stack") or ""),
            mtu=int(body.get("mtu") or 1500),
            reject_quic=bool(body.get("reject_quic")),
            group_type=(body.get("group_type") or "select"),
        )
        if not res.get("ok"):
            response.status = 400
        return res

    # ─────── watchdog (проверка соединения) ─────────────────────────

    @app.route("/api/mihomo/watchdog")
    def mihomo_watchdog_get():
        response.content_type = "application/json; charset=utf-8"
        try:
            from core.mihomo_watchdog import get_watchdog
            return {"ok": True, "status": get_watchdog().get_status()}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/mihomo/watchdog", method="POST")
    def mihomo_watchdog_set():
        """Изменить настройки watchdog'а (любое подмножество полей)."""
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        try:
            from core.mihomo_watchdog import set_settings, get_watchdog
            new = set_settings(**{k: body.get(k) for k in (
                "enabled", "check_interval_sec", "cooldown_sec",
                "max_restarts_per_hour", "probe_target",
                "probe_timeout_ms", "probe_fail_threshold") if k in body})
            return {"ok": True, "status": get_watchdog().get_status(),
                    "settings": new}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── tester / traffic ──────────────────────────────────────

    @app.route("/api/mihomo/test", method="POST")
    def mihomo_test_start():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        proxies, ep = _resolve_test_proxies(body)
        if proxies is None:
            response.status = 400
            return {"ok": False, "error": "Укажите config"}
        if not proxies:
            return {"ok": False, "error": "Не нашлось прокси для теста"}
        target = (body.get("target") or "cloudflare").strip()
        try:
            timeout_ms = int(body.get("timeout_ms") or 5000)
        except (TypeError, ValueError):
            timeout_ms = 5000
        from core.mihomo_proxy_tester import get_mihomo_test_job
        from core.mihomo_detector import get_mihomo_detector
        binary = get_mihomo_detector().detect_binary().get("path", "")
        started = get_mihomo_test_job().start(
            proxies, target=target, timeout_ms=timeout_ms,
            controller=ep, binary=binary)
        if not started:
            return {"ok": False, "running": True,
                    "error": "Тест уже выполняется"}
        return {"ok": True, "started": True, "count": len(proxies)}

    @app.route("/api/mihomo/test/status")
    def mihomo_test_status():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_proxy_tester import get_mihomo_test_job
        from core.proxy_tester import TARGET_PRESETS
        st = get_mihomo_test_job().status()
        st["ok"] = True
        st["targets"] = list(TARGET_PRESETS.keys())
        return st

    @app.route("/api/mihomo/traffic")
    def mihomo_traffic():
        """Кумулятивный трафик per-proxy {name:{up,down}} (?config=<name>
        — фильтр по тегам конфига + сообщить про external-controller)."""
        response.content_type = "application/json; charset=utf-8"
        from core.proxy_traffic import get_mihomo_traffic_tracker
        from core import mihomo_proxies as mp
        tracker = get_mihomo_traffic_tracker()
        tracker.ensure_running()
        name = (request.query.get("config") or "").strip()
        tags, controller, running = None, None, None
        if name:
            mgr, res, cfg = _load_cfg(name)
            if res.get("ok"):
                tags = mp.proxy_names(cfg or {})
                controller = mp.external_controller_endpoint(
                    cfg or {}) is not None
                running = mgr.is_running(name)
        return {"ok": True, "traffic": tracker.snapshot(tags),
                "controller": controller, "running": running}

    # ─────── autostart ────────────────────────────────────────────

    @app.route("/api/mihomo/autostart")
    def mihomo_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import status
        return {"ok": True, "status": status()}

    @app.route("/api/mihomo/autostart/<name>", method="POST")
    def mihomo_autostart_set(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        enabled = bool(body.get("enabled", False))
        from core.mihomo_autostart import set_autostart, regenerate
        r = set_autostart(name, enabled)
        if r.get("ok"):
            regenerate()
        return r

    @app.route("/api/mihomo/autostart/regenerate", method="POST")
    def mihomo_autostart_regen():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import regenerate
        return regenerate()

    @app.route("/api/mihomo/autostart/remove", method="POST")
    def mihomo_autostart_remove():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import remove
        return remove()

    @app.route("/api/mihomo/autostart/apply", method="POST")
    def mihomo_autostart_apply():
        response.content_type = "application/json; charset=utf-8"
        from core.mihomo_autostart import apply_now
        return apply_now()
