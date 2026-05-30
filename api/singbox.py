# api/singbox.py
"""
REST API для sing-box.

Маршруты (по аналогии с api/awg.py):

  GET    /api/singbox/environment           — полный отчёт об окружении
  POST   /api/singbox/environment/refresh   — сбросить кэш

  GET    /api/singbox/manifest              — manifest.json релиза
  GET    /api/singbox/install/status        — прогресс текущей операции
  POST   /api/singbox/install               — установить бинарь
  POST   /api/singbox/uninstall             — удалить бинарь
  GET    /api/singbox/version               — установленная версия + апдейт

  GET    /api/singbox/configs               — список конфигов
  POST   /api/singbox/configs               — создать (body: name, text|parsed)
  GET    /api/singbox/configs/<name>        — получить конфиг
  PUT    /api/singbox/configs/<name>        — сохранить
  DELETE /api/singbox/configs/<name>        — удалить
  POST   /api/singbox/configs/<name>/up
  POST   /api/singbox/configs/<name>/down
  POST   /api/singbox/configs/<name>/restart
  GET    /api/singbox/configs/<name>/status
  POST   /api/singbox/configs/<name>/validate  — sing-box check -c <file>
  POST   /api/singbox/configs/<name>/wrap      — обернуть outbound'ы в
                                                  selector/urltest

  GET    /api/singbox/configs/<name>/outbounds       — список outbound'ов
  POST   /api/singbox/configs/<name>/outbounds       — добавить
                                                       (body: {_form, ...} или raw)
  PUT    /api/singbox/configs/<name>/outbounds/<tag> — обновить
  DELETE /api/singbox/configs/<name>/outbounds/<tag> — удалить

  GET    /api/singbox/transparent/status    — доступность + сохранённые
                                                настройки прозрач. проксир.
  POST   /api/singbox/transparent/apply     — поднять firewall TProxy/
                                                Redirect/Hybrid
  POST   /api/singbox/transparent/remove    — снять firewall-правила
  POST   /api/singbox/configs/<name>/transparent-inbounds
                                              — вставить transparent-
                                                inbound'ы в конфиг

  GET    /api/singbox/autostart             — статус автозапуска
  POST   /api/singbox/autostart/<name>      — body: {"enabled": bool}
  POST   /api/singbox/autostart/regenerate
  POST   /api/singbox/autostart/remove
  POST   /api/singbox/autostart/apply

  GET    /api/singbox/subscriptions         — список сохранённых подписок
  POST   /api/singbox/subscriptions         — добавить подписку
                                                (name, url, format, interval_hours)
  PUT    /api/singbox/subscriptions/<id>    — обновить настройки подписки
  DELETE /api/singbox/subscriptions/<id>    — удалить подписку
  POST   /api/singbox/subscriptions/<id>/refresh — force-refresh одной
  POST   /api/singbox/subscriptions/refresh-all  — force-refresh всех

  GET    /api/singbox/pool                  — пул серверов: настройки,
                                                источники, пресеты, статус
  POST   /api/singbox/pool/settings         — настройки пула
                                                (interval/cap/group/target/
                                                 health_filter)
  POST   /api/singbox/pool/sources          — добавить источник
  PUT    /api/singbox/pool/sources/<sid>    — обновить (enabled/name/url)
  DELETE /api/singbox/pool/sources/<sid>    — удалить источник
  POST   /api/singbox/pool/refresh          — пересобрать пул (async job)
  GET    /api/singbox/pool/refresh/status   — прогресс/результат сборки

  POST   /api/singbox/test                  — тест серверов (body: config |
                                                outbounds | url; target,
                                                timeout_ms) — запуск
  GET    /api/singbox/test/status           — прогресс/результат теста
"""

import threading
from bottle import request, response


# Сколько ждать в HTTP-запросе install перед тем как вернуть in_progress
INSTALL_API_WAIT = 8


# ════════════════════════════════════════════════════════════
# helpers для outbounds CRUD
# ════════════════════════════════════════════════════════════

def _modify_outbounds(name: str, mutate):
    """
    Обёртка над «прочитать конфиг → mutate(outbounds) → сохранить».

    mutate(outbounds: list) → может вернуть dict с error/result либо
    None (тогда считаем успешным).
    """
    from bottle import response
    from core.singbox_manager import get_singbox_manager
    from core.singbox_config import render_conf

    mgr = get_singbox_manager()
    cfg_resp = mgr.get_config(name)
    if not cfg_resp.get("ok"):
        response.status = 404
        return cfg_resp
    cfg = cfg_resp.get("parsed") or {}
    obs = cfg.get("outbounds") or []
    if not isinstance(obs, list):
        response.status = 400
        return {"ok": False, "error": "outbounds — не массив"}

    try:
        res = mutate(obs)
    except ValueError as e:
        response.status = 400
        return {"ok": False, "error": str(e)}
    if isinstance(res, dict) and res.get("error"):
        # Если конкретная mutate-функция знает какой статус нужен —
        # она может вернуть {"_status": 404, "error": "..."}.
        status = res.pop("_status", 400)
        response.status = status
        res.setdefault("ok", False)
        return res

    cfg["outbounds"] = obs
    save = mgr.save_config(name, text=render_conf(cfg))
    if not save.get("ok"):
        response.status = 500
        return save
    return {"ok": True, "outbounds_count": len(obs)}


def _do_add(obs: list, outbound: dict):
    """Добавить outbound в список — проверяем уникальность tag'а."""
    tag = outbound.get("tag")
    if not tag:
        return {"_status": 400, "error": "tag обязателен"}
    if any(isinstance(o, dict) and o.get("tag") == tag for o in obs):
        return {"_status": 409, "error":
                "outbound с tag '%s' уже существует" % tag}
    obs.append(outbound)
    return None


def _do_replace(obs: list, old_tag: str, outbound: dict):
    new_tag = outbound.get("tag")
    idx = next((i for i, o in enumerate(obs)
                if isinstance(o, dict) and o.get("tag") == old_tag), -1)
    if idx < 0:
        return {"_status": 404,
                "error": "outbound '%s' не найден" % old_tag}
    # Если tag меняется — проверяем чтобы не было коллизии с другим.
    if new_tag and new_tag != old_tag:
        for j, o in enumerate(obs):
            if j != idx and isinstance(o, dict) and o.get("tag") == new_tag:
                return {"_status": 409,
                        "error": "outbound с tag '%s' уже существует"
                                  % new_tag}
    obs[idx] = outbound
    return None


def _do_delete(obs: list, tag: str):
    idx = next((i for i, o in enumerate(obs)
                if isinstance(o, dict) and o.get("tag") == tag), -1)
    if idx < 0:
        return {"_status": 404, "error": "outbound '%s' не найден" % tag}
    # Защита: если этот tag используется в route.rules — не даём
    # удалить, иначе sing-box упадёт при старте. Эту проверку
    # делаем в caller (где есть cfg целиком), но здесь просто
    # удаляем; caller увидит ошибку sing-box-check при save.
    obs.pop(idx)
    return None


# Маппинг _form-имя → builder. Все builders определены в
# core/singbox_config.py.
def _build_outbound_from_body(body: dict) -> dict:
    """
    Если в body есть `_form: vless|trojan|...` — собрать outbound
    через builder. Иначе считаем, что body — уже готовый sing-box
    outbound dict (с минимальной валидацией).
    """
    form = (body.get("_form") or "").lower().strip()
    if not form:
        # Сырой outbound. Минимальная валидация — должны быть type+tag.
        if not body.get("type") or not body.get("tag"):
            raise ValueError("type и tag обязательны")
        return _strip_form_keys(body)

    from core.singbox_config import (
        make_vless_outbound, make_trojan_outbound,
        make_shadowsocks_outbound, make_hysteria2_outbound,
        make_tuic_outbound,
    )

    tag    = (body.get("tag") or "").strip()
    server = (body.get("server") or "").strip()
    try:
        port = int(body.get("port") or 0)
    except (TypeError, ValueError):
        raise ValueError("port — не число")
    if not tag or not server or not port:
        raise ValueError("tag, server и port обязательны")

    if form == "vless":
        uuid_ = (body.get("uuid") or "").strip()
        if not uuid_:
            raise ValueError("vless: нужен uuid")
        tls = _build_tls_from_form(body)
        return make_vless_outbound(
            tag=tag, server=server, port=port, uuid=uuid_,
            flow=(body.get("flow") or "").strip(),
            transport=_build_transport_from_form(body),
            tls=tls)

    if form == "trojan":
        password = (body.get("password") or "").strip()
        if not password:
            raise ValueError("trojan: нужен password")
        return make_trojan_outbound(
            tag=tag, server=server, port=port, password=password,
            sni=(body.get("sni") or "").strip(),
            transport=_build_transport_from_form(body))

    if form == "shadowsocks":
        method   = (body.get("method") or "aes-128-gcm").strip()
        password = (body.get("password") or "").strip()
        if not password:
            raise ValueError("shadowsocks: нужен password")
        return make_shadowsocks_outbound(
            tag=tag, server=server, port=port,
            method=method, password=password)

    if form == "hysteria2":
        password = (body.get("password") or "").strip()
        if not password:
            raise ValueError("hysteria2: нужен password")
        return make_hysteria2_outbound(
            tag=tag, server=server, port=port, password=password,
            sni=(body.get("sni") or "").strip(),
            insecure=bool(body.get("insecure")))

    if form == "tuic":
        uuid_ = (body.get("uuid") or "").strip()
        if not uuid_:
            raise ValueError("tuic: нужен uuid")
        return make_tuic_outbound(
            tag=tag, server=server, port=port,
            uuid=uuid_,
            password=(body.get("password") or "").strip(),
            sni=(body.get("sni") or "").strip())

    raise ValueError("неизвестный _form: %s" % form)


def _strip_form_keys(body: dict) -> dict:
    """Убрать вспомогательные _form*-поля из готового outbound."""
    return {k: v for k, v in body.items() if not k.startswith("_")}


def _build_transport_from_form(body: dict):
    """ws / grpc transport из плоских form-полей."""
    t_type = (body.get("transport") or "tcp").lower().strip()
    if t_type == "ws":
        tr = {"type": "ws", "path": body.get("ws_path") or "/"}
        host = body.get("ws_host")
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if t_type == "grpc":
        return {"type": "grpc",
                "service_name": (body.get("grpc_service") or "").strip()}
    return None


def _build_tls_from_form(body: dict):
    """TLS / Reality из плоских form-полей."""
    sec = (body.get("security") or "").lower().strip()
    if sec not in ("tls", "reality"):
        return None
    tls = {"enabled": True}
    sni = (body.get("sni") or "").strip()
    if sni:
        tls["server_name"] = sni
    fp = (body.get("fingerprint") or "").strip()
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if sec == "reality":
        tls["reality"] = {
            "enabled":    True,
            "public_key": (body.get("reality_pbk") or "").strip(),
            "short_id":   (body.get("reality_sid") or "").strip(),
        }
    if body.get("insecure"):
        tls["insecure"] = True
    return tls


_SERVICE_OUTBOUND_TYPES = {"direct", "block", "dns", "selector", "urltest"}


def _real_outbounds(cfg: dict) -> list:
    """Достать «реальные» (не служебные) outbound'ы конфига для теста."""
    if not isinstance(cfg, dict):
        return []
    out = []
    for ob in (cfg.get("outbounds") or []):
        if (isinstance(ob, dict) and ob.get("type")
                and ob.get("type") not in _SERVICE_OUTBOUND_TYPES
                and ob.get("tag")):
            out.append(ob)
    return out


def _resolve_test_outbounds(body: dict):
    """
    Источник серверов для теста (по приоритету):
      1) body["outbounds"] — готовый список;
      2) body["config"]    — имя сохранённого конфига (server-pool,
                              imported-subscription-*, любой);
      3) body["url"]       — скачать и распарсить подписку «на лету».
    Возвращает list (возможно пустой) либо None, если ничего не задано.
    """
    obs = body.get("outbounds")
    if isinstance(obs, list):
        return [o for o in obs if isinstance(o, dict) and o.get("tag")]

    name = (body.get("config") or "").strip()
    if name:
        try:
            from core.singbox_manager import get_singbox_manager
            res = get_singbox_manager().get_config(name)
            if not isinstance(res, dict) or not res.get("ok"):
                return []
            return _real_outbounds(res.get("parsed") or {})
        except Exception:
            return []

    url = (body.get("url") or "").strip()
    if url:
        try:
            from core.subscription_manager import fetch_outbounds
            res = fetch_outbounds(url, (body.get("format") or "auto").strip())
            return res.get("outbounds") or []
        except Exception:
            return []

    return None


def register(app):

    # ─────── environment / install ────────────────────────────────

    @app.route("/api/singbox/environment")
    def singbox_environment():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_detector import get_singbox_detector
        return get_singbox_detector().get_environment_report()

    @app.route("/api/singbox/environment/refresh", method="POST")
    def singbox_environment_refresh():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_detector import get_singbox_detector
        return get_singbox_detector().get_environment_report(force=True)

    @app.route("/api/singbox/manifest")
    def singbox_manifest():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            tag = (request.params.get("tag") or "").strip()
            force = request.params.get("force") in ("1", "true", "True")
            data = get_singbox_installer().get_manifest(
                tag=tag, force=force)
            return {"ok": True, "manifest": data}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/singbox/install/status")
    def singbox_install_status():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        return {"ok": True,
                "progress": get_singbox_installer().get_operation_status()}

    @app.route("/api/singbox/install", method="POST")
    def singbox_install():
        """
        Запустить установку в фоне; вернуть результат если уложились
        в INSTALL_API_WAIT, иначе in_progress.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = (body.get("arch") or "").strip()
        tag  = (body.get("tag")  or "").strip()

        from core.singbox_installer import get_singbox_installer
        installer = get_singbox_installer()

        result_box = {}
        done = threading.Event()

        def _run():
            try:
                result_box["result"] = installer.install(arch=arch, tag=tag)
            except Exception as e:
                result_box["result"] = {"ok": False, "error": str(e)}
            finally:
                done.set()

        threading.Thread(target=_run, daemon=True).start()
        finished = done.wait(timeout=INSTALL_API_WAIT)
        if finished:
            return result_box.get("result") or {"ok": False,
                                                 "error": "no result"}
        return {"ok": True, "in_progress": True,
                "progress": installer.get_operation_status()}

    @app.route("/api/singbox/uninstall", method="POST")
    def singbox_uninstall():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            return get_singbox_installer().uninstall()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/singbox/version")
    def singbox_version():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_installer import get_singbox_installer
        try:
            return get_singbox_installer().check_for_updates()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    # ─────── configs ──────────────────────────────────────────────

    @app.route("/api/singbox/configs")
    def singbox_configs():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return {"ok": True,
                "configs": get_singbox_manager().list_configs()}

    @app.route("/api/singbox/configs", method="POST")
    def singbox_configs_create():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        text = body.get("text") or ""
        parsed = body.get("parsed")
        if not name:
            response.status = 400
            return {"ok": False, "error": "Поле 'name' обязательно"}
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().save_config(
            name, text=text, parsed=parsed)

    @app.route("/api/singbox/configs/<name>")
    def singbox_configs_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().get_config(name)
        if not res.get("ok"):
            response.status = 404
        return res

    @app.route("/api/singbox/configs/<name>", method="PUT")
    def singbox_configs_put(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        text = body.get("text") or ""
        parsed = body.get("parsed")
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().save_config(
            name, text=text, parsed=parsed)

    @app.route("/api/singbox/configs/<name>", method="DELETE")
    def singbox_configs_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().delete_config(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/singbox/configs/<name>/up", method="POST")
    def singbox_configs_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        res = get_singbox_manager().up(name)
        if not res.get("ok"):
            response.status = 400
        return res

    @app.route("/api/singbox/configs/<name>/down", method="POST")
    def singbox_configs_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().down(name)

    @app.route("/api/singbox/configs/<name>/restart", method="POST")
    def singbox_configs_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().restart(name)

    @app.route("/api/singbox/configs/<name>/status")
    def singbox_configs_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return {"ok": True, "status": get_singbox_manager().status(name)}

    @app.route("/api/singbox/configs/<name>/validate", method="POST")
    def singbox_configs_validate(name):
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        return get_singbox_manager().validate_via_binary(name)

    # ─────── outbounds CRUD (для Outbounds Builder UI) ────────────

    @app.route("/api/singbox/configs/<name>/outbounds")
    def singbox_outbounds_list(name):
        """Список outbound'ов конфига как они есть в JSON."""
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_manager import get_singbox_manager
        r = get_singbox_manager().get_config(name)
        if not r.get("ok"):
            response.status = 404
            return r
        cfg = r.get("parsed") or {}
        return {"ok": True, "outbounds": cfg.get("outbounds") or []}

    @app.route("/api/singbox/configs/<name>/outbounds", method="POST")
    def singbox_outbounds_add(name):
        """
        Добавить один outbound. Body — готовый sing-box outbound JSON
        (с обязательным `type` и `tag`) или удобная «упрощённая» форма:
            {"_form": "vless", "tag":"...", "server":"...", ...}
        Во втором случае построим через make_*_outbound из
        singbox_config.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            response.status = 400
            return {"ok": False, "error": "body должен быть объектом"}

        try:
            outbound = _build_outbound_from_body(body)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

        return _modify_outbounds(name, lambda obs: _do_add(obs, outbound))

    @app.route("/api/singbox/configs/<name>/outbounds/<tag>", method="PUT")
    def singbox_outbounds_update(name, tag):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        try:
            outbound = _build_outbound_from_body(body)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        return _modify_outbounds(
            name, lambda obs: _do_replace(obs, tag, outbound))

    @app.route("/api/singbox/configs/<name>/outbounds/<tag>", method="DELETE")
    def singbox_outbounds_delete(name, tag):
        response.content_type = "application/json; charset=utf-8"
        return _modify_outbounds(
            name, lambda obs: _do_delete(obs, tag))

    @app.route("/api/singbox/configs/<name>/wrap", method="POST")
    def singbox_configs_wrap(name):
        """
        Обернуть все outbound'ы конфига в selector или urltest.

        body: {"group_type": "selector"|"urltest",
               "group_tag":  "auto" (default),
               "default":    "<tag>"   (для selector),
               "url":        "..."     (для urltest),
               "interval":   "3m"      (для urltest)}
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import wrap_in_group, render_conf

        mgr = get_singbox_manager()
        cfg_resp = mgr.get_config(name)
        if not cfg_resp.get("ok"):
            response.status = 404
            return cfg_resp
        cfg = cfg_resp.get("parsed") or {}
        group_type = (body.get("group_type") or "selector").lower()
        group_tag  = (body.get("group_tag")  or "auto").strip()
        try:
            wrap_in_group(
                cfg,
                group_tag=group_tag,
                group_type=group_type,
                default=(body.get("default") or "").strip(),
                url=(body.get("url") or
                     "https://www.gstatic.com/generate_204"),
                interval=(body.get("interval") or "3m"),
            )
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        # Сохраняем обновлённый конфиг
        save_res = mgr.save_config(name, text=render_conf(cfg))
        if not save_res.get("ok"):
            response.status = 500
            return save_res
        return {"ok": True, "name": name, "group_tag": group_tag,
                "group_type": group_type,
                "outbounds_count": len([o for o in cfg.get("outbounds", [])
                                         if isinstance(o, dict)])}

    # ─────── transparent proxy (TProxy/Redirect/Hybrid) ──────────

    @app.route("/api/singbox/transparent/status")
    def singbox_transparent_status():
        response.content_type = "application/json; charset=utf-8"
        from core import singbox_transparent as tp
        from core.config_manager import get_config_manager
        saved = get_config_manager().get("singbox", "transparent",
                                         default={}) or {}
        return {"ok": True,
                "available_v4": tp.available("v4"),
                "available_v6": tp.available("v6"),
                "settings": saved}

    @app.route("/api/singbox/configs/<name>/transparent-inbounds",
               method="POST")
    def singbox_transparent_inbounds(name):
        """
        Вставить transparent-inbound'ы (redirect/tproxy/hybrid) в конфиг.
        body: {mode, tcp_port, udp_port, dns_port, sniff}.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import set_transparent_inbounds, render_conf
        mgr = get_singbox_manager()
        cfg_resp = mgr.get_config(name)
        if not cfg_resp.get("ok"):
            response.status = 404
            return cfg_resp
        cfg = cfg_resp.get("parsed") or {}
        set_transparent_inbounds(
            cfg,
            mode=(body.get("mode") or "tproxy"),
            tcp_port=int(body.get("tcp_port") or 1100),
            udp_port=int(body.get("udp_port") or 1102),
            dns_port=int(body.get("dns_port") or 0),
            sniff=bool(body.get("sniff", True)))
        save = mgr.save_config(name, text=render_conf(cfg))
        if not save.get("ok"):
            response.status = 500
        return save

    @app.route("/api/singbox/transparent/apply", method="POST")
    def singbox_transparent_apply():
        """
        Поднять firewall-правила прозрачного проксирования.
        body: mode, tcp_port, udp_port, mark, table, families[],
              lan_ifaces[], server_ips[], bypass[], proxy_self,
              dns_hijack_port, ipv6_policy.
        """
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import singbox_transparent as tp
        from core.config_manager import get_config_manager
        try:
            params = dict(
                mode=(body.get("mode") or "tproxy"),
                tcp_port=int(body.get("tcp_port") or 1100),
                udp_port=int(body.get("udp_port") or 1102),
                mark=int(body.get("mark") or tp.DEFAULT_TPROXY_MARK),
                table=int(body.get("table") or tp.DEFAULT_TPROXY_TABLE),
                families=tuple(body.get("families") or ["v4"]),
                lan_ifaces=body.get("lan_ifaces") or None,
                server_ips=body.get("server_ips") or None,
                bypass=body.get("bypass") or None,
                proxy_self=bool(body.get("proxy_self", False)),
                dns_hijack_port=int(body.get("dns_hijack_port") or 0),
                ipv6_policy=(body.get("ipv6_policy") or "allow"),
            )
        except (TypeError, ValueError) as e:
            response.status = 400
            return {"ok": False, "error": "Некорректные параметры: %s" % e}
        res = tp.apply(**params)
        # Запоминаем настройки, чтобы UI показал текущее состояние и
        # чтобы можно было снять/переприменить.
        if res.get("ok"):
            cfg = get_config_manager()
            # families/lan_ifaces — списки; tuple не сериализуется в JSON.
            persist = dict(params)
            persist["families"] = list(params["families"])
            cfg.set("singbox", "transparent", persist)
            cfg.save()
        if not res.get("ok"):
            response.status = 500
        return res

    @app.route("/api/singbox/transparent/remove", method="POST")
    def singbox_transparent_remove():
        response.content_type = "application/json; charset=utf-8"
        from core import singbox_transparent as tp
        from core.config_manager import get_config_manager
        saved = get_config_manager().get("singbox", "transparent",
                                         default={}) or {}
        res = tp.remove(
            mark=int(saved.get("mark") or tp.DEFAULT_TPROXY_MARK),
            table=int(saved.get("table") or tp.DEFAULT_TPROXY_TABLE),
            families=("v4", "v6"))
        cfg = get_config_manager()
        cfg.set("singbox", "transparent", {})
        cfg.save()
        return res

    # ─────── autostart ────────────────────────────────────────────

    @app.route("/api/singbox/autostart")
    def singbox_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import status
        return {"ok": True, "status": status()}

    @app.route("/api/singbox/autostart/<name>", method="POST")
    def singbox_autostart_set(name):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        enabled = bool(body.get("enabled", False))
        from core.singbox_autostart import set_autostart, regenerate
        r = set_autostart(name, enabled)
        # При смене состояния перегенерим init-скрипт.
        if r.get("ok"):
            regenerate()
        return r

    @app.route("/api/singbox/autostart/regenerate", method="POST")
    def singbox_autostart_regen():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import regenerate
        return regenerate()

    @app.route("/api/singbox/autostart/remove", method="POST")
    def singbox_autostart_remove():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import remove
        return remove()

    @app.route("/api/singbox/autostart/apply", method="POST")
    def singbox_autostart_apply():
        response.content_type = "application/json; charset=utf-8"
        from core.singbox_autostart import apply_now
        return apply_now()

    # ─────── subscriptions ────────────────────────────────────────

    @app.route("/api/singbox/subscriptions")
    def singbox_subscriptions_list():
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import list_subscriptions, get_refresher
        return {
            "ok": True,
            "subscriptions": list_subscriptions(),
            "refresher": get_refresher().get_status(),
        }

    @app.route("/api/singbox/subscriptions", method="POST")
    def singbox_subscriptions_add():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        name = (body.get("name") or "").strip()
        url  = (body.get("url")  or "").strip()
        fmt  = (body.get("format") or "auto").strip()
        group = (body.get("group") or "urltest").strip()
        try:
            interval = int(body.get("interval_hours") or 6)
        except (TypeError, ValueError):
            interval = 6
        if not name or not url:
            response.status = 400
            return {"ok": False, "error": "Нужны поля name и url"}
        from core.subscription_manager import add_subscription
        return add_subscription(name=name, url=url, fmt=fmt,
                                interval_hours=interval, group=group)

    @app.route("/api/singbox/subscriptions/<sid>", method="PUT")
    def singbox_subscriptions_update(sid):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        # Передаём через **kwargs — функция возьмёт только известные поля.
        from core.subscription_manager import update_subscription
        kw = {}
        for k in ("name", "url", "format", "interval_hours", "group"):
            if k in body:
                kw[k] = body[k]
        if "interval_hours" in kw:
            try:
                kw["interval_hours"] = max(1, int(kw["interval_hours"]))
            except (TypeError, ValueError):
                kw.pop("interval_hours")
        return update_subscription(sid, **kw)

    @app.route("/api/singbox/subscriptions/<sid>", method="DELETE")
    def singbox_subscriptions_remove(sid):
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import remove_subscription
        return remove_subscription(sid)

    @app.route("/api/singbox/subscriptions/<sid>/refresh", method="POST")
    def singbox_subscriptions_refresh_one(sid):
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import refresh_one
        return refresh_one(sid)

    @app.route("/api/singbox/subscriptions/refresh-all", method="POST")
    def singbox_subscriptions_refresh_all():
        response.content_type = "application/json; charset=utf-8"
        from core.subscription_manager import refresh_all
        return refresh_all()

    # ─────── server pool (публичные источники) ─────────────────────

    @app.route("/api/singbox/pool")
    def singbox_pool_get():
        response.content_type = "application/json; charset=utf-8"
        from core import server_pool as sp
        return {
            "ok": True,
            "settings": sp.get_settings(),
            "sources": sp.list_sources(),
            "presets": sp.presets(),
            "refresher": sp.get_pool_refresher().get_status(),
        }

    @app.route("/api/singbox/pool/settings", method="POST")
    def singbox_pool_settings():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import server_pool as sp
        return sp.update_settings(**body)

    @app.route("/api/singbox/pool/sources", method="POST")
    def singbox_pool_source_add():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import server_pool as sp
        return sp.add_source(
            name=(body.get("name") or "").strip(),
            url=(body.get("url") or "").strip(),
            fmt=(body.get("format") or "auto").strip(),
            enabled=bool(body.get("enabled", True)))

    @app.route("/api/singbox/pool/sources/<sid>", method="PUT")
    def singbox_pool_source_update(sid):
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}
        from core import server_pool as sp
        kw = {k: body[k] for k in ("name", "url", "format", "enabled")
              if k in body}
        return sp.update_source(sid, **kw)

    @app.route("/api/singbox/pool/sources/<sid>", method="DELETE")
    def singbox_pool_source_remove(sid):
        response.content_type = "application/json; charset=utf-8"
        from core import server_pool as sp
        return sp.remove_source(sid)

    @app.route("/api/singbox/pool/refresh", method="POST")
    def singbox_pool_refresh():
        response.content_type = "application/json; charset=utf-8"
        from core import server_pool as sp
        # Сборка может быть долгой (скачивание источников + health-filter
        # с тестом каждого сервера). Гоняем в фоне как job и отдаём
        # прогресс через /pool/refresh/status — UI рисует прогресс-бар.
        started = sp.get_refresh_job().start()
        if not started:
            return {"ok": True, "running": True,
                    "message": "Сборка уже выполняется"}
        return {"ok": True, "started": True}

    @app.route("/api/singbox/pool/refresh/status")
    def singbox_pool_refresh_status():
        response.content_type = "application/json; charset=utf-8"
        from core import server_pool as sp
        st = sp.get_refresh_job().status()
        st["ok"] = True
        return st

    # ─────── proxy tester ──────────────────────────────────────────

    @app.route("/api/singbox/test", method="POST")
    def singbox_test_start():
        response.content_type = "application/json; charset=utf-8"
        try:
            body = request.json or {}
        except Exception:
            body = {}

        outbounds = _resolve_test_outbounds(body)
        if outbounds is None:
            response.status = 400
            return {"ok": False,
                    "error": "Укажите config, url или outbounds"}
        if not outbounds:
            return {"ok": False, "error": "Не нашлось серверов для теста"}

        target = (body.get("target") or "cloudflare").strip()
        try:
            timeout_ms = int(body.get("timeout_ms") or 5000)
        except (TypeError, ValueError):
            timeout_ms = 5000

        from core.proxy_tester import get_test_job
        job = get_test_job()
        started = job.start(outbounds, target=target, timeout_ms=timeout_ms)
        if not started:
            return {"ok": False, "error": "Тест уже выполняется",
                    "running": True}
        return {"ok": True, "started": True, "count": len(outbounds)}

    @app.route("/api/singbox/test/status")
    def singbox_test_status():
        response.content_type = "application/json; charset=utf-8"
        from core.proxy_tester import get_test_job, TARGET_PRESETS
        st = get_test_job().status()
        st["ok"] = True
        st["targets"] = list(TARGET_PRESETS.keys())
        return st
