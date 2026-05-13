# api/awg.py
"""
REST API для интеграции amneziawg-go.

Маршруты:
  GET  /api/awg/environment             — полный отчёт об окружении
  POST /api/awg/environment/refresh     — сбросить кэш и пересканировать

  GET  /api/awg/manifest                — manifest.json последнего релиза
  GET  /api/awg/install/status          — прогресс текущей операции
  POST /api/awg/install                 — установить бинарники
  POST /api/awg/uninstall               — удалить бинарники

  GET  /api/awg/keenetic/opkg-tun       — состояние OpkgTun на Keenetic

  GET    /api/awg/configs               — список конфигов
  POST   /api/awg/configs               — создать новый (JSON: name, text|parsed)
  GET    /api/awg/configs/<name>        — получить конфиг (text + parsed + errors)
  PUT    /api/awg/configs/<name>        — сохранить (text|parsed)
  DELETE /api/awg/configs/<name>        — удалить

  POST   /api/awg/configs/<name>/up     — поднять
  POST   /api/awg/configs/<name>/down   — опустить
  POST   /api/awg/configs/<name>/restart
  GET    /api/awg/configs/<name>/status

  POST   /api/awg/configs/validate      — валидация без сохранения
  POST   /api/awg/keypair               — сгенерировать пару ключей
  GET    /api/awg/interfaces            — все активные AWG/WG интерфейсы

  POST   /api/awg/warp/import           — импорт готового WARP .conf
  POST   /api/awg/warp/generate         — нативная генерация AWG-WARP

  GET    /api/awg/warp-in-warp          — статус WARP-in-WARP
  POST   /api/awg/warp-in-warp          — поднять (body: outer, inner)
  DELETE /api/awg/warp-in-warp          — отключить

  GET    /api/awg/autostart             — статус автозапуска
  POST   /api/awg/autostart/install     — установить init-скрипт
  POST   /api/awg/autostart/remove      — удалить init-скрипт
  POST   /api/awg/autostart/regenerate  — пересоздать init-скрипт
  POST   /api/awg/autostart/<name>      — установить флаг autostart
                                           (body: {"enabled": true|false})
  POST   /api/awg/autostart/apply       — применить (поднять enabled) сейчас
"""

import threading

from bottle import request, response


# Сколько ждём в основном HTTP-запросе перед тем как вернуть in_progress
INSTALL_API_WAIT = 8


def register(app):

    @app.route("/api/awg/environment")
    def awg_environment():
        """
        Полный отчёт об окружении (см. core.awg_detector).
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report()

    @app.route("/api/awg/environment/refresh", method="POST")
    def awg_environment_refresh():
        """Сбросить кэш детекта и вернуть свежий отчёт."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_detector import get_awg_detector
        det = get_awg_detector()
        return det.get_environment_report(force=True)

    # ─────────── manifest / installer ────────────────────────────

    @app.route("/api/awg/manifest")
    def awg_manifest():
        """Manifest последнего релиза с бинарниками AWG."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        try:
            force = request.params.get("force", "").lower() in ("1", "true")
            tag = request.params.get("tag") or None
            manifest = inst.get_manifest(tag=tag, force=force)
            return {"ok": True, "manifest": manifest}
        except RuntimeError as e:
            response.status = 502
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/install/status")
    def awg_install_status():
        """
        Текущий статус установки/удаления + установленная версия +
        информация о target_dir и потенциальных конфликтах с внешней
        установкой.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()
        op = inst.get_operation_status()
        installed = inst.get_installed_version()
        target = inst.get_target_info()
        return {
            "ok":         True,
            "operation":  op,
            "installed":  installed,
            "target":     target,
        }

    @app.route("/api/awg/install", method="POST")
    def awg_install():
        """
        Запустить установку бинарников. Тело: {"arch": "...", "tag": "..."}.
        Оба поля опциональны — без них берётся detector + последний релиз.
        """
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()

        try:
            body = request.json or {}
        except Exception:
            body = {}
        arch = body.get("arch") or None
        tag = body.get("tag") or None

        result_holder = {"result": None}

        def task():
            result_holder["result"] = inst.install_binaries(arch=arch, tag=tag)

        t = threading.Thread(target=task, daemon=True, name="awg-install")
        t.start()
        t.join(timeout=INSTALL_API_WAIT)

        if t.is_alive():
            return {
                "ok":          True,
                "in_progress": True,
                "message":     "Установка запущена. Следите за прогрессом.",
            }

        result = result_holder["result"] or {
            "ok": False, "message": "Внутренняя ошибка"
        }
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/uninstall", method="POST")
    def awg_uninstall():
        """Удалить установленные AWG-бинарники."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_installer import get_awg_installer
        inst = get_awg_installer()

        result = inst.uninstall_binaries()
        if not result.get("ok"):
            response.status = 500
        return result

    # ─────────── Keenetic helpers ───────────────────────────────

    @app.route("/api/awg/keenetic/opkg-tun")
    def awg_keenetic_opkg_tun():
        """Состояние OpkgTun + инструкция (если требуется)."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_keenetic_setup import check_opkg_tun
        return check_opkg_tun()

    # ─────────── Configs CRUD ──────────────────────────────────

    @app.route("/api/awg/configs")
    def awg_configs_list():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "configs": get_awg_manager().list_configs()}

    @app.route("/api/awg/configs", method="POST")
    def awg_configs_create():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        body = request.json or {}
        name = (body.get("name") or "").strip()
        text = body.get("text")
        parsed = body.get("parsed")
        if not name:
            response.status = 400
            return {"ok": False, "error": "name обязателен"}
        try:
            cfg = get_awg_manager().save_config(
                name, text=text, parsed=parsed, allow_overwrite=False
            )
            return {"ok": True, "config": cfg}
        except (ValueError, FileExistsError) as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/validate", method="POST")
    def awg_configs_validate():
        """Распарсить и проверить .conf-текст без сохранения."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_config import parse_conf, validate as validate_cfg
        body = request.json or {}
        text = body.get("text") or ""
        try:
            parsed = parse_conf(text)
            errors = validate_cfg(parsed)
            return {"ok": not errors, "parsed": parsed, "errors": errors}
        except Exception as e:
            response.status = 400
            return {"ok": False, "errors": [str(e)]}

    @app.route("/api/awg/configs/<name>")
    def awg_config_get(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        try:
            return {"ok": True, "config": get_awg_manager().get_config(name)}
        except FileNotFoundError:
            response.status = 404
            return {"ok": False, "error": "Конфиг не найден"}
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/<name>", method="PUT")
    def awg_config_save(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        body = request.json or {}
        try:
            cfg = get_awg_manager().save_config(
                name, text=body.get("text"), parsed=body.get("parsed"),
                allow_overwrite=True,
            )
            return {"ok": True, "config": cfg}
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/configs/<name>", method="DELETE")
    def awg_config_delete(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        try:
            return get_awg_manager().delete_config(name)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}

    # ─────────── Interface up/down/status ──────────────────────

    @app.route("/api/awg/configs/<name>/up", method="POST")
    def awg_iface_up(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().up(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/down", method="POST")
    def awg_iface_down(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().down(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/restart", method="POST")
    def awg_iface_restart(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        result = get_awg_manager().restart(name)
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/configs/<name>/status")
    def awg_iface_status(name):
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "status": get_awg_manager().status(name)}

    @app.route("/api/awg/interfaces")
    def awg_interfaces_list():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_manager import get_awg_manager
        return {"ok": True, "interfaces": get_awg_manager().list_interfaces()}

    # ─────────── Keypair ───────────────────────────────────────

    # ─────────── WARP import ──────────────────────────────────

    @app.route("/api/awg/warp/import", method="POST")
    def awg_warp_import():
        """
        Импорт готового AWG-WARP конфига.

        Принимает:
          - JSON: {"text": "<.conf content>", "name": "warp-1" (опц.)}
          - multipart/form-data с полем "file" (.conf) и опц. "name"
          - text/plain — тело запроса как сам .conf
        """
        response.content_type = "application/json; charset=utf-8"
        from core.warp_importer import import_from_text

        text = ""
        name = None

        # multipart upload
        upload = request.files.get("file") if hasattr(request, "files") else None
        if upload is not None and getattr(upload, "file", None):
            try:
                raw = upload.file.read()
                if isinstance(raw, bytes):
                    text = raw.decode("utf-8", errors="replace")
                else:
                    text = str(raw)
            except Exception as e:
                response.status = 400
                return {"ok": False, "error": f"Не удалось прочитать файл: {e}"}
            name = (request.forms.get("name") or "").strip() or None
        else:
            ctype = (request.content_type or "").lower()
            if "application/json" in ctype:
                body = request.json or {}
                text = body.get("text") or ""
                name = (body.get("name") or "").strip() or None
            else:
                # text/plain или что-то ещё — берём raw body
                try:
                    raw = request.body.read() if request.body else b""
                    if isinstance(raw, bytes):
                        text = raw.decode("utf-8", errors="replace")
                    else:
                        text = str(raw)
                except Exception:
                    text = ""
                name = (request.params.get("name") or "").strip() or None

        if not text.strip():
            response.status = 400
            return {"ok": False, "error": "Пустой конфиг"}

        try:
            return import_from_text(text, name=name)
        except FileExistsError:
            response.status = 409
            return {"ok": False, "error": "Конфиг с таким именем уже существует"}
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/warp/generate", method="POST")
    def awg_warp_generate():
        """
        Нативная генерация AWG-WARP конфига.

        Тело JSON (всё опционально):
          {
            "license_key": "XXXX-XXXX-XXXX",  # WARP+ ключ
            "save":        true,              # сохранить через AwgManager
            "name":        "warp-gen-...",    # желаемое имя
            "dns":         ["1.1.1.1", ...],
            "mtu":         1280
          }

        В случае preview (save=false) — конфиг возвращается, но не
        сохраняется; UI может показать его и дать кнопку «Сохранить».
        """
        response.content_type = "application/json; charset=utf-8"
        from core.warp_generator import generate_warp_config, WarpApiError

        try:
            body = request.json or {}
        except Exception:
            body = {}

        license_key = (body.get("license_key") or "").strip() or None
        save        = bool(body.get("save"))
        name        = (body.get("name") or "").strip() or None
        dns         = body.get("dns") or None
        mtu         = body.get("mtu") or 1280

        if dns is not None and not isinstance(dns, list):
            response.status = 400
            return {"ok": False, "error": "dns должен быть массивом"}

        try:
            return generate_warp_config(
                license_key=license_key, save=save, name=name,
                dns=dns, mtu=int(mtu) if mtu else 1280,
            )
        except WarpApiError as e:
            response.status = 502
            return {"ok": False, "error": str(e)}
        except (ValueError, FileExistsError) as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        except RuntimeError as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": "Внутренняя ошибка: %s" % e}

    # ─────────── WARP-in-WARP ─────────────────────────────────

    @app.route("/api/awg/warp-in-warp")
    def awg_wiw_status():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_warp_in_warp import status as wiw_status
        try:
            return wiw_status()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/warp-in-warp", method="POST")
    def awg_wiw_setup():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_warp_in_warp import setup as wiw_setup
        try:
            body = request.json or {}
        except Exception:
            body = {}
        outer = (body.get("outer") or "").strip()
        inner = (body.get("inner") or "").strip()
        if not outer or not inner:
            response.status = 400
            return {"ok": False, "error": "outer и inner обязательны"}
        try:
            result = wiw_setup(outer, inner)
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
        if not result.get("ok"):
            response.status = 400
        return result

    @app.route("/api/awg/warp-in-warp", method="DELETE")
    def awg_wiw_teardown():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_warp_in_warp import teardown as wiw_teardown
        try:
            result = wiw_teardown()
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
        if not result.get("ok"):
            response.status = 500
        return result

    # ─────────── Autostart ─────────────────────────────────────

    @app.route("/api/awg/autostart")
    def awg_autostart_status():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        am = get_awg_autostart_manager()
        return {"ok": True, "status": am.get_status()}

    @app.route("/api/awg/autostart/install", method="POST")
    def awg_autostart_install():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        result = get_awg_autostart_manager().install_script()
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/autostart/remove", method="POST")
    def awg_autostart_remove():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        result = get_awg_autostart_manager().remove_script()
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/autostart/regenerate", method="POST")
    def awg_autostart_regenerate():
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        result = get_awg_autostart_manager().regenerate()
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/autostart/apply", method="POST")
    def awg_autostart_apply():
        """Поднять enabled-интерфейсы прямо сейчас."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        result = get_awg_autostart_manager().apply_autostart()
        if not result.get("ok"):
            response.status = 500
        return result

    @app.route("/api/awg/autostart/<name>", method="POST")
    def awg_autostart_set(name):
        """Установить флаг autostart для конкретного конфига."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_autostart_manager import get_awg_autostart_manager
        try:
            body = request.json or {}
        except Exception:
            body = {}
        enabled = bool(body.get("enabled"))
        try:
            return get_awg_autostart_manager().set_enabled(name, enabled)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        except Exception as e:
            response.status = 500
            return {"ok": False, "error": str(e)}

    @app.route("/api/awg/keypair", method="POST")
    def awg_keypair():
        """Сгенерировать пару ключей X25519."""
        response.content_type = "application/json; charset=utf-8"
        from core.awg_config import generate_keypair
        from core.awg_installer import get_awg_installer
        info = get_awg_installer().get_installed_version()
        try:
            priv, pub = generate_keypair(awg_binary=info.get("awg") or None)
            return {"ok": True, "private_key": priv, "public_key": pub}
        except RuntimeError as e:
            response.status = 500
            return {"ok": False, "error": str(e)}
