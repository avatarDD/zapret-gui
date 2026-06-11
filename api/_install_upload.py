# api/_install_upload.py
"""
Общий помощник эндпоинтов «установить бинарь из локального файла»
(multipart-загрузка): сохранить файл(ы) во временный каталог
(см. binary_installer.make_workdir — уважает install.tmpdir, чтобы не
упереться в tmpfs), вызвать установщик, прибрать за собой.

Используется api/awg.py, api/singbox.py, api/mihomo.py. Своего
register() нет — это не самостоятельный API-модуль.
"""

import os
import shutil

from bottle import request, response


def _save_upload(upload, workdir: str, fallback_name: str) -> str:
    """Сохранить bottle FileUpload в workdir, вернуть путь."""
    raw = getattr(upload, "raw_filename", "") or upload.filename or ""
    name = os.path.basename(raw).replace("/", "_").replace("\\", "_")
    name = name or fallback_name
    dst = os.path.join(workdir, name)
    upload.save(dst, overwrite=True)
    return dst


def handle_single_upload(install_fn):
    """
    Эндпоинт с одним файлом (multipart-поле `file`).
    install_fn(path, orig_name) → dict установщика.
    """
    upload = request.files.get("file")
    if upload is None or not getattr(upload, "file", None):
        response.status = 400
        return {"ok": False, "error": "Нет файла (multipart-поле 'file')"}
    from core.binary_installer import make_workdir
    workdir = make_workdir(prefix="upload-install-")
    try:
        path = _save_upload(upload, workdir, "upload.bin")
        result = install_fn(
            path, getattr(upload, "raw_filename", "") or upload.filename or "")
    except Exception as e:
        response.status = 500
        return {"ok": False, "error": str(e)}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if not isinstance(result, dict):
        result = {"ok": False, "error": "установщик не вернул результат"}
    if not result.get("ok"):
        response.status = 500
    return result


def handle_multi_upload(fields, install_fn):
    """
    Эндпоинт с несколькими опциональными файлами.
    fields    : [(form_field, fallback_name), ...]
    install_fn: (paths: {form_field: path|None}) → dict установщика.
    Хотя бы один файл обязателен.
    """
    uploads = {}
    for field, fallback in fields:
        u = request.files.get(field)
        if u is not None and getattr(u, "file", None):
            uploads[field] = (u, fallback)
    if not uploads:
        response.status = 400
        return {"ok": False,
                "error": "Нет файлов (multipart-поля: %s)"
                         % ", ".join(f for f, _ in fields)}
    from core.binary_installer import make_workdir
    workdir = make_workdir(prefix="upload-install-")
    try:
        paths = {field: None for field, _ in fields}
        for field, (u, fallback) in uploads.items():
            sub = os.path.join(workdir, field)
            os.makedirs(sub, exist_ok=True)
            paths[field] = _save_upload(u, sub, fallback)
        result = install_fn(paths)
    except Exception as e:
        response.status = 500
        return {"ok": False, "error": str(e)}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if not isinstance(result, dict):
        result = {"ok": False, "error": "установщик не вернул результат"}
    if not result.get("ok"):
        response.status = 500
    return result
