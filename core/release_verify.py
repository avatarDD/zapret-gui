# core/release_verify.py
"""
Проверка выпуска GUI перед установкой: SHA256SUMS и подпись Ed25519.

## Зачем

Самообновление GUI ставит код, который потом исполняется от root. Раньше
архив брался как есть: битая загрузка через обход (AWG/sing-box/mihomo),
обрезанный ответ зеркала или подменённый файл узнавались только по
падению после перезапуска. Приём d2k (necronicle/d2k,
``files/d2k-update.sh``): выпуск публикует список хешей архивов и его
подпись Ed25519, открытый ключ ЗАКРЕПЛЁН в коде, а не берётся из сети.

## Что проверяется

* ``SHA256SUMS`` релиза (``.github/workflows/release.yml``) — архив
  обязан совпасть по хешу. Это защита от битой и обрезанной загрузки.
* ``SHA256SUMS.sig`` — подпись этого списка ключом владельца
  репозитория. Подлинность — только она: хеш, лежащий рядом с архивом,
  подменяется вместе с архивом. Проверка — ``openssl pkeyutl -verify
  -rawin`` (в Python нет Ed25519 без сторонних пакетов, а на роутере
  ``openssl-util`` обычно уже есть).

Ключи — :data:`PUBLIC_KEYS`. Пусто — владелец ключ ещё не завёл, и
подлинность не проверяется (только целостность), о чём честно пишем.

## Режимы (``gui.update_verify``)

* ``auto`` — проверить всё, что можно: несовпадение хеша и неверная
  подпись — отказ; нет SHA256SUMS (старый выпуск) или нечем проверить
  подпись — установка с предупреждением;
* ``require`` — ставить только выпуск с подписью, проверенной
  закреплённым ключом. Обновление на ветку (без выпуска) — отказ.

Разбор и решение — чистые функции; сеть и openssl — у вызывающего.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile


SUMS_NAME = "SHA256SUMS"
SIG_NAME = "SHA256SUMS.sig"
# Архив, который ставит самообновление (тот же, что README советует
# для Linux): дерево проекта внутри каталога zapret-gui/.
ARCHIVE_NAME = "zapret-gui-linux.tar.gz"

MODE_AUTO = "auto"
MODE_REQUIRE = "require"

# Открытые ключи Ed25519 владельца (PEM, «-----BEGIN PUBLIC KEY-----»).
# Закрытый — секрет RELEASE_SIGNING_KEY в настройках репозитория, в код
# не попадает никогда. Несколько ключей — на время смены ключа.
PUBLIC_KEYS = ()

_SUM_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$")


def mode(cfg=None) -> str:
    """Режим проверки из ``gui.update_verify`` (мусор — auto)."""
    try:
        if cfg is None:
            from core.config_manager import get_config_manager
            cfg = get_config_manager()
        value = str(cfg.get("gui", "update_verify", default=MODE_AUTO)
                    or "").strip().lower()
    except Exception:                           # noqa: BLE001 — граница
        value = MODE_AUTO
    return MODE_REQUIRE if value == MODE_REQUIRE else MODE_AUTO


def parse_sums(text: str) -> dict:
    """``sha256sum``-формат → ``{имя_файла: hex}`` (имена без путей)."""
    out = {}
    for line in str(text or "").splitlines():
        match = _SUM_RE.match(line.strip())
        if match:
            out[os.path.basename(match.group(2))] = match.group(1).lower()
    return out


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_signature(data_path: str, sig_path: str, keys=None) -> tuple:
    """Проверить подпись Ed25519 файла любым из закреплённых ключей.

    Returns:
        (True, ключ №) — подпись верна; (False, причина) — неверна;
        (None, причина) — проверить нечем (нет ключей / openssl / подписи).
    """
    keys = PUBLIC_KEYS if keys is None else keys
    if not keys:
        return None, "ключ подписи не закреплён (release_verify.PUBLIC_KEYS)"
    if not sig_path or not os.path.isfile(sig_path):
        return None, "подписи SHA256SUMS.sig в выпуске нет"
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "нет openssl (opkg install openssl-util)"
    workdir = tempfile.mkdtemp(prefix="zgui-verify-")
    try:
        for index, pem in enumerate(keys):
            key_path = os.path.join(workdir, "key%d.pem" % index)
            with open(key_path, "w") as handle:
                handle.write(pem.strip() + "\n")
            try:
                result = subprocess.run(
                    [openssl, "pkeyutl", "-verify", "-pubin", "-inkey",
                     key_path, "-rawin", "-in", data_path,
                     "-sigfile", sig_path],
                    capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired) as e:
                return None, "openssl не отработал: %s" % e
            if result.returncode == 0:
                return True, "ключ №%d" % (index + 1)
            if "rawin" in (result.stderr or "") and "unknown" in (
                    result.stderr or "").lower():
                return None, "openssl без -rawin (нужен OpenSSL 3)"
        return False, "подпись не сходится ни с одним закреплённым ключом"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def decide(archive_sha: str, sums: dict, signature: tuple,
           verify_mode: str = MODE_AUTO,
           name: str = ARCHIVE_NAME) -> dict:
    """Ставить ли архив — чистая функция.

    Args:
        archive_sha: хеш скачанного архива.
        sums: разобранный SHA256SUMS (``{}`` — его нет в выпуске).
        signature: результат :func:`verify_signature`.

    Returns:
        dict: ``ok`` (ставить ли), ``integrity`` (хеш сверен),
        ``authentic`` (подпись проверена), ``message``, ``warnings``.
    """
    warnings = []
    if not sums:
        if verify_mode == MODE_REQUIRE:
            return {"ok": False, "integrity": False, "authentic": False,
                    "message": "в выпуске нет SHA256SUMS — режим "
                               "gui.update_verify=require такой не ставит",
                    "warnings": warnings}
        return {"ok": True, "integrity": False, "authentic": False,
                "message": "выпуск без SHA256SUMS: целостность не "
                           "проверена",
                "warnings": ["выпуск без SHA256SUMS — архив не сверен"]}
    expected = sums.get(name)
    if not expected:
        return {"ok": False, "integrity": False, "authentic": False,
                "message": "в SHA256SUMS нет строки для %s" % name,
                "warnings": warnings}
    if expected != (archive_sha or "").lower():
        return {"ok": False, "integrity": False, "authentic": False,
                "message": "хеш архива не совпал с SHA256SUMS: загрузка "
                           "битая или файл подменён — не ставим",
                "warnings": warnings}
    verified, why = signature
    if verified is False:
        return {"ok": False, "integrity": True, "authentic": False,
                "message": "подпись выпуска неверна (%s) — не ставим" % why,
                "warnings": warnings}
    if verified is None:
        if verify_mode == MODE_REQUIRE:
            return {"ok": False, "integrity": True, "authentic": False,
                    "message": "подпись не проверена (%s), а режим "
                               "gui.update_verify=require" % why,
                    "warnings": warnings}
        warnings.append("подлинность не проверена: %s" % why)
        return {"ok": True, "integrity": True, "authentic": False,
                "message": "хеш сверен; подпись не проверена (%s)" % why,
                "warnings": warnings}
    return {"ok": True, "integrity": True, "authentic": True,
            "message": "хеш сверен, подпись верна (%s)" % why,
            "warnings": warnings}
