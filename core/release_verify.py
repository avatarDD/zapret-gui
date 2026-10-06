# core/release_verify.py
"""
Проверка выпуска GUI перед установкой: архив сверяется с SHA256SUMS.

## Зачем

Самообновление GUI ставит код, который потом исполняется от root. Раньше
архив брался как есть: битая загрузка через обход (AWG/sing-box/mihomo)
или обрезанный ответ зеркала узнавались только по падению после
перезапуска. Приём d2k (necronicle/d2k, ``files/d2k-update.sh``):
выпуск публикует список хешей своих архивов, и ставится только архив,
совпавший с ним.

## Что проверяется — и чего нет

* ``SHA256SUMS`` релиза (``.github/workflows/release.yml``) — архив
  обязан совпасть по хешу. Это **целостность**: защита от битой и
  обрезанной загрузки.
* **Подлинности нет**: хеш лежит рядом с архивом и подменяется вместе с
  ним. Подпись списка (у d2k — Ed25519 с закреплённым ключом) отложена
  до отдельной задачи.

Выпуск без SHA256SUMS (старше этой проверки) ставится, как раньше, с
предупреждением в журнале.

Разбор и решение — чистые функции; сеть — у вызывающего.
"""

import hashlib
import os
import re


SUMS_NAME = "SHA256SUMS"
# Архив, который ставит самообновление (тот же, что README советует
# для Linux): дерево проекта внутри каталога zapret-gui/.
ARCHIVE_NAME = "zapret-gui-linux.tar.gz"

_SUM_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$")


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


def decide(archive_sha: str, sums: dict, name: str = ARCHIVE_NAME) -> dict:
    """Ставить ли архив — чистая функция.

    Args:
        archive_sha: хеш скачанного архива.
        sums: разобранный SHA256SUMS (``{}`` — его нет в выпуске).

    Returns:
        dict: ``ok`` (ставить ли), ``integrity`` (хеш сверен),
        ``message``, ``warnings``.
    """
    if not sums:
        return {"ok": True, "integrity": False,
                "message": "выпуск без SHA256SUMS: целостность не "
                           "проверена",
                "warnings": ["выпуск без SHA256SUMS — архив не сверен"]}
    expected = sums.get(name)
    if not expected:
        return {"ok": False, "integrity": False,
                "message": "в SHA256SUMS нет строки для %s" % name,
                "warnings": []}
    if expected != (archive_sha or "").lower():
        return {"ok": False, "integrity": False,
                "message": "хеш архива не совпал с SHA256SUMS: загрузка "
                           "битая или файл подменён — не ставим",
                "warnings": []}
    return {"ok": True, "integrity": True,
            "message": "хеш архива сверен с SHA256SUMS",
            "warnings": []}
