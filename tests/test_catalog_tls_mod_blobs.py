# tests/test_catalog_tls_mod_blobs.py
"""
tls_mod в поставляемых каталогах применяется только к TLS ClientHello.

`tls_mod` переписывает фейк как ClientHello (rnd/dupsid/sni). Если blob
им не является, C-функция TLSMod (nfq2/protocol.c) пишет в лог «cannot
apply tls mod. tls structure invalid» и возвращает nil, а `fake` шлёт
blob без изменений. Обход не ломается, но под circular строка сыплется
в лог на каждом соединении (обсуждение #102: «z2k RKN авто (50
стратегий)», шаги с blob=0x00000000 и blob=0x0F0F0E0F).

Тест открывает каждый blob, на который в каталогах висит tls_mod, и
проверяет его тем же условием, что TLSMod: полная TLS-запись с
ClientHello и session id, а для sni=/rndsni — расширение SNI.
"""

import os
import re
import unittest

from core import blob_registry
from core import catalog_loader as cl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOGS = os.path.join(ROOT, "catalogs")
IMPORT = os.path.join(ROOT, "import")

_DESYNC_RE = re.compile(r"^--lua-desync=([A-Za-z0-9_]+):(.*)$")
_DECL_RE = re.compile(r"^--blob=([^:]+):@?(.+)$")


def _client_hello_error(data: bytes, need_sni: bool):
    """Причина, по которой TLSMod откажется, или None."""
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[2] > 0x03:
        return "не TLS-запись"
    if len(data) < 5 + int.from_bytes(data[3:5], "big"):
        return "TLS-запись обрезана"
    if data[5] != 0x01:
        return "не ClientHello"
    if len(data) < 44 or len(data) < 44 + data[43]:
        return "нет session id"
    if not need_sni:
        return None
    pos = 44 + data[43]
    pos += 2 + int.from_bytes(data[pos:pos + 2], "big")      # cipher suites
    pos += 1 + data[pos]                                     # compression
    end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    while pos + 4 <= end:
        if int.from_bytes(data[pos:pos + 2], "big") == 0:
            return None
        pos += 4 + int.from_bytes(data[pos + 2:pos + 4], "big")
    return "нет расширения SNI"


def _blob_bytes(name: str, declared: dict):
    if name.lower().startswith("0x"):
        return bytes.fromhex(name[2:])
    path = declared.get(name) or blob_registry._FALLBACK_ALIASES.get(name)
    if not path:
        return None
    path = path.lstrip("@")
    if path.startswith("bin/"):
        path = os.path.join(IMPORT, path)
    with open(path, "rb") as fh:
        return fh.read()


def _catalog_files():
    for base, _dirs, files in os.walk(CATALOGS):
        for name in sorted(files):
            if name.endswith(".txt"):
                yield os.path.join(base, name)


class TestCatalogTlsModBlobs(unittest.TestCase):

    def test_tls_mod_only_on_client_hello(self):
        checked = 0
        for path in _catalog_files():
            with open(path, encoding="utf-8") as fh:
                entries = cl._parse_catalog_content(
                    fh.read(), os.path.basename(path), protocol="tcp")
            for entry in entries:
                declared = {}
                for arg in entry.args.splitlines():
                    decl = _DECL_RE.match(arg)
                    if decl:
                        declared[decl.group(1)] = decl.group(2)
                        continue
                    m = _DESYNC_RE.match(arg)
                    if not m or m.group(1) != "fake":
                        continue
                    opts = dict(o.split("=", 1) if "=" in o else (o, "")
                                for o in m.group(2).split(":"))
                    if "tls_mod" not in opts:
                        continue
                    blob = opts.get("blob", "fake_default_tls")
                    if blob in blob_registry.BUILTIN_BLOB_NAMES:
                        continue
                    data = _blob_bytes(blob, declared)
                    where = "%s [%s]: %s" % (
                        os.path.relpath(path, ROOT), entry.section_id, arg)
                    self.assertIsNotNone(data, "blob не найден: " + where)
                    mods = opts["tls_mod"].split(",")
                    need_sni = any(x.startswith("sni=") or x == "rndsni"
                                   for x in mods)
                    err = _client_hello_error(data, need_sni)
                    self.assertIsNone(err, "%s — %s" % (where, err))
                    checked += 1
        # Тест не должен «пройти», ничего не проверив.
        self.assertGreater(checked, 50)


if __name__ == "__main__":
    unittest.main()
