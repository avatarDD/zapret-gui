"""
Зависимости пакета OpenWrt: ipk (packaging/openwrt/control) и apk
(Makefile → `apk mkpkg --info depends:`) должны совпадать.

Issue #285: в apk-списке жил `python3-email`, которого в текущем фиде
OpenWrt больше нет (модуль `email` переехал в python3-urllib) — установка
падала целиком: «python3-email (no such package)». Списки лежат в двух
разных файлах, поэтому расхождение между ними ничем не ловилось.
"""

import os
import re
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Пакеты, которых в apk-фиде OpenWrt (24.10+/SNAPSHOT) больше не существует:
# зависимость от них делает пакет неустанавливаемым.
REMOVED_UPSTREAM = {"python3-email"}


def _ipk_depends() -> list:
    path = os.path.join(ROOT, "packaging", "openwrt", "control")
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("Depends:"):
                raw = line.split(":", 1)[1]
                return [d.strip() for d in raw.split(",") if d.strip()]
    return []


def _apk_depends() -> list:
    path = os.path.join(ROOT, "Makefile")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^OPENWRT_DEPENDS\s*:?=\s*((?:.*\\\n)*.*)$", text, re.M)
    if not m:
        return []
    raw = m.group(1).replace("\\\n", " ")
    return raw.split()


class TestPackagingDeps(unittest.TestCase):

    def test_ipk_and_apk_depends_match(self):
        self.assertEqual(sorted(_ipk_depends()), sorted(_apk_depends()))

    def test_apk_recipe_uses_the_shared_list(self):
        with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('--info "depends:$(OPENWRT_DEPENDS)"', text)

    def test_no_packages_removed_upstream(self):
        for dep in _ipk_depends() + _apk_depends():
            self.assertNotIn(dep, REMOVED_UPSTREAM,
                             "%s больше нет в фиде OpenWrt" % dep)

    def test_urllib_present_it_carries_email(self):
        # Модуль email нужен bottle (email.utils). На новом OpenWrt он
        # приезжает только вместе с python3-urllib.
        self.assertIn("python3-urllib", _ipk_depends())
        self.assertIn("python3-urllib", _apk_depends())


if __name__ == "__main__":
    unittest.main()
