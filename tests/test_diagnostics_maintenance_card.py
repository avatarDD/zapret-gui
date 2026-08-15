# tests/test_diagnostics_maintenance_card.py
"""Регрессия: кнопки «Перезапустить zapret-gui» и «Перезагрузить роутер»
пропадали со страницы «Диагностика».

Карточка «Обслуживание» рисовалась скрытой (`display:none`) и
показывалась ТОЛЬКО при успешном ответе `/api/system/control`. Любой сбой
этого запроса — таймаут (15 с на занятом роутере набираются легко: во
время самодиагностики он молотит юнит-тесты минутами), обрыв, ошибка
сервера — оставлял её скрытой навсегда: повторной попытки не было, и с
точки зрения пользователя кнопки просто исчезали.

Проверяем разметку и код страницы: карточка не скрыта заранее, ошибка
проверки не прячет её, а лишь гасит кнопки, и есть кнопка повтора.
Заодно — что API отдаёт причину недоступности, чтобы её было что
показать.
"""

import os
import re
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PAGE = os.path.join(_ROOT, "web", "js", "pages", "diagnostics.js")


class TestMaintenanceCardVisibility(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(_PAGE, encoding="utf-8") as f:
            cls.src = f.read()

    def _card_tag(self) -> str:
        m = re.search(r"<div[^>]*id=\"diag-maintenance-card\"[^>]*>", self.src)
        self.assertIsNotNone(m, "карточка «Обслуживание» исчезла со страницы")
        return m.group(0)

    def test_card_is_not_hidden_by_default(self):
        self.assertNotIn("display:none", self._card_tag().replace(" ", ""))

    def test_buttons_exist(self):
        self.assertIn('id="diag-restart-gui"', self.src)
        self.assertIn('id="diag-reboot"', self.src)

    def test_failed_capability_check_does_not_hide_the_card(self):
        body = self._function_body("loadMaintenanceCaps")
        self.assertNotIn("card.style.display", body)
        # В catch-ветке должно остаться объяснение, а не молчание.
        self.assertIn("_setMaintenanceStatus", body)

    def test_retry_is_offered(self):
        self.assertIn("retryMaintenanceCaps", self.src)
        self.assertIn('id="diag-maintenance-retry"', self.src)

    def _function_body(self, name: str) -> str:
        start = self.src.index("function %s(" % name)
        depth, i = 0, self.src.index("{", start)
        for j in range(i, len(self.src)):
            if self.src[j] == "{":
                depth += 1
            elif self.src[j] == "}":
                depth -= 1
                if depth == 0:
                    return self.src[start:j + 1]
        self.fail("не удалось разобрать тело %s" % name)


class TestControlCapabilities(unittest.TestCase):

    def test_capabilities_explain_what_is_missing(self):
        from core import system_control
        caps = system_control.capabilities()
        self.assertTrue(caps["ok"])
        for key in ("restart_gui", "reboot", "restart_command",
                    "reboot_command"):
            self.assertIn(key, caps)
        # Команда и флаг обязаны быть согласованы: флаг True без команды
        # означал бы кнопку, которой не на чем сработать.
        self.assertEqual(caps["restart_gui"], bool(caps["restart_command"]))
        self.assertEqual(caps["reboot"], bool(caps["reboot_command"]))


if __name__ == "__main__":
    unittest.main()
