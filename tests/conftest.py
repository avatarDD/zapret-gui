# tests/conftest.py
"""Общая настройка pytest для всего набора тестов."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Правка списка откладывает переприменение маршрутов единого слоя в
# фоновый таймер (core.unified.manager.notify_list_changed). В тестах он
# сработал бы через несколько секунд уже внутри чужого теста — со своими
# настройками и моками. Проверяется этот механизм отдельно и синхронно.
import core.unified.manager as _unified_manager  # noqa: E402

_unified_manager.AUTO_REAPPLY = False
