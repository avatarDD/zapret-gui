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

# Сторожа перед рестартом спрашивают «не лежит ли WAN» (core.reachability)
# — это TCP-соединения наружу. В тестах сеть недоступна или медленная, и
# каждый тест сторожа ждал бы таймаутов, а то и решал бы, что WAN лежит.
# По умолчанию WAN «жив»; тесты самого модуля подменяют _connect сами.
import core.reachability as _reachability  # noqa: E402

_reachability._connect = lambda addr, timeout=None: True
# Поток «ждём возвращения WAN» в тестах не нужен: возвращение они
# проверяют явным замером.
_reachability.WATCH_RECOVERY = False

# Интерфейсов туннелей (awg0, tun0…) в тестовом окружении нет: проверка
# «метод смотрит в существующий интерфейс» при сохранении маршрута
# отвергла бы почти любой тестовый маршрут. Механизм проверяется отдельно.
_unified_manager.CHECK_IFACES = False
