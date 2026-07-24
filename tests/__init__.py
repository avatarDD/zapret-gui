# tests package — unit-тесты zapret-gui.
#
# Запуск:
#     python3 -m unittest discover -s tests -v
#
# Тесты должны работать без сети (DoH/RCI/HTTP-fetch — через моки)
# и без spawned subprocess'ов (nft/ipset/awg — через моки _run).

import sys
from unittest.mock import MagicMock

# Mock Unix-only modules for running tests on Windows
for mod_name in ['pty', 'tty', 'termios']:
    try:
        __import__(mod_name)
    except ImportError:
        sys.modules[mod_name] = MagicMock()
