# tests package — unit-тесты zapret-gui.
#
# Запуск:
#     python3 -m unittest discover -s tests -v
#
# Тесты должны работать без сети (DoH/RCI/HTTP-fetch — через моки)
# и без spawned subprocess'ов (nft/ipset/awg — через моки _run).
