# Каталоги стратегий nfqws2

**Единственный источник** всех builtin-стратегий проекта zapret-gui.

Пользовательские стратегии хранятся отдельно в `config/strategies/user/*.json`.

## Архитектура

```
catalogs/                  ← ВСЕ builtin-стратегии (INI, read-only)
├── builtin/               ← Полные конфигурации (с --filter-*/--new)
│   ├── zapret_gui_defaults.txt   ← дефолты zapret-gui
│   ├── winws2_presets.txt        ← winws2-пресеты, конвертированные в INI
│   └── z2k_*.txt                 ← оркестраторы circular/autocircular
├── basic/                 ← Базовые стратегии для быстрого сканирования
├── advanced/              ← Продвинутые стратегии
└── direct/                ← Одиночные приёмы desync (полный набор)

config/strategies/user/    ← Пользовательские стратегии (JSON, CRUD)
```

**Поток данных:**
1. `CatalogManager` загружает все INI-каталоги → ~1800 записей
2. `StrategyManager` берёт их из `CatalogManager` как builtin и
   схлопывает по `section_id` → ~730 стратегий в интерфейсе
3. Поверх загружаются user JSON-стратегии (перезаписывают по id)
4. Scanner находит рабочую стратегию → сохраняет как user JSON

## Откуда берутся и как обновляются

Каталоги — часть сборки GUI. Их «сырьё» лежит в `import/`, и на установке
и обновлении GUI `core/asset_importer.py` подмешивает его в `catalogs/`
через `core/catalog_merge.py`: слияние идёт по `section_id`, апстримная
секция побеждает на коллизии, а секции, которых в поставке нет (ваши
правки прямо в INI), сохраняются в конце файла.

Отдельной кнопки «обновить каталоги» в GUI больше нет. Раньше они
тянулись из `youtubediscord/zapret`, но в августе 2026 этот репозиторий
снят вместе со всей организацией — обновлять стало неоткуда, и загрузчик
убран (см. CHANGELOG). Если появится новый доверенный источник, его можно
вернуть: merge-семантика, ради которой всё писалось, на месте.

## INI-формат

### Одиночная стратегия (для scanner)

```ini
[fake_badseq_disorder]
name = Fake BadSeq + Disorder
author = Community
label = recommended
--lua-desync=fake:blob=fake_default_http:tcp_seq=-10000
--lua-desync=multidisorder:pos=host+1
```

### Полная конфигурация (с фильтрами и --new)

```ini
[tcp_default]
name = Default — базовая стратегия
label = recommended
--filter-tcp=80
--lua-desync=fake:blob=fake_default_http
--lua-desync=multisplit:pos=method+2
--new
--filter-tcp=443
--lua-desync=fake:blob=fake_default_tls
--lua-desync=multisplit:pos=1,midsld
```

## Использование

```python
from core.catalog_loader import get_catalog_manager
from core.strategy_builder import get_strategy_manager

# Каталоги (для scanner)
cm = get_catalog_manager()
quick = cm.get_quick_set(protocol="tcp")    # ~30 recommended

# Стратегии (единый API для UI)
sm = get_strategy_manager()
all_strats = sm.get_strategies()            # каталоги + user JSON
args = sm.build_nfqws_args(sm.get_strategy("tcp_default"))
