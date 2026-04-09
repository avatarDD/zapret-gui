# Каталоги стратегий nfqws2

**Единственный источник** всех builtin-стратегий проекта zapret-gui.

Пользовательские стратегии хранятся отдельно в `config/strategies/user/*.json`.

## Архитектура

```
catalogs/                  ← ВСЕ builtin-стратегии (INI, read-only)
├── builtin/               ← Встроенные стратегии zapret-gui (8 шт.)
│   └── zapret_gui_defaults.txt
├── basic/                 ← Базовые стратегии для быстрого сканирования
├── advanced/              ← Продвинутые стратегии
└── direct/                ← Прямые стратегии (полный набор)

config/strategies/user/    ← Пользовательские стратегии (JSON, CRUD)
```

**Поток данных:**
1. `CatalogManager` загружает все INI-каталоги → 500+ стратегий
2. `StrategyManager` берёт их из `CatalogManager` как builtin
3. Поверх загружаются user JSON-стратегии (перезаписывают по id)
4. Scanner находит рабочую стратегию → сохраняет как user JSON

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
