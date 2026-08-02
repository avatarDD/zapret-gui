/**
 * strategy_scan_hub.js — Раздел «Подбор стратегий».
 *
 * Объединяет два перебора, которые раньше были отдельными пунктами меню с
 * непрозрачными названиями («BlockCheck2 (официальный)» и
 * «BlockCheck(mod)») — при том что задача у них одна: найти стратегию,
 * которая пробивает блокировку. Отличается только движок перебора:
 *   • «Официальный» (Blockcheck2Page) — штатный blockcheck2.sh из zapret2,
 *     эталон, со своей телеметрией;
 *   • «По каталогу zapret-gui» (ScanPage) — наш перебор, результат
 *     применяется в один клик.
 *
 * Слова «BlockCheck» в меню больше нет: оно путалось с разделом
 * «Диагностика блокировок», который не подбирает стратегии, а ставит
 * диагноз.
 *
 * Хеш: #scan (официальный) и #scan?tab=catalog.
 */

const StrategyScanHubPage = (() => {

    const TABS = {
        official: {
            label: 'Официальный (blockcheck2.sh)',
            help:  'blockcheck2',
            desc:  'Штатный скрипт zapret2 с потоковой телеметрией — эталонный перебор.',
            page:  () => (typeof Blockcheck2Page !== 'undefined' ? Blockcheck2Page : null),
        },
        catalog: {
            label: 'По каталогу zapret-gui',
            help:  'scan',
            desc:  'Наш перебор стратегий из каталогов: найденное применяется в один клик.',
            page:  () => (typeof ScanPage !== 'undefined' ? ScanPage : null),
        },
    };

    let activeTab = 'official';
    let mountedTab = null;
    let rootEl = null;
    let hashHandler = null;

    /* ───────── lifecycle ───────── */

    function render(container) {
        rootEl = container;
        activeTab = _tabFromHash() || activeTab;

        const tab = TABS[activeTab];
        const helpBtn = (typeof Help !== 'undefined') ? Help.button(tab.help) : '';

        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    Подбор стратегий${helpBtn}
                </h1>
                <p class="page-description">${tab.desc}</p>
            </div>

            <div class="tabs-bar">
                ${Object.keys(TABS).map(id => `
                    <button class="tab-btn ${id === activeTab ? 'active' : ''}"
                            onclick="StrategyScanHubPage.switchTab('${id}')">
                        ${TABS[id].label}
                    </button>
                `).join('')}
            </div>

            <div id="scan-tab-body"></div>
        `;

        // Тот же приём, что в blockcheck_hub: при смене ?tab= на уже
        // открытом разделе роутер видит прежний pageId и не перерисовывает.
        if (!hashHandler) {
            hashHandler = () => {
                if (_pageFromHash() !== 'scan') return;
                const tab = _tabFromHash() || 'official';
                if (tab !== activeTab) switchTab(tab);
            };
            window.addEventListener('hashchange', hashHandler);
        }

        _mount();
    }

    function destroy() {
        if (hashHandler) {
            window.removeEventListener('hashchange', hashHandler);
            hashHandler = null;
        }
        _unmount();
        rootEl = null;
    }

    /* ───────── tabs ───────── */

    function switchTab(id) {
        if (!TABS[id] || id === activeTab) return;
        _unmount();
        activeTab = id;
        const target = (id === 'official') ? 'scan' : `scan?tab=${id}`;
        if (window.location.hash.slice(1) !== target) {
            window.location.hash = target;
        }
        if (rootEl) render(rootEl);
    }

    function _mount() {
        const body = document.getElementById('scan-tab-body');
        if (!body) return;
        const page = TABS[activeTab].page();
        if (!page) {
            body.innerHTML = '<div class="card"><div class="card-body text-error">Страница не загружена</div></div>';
            return;
        }
        mountedTab = activeTab;
        page.render(body);
    }

    function _unmount() {
        if (!mountedTab) return;
        const page = TABS[mountedTab] && TABS[mountedTab].page();
        // Оба перебора держат поллинг/SSE — без destroy() они продолжали бы
        // тянуть API уже закрытой вкладки.
        if (page && page.destroy) {
            try { page.destroy(); } catch (e) { /* не роняем переключение */ }
        }
        mountedTab = null;
    }

    function _pageFromHash() {
        const hash = window.location.hash.slice(1);
        const q = hash.indexOf('?');
        return q < 0 ? hash : hash.slice(0, q);
    }

    function _tabFromHash() {
        const hash = window.location.hash.slice(1);
        const q = hash.indexOf('?');
        if (q < 0) return null;
        const params = new URLSearchParams(hash.slice(q + 1));
        const tab = params.get('tab');
        return TABS[tab] ? tab : null;
    }

    return { render, destroy, switchTab };
})();
