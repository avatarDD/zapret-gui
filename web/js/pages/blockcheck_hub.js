/**
 * blockcheck_hub.js — Раздел «Диагностика блокировок».
 *
 * Объединяет две страницы, которые раньше жили порознь в разных группах меню
 * и решали половину общей задачи каждая:
 *   • «Тест доступности» (BlockcheckPage)  — разовый прогон по списку доменов,
 *     полный набор фаз (TLS/QUIC/STUN/CDN/traceroute) и вердикт с обходом;
 *   • «Мониторинг DNS»   (BlockDetectorPage) — фоновой демон: подсматривает
 *     живые DNS-запросы клиентов и сам находит, что именно ломается.
 *
 * Первый отвечает «как сломано», второй — «что сломано»; вместе это один
 * рабочий цикл, поэтому и вкладки одного раздела. Полностью сливать страницы
 * нельзя: у них разные жизненные циклы (демон против интерактивного прогона)
 * и разные требования (монитору нужны логи DNS или root).
 *
 * Хеш: #blockcheck (вкладка «Тест») и #blockcheck?tab=monitor.
 */

const BlockcheckHubPage = (() => {

    const TABS = {
        test: {
            label: 'Тест доступности',
            help:  'blockcheck',
            desc:  'Разовый прогон по списку доменов: TLS, QUIC, ClientHello, CDN, троттлинг — с вердиктом и способом обхода.',
            page:  () => (typeof BlockcheckPage !== 'undefined' ? BlockcheckPage : null),
        },
        monitor: {
            label: 'Мониторинг DNS',
            help:  'block-detector',
            desc:  'Фоновой детектор: следит за DNS-запросами клиентов, сам проверяет новые домены и может складывать заблокированные в список.',
            page:  () => (typeof BlockDetectorPage !== 'undefined' ? BlockDetectorPage : null),
        },
    };

    let activeTab = 'test';
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
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    Диагностика блокировок${helpBtn}
                </h1>
                <p class="page-description">${tab.desc}</p>
            </div>

            <div class="tabs-bar">
                ${Object.keys(TABS).map(id => `
                    <button class="tab-btn ${id === activeTab ? 'active' : ''}"
                            onclick="BlockcheckHubPage.switchTab('${id}')">
                        ${TABS[id].label}
                    </button>
                `).join('')}
            </div>

            <div id="bcd-tab-body"></div>
        `;

        // Смена ?tab= при уже открытом разделе (легаси-хеш #block-detector,
        // «назад» в браузере, вставленная ссылка): App.navigateTo видит тот же
        // pageId и ничего не перерисовывает — вкладку переключаем сами.
        if (!hashHandler) {
            hashHandler = () => {
                if (_pageFromHash() !== 'blockcheck') return;
                const tab = _tabFromHash() || 'test';
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
        // Хеш меняем ради закладок и кнопки «назад». App.navigateTo увидит тот
        // же pageId ('blockcheck') и перерисовку не запустит — рисуем сами.
        const target = (id === 'test') ? 'blockcheck' : `blockcheck?tab=${id}`;
        if (window.location.hash.slice(1) !== target) {
            window.location.hash = target;
        }
        if (rootEl) render(rootEl);
    }

    function _mount() {
        const body = document.getElementById('bcd-tab-body');
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
        // Таймеры опроса живут в самих страницах — без destroy() они бы
        // продолжали дёргать API уже несуществующей вкладки.
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

    /* ───────── cross-tab ───────── */

    /**
     * «Проверить глубоко» из мониторинга: открыть вкладку теста с этим
     * доменом. Монитор говорит, ЧТО сломалось, тест — на каком слое и чем
     * лечится; переход между ними и есть рабочий цикл раздела.
     */
    function deepCheck(domain) {
        if (!domain) return;
        const page = TABS.test.page();
        if (page && page.prefill) page.prefill([domain], 'dpi_only');
        switchTab('test');
        if (typeof Toast !== 'undefined') {
            Toast.info(`Список заменён на ${domain} — нажмите «Запустить» (вернуть свой: «Сбросить»)`);
        }
    }

    return { render, destroy, switchTab, deepCheck };
})();
