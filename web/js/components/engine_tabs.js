/**
 * engine_tabs.js — раздел «Обход DPI», сгруппированный по задачам.
 *
 * У обхода два движка (nfqws2 и geneva_c), а задачи у них одни и те же:
 * управлять движком, выбрать стратегию, подобрать стратегию. Поэтому меню
 * устроено по задачам, а движок — вкладка внутри задачи:
 *
 *   Движок обхода      — какой движок работает, переключение (#bypass)
 *   Управление         — nfqws2 | geneva_c  (#control?engine=…)
 *   Стратегии          — nfqws2 | geneva_c  (#strategies?engine=…)
 *   Подбор стратегий   — вкладки переборов nfqws2 и генетический geneva_c
 *                        (strategy_scan_hub.js, #scan?tab=geneva)
 *
 * Без ?engine= открывается вкладка АКТИВНОГО движка: человек попадает к
 * тому, что у него сейчас работает.
 */

const EngineTabs = (() => {

    const ENGINES = [
        { id: 'nfqws2', label: 'nfqws2' },
        { id: 'geneva', label: 'geneva_c' },
    ];

    function _hashParts() {
        const h = window.location.hash.slice(1);
        const q = h.indexOf('?');
        return {
            page: q >= 0 ? h.slice(0, q) : h,
            params: new URLSearchParams(q >= 0 ? h.slice(q + 1) : ''),
        };
    }

    /**
     * Страница-задача с вкладками движков.
     *
     * @param {object} o
     * @param {string} o.pageId   id страницы в роутере (control, strategies)
     * @param {Function} o.nfqws  () => страница nfqws2 ({render, destroy})
     * @param {object} o.geneva   опции GenevaPage.render: sections, title…
     */
    function make(o) {
        let root = null;
        let mounted = null;      // 'nfqws2' | 'geneva'
        let current = null;
        let active = '';
        let hashHandler = null;

        async function render(container) {
            root = container;
            const want = _hashParts().params.get('engine');
            if (!active) {
                try {
                    const ov = await API.get('/api/bypass/engine');
                    active = ov.active || 'nfqws2';
                } catch (_) {
                    active = 'nfqws2';
                }
            }
            if (root !== container) return;          // ушли со страницы
            current = ENGINES.some(e => e.id === want) ? want : active;
            container.innerHTML = `
                <div class="tabs-bar engine-tabs" role="tablist" aria-label="Движок обхода">
                    ${ENGINES.map(e => `
                        <button class="tab-btn ${e.id === current ? 'active' : ''}" data-engine="${e.id}" role="tab"
                                aria-selected="${e.id === current}">
                            ${e.label}
                            ${e.id === active ? '<span class="badge badge-success">работает сейчас</span>' : ''}
                        </button>`).join('')}
                    <a class="engine-tabs-link" href="#bypass">выбор движка →</a>
                </div>
                <div class="engine-tabs-body"></div>`;
            container.querySelectorAll('[data-engine]').forEach(btn => {
                btn.addEventListener('click', () => _select(btn.dataset.engine));
            });
            if (!hashHandler) {
                hashHandler = () => {
                    const h = _hashParts();
                    if (h.page !== o.pageId || !root) return;
                    const e = h.params.get('engine') || active;
                    if (e !== current) render(root);
                };
                window.addEventListener('hashchange', hashHandler);
            }
            _mount(container.querySelector('.engine-tabs-body'));
        }

        function _select(id) {
            if (id === current) return;
            // Хеш держит выбор: «Назад» и ссылка из «Обновлений» ведут
            // ровно на эту вкладку.
            window.location.hash = o.pageId + '?engine=' + id;
        }

        function _mount(body) {
            _unmount();
            if (!body) return;
            if (current === 'geneva') {
                mounted = 'geneva';
                GenevaPage.render(body, o.geneva);
                return;
            }
            const page = o.nfqws();
            if (!page) {
                body.innerHTML = '<div class="card"><div class="card-body text-error">Страница не загружена</div></div>';
                return;
            }
            mounted = 'nfqws2';
            page.render(body);
        }

        function _unmount() {
            if (!mounted) return;
            const page = mounted === 'geneva' ? GenevaPage : o.nfqws();
            if (page && page.destroy) {
                try { page.destroy(); } catch (_) { /* не роняем переключение */ }
            }
            mounted = null;
        }

        function destroy() {
            if (hashHandler) {
                window.removeEventListener('hashchange', hashHandler);
                hashHandler = null;
            }
            _unmount();
            root = null;
            // Активный движок могли переключить — при следующем входе
            // спросим заново.
            active = '';
        }

        return { render, destroy };
    }

    return { make };
})();

/* Страницы раздела «Обход DPI». */

const BypassPage = {
    render: c => GenevaPage.render(c, { sections: ['engines'] }),
    destroy: () => GenevaPage.destroy(),
};

const ControlHubPage = EngineTabs.make({
    pageId: 'control',
    nfqws: () => (typeof ControlPage !== 'undefined' ? ControlPage : null),
    geneva: {
        sections: ['engine', 'settings'],
        title: 'Управление',
        subtitle: 'Запуск, остановка, рабочая стратегия и телеметрия geneva_c',
    },
});

const StrategiesHubPage = EngineTabs.make({
    pageId: 'strategies',
    nfqws: () => (typeof StrategiesPage !== 'undefined' ? StrategiesPage : null),
    geneva: {
        sections: ['library'],
        title: 'Стратегии',
        subtitle: 'Готовые стратегии Geneva: проверить на своей сети и сделать рабочей',
    },
});
