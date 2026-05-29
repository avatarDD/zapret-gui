/**
 * list_ui.js — Универсальный компонент для длинных списков.
 *
 * Решает «прокрутку полчаса» на страницах со многими карточками/строками:
 *
 *   • Поиск с debounce (по нескольким полям одновременно)
 *   • Группировка с sticky-заголовками и счётчиками
 *   • Прогрессивный рендер: чанками по N, добавление по «Показать ещё» либо
 *     автозагрузка через IntersectionObserver — без проблем «настоящей»
 *     виртуализации (карточки переменной высоты не дружат с фиксированными
 *     окнами и ломаются при ресайзе)
 *   • Компактный/развёрнутый режим элемента (раскрытие по клику)
 *   • Сохранение состояния (поиск/группа/режим) в localStorage по storageKey
 *
 * Использование:
 *
 *   const ui = ListUI.create({
 *       container: document.getElementById('strategies-list'),
 *       items: strategies,
 *       searchFields: s => [s.name, s.description, s.author],
 *       filters: [
 *           { id: 'all', label: 'Все', test: () => true, default: true },
 *           { id: 'fav', label: 'Избранное', test: s => s.is_favorite },
 *       ],
 *       groupBy: s => s.protocol || 'tcp',  // null → без групп
 *       groupLabel: g => ({tcp:'TCP', udp:'UDP'}[g] || g),
 *       renderItem: s => `<div class="strategy-card">…</div>`,
 *       pageSize: 50,
 *       storageKey: 'strategies-list',
 *   });
 *   ui.setItems(newItems);     // когда данные пришли с сервера
 *   ui.refresh();              // перерисовать (например, после toggleFavorite)
 *   ui.destroy();
 */

const ListUI = (() => {

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function loadState(key) {
        if (!key) return {};
        try { return JSON.parse(localStorage.getItem(key) || '{}'); }
        catch (_e) { return {}; }
    }

    function saveState(key, state) {
        if (!key) return;
        try { localStorage.setItem(key, JSON.stringify(state)); }
        catch (_e) { /* quota — игнорируем */ }
    }

    function create(opts) {
        const cfg = Object.assign({
            container: null,
            items: [],
            searchPlaceholder: 'Поиск...',
            searchFields: () => [],
            filters: null,            // [{id, label, test, default}]
            groupBy: null,
            groupLabel: g => g,
            renderItem: () => '',
            renderEmpty: () => '<div class="list-ui-empty">Ничего не найдено</div>',
            pageSize: 50,
            countLabel: (visible, total) => `${visible} из ${total}`,
            storageKey: null,
            toolbarExtra: '',         // произвольный HTML справа от поиска
        }, opts || {});

        if (!cfg.container) {
            throw new Error('ListUI: container is required');
        }

        // ──────────────────────── state ────────────────────────
        const saved = loadState(cfg.storageKey);
        const state = {
            search: saved.search || '',
            filterId: saved.filterId
                || (cfg.filters && cfg.filters.find(f => f.default)?.id)
                || (cfg.filters && cfg.filters[0] && cfg.filters[0].id)
                || null,
            collapsedGroups: new Set(saved.collapsedGroups || []),
            visibleCount: cfg.pageSize,
        };

        let items = (cfg.items || []).slice();
        let filteredCache = null;
        let intersectionObserver = null;

        // ────────────────────── DOM scaffold ───────────────────
        const root = cfg.container;
        root.classList.add('list-ui');
        root.innerHTML = `
            <div class="list-ui-toolbar">
                <div class="list-ui-search">
                    <svg class="list-ui-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    <input type="text" class="form-input list-ui-search-input"
                           placeholder="${escapeHtml(cfg.searchPlaceholder)}"
                           value="${escapeHtml(state.search)}"
                           spellcheck="false" autocomplete="off">
                    <button class="list-ui-search-clear" title="Очистить" style="display:none;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
                            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="list-ui-toolbar-right">
                    <span class="list-ui-count" data-list-ui="count"></span>
                    ${cfg.toolbarExtra || ''}
                </div>
            </div>
            ${cfg.filters ? `<div class="list-ui-filters" data-list-ui="filters"></div>` : ''}
            <div class="list-ui-body" data-list-ui="body"></div>
            <div class="list-ui-loadmore" data-list-ui="loadmore" style="display:none;">
                <button type="button" class="btn btn-ghost btn-sm">Показать ещё</button>
                <div class="list-ui-loadmore-sentinel"></div>
            </div>
        `;

        const $input = root.querySelector('.list-ui-search-input');
        const $clear = root.querySelector('.list-ui-search-clear');
        const $count = root.querySelector('[data-list-ui="count"]');
        const $filters = root.querySelector('[data-list-ui="filters"]');
        const $body = root.querySelector('[data-list-ui="body"]');
        const $loadmore = root.querySelector('[data-list-ui="loadmore"]');
        const $loadBtn = $loadmore.querySelector('button');
        const $sentinel = $loadmore.querySelector('.list-ui-loadmore-sentinel');

        // ─────────────────── render filters ────────────────────
        if (cfg.filters && $filters) {
            $filters.innerHTML = cfg.filters.map(f => `
                <button type="button"
                        class="btn btn-ghost btn-sm list-ui-filter${state.filterId === f.id ? ' active' : ''}"
                        data-filter-id="${escapeHtml(f.id)}">${escapeHtml(f.label)}</button>
            `).join('');
            $filters.addEventListener('click', e => {
                const btn = e.target.closest('[data-filter-id]');
                if (!btn) return;
                state.filterId = btn.dataset.filterId;
                $filters.querySelectorAll('[data-filter-id]').forEach(b =>
                    b.classList.toggle('active', b.dataset.filterId === state.filterId));
                resetPagination();
                persist();
                refresh();
            });
        }

        // ─────────────────── search input ─────────────────────
        const onSearch = Utils.debounce(value => {
            state.search = value.trim();
            $clear.style.display = state.search ? '' : 'none';
            resetPagination();
            persist();
            refresh();
        }, 200);

        $input.addEventListener('input', e => onSearch(e.target.value));
        $input.addEventListener('keydown', e => {
            if (e.key === 'Escape' && state.search) {
                $input.value = '';
                onSearch('');
            }
        });
        $clear.style.display = state.search ? '' : 'none';
        $clear.addEventListener('click', () => {
            $input.value = '';
            state.search = '';
            $clear.style.display = 'none';
            resetPagination();
            persist();
            refresh();
            $input.focus();
        });

        // ─────────────────── group toggle (delegation) ─────────
        $body.addEventListener('click', e => {
            const head = e.target.closest('[data-list-ui-group]');
            if (head) {
                const gid = head.dataset.listUiGroup;
                if (state.collapsedGroups.has(gid)) state.collapsedGroups.delete(gid);
                else state.collapsedGroups.add(gid);
                persist();
                refresh();
                return;
            }
            const toggle = e.target.closest('[data-list-ui-toggle]');
            if (toggle) {
                const card = toggle.closest('[data-list-ui-card]');
                if (card) card.classList.toggle('expanded');
            }
        });

        // ─────────────────── load more ─────────────────────────
        $loadBtn.addEventListener('click', () => {
            state.visibleCount += cfg.pageSize;
            refresh();
        });

        // IntersectionObserver — автоподгрузка при докрутке к сентинелу.
        if ('IntersectionObserver' in window) {
            intersectionObserver = new IntersectionObserver(entries => {
                for (const e of entries) {
                    if (e.isIntersecting && $loadmore.style.display !== 'none') {
                        state.visibleCount += cfg.pageSize;
                        refresh();
                        break;
                    }
                }
            }, { rootMargin: '200px' });
            intersectionObserver.observe($sentinel);
        }

        // ──────────────────────── helpers ──────────────────────
        function resetPagination() { state.visibleCount = cfg.pageSize; }

        function persist() {
            saveState(cfg.storageKey, {
                search: state.search,
                filterId: state.filterId,
                collapsedGroups: Array.from(state.collapsedGroups),
            });
        }

        function applyFilters() {
            let res = items;
            if (cfg.filters && state.filterId) {
                const f = cfg.filters.find(x => x.id === state.filterId);
                if (f) res = res.filter(f.test);
            }
            if (state.search) {
                const needles = state.search.toLowerCase().split(/\s+/).filter(Boolean);
                res = res.filter(it => {
                    const hay = cfg.searchFields(it).filter(Boolean)
                        .join(' ').toLowerCase();
                    return needles.every(n => hay.includes(n));
                });
            }
            return res;
        }

        function refresh() {
            const filtered = applyFilters();
            filteredCache = filtered;
            const total = items.length;
            const filteredN = filtered.length;
            const visibleN = Math.min(state.visibleCount, filteredN);
            $count.textContent = cfg.countLabel(visibleN, total) +
                (state.search || (cfg.filters && state.filterId !== cfg.filters[0]?.id)
                    ? ' (отфильтровано из ' + total + ')' : '');

            if (filteredN === 0) {
                $body.innerHTML = '';
                $body.appendChild(htmlToNode(cfg.renderEmpty(state.search, state.filterId)));
                $loadmore.style.display = 'none';
                return;
            }

            const window_ = filtered.slice(0, visibleN);

            if (cfg.groupBy) {
                renderGrouped(window_);
            } else {
                renderFlat(window_);
            }

            $loadmore.style.display = visibleN < filteredN ? '' : 'none';
            if ($loadBtn) {
                const rest = filteredN - visibleN;
                $loadBtn.textContent = 'Показать ещё (' + Math.min(cfg.pageSize, rest) + ' из ' + rest + ')';
            }
        }

        function renderFlat(window_) {
            $body.innerHTML = window_.map(cfg.renderItem).join('');
        }

        function renderGrouped(window_) {
            const groups = new Map();
            for (const it of window_) {
                const g = cfg.groupBy(it) ?? '_';
                if (!groups.has(g)) groups.set(g, []);
                groups.get(g).push(it);
            }
            let html = '';
            for (const [gid, list] of groups) {
                const collapsed = state.collapsedGroups.has(String(gid));
                html += `
                    <div class="list-ui-group ${collapsed ? 'collapsed' : ''}">
                        <button type="button" class="list-ui-group-header" data-list-ui-group="${escapeHtml(String(gid))}">
                            <svg class="list-ui-group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="6 9 12 15 18 9"/>
                            </svg>
                            <span class="list-ui-group-label">${escapeHtml(cfg.groupLabel(gid))}</span>
                            <span class="list-ui-group-count">${list.length}</span>
                        </button>
                        <div class="list-ui-group-body">
                            ${list.map(cfg.renderItem).join('')}
                        </div>
                    </div>
                `;
            }
            $body.innerHTML = html;
        }

        function htmlToNode(html) {
            const t = document.createElement('div');
            t.innerHTML = html;
            return t.firstElementChild || t;
        }

        // Первый рендер.
        refresh();

        // ─────────────────────── public API ─────────────────────
        return {
            setItems(next) { items = (next || []).slice(); resetPagination(); refresh(); },
            getItems() { return items.slice(); },
            getFiltered() { return (filteredCache || []).slice(); },
            refresh,
            destroy() {
                if (intersectionObserver) {
                    try { intersectionObserver.disconnect(); } catch (_e) {}
                    intersectionObserver = null;
                }
                if (root) root.classList.remove('list-ui');
            },
        };
    }

    return { create };
})();
