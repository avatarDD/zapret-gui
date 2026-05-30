/**
 * sidebar.js — Боковая навигация.
 *
 * Определяет все страницы и рендерит меню.
 * Иконки — inline SVG (без внешних зависимостей).
 */

const Sidebar = (() => {

    // Иконки (Lucide-совместимые SVG paths)
    const ICONS = {
        dashboard:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>',
        play:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
        strategy:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        list:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
        globe:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        blob:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>',
        log:         '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
        settings:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        hostlist:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/><path d="M2 12h20"/><path d="M12 2c2.5 2.8 3.9 6.3 3.9 10s-1.4 7.2-3.9 10c-2.5-2.8-3.9-6.3-3.9-10S9.5 4.8 12 2z"/></svg>',
        ipset:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/><line x1="2" y1="15" x2="22" y2="15"/><line x1="8" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="16" y2="21"/></svg>',
        lua:         '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="10 13 8 15 10 17"/><polyline points="14 17 16 15 14 13"/></svg>',
        autostart:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>',
        zapret:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
        hosts:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
        diagnostic:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
        blockcheck:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
        scan:        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>',
        awg:         '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M8 11l3 3 5-6"/></svg>',
        chevron:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
    };

    // Группы с разделителями. Порядок — по логике использования:
    // Главная → обход DPI (nfqws2) → VPN/туннели → списки/данные →
    // диагностика → система.
    const NAV_GROUPS = [
        {
            items: [
                { id: 'dashboard', label: 'Главная', icon: 'dashboard' },
            ]
        },
        {
            label: 'Обход DPI (nfqws2)',
            items: [
                { id: 'control',    label: 'Управление',       icon: 'play' },
                { id: 'strategies', label: 'Стратегии',        icon: 'strategy' },
                { id: 'scan',       label: 'Подбор стратегий', icon: 'scan' },
                { id: 'blockcheck', label: 'BlockCheck',       icon: 'blockcheck' },
            ]
        },
        {
            label: 'VPN и маршрутизация',
            items: [
                { id: 'routing', label: 'Маршрутизация', icon: 'globe' },
                { id: 'awg', label: 'AmneziaWG', icon: 'awg', children: [
                    { id: 'awg-configs', label: 'Конфиги',  icon: 'lua' },
                    { id: 'awg-warp',    label: 'WARP',      icon: 'awg' },
                    { id: 'awg-routing', label: 'AWG-правила', icon: 'globe' },
                    { id: 'awg-setup',   label: 'Установка', icon: 'settings' },
                ] },
                { id: 'singbox', label: 'sing-box', icon: 'awg', children: [
                    { id: 'singbox-configs', label: 'Конфиги',  icon: 'lua' },
                    { id: 'singbox-setup',   label: 'Установка', icon: 'settings' },
                ] },
                { id: 'mihomo', label: 'mihomo', icon: 'awg' },
            ]
        },
        {
            label: 'Списки и данные',
            items: [
                { id: 'lists',     label: 'Списки маршрутизации', icon: 'globe' },
                { id: 'hostlists', label: 'Домены (nfqws2)', icon: 'hostlist' },
                { id: 'ipsets',    label: 'IP-списки',    icon: 'ipset' },
                { id: 'blobs',     label: 'Блобы',        icon: 'blob' },
                { id: 'lua',       label: 'Lua-скрипты',  icon: 'lua' },
                { id: 'hosts',     label: 'Hosts',        icon: 'hosts' },
            ]
        },
        {
            label: 'Диагностика',
            items: [
                { id: 'diagnostics', label: 'Диагностика', icon: 'diagnostic' },
                { id: 'logs',        label: 'Логи',        icon: 'log' },
            ]
        },
        {
            label: 'Система',
            items: [
                { id: 'zapret',      label: 'Zapret2 (установка)', icon: 'zapret' },
                { id: 'autostart',   label: 'Автозапуск',  icon: 'autostart' },
                { id: 'settings',    label: 'Настройки',   icon: 'settings' },
            ]
        },
    ];

    let currentPage = 'dashboard';
    // Состояние раскрытия родительских пунктов дерева (id → bool).
    const expanded = {};

    function _hasActiveChild(item) {
        return (item.children || []).some(c => c.id === currentPage);
    }

    function _navigate(pageId) {
        window.location.hash = pageId;
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar')?.classList.remove('open');
        }
    }

    function _renderLeaf(parentEl, item, isChild) {
        const el = document.createElement('div');
        el.className = 'nav-item'
            + (isChild ? ' nav-child' : '')
            + (item.id === currentPage ? ' active' : '');
        el.dataset.page = item.id;
        el.innerHTML = `
            <span class="nav-item-icon">${ICONS[item.icon] || ''}</span>
            <span class="nav-item-label">${item.label}</span>
        `;
        el.addEventListener('click', () => _navigate(item.id));
        parentEl.appendChild(el);
    }

    function _renderParent(nav, item) {
        // Автораскрытие, если активна сама ветка или один из детей.
        if (expanded[item.id] === undefined
            && (item.id === currentPage || _hasActiveChild(item))) {
            expanded[item.id] = true;
        }
        const isOpen = !!expanded[item.id];

        const row = document.createElement('div');
        row.className = 'nav-item nav-parent'
            + (item.id === currentPage ? ' active' : '')
            + (_hasActiveChild(item) ? ' has-active-child' : '')
            + (isOpen ? ' open' : '');
        row.dataset.page = item.id;
        row.innerHTML = `
            <span class="nav-item-icon">${ICONS[item.icon] || ''}</span>
            <span class="nav-item-label">${item.label}</span>
            <span class="nav-caret">${ICONS.chevron}</span>
        `;
        row.addEventListener('click', (e) => {
            // Клик по шеврону — только свернуть/развернуть, без перехода.
            if (e.target.closest('.nav-caret')) {
                expanded[item.id] = !expanded[item.id];
                render();
                return;
            }
            // Клик по строке — переходим на страницу и раскрываем ветку.
            expanded[item.id] = true;
            if (item.id) _navigate(item.id);
            else { render(); }
        });
        nav.appendChild(row);

        const box = document.createElement('div');
        box.className = 'nav-children' + (isOpen ? ' open' : '');
        (item.children || []).forEach(c => _renderLeaf(box, c, true));
        nav.appendChild(box);
    }

    function render() {
        const nav = document.getElementById('sidebar-nav');
        if (!nav) return;

        nav.innerHTML = '';

        NAV_GROUPS.forEach((group, gi) => {
            if (group.items.length === 0) return;

            // Разделитель между группами (кроме первой)
            if (gi > 0) {
                const sep = document.createElement('div');
                sep.className = 'nav-separator';
                nav.appendChild(sep);
            }

            // Метка секции
            if (group.label) {
                const label = document.createElement('div');
                label.className = 'nav-section-label';
                label.textContent = group.label;
                nav.appendChild(label);
            }

            // Элементы (с поддержкой вложенных children)
            group.items.forEach(item => {
                if (item.children && item.children.length) {
                    _renderParent(nav, item);
                } else {
                    _renderLeaf(nav, item, false);
                }
            });
        });
    }

    function setCurrentPage(pageId) {
        currentPage = pageId;
        // Полная перерисовка — чтобы активная ветка дерева авто-раскрылась
        // (например, при переходе по прямой ссылке на дочернюю страницу).
        render();
    }

    function initMobileToggle() {
        const toggle = document.getElementById('sidebar-toggle');
        const sidebar = document.getElementById('sidebar');
        if (!toggle || !sidebar) return;

        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            sidebar.classList.toggle('open');
        });

        // Закрытие при клике вне sidebar на мобильных
        document.addEventListener('click', (e) => {
            if (window.innerWidth <= 768 &&
                sidebar.classList.contains('open') &&
                !sidebar.contains(e.target)) {
                sidebar.classList.remove('open');
            }
        });
    }

    return { render, setCurrentPage, initMobileToggle };
})();
