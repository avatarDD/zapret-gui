/**
 * app.js — Точка входа SPA.
 *
 * Hash-based роутинг (#dashboard, #control, #strategies, #blobs, #logs, #settings).
 * Инициализация sidebar, загрузка начальной страницы.
 */

const App = (() => {
    // Реестр страниц: id → { render(container), destroy?() }
    const pages = {
        dashboard:  DashboardPage,
        control:    ControlPage,
        strategies: StrategiesPage,
        hostlists:  HostlistsPage,
        ipsets:     IPSetsPage,
        blobs:      BlobsPage,
        hosts:      HostsPage,
        diagnostics: DiagnosticsPage,
        // Заглушки для будущих страниц:
        logs:     { render: (c) => renderPlaceholder(c, 'Логи', 'Будет реализовано в Фазе 7') },
        settings: { render: (c) => renderPlaceholder(c, 'Настройки', 'Будет реализовано в Фазе 9') },
    };

    let currentPage = null;
    let currentPageId = null;

    function init() {
        // Рендерим sidebar
        Sidebar.render();
        Sidebar.initMobileToggle();

        // Слушаем изменение hash
        window.addEventListener('hashchange', onHashChange);

        // Начальная навигация
        onHashChange();
    }

    function onHashChange() {
        const hash = window.location.hash.slice(1) || 'dashboard';
        navigateTo(hash);
    }

    function navigateTo(pageId) {
        // Если такой страницы нет — на dashboard
        if (!pages[pageId]) {
            pageId = 'dashboard';
            window.location.hash = pageId;
        }

        // Не перерисовываем если уже на этой странице
        if (pageId === currentPageId) return;

        // Уничтожаем текущую страницу
        if (currentPage && currentPage.destroy) {
            currentPage.destroy();
        }

        currentPageId = pageId;
        currentPage = pages[pageId];

        // Обновляем sidebar
        Sidebar.setCurrentPage(pageId);

        // Рендерим страницу
        const container = document.getElementById('page-container');
        if (container && currentPage) {
            container.innerHTML = '';
            currentPage.render(container);
        }
    }

    function renderPlaceholder(container, title, description) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">${title}</h1>
                <p class="page-description">${description}</p>
            </div>
            <div class="card" style="text-align: center; padding: 48px 20px;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                     width="48" height="48" style="color: var(--text-muted); margin-bottom: 16px;">
                    <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                    <path d="M2 17l10 5 10-5"/>
                    <path d="M2 12l10 5 10-5"/>
                </svg>
                <div style="color: var(--text-secondary); font-size: 15px; font-weight: 500; margin-bottom: 8px;">
                    В разработке
                </div>
                <div style="color: var(--text-muted); font-size: 13px;">
                    ${description}
                </div>
            </div>
        `;
    }

    // Запуск при загрузке DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { navigateTo };
})();


