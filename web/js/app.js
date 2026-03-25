/**
 * app.js — Точка входа SPA.
 *
 * Hash-based роутинг (#dashboard, #control, #strategies, #blobs, #logs, #settings).
 * Инициализация sidebar, загрузка начальной страницы.
 */

const App = (() => {
    // Реестр страниц: id → { render(container), destroy?() }
    const pages = {
        dashboard:   DashboardPage,
        control:     ControlPage,
        strategies:  StrategiesPage,
        hostlists:   HostlistsPage,
        ipsets:      IPSetsPage,
        blobs:       BlobsPage,
        hosts:       HostsPage,
        diagnostics: DiagnosticsPage,
        logs:        LogsPage,
        autostart:   AutostartPage,
        zapret:      ZapretManagerPage,
        settings:    SettingsPage,
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

    // Запуск при загрузке DOM
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { navigateTo };
})();


