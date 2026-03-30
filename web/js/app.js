const App = (() => {
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
        Sidebar.render();
        Sidebar.initMobileToggle();
        window.addEventListener('hashchange', onHashChange);
        onHashChange();
    }
    function onHashChange() {
        const hash = window.location.hash.slice(1) || 'dashboard';
        navigateTo(hash);
    }
    function navigateTo(pageId) {
        if (!pages[pageId]) {
            pageId = 'dashboard';
            window.location.hash = pageId;
        }
        if (pageId === currentPageId) return;
        if (currentPage && currentPage.destroy) {
            currentPage.destroy();
        }
        currentPageId = pageId;
        currentPage = pages[pageId];
        Sidebar.setCurrentPage(pageId);
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
