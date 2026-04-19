/**
 * app.js - SPA entry point.
 *
 * Hash-based routing (#dashboard, #control, #strategies, #blobs, #logs, #settings).
 * Initializes the sidebar and loads the initial page.
 */

const App = (() => {
    // Page registry: id -> { render(container), destroy?() }
    const pages = {
        dashboard:   DashboardPage,
        control:     ControlPage,
        strategies:  StrategiesPage,
        hostlists:   HostlistsPage,
        ipsets:      IPSetsPage,
        blobs:       BlobsPage,
        hosts:       HostsPage,
        diagnostics: DiagnosticsPage,
        blockcheck:  BlockcheckPage,
        scan:        ScanPage,
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
        loadGuiVersion();

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

    async function loadGuiVersion() {
        const sidebarVersion = document.getElementById('sidebar-version');
        if (!sidebarVersion) return;

        try {
            const versionData = await API.get('/api/gui/version');
            if (versionData && versionData.version) {
                sidebarVersion.textContent = `v${versionData.version}`;
            }
        } catch (_) {
            sidebarVersion.textContent = '-';
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { navigateTo };
})();
