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
        lua:         LuaScriptsPage,
        blobs:       BlobsPage,
        hosts:       HostsPage,
        diagnostics: DiagnosticsPage,
        blockcheck:  BlockcheckPage,
        blockcheck2: Blockcheck2Page,
        scan:        ScanPage,
        logs:        LogsPage,
        autostart:   AutostartPage,
        zapret:      ZapretManagerPage,
        awg:           AwgDashboardPage,
        'awg-configs': AwgConfigsPage,
        'awg-warp':    AwgWarpPage,
        'awg-routing': AwgRoutingPage,
        'awg-setup':   AwgSetupPage,
        singbox:           SingboxDashboardPage,
        'singbox-configs': SingboxConfigsPage,
        'singbox-proxies': SingboxProxiesPage,
        'singbox-setup':   SingboxSetupPage,
        mihomo:            MihomoPage,
        'mihomo-proxies':  MihomoProxiesPage,
        'mihomo-setup':    MihomoSetupPage,
        usque:             UsquePage,
        'usque-setup':     UsqueSetupPage,
        'warp-in-warp':    WarpInWarpPage,
        'tunnel-monitor':  TunnelMonitorPage,
        'tunnel-optimizer': TunnelOptimizerPage,
        'dns-routing':      DnsRoutingPage,
        tgproxy:           TgProxyPage,
        'block-detector':  BlockDetectorPage,
        'opera-proxy':     OperaProxyPage,
        'updates':         UpdateCheckerPage,
        lists:       ListsPage,
        routing:     RoutingUnifiedPage,
        settings:    SettingsPage,
    };

    let currentPage = null;
    let currentPageId = null;

    async function loadSidebarVersion() {
        try {
            const data = await API.get('/api/gui/version');
            const el = document.getElementById('sidebar-version');
            if (el && data && data.version) {
                el.textContent = 'v' + data.version;
            }
        } catch (_) {}
    }

    function init() {
        // Тема (тёмная/светлая) — синхронизируем иконку переключателя
        if (typeof Theme !== 'undefined') Theme.init();

        // Режим эксперта (галка в футере сайдбара) — расширенные поля
        if (typeof Expert !== 'undefined') Expert.init();

        // Рендерим sidebar
        Sidebar.render();
        Sidebar.initMobileToggle();

        // Загружаем версию GUI в sidebar
        loadSidebarVersion();

        // Слушаем изменение hash
        window.addEventListener('hashchange', onHashChange);

        // Начальная навигация
        onHashChange();
    }

    function onHashChange() {
        let hash = window.location.hash.slice(1) || 'dashboard';
        // Поддержка query-части после '?', напр. #awg-configs?edit=awg0
        const q = hash.indexOf('?');
        if (q >= 0) hash = hash.slice(0, q);
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

        // Рендерим страницу.
        // Заменяем #page-container свежим клоном (без детей и без
        // слушателей): страницы вешают делегированные click-обработчики
        // на переданный container в render() и не снимают в destroy(), а
        // #page-container — ПОСТОЯННЫЙ элемент. Без замены обработчики
        // накапливались бы между переходами (двойные действия) и срабатывали
        // бы на чужих страницах (совпадающие data-action → напр. удаление
        // маршрута дёргало и удаление списка). Клон сохраняет id/class →
        // CSS не меняется. Свежий узел уничтожает всё, что навесил render().
        const oldContainer = document.getElementById('page-container');
        if (oldContainer && currentPage) {
            let container = oldContainer;
            if (oldContainer.parentNode) {
                container = oldContainer.cloneNode(false);
                oldContainer.parentNode.replaceChild(container, oldContainer);
            } else {
                container.innerHTML = '';
            }
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
