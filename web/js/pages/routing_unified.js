/**
 * routing_unified.js — ЕДИНЫЙ раздел «Маршрутизация».
 *
 * Один движок (core/unified) и одна страница для всех правил
 * маршрутизации: «что маршрутизируем» (домены / CIDR / списки /
 * geosite/geoip / устройства / DSCP) → «через что» (direct / nfqws2 /
 * awg / sing-box / mihomo), с fallback-цепочкой и мониторингом.
 *
 * Бывшие «AWG-правила» — это отфильтрованный вид этой же страницы
 * (фильтр «Через: AWG», см. awg_routing.js-адаптер): низкоуровневые
 * возможности (устройства, DSCP, dnsmasq/NDMS-окружение) перенесены
 * сюда. Legacy-правила из старого хранилища предлагается перенести
 * баннером миграции (POST /api/unified/migrate).
 *
 * Бэкенд: /api/unified/*, /api/lists, /api/routing/{interfaces,
 * dnsmasq/*,ndms/status}, /api/awg/{configs,environment}, /api/devices.
 */

const RoutingUnifiedPage = (() => {

    let routes = [];
    let statusMap = {};       // id → status entry из /api/unified/status
    let interfaces = [];      // /api/routing/interfaces (ndms/singbox/активные awg)
    let awgConfigs = [];      // /api/awg/configs (цели даже для лежащих туннелей)
    let namedLists = [];
    let hostLists = [];       // /api/hostlists — nfqws2-хостлисты (id `hl:имя`)
    let legacyRules = [];     // /api/unified/legacy — старый формат
    let dnsmasqInfo = null;   // /api/routing/dnsmasq/status
    let ndmsInfo = null;      // /api/routing/ndms/status
    let environment = null;   // /api/awg/environment (платформа/firewall)
    let netEnv = null;        // /api/network/environment (роутер / ПК 1 NIC)
    let devices = [];         // /api/devices (для выбора устройств)
    let devicesSrc = null;
    let devicesLoaded = false;
    let devicesAutoTimer = null;
    let monitorRunning = false;
    let editing = null;
    let pollTimer = null;

    // Фильтр «Через»: '' | 'direct' | 'nfqws2' | kind ('awg'|'singbox'|
    // 'mihomo') | точный метод ('awg:awg0'). Задаётся фильтр-баром,
    // пресетом render(opts.via) или hash-query (#routing?via=awg).
    let viaFilter = '';
    let searchQuery = '';
    // Режим-алиас «AWG-правила»: фиксированный заголовок + подсказка.
    let aliasMode = '';

    function render(container, opts) {
        opts = opts || {};
        aliasMode = opts.alias || '';
        viaFilter = opts.via || _viaFromHash() || (aliasMode ? 'awg' : '');
        searchQuery = '';
        editing = null;
        devPickerOpen = false;
        stopDevicesAuto();

        const title = aliasMode === 'awg' ? 'AWG-правила' : 'Маршрутизация';
        const helpId = aliasMode === 'awg' ? 'awgrules' : 'routing';
        const subtitle = aliasMode === 'awg'
            ? `Отфильтрованный вид раздела
               <a href="#routing" style="text-decoration:underline;">Маршрутизация</a>
               (Через: AWG). Это тот же единый движок — правила здесь и там одни.`
            : `Единый слой: что маршрутизируем (домены / CIDR / списки /
               устройства / DSCP) → через что (direct / nfqws2 / туннель),
               с резервными методами и авто-переключением.`;

        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">${title}${typeof Help !== 'undefined' ? Help.button(helpId) : ''}${typeof Help !== 'undefined' ? Help.button('routing-modes', {label: '⇄'}) : ''}</h1>
                    <p class="page-description">${subtitle}</p>
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted" style="font-size:12px; display:flex; gap:6px; align-items:center;">
                        <input type="checkbox" id="ru-monitor" onchange="RoutingUnifiedPage.toggleMonitor(this.checked)">
                        Мониторинг
                    </label>${typeof Help !== 'undefined' ? Help.button('monitoring') : ''}
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.newRoute()">+ Маршрут</button>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.applyAll()">Применить все</button>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.refresh()">Обновить</button>
                </div>
            </div>
            <div id="ru-banners"></div>
            <div id="ru-editor"></div>
            <div class="card" style="margin-bottom:12px; padding:10px 14px;">
                <div style="display:flex; gap:14px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted" style="font-size:12px; display:flex; gap:6px; align-items:center;">
                        Через:
                        <select id="ru-via" class="form-control" style="max-width:240px;"
                                onchange="RoutingUnifiedPage.setVia(this.value)"></select>
                    </label>
                    <div class="list-ui-search" style="flex:0 0 220px; min-width:160px;">
                        <svg class="list-ui-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                        <input type="text" class="form-input list-ui-search-input" id="ru-search"
                               placeholder="Поиск по маршрутам..." spellcheck="false" autocomplete="off"
                               oninput="RoutingUnifiedPage.setSearch(this.value)">
                    </div>
                    <span class="text-muted" style="font-size:12px;" id="ru-count"></span>
                </div>
            </div>
            <div id="ru-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
            <div class="text-muted expert-only" style="margin-top:14px; font-size:12px; display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
                <span>Классические инструменты (расширенный режим):
                    <a href="#strategies" style="text-decoration:underline;">Стратегии</a> ·
                    <a href="#scan" style="text-decoration:underline;">Подбор стратегий</a> ·
                    <a href="#lists" style="text-decoration:underline;">Списки</a></span>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.reapplyLowLevel()"
                        title="Снять и заново применить все низкоуровневые правила (ip rule/ipset), включая производные единого слоя">
                    Переприменить низкоуровневые правила
                </button>
            </div>
        `;
        loadAux().then(refresh);
        pollTimer = setInterval(refreshStatus, 7000);
    }

    function destroy() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
        stopDevicesAuto();
    }

    function _viaFromHash() {
        const h = window.location.hash || '';
        const q = h.indexOf('?');
        if (q < 0) return '';
        const params = new URLSearchParams(h.slice(q + 1));
        return params.get('via') || '';
    }

    // ─────── data ───────

    async function loadAux() {
        try {
            const [ifResp, listResp, cfgResp, dnResp, ndmsResp, envResp,
                   netResp, legResp, hlResp] =
                await Promise.all([
                    API.get('/api/routing/interfaces').catch(() => null),
                    API.get('/api/lists').catch(() => null),
                    API.get('/api/awg/configs').catch(() => null),
                    API.get('/api/routing/dnsmasq/status').catch(() => null),
                    API.get('/api/routing/ndms/status').catch(() => null),
                    API.get('/api/awg/environment').catch(() => null),
                    API.get('/api/network/environment').catch(() => null),
                    API.get('/api/unified/legacy').catch(() => null),
                    API.get('/api/hostlists').catch(() => null),
                ]);
            interfaces  = (ifResp && ifResp.interfaces) || [];
            namedLists  = (listResp && listResp.lists) || [];
            // nfqws2-хостлисты как выбираемые списки маршрутизации (id `hl:имя`).
            // Domain-движок разворачивает их через Destination.resolve().
            const hlFiles = (hlResp && hlResp.files) || [];
            hostLists = hlFiles.map(f => ({
                id: 'hl:' + (f.name || f.file || ''),
                name: ((f.name || f.file || '') + ' (nfqws2'
                       + (f.count != null ? ', ' + f.count : '') + ')'),
            })).filter(x => x.id !== 'hl:');
            awgConfigs  = (cfgResp && cfgResp.configs) || [];
            dnsmasqInfo = dnResp || null;
            ndmsInfo    = ndmsResp || null;
            environment = envResp || null;
            netEnv      = netResp || null;
            legacyRules = (legResp && legResp.rules) || [];
        } catch (_) {}
    }

    async function refresh() {
        try {
            const r = await API.get('/api/unified/routes');
            routes = (r && r.routes) || [];
        } catch (e) { Toast.error(e.message); }
        try {
            const leg = await API.get('/api/unified/legacy');
            legacyRules = (leg && leg.rules) || [];
        } catch (_) {}
        await refreshStatus();
        renderBanners();
        renderViaOptions();
        renderEditor();
        renderBody();
    }

    async function refreshStatus() {
        try {
            const s = await API.get('/api/unified/status');
            statusMap = {};
            (s.routes || []).forEach(x => statusMap[x.id] = x);
            monitorRunning = !!s.monitor_running;
            const cb = document.getElementById('ru-monitor');
            if (cb) cb.checked = monitorRunning;
            renderBody();
        } catch (_) {}
    }

    // ─────── методы (цели) ───────

    /**
     * Все доступные цели-токены. Источники:
     *   - AWG-конфиги (/api/awg/configs) — даже не поднятые (правило
     *     отложится до старта туннеля);
     *   - /api/routing/interfaces — нативные Keenetic WG (NDMS),
     *     sing-box/mihomo tun, активные awg.
     */
    function methodTargets() {
        const seen = new Set();
        const out = [];
        awgConfigs.forEach(c => {
            if (!c.name || seen.has(c.name)) return;
            seen.add(c.name);
            out.push({ token: 'awg:' + c.name, kind: 'awg', name: c.name,
                       active: !!c.active, label: `awg → ${c.name}${c.active ? ' (активен)' : ''}` });
        });
        interfaces.forEach(i => {
            if (!i.name || seen.has(i.name)) return;
            seen.add(i.name);
            const kind = (i.source === 'singbox') ? 'singbox'
                       : (i.source === 'mihomo') ? 'mihomo' : 'awg';
            const extra = i.source === 'ndms' ? ' · Keenetic' : '';
            out.push({ token: kind + ':' + i.name, kind, name: i.name,
                       active: !!i.active,
                       label: `${kind} → ${i.name}${extra}${i.active ? ' (активен)' : ''}` });
        });
        return out;
    }

    function methodOptions(selected) {
        const opts = [['direct', 'Прямой (direct)'], ['nfqws2', 'nfqws2 (обход DPI)']]
            .concat(methodTargets().map(t => [t.token, t.label]));
        if (selected && !opts.some(([v]) => v === selected)) {
            opts.push([selected, selected + ' (недоступен)']);
        }
        return opts.map(([v, l]) =>
            `<option value="${escAttr(v)}" ${v === selected ? 'selected' : ''}>${esc(l)}</option>`
        ).join('');
    }

    // ─────── фильтр «Через» ───────

    function renderViaOptions() {
        const sel = document.getElementById('ru-via');
        if (!sel) return;
        const groups = [
            ['', 'Все'],
            ['direct', 'Прямой (direct)'],
            ['nfqws2', 'nfqws2'],
            ['awg', 'AWG (все туннели)'],
            ['singbox', 'sing-box (все)'],
            ['mihomo', 'mihomo (все)'],
        ];
        const targets = methodTargets().map(t => [t.token, '→ ' + t.name]);
        const all = groups.concat(targets);
        if (viaFilter && !all.some(([v]) => v === viaFilter)) {
            all.push([viaFilter, viaFilter]);
        }
        sel.innerHTML = all.map(([v, l]) =>
            `<option value="${escAttr(v)}" ${v === viaFilter ? 'selected' : ''}>${esc(l)}</option>`
        ).join('');
    }

    function setVia(v) { viaFilter = v; renderBody(); }
    function setSearch(v) { searchQuery = (v || '').toLowerCase(); renderBody(); }

    function _kindOf(method) {
        const i = (method || '').indexOf(':');
        return i < 0 ? (method || '') : method.slice(0, i);
    }

    function matchesVia(r) {
        if (!viaFilter) return true;
        const st = statusMap[r.id] || {};
        const methods = [r.method, st.active_method].filter(Boolean);
        if (viaFilter.includes(':')) {
            return methods.includes(viaFilter);
        }
        return methods.some(m => _kindOf(m) === viaFilter);
    }

    function matchesSearch(r) {
        if (!searchQuery) return true;
        const d = r.destination || {};
        const hay = [
            r.name, r.method, (r.fallbacks || []).join(' '),
            (d.domains || []).join(' '), (d.cidrs || []).join(' '),
            (d.geosite || []).join(' '), (d.geoip || []).join(' '),
            (r.devices || []).map(x => `${x.ip} ${x.mac} ${x.hostname}`).join(' '),
            r.dscp != null ? 'dscp ' + r.dscp : '',
        ].join(' ').toLowerCase();
        return hay.includes(searchQuery);
    }

    // ─────── баннеры (миграция + окружение) ───────

    function renderBanners() {
        const box = document.getElementById('ru-banners');
        if (!box) return;
        box.innerHTML = legacyBannerHtml() + pcModeHtml() + infraHtml();
    }

    // Локальный режим (задача №5): ПК/VPS без LAN-ролей — правила
    // действуют на исходящий трафик самой машины (mangle OUTPUT уже
    // маркируется ipset/nftset-бэкендом), форвардить некого.
    function pcModeHtml() {
        if (!netEnv || netEnv.profile !== 'pc') return '';
        const what = netEnv.single_nic
            ? 'одна сетевая карта' : 'ПК/VPS без LAN';
        return `<div style="font-size:12px; margin-bottom:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <span>🖥</span>
            <span class="text-muted">
                <strong>Локальный режим</strong> (${esc(what)}): правила
                применяются к исходящему трафику этой машины — LAN-форвардинг
                не используется, выбор устройств сети обычно не нужен.
                ${netEnv.profile_source === 'override' ? ' Профиль задан вручную в Настройках.' : ''}
            </span>
        </div>`;
    }

    function legacyBannerHtml() {
        if (!legacyRules.length) return '';
        const summary = legacyRules.slice(0, 6).map(r => {
            let what = r.type;
            if (r.type === 'cidr') what = `CIDR ×${(r.cidrs || []).length}`;
            if (r.type === 'domain') what = `домены ×${(r.domains || []).length}`;
            if (r.type === 'device') what = `устройство ${r.source_ip || ''}`;
            if (r.type === 'dscp') what = `DSCP ${r.dscp}`;
            return `<li style="margin:2px 0;">
                <code>${esc(what)}</code> → <strong>${esc(r.target_iface)}</strong>
                ${r.description ? `<span class="text-muted">(${esc(r.description)})</span>` : ''}
                <button class="btn btn-ghost btn-sm expert-only" title="Удалить без переноса"
                        onclick="RoutingUnifiedPage.deleteLegacy('${escAttr(r.id)}')">✕</button>
            </li>`;
        }).join('');
        const more = legacyRules.length > 6
            ? `<li class="text-muted">… ещё ${legacyRules.length - 6}</li>` : '';
        return `<div class="alert alert-warning" style="margin-bottom:12px;">
            <div class="alert-title">Найдены правила старого формата (${legacyRules.length})</div>
            <p style="font-size:13px; margin:6px 0;">
                Это правила прежнего раздела «AWG-правила» (отдельное
                хранилище). Теперь маршрутизация единая — перенесите их
                в маршруты одним нажатием: каждое правило станет
                маршрутом с методом-туннелем, ничего не потеряется.
                Перенос также выполняется автоматически при перезапуске GUI.
            </p>
            <ul style="font-size:12px; margin:6px 0 8px 18px; padding:0;">${summary}${more}</ul>
            <button class="btn btn-primary btn-sm" onclick="RoutingUnifiedPage.migrateLegacy()">
                Перенести в единый слой
            </button>
        </div>`;
    }

    // Окружение domain-маршрутизации: NDMS (Keenetic-native) либо
    // dnsmasq+ipset/nftset. Компактная строка всегда; развёрнутое
    // предупреждение — когда доменные маршруты есть, а окружение не
    // готово (или открыт редактор — пользователь собирается создавать).
    function infraHtml() {
        const dn = (dnsmasqInfo && dnsmasqInfo.dnsmasq) || {};
        const backends = (dnsmasqInfo && dnsmasqInfo.backends) || {};
        const preferred = (dnsmasqInfo && dnsmasqInfo.preferred_backend) || '';
        const ndmsActive = !!(ndmsInfo && ndmsInfo.available);
        const dnReady = !!dn.available && !!dn.running && !!preferred;
        const domainReady = ndmsActive || dnReady;
        const setupApplied = !!(dnsmasqInfo && dnsmasqInfo.auto_setup_applied);
        const platformName = (environment && environment.platform && environment.platform.name) || '';

        const platformLine = environment && environment.platform
            ? `<span class="text-muted expert-only" style="font-size:11px;">
                   Платформа: ${esc(platformName || '?')},
                   firewall: ${esc(environment.platform.firewall_backend || 'n/a')}
               </span>`
            : '';

        const hasDomainRoutes = routes.some(r => {
            const d = r.destination || {};
            const tun = ['awg', 'singbox', 'mihomo'].includes(_kindOf(r.method));
            return tun && ((d.domains || []).length || (d.list_ids || []).length);
        });
        const needWarn = !domainReady && (hasDomainRoutes || !!editing);

        const needsSetup = !dnReady &&
            (!!dn.available || !!backends.ipset || !!backends.nftset);
        const setupPlanHasSteps = !!(dnsmasqInfo &&
            dnsmasqInfo.auto_setup_plan && dnsmasqInfo.auto_setup_plan.applicable);
        const setupButton = (needsSetup || setupPlanHasSteps)
            ? `<button class="btn ${needWarn ? 'btn-primary' : 'btn-ghost'} btn-sm"
                       onclick="RoutingUnifiedPage.runDnsmasqSetup()">
                   ${needsSetup ? 'Настроить dnsmasq автоматически'
                                : 'Применить обновления dnsmasq-конфига'}
               </button>`
            : '';
        const revertButton = setupApplied && dnReady
            ? `<button class="btn btn-ghost btn-sm"
                       onclick="RoutingUnifiedPage.runDnsmasqRevert()"
                       title="Откатить изменения: вернуть systemd-resolved на :53 и остановить dnsmasq">
                   Откатить настройку dnsmasq
               </button>`
            : '';

        if (ndmsActive) {
            return `<div style="font-size:12px; margin-bottom:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <span style="color:#39c45e;">●</span>
                <span class="text-muted">
                    Маршрутизация по доменам: <strong>Keenetic-native (NDMS
                    ${esc(ndmsInfo.version || '?')})</strong> — встроенный
                    <code>dns-proxy route</code>, dnsmasq не нужен.
                </span>
                ${platformLine}
            </div>`;
        }
        if (dnReady) {
            return `<div style="font-size:12px; margin-bottom:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <span style="color:#39c45e;">●</span>
                <span class="text-muted">
                    Маршрутизация по доменам: dnsmasq
                    <strong>${esc(dn.version || '?')}</strong> (запущен),
                    бэкенд <strong>${esc(preferred)}</strong>
                    ${setupApplied ? ' — настроен через GUI' : ''}
                </span>
                ${setupButton} ${revertButton} ${platformLine}
            </div>`;
        }
        if (!needWarn) {
            return `<div style="font-size:12px; margin-bottom:12px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <span class="text-muted">○ Маршрутизация по доменам через
                    туннель пока не настроена (понадобится dnsmasq) —
                    CIDR/устройства/DSCP/nfqws2 работают и без него.</span>
                ${setupButton} ${platformLine}
            </div>`;
        }
        const statusLine = `
            <p style="font-size:12px; margin:6px 0 10px;">
              Статус на этом устройстве: dnsmasq=<strong>${dn.available ? 'установлен' : 'не найден'}</strong>,
              запущен=<strong>${dn.running ? 'да' : 'нет'}</strong>,
              ipset=<strong>${backends.ipset ? 'есть' : 'нет'}</strong>,
              nft=<strong>${backends.nftset ? 'есть' : 'нет'}</strong>.
            </p>`;
        return `<div class="alert alert-warning" style="margin-bottom:12px;">
            <div class="alert-title">Маршрутизация по доменам через туннель требует работающего dnsmasq</div>
            ${dnsmasqExplanation(platformName)}
            ${statusLine}
            ${setupButton} ${platformLine}
        </div>`;
    }

    // Платформо-зависимое пояснение, зачем dnsmasq и почему он может
    // не работать (на Keenetic/OpenWrt он штатный, на десктопном Linux
    // мешает stub-listener systemd-resolved).
    function dnsmasqExplanation(platformName) {
        const common =
            `<p style="font-size:13px;">
                Доменная маршрутизация работает так: dnsmasq резолвит
                указанные домены и складывает их IP в ipset/nftset, а
                трафик к этим IP заворачивается в выбранный туннель.
                Без запущенного dnsmasq собирать IP по доменам нечем.
             </p>`;
        if (platformName === 'keenetic' || platformName === 'openwrt') {
            return common +
                `<p style="font-size:13px;">
                    На <strong>${esc(platformName === 'keenetic' ? 'Keenetic' : 'OpenWrt')}</strong>
                    dnsmasq — штатный DNS-сервер роутера и обычно уже
                    слушает :53. Кнопка ниже просто убедится, что он
                    запущен, и добавит include с нашими правилами в его
                    конфиг.
                 </p>`;
        }
        return common +
            `<p style="font-size:13px;">
                На десктопном Linux (Debian/Ubuntu) порт 53 обычно занят
                stub-listener'ом systemd-resolved, и dnsmasq не стартует.
                Кнопка ниже отключит DNSStubListener в
                <code>/etc/systemd/resolved.conf</code>, поднимет dnsmasq
                на :53 и сохранит state-файл для отката.
             </p>`;
    }

    // ─────── таблица ───────

    function renderBody() {
        const box = document.getElementById('ru-body');
        if (!box) return;
        if (!routes.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Маршрутов нет. Нажмите «+ Маршрут».</div></div>`;
            _setCount(0, 0);
            return;
        }
        const visible = routes.filter(r => matchesVia(r) && matchesSearch(r));
        _setCount(visible.length, routes.length);
        if (!visible.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Под фильтр не попал ни один маршрут (всего: ${routes.length}).
            </div></div>`;
            return;
        }
        box.innerHTML = `<div class="card"><table class="table">
            <thead><tr>
                <th>Маршрут</th><th>Трафик</th><th>Метод</th>
                <th>Статус</th><th>Успешность</th><th style="width:230px;"></th>
            </tr></thead>
            <tbody>${visible.map(rowHtml).join('')}</tbody>
        </table></div>`;
    }

    function _setCount(visible, total) {
        const el = document.getElementById('ru-count');
        if (el) el.textContent = total
            ? (visible === total ? `${total} маршрут(ов)` : `${visible}/${total}`)
            : '';
    }

    function trafficSummary(r) {
        const dest = r.destination || {};
        return [
            (dest.domains || []).length ? `${dest.domains.length} дом.` : '',
            (dest.cidrs || []).length ? `${dest.cidrs.length} CIDR` : '',
            (dest.list_ids || []).length ? `${dest.list_ids.length} спис.` : '',
            (dest.geosite || []).length ? `geosite:${dest.geosite.join(',')}` : '',
            (dest.geoip || []).length ? `geoip:${dest.geoip.join(',')}` : '',
            (r.devices || []).length ? `${r.devices.length} устр.` : '',
            (r.dscp != null && r.dscp !== '') ? `DSCP ${r.dscp}` : '',
        ].filter(Boolean).join(', ') || '—';
    }

    function rowHtml(r) {
        const st = statusMap[r.id] || {};
        const active = st.active_method || r.method;
        const mon = st.monitor || {};
        const rate = (mon.rate == null) ? '—' : Math.round(mon.rate * 100) + '%';
        const rateColor = (mon.rate == null) ? 'var(--text-muted,#888)'
                        : (mon.rate >= 0.5 ? '#39c45e' : '#e58');
        const enabledDot = r.enabled
            ? '<span style="color:#39c45e;">●</span>'
            : '<span class="text-muted">○</span>';
        const scanBtn = st.suggest_scan
            ? `<button class="btn btn-ghost btn-sm" title="${escAttr(st.suggest_reason||'')}"
                       onclick="RoutingUnifiedPage.scan('${esc(r.id)}')">Подобрать</button>`
            : '';
        return `<tr>
            <td>${enabledDot} <strong>${esc(r.name)}</strong>
                ${r.failover_enabled ? '<span class="text-muted" style="font-size:10px;"> failover</span>' : ''}</td>
            <td style="font-size:12px;">${esc(trafficSummary(r))}</td>
            <td style="font-family:monospace; font-size:12px;">
                ${esc(active)}${active !== r.method ? ` <span class="text-muted">(осн. ${esc(r.method)})</span>` : ''}
                ${(r.fallbacks||[]).length ? `<br><span class="text-muted" style="font-size:10px;">↳ ${esc((r.fallbacks||[]).join(', '))}</span>` : ''}</td>
            <td>${r.monitor_enabled ? (mon.last_ok == null ? 'ждём' : (mon.last_ok ? 'ok' : 'сбой')) : '—'}</td>
            <td style="color:${rateColor};">${rate}</td>
            <td style="text-align:right;">
                ${scanBtn}
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.apply('${esc(r.id)}')">Применить</button>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.edit('${esc(r.id)}')">Ред.</button>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.del('${esc(r.id)}')">✕</button>
            </td>
        </tr>`;
    }

    // ─────── редактор ───────

    function blankRoute() {
        // Пресет метода — по активному фильтру: на AWG-виде логично
        // сразу предлагать первый AWG-туннель.
        let method = 'direct';
        if (viaFilter && viaFilter.includes(':')) {
            method = viaFilter;
        } else if (['awg', 'singbox', 'mihomo'].includes(viaFilter)) {
            const t = methodTargets().find(x => x.kind === viaFilter);
            if (t) method = t.token;
        } else if (viaFilter === 'nfqws2') {
            method = 'nfqws2';
        }
        return { id: '', name: '', enabled: true, method,
                 fallbacks: [], monitor_enabled: false, failover_enabled: false,
                 probe_domain: '', devices: [], dscp: null, dscp_self: false,
                 destination: { domains: [], cidrs: [], list_ids: [],
                                geosite: [], geoip: [] } };
    }

    function renderEditor() {
        const box = document.getElementById('ru-editor');
        if (!box) return;
        if (!editing) { box.innerHTML = ''; renderBanners(); return; }
        const e = editing;
        const d = e.destination || {};
        const allLists = namedLists.concat(hostLists);
        const listChecks = allLists.map(l =>
            `<label class="text-muted" style="display:inline-flex; gap:4px; margin-right:12px; font-size:12px;">
                <input type="checkbox" value="${escAttr(l.id)}"
                       ${(d.list_ids||[]).includes(l.id) ? 'checked' : ''}
                       class="ru-listchk"> ${esc(l.name)}
            </label>`).join('') || '<span class="text-muted" style="font-size:12px;">нет списков</span>';

        const dscpPresets = [
            ['', '— нет —'], ['46', '46 · EF (realtime/VoIP)'],
            ['34', '34 · AF41 (видео)'], ['26', '26 · AF31'],
            ['10', '10 · AF11'], ['8', '8 · CS1 (bulk)'], ['0', '0 · CS0 (best effort)'],
        ];
        const dscpVal = (e.dscp == null) ? '' : String(e.dscp);

        box.innerHTML = `
            <div class="card" style="margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between;">
                    <div class="card-title">${e.id ? 'Редактирование маршрута' : 'Новый маршрут'}</div>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.closeEditor()">Закрыть</button>
                </div>
                <div style="display:grid; grid-template-columns:150px 1fr; gap:8px 12px; margin-top:8px; align-items:start;">
                    <label class="text-muted" style="padding-top:6px;">Имя</label>
                    <input id="ru-name" class="form-control" style="max-width:320px;" value="${escAttr(e.name)}">

                    <label class="text-muted" style="padding-top:6px;">Домены</label>
                    <textarea id="ru-domains" rows="3" style="width:100%; font-family:monospace; font-size:12px;"
                        placeholder="youtube.com, googlevideo.com">${esc((d.domains||[]).join('\n'))}</textarea>

                    <label class="text-muted" style="padding-top:6px;">CIDR</label>
                    <textarea id="ru-cidrs" rows="2" style="width:100%; font-family:monospace; font-size:12px;"
                        placeholder="1.2.3.0/24">${esc((d.cidrs||[]).join('\n'))}</textarea>

                    <label class="text-muted" style="padding-top:6px;">Списки</label>
                    <div>${listChecks}</div>

                    <label class="text-muted" style="padding-top:6px;">geosite / geoip</label>
                    <div style="display:flex; gap:8px;">
                        <input id="ru-geosite" class="form-control" placeholder="geosite (google,youtube)"
                               value="${escAttr((d.geosite||[]).join(','))}" style="max-width:240px;">
                        <input id="ru-geoip" class="form-control" placeholder="geoip (ru)"
                               value="${escAttr((d.geoip||[]).join(','))}" style="max-width:160px;">
                    </div>

                    <label class="text-muted" style="padding-top:6px;"
                           title="Весь трафик с выбранных устройств локальной сети пойдёт через метод маршрута (ip rule from <ip>). Работает только с туннельными методами.">
                        Устройства</label>
                    <div id="ru-devbox"></div>

                    <label class="text-muted expert-only" style="padding-top:6px;"
                           title="Трафик с этой DSCP-меткой (её ставит штатный QoS роутера) уйдёт через метод маршрута. Только для туннельных методов.">
                        DSCP / QoS</label>
                    <div class="expert-only" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <input type="number" min="0" max="63" id="ru-dscp" class="form-control"
                               style="max-width:100px;" value="${escAttr(dscpVal)}" placeholder="—">
                        <select class="form-control" style="max-width:220px;"
                                onchange="document.getElementById('ru-dscp').value=this.value;">
                            ${dscpPresets.map(([v, l]) =>
                                `<option value="${v}" ${dscpVal === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}
                        </select>
                        <label class="text-muted" style="font-size:12px; display:flex; gap:6px; align-items:center;">
                            <input type="checkbox" id="ru-dscp-self" ${e.dscp_self ? 'checked' : ''}>
                            и трафик самого роутера (OUTPUT)
                        </label>
                    </div>

                    <label class="text-muted" style="padding-top:6px;">Метод</label>
                    <select id="ru-method" class="form-control" style="max-width:320px;">${methodOptions(e.method)}</select>

                    <label class="text-muted expert-only" style="padding-top:6px;">Fallback-методы</label>
                    <input id="ru-fallbacks" class="form-control expert-only" style="max-width:480px;"
                           placeholder="через запятую: awg:awg0, nfqws2, direct"
                           value="${escAttr((e.fallbacks||[]).join(', '))}">

                    <label class="text-muted expert-only" style="padding-top:6px;">Probe-домен</label>
                    <input id="ru-probe" class="form-control expert-only" style="max-width:320px;"
                           placeholder="для мониторинга (по умолч. первый домен)"
                           value="${escAttr(e.probe_domain||'')}">

                    <label class="text-muted" style="padding-top:6px;">Опции
                        ${typeof Help !== 'undefined' ? Help.button('failover') : ''}</label>
                    <div style="display:flex; flex-direction:column; gap:6px; padding-top:4px;">
                        <label style="font-size:13px; display:flex; gap:6px; align-items:center;">
                            <input type="checkbox" id="ru-enabled" ${e.enabled ? 'checked' : ''}> включён</label>
                        <label style="font-size:13px; display:flex; gap:6px; align-items:center;">
                            <input type="checkbox" id="ru-fo" ${e.failover_enabled ? 'checked' : ''}>
                            <b>Автопереключение метода при сбоях</b> (failover)</label>
                        <label class="text-muted" style="font-size:12px; display:flex; gap:6px; align-items:center; margin-left:22px;">
                            <input type="checkbox" id="ru-mon" ${e.monitor_enabled ? 'checked' : ''}>
                            только следить за доступностью (без переключения)</label>
                        <span class="text-muted" style="font-size:11px; margin-left:22px;">
                            Любая из галок включает фоновую проверку автоматически —
                            отдельно запускать мониторинг сверху не нужно.</span>
                    </div>
                </div>
                ${typeof Expert !== 'undefined'
                    ? Expert.noteHtml('Тонкая настройка (DSCP, fallback-методы, probe-домен) скрыта')
                    : ''}
                <div style="margin-top:12px;">
                    <button class="btn btn-primary btn-sm" onclick="RoutingUnifiedPage.save()">Сохранить</button>
                </div>
            </div>`;
        renderDevicesBox();
        renderBanners();
    }

    function newRoute() { editing = blankRoute(); renderEditor(); }

    async function edit(id) {
        try {
            const r = await API.get('/api/unified/routes/' + encodeURIComponent(id));
            if (!r || !r.ok) { Toast.error('не найден'); return; }
            editing = r.route;
            editing.devices = editing.devices || [];
            renderEditor();
        } catch (e) { Toast.error(e.message); }
    }
    function closeEditor() { editing = null; stopDevicesAuto(); renderEditor(); }

    // ─────── выбор устройств (в редакторе) ───────

    let devPickerOpen = false;
    let devAutoRefresh = false;

    async function loadDevices() {
        try {
            const r = await API.get('/api/devices');
            devices = (r && r.ok && r.devices) || [];
            devicesSrc = (r && r.sources) || null;
        } catch (_) {
            devices = [];
            devicesSrc = null;
        }
        devicesLoaded = true;
    }

    /**
     * Перерисовать ТОЛЬКО блок устройств — чтобы автообновление списка
     * не сбрасывало остальные поля редактора.
     */
    function renderDevicesBox() {
        const box = document.getElementById('ru-devbox');
        if (!box || !editing) return;
        const chosen = editing.devices || [];

        // ip → имя маршрута, где устройство уже используется (кроме текущего)
        const usedBy = {};
        routes.forEach(r => {
            if (editing.id && r.id === editing.id) return;
            (r.devices || []).forEach(x => { if (x.ip) usedBy[x.ip] = r.name; });
        });

        const chips = chosen.map(x => `
            <span style="display:inline-flex; gap:6px; align-items:center; border:1px solid var(--border,#444);
                         border-radius:12px; padding:2px 8px; margin:2px; font-size:12px;">
                <span style="font-family:monospace;">${esc(x.ip)}</span>
                ${x.hostname ? `<span class="text-muted">${esc(x.hostname)}</span>` : ''}
                <a href="javascript:void(0)" onclick="RoutingUnifiedPage.removeDevice('${escAttr(x.ip)}')"
                   style="text-decoration:none;">✕</a>
            </span>`).join('')
            || '<span class="text-muted" style="font-size:12px;">не выбраны</span>';

        const srcSummary = devicesSrc
            ? `<div class="text-muted" style="font-size:11px; margin:4px 0;">
                    Источники: DHCP-leases — ${(devicesSrc.leases_paths || []).length} файл(а),
                    ARP — ${devicesSrc.arp_available ? 'да' : 'нет'}${
                        typeof devicesSrc.ndm_available !== 'undefined'
                            ? `, Keenetic NDM — ${devicesSrc.ndm_available ? 'да' : 'нет'}` : ''}.
                    «Имя» — hostname из DHCP/роутера (пусто, если устройство его не отдало).
               </div>`
            : '';

        const pickerTable = !devPickerOpen ? '' : `
            ${srcSummary}
            ${devices.length === 0
                ? `<p class="text-muted" style="font-size:12px; margin:6px 0;">
                       ${devicesLoaded ? 'Список пуст — введите IP вручную ниже.' : 'Загрузка...'}
                   </p>`
                : `<table class="table" style="margin-top:4px; font-size:12px;">
                    <thead><tr>
                        <th style="width:18%;">IP</th><th style="width:22%;">MAC</th>
                        <th>Имя</th><th style="width:12%;">Источник</th>
                        <th style="width:14%; text-align:right;"></th>
                    </tr></thead>
                    <tbody>${devices.map(dv => {
                        const inRoute = chosen.some(x => x.ip === dv.ip);
                        const used = usedBy[dv.ip];
                        let action;
                        if (inRoute) {
                            action = `<button class="btn btn-ghost btn-sm"
                                onclick="RoutingUnifiedPage.removeDevice('${escAttr(dv.ip)}')">Убрать</button>`;
                        } else {
                            action = `<button class="btn btn-ghost btn-sm"
                                onclick="RoutingUnifiedPage.addDevice('${escAttr(dv.ip)}','${escAttr(dv.mac || '')}','${escAttr(dv.hostname || '')}')">+ В маршрут</button>`
                                + (used ? `<div class="text-muted" style="font-size:10px;">в «${esc(used)}»</div>` : '');
                        }
                        return `<tr>
                            <td style="font-family:monospace;">${esc(dv.ip)}</td>
                            <td style="font-family:monospace;">${esc(dv.mac || '—')}</td>
                            <td>${esc(dv.hostname || '')}</td>
                            <td><span class="text-muted" style="font-size:11px;">${esc(dv.source || '')}</span></td>
                            <td style="text-align:right;">${action}</td>
                        </tr>`;
                    }).join('')}</tbody>
                </table>`}
        `;

        box.innerHTML = `
            <div>${chips}</div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:6px;">
                <input type="text" id="ru-dev-manual" class="form-control" style="max-width:200px;"
                       placeholder="IP вручную: 192.168.1.50">
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.addDeviceManual()">Добавить</button>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.toggleDevPicker()">
                    ${devPickerOpen ? 'Скрыть устройства сети' : 'Выбрать из сети…'}</button>
                ${devPickerOpen ? `
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.refreshDevices()">Обновить список</button>
                    <label class="text-muted" style="font-size:12px; display:flex; gap:4px; align-items:center;">
                        <input type="checkbox" ${devAutoRefresh ? 'checked' : ''}
                               onchange="RoutingUnifiedPage.toggleDevicesAuto(this.checked)">
                        автообновление
                    </label>` : ''}
            </div>
            <div>${pickerTable}</div>
            <div class="text-muted" style="font-size:11px; margin-top:4px;">
                Устройства и DSCP работают только с туннельными методами
                (awg/sing-box/mihomo); для direct/nfqws2 они пропускаются.
                ${netEnv && netEnv.profile === 'pc'
                    ? '<br>🖥 Локальный режим (ПК без LAN-клиентов): устройства' +
                      ' обычно не нужны — домены/CIDR-правила и так действуют' +
                      ' на трафик этой машины.'
                    : ''}
            </div>
        `;
    }

    function toggleDevPicker() {
        devPickerOpen = !devPickerOpen;
        if (devPickerOpen && !devicesLoaded) {
            loadDevices().then(renderDevicesBox);
        }
        if (!devPickerOpen) stopDevicesAuto();
        renderDevicesBox();
    }

    async function refreshDevices() {
        await loadDevices();
        renderDevicesBox();
    }

    function toggleDevicesAuto(on) {
        devAutoRefresh = !!on;
        stopDevicesAuto();
        if (devAutoRefresh) {
            devicesAutoTimer = setInterval(async () => {
                if (!editing || !devPickerOpen) { stopDevicesAuto(); return; }
                await loadDevices();
                renderDevicesBox();
            }, 10000);
        }
        renderDevicesBox();
    }

    function stopDevicesAuto() {
        if (devicesAutoTimer) clearInterval(devicesAutoTimer);
        devicesAutoTimer = null;
        devAutoRefresh = false;
    }

    function addDevice(ip, mac, hostname) {
        if (!editing) return;
        editing.devices = editing.devices || [];
        if (!editing.devices.some(x => x.ip === ip)) {
            editing.devices.push({ ip, mac: mac || '', hostname: hostname || '' });
        }
        renderDevicesBox();
    }

    function addDeviceManual() {
        const inp = document.getElementById('ru-dev-manual');
        const ip = (inp && inp.value || '').trim();
        if (!ip) { Toast.error('Введите IP устройства'); return; }
        const known = devices.find(d => d.ip === ip) || {};
        addDevice(ip, known.mac || '', known.hostname || '');
        if (inp) inp.value = '';
    }

    function removeDevice(ip) {
        if (!editing) return;
        editing.devices = (editing.devices || []).filter(x => x.ip !== ip);
        renderDevicesBox();
    }

    // ─────── save / CRUD ───────

    function splitList(v) {
        return String(v || '').split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
    }

    async function save() {
        const listIds = Array.from(document.querySelectorAll('.ru-listchk'))
            .filter(c => c.checked).map(c => c.value);
        const dscpRaw = (document.getElementById('ru-dscp')?.value || '').trim();
        let dscp = null;
        if (dscpRaw !== '') {
            dscp = parseInt(dscpRaw, 10);
            if (isNaN(dscp) || dscp < 0 || dscp > 63) {
                Toast.error('DSCP должен быть числом 0–63');
                return;
            }
        }
        const payload = {
            id: editing.id || undefined,
            name: (document.getElementById('ru-name').value || '').trim(),
            enabled: document.getElementById('ru-enabled').checked,
            method: document.getElementById('ru-method').value,
            fallbacks: splitList(document.getElementById('ru-fallbacks').value),
            probe_domain: (document.getElementById('ru-probe').value || '').trim(),
            monitor_enabled: document.getElementById('ru-mon').checked,
            failover_enabled: document.getElementById('ru-fo').checked,
            devices: editing.devices || [],
            dscp: dscp,
            dscp_self: !!document.getElementById('ru-dscp-self')?.checked,
            destination: {
                domains: splitList(document.getElementById('ru-domains').value),
                cidrs: splitList(document.getElementById('ru-cidrs').value),
                list_ids: listIds,
                geosite: splitList(document.getElementById('ru-geosite').value),
                geoip: splitList(document.getElementById('ru-geoip').value),
            },
        };
        if (!payload.name) { Toast.error('Укажите имя'); return; }
        try {
            const r = await API.post('/api/unified/routes', payload);
            if (r && r.ok) {
                Toast.success('Сохранено');
                if (r.applied && r.applied.skipped_selectors && r.applied.skipped_selectors.length) {
                    Toast.info('Пропущено: ' + r.applied.skipped_selectors.join('; '));
                }
                editing = null;
                stopDevicesAuto();
                await refresh();
            } else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    async function del(id) {
        if (!confirm('Удалить маршрут?')) return;
        try {
            const r = await API.delete('/api/unified/routes/' + encodeURIComponent(id));
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    async function apply(id) {
        try {
            const r = await API.post('/api/unified/routes/' + encodeURIComponent(id) + '/apply');
            if (r && r.ok) Toast.success('Применено');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function applyAll() {
        try {
            await API.post('/api/unified/apply-all');
            Toast.success('Применены все маршруты');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function toggleMonitor(enabled) {
        try {
            const r = await API.post('/api/unified/monitor', { enabled, interval: 60 });
            Toast.success('Мониторинг: ' + (r && r.running ? 'включён' : 'выключен'));
        } catch (e) { Toast.error(e.message); }
        finally { await refreshStatus(); }
    }

    async function scan(id) {
        try {
            const r = await API.post('/api/unified/routes/' + encodeURIComponent(id) + '/scan', {});
            if (r && r.ok) Toast.success('Подбор стратегии запущен для ' + r.target + ' (см. «Подбор стратегий»)');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ─────── миграция legacy-правил ───────

    async function migrateLegacy() {
        try {
            const r = await API.post('/api/unified/migrate');
            if (r && r.ok) {
                Toast.success('Перенесено правил: ' + ((r.migrated || []).length));
            } else {
                const errs = (r && r.errors || []).join('; ');
                Toast.error('Перенос с ошибками: ' + (errs || (r && r.error) || '?'));
            }
        } catch (e) { Toast.error(e.message); }
        await refresh();
    }

    async function deleteLegacy(id) {
        if (!confirm('Удалить старое правило без переноса?')) return;
        try {
            const r = await API.delete('/api/routing/rules/' + encodeURIComponent(id));
            if (r && r.ok) Toast.success('Удалено');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        await refresh();
    }

    async function reapplyLowLevel() {
        try {
            const r = await API.post('/api/routing/apply');
            if (r && r.ok) Toast.success('Низкоуровневые правила переприменены');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ─────── dnsmasq setup / revert (перенесено из AWG-правил) ───────

    async function runDnsmasqSetup() {
        let plan;
        try {
            const r = await API.get('/api/routing/dnsmasq/setup/plan');
            if (!r || !r.ok) {
                Toast.error((r && r.error) || 'Не удалось получить план');
                return;
            }
            plan = r.plan || {};
        } catch (e) {
            Toast.error(e.message);
            return;
        }
        const steps = plan.steps || [];
        if (steps.length === 0) {
            Toast.info('Менять нечего — dnsmasq уже настроен корректно');
            await refresh();
            return;
        }
        const stepLines = steps.map((s, i) => `${i + 1}. ${s.what}`).join('\n');
        const warnLines = (plan.warnings || []).join('\n');
        const revertNote = plan.have_systemctl
            ? '\n\nПри выключении последнего AWG-интерфейса все изменения' +
              ' автоматически откатятся.'
            : '';
        const ok = window.confirm(
            'zapret-gui сделает следующее:\n\n' + stepLines +
            (warnLines ? '\n\nВнимание:\n' + warnLines : '') +
            revertNote + '\n\nПродолжить?'
        );
        if (!ok) return;
        Toast.info('Настройка dnsmasq...');
        try {
            const r = await API.post('/api/routing/dnsmasq/setup');
            if (r && r.ok) {
                Toast.success('dnsmasq настроен');
            } else {
                const failed = ((r && r.steps) || [])
                    .filter(s => !s.ok)
                    .map(s => `${s.step}: ${s.error || '?'}`)
                    .join('; ');
                Toast.error(failed || (r && r.error) || 'Ошибка настройки');
            }
        } catch (e) {
            Toast.error(e.message);
        }
        await loadAux();
        await refresh();
    }

    async function runDnsmasqRevert() {
        const ok = window.confirm(
            'Откатить настройку dnsmasq?\n\n' +
            'systemd-resolved будет восстановлен на порту 53,' +
            ' dnsmasq остановлен. Маршрутизация по доменам после этого' +
            ' работать не будет до следующей настройки.\n\nПродолжить?'
        );
        if (!ok) return;
        Toast.info('Откат настройки dnsmasq...');
        try {
            const r = await API.post('/api/routing/dnsmasq/revert');
            if (r && r.ok) {
                Toast.success('dnsmasq откачен');
            } else {
                const failed = ((r && r.steps) || [])
                    .filter(s => !s.ok)
                    .map(s => `${s.step}: ${s.error || '?'}`)
                    .join('; ');
                Toast.error(failed || (r && r.error) || 'Ошибка отката');
            }
        } catch (e) {
            Toast.error(e.message);
        }
        await loadAux();
        await refresh();
    }

    // ─────── helpers ───────

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    // Экранирует и кавычки — пригодно для value="" и для строк внутри
    // inline-onclick (hostname устройства может содержать апостроф).
    function escAttr(s) {
        return esc(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    return {
        render, destroy, refresh,
        newRoute, edit, closeEditor, save, del, apply, applyAll,
        toggleMonitor, scan,
        setVia, setSearch,
        addDevice, addDeviceManual, removeDevice,
        toggleDevPicker, refreshDevices, toggleDevicesAuto,
        migrateLegacy, deleteLegacy, reapplyLowLevel,
        runDnsmasqSetup, runDnsmasqRevert,
    };
})();
