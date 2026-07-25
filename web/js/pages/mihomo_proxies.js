/**
 * mihomo_proxies.js — таблица проксей mihomo (паритет с sing-box).
 *
 * Тонкий адаптер над общим компонентом ProxyTable (см.
 * components/proxy_table.js): таблица Имя | Тип | Адрес | Задержка |
 * Трафик, мультивыбор, сортировка, тест, copy/paste ссылок, активация.
 *
 * Специфика mihomo:
 *   - items = секция `proxies` clash-конфига, активный — `now` первой
 *     select-группы;
 *   - переключение узла/трафик/тест через движок требуют запущенного
 *     инстанса с external-controller (RESTful Clash API) — баннер с
 *     кнопкой включения; выбор узла живёт в рантайме, не в YAML;
 *   - режим отладки (log-level=debug) и просмотр хвоста лога инстанса
 *     (галка отладки — в режиме эксперта).
 */

const MihomoProxiesPage = (() => {

    const esc = ProxyTable.esc;
    const cfgUrl = (name, tail) =>
        `/api/mihomo/configs/${encodeURIComponent(name)}${tail || ''}`;

    // ══════════════ движко-специфичные действия ══════════════

    async function activate(ctx, name) {
        const st = ctx.state;
        const r = await API.post(cfgUrl(st.configName, '/activate'), { name });
        if (r && r.ok) {
            Toast.success(`Трафик идёт через «${name}» (группа ${r.group || '?'})`);
            await ctx.loadItems();
        } else if (r && r.needs_running) {
            Toast.error('Запустите конфиг — переключение у mihomo делается на лету.');
        } else if (r && r.needs_controller) {
            Toast.error('Нет external-controller — включите управление кнопкой и перезапустите конфиг.');
        } else {
            Toast.error((r && r.error) || 'не удалось переключить');
        }
    }

    async function enableController(ctx) {
        const st = ctx.state;
        st.busy = true; ctx.renderBody();
        try {
            const r = await API.post(cfgUrl(st.configName, '/enable-controller'));
            if (r && r.ok) {
                if (r.needs_restart) {
                    Toast.success(`external-controller добавлен (порт ${r.port}). Перезапустите конфиг, чтобы заработало.`);
                } else {
                    Toast.success(`external-controller добавлен (порт ${r.port}).`);
                }
                await ctx.loadItems();
            } else {
                Toast.error((r && r.error) || 'не удалось включить');
            }
        } catch (e) { Toast.error(e.message); }
        finally { st.busy = false; ctx.renderBody(); }
    }

    async function toggleDebug(ctx, on) {
        try {
            const r = await API.post('/api/mihomo/debug', { enabled: on });
            if (r && r.ok) {
                ctx.state.extra.debugEnabled = !!r.enabled;
                Toast.success(`Режим отладки ${r.enabled ? 'включён' : 'выключен'} — применится при перезапуске инстанса`);
            } else {
                Toast.error((r && r.error) || 'не удалось');
            }
        } catch (e) { Toast.error(e.message); }
        finally { ctx.renderBody(); }
    }

    async function toggleLog(ctx) {
        const st = ctx.state;
        if (st.extra.logText !== null) { st.extra.logText = null; ctx.renderBody(); return; }
        if (!st.configName) { Toast.error('Сначала выберите конфиг'); return; }
        try {
            const r = await API.get(cfgUrl(st.configName, '/log?lines=200'));
            if (r && r.ok) {
                st.extra.logText = r.exists ? (r.log || '(пусто)') : '(лог ещё не создан — запустите конфиг)';
            } else {
                st.extra.logText = (r && r.error) || '(ошибка чтения лога)';
            }
        } catch (e) { st.extra.logText = e.message; }
        ctx.renderBody();
    }

    // ══════════════ адаптер ProxyTable ══════════════

    return ProxyTable.create({
        globalName: 'MihomoProxiesPage',
        bodyId: 'mpx-body',
        title: 'Прокси',
        description: 'Серверы clash-конфига: тест задержки через движок, ' +
                     'учёт трафика, переключение активного узла на лету, ' +
                     'copy/paste ссылок (Ctrl+C / Ctrl+V).',
        backHash: 'mihomo',
        backLabel: 'Инстансы',
        testStatusUrl: '/api/mihomo/test/status',

        labels: {
            countWord:    'прокси',
            testNoun:     'прокси',
            itemOneAcc:   'узел',
            itemsAcc:     'прокси',
            rowTitle:     'Двойной клик — пустить трафик через этот узел',
            activeMark:   'активный узел',
            activateTitle:'Пустить трафик через выделенный узел (двойной клик по строке)',
            noLinks:      'Нет ссылок для копирования (тип не экспортируется)',
        },

        // Состояние отладки/лога живёт в state.extra.
        init: (ctx) => {
            ctx.state.extra.debugEnabled = false;
            ctx.state.extra.logText = null;
            API.get('/api/mihomo/debug')
                .then(r => {
                    ctx.state.extra.debugEnabled = !!(r && r.enabled);
                    ctx.renderBody();
                })
                .catch(() => { /* не критично */ });
        },

        onSwitchConfig: (ctx) => { ctx.state.extra.logText = null; },

        loadConfigs: async () => {
            const r = await API.get('/api/mihomo/configs');
            return (r && r.configs) || [];
        },

        loadItems: async (ctx, configName) => {
            const r = await API.get(cfgUrl(configName, '/proxies'));
            if (!r || !r.ok) {
                Toast.error((r && r.error) || 'не удалось получить прокси');
                return {
                    items: [], activeId: '', running: false,
                    extra: { hasController: false, controllerLive: false, selectGroups: [] },
                };
            }
            // Узлы подписки (proxy-providers) в конфиге не лежат — их
            // скачивает сам mihomo. Пока инстанс запущен и доступен
            // external-controller, показываем их наравне с обычными
            // (issue #248: иначе таблица пуста и подписка выглядит
            // нерабочей, хотя конфиг корректный).
            const fromProviders = [];
            for (const prov of (r.provider_live || [])) {
                for (const p of (prov.proxies || [])) {
                    fromProviders.push({
                        id: p.name,
                        type: p.type,
                        address: `подписка: ${prov.name}`,
                        raw: { name: p.name, type: p.type, provider: prov.name },
                    });
                }
            }
            const own = (r.proxies || []).map(p => ({
                id: p.name,
                type: p.type,
                address: (p.server != null ? String(p.server) : '')
                         + (p.port != null && p.port !== '' ? ':' + p.port : ''),
                raw: p,
            }));
            const seen = new Set(own.map(i => i.id));
            return {
                items: own.concat(fromProviders.filter(i => !seen.has(i.id))),
                activeId: r.active || '',
                running: !!r.running,
                extra: {
                    hasController: !!r.controller,
                    controllerLive: !!r.controller_live,
                    selectGroups: r.select_groups || [],
                    providers: r.providers || [],
                    providerLive: r.provider_live || [],
                },
            };
        },

        loadTraffic: async (ctx, configName) => {
            const r = await API.get(
                `/api/mihomo/traffic?config=${encodeURIComponent(configName)}`);
            if (!r || !r.ok) return null;
            return { traffic: r.traffic || {} };
        },

        startTest: async (ctx, selectedOnly) => {
            const st = ctx.state;
            const payload = { config: st.configName, target: st.target };
            if (selectedOnly) payload.names = [...st.selected];
            return API.post('/api/mihomo/test', payload);
        },

        testDoneExtra: (result) => result.engine_used
            ? '' : ' (только TCP — запустите конфиг для теста через движок)',

        exportLinks: (ctx) =>
            API.post('/api/mihomo/export-links',
                     { config: ctx.state.configName, names: [...ctx.state.selected] }),

        importLinks: (ctx, text) =>
            API.post(cfgUrl(ctx.state.configName, '/import-links'), { text }),

        deleteItems: (ctx, names) =>
            API.post(cfgUrl(ctx.state.configName, '/proxies/delete-bulk'), { names }),

        activate,

        statusInlineHtml: (st) => st.running
            ? ' · <span style="color:#39c45e;">running</span>'
            : ' · <span style="color:#e58;">stopped</span>',

        belowToolbarHtml: (st) => `
            <div style="display:flex; gap:14px; align-items:center; flex-wrap:wrap; margin-top:10px;">
                <label class="text-muted expert-only" style="display:flex; align-items:center; gap:5px; font-size:12px;">
                    <input type="checkbox" ${st.extra.debugEnabled ? 'checked' : ''}
                           onchange="MihomoProxiesPage.toggleDebug(this.checked)">
                    режим отладки (log-level=debug)
                </label>
                <button class="btn btn-ghost btn-sm" onclick="MihomoProxiesPage.toggleLog()">
                    ${st.extra.logText !== null ? 'Скрыть лог' : 'Показать лог'}
                </button>
            </div>`,

        bannersHtml: (st) => {
            const ex = st.extra;
            // Подписки proxy-providers: их узлы не лежат в конфиге, их
            // качает сам mihomo. Без этой плашки таблица выглядела пустой
            // и подписка казалась нерабочей (issue #248).
            let providersBanner = '';
            const provs = ex.providers || [];
            if (provs.length) {
                const live = (ex.providerLive || [])
                    .reduce((n, p) => n + (p.count || 0), 0);
                const list = provs.map(p =>
                    `<li><strong>${esc(p.name)}</strong>`
                    + (p.type ? ` · ${esc(p.type)}` : '')
                    + (p.url_host ? ` · ${esc(p.url_host)}` : '')
                    + (p.interval ? ` · обновление раз в ${esc(String(p.interval))} с` : '')
                    + `</li>`).join('');
                const tail = live
                    ? `Из них сейчас загружено узлов: <strong>${live}</strong> —
                       они показаны в таблице ниже.`
                    : (st.running
                        ? `Узлы пока не загружены. Обычно это значит, что mihomo не смог
                           скачать подписку (нет сети, неверный URL или требуется свой
                           User-Agent) — посмотрите «Лог».`
                        : `Узлы появятся после запуска конфига: их скачивает сам mihomo,
                           в файле конфига их нет.`)
                    + (ex.hasController ? '' :
                       ` Чтобы видеть узлы подписки, нужен <code>external-controller</code> —
                         кнопка ниже.`);
                providersBanner = `
                    <div class="alert" style="margin-top:10px; font-size:12px;">
                        <div>Подписки (<code>proxy-providers</code>) в этом конфиге:</div>
                        <ul style="margin:6px 0 6px 18px;">${list}</ul>
                        <div>${tail}</div>
                    </div>`;
            }
            if (ex.hasController && (ex.controllerLive || !st.running)) {
                return providersBanner;
            }
            if (!ex.hasController) {
                return `
                    <div class="alert alert-warning" style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                        <div style="font-size:12px;">
                            У конфига <strong>${esc(st.configName)}</strong> нет
                            <code>external-controller</code> — без него недоступны учёт
                            трафика, тест через движок и переключение узла на лету.
                        </div>
                        <button class="btn btn-primary btn-sm" ${st.busy ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.enableController()">
                            Включить управление и учёт трафика
                        </button>
                    </div>` + providersBanner;
            }
            // есть controller, но running и не отвечает
            return `
                <div class="alert alert-warning" style="margin-top:10px; font-size:12px;">
                    external-controller настроен, но не отвечает. Проверьте порт/secret
                    и что конфиг перезапущен после изменения.
                </div>` + providersBanner;
        },

        panelsHtml: (st) => {
            if (st.extra.logText === null || st.extra.logText === undefined) return '';
            return `
                <div style="margin-top:12px;">
                    <div class="text-muted" style="font-size:11px; margin-bottom:4px;">
                        Лог инстанса «${esc(st.configName)}» (хвост):
                    </div>
                    <pre style="max-height:240px; overflow:auto; background:var(--bg-input);
                                padding:8px; border-radius:6px; font-size:11px; white-space:pre-wrap;
                                margin:0;">${esc(st.extra.logText || '(пусто)')}</pre>
                </div>`;
        },

        emptyConfigsHtml: () => `<div class="card"><div class="text-muted">
            Конфигов нет. Создайте конфиг на странице
            <a href="#mihomo" style="text-decoration:underline;">Инстансы</a>
            и вставьте clash-YAML, либо вставьте ссылки сюда (Ctrl+V).
        </div></div>`,

        emptyItemsHtml: (st) => `<div class="card"><div class="text-muted">
            В конфиге «${esc(st.configName)}» нет прокси. Вставьте ссылки
            (Ctrl+V / кнопка «Вставить») или добавьте их в YAML на странице
            «Инстансы».
        </div></div>`,

        extraMethods: { enableController, toggleDebug, toggleLog },
    });
})();
