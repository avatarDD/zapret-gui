/**
 * singbox_proxies.js — таблица проксей sing-box.
 *
 * Тонкий адаптер над общим компонентом ProxyTable (см.
 * components/proxy_table.js): таблица Имя | Тип | Адрес | Задержка |
 * Трафик, мультивыбор, сортировка, тест, copy/paste ссылок, активация.
 *
 * Специфика sing-box:
 *   - items = «реальные» outbound'ы конфига (служебные direct/block/dns/
 *     selector/urltest отфильтрованы), активный — default selector'а;
 *   - серверы с битым ключом (reality без pbk и т.п. — sing-box на них
 *     не стартует) подсвечиваются через prune-invalid(apply:false) и
 *     удаляются кнопкой «Убрать битые»;
 *   - учёт трафика требует clash_api в конфиге — баннер с кнопкой
 *     включения;
 *   - активация пишется в конфиг (selector.default) — при работающем
 *     инстансе предлагаем перезапуск.
 */

const SingboxProxiesPage = (() => {

    const esc = ProxyTable.esc;
    const cfgUrl = (name, tail) =>
        `/api/singbox/configs/${encodeURIComponent(name)}${tail || ''}`;

    // ══════════════ движко-специфичные действия ══════════════

    async function activate(ctx, tag) {
        const st = ctx.state;
        const r = await API.post(cfgUrl(st.configName, '/activate'), { tag });
        if (!r || !r.ok) { Toast.error((r && r.error) || 'не удалось'); return; }
        if (r.live) {
            Toast.success(`Трафик идёт через «${tag}»`);
        } else if (r.needs_restart) {
            // Применится только после перезапуска — предложим сразу.
            if (confirm(`«${tag}» выбран. Перезапустить конфиг «${st.configName}», чтобы трафик пошёл через него?`)) {
                const rr = await API.post(cfgUrl(st.configName, '/restart'));
                if (rr && rr.ok) Toast.success(`Перезапущено — трафик через «${tag}»`);
                else Toast.error((rr && rr.error) || 'перезапуск не удался');
            } else {
                Toast.info(`«${tag}» выбран, применится после перезапуска`);
            }
        } else {
            Toast.success(`«${tag}» выбран активным`);
        }
        await ctx.loadItems();
        await ctx.loadTraffic();
    }

    async function pruneInvalid(ctx) {
        const st = ctx.state;
        if (!st.configName) return;
        const n = Object.keys(st.extra.invalidTags || {}).length;
        if (!n) { Toast.info('Серверов с битым ключом нет'); return; }
        if (!confirm(`Удалить ${n} серв. с битым ключом? Из-за них sing-box не запускается («invalid public_key»).`))
            return;
        st.busy = true; ctx.renderBody();
        try {
            const r = await API.post(cfgUrl(st.configName, '/prune-invalid'),
                                     { apply: true });
            if (r && r.ok) {
                Toast.success(`Удалено серверов с битым ключом: ${(r.removed || []).length}`);
                await ctx.loadItems();
                await ctx.loadTraffic();
            } else { Toast.error((r && r.error) || 'не удалось'); }
        } catch (e) { Toast.error(e.message); }
        finally { st.busy = false; ctx.renderBody(); }
    }

    async function enableClashApi(ctx) {
        const st = ctx.state;
        st.busy = true; ctx.renderBody();
        try {
            const r = await API.post(cfgUrl(st.configName, '/enable-clash-api'));
            if (r && r.ok) {
                if (r.needs_restart) {
                    Toast.success(`clash_api добавлен (порт ${r.port}). Перезапустите конфиг, чтобы учёт заработал.`);
                } else {
                    Toast.success(`clash_api добавлен (порт ${r.port}).`);
                }
                await ctx.loadTraffic();
            } else {
                Toast.error((r && r.error) || 'не удалось включить clash_api');
            }
        } catch (e) { Toast.error(e.message); }
        finally { st.busy = false; ctx.renderBody(); }
    }

    // ══════════════ адаптер ProxyTable ══════════════

    return ProxyTable.create({
        globalName: 'SingboxProxiesPage',
        bodyId: 'px-body',
        title: 'Прокси',
        description: 'Серверы конфига sing-box: тест доступности и задержки, ' +
                     'учёт трафика, копирование/вставка ссылок по Ctrl+C / Ctrl+V.',
        backHash: 'singbox-configs',
        backLabel: 'Конфиги',
        testStatusUrl: '/api/singbox/test/status',

        loadConfigs: async () => {
            const r = await API.get('/api/singbox/configs');
            return (r && r.configs) || [];
        },

        // По умолчанию — первый «не подписочный», иначе первый.
        pickDefaultConfig: (configs) => {
            const own = configs.find(c => !c.name.startsWith('imported-subscription-'));
            return (own || configs[0] || {}).name || '';
        },

        configOptionLabel: (c) =>
            (c.name.startsWith('imported-subscription-') ? ' (подписка)' : '')
            + (c.running ? ' ●' : ''),

        loadItems: async (ctx, configName) => {
            const r = await API.get(cfgUrl(configName, '/outbounds'));
            const all = (r && r.outbounds) || [];
            const service = new Set(['direct', 'block', 'dns', 'selector', 'urltest']);
            const real = all.filter(o => o && o.tag && o.type && !service.has(o.type));
            // Активный сервер — default первого selector'а (если он есть).
            const sel = all.find(o => o && o.type === 'selector');
            const activeId = sel ? (sel.default || (sel.outbounds || [])[0] || '') : '';

            // Серверы с битым ключом (reality без pbk и т.п.) — sing-box на
            // них не стартует. Помечаем их, чтобы было видно и можно удалить.
            const invalidTags = {};
            try {
                const p = await API.post(cfgUrl(configName, '/prune-invalid'),
                                         { apply: false });
                if (p && p.ok) for (const it of (p.invalid || [])) invalidTags[it.tag] = it.reason;
            } catch (e) { /* не критично — просто без бейджей */ }

            return {
                items: real.map(o => ({
                    id: o.tag,
                    type: o.type,
                    address: (o.server != null ? String(o.server) : '')
                             + (o.server_port != null ? ':' + o.server_port : ''),
                    raw: o,
                })),
                activeId,
                extra: { invalidTags },
            };
        },

        loadTraffic: async (ctx, configName) => {
            const r = await API.get(
                `/api/singbox/traffic?config=${encodeURIComponent(configName)}`);
            if (!r || !r.ok) return null;
            return {
                traffic: r.traffic || {},
                extra: { clashEnabled: r.clash_api, engineRunning: r.running },
            };
        },
        emptyTrafficExtra: { clashEnabled: null },

        // Полный re-render только когда статус clash_api сменился
        // (появился/исчез баннер) — иначе обновляем ячейки на месте.
        trafficNeedsRender: (prev, next) =>
            prev.clashEnabled !== next.clashEnabled,

        startTest: async (ctx, selectedOnly) => {
            const st = ctx.state;
            let payload;
            if (selectedOnly) {
                const obs = st.items.filter(i => st.selected.has(i.id)).map(i => i.raw);
                payload = { outbounds: obs, target: st.target };
            } else {
                payload = { config: st.configName, target: st.target };
            }
            return API.post('/api/singbox/test', payload);
        },

        exportLinks: (ctx) => {
            const st = ctx.state;
            const obs = st.items.filter(i => st.selected.has(i.id)).map(i => i.raw);
            return API.post('/api/singbox/export-links', { outbounds: obs });
        },

        importLinks: (ctx, text) =>
            API.post(cfgUrl(ctx.state.configName, '/import-links'), { text }),

        deleteItems: (ctx, tags) =>
            API.post(cfgUrl(ctx.state.configName, '/outbounds/delete-bulk'), { tags }),

        activate,

        // Бейдж «битый ключ» вместо результата теста.
        testCellOverride: (id, st) => {
            const bad = (st.extra.invalidTags || {})[id];
            if (!bad) return null;
            return `<span style="color:#e58;" title="${ProxyTable.escAttr(bad)}">⚠ битый ключ</span>`;
        },

        toolbarExtraHtml: (st) => {
            const invalidCount = Object.keys(st.extra.invalidTags || {}).length;
            if (!invalidCount) return '';
            return `
                <button class="btn btn-ghost btn-sm" ${st.busy ? 'disabled' : ''}
                        style="color:#e58; border-color:#e58;"
                        onclick="SingboxProxiesPage.pruneInvalid()"
                        title="Удалить серверы с битым ключом — из-за них sing-box не запускается">
                    ⚠ Убрать битые (${invalidCount})
                </button>`;
        },

        bannersHtml: (st) => {
            if (st.extra.clashEnabled !== false) return '';
            return `
                <div class="alert alert-warning" style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                    <div style="font-size:12px;">
                        Учёт трафика выключен: у конфига <strong>${esc(st.configName)}</strong>
                        нет <code>clash_api</code>. Включите его, чтобы считать объём
                        прокачанного через каждый сервер трафика.
                    </div>
                    <button class="btn btn-primary btn-sm" ${st.busy ? 'disabled' : ''}
                            onclick="SingboxProxiesPage.enableClashApi()">
                        Включить учёт трафика
                    </button>
                </div>`;
        },

        emptyConfigsHtml: () => `<div class="card"><div class="text-muted">
            Конфигов нет. Создайте конфиг или импортируйте подписку в разделе
            <a href="#singbox-configs" style="text-decoration:underline;">Конфиги</a>,
            либо вставьте ссылки сюда (Ctrl+V).
        </div></div>`,

        emptyItemsHtml: (st) => `<div class="card"><div class="text-muted">
            В конфиге «${esc(st.configName)}» нет серверов. Добавьте их в
            «Конструкторе» / «Импорте» или вставьте ссылки (Ctrl+V / кнопка «Вставить»).
        </div></div>`,

        extraMethods: { pruneInvalid, enableClashApi },
    });
})();
