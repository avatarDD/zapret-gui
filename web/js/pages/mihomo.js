/**
 * mihomo.js — страница mihomo (Clash.Meta).
 *
 * Альтернативный прокси-движок рядом с sing-box (идея из XKeen).
 * Страница инстансов: обзор окружения, список инстансов с
 * up/down/restart и простой YAML-редактор конфигов. Установка/обновление
 * бинаря вынесены в отдельный раздел (mihomo-setup) — как у sing-box.
 *
 * Бэкенд — /api/mihomo/* (зеркалит /api/singbox/*). Конфиги — clash-YAML.
 * Polling раз в 5 секунд.
 */

const MihomoPage = (() => {

    let pollTimer = null;
    let configs = [];
    let env = null;
    let autostart = {};
    let busy = {};
    let editing = null;   // {name, text} | null   (null = редактор закрыт)

    // Маршрутизация (самодостаточные конфиги: tun+dns/fake-ip+rules внутри
    // движка mihomo — OS-слой ip rule не нужен).
    let routingOpts = null;            // /api/mihomo/routing/options
    let domainRendered = false, domainBusy = false;
    let domainForm = {
        name: 'mihomo-domains', proxy_link: '', proxy_config: '',
        route_all: false, hostlists: {}, lists: {}, domains: '', cidrs: '',
        stack: '', mtu: 1500, reject_quic: false, group_type: 'select',
    };
    let sourceRendered = false, sourceBusy = false;
    let sourceForm = {
        name: 'mihomo-devices', proxy_link: '', proxy_config: '',
        source_ips: '', route_all: false, stack: '', mtu: 1500,
        reject_quic: false, group_type: 'select',
    };
    let watchdog = null;               // /api/mihomo/watchdog

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">mihomo (Clash.Meta)${typeof Help !== 'undefined' ? Help.button('mihomo') : ''}</h1>
                    <p class="page-description">
                        Альтернативный прокси-движок: clash-YAML конфиги,
                        VLESS/Trojan/SS/Hysteria2/TUIC, GeoIP/GeoSite-роутинг.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.newConfig()">
                        + Конфиг
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='mihomo-setup'">
                        Установка
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div class="card" id="mh-summary" style="margin-bottom:16px;">
                <div class="card-title">Обзор</div>
                <div id="mh-summary-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div id="mh-editor"></div>

            <div class="card" id="mh-routing-domain" style="margin-bottom:16px;">
                <div class="card-title">
                    Маршрутизация — домены / списки${typeof Help !== 'undefined' ? Help.button('mihomo-routing') : ''}
                </div>
                <div id="mh-routing-domain-body" style="margin-top:8px;">
                    <div class="text-muted">Загрузка…</div>
                </div>
            </div>

            <div class="card" id="mh-routing-source" style="margin-bottom:16px;">
                <div class="card-title">
                    Весь трафик / по устройствам${typeof Help !== 'undefined' ? Help.button('mihomo-lite') : ''}
                </div>
                <div id="mh-routing-source-body" style="margin-top:8px;">
                    <div class="text-muted">Загрузка…</div>
                </div>
            </div>

            <div class="card" id="mh-watchdog" style="margin-bottom:16px;">
                <div class="card-title">
                    Проверка соединения (watchdog)${typeof Help !== 'undefined' ? Help.button('mihomo-watchdog') : ''}
                </div>
                <div id="mh-watchdog-body" style="margin-top:8px;">
                    <div class="text-muted">Загрузка…</div>
                </div>
            </div>

            <div id="mh-instances"></div>
        `;
        refresh();
        startPolling();
    }

    function destroy() {
        stopPolling();
    }

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [envResp, cfgsResp, autoResp, optsResp, wdResp] = await Promise.all([
                API.get('/api/mihomo/environment').catch(() => null),
                API.get('/api/mihomo/configs').catch(() => null),
                API.get('/api/mihomo/autostart').catch(() => null),
                API.get('/api/mihomo/routing/options').catch(() => null),
                API.get('/api/mihomo/watchdog').catch(() => null),
            ]);
            env       = envResp || null;
            configs   = (cfgsResp && cfgsResp.configs) || [];
            autostart = (autoResp && autoResp.status && autoResp.status.autostart) || {};
            if (optsResp && optsResp.ok) routingOpts = optsResp;
            if (wdResp && wdResp.ok) watchdog = wdResp.status;
        } catch (err) {
            const box = document.getElementById('mh-summary-body');
            if (box) box.innerHTML =
                `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function refresh() {
        await loadAll();
        renderSummary();
        renderDomainRouting();
        renderSourceRouting();
        renderWatchdog();
        renderInstances();
        renderEditor();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            // Не дёргаем список во время редактирования — не сбиваем ввод.
            if (!editing) refresh();
        }, 5000);
    }
    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // ══════════════ summary ══════════════

    function renderSummary() {
        const body = document.getElementById('mh-summary-body');
        if (!body) return;
        if (!env) {
            body.innerHTML = `<div class="text-muted">Нет данных от сервера.</div>`;
            return;
        }
        const bin       = env.binary || {};
        const platform  = env.platform || {};
        const installed = !!bin.installed;
        const active = configs.filter(c => c.running).length;

        // Установка/обновление вынесены в отдельный раздел «Установка»
        // (mihomo-setup) — как у sing-box. На дашборде показываем кнопку
        // установки только когда бинарь ещё не стоит.
        const installBtn = installed
            ? ''
            : `<button class="btn btn-primary btn-sm"
                       onclick="window.location.hash='mihomo-setup'">
                  Установить mihomo
               </button>`;

        body.innerHTML = `
            <div style="display:flex; gap:24px; flex-wrap:wrap; font-size:13px;">
                <div>
                    <div class="text-muted" style="font-size:11px;">Платформа</div>
                    <strong>${escapeHtml(platform.kind || platform.name || '?')}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">mihomo</div>
                    <strong>${installed
                        ? escapeHtml(bin.version || 'установлен')
                        : '<span style="color:#e58;">не установлен</span>'}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">Конфиги</div>
                    <strong>${configs.length} <span class="text-muted">(активно ${active})</span></strong>
                </div>
                <div style="margin-left:auto; display:flex; gap:8px;">
                    ${installBtn}
                </div>
            </div>
        `;
    }

    // ══════════════ instances ══════════════

    function renderInstances() {
        const box = document.getElementById('mh-instances');
        if (!box) return;
        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <div class="text-muted">
                      Конфигов нет. Нажмите «+ Конфиг» и вставьте clash-YAML.
                    </div>
                </div>`;
            return;
        }
        box.innerHTML = configs.map(c => {
            const active = !!c.running;
            const autoOn = !!autostart[c.name];
            const isBusy = !!busy[c.name];
            const upBtn = active
                ? `<button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="MihomoPage.down('${escapeAttr(c.name)}')">Остановить</button>`
                : `<button class="btn btn-primary btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="MihomoPage.up('${escapeAttr(c.name)}')">Запустить</button>`;
            return `
            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:15px; font-weight:600;">
                            ${escapeHtml(c.name)}
                            ${active
                                ? '<span style="color:#39c45e; font-size:11px; margin-left:6px;">● running</span>'
                                : '<span class="text-muted" style="font-size:11px; margin-left:6px;">● stopped</span>'}
                        </div>
                        <div class="text-muted" style="font-size:11px;">
                            ${escapeHtml(c.path)} · ${Math.round((c.size||0) / 1024)} KB
                            ${autoOn ? ' · автозапуск' : ''}
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        ${upBtn}
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="MihomoPage.restart('${escapeAttr(c.name)}')">Restart</button>
                        <label class="text-muted" style="font-size:11px; display:flex; align-items:center; gap:4px;">
                            <input type="checkbox" ${autoOn ? 'checked' : ''}
                                   onchange="MihomoPage.toggleAuto('${escapeAttr(c.name)}', this.checked)">
                            автозапуск
                        </label>
                        <button class="btn btn-ghost btn-sm"
                                onclick="MihomoPage.edit('${escapeAttr(c.name)}')">Редактировать</button>
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="MihomoPage.del('${escapeAttr(c.name)}')">Удалить</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    // ══════════════ editor ══════════════

    const SAMPLE_YAML =
`mixed-port: 7890
mode: rule
proxies:
  - name: "my-vless"
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: tcp
    tls: true
    servername: example.com
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["my-vless"]
rules:
  - MATCH,PROXY
`;

    function renderEditor() {
        const box = document.getElementById('mh-editor');
        if (!box) return;
        if (!editing) { box.innerHTML = ''; return; }
        const isNew = editing.isNew;
        box.innerHTML = `
            <div class="card" style="margin-bottom:16px; border:1px solid var(--border, #333);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="card-title">${isNew ? 'Новый конфиг' : 'Редактирование: ' + escapeHtml(editing.name)}</div>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.closeEditor()">Закрыть</button>
                </div>
                ${isNew ? `
                <div style="margin-top:8px;">
                    <label class="text-muted" style="font-size:12px;">Имя (A-Za-z0-9._-)</label>
                    <input id="mh-edit-name" class="input" style="width:100%; max-width:320px;"
                           value="${escapeAttr(editing.name)}" placeholder="например: home">
                </div>` : ''}
                <textarea id="mh-edit-text" spellcheck="false"
                          style="width:100%; min-height:340px; margin-top:8px; font-family:monospace;
                                 font-size:12px; white-space:pre; overflow:auto;">${escapeHtml(editing.text)}</textarea>
                <div style="display:flex; gap:8px; margin-top:8px;">
                    <button class="btn btn-primary btn-sm" onclick="MihomoPage.save()">Сохранить</button>
                    <button class="btn btn-ghost btn-sm"
                        onclick="MihomoPage.validate()">Проверить (mihomo -t)</button>
                </div>
            </div>
        `;
    }

    function newConfig() {
        editing = { name: '', text: SAMPLE_YAML, isNew: true };
        renderEditor();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function edit(name) {
        try {
            const r = await API.get(`/api/mihomo/configs/${encodeURIComponent(name)}`);
            if (!r || !r.ok) { Toast.error((r && r.error) || 'не найден'); return; }
            editing = { name, text: r.text || '', isNew: false };
            renderEditor();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (e) { Toast.error(e.message); }
    }

    function closeEditor() {
        editing = null;
        renderEditor();
        refresh();
    }

    async function save() {
        const ta = document.getElementById('mh-edit-text');
        if (!ta) return;
        const text = ta.value;
        let name = editing.name;
        if (editing.isNew) {
            const ni = document.getElementById('mh-edit-name');
            name = (ni && ni.value || '').trim();
            if (!name) { Toast.error('Укажите имя конфига'); return; }
        }
        try {
            let r;
            if (editing.isNew) {
                r = await API.post('/api/mihomo/configs', { name, text });
            } else {
                r = await API.put(`/api/mihomo/configs/${encodeURIComponent(name)}`, { text });
            }
            if (r && r.ok) {
                Toast.success('Сохранено');
                if (r.warnings && r.warnings.length) {
                    Toast.error('Предупреждения: ' + r.warnings.join('; '));
                }
                editing = null;
                renderEditor();
                await refresh();
            } else {
                Toast.error((r && r.error) || 'ошибка сохранения');
            }
        } catch (e) { Toast.error(e.message); }
    }

    async function validate() {
        if (!editing) return;
        // Проверяем то, что СЕЙЧАС в редакторе (а не сохранённое на диск) —
        // иначе кнопка вводит в заблуждение после правок без «Сохранить».
        const ta = document.getElementById('mh-edit-text');
        const text = ta ? ta.value : undefined;
        let name = editing.name;
        if (editing.isNew) {
            const ni = document.getElementById('mh-edit-name');
            name = ((ni && ni.value) || '').trim() || '_editor';
        }
        try {
            const r = await API.post(
                `/api/mihomo/configs/${encodeURIComponent(name)}/validate`,
                { text });
            if (r && r.ok) Toast.success('Конфиг валиден');
            else Toast.error('mihomo -t: ' + ((r && (r.stderr || r.error)) || 'ошибка'));
        } catch (e) { Toast.error(e.message); }
    }

    async function del(name) {
        if (!confirm(`Удалить конфиг «${name}»?`)) return;
        try {
            const r = await API.delete(`/api/mihomo/configs/${encodeURIComponent(name)}`);
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ══════════════ actions ══════════════

    async function up(name)      { await action(name, 'up'); }
    async function down(name)    { await action(name, 'down'); }
    async function restart(name) { await action(name, 'restart'); }

    async function action(name, op) {
        busy[name] = true;
        renderInstances();
        try {
            const r = await API.post(`/api/mihomo/configs/${encodeURIComponent(name)}/${op}`);
            if (r && r.ok) Toast.success(`${name}: ${op} OK`);
            else {
                Toast.error(`${name}: ${(r && r.error) || 'ошибка'}`);
                if (r && r.log_tail) console.warn(`mihomo ${name} log:`, r.log_tail);
            }
        } catch (e) { Toast.error(`${name}: ${e.message}`); }
        finally { busy[name] = false; await refresh(); }
    }

    async function toggleAuto(name, enabled) {
        try {
            const r = await API.post(`/api/mihomo/autostart/${encodeURIComponent(name)}`,
                                     { enabled });
            if (r && r.ok) Toast.success(`автозапуск ${name}: ${enabled ? 'вкл' : 'выкл'}`);
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    // ══════════════ routing: общий блок выбора прокси ══════════════

    function proxySourceHtml(prefix, f) {
        const cfgOptions = ((routingOpts && routingOpts.configs) || [])
            .map(n => `<option value="${escapeAttr(n)}" ${f.proxy_config === n ? 'selected' : ''}>${escapeHtml(n)}</option>`)
            .join('');
        return `
            <div>
                <div style="font-size:12px; margin-bottom:3px;">Прокси-сервер (ссылка или подписка)</div>
                <textarea rows="2" placeholder="vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// — одна или несколько ссылок / подписка"
                          style="width:100%; font-family:monospace; font-size:12px;"
                          oninput="MihomoPage.set${prefix}('proxy_link', this.value)">${escapeHtml(f.proxy_link)}</textarea>
                <div class="text-muted" style="font-size:11px; margin-top:3px;">
                    …или взять узлы из конфига:
                    <select onchange="MihomoPage.set${prefix}('proxy_config', this.value)">
                        <option value="">—</option>${cfgOptions}
                    </select>
                    <span>(если вставлена ссылка — используется она)</span>
                </div>
            </div>`;
    }

    function stackSelectHtml(prefix, f, recommend) {
        const opt = (v, label) =>
            `<option value="${v}" ${f.stack === v ? 'selected' : ''}>${label}</option>`;
        return `
            <label style="font-size:12px;">Стек TUN
                <select onchange="MihomoPage.set${prefix}('stack', this.value)">
                    ${opt('', 'авто (' + recommend + ')')}
                    ${opt('gvisor', 'gvisor — надёжно, выше CPU')}
                    ${opt('system', 'system — kernel, низкий CPU')}
                    ${opt('mixed', 'mixed')}
                </select>
            </label>`;
    }

    function routingNotice() {
        const o = routingOpts || {};
        let out = '';
        if (!o.installed)
            out += `<div style="color:#e58; font-size:12px; margin-bottom:6px;">
                mihomo не установлен — конфиг сохранится без проверки (mihomo -t).</div>`;
        else if (o.has_gvisor === false)
            out += `<div style="color:#e58; font-size:12px; margin-bottom:6px;">
                Сборка mihomo без gvisor — для доменного режима будет использован system-стек.</div>`;
        if (o.installed && o.tun_available === false)
            out += `<div style="color:#e58; font-size:12px; margin-bottom:6px;">
                /dev/net/tun недоступен — маршрутизация через TUN не заработает.</div>`;
        return out;
    }

    // ══════════════ routing: домены / списки ══════════════

    function renderDomainRouting() {
        const body = document.getElementById('mh-routing-domain-body');
        if (!body) return;
        if (!routingOpts) { body.innerHTML = '<div class="text-muted">Нет данных от сервера.</div>'; return; }
        if (domainRendered) return;       // не перерисовываем при poll (не теряем ввод)
        domainRendered = true;
        const o = routingOpts, f = domainForm;

        const hostlistChecks = (o.hostlists || []).map(h => `
            <label style="display:inline-flex; align-items:center; gap:5px; margin:2px 10px 2px 0; font-size:12px;">
                <input type="checkbox" ${f.hostlists[h.name] ? 'checked' : ''}
                       onchange="MihomoPage.toggleDomainHostlist('${escapeAttr(h.name)}', this.checked)">
                ${escapeHtml(h.name)} <span class="text-muted">(${h.count})</span>
            </label>`).join('') || '<span class="text-muted" style="font-size:12px;">нет списков</span>';

        const namedChecks = (o.lists || []).map(l => `
            <label style="display:inline-flex; align-items:center; gap:5px; margin:2px 10px 2px 0; font-size:12px;">
                <input type="checkbox" ${f.lists[l.id] ? 'checked' : ''}
                       onchange="MihomoPage.toggleDomainList('${escapeAttr(l.id)}', this.checked)">
                ${escapeHtml(l.name)} <span class="text-muted">(${l.domain_count})</span>
            </label>`).join('') || '<span class="text-muted" style="font-size:12px;">нет списков</span>';

        body.innerHTML = `
            <p class="text-muted" style="font-size:12.5px; margin-top:0;">
                Готовый конфиг mihomo, который заворачивает выбранные домены/списки
                в прокси через <strong>TUN + fake-ip</strong> (надёжный доменный
                роутинг: CDN/QUIC, чистый DNS — блокируемые домены резолвит сам
                прокси). Остальное идёт напрямую. OS-правила (ip rule) НЕ нужны —
                mihomo маршрутизирует сам. После создания запустите конфиг ниже.
            </p>
            ${routingNotice()}
            <div style="display:flex; flex-direction:column; gap:10px; max-width:680px;">
                <label style="font-size:12px;">Имя конфига
                    <input type="text" value="${escapeAttr(f.name)}" style="width:100%; max-width:320px;"
                           oninput="MihomoPage.setDomain('name', this.value)">
                </label>
                ${proxySourceHtml('Domain', f)}
                <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                    <input type="checkbox" ${f.route_all ? 'checked' : ''}
                           onchange="MihomoPage.setDomain('route_all', this.checked)">
                    Проксировать <strong>весь</strong> трафик (иначе — только выбранное ниже)
                </label>
                <div>
                    <div style="font-size:12px; margin-bottom:3px;">Списки доменов (nfqws2-хостлисты):</div>
                    <div>${hostlistChecks}</div>
                </div>
                <div>
                    <div style="font-size:12px; margin-bottom:3px;">Именованные списки:</div>
                    <div>${namedChecks}</div>
                </div>
                <label style="font-size:12px;">Доп. домены (по одному в строке)
                    <textarea rows="2" placeholder="example.com&#10;site.org" style="width:100%; font-size:12px;"
                              oninput="MihomoPage.setDomain('domains', this.value)">${escapeHtml(f.domains)}</textarea>
                </label>
                <label style="font-size:12px;">Доп. подсети / IP (CIDR, по одному в строке)
                    <textarea rows="2" placeholder="203.0.113.0/24" style="width:100%; font-size:12px;"
                              oninput="MihomoPage.setDomain('cidrs', this.value)">${escapeHtml(f.cidrs)}</textarea>
                </label>
                <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
                    ${stackSelectHtml('Domain', f, 'gvisor')}
                    <label style="font-size:12px;">MTU
                        <input type="number" min="1280" max="9000" value="${escapeAttr(f.mtu)}" style="width:90px;"
                               oninput="MihomoPage.setDomain('mtu', this.value)">
                    </label>
                    <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                        <input type="checkbox" ${f.reject_quic ? 'checked' : ''}
                               onchange="MihomoPage.setDomain('reject_quic', this.checked)">
                        Глушить QUIC (если не работает через прокси)
                    </label>
                </div>
                <div>
                    <button class="btn btn-primary btn-sm" id="mh-domain-create"
                            onclick="MihomoPage.createDomainRouting()">Создать конфиг</button>
                </div>
            </div>`;
    }

    function setDomain(key, val) {
        if (key === 'route_all' || key === 'reject_quic') domainForm[key] = !!val;
        else domainForm[key] = val;
    }
    function toggleDomainHostlist(name, checked) { domainForm.hostlists[name] = !!checked; }
    function toggleDomainList(id, checked) { domainForm.lists[id] = !!checked; }

    async function createDomainRouting() {
        if (domainBusy) return;
        const f = domainForm;
        if (!f.proxy_link.trim() && !f.proxy_config) {
            Toast.error('Укажите прокси: вставьте ссылку/подписку или выберите конфиг');
            return;
        }
        const payload = {
            name: f.name.trim() || 'mihomo-domains',
            proxy_link: f.proxy_link.trim(), proxy_config: f.proxy_config,
            route_all: f.route_all,
            hostlists: Object.keys(f.hostlists).filter(k => f.hostlists[k]),
            lists: Object.keys(f.lists).filter(k => f.lists[k]),
            domains: f.domains, cidrs: f.cidrs,
            stack: f.stack, mtu: parseInt(f.mtu, 10) || 1500,
            reject_quic: f.reject_quic, group_type: f.group_type,
        };
        domainBusy = true;
        const btn = document.getElementById('mh-domain-create');
        if (btn) { btn.disabled = true; btn.textContent = 'Создаю…'; }
        try {
            const r = await API.post('/api/mihomo/routing/domain/build', payload);
            if (r && r.ok) {
                const mode = r.route_all ? 'весь трафик'
                    : `${r.domains} доменов${r.cidrs ? ', ' + r.cidrs + ' подсетей' : ''}`;
                Toast.success(`Конфиг «${r.name}» создан (${mode}, стек=${r.stack}). Запустите его в списке ниже.`);
                if (r.warning) Toast.error(r.warning, 8000);
                await refresh();
            } else {
                Toast.error((r && r.error) || 'ошибка создания', 12000);
            }
        } catch (e) { Toast.error(e.message); }
        finally {
            domainBusy = false;
            if (btn) { btn.disabled = false; btn.textContent = 'Создать конфиг'; }
        }
    }

    // ══════════════ routing: весь трафик / по устройствам ══════════════

    function renderSourceRouting() {
        const body = document.getElementById('mh-routing-source-body');
        if (!body) return;
        if (!routingOpts) { body.innerHTML = '<div class="text-muted">Нет данных от сервера.</div>'; return; }
        if (sourceRendered) return;
        sourceRendered = true;
        const f = sourceForm;
        body.innerHTML = `
            <p class="text-muted" style="font-size:12px; margin:0 0 8px;">
                Лёгкий режим «весь ПК / выбранные устройства через прокси»:
                mihomo сам забирает трафик через <b>kernel-стек (system + auto-route)</b>
                — низкий CPU. Кого слать в прокси — по <b>source-IP</b> устройств или
                «весь трафик». Откат — просто остановите инстанс (down).
            </p>
            <div style="padding:8px 10px; border-radius:6px; margin-bottom:10px;
                        background:rgba(220,170,60,.12); border:1px solid rgba(220,170,60,.4);
                        font-size:12px;">
                ⚠️ На Keenetic экспериментально: auto-route ставит свои маршруты
                (может конфликтовать с NDM); на iptables-прошивках перехват
                ПЕРЕсылаемого трафика LAN-устройств не гарантирован (полноценный
                auto-redirect — только на nftables). Если устройство за роутером не
                заворачивается — используйте доменный режим выше или AWG.
            </div>
            ${routingNotice()}
            <div style="display:flex; flex-direction:column; gap:10px; max-width:680px;">
                <label style="font-size:12px;">Имя конфига
                    <input type="text" value="${escapeAttr(f.name)}" style="width:100%; max-width:320px;"
                           oninput="MihomoPage.setSource('name', this.value)">
                </label>
                ${proxySourceHtml('Source', f)}
                <label style="font-size:12px;">IP устройств (через запятую)
                    <input type="text" placeholder="192.168.1.117, 192.168.1.84" style="width:100%;"
                           value="${escapeAttr(f.source_ips)}"
                           oninput="MihomoPage.setSource('source_ips', this.value)">
                </label>
                <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                    <input type="checkbox" ${f.route_all ? 'checked' : ''}
                           onchange="MihomoPage.setSource('route_all', this.checked)">
                    Весь трафик роутера через прокси (игнорировать список IP)
                </label>
                <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
                    ${stackSelectHtml('Source', f, 'system')}
                    <label style="font-size:12px;">MTU
                        <input type="number" min="1280" max="9000" value="${escapeAttr(f.mtu)}" style="width:90px;"
                               oninput="MihomoPage.setSource('mtu', this.value)">
                    </label>
                    <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                        <input type="checkbox" ${f.reject_quic ? 'checked' : ''}
                               onchange="MihomoPage.setSource('reject_quic', this.checked)">
                        Глушить QUIC
                    </label>
                </div>
                <div>
                    <button class="btn btn-primary btn-sm" id="mh-source-create"
                            onclick="MihomoPage.createSourceRouting()">Создать конфиг</button>
                </div>
            </div>`;
    }

    function setSource(key, val) {
        if (key === 'route_all' || key === 'reject_quic') sourceForm[key] = !!val;
        else sourceForm[key] = val;
    }

    async function createSourceRouting() {
        if (sourceBusy) return;
        const f = sourceForm;
        if (!f.proxy_link.trim() && !f.proxy_config) {
            Toast.error('Укажите прокси (ссылку/подписку или конфиг)'); return;
        }
        const payload = {
            name: f.name.trim() || 'mihomo-devices',
            proxy_link: f.proxy_link.trim(), proxy_config: f.proxy_config,
            source_ips: f.source_ips, route_all: f.route_all,
            stack: f.stack, mtu: parseInt(f.mtu, 10) || 1500,
            reject_quic: f.reject_quic, group_type: f.group_type,
        };
        sourceBusy = true;
        const btn = document.getElementById('mh-source-create');
        if (btn) { btn.disabled = true; btn.textContent = 'Создаю…'; }
        try {
            const r = await API.post('/api/mihomo/routing/source/build', payload);
            if (r && r.ok) {
                Toast.success(`Конфиг «${r.name}» создан (стек=${r.stack}). `
                    + 'Запустите его. OS-правила (ip rule) НЕ нужны — mihomo заберёт трафик сам.');
                if (r.warning) Toast.error(r.warning, 8000);
                await refresh();
            } else {
                Toast.error((r && r.error) || 'ошибка', 12000);
            }
        } catch (e) { Toast.error(e.message); }
        finally {
            sourceBusy = false;
            if (btn) { btn.disabled = false; btn.textContent = 'Создать конфиг'; }
        }
    }

    // ══════════════ watchdog ══════════════

    function renderWatchdog() {
        const box = document.getElementById('mh-watchdog-body');
        if (!box) return;
        const s = (watchdog && watchdog.settings) || {};
        const on = !!s.enabled;
        box.innerHTML = `
            <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                <input type="checkbox" id="mh-wd-on" ${on ? 'checked' : ''}
                       onchange="MihomoPage.saveWatchdog()">
                <span>Перезапускать mihomo при плохом соединении</span>
            </label>
            <p class="text-muted" style="font-size:12px; margin:6px 0 0;">
                Периодически проверяет связь <b>через прокси</b> (external-controller:
                реально открывает облако сквозь активный узел группы) и
                перезапускает инстанс, если соединение зависло или движок перестал
                отвечать. Работает только для конфигов с external-controller — наш
                флоу маршрутизации добавляет его автоматически.
            </p>
            <div id="mh-wd-adv" style="margin-top:10px; ${on ? '' : 'display:none;'}">
                <div style="display:grid; grid-template-columns:220px 1fr; gap:6px 12px; max-width:560px; align-items:center;">
                    <label class="text-muted" style="font-size:12px;">Интервал проверки, с</label>
                    <input type="number" id="mh-wd-iv" style="max-width:100px;"
                           min="15" max="3600" value="${escapeAttr(s.check_interval_sec || 60)}">
                    <label class="text-muted" style="font-size:12px;">Неудач подряд → рестарт</label>
                    <input type="number" id="mh-wd-thr" style="max-width:100px;"
                           min="1" max="10" value="${escapeAttr(s.probe_fail_threshold || 2)}">
                    <label class="text-muted" style="font-size:12px;">Таймаут пробы, мс</label>
                    <input type="number" id="mh-wd-to" style="max-width:100px;"
                           min="1000" max="30000" value="${escapeAttr(s.probe_timeout_ms || 5000)}">
                </div>
                <div style="margin-top:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.saveWatchdog()">Сохранить параметры</button>
                </div>
            </div>`;
    }

    async function saveWatchdog() {
        const on = !!(document.getElementById('mh-wd-on') || {}).checked;
        const iv = (document.getElementById('mh-wd-iv') || {}).value;
        const thr = (document.getElementById('mh-wd-thr') || {}).value;
        const to = (document.getElementById('mh-wd-to') || {}).value;
        const payload = { enabled: on };
        if (iv) payload.check_interval_sec = parseInt(iv, 10) || 60;
        if (thr) payload.probe_fail_threshold = parseInt(thr, 10) || 2;
        if (to) payload.probe_timeout_ms = parseInt(to, 10) || 5000;
        try {
            const r = await API.post('/api/mihomo/watchdog', payload);
            if (r && r.ok) {
                watchdog = r.status || watchdog;
                Toast.success(on ? 'Проверка соединения включена'
                                 : 'Проверка соединения выключена');
                const adv = document.getElementById('mh-wd-adv');
                if (adv) adv.style.display = on ? '' : 'none';
            } else {
                Toast.error((r && r.error) || 'ошибка');
            }
        } catch (e) { Toast.error(e.message); }
    }

    // ══════════════ helpers ══════════════

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escapeAttr(s) {
        return escapeHtml(s).replace(/"/g, '&quot;');
    }

    return {
        render, destroy, refresh,
        up, down, restart, toggleAuto,
        newConfig, edit, closeEditor, save, validate, del,
        setDomain, toggleDomainHostlist, toggleDomainList, createDomainRouting,
        setSource, createSourceRouting,
        saveWatchdog,
    };
})();
