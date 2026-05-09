/**
 * awg_routing.js — Selective routing.
 *
 * Табы:
 *   - По IP/CIDR  (реализовано)
 *   - Домены      (заглушка — будет в следующем промте)
 *   - Устройства  (заглушка — будет в следующем промте)
 */

const AwgRoutingPage = (() => {

    let activeTab    = 'cidr';
    let rules        = [];
    let configs      = [];     // список AWG-конфигов
    let environment  = null;   // отчёт детектора (для подсказок)
    let busy         = false;

    // Форма создания
    let formIface    = '';
    let formCidrs    = '';
    let formIpVer    = 'auto';
    let formDesc     = '';

    // Фильтр списка
    let filterIface  = '';

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Selective routing</h1>
                    <p class="page-description">
                        Какой трафик в какой туннель направлять.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='awg'">
                        ← Туннели
                    </button>
                    <button class="btn btn-ghost btn-sm"
                            onclick="AwgRoutingPage.reapplyAll()">
                        Переприменить все
                    </button>
                </div>
            </div>

            <div class="tabs-bar">
                <button class="tab-btn ${activeTab === 'cidr' ? 'active' : ''}"
                        onclick="AwgRoutingPage.switchTab('cidr')">
                    По IP/CIDR
                </button>
                <button class="tab-btn ${activeTab === 'domain' ? 'active' : ''}"
                        onclick="AwgRoutingPage.switchTab('domain')">
                    Домены
                </button>
                <button class="tab-btn ${activeTab === 'device' ? 'active' : ''}"
                        onclick="AwgRoutingPage.switchTab('device')">
                    Устройства
                </button>
            </div>

            <div class="card" style="border-top-left-radius:0; border-top-right-radius:0;">
                <div id="awg-routing-tab-content">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>
        `;

        loadAll().then(renderTab);
    }

    function destroy() {}

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [rulesResp, cfgsResp, envResp] = await Promise.all([
                API.get('/api/routing/rules'),
                API.get('/api/awg/configs'),
                API.get('/api/awg/environment').catch(() => null),
            ]);
            rules       = (rulesResp && rulesResp.rules)   || [];
            configs     = (cfgsResp  && cfgsResp.configs)  || [];
            environment = envResp || null;
            if (!formIface && configs.length > 0) {
                formIface = configs[0].name;
            }
        } catch (err) {
            const box = document.getElementById('awg-routing-tab-content');
            if (box) box.innerHTML = `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function refresh() {
        try {
            const r = await API.get('/api/routing/rules');
            rules = r.rules || [];
            renderTab();
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════ tabs ══════════════

    function switchTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.tabs-bar .tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        const map = { cidr: 0, domain: 1, device: 2 };
        const btns = document.querySelectorAll('.tabs-bar .tab-btn');
        if (btns[map[tab]]) btns[map[tab]].classList.add('active');
        renderTab();
    }

    function renderTab() {
        const box = document.getElementById('awg-routing-tab-content');
        if (!box) return;
        if (activeTab === 'cidr')   return renderCidrTab(box);
        if (activeTab === 'domain') return renderPlaceholder(box, 'Домены',
            'Маршрутизация по доменам через dnsmasq + ipset/nftset появится в следующей итерации.');
        if (activeTab === 'device') return renderPlaceholder(box, 'Устройства',
            'Per-device routing (по IP/MAC устройств LAN) появится в следующей итерации.');
    }

    function renderPlaceholder(box, title, desc) {
        box.innerHTML = `
            <h3 style="margin: 4px 0 12px 0;">${escapeHtml(title)}</h3>
            <p class="text-muted">${escapeHtml(desc)}</p>
        `;
    }

    // ══════════════ tab: CIDR ══════════════

    function renderCidrTab(box) {
        const cidrRules = rules.filter(r => r.type === 'cidr');
        const visibleRules = filterIface
            ? cidrRules.filter(r => r.target_iface === filterIface)
            : cidrRules;

        const ifacesInRules = Array.from(new Set(cidrRules.map(r => r.target_iface)));

        const platformLine = environment && environment.platform
            ? `<div class="text-muted" style="font-size:12px; margin-bottom:8px;">
                    Платформа: <strong>${escapeHtml(environment.platform.name || '?')}</strong>,
                    firewall: <strong>${escapeHtml((environment.platform.firewall_backend) || 'n/a')}</strong>
               </div>`
            : '';

        const cfgOptions = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === formIface ? 'selected' : ''}>
                ${escapeHtml(c.name)}${c.active ? ' (активен)' : ''}
             </option>`
        ).join('');

        const filterOptions = ['<option value="">Все интерфейсы</option>'].concat(
            ifacesInRules.map(i =>
                `<option value="${escapeAttr(i)}" ${i === filterIface ? 'selected' : ''}>
                    ${escapeHtml(i)}
                 </option>`
            )
        ).join('');

        box.innerHTML = `
            ${platformLine}

            <div class="card" style="margin-bottom: 12px;">
                <div class="card-title">Добавить CIDR-правило</div>
                ${configs.length === 0 ? `
                    <p class="text-muted" style="margin-top: 8px;">
                        Нет ни одного AWG-конфига. Сначала создайте туннель в разделе
                        <a href="#awg-configs">Конфиги</a>.
                    </p>
                ` : `
                    <div style="display: grid; grid-template-columns: 200px 1fr; gap: 8px 12px; margin-top: 8px; align-items: start;">
                        <label class="text-muted" style="padding-top: 6px;">Интерфейс</label>
                        <select id="rt-form-iface" onchange="AwgRoutingPage.setFormIface(this.value)"
                                class="form-control" style="max-width: 280px;">
                            ${cfgOptions}
                        </select>

                        <label class="text-muted" style="padding-top: 6px;">CIDR-список</label>
                        <textarea id="rt-form-cidrs"
                                  oninput="AwgRoutingPage.setFormCidrs(this.value)"
                                  placeholder="По одному в строке или через запятую: 1.2.3.0/24, 10.0.0.0/8, ::/0"
                                  rows="4"
                                  style="font-family: monospace; width: 100%;">${escapeHtml(formCidrs)}</textarea>

                        <label class="text-muted" style="padding-top: 6px;">IP-версия</label>
                        <select id="rt-form-ipver" onchange="AwgRoutingPage.setFormIpVer(this.value)"
                                class="form-control" style="max-width: 280px;">
                            <option value="auto" ${formIpVer === 'auto' ? 'selected' : ''}>Авто</option>
                            <option value="v4"   ${formIpVer === 'v4'   ? 'selected' : ''}>Только IPv4</option>
                            <option value="v6"   ${formIpVer === 'v6'   ? 'selected' : ''}>Только IPv6</option>
                        </select>

                        <label class="text-muted" style="padding-top: 6px;">Описание</label>
                        <input type="text" id="rt-form-desc"
                               oninput="AwgRoutingPage.setFormDesc(this.value)"
                               value="${escapeAttr(formDesc)}"
                               placeholder="например: Telegram CIDR через WARP"
                               class="form-control" style="max-width: 480px;">
                    </div>
                    <div style="margin-top: 12px;">
                        <button class="btn btn-primary btn-sm" ${busy ? 'disabled' : ''}
                                onclick="AwgRoutingPage.submitCidr()">
                            Добавить правило
                        </button>
                    </div>
                `}
            </div>

            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="card-title">CIDR-правила (${cidrRules.length})</div>
                    <select onchange="AwgRoutingPage.setFilterIface(this.value)"
                            class="form-control" style="max-width: 220px;">
                        ${filterOptions}
                    </select>
                </div>

                ${visibleRules.length === 0
                    ? `<p class="text-muted" style="margin-top: 12px;">Правил пока нет.</p>`
                    : `
                <table class="table" style="margin-top: 8px;">
                    <thead>
                        <tr>
                            <th style="width: 14%;">Интерфейс</th>
                            <th>CIDR</th>
                            <th style="width: 8%;">v</th>
                            <th>Описание</th>
                            <th style="width: 6%;"></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visibleRules.map(r => `
                            <tr>
                                <td><strong>${escapeHtml(r.target_iface)}</strong></td>
                                <td style="font-family: monospace; font-size: 12px;">
                                    ${(r.cidrs || []).map(c => escapeHtml(c)).join('<br>')}
                                </td>
                                <td>${escapeHtml(r.ip_version || 'auto')}</td>
                                <td>${escapeHtml(r.description || '')}</td>
                                <td style="text-align: right;">
                                    <button class="btn btn-ghost btn-sm"
                                            title="Удалить"
                                            onclick="AwgRoutingPage.deleteRule('${escapeAttr(r.id)}')">
                                        ✕
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`
                }
            </div>
        `;
    }

    // ══════════════ form actions ══════════════

    function setFormIface(v)  { formIface = v; }
    function setFormCidrs(v)  { formCidrs = v; }
    function setFormIpVer(v)  { formIpVer = v; }
    function setFormDesc(v)   { formDesc  = v; }
    function setFilterIface(v) { filterIface = v; renderTab(); }

    function parseCidrs(text) {
        return String(text || '')
            .split(/[\s,;]+/)
            .map(s => s.trim())
            .filter(Boolean);
    }

    async function submitCidr() {
        if (busy) return;
        const cidrs = parseCidrs(formCidrs);
        if (!formIface) {
            Toast.error('Выберите интерфейс');
            return;
        }
        if (cidrs.length === 0) {
            Toast.error('Укажите хотя бы один CIDR');
            return;
        }

        busy = true;
        try {
            const resp = await API.post('/api/routing/rules', {
                type:         'cidr',
                target_iface: formIface,
                cidrs:        cidrs,
                ip_version:   formIpVer,
                description:  formDesc,
                enabled:      true,
            });
            if (resp.ok) {
                Toast.success('Правило добавлено');
                if (resp.applied && resp.applied.deferred) {
                    Toast.info('Интерфейс не поднят — правило применится при старте');
                } else if (resp.applied && resp.applied.errors && resp.applied.errors.length) {
                    Toast.error('Ошибки применения: ' + resp.applied.errors.join('; '));
                }
                formCidrs = '';
                formDesc  = '';
                await refresh();
            } else {
                Toast.error(resp.error || 'Ошибка добавления');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            busy = false;
        }
    }

    async function deleteRule(id) {
        if (!confirm('Удалить правило?')) return;
        try {
            const r = await API.delete('/api/routing/rules/' + encodeURIComponent(id));
            if (r.ok) {
                Toast.success('Правило удалено');
                await refresh();
            } else {
                Toast.error(r.error || 'Ошибка удаления');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function reapplyAll() {
        try {
            const r = await API.post('/api/routing/apply');
            if (r.ok) {
                Toast.success('Правила переприменены');
                await refresh();
            } else {
                Toast.error(r.error || 'Ошибка');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════ helpers ══════════════

    function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    }

    function escapeAttr(s) {
        return String(s || '').replace(/'/g, '&#39;').replace(/"/g, '&quot;');
    }

    return {
        render, destroy,
        switchTab,
        setFormIface, setFormCidrs, setFormIpVer, setFormDesc,
        setFilterIface,
        submitCidr, deleteRule, reapplyAll,
    };
})();
