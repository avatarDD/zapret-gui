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
    let dnsmasqInfo  = null;   // /api/routing/dnsmasq/status
    let devices      = [];     // /api/devices (DHCP+ARP)
    let devicesSrc   = null;   // sources status
    let busy         = false;

    // Форма создания (CIDR)
    let formIface    = '';
    let formCidrs    = '';
    let formIpVer    = 'auto';
    let formDesc     = '';

    // Форма создания (Domain)
    let formDomIface = '';
    let formDomList  = '';
    let formDomDesc  = '';

    // Форма создания (Device)
    let formDevIface  = '';
    let formDevManual = '';     // ручной ввод IP, если нет в списке
    let formDevDesc   = '';
    let devicesAutoRefresh = false;
    let devicesAutoTimer   = null;

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

    function destroy() {
        stopDevicesAutoRefresh();
    }

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [rulesResp, cfgsResp, envResp, dnResp] = await Promise.all([
                API.get('/api/routing/rules'),
                API.get('/api/awg/configs'),
                API.get('/api/awg/environment').catch(() => null),
                API.get('/api/routing/dnsmasq/status').catch(() => null),
            ]);
            rules       = (rulesResp && rulesResp.rules)   || [];
            configs     = (cfgsResp  && cfgsResp.configs)  || [];
            environment = envResp || null;
            dnsmasqInfo = dnResp   || null;
            if (!formIface && configs.length > 0) {
                formIface = configs[0].name;
            }
            if (!formDomIface && configs.length > 0) {
                formDomIface = configs[0].name;
            }
            if (!formDevIface && configs.length > 0) {
                formDevIface = configs[0].name;
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
        // Останавливаем авто-обновление устройств при уходе со страницы.
        if (activeTab !== 'device') stopDevicesAutoRefresh();
        if (activeTab === 'cidr')   return renderCidrTab(box);
        if (activeTab === 'domain') return renderDomainTab(box);
        if (activeTab === 'device') return renderDeviceTab(box);
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

    // ══════════════ tab: Domains ══════════════

    function renderDomainTab(box) {
        const dnRules = rules.filter(r => r.type === 'domain');
        const visibleRules = filterIface
            ? dnRules.filter(r => r.target_iface === filterIface)
            : dnRules;

        const ifacesInRules = Array.from(new Set(dnRules.map(r => r.target_iface)));
        const dn = (dnsmasqInfo && dnsmasqInfo.dnsmasq) || {};
        const backends = (dnsmasqInfo && dnsmasqInfo.backends) || {};
        const preferred = (dnsmasqInfo && dnsmasqInfo.preferred_backend) || '';

        const dnAvailable = !!dn.available && !!preferred;
        const banner = dnAvailable
            ? `<div class="text-muted" style="font-size:12px; margin-bottom:8px;">
                    dnsmasq <strong>${escapeHtml(dn.version || '?')}</strong>${dn.running ? ' (запущен)' : ' (не запущен)'},
                    main config: <code>${escapeHtml(dn.main_config || 'не найден')}</code>,
                    бэкенд: <strong>${escapeHtml(preferred)}</strong>
                    ${dn.include_present ? '' : ' — include будет добавлен автоматически'}
               </div>`
            : `<div class="card" style="background:#fbeaea; margin-bottom:12px;">
                    <strong>dnsmasq недоступен</strong><br>
                    <span class="text-muted" style="font-size:13px;">
                    ${dn.available ? 'Бэкенд (ipset или nftables) не найден.' : 'dnsmasq не установлен или не виден.'}
                    Без него domain-routing работать не будет —
                    установите/активируйте dnsmasq, ipset или nftables на платформе.
                    Текущий статус:
                    dnsmasq=${dn.available ? 'есть' : 'нет'},
                    ipset=${backends.ipset ? 'есть' : 'нет'},
                    nft=${backends.nftset ? 'есть' : 'нет'}.
                    </span>
               </div>`;

        const cfgOptions = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === formDomIface ? 'selected' : ''}>
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
            ${banner}

            <div class="card" style="margin-bottom: 12px;">
                <div class="card-title">Добавить правило по доменам</div>
                ${configs.length === 0 ? `
                    <p class="text-muted" style="margin-top: 8px;">
                        Нет ни одного AWG-конфига. Сначала создайте туннель в разделе
                        <a href="#awg-configs">Конфиги</a>.
                    </p>
                ` : `
                    <p class="text-muted" style="margin-top: 6px; font-size: 13px;">
                        dnsmasq будет резолвить эти домены и добавлять полученные IP
                        в ${escapeHtml(preferred || 'set')}. Маркированные пакеты уйдут
                        через выбранный интерфейс. Поддерживаются поддомены: например,
                        <code>example.com</code> покрывает <code>www.example.com</code>.
                    </p>
                    <div style="display: grid; grid-template-columns: 200px 1fr; gap: 8px 12px; margin-top: 8px; align-items: start;">
                        <label class="text-muted" style="padding-top: 6px;">Интерфейс</label>
                        <select id="rt-dom-iface" onchange="AwgRoutingPage.setFormDomIface(this.value)"
                                class="form-control" style="max-width: 280px;">
                            ${cfgOptions}
                        </select>

                        <label class="text-muted" style="padding-top: 6px;">Домены</label>
                        <textarea id="rt-dom-list"
                                  oninput="AwgRoutingPage.setFormDomList(this.value)"
                                  placeholder="По одному в строке: example.com, telegram.org, googlevideo.com"
                                  rows="6"
                                  style="font-family: monospace; width: 100%;">${escapeHtml(formDomList)}</textarea>

                        <label class="text-muted" style="padding-top: 6px;">Описание</label>
                        <input type="text" id="rt-dom-desc"
                               oninput="AwgRoutingPage.setFormDomDesc(this.value)"
                               value="${escapeAttr(formDomDesc)}"
                               placeholder="например: соцсети через WARP"
                               class="form-control" style="max-width: 480px;">
                    </div>
                    <div style="margin-top: 12px;">
                        <button class="btn btn-primary btn-sm" ${(busy || !dnAvailable) ? 'disabled' : ''}
                                onclick="AwgRoutingPage.submitDomain()">
                            Добавить правило
                        </button>
                        ${dnAvailable ? '' : '<span class="text-muted" style="margin-left:10px; font-size:12px;">недоступно: см. сообщение выше</span>'}
                    </div>
                `}
            </div>

            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="card-title">Domain-правила (${dnRules.length})</div>
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
                            <th>Домены</th>
                            <th>Описание</th>
                            <th style="width: 6%;"></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visibleRules.map(r => `
                            <tr>
                                <td><strong>${escapeHtml(r.target_iface)}</strong></td>
                                <td style="font-family: monospace; font-size: 12px;">
                                    ${(r.domains || []).slice(0, 8).map(d => escapeHtml(d)).join(', ')}
                                    ${(r.domains || []).length > 8 ? ` <span class="text-muted">… +${r.domains.length - 8}</span>` : ''}
                                </td>
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

    // ══════════════ tab: Devices ══════════════

    async function loadDevices() {
        try {
            const r = await API.get('/api/devices');
            if (r && r.ok) {
                devices    = r.devices || [];
                devicesSrc = r.sources || null;
            } else {
                devices    = [];
                devicesSrc = null;
            }
        } catch (e) {
            devices    = [];
            devicesSrc = null;
        }
    }

    function renderDeviceTab(box) {
        const devRules = rules.filter(r => r.type === 'device');
        const visibleRules = filterIface
            ? devRules.filter(r => r.target_iface === filterIface)
            : devRules;
        const ifacesInRules = Array.from(new Set(devRules.map(r => r.target_iface)));

        const cfgOptions = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === formDevIface ? 'selected' : ''}>
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

        // Уже привязанные source IP → быстрый поиск.
        const boundByIp = {};
        devRules.forEach(r => {
            const ip = (r.source_ip || '').split('/')[0];
            if (ip) boundByIp[ip] = r;
        });

        const srcSummary = devicesSrc
            ? `<div class="text-muted" style="font-size:12px; margin-bottom:8px;">
                    Источники: leases — <strong>${(devicesSrc.leases_paths || []).length}</strong>,
                    ARP — <strong>${devicesSrc.arp_available ? 'да' : 'нет'}</strong>
               </div>`
            : '';

        // Запускаем первичную загрузку устройств, если ещё не делали.
        if (devices.length === 0 && devicesSrc === null) {
            loadDevices().then(() => renderTab());
        }

        box.innerHTML = `
            ${srcSummary}

            <div class="card" style="margin-bottom: 12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="card-title">Привязать устройство к интерфейсу</div>
                    <div style="display:flex; gap:6px; align-items:center;">
                        <label class="text-muted" style="font-size:12px;">
                            <input type="checkbox"
                                   ${devicesAutoRefresh ? 'checked' : ''}
                                   onchange="AwgRoutingPage.toggleDevicesAutoRefresh()">
                            автообновление
                        </label>
                        <button class="btn btn-ghost btn-sm" onclick="AwgRoutingPage.refreshDevices()">
                            Обновить список
                        </button>
                    </div>
                </div>

                ${configs.length === 0 ? `
                    <p class="text-muted" style="margin-top: 8px;">
                        Нет ни одного AWG-конфига. Сначала создайте туннель в разделе
                        <a href="#awg-configs">Конфиги</a>.
                    </p>
                ` : `
                    <p class="text-muted" style="margin-top: 6px; font-size: 13px;">
                        Весь трафик с выбранного устройства уйдёт через интерфейс
                        ниже. Используется
                        <code>ip rule from &lt;ip&gt; lookup &lt;table&gt;</code>,
                        работает на Keenetic/OpenWrt/Linux.
                    </p>

                    <div style="display: grid; grid-template-columns: 200px 1fr; gap: 8px 12px; margin-top: 8px; align-items: start;">
                        <label class="text-muted" style="padding-top: 6px;">Интерфейс</label>
                        <select id="rt-dev-iface" onchange="AwgRoutingPage.setFormDevIface(this.value)"
                                class="form-control" style="max-width: 280px;">
                            ${cfgOptions}
                        </select>

                        <label class="text-muted" style="padding-top: 6px;">Описание</label>
                        <input type="text" id="rt-dev-desc"
                               oninput="AwgRoutingPage.setFormDevDesc(this.value)"
                               value="${escapeAttr(formDevDesc)}"
                               placeholder="например: телефон жены через WARP"
                               class="form-control" style="max-width: 480px;">
                    </div>

                    <div style="margin-top: 14px;">
                        <div class="text-muted" style="font-size: 12px; margin-bottom: 6px;">
                            Устройства из DHCP/ARP (${devices.length}):
                        </div>
                        ${devices.length === 0
                            ? `<p class="text-muted" style="font-size: 13px;">
                                Список пуст. Убедитесь, что сервис запущен на роутере,
                                либо введите IP вручную ниже.
                               </p>`
                            : `
                            <table class="table" style="margin-top: 4px;">
                                <thead>
                                    <tr>
                                        <th style="width: 14%;">IP</th>
                                        <th style="width: 18%;">MAC</th>
                                        <th>Имя</th>
                                        <th style="width: 12%;">Источник</th>
                                        <th style="width: 22%; text-align: right;"></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${devices.map(d => {
                                        const bound = boundByIp[d.ip];
                                        return `
                                        <tr>
                                            <td style="font-family: monospace; font-size: 12px;">${escapeHtml(d.ip)}</td>
                                            <td style="font-family: monospace; font-size: 12px;">${escapeHtml(d.mac || '—')}</td>
                                            <td>${escapeHtml(d.hostname || '')}</td>
                                            <td><span class="text-muted" style="font-size: 11px;">${escapeHtml(d.source || '')}</span></td>
                                            <td style="text-align: right;">
                                                ${bound
                                                    ? `<span class="text-muted" style="font-size: 12px; margin-right: 6px;">
                                                            → <strong>${escapeHtml(bound.target_iface)}</strong>
                                                       </span>
                                                       <button class="btn btn-ghost btn-sm"
                                                               onclick="AwgRoutingPage.deleteRule('${escapeAttr(bound.id)}')">
                                                           Отвязать
                                                       </button>`
                                                    : `<button class="btn btn-primary btn-sm" ${busy ? 'disabled' : ''}
                                                               onclick="AwgRoutingPage.bindDeviceFromList('${escapeAttr(d.ip)}', '${escapeAttr(d.mac || '')}', '${escapeAttr(d.hostname || '')}')">
                                                           Через ${escapeHtml(formDevIface || '?')}
                                                       </button>`
                                                }
                                            </td>
                                        </tr>`;
                                    }).join('')}
                                </tbody>
                            </table>`
                        }
                    </div>

                    <div style="margin-top: 16px;">
                        <div class="text-muted" style="font-size: 12px; margin-bottom: 6px;">
                            Или вручную (если устройства нет в списке выше):
                        </div>
                        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                            <input type="text" id="rt-dev-manual"
                                   oninput="AwgRoutingPage.setFormDevManual(this.value)"
                                   value="${escapeAttr(formDevManual)}"
                                   placeholder="например: 192.168.1.50"
                                   class="form-control" style="max-width: 240px;">
                            <button class="btn btn-primary btn-sm" ${busy ? 'disabled' : ''}
                                    onclick="AwgRoutingPage.submitDeviceManual()">
                                Добавить
                            </button>
                        </div>
                    </div>
                `}
            </div>

            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="card-title">Device-правила (${devRules.length})</div>
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
                            <th style="width: 18%;">IP</th>
                            <th style="width: 18%;">MAC</th>
                            <th>Hostname / описание</th>
                            <th style="width: 6%;"></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${visibleRules.map(r => `
                            <tr>
                                <td><strong>${escapeHtml(r.target_iface)}</strong></td>
                                <td style="font-family: monospace; font-size: 12px;">${escapeHtml(r.source_ip || '')}</td>
                                <td style="font-family: monospace; font-size: 12px;">${escapeHtml(r.mac || '—')}</td>
                                <td>
                                    ${r.hostname ? `<strong>${escapeHtml(r.hostname)}</strong>` : ''}
                                    ${r.description ? `<div class="text-muted" style="font-size: 12px;">${escapeHtml(r.description)}</div>` : ''}
                                </td>
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

    async function refreshDevices() {
        await loadDevices();
        renderTab();
    }

    function toggleDevicesAutoRefresh() {
        devicesAutoRefresh = !devicesAutoRefresh;
        if (devicesAutoRefresh) {
            startDevicesAutoRefresh();
        } else {
            stopDevicesAutoRefresh();
        }
        renderTab();
    }

    function startDevicesAutoRefresh() {
        stopDevicesAutoRefresh();
        devicesAutoTimer = setInterval(async () => {
            if (activeTab !== 'device') {
                stopDevicesAutoRefresh();
                return;
            }
            await loadDevices();
            // Также подтянем правила, на случай если их меняли.
            try {
                const r = await API.get('/api/routing/rules');
                rules = r.rules || [];
            } catch (e) { /* ignore */ }
            renderTab();
        }, 10000);
    }

    function stopDevicesAutoRefresh() {
        if (devicesAutoTimer) {
            clearInterval(devicesAutoTimer);
            devicesAutoTimer = null;
        }
    }

    async function bindDeviceFromList(ip, mac, hostname) {
        if (busy) return;
        if (!formDevIface) {
            Toast.error('Выберите интерфейс');
            return;
        }
        await submitDevice({ source_ip: ip, mac: mac, hostname: hostname });
    }

    async function submitDeviceManual() {
        if (busy) return;
        const ip = (formDevManual || '').trim();
        if (!ip) {
            Toast.error('Введите IP устройства');
            return;
        }
        await submitDevice({ source_ip: ip });
    }

    async function submitDevice({ source_ip, mac = '', hostname = '' }) {
        if (busy) return;
        if (!formDevIface) {
            Toast.error('Выберите интерфейс');
            return;
        }
        busy = true;
        try {
            const resp = await API.post('/api/routing/rules', {
                type:         'device',
                target_iface: formDevIface,
                source_ip:    source_ip,
                mac:          mac,
                hostname:     hostname,
                description:  formDevDesc,
                enabled:      true,
            });
            if (resp.ok) {
                Toast.success('Устройство привязано');
                if (resp.applied && resp.applied.deferred) {
                    Toast.info('Интерфейс не поднят — правило применится при старте');
                } else if (resp.applied && resp.applied.error) {
                    Toast.error('Ошибка применения: ' + resp.applied.error);
                }
                formDevManual = '';
                formDevDesc   = '';
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

    function parseDomains(text) {
        return String(text || '')
            .split(/[\s,;]+/)
            .map(s => s.trim().toLowerCase())
            .filter(s => s && /^[a-z0-9.\-_*]+$/i.test(s));
    }

    async function submitDomain() {
        if (busy) return;
        const domains = parseDomains(formDomList);
        if (!formDomIface) {
            Toast.error('Выберите интерфейс');
            return;
        }
        if (domains.length === 0) {
            Toast.error('Укажите хотя бы один домен');
            return;
        }
        busy = true;
        try {
            const resp = await API.post('/api/routing/rules', {
                type:         'domain',
                target_iface: formDomIface,
                domains:      domains,
                description:  formDomDesc,
                enabled:      true,
            });
            if (resp.ok) {
                Toast.success('Правило добавлено');
                if (resp.applied && resp.applied.deferred) {
                    Toast.info('Интерфейс не поднят — dnsmasq уже собирает IP, fwmark подключится при старте');
                } else if (resp.applied && resp.applied.errors && resp.applied.errors.length) {
                    Toast.error('Ошибки применения: ' + resp.applied.errors.join('; '));
                }
                formDomList = '';
                formDomDesc = '';
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

    // ══════════════ form actions ══════════════

    function setFormIface(v)  { formIface = v; }
    function setFormCidrs(v)  { formCidrs = v; }
    function setFormIpVer(v)  { formIpVer = v; }
    function setFormDesc(v)   { formDesc  = v; }
    function setFilterIface(v) { filterIface = v; renderTab(); }

    function setFormDomIface(v) { formDomIface = v; }
    function setFormDomList(v)  { formDomList  = v; }
    function setFormDomDesc(v)  { formDomDesc  = v; }

    function setFormDevIface(v)  { formDevIface  = v; renderTab(); }
    function setFormDevManual(v) { formDevManual = v; }
    function setFormDevDesc(v)   { formDevDesc   = v; }

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
        setFormDomIface, setFormDomList, setFormDomDesc, submitDomain,
        setFormDevIface, setFormDevManual, setFormDevDesc,
        bindDeviceFromList, submitDeviceManual,
        refreshDevices, toggleDevicesAutoRefresh,
    };
})();
