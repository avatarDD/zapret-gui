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
    let ndmsInfo     = null;   // /api/routing/ndms/status (Keenetic-native)
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
            const [rulesResp, cfgsResp, envResp, dnResp, ndmsResp] =
                await Promise.all([
                    API.get('/api/routing/rules'),
                    API.get('/api/awg/configs'),
                    API.get('/api/awg/environment').catch(() => null),
                    API.get('/api/routing/dnsmasq/status').catch(() => null),
                    API.get('/api/routing/ndms/status').catch(() => null),
                ]);
            rules       = (rulesResp && rulesResp.rules)   || [];
            configs     = (cfgsResp  && cfgsResp.configs)  || [];
            environment = envResp || null;
            dnsmasqInfo = dnResp   || null;
            ndmsInfo    = ndmsResp || null;
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

        const filterOptions = ['<option value="">Все (без фильтра)</option>'].concat(
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
                    <p class="text-muted" style="margin-top: 6px; font-size: 13px;">
                        Трафик к указанным IP/подсетям пойдёт через выбранный
                        туннель (через его таблицу маршрутизации). Удобно, когда
                        вы заранее знаете адреса сервиса. Пример:
                        <code>2.16.0.0/13</code> — диапазон CDN.
                    </p>
                    <div style="display: grid; grid-template-columns: 200px 1fr; gap: 8px 12px; margin-top: 8px; align-items: start;">
                        <label class="text-muted" style="padding-top: 6px;"
                               title="AWG-туннель, в который пойдёт выбранный трафик. В списке — ваши конфиги; пометка «(активен)» означает, что туннель сейчас поднят.">
                            Туннель назначения
                        </label>
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
                    <label class="text-muted" style="font-size:12px; display:flex; align-items:center; gap:6px;"
                           title="Показать в таблице ниже только правила, ведущие в выбранный туннель">
                        Фильтр по интерфейсу:
                        <select onchange="AwgRoutingPage.setFilterIface(this.value)"
                                class="form-control" style="max-width: 220px;">
                            ${filterOptions}
                        </select>
                    </label>
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

    // Платформо-зависимое пояснение: для чего нужен dnsmasq и почему он
    // может не работать. На Keenetic/OpenWrt dnsmasq — это штатный
    // DNS-сервер роутера, поэтому отдельная «настройка под :53» обычно
    // не нужна — нужно лишь убедиться, что он запущен. Проблема со
    // stub-listener'ом systemd-resolved актуальна именно для десктопного
    // Linux (Debian/Ubuntu).
    function dnsmasqExplanation(platformName) {
        const common =
            `<p style="font-size:13px;">
                Доменное routing работает так: dnsmasq резолвит указанные
                домены и складывает их IP в ipset/nftset, а трафик к этим
                IP заворачивается в выбранный туннель. Без запущенного
                dnsmasq собирать IP по доменам нечем.
             </p>`;

        if (platformName === 'keenetic' || platformName === 'openwrt') {
            return common +
                `<p style="font-size:13px;">
                    На <strong>${escapeHtml(platformName === 'keenetic' ? 'Keenetic' : 'OpenWrt')}</strong>
                    dnsmasq — это штатный DNS-сервер роутера, и он, как правило,
                    уже слушает :53. Отдельно отключать systemd-resolved здесь
                    не требуется. Кнопка ниже просто убедится, что dnsmasq
                    запущен, и при необходимости добавит include с нашими
                    правилами в его конфиг. Если статус ниже показывает
                    «запущен=да», скорее всего делать ничего не нужно.
                 </p>`;
        }

        // Generic Linux / Debian / Ubuntu и неизвестные платформы.
        return common +
            `<p style="font-size:13px;">
                На десктопном Linux (Debian/Ubuntu) со штатным
                systemd-resolved порт 53 обычно занят stub-listener'ом, и
                dnsmasq не стартует. Кнопка ниже автоматически отключит
                DNSStubListener в <code>/etc/systemd/resolved.conf</code>,
                поднимет dnsmasq на :53 и сохранит state-файл, чтобы при
                выключении последнего AWG-интерфейса откатить всё обратно.
             </p>`;
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

        // Keenetic NDMS-backend: если он доступен, dnsmasq нам не нужен
        // вообще — резолв и маршрутизация идут через встроенный
        // ndnsproxy роутера. В этом случае показываем зелёный баннер
        // вместо предупреждения про dnsmasq.
        const ndmsActive = !!(ndmsInfo && ndmsInfo.available);

        const dnReady = !!dn.available && !!dn.running && !!preferred;
        const setupApplied = !!(dnsmasqInfo && dnsmasqInfo.auto_setup_applied);
        // Кнопка нужна, если у нас не работает domain-routing и есть хоть
        // какая-то надежда поднять его: либо dnsmasq установлен (его надо
        // только запустить), либо есть бэкенд (можно поставить dnsmasq).
        const needsSetup = !dnReady &&
            (!!dn.available || !!backends.ipset || !!backends.nftset);
        // Также показываем кнопку, если auto_setup имеет применимые шаги
        // (например, при апгрейде версии: новая версия требует user=root
        // в dnsmasq.conf, и нашу запись надо добавить ретроактивно).
        const setupPlanHasSteps = !!(dnsmasqInfo &&
            dnsmasqInfo.auto_setup_plan &&
            dnsmasqInfo.auto_setup_plan.applicable);
        const setupButton = (needsSetup || setupPlanHasSteps)
            ? `<button class="btn btn-primary btn-sm"
                       onclick="AwgRoutingPage.runDnsmasqSetup()">
                   ${needsSetup ? 'Настроить dnsmasq автоматически'
                                 : 'Применить обновления dnsmasq-конфига'}
               </button>`
            : '';
        const revertButton = setupApplied && dnReady
            ? `<button class="btn btn-ghost btn-sm"
                       onclick="AwgRoutingPage.runDnsmasqRevert()"
                       title="Откатить изменения, возвращает systemd-resolved на :53 и останавливает dnsmasq">
                   Откатить настройку dnsmasq
               </button>`
            : '';

        const platformName = (environment && environment.platform && environment.platform.name) || '';
        const statusLine = `
            <p style="font-size:12px; margin:6px 0 10px;">
              Статус на этом устройстве: dnsmasq=<strong>${dn.available ? 'установлен' : 'не найден'}</strong>,
              запущен=<strong>${dn.running ? 'да' : 'нет'}</strong>,
              ipset=<strong>${backends.ipset ? 'есть' : 'нет'}</strong>,
              nft=<strong>${backends.nftset ? 'есть' : 'нет'}</strong>.
            </p>`;

        // Баннер: NDMS-режим → зелёный, dnsmasq-готов → нейтральный
        // info, dnsmasq-не-готов → жёлтый warning.
        let banner;
        if (ndmsActive) {
            banner = `<div class="alert alert-success" style="margin-bottom:12px;">
                <div class="alert-title">
                  Активен Keenetic-native режим (NDMS)
                </div>
                <p style="font-size:12px; margin:6px 0 0;">
                  Domain-маршрутизация идёт через встроенный
                  <code>dns-proxy route</code> Keenetic'а
                  (версия <strong>${escapeHtml(ndmsInfo.version || '?')}</strong>).
                  Никакой dnsmasq на этой платформе не нужен —
                  резолв и привязка к интерфейсу выполняются
                  системным ndnsproxy на 53-м порту.
                </p>
              </div>`;
        } else if (dnReady) {
            banner = `<div style="font-size:12px; margin-bottom:8px;
                            display:flex; gap:8px; align-items:center;
                            flex-wrap:wrap;">
                    <span class="text-muted">
                      dnsmasq <strong>${escapeHtml(dn.version || '?')}</strong>
                      (запущен), main config:
                      <code>${escapeHtml(dn.main_config || 'не найден')}</code>,
                      бэкенд: <strong>${escapeHtml(preferred)}</strong>
                      ${dn.include_present ? '' : ' — include будет добавлен автоматически'}
                      ${setupApplied ? ' — настройка выполнена через GUI, откатится при выключении последнего AWG' : ''}
                    </span>
                    ${revertButton}
               </div>`;
        } else {
            banner = `<div class="alert alert-warning" style="margin-bottom:12px;">
                    <div class="alert-title">Domain routing требует работающего dnsmasq</div>
                    ${dnsmasqExplanation(platformName)}
                    ${statusLine}
                    ${setupButton}
               </div>`;
        }

        const cfgOptions = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === formDomIface ? 'selected' : ''}>
                ${escapeHtml(c.name)}${c.active ? ' (активен)' : ''}
             </option>`
        ).join('');

        const filterOptions = ['<option value="">Все (без фильтра)</option>'].concat(
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
                        <label class="text-muted" style="padding-top: 6px;"
                               title="AWG-туннель, в который пойдёт выбранный трафик. В списке — ваши конфиги; пометка «(активен)» означает, что туннель сейчас поднят.">
                            Туннель назначения
                        </label>
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
                        <button class="btn btn-primary btn-sm" ${(busy || !dnReady) ? 'disabled' : ''}
                                onclick="AwgRoutingPage.submitDomain()">
                            Добавить правило
                        </button>
                        ${dnReady ? '' : '<span class="text-muted" style="margin-left:10px; font-size:12px;">недоступно: см. сообщение выше</span>'}
                    </div>
                `}
            </div>

            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="card-title">Domain-правила (${dnRules.length})</div>
                    <label class="text-muted" style="font-size:12px; display:flex; align-items:center; gap:6px;"
                           title="Показать в таблице ниже только правила, ведущие в выбранный туннель">
                        Фильтр по интерфейсу:
                        <select onchange="AwgRoutingPage.setFilterIface(this.value)"
                                class="form-control" style="max-width: 220px;">
                            ${filterOptions}
                        </select>
                    </label>
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

        const filterOptions = ['<option value="">Все (без фильтра)</option>'].concat(
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
                    Откуда берётся список:
                    DHCP-leases — <strong>${(devicesSrc.leases_paths || []).length}</strong> файл(а),
                    ARP — <strong>${devicesSrc.arp_available ? 'да' : 'нет'}</strong>${
                        typeof devicesSrc.ndm_available !== 'undefined'
                            ? `, Keenetic NDM — <strong>${devicesSrc.ndm_available ? 'да' : 'нет'}</strong>`
                            : ''
                    }.
                    Колонка «Имя» — это hostname из DHCP/роутера; она пустует,
                    если устройство не отдало имя (тогда ориентируйтесь на IP и MAC).
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
                        <label class="text-muted" style="padding-top: 6px;"
                               title="AWG-туннель, в который пойдёт выбранный трафик. В списке — ваши конфиги; пометка «(активен)» означает, что туннель сейчас поднят.">
                            Туннель назначения
                        </label>
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
                            Устройства в локальной сети (${devices.length}) — нажмите
                            «Через ${escapeHtml(formDevIface || '…')}» в строке, чтобы
                            направить весь трафик устройства в выбранный туннель:
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
                                        <th title="Hostname из DHCP/роутера. Пусто, если устройство не сообщило имя.">Имя</th>
                                        <th style="width: 12%;" title="Откуда узнали об устройстве: leases (DHCP), arp, ndm (Keenetic), rdns, oui (по MAC).">Источник</th>
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
                    <label class="text-muted" style="font-size:12px; display:flex; align-items:center; gap:6px;"
                           title="Показать в таблице ниже только правила, ведущие в выбранный туннель">
                        Фильтр по интерфейсу:
                        <select onchange="AwgRoutingPage.setFilterIface(this.value)"
                                class="form-control" style="max-width: 220px;">
                            ${filterOptions}
                        </select>
                    </label>
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

    async function runDnsmasqSetup() {
        // Сначала покажем план — что именно поменяется.
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
        const stepLines = steps.map((s, i) =>
            `${i + 1}. ${s.what}`).join('\n');
        const warnLines = (plan.warnings || []).join('\n');
        // Авто-revert при выключении последнего AWG есть только на
        // systemd-системах (там мы сохраняем state-файл). На
        // Keenetic/Entware dnsmasq — штатный резолвер, мы его не глушим.
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
        await refresh();
    }

    async function runDnsmasqRevert() {
        const ok = window.confirm(
            'Откатить настройку dnsmasq?\n\n' +
            'systemd-resolved будет восстановлен на порту 53,' +
            ' dnsmasq остановлен. Доменное routing после этого' +
            ' работать не будет до следующего setup.\n\nПродолжить?'
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
        await refresh();
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
        runDnsmasqSetup, runDnsmasqRevert,
    };
})();
