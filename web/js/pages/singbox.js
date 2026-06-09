/**
 * singbox.js — Dashboard для sing-box.
 *
 * Список конфигов / активных инстансов, статус каждого,
 * кнопки up/down/restart, ссылки на «Конфиги» и «Установка».
 * Polling раз в 5 секунд (как awg_dashboard).
 */

const SingboxDashboardPage = (() => {

    let pollTimer = null;
    let configs = [];
    let env = null;
    let autostart = {};
    let busy = {};
    let transparent = null;          // /api/singbox/transparent/status
    let tpForm = {                   // форма прозрачного проксирования
        mode: 'tproxy', tcp_port: 1100, udp_port: 1102,
        proxy_self: false, dns_hijack_port: 0, ipv6_policy: 'allow',
        inject_config: '',
    };
    let tunForm = {                  // форма TUN-интерфейса (для Selective routing)
        config: '', interface_name: 'singbox-tun',
        address: '172.18.0.1/30', stack: 'system', mtu: 9000,
        auto_route: false,
    };
    let tpNote = '';                 // последняя ошибка применения firewall (persist)

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">sing-box — инстансы</h1>
                    <p class="page-description">
                        VLESS / Trojan / Hysteria2 / TUIC / Shadowsocks через
                        универсальный sing-box-движок.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox-configs'">
                        Конфиги
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox-setup'">
                        Установка
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SingboxDashboardPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div class="card" id="sb-summary" style="margin-bottom:16px;">
                <div class="card-title">Обзор</div>
                <div id="sb-summary-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div id="sb-instances"></div>

            <div class="card" id="sb-transparent" style="margin-top:16px;">
                <div class="card-title">Прозрачное проксирование (TProxy / Redirect / Hybrid)${typeof Help !== 'undefined' ? Help.button('transparent') : ''}</div>
                <div id="sb-transparent-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div class="card" id="sb-tun" style="margin-top:16px;">
                <div class="card-title">TUN-интерфейс (для выборочной маршрутизации)</div>
                <div id="sb-tun-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>
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
            const [envResp, cfgsResp, autoResp, tpResp] = await Promise.all([
                API.get('/api/singbox/environment').catch(() => null),
                API.get('/api/singbox/configs').catch(() => null),
                API.get('/api/singbox/autostart').catch(() => null),
                API.get('/api/singbox/transparent/status').catch(() => null),
            ]);
            env       = envResp || null;
            configs   = (cfgsResp && cfgsResp.configs) || [];
            autostart = (autoResp && autoResp.status && autoResp.status.autostart) || {};
            transparent = tpResp || null;
            // Подхватываем сохранённые настройки в форму (один раз и при смене).
            if (transparent && transparent.settings && transparent.settings.mode) {
                const s = transparent.settings;
                tpForm = Object.assign({}, tpForm, {
                    mode: s.mode, tcp_port: s.tcp_port, udp_port: s.udp_port,
                    proxy_self: !!s.proxy_self,
                    dns_hijack_port: s.dns_hijack_port || 0,
                    ipv6_policy: s.ipv6_policy || 'allow',
                });
            }
        } catch (err) {
            const box = document.getElementById('sb-summary-body');
            if (box) box.innerHTML =
                `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function refresh() {
        await loadAll();
        renderSummary();
        renderInstances();
        renderTransparent();
        renderTun();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(refresh, 5000);
    }
    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // ══════════════ summary ══════════════

    function renderSummary() {
        const body = document.getElementById('sb-summary-body');
        if (!body) return;

        if (!env) {
            body.innerHTML = `<div class="text-muted">Нет данных от сервера.</div>`;
            return;
        }

        const bin       = env.binary || {};
        const platform  = env.platform || {};
        const tun       = env.tun || {};
        const installed = !!bin.installed;
        const ready     = !!env.ready;
        const active = configs.filter(c => c.running).length;

        const installBtn = installed
            ? ''
            : `<button class="btn btn-primary btn-sm"
                       onclick="window.location.hash='singbox-setup'">
                  Установить sing-box
              </button>`;

        body.innerHTML = `
            <div style="display:flex; gap:24px; flex-wrap:wrap; font-size:13px;">
                <div>
                    <div class="text-muted" style="font-size:11px;">Платформа</div>
                    <strong>${escapeHtml(platform.kind || platform.name || '?')}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">sing-box</div>
                    <strong>${installed
                        ? escapeHtml(bin.version || 'установлен')
                        : '<span style="color:#e58;">не установлен</span>'}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">TUN</div>
                    <strong>${tun.available
                        ? 'доступен'
                        : '<span style="color:#e58;">нет</span>'}</strong>
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
        const box = document.getElementById('sb-instances');
        if (!box) return;

        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <div class="text-muted">
                      Конфигов нет. Перейдите в раздел
                      <a href="#singbox-configs" style="text-decoration:underline;">Конфиги</a>,
                      создайте новый или импортируйте подписку.
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
                           onclick="SingboxDashboardPage.down('${escapeAttr(c.name)}')">
                       Остановить
                   </button>`
                : `<button class="btn btn-primary btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="SingboxDashboardPage.up('${escapeAttr(c.name)}')">
                       Запустить
                   </button>`;

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
                            ${escapeHtml(c.path)} · ${Math.round(c.size / 1024)} KB
                            ${autoOn ? ' · автозапуск' : ''}
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        ${upBtn}
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="SingboxDashboardPage.restart('${escapeAttr(c.name)}')">
                            Restart
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="window.location.hash='singbox-configs?edit=${encodeURIComponent(c.name)}'">
                            Редактировать
                        </button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    // ══════════════ actions ══════════════

    async function up(name) {
        await action(name, 'up');
    }
    async function down(name) {
        await action(name, 'down');
    }
    async function restart(name) {
        await action(name, 'restart');
    }

    async function action(name, op) {
        busy[name] = true;
        renderInstances();
        try {
            const r = await API.post(`/api/singbox/configs/${encodeURIComponent(name)}/${op}`);
            if (r && r.ok) {
                Toast.success(`${name}: ${op} OK`);
            } else {
                const err = (r && r.error) || 'ошибка';
                Toast.error(`${name}: ${err}`);
                if (r && r.log_tail) {
                    console.warn(`sing-box ${name} log tail:`, r.log_tail);
                }
            }
        } catch (e) {
            Toast.error(`${name}: ${e.message}`);
        } finally {
            busy[name] = false;
            await refresh();
        }
    }

    // ══════════════ transparent proxy ══════════════

    function renderTransparent() {
        const box = document.getElementById('sb-transparent-body');
        if (!box) return;
        const backend = transparent ? (transparent.backend || 'none') : 'none';
        const avail = backend !== 'none';
        const applied = transparent && transparent.settings
                        && transparent.settings.mode;
        const cfgOpts = ['<option value="">— выбрать конфиг —</option>'].concat(
            configs.map(c => `<option value="${escapeAttr(c.name)}"
                ${c.name === tpForm.inject_config ? 'selected' : ''}>${escapeHtml(c.name)}</option>`)
        ).join('');
        const opt = (v, cur, label) =>
            `<option value="${v}" ${v === cur ? 'selected' : ''}>${label}</option>`;

        box.innerHTML = `
            <p class="text-muted" style="font-size:13px; margin-top:0;">
                Заворачивает трафик LAN-клиентов (и опц. самого роутера) в
                sing-box без настройки клиентов. Нужен соответствующий inbound
                в конфиге (кнопка «Добавить inbound'ы»).
                ${backend === 'iptables' ? ' Бэкенд: <strong>iptables</strong>.' : ''}
                ${backend === 'nftables' ? '<br><span style="color:#6aa;">iptables не найден — будет использован бэкенд <strong>nftables</strong>.</span>' : ''}
                ${avail ? '' : '<br><span style="color:#e58;">Ни iptables, ни nftables не найдены — применение работать не будет.</span>'}
            </p>
            ${tpNote ? `<div style="margin:0 0 10px; padding:9px 11px; border-radius:6px;
                background:rgba(229,80,136,0.12); border:1px solid rgba(229,80,136,0.35);
                color:#e58; font-size:12px; line-height:1.45; white-space:pre-wrap;">${escapeHtml(tpNote)}</div>` : ''}
            ${applied ? `<div style="margin-bottom:8px; font-size:12px;">
                Сейчас активно: <strong>${escapeHtml(transparent.settings.mode)}</strong>,
                порты ${escapeHtml(transparent.settings.tcp_port)}${transparent.settings.mode==='hybrid' ? '/'+escapeHtml(transparent.settings.udp_port) : ''}
                ${transparent.settings.proxy_self ? ', +роутер' : ''}
                </div>` : ''}
            <div style="display:grid; grid-template-columns:160px 1fr; gap:8px 12px; align-items:center; max-width:640px;">
                <label class="text-muted">Режим</label>
                <select class="form-control" style="max-width:220px;"
                        onchange="SingboxDashboardPage.setTp('mode', this.value)">
                    ${opt('tproxy', tpForm.mode, 'TProxy (TCP+UDP)')}
                    ${opt('redirect', tpForm.mode, 'Redirect (только TCP)')}
                    ${opt('hybrid', tpForm.mode, 'Hybrid (TCP redirect + UDP tproxy)')}
                </select>

                <label class="text-muted">TCP-порт</label>
                <input type="number" class="form-control" style="max-width:140px;"
                       value="${escapeAttr(tpForm.tcp_port)}"
                       onchange="SingboxDashboardPage.setTp('tcp_port', this.value)">

                <label class="text-muted">UDP-порт (hybrid)</label>
                <input type="number" class="form-control" style="max-width:140px;"
                       value="${escapeAttr(tpForm.udp_port)}"
                       onchange="SingboxDashboardPage.setTp('udp_port', this.value)">

                <label class="text-muted">DNS-hijack порт</label>
                <input type="number" class="form-control" style="max-width:140px;"
                       value="${escapeAttr(tpForm.dns_hijack_port)}"
                       title="0 = выключено"
                       onchange="SingboxDashboardPage.setTp('dns_hijack_port', this.value)">

                <label class="text-muted">IPv6</label>
                <select class="form-control" style="max-width:220px;"
                        onchange="SingboxDashboardPage.setTp('ipv6_policy', this.value)">
                    ${opt('allow', tpForm.ipv6_policy, 'Не трогать')}
                    ${opt('drop', tpForm.ipv6_policy, 'Глушить v6 (anti-leak)')}
                </select>

                <label class="text-muted">Трафик роутера</label>
                <label class="text-muted" style="display:flex; align-items:center; gap:6px;">
                    <input type="checkbox" ${tpForm.proxy_self ? 'checked' : ''}
                           onchange="SingboxDashboardPage.setTp('proxy_self', this.checked)">
                    Заворачивать OUTPUT (трафик самого роутера)
                </label>
            </div>

            <div style="display:flex; gap:8px; margin-top:12px; flex-wrap:wrap;">
                <button class="btn btn-primary btn-sm" ${avail ? '' : 'disabled'}
                        onclick="SingboxDashboardPage.applyTransparent()">Применить firewall</button>
                <button class="btn btn-ghost btn-sm"
                        onclick="SingboxDashboardPage.removeTransparent()">Снять</button>
            </div>

            <div style="margin-top:14px; border-top:1px solid var(--border,#333); padding-top:10px;">
                <div class="text-muted" style="font-size:12px; margin-bottom:6px;">
                    Добавить нужные inbound'ы (redirect/tproxy) в конфиг под выбранный режим:
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <select class="form-control" style="max-width:240px;"
                            onchange="SingboxDashboardPage.setTp('inject_config', this.value)">
                        ${cfgOpts}
                    </select>
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxDashboardPage.injectInbounds()">Добавить inbound'ы</button>
                </div>
            </div>
        `;
    }

    function setTp(key, value) {
        if (key === 'proxy_self') tpForm.proxy_self = !!value;
        else if (['tcp_port', 'udp_port', 'dns_hijack_port'].includes(key))
            tpForm[key] = parseInt(value, 10) || 0;
        else tpForm[key] = value;
    }

    async function applyTransparent() {
        try {
            const r = await API.post('/api/singbox/transparent/apply', {
                mode: tpForm.mode,
                tcp_port: tpForm.tcp_port,
                udp_port: tpForm.udp_port,
                proxy_self: tpForm.proxy_self,
                dns_hijack_port: tpForm.dns_hijack_port,
                ipv6_policy: tpForm.ipv6_policy,
            });
            if (r && r.ok) {
                tpNote = '';
                Toast.success('Прозрачное проксирование применено (' + tpForm.mode + ')');
            } else {
                tpNote = (r && (r.error || (r.errors || []).join('; '))) || 'ошибка';
                // Подсказку про TPROXY держим дольше — её надо прочитать.
                Toast.error(tpNote, r && r.need === 'tproxy' ? 15000 : undefined);
            }
        } catch (e) { tpNote = e.message; Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function removeTransparent() {
        try {
            const r = await API.post('/api/singbox/transparent/remove', {});
            if (r && r.ok) { tpNote = ''; Toast.success('Правила сняты'); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function injectInbounds() {
        if (!tpForm.inject_config) { Toast.error('Выберите конфиг'); return; }
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(tpForm.inject_config)}/transparent-inbounds`,
                { mode: tpForm.mode, tcp_port: tpForm.tcp_port,
                  udp_port: tpForm.udp_port,
                  dns_port: tpForm.dns_hijack_port });
            if (r && r.ok) Toast.success('Inbound\'ы добавлены в ' + tpForm.inject_config);
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ══════════════ TUN interface (for selective routing) ══════════════

    function renderTun() {
        const box = document.getElementById('sb-tun-body');
        if (!box) return;
        if (!tunForm.config && configs.length) tunForm.config = configs[0].name;
        const cfgOpts = ['<option value="">— выбрать конфиг —</option>'].concat(
            configs.map(c => `<option value="${escapeAttr(c.name)}"
                ${c.name === tunForm.config ? 'selected' : ''}>${escapeHtml(c.name)}${c.running ? ' ●' : ''}</option>`)
        ).join('');
        const opt = (v, cur, label) =>
            `<option value="${v}" ${v === cur ? 'selected' : ''}>${label}</option>`;
        box.innerHTML = `
            <p class="text-muted" style="font-size:13px; margin-top:0;">
                Создаёт сетевой интерфейс sing-box. После (пере)запуска конфига он
                появится в системе и на странице
                <a href="#routing" style="text-decoration:underline;">Selective routing</a>,
                где можно завернуть в него выбранные устройства / домены / подсети.
                Маршрут по умолчанию не забирается (auto_route выкл.) — что
                заворачивать, решают правила маршрутизации.
            </p>
            <div style="display:grid; grid-template-columns:170px 1fr; gap:8px 12px; align-items:center; max-width:660px;">
                <label class="text-muted">Конфиг</label>
                <select class="form-control" style="max-width:240px;"
                        onchange="SingboxDashboardPage.setTun('config', this.value)">${cfgOpts}</select>

                <label class="text-muted">Имя интерфейса</label>
                <input type="text" class="form-control" style="max-width:200px;"
                       value="${escapeAttr(tunForm.interface_name)}"
                       onchange="SingboxDashboardPage.setTun('interface_name', this.value)">

                <label class="text-muted">Адрес (CIDR)</label>
                <input type="text" class="form-control" style="max-width:200px;"
                       value="${escapeAttr(tunForm.address)}"
                       title="напр. 172.18.0.1/30"
                       onchange="SingboxDashboardPage.setTun('address', this.value)">

                <label class="text-muted">Сетевой стек</label>
                <select class="form-control" style="max-width:280px;"
                        onchange="SingboxDashboardPage.setTun('stack', this.value)">
                    ${opt('system', tunForm.stack, 'system (быстрее, нужен tun ядра)')}
                    ${opt('gvisor', tunForm.stack, 'gvisor (userspace, переносимее)')}
                    ${opt('mixed', tunForm.stack, 'mixed')}
                </select>

                <label class="text-muted">MTU</label>
                <input type="number" class="form-control" style="max-width:120px;"
                       value="${escapeAttr(tunForm.mtu)}"
                       onchange="SingboxDashboardPage.setTun('mtu', this.value)">

                <label class="text-muted">Весь трафик</label>
                <label class="text-muted" style="display:flex; align-items:center; gap:6px;">
                    <input type="checkbox" ${tunForm.auto_route ? 'checked' : ''}
                           onchange="SingboxDashboardPage.setTun('auto_route', this.checked)">
                    auto_route — завернуть ВЕСЬ трафик (вместо выборочной маршрутизации)
                </label>
            </div>
            <div style="margin-top:12px;">
                <button class="btn btn-primary btn-sm"
                        onclick="SingboxDashboardPage.createTunInbound()">Создать TUN-инбаунд</button>
            </div>
        `;
    }

    function setTun(key, value) {
        if (key === 'auto_route') tunForm.auto_route = !!value;
        else if (key === 'mtu') tunForm.mtu = parseInt(value, 10) || 9000;
        else tunForm[key] = value;
    }

    async function createTunInbound() {
        if (!tunForm.config) { Toast.error('Выберите конфиг'); return; }
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(tunForm.config)}/tun-inbound`,
                { interface_name: tunForm.interface_name, address: tunForm.address,
                  stack: tunForm.stack, mtu: tunForm.mtu,
                  auto_route: tunForm.auto_route });
            if (r && r.ok) {
                Toast.success('TUN-инбаунд добавлен в ' + tunForm.config +
                    '. (Пере)запустите конфиг, затем настройте Selective routing.');
                await refresh();
            } else Toast.error((r && r.error) || 'ошибка');
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
        up, down, restart,
        setTp, applyTransparent, removeTransparent, injectInbounds,
        setTun, createTunInbound,
    };
})();
