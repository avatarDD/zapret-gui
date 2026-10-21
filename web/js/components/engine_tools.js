/**
 * engine_tools.js — общая обвязка AmneziaWG, sing-box и mihomo в GUI.
 *
 * Один компонент на три дашборда, чтобы обвязка движков выглядела и
 * работала одинаково (бэкенд — core/engine_common.py, api/engine_wrapper.py):
 *   - карточка «Лимит памяти Go» (GOGC/GOMEMLIMIT) — /api/<engine>/go-memory;
 *   - окно лога инстанса — /api/<engine>/configs/<name>/log;
 *   - окно диагностики sing-box/mihomo — /api/<engine>/configs/<name>/diagnostics
 *     (у AWG своя, подробная, но с тем же блоком «Обвязка» — wrapperLines);
 *   - переключатель режима отладки — /api/<engine>/debug;
 *   - строка состояния init-скрипта автозапуска с кнопками.
 *
 * Использование:
 *   EngineTools.mountGoMemory('awg-go-memory', 'awg');
 *   EngineTools.showLog('mihomo', 'home');
 *   EngineTools.showDiagnostics('singbox', 'vless');
 *   await EngineTools.setDebug('awg', true);
 *   EngineTools.autostartLineHtml('singbox', status, 'SingboxDashboardPage.refresh')
 */
const EngineTools = (() => {

    const LABELS = { awg: 'AmneziaWG', singbox: 'sing-box', mihomo: 'mihomo' };
    // Как называется сам процесс — для подписей карточки памяти.
    const PROCESS = { awg: 'amneziawg-go', singbox: 'sing-box', mihomo: 'mihomo' };

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function cfgUrl(engine, name, tail) {
        return `/api/${engine}/configs/${encodeURIComponent(name)}${tail || ''}`;
    }

    // ══════════════ окно с текстом (лог, диагностика) ══════════════

    /**
     * Окно с моноширинным текстом и кнопками «Копировать» / «Обновить» /
     * «Закрыть». reload — async () => text: «Обновить» перечитывает.
     */
    function textModal(title, text, reload, opts) {
        // tail: открыть в конце (лог — свежее внизу); диагностика — с начала,
        // там сводка.
        const tail = !!(opts && opts.tail);
        const overlay = document.createElement('div');
        overlay.className = 'modal-backdrop';
        const box = document.createElement('div');
        box.className = 'modal-content';
        box.style.cssText = 'max-width:1000px; display:flex; flex-direction:column; overflow:hidden;';
        box.innerHTML = `
            <div style="padding:12px 16px; border-bottom:1px solid var(--border);
                        display:flex; justify-content:space-between; align-items:center; gap:12px;">
                <strong style="font-size:14px;">${esc(title)}</strong>
                <div style="display:flex; gap:8px;">
                    ${reload ? '<button class="btn btn-ghost btn-sm" data-act="reload">↻ Обновить</button>' : ''}
                    <button class="btn btn-ghost btn-sm" data-act="copy">⧉ Копировать</button>
                    <button class="btn btn-ghost btn-sm" data-act="close">Закрыть</button>
                </div>
            </div>
            <pre style="margin:0; padding:14px 16px; overflow:auto; flex:1;
                        background:var(--bg-input); font-size:12px; line-height:1.5;
                        white-space:pre-wrap; word-break:break-word;"></pre>`;
        const pre = box.querySelector('pre');
        let current = text;
        const show = (t) => {
            current = t;
            pre.textContent = t;
            pre.scrollTop = tail ? pre.scrollHeight : 0;
        };
        show(text);
        const close = () => {
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
            document.removeEventListener('keydown', onKey);
            window.removeEventListener('hashchange', close);
        };
        const onKey = (e) => { if (e.key === 'Escape') close(); };
        // Окно висит на body: без этого оно переживало бы переход на
        // другую страницу SPA и закрывало её собой.
        window.addEventListener('hashchange', close);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
        box.querySelector('[data-act="close"]').onclick = close;
        box.querySelector('[data-act="copy"]').onclick = () =>
            Clipboard.copyWithToast(current);
        if (reload) {
            box.querySelector('[data-act="reload"]').onclick = async () => {
                try { show(await reload()); } catch (e) { Toast.error(e.message); }
            };
        }
        document.addEventListener('keydown', onKey);
        overlay.appendChild(box);
        document.body.appendChild(overlay);
        return { close, show };
    }

    // ══════════════ лог инстанса ══════════════

    async function logText(engine, name) {
        const r = await API.get(cfgUrl(engine, name, '/log?lines=300'));
        if (!r || !r.ok) return (r && r.error) || 'не удалось прочитать лог';
        if (!r.exists) {
            return engine === 'awg'
                ? 'Лог демона ещё не создан. amneziawg-go пишет его только в '
                  + 'режиме отладки: включите «Отладка» и перезапустите туннель.'
                : 'Лог ещё не создан — запустите конфиг.';
        }
        return (r.debug ? '[режим отладки]\n' : '') + (r.log || '(пусто)');
    }

    async function showLog(engine, name) {
        let text;
        try { text = await logText(engine, name); }
        catch (e) { Toast.error(e.message); return; }
        textModal(`Лог ${LABELS[engine] || engine}: ${name}`, text,
                  () => logText(engine, name), { tail: true });
    }

    // ══════════════ диагностика ══════════════

    function kb(n) {
        if (n == null) return '?';
        return n >= 1024 ? (n / 1024).toFixed(1) + ' МБ' : n + ' КБ';
    }

    function duration(sec) {
        if (sec == null) return '?';
        if (sec < 60) return sec + ' с';
        if (sec < 3600) return Math.floor(sec / 60) + ' мин';
        if (sec < 86400) return Math.floor(sec / 3600) + ' ч ' + Math.floor(sec % 3600 / 60) + ' мин';
        return Math.floor(sec / 86400) + ' дн ' + Math.floor(sec % 86400 / 3600) + ' ч';
    }

    /** Строки «процесс / отладка / лимит памяти / автозапуск» — общий
     *  блок диагностики всех трёх движков. */
    function wrapperLines(process, wrapper) {
        const lines = [];
        const p = process || {};
        const w = wrapper || {};
        if (p.pid) {
            lines.push('process:  pid ' + p.pid + '  RSS ' + kb(p.rss_kb)
                       + ' (пик ' + kb(p.rss_peak_kb) + ')  потоков '
                       + (p.threads == null ? '?' : p.threads)
                       + '  работает ' + duration(p.uptime_sec));
        } else {
            lines.push('process:  не запущен');
        }
        const gm = w.go_memory || {};
        lines.push('debug:    ' + (w.debug ? 'вкл' : 'выкл'));
        lines.push('go-mem:   ' + (gm.enabled
            ? 'GOGC=' + (gm.gogc || 'не задан') + ' GOMEMLIMIT='
              + (gm.memlimit_mb ? gm.memlimit_mb + 'MiB' : 'не задан')
            : 'выкл'));
        if (w.autostart != null) lines.push('autostart: ' + (w.autostart ? 'да' : 'нет'));
        return lines;
    }

    function formatDiagnostics(d) {
        const lines = [];
        const push = (label, val) => {
            lines.push('── ' + label + ' ──');
            lines.push(val == null || val === '' ? '(пусто)' : String(val).trimEnd());
            lines.push('');
        };
        const b = d.binary || {};
        const c = d.config || {};
        const chk = d.config_check || {};
        const ctl = d.controller || {};
        lines.push('zapret-gui ' + (LABELS[d.engine] || d.engine) + ' diagnostics');
        lines.push('gui_ver:  ' + (d.gui_version || '?'));
        lines.push('config:   ' + (d.name || '') + (c.exists
            ? '  (' + c.path + ', ' + c.size + ' байт)' : '  (файла нет)'));
        lines.push('active:   ' + (d.active ? 'yes' : 'no'));
        lines.push('binary:   ' + (b.installed ? (b.version || '?') + '  ' + (b.path || '')
                                              : 'не установлен'));
        lines.push('check:    ' + (chk.ok === true ? 'ok ✓'
                                  : chk.ok === false ? 'ОШИБКА ✗' : 'не выполнялась'));
        if (chk.output) lines.push('  → ' + chk.output);
        wrapperLines(d.process, d.wrapper).forEach(l => lines.push(l));
        if (d.wrapper && d.wrapper.go_env && Object.keys(d.wrapper.go_env).length) {
            lines.push('go-env:   ' + Object.entries(d.wrapper.go_env)
                .map(([k, v]) => k + '=' + v).join(' '));
        }
        if (ctl.configured) {
            lines.push('controller: ' + (ctl.endpoint || '?') + '  '
                + (ctl.reachable === true ? 'отвечает ✓' + (ctl.version ? ' (' + ctl.version + ')' : '')
                   : ctl.reachable === false ? 'НЕ отвечает ✗ ' + (ctl.error || '')
                   : 'не опрашивался (инстанс не запущен)'));
        } else {
            lines.push('controller: не настроен (тест/трафик/переключение узла через движок недоступны)');
        }
        if (d.dns_in_port) lines.push('dns-in:   порт ' + d.dns_in_port + ' (FakeIP-перехват :53)');
        if (d.mode) lines.push('mode:     ' + d.mode);
        if (d.debug_launch_config) lines.push('launch:   отладочный launch-конфиг .run-' + d.name + '.yaml');
        if (d.errors && d.errors.length) lines.push('errors:   ' + d.errors.join('; '));
        lines.push('');
        if (d.tun && d.tun.iface) push('TUN ' + d.tun.iface, d.tun.addr || '(инстанс не запущен)');
        push('log tail (' + (d.log_path || '') + ')', d.log_tail);
        if (d.gui_log_tail && d.gui_log_tail.length) {
            lines.push('── GUI log (' + d.engine + ', упоминания ' + d.name + ') ──');
            d.gui_log_tail.forEach(e => {
                const ts = e.timestamp ? new Date(e.timestamp * 1000).toISOString() : '?';
                lines.push('[' + ts + '] ' + (e.level || '') + ' ' + (e.message || ''));
            });
        }
        return lines.join('\n');
    }

    async function diagnosticsText(engine, name) {
        const r = await API.get(cfgUrl(engine, name, '/diagnostics'), { timeout: 30000 });
        if (!r || !r.ok) throw new Error((r && r.error) || 'Ошибка диагностики');
        return formatDiagnostics(r.diagnostics || {});
    }

    async function showDiagnostics(engine, name) {
        let text;
        try { text = await diagnosticsText(engine, name); }
        catch (e) { Toast.error(e.message); return; }
        textModal(`Диагностика ${LABELS[engine] || engine}: ${name}`, text,
                  () => diagnosticsText(engine, name));
    }

    // ══════════════ режим отладки ══════════════

    async function setDebug(engine, on) {
        try {
            const r = await API.post(`/api/${engine}/debug`, { enabled: !!on });
            if (r && r.ok) {
                Toast.success(`Режим отладки ${r.enabled ? 'включён' : 'выключен'} — `
                              + 'применится при следующем запуске');
                return !!r.enabled;
            }
            Toast.error((r && r.error) || 'не удалось');
        } catch (e) { Toast.error(e.message); }
        return null;
    }

    // ══════════════ лимит памяти Go ══════════════

    const goMem = {};    // containerId -> {engine, state}

    async function mountGoMemory(containerId, engine) {
        goMem[containerId] = { engine, state: null };
        try {
            const r = await API.get(`/api/${engine}/go-memory`);
            goMem[containerId].state = (r && r.ok) ? r : null;
        } catch (_) { /* карточка покажет умолчания */ }
        renderGoMemory(containerId);
    }

    function renderGoMemory(containerId) {
        const box = document.getElementById(containerId);
        const entry = goMem[containerId];
        if (!box || !entry) return;
        const s = entry.state || {};
        const on = !!s.enabled;
        const proc = PROCESS[entry.engine] || entry.engine;
        const id = (k) => `${containerId}-${k}`;
        const when = entry.engine === 'awg' ? 'подъёме туннеля' : 'запуске инстанса';
        box.innerHTML = `
            <div class="card-title">Лимит памяти ${esc(proc)}</div>
            <label style="display:flex; align-items:center; gap:8px; margin-top:8px; cursor:pointer;">
                <input type="checkbox" id="${id('on')}" ${on ? 'checked' : ''}
                       onchange="EngineTools.saveGoMemory('${containerId}')">
                <span>Ограничивать память ${esc(proc)}</span>
            </label>
            <p class="text-muted" style="font-size:12px; margin:6px 0 0;">
                ${esc(proc)} написан на Go и на роутере с малым ОЗУ может
                разрастаться до нехватки памяти — частая причина внезапной
                перезагрузки. Лимит (GOGC/GOMEMLIMIT) удерживает потребление
                в рамках. Применяется при следующем ${when}.
            </p>
            <div style="margin-top:10px; ${on ? '' : 'display:none;'}">
                <div style="display:grid; grid-template-columns:240px 1fr; gap:6px 12px; max-width:560px; align-items:center;">
                    <label class="text-muted" style="font-size:12px;" for="${id('gogc')}">GOGC (меньше = экономнее, чаще GC; 0 = не задавать)</label>
                    <input type="number" id="${id('gogc')}" class="form-control" style="max-width:100px;"
                           min="0" max="1000" value="${esc(s.gogc != null ? s.gogc : 50)}">
                    <label class="text-muted" style="font-size:12px;" for="${id('mb')}">GOMEMLIMIT, МиБ (0 = не задавать)</label>
                    <input type="number" id="${id('mb')}" class="form-control" style="max-width:100px;"
                           min="0" max="16384" value="${esc(s.memlimit_mb != null ? s.memlimit_mb : 64)}">
                </div>
                <div style="margin-top:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="EngineTools.saveGoMemory('${containerId}')">Сохранить параметры</button>
                </div>
            </div>`;
    }

    async function saveGoMemory(containerId) {
        const entry = goMem[containerId];
        if (!entry) return;
        const val = (k) => (document.getElementById(`${containerId}-${k}`) || {});
        const on = !!val('on').checked;
        const payload = { enabled: on };
        const gogc = val('gogc').value;
        const mb = val('mb').value;
        if (gogc !== undefined && gogc !== '') payload.gogc = parseInt(gogc, 10) || 0;
        if (mb !== undefined && mb !== '') payload.memlimit_mb = parseInt(mb, 10) || 0;
        try {
            const r = await API.post(`/api/${entry.engine}/go-memory`, payload);
            if (r && r.ok) {
                entry.state = r;
                Toast.success(on ? 'Лимит памяти сохранён — применится при следующем запуске'
                                 : 'Лимит памяти выключен');
                renderGoMemory(containerId);
            } else {
                Toast.error((r && r.error) || 'ошибка');
            }
        } catch (e) { Toast.error(e.message); }
    }

    // ══════════════ init-скрипт автозапуска ══════════════

    /**
     * Строка «скрипт: установлен / устарел / нет» с кнопками. st — ответ
     * /api/<engine>/autostart (.status): script_installed, script_path,
     * up_to_date. refreshFn — имя глобальной функции перерисовки страницы.
     */
    function autostartLineHtml(engine, st, refreshFn) {
        st = st || {};
        const count = Object.values(st.autostart || st.interfaces || {}).filter(Boolean).length;
        let state;
        if (!st.script_installed) {
            state = '<span class="text-muted">не установлен</span>';
        } else if (st.up_to_date === false) {
            state = '<span style="color:#fb8;" title="Скрипт старого образца: при загрузке может поднять не все конфиги">устарел</span>';
        } else {
            state = '<span class="text-running">установлен</span>';
        }
        const path = st.script_path
            ? ` <span class="text-muted" style="font-size:11px;">(${esc(st.script_path)})</span>` : '';
        const btn = (act, label) =>
            `<button class="btn btn-ghost btn-sm" onclick="EngineTools.autostartAction('${engine}', '${act}', ${refreshFn})">${label}</button>`;
        // У AWG установка — отдельный роут (/autostart/install), у
        // sing-box/mihomo её делает regenerate (если есть отмеченные).
        const install = engine === 'awg' ? 'install' : 'regenerate';
        const buttons = st.script_installed
            ? btn('regenerate', 'Пересоздать скрипт') + btn('remove', 'Удалить скрипт')
            : (count ? btn(install, 'Установить init-скрипт')
                     : `<button class="btn btn-ghost btn-sm" disabled
                                title="Включите автозапуск хотя бы у одного конфига">Установить init-скрипт</button>`);
        return `
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; font-size:13px;">
                <span>Автозапуск: ${count} конф., скрипт: ${state}${path}</span>
                ${buttons}
            </div>`;
    }

    async function autostartAction(engine, act, refresh) {
        if (act === 'remove' && !confirm(`Удалить init-скрипт автозапуска ${LABELS[engine] || engine}?`)) return;
        try {
            const r = await API.post(`/api/${engine}/autostart/${act}`);
            if (!r || !r.ok) {
                Toast.error((r && r.error) || 'ошибка');
            } else if (act === 'remove' || (act === 'regenerate' && engine !== 'awg' && !r.names)) {
                // regenerate у sing-box/mihomo без отмеченных конфигов
                // скрипт снимает, а не пишет.
                Toast.success(r.noop ? 'Скрипта и не было' : 'Скрипт удалён');
            } else {
                Toast.success(r.message || 'Скрипт записан');
            }
        } catch (e) { Toast.error(e.message); }
        if (typeof refresh === 'function') await refresh();
    }

    return {
        esc, textModal, showLog, showDiagnostics, formatDiagnostics, wrapperLines,
        setDebug, mountGoMemory, saveGoMemory,
        autostartLineHtml, autostartAction,
    };
})();
