/**
 * flash.js — «Память (flash)»: износ носителя, объём записи и как писать
 * меньше.
 *
 * Бэкенд: GET /api/flash/status (core/flash_wear.py + core/flash_saver.py),
 * PUT /api/flash/settings, POST /api/flash/action, POST /api/flash/stats/reset.
 */

const FlashPage = (() => {
    let _data = null;
    let _form = null;      // правки настроек до «Сохранить»
    let _timer = null;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Память (flash)</h1>
                <span class="page-subtitle">Износ постоянной памяти роутера, сколько на неё пишется и как писать меньше</span>
            </div>
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Носители и износ
                    <button class="btn btn-ghost btn-sm" id="fl-refresh" style="margin-left:auto;">Обновить</button></div>
                <div class="card-body" id="fl-devices">Загрузка…</div>
            </div>
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Сколько записано</div>
                <div class="card-body" id="fl-writes"></div>
            </div>
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Снизить запись на flash</div>
                <div class="card-body" id="fl-saver"></div>
            </div>
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Что ещё пишет на flash</div>
                <div class="card-body" id="fl-hints"></div>
            </div>
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Кто пишет больше всех</div>
                <div class="card-body" id="fl-top"></div>
            </div>`;
        container.querySelector('#fl-refresh').onclick = () => load(true);
        _form = null;
        await load(true);
        // Счётчики меняются медленно: раз в минуту достаточно.
        _timer = setInterval(() => load(false), 60000);
    }

    function destroy() {
        if (_timer) clearInterval(_timer);
        _timer = null;
    }

    async function load(fresh) {
        try {
            _data = await API.get('/api/flash/status' + (fresh ? '?fresh=1' : ''),
                                  { timeout: 30000 });
        } catch (e) {
            const el = document.getElementById('fl-devices');
            if (el) el.innerHTML = `<div class="note-box err">Не удалось получить данные: ${esc(e.message || e)}</div>`;
            return;
        }
        if (!document.getElementById('fl-devices')) return;
        if (!_form) _form = Object.assign({}, _data.settings || {});
        renderDevices();
        renderWrites();
        renderSaver();
        renderHints();
        renderTop();
    }

    // ══════════════ носители ══════════════

    const LEVEL_COLOR = { ok: 'var(--success)', warn: 'var(--warning)',
                          bad: 'var(--error)', unknown: 'var(--text-muted)' };

    function renderDevices() {
        const el = document.getElementById('fl-devices');
        const devs = (_data && _data.devices) || [];
        if (!devs.length) {
            el.innerHTML = `<div class="note-box warn">Не нашлось ни одной постоянной файловой системы
                на запись — похоже, всё в ОЗУ или /proc/mounts недоступен.</div>`;
            return;
        }
        el.innerHTML = devs.map(deviceHtml).join('');
    }

    function deviceHtml(d) {
        const w = d.wear || {};
        const mounts = (d.mounts || []).map(m =>
            `<code>${esc(m.mnt)}</code> <span class="text-muted">${esc(m.fstype)}${m.noatime ? ', noatime' : ''}</span>`
        ).join(', ');
        const life = (d.mounts || []).filter(m => m.lifetime_written)
            .map(m => `${esc(m.mnt)}: ${fmtBytes(m.lifetime_written)}`).join(', ');
        return `
            <div style="padding:10px 0; border-bottom:1px solid var(--border);">
                <div style="display:flex; gap:8px; align-items:baseline; flex-wrap:wrap;">
                    <b>${esc(d.label)}</b> <code>${esc(d.id)}</code>
                    ${d.model ? `<span class="text-muted">${esc(d.model)}</span>` : ''}
                    ${d.size ? `<span class="text-muted">· ${fmtBytes(d.size)}</span>` : ''}
                </div>
                <div style="font-size:12px; margin:4px 0;">Разделы: ${mounts}</div>
                ${wearHtml(d, w)}
                ${life ? `<div class="text-muted" style="font-size:12px;">Записано файловой системой за всё время её жизни: ${life}</div>` : ''}
            </div>`;
    }

    function wearHtml(d, w) {
        if (w.source === 'emmc') {
            const r = w.percent_range || [0, 0];
            const parts = [];
            if (w.type_a) parts.push(`SLC-область: ${w.type_a.min}–${w.type_a.max} %`);
            if (w.type_b) parts.push(`основная (MLC): ${w.type_b.min}–${w.type_b.max} %`);
            return meter(w.percent, w.level, `Износ ${r[0]}–${r[1]} %`) + `
                <div class="text-muted" style="font-size:12px;">Данные самого чипа eMMC (шаг 10 %): ${parts.join(', ') || '—'}.
                    ${w.pre_eol_text ? 'Резервные блоки: ' + esc(w.pre_eol_text) + '.' : ''}</div>`;
        }
        if (w.source === 'ubi') {
            const bad = w.bad_blocks !== null && w.bad_blocks !== undefined
                ? ` Плохих блоков: ${w.bad_blocks}${w.reserved_for_bad ? ' из резерва ' + w.reserved_for_bad : ''}.` : '';
            return meter(w.percent, w.level, `≈ ${fmtPct(w.percent)} (оценка)`) + `
                <div class="text-muted" style="font-size:12px;">Самый изношенный блок стёрт ${w.max_ec} раз из ~${fmtNum(w.endurance)}
                    (типовой ресурс NAND; задаётся ниже в «Ресурс NAND»). Точного процента NAND не сообщает.${bad}</div>`;
        }
        if (w.source === 'smart') {
            return meter(w.percent, w.level, `Износ ${fmtPct(w.percent)}`) +
                `<div class="text-muted" style="font-size:12px;">По данным SMART${w.attribute ? ' (' + esc(w.attribute) + ')' : ''}.</div>`;
        }
        const why = {
            sd: 'SD-карты не сообщают износ.',
            usb: 'USB-флешки не сообщают износ (SMART у них обычно нет).',
            mtd: 'NOR/MTD-flash без UBI не ведёт счётчиков стирания.',
            ssd: 'Установите smartctl (пакет smartmontools), чтобы увидеть износ SSD.',
            nvme: 'Установите smartctl (пакет smartmontools), чтобы увидеть износ.',
            hdd: 'Жёсткий диск не изнашивается от записи так, как flash.',
            emmc: 'Чип eMMC не сообщает life_time (нужен eMMC 5.0+ и ядро 4.x+).',
        }[d.kind] || 'Носитель не сообщает износ.';
        return `<div class="text-muted" style="font-size:12px; margin:4px 0;">Износ: недоступен. ${why}
            Объём записи всё равно считается — он и есть главный показатель.</div>`;
    }

    function meter(pct, level, label) {
        const p = Math.max(0, Math.min(100, Number(pct) || 0));
        const color = LEVEL_COLOR[level] || LEVEL_COLOR.unknown;
        return `
            <div style="display:flex; align-items:center; gap:10px; margin:6px 0;">
                <div style="flex:1; max-width:320px; height:10px; border-radius:5px; background:var(--border); overflow:hidden;">
                    <div style="width:${Math.max(p, 2)}%; height:100%; background:${color};"></div>
                </div>
                <b style="color:${color};">${esc(label)}</b>
            </div>`;
    }

    // ══════════════ запись ══════════════

    function renderWrites() {
        const el = document.getElementById('fl-writes');
        const devs = ((_data && _data.devices) || []);
        const counted = devs.filter(d => d.writes_supported);
        const t = _data.total;
        let html = '';
        if (t) {
            const boot = counted.reduce((s, d) => s + (d.written_since_boot || 0), 0);
            html += `<div class="status-grid">
                ${tile('Сегодня', fmtBytes(t.today))}
                ${tile('Вчера', fmtBytes(t.yesterday))}
                ${tile('В среднем за сутки', t.avg_day === null ? '—' : fmtBytes(t.avg_day),
                       t.days_counted ? `по ${t.days_counted} полн. дн.` : 'нужны сутки замеров')}
                ${tile('Этот месяц', fmtBytes(t.month))}
                ${tile('Прошлый месяц', fmtBytes(t.prev_month))}
                ${tile('С загрузки роутера', fmtBytes(boot), 'счётчик ядра')}
            </div>
            ${bars(t.series)}`;
            if (counted.length > 1) {
                html += `<table class="table" style="margin-top:12px;"><thead><tr>
                    <th>Носитель</th><th>Сегодня</th><th>Вчера</th><th>Месяц</th><th>30 дней</th></tr></thead><tbody>
                    ${counted.map(d => `<tr><td>${esc(d.label)} <code>${esc(d.id)}</code></td>
                        <td>${fmtBytes(d.writes.today)}</td><td>${fmtBytes(d.writes.yesterday)}</td>
                        <td>${fmtBytes(d.writes.month)}</td><td>${fmtBytes(d.writes.last30)}</td></tr>`).join('')}
                    </tbody></table>`;
            }
        }
        const ubi = devs.filter(d => d.kind === 'ubi' || d.kind === 'mtd');
        ubi.forEach(d => {
            html += `<div class="note-box" style="margin-top:10px;">${esc(d.label)} <code>${esc(d.id)}</code>:
                у «сырого» NAND/NOR ядро не ведёт счётчик записанных байт.`;
            const s = (d.ec_series || []).filter(x => x.max_ec !== null);
            if (d.kind === 'ubi' && s.length > 1) {
                const grow = s[s.length - 1].max_ec - s[0].max_ec;
                html += ` Зато видно, как растёт число стираний худшего блока: +${grow} за ${s.length} дн.`;
            } else if (d.kind === 'ubi') {
                html += ' Рост числа стираний худшего блока появится здесь через пару дней наблюдения.';
            }
            html += `</div>`;
        });
        const since = _data.since ? new Date(_data.since * 1000).toLocaleDateString() : '';
        const fh = _data.stats_flush_hours;
        html += `<div class="text-muted" style="font-size:12px; margin-top:10px;">
            ${since ? `Учёт ведётся с ${esc(since)}. ` : ''}Замер раз в минуту, в ОЗУ;
            на flash статистика сохраняется ${fh > 0 ? `раз в ${fh} ч и при штатной перезагрузке` : 'никогда — после перезагрузки начнётся заново'}.
            <a href="#" id="fl-reset">Обнулить статистику</a></div>`;
        if (!t && !ubi.length) html = `<div class="text-muted">Нет носителей со счётчиком записи.</div>` + html;
        el.innerHTML = html;
        const r = el.querySelector('#fl-reset');
        if (r) r.onclick = async (e) => {
            e.preventDefault();
            if (!confirm('Обнулить накопленную статистику записи?')) return;
            try { await API.post('/api/flash/stats/reset'); Toast.success('Статистика обнулена'); load(false); }
            catch (err) { Toast.error(err.message || String(err)); }
        };
    }

    function tile(label, value, detail) {
        return `<div class="status-card"><div class="status-card-label">${esc(label)}</div>
            <div class="status-card-value">${esc(value)}</div>
            ${detail ? `<div class="status-card-detail">${esc(detail)}</div>` : ''}</div>`;
    }

    function bars(series) {
        if (!series || !series.length) return '';
        const max = Math.max.apply(null, series.map(s => s.bytes)) || 1;
        return `<div style="font-size:12px; color:var(--text-secondary); margin:6px 0;">По дням, последние 30</div>
            <div style="display:flex; align-items:flex-end; gap:2px; height:90px; border-bottom:1px solid var(--border);">
            ${series.map(s => {
                const h = s.bytes ? Math.max(2, Math.round(s.bytes / max * 88)) : 0;
                return `<div title="${esc(s.day)}: ${esc(fmtBytes(s.bytes))}"
                    style="flex:1; min-width:3px; height:${h}px; background:var(--accent); opacity:.8; border-radius:2px 2px 0 0;"></div>`;
            }).join('')}</div>
            <div style="display:flex; justify-content:space-between; font-size:11px;" class="text-muted">
                <span>${esc(series[0].day.slice(5))}</span><span>макс. ${esc(fmtBytes(max))}</span>
                <span>${esc(series[series.length - 1].day.slice(5))}</span></div>`;
    }

    // ══════════════ рычаги ══════════════

    function renderSaver() {
        const el = document.getElementById('fl-saver');
        const f = _form;
        const presets = _data.presets || {};
        const st = _data.state || {};
        const logDir = st.engine_log_dir || {};
        const vm = st.vm || {};
        el.innerHTML = `
            <p class="text-muted" style="margin-top:0;">Готовые наборы заполняют настройки ниже — потом
                можно поправить любую. Ничего не применяется до «Сохранить».</p>
            <div class="choice-grid">${Object.entries(presets).map(([id, p]) => `
                <button class="choice-card ${presetMatches(p) ? 'active' : ''}" data-preset="${esc(id)}">
                    <div class="choice-title">${esc(p.title)}${id === 'economy' ? ' <span class="badge badge-accent">рекомендуем</span>' : ''}</div>
                    <div class="choice-desc">${esc(p.desc)}</div>
                </button>`).join('')}</div>

            <h4 style="margin:16px 0 6px;">ОЗУ вместо flash</h4>
            ${toggle('engine_logs_ram', 'Логи туннелей (AWG, sing-box, mihomo) в ОЗУ',
                logDir.path ? (logDir.ram ? `Сейчас: ${logDir.path} — уже в ОЗУ.` : `Сейчас: ${logDir.path} — на постоянном носителе. Действует со следующего запуска туннеля; после перезагрузки логи пропадают.`) : '')}
            ${toggle('persist_critical', 'Журнал критичных событий на flash',
                'Переживает перезагрузку — помогает понять, почему роутер перезагрузился. Пишет немного.')}
            ${f.persist_critical ? select('persist_min_level', 'Что в него писать',
                [['WARNING', 'предупреждения и ошибки'], ['ERROR', 'только ошибки']]) : ''}
            ${toggle('history_enabled', 'История изменений файлов',
                'Копия настроек и списков при каждом сохранении (для отката). Пишет только когда вы что-то меняете.')}
            ${number('counters_flush_sec', 'Счётчики трафика прокси — на диск не чаще, сек', 2, 86400,
                'Опрос идёт каждые 2 с; при сбое питания теряется не больше этого интервала.')}
            ${number('stats_flush_hours', 'Статистика этого раздела — на flash раз в, ч', 0, 168,
                '0 — только в ОЗУ: после перезагрузки учёт начнётся заново.')}

            <h4 style="margin:16px 0 6px;">Ядро и файловые системы</h4>
            ${toggle('lazy_writeback', 'Отложенная запись: держать изменения в ОЗУ дольше',
                `Повторные записи одного блока сливаются в одну. Сейчас ядро: dirty_expire ${fmtCs(vm.dirty_expire_centisecs)}, writeback ${fmtCs(vm.dirty_writeback_centisecs)}.`)}
            ${f.lazy_writeback ? number('writeback_sec', 'Сколько держать, сек', 30, 600,
                'При внезапной пропаже питания теряется до этого времени последних изменений.') : ''}
            ${toggle('noatime', 'noatime — не записывать время доступа при чтении файлов',
                mountsNote(st.mounts))}
            ${number('ext4_commit_sec', 'Журнал ext4: интервал, сек (0 — не менять)', 0, 600,
                'У ядра 5 с. Больше — меньше записи, но дольше окно потери при сбое питания. Только для ext4.')}
            ${number('nand_endurance', 'Ресурс NAND для оценки износа UBI, циклов (0 — авто)', 0, 10000000,
                'SLC — около 100 000, MLC — около 3 000. Посмотрите в даташите чипа, если знаете модель.')}

            <div class="gen-actions" style="margin-top:12px;">
                <button class="btn btn-primary" id="fl-save">Сохранить и применить</button>
                <button class="btn btn-ghost" id="fl-cancel">Отменить правки</button>
            </div>
            <div id="fl-save-result" style="margin-top:8px;"></div>`;

        el.querySelectorAll('[data-preset]').forEach(b => b.onclick = () => {
            const p = presets[b.dataset.preset];
            Object.assign(_form, p.values || {});
            renderSaver();
        });
        el.querySelectorAll('[data-key]').forEach(inp => inp.onchange = () => {
            const k = inp.dataset.key;
            if (inp.type === 'checkbox') _form[k] = inp.checked;
            else if (inp.type === 'number') _form[k] = Number(inp.value);
            else _form[k] = inp.value;
            if (['persist_critical', 'lazy_writeback'].includes(k) || inp.type === 'checkbox') renderSaver();
        });
        el.querySelector('#fl-save').onclick = save;
        el.querySelector('#fl-cancel').onclick = () => {
            _form = Object.assign({}, _data.settings || {});
            renderSaver();
        };
    }

    function presetMatches(p) {
        return Object.entries(p.values || {}).every(([k, v]) => _form[k] === v);
    }

    function toggle(key, label, hint) {
        return `<div class="form-group" style="margin-bottom:10px;">
            <label style="display:flex; gap:10px; align-items:center; cursor:pointer;">
                <span class="toggle-switch"><input type="checkbox" data-key="${key}" ${_form[key] ? 'checked' : ''}>
                    <span class="toggle-slider"></span></span>
                <span>${esc(label)}</span></label>
            ${hint ? `<div class="form-hint" style="margin-left:54px;">${esc(hint)}</div>` : ''}</div>`;
    }

    function number(key, label, min, max, hint) {
        return `<div class="form-group" style="margin-bottom:10px;">
            <label class="form-label">${esc(label)}</label>
            <input type="number" class="form-input" style="max-width:160px;" data-key="${key}"
                   min="${min}" max="${max}" value="${esc(_form[key] ?? '')}">
            ${hint ? `<div class="form-hint">${esc(hint)}</div>` : ''}</div>`;
    }

    function select(key, label, options) {
        return `<div class="form-group" style="margin-bottom:10px; margin-left:54px;">
            <label class="form-label">${esc(label)}</label>
            <select class="form-input form-select" style="max-width:260px;" data-key="${key}">
                ${options.map(([v, t]) => `<option value="${v}" ${_form[key] === v ? 'selected' : ''}>${esc(t)}</option>`).join('')}
            </select></div>`;
    }

    function mountsNote(mounts) {
        if (!mounts || !mounts.length) return '';
        return 'Сейчас: ' + mounts.map(m => `${m.mnt} — ${m.noatime ? 'noatime' : 'с atime'}` +
            (m.commit ? `, commit=${m.commit}` : '')).join('; ') + '.';
    }

    async function save() {
        const btn = document.getElementById('fl-save');
        const out = document.getElementById('fl-save-result');
        btn.disabled = true;
        try {
            const r = await API.put('/api/flash/settings', _form, { timeout: 60000 });
            _form = null;
            await load(false);
            const box = document.getElementById('fl-save-result');
            if (box) box.innerHTML = resultHtml(r);
        } catch (e) {
            out.innerHTML = `<div class="note-box err">Не сохранилось: ${esc(e.message || e)}</div>`;
        } finally {
            const b = document.getElementById('fl-save');
            if (b) b.disabled = false;
        }
    }

    function resultHtml(r) {
        const applied = (r.applied || []);
        const errors = (r.errors || []);
        return `<div class="note-box ${errors.length ? 'warn' : 'ok'}">Сохранено.
            ${applied.length ? 'Применено: ' + esc(applied.join(', ')) + '.' : ''}
            ${errors.length ? 'Не получилось: ' + esc(errors.join('; ')) + '.' : ''}</div>`;
    }

    // ══════════════ подсказки и «кто пишет» ══════════════

    function renderHints() {
        const el = document.getElementById('fl-hints');
        const hints = _data.hints || [];
        if (!hints.length) {
            el.innerHTML = `<div class="note-box ok">Явных лишних записей не видно.</div>`;
            return;
        }
        const cls = { warn: 'warn', ok: 'ok', info: '' };
        el.innerHTML = hints.map(h => `
            <div class="note-box ${cls[h.level] || ''}" style="margin-bottom:8px;">${esc(h.text)}
                ${h.action ? `<button class="btn btn-sm" style="margin-left:8px;" data-action="${esc(h.action)}">${esc(h.action_label || 'Исправить')}</button>` : ''}
            </div>`).join('');
        el.querySelectorAll('[data-action]').forEach(b => b.onclick = async () => {
            b.disabled = true;
            try {
                await API.post('/api/flash/action', { name: b.dataset.action });
                Toast.success('Готово');
                await load(false);
            } catch (e) {
                Toast.error(e.message || String(e));
                b.disabled = false;
            }
        });
    }

    function renderTop() {
        const el = document.getElementById('fl-top');
        const t = _data.top_writers || {};
        if (!t.supported) {
            el.innerHTML = `<div class="text-muted">Ядро роутера не ведёт учёт ввода-вывода по процессам
                (нет /proc/&lt;pid&gt;/io) — показать, кто пишет, нельзя.</div>`;
            return;
        }
        if (!(t.items || []).length) {
            el.innerHTML = `<div class="text-muted">С момента запуска процессы почти ничего не записали.</div>`;
            return;
        }
        el.innerHTML = `<table class="table"><thead><tr><th>Процесс</th><th>PID</th><th>Записал с запуска</th></tr></thead><tbody>
            ${t.items.map(p => `<tr><td><b>${esc(p.comm)}</b>
                <div class="text-muted" style="font-size:11px; word-break:break-all;">${esc(p.cmd)}</div></td>
                <td>${p.pid}</td><td>${fmtBytes(p.written)}</td></tr>`).join('')}
            </tbody></table>
            <div class="text-muted" style="font-size:12px;">Байты, ушедшие на носители (запись в ОЗУ /tmp сюда не входит),
                с момента старта каждого процесса.</div>`;
    }

    // ══════════════ форматирование ══════════════

    function fmtBytes(n) {
        if (n === null || n === undefined) return '—';
        n = Number(n);
        if (n < 1024) return n + ' Б';
        const u = ['КБ', 'МБ', 'ГБ', 'ТБ'];
        let i = -1;
        do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
        return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
    }

    function fmtPct(p) {
        if (p === null || p === undefined) return '—';
        return (p < 1 ? Number(p).toFixed(2) : Number(p).toFixed(0)) + ' %';
    }

    function fmtNum(n) { return Number(n || 0).toLocaleString('ru-RU'); }

    function fmtCs(cs) { return cs === null || cs === undefined ? '—' : (cs / 100) + ' с'; }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s === null || s === undefined ? '' : String(s);
        return d.innerHTML;
    }

    return { render, destroy };
})();
