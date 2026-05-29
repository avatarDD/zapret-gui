/**
 * help.js — контекстные подсказки по кнопке «?».
 *
 * Help.button('topic')  → HTML маленькой кнопки «?».
 * Help.show('topic')    → модалка с заголовком, описанием и примерами.
 * Help.register(topic, {title, body, examples[]}) — добавить тему.
 *
 * Темы для ключевых элементов GUI зарегистрированы ниже. Кнопки
 * вставляются в заголовки страниц (Маршрутизация, Списки, mihomo,
 * прозрачное проксирование, настройки).
 */

const Help = (() => {

    const topics = {};

    function register(id, data) { topics[id] = data; }

    function button(id, opts) {
        opts = opts || {};
        const label = opts.label || '?';
        return `<button type="button" class="help-btn"
            title="Подсказка"
            onclick="Help.show('${id}')"
            style="display:inline-flex; align-items:center; justify-content:center;
                   width:18px; height:18px; border-radius:50%; border:1px solid var(--border,#444);
                   background:transparent; color:var(--text-secondary,#9ca3af);
                   font-size:12px; cursor:pointer; line-height:1; padding:0; margin-left:6px;">${label}</button>`;
    }

    function show(id) {
        const t = topics[id];
        if (!t) { if (typeof Toast !== 'undefined') Toast.error('Нет подсказки: ' + id); return; }
        close();
        const examplesHtml = (t.examples && t.examples.length)
            ? `<div style="margin-top:12px;">
                 <div style="font-size:12px; color:var(--text-secondary,#9ca3af); margin-bottom:4px;">Примеры:</div>
                 ${t.examples.map(e => `
                    <div style="margin-bottom:8px;">
                        ${e.label ? `<div style="font-size:12px; font-weight:600;">${esc(e.label)}</div>` : ''}
                        <code style="display:block; white-space:pre-wrap; font-family:monospace;
                                     font-size:12px; background:var(--bg-secondary,#1a1a1a);
                                     padding:8px; border-radius:6px; margin-top:2px;">${esc(e.code)}</code>
                    </div>`).join('')}
               </div>`
            : '';
        const overlay = document.createElement('div');
        overlay.id = 'help-overlay';
        overlay.style.cssText = `position:fixed; inset:0; background:rgba(0,0,0,0.5);
            display:flex; align-items:center; justify-content:center; z-index:9999;`;
        overlay.onclick = (ev) => { if (ev.target === overlay) close(); };
        overlay.innerHTML = `
            <div role="dialog" style="background:var(--bg-card,#222); color:var(--text-primary,#eee);
                 max-width:560px; width:92%; max-height:80vh; overflow:auto;
                 border:1px solid var(--border,#444); border-radius:10px; padding:18px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
                    <h3 style="margin:0; font-size:16px;">${esc(t.title || id)}</h3>
                    <button onclick="Help.close()" class="btn btn-ghost btn-sm">✕</button>
                </div>
                <div style="margin-top:10px; font-size:13px; line-height:1.5;">${t.body || ''}</div>
                ${examplesHtml}
            </div>`;
        document.body.appendChild(overlay);
        document.addEventListener('keydown', _onKey);
    }

    function close() {
        const o = document.getElementById('help-overlay');
        if (o) o.remove();
        document.removeEventListener('keydown', _onKey);
    }

    function _onKey(e) { if (e.key === 'Escape') close(); }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    // ─────── контент подсказок ───────

    register('routing', {
        title: 'Маршрутизация: назначение → метод',
        body: 'Для каждого «назначения» (домены, IP/CIDR, общий список, ' +
              'geosite/geoip) выберите «метод» — через что пустить трафик: ' +
              '<b>direct</b> (напрямую), <b>nfqws2</b> (обход DPI на месте) ' +
              'или туннель (<b>awg:/singbox:/mihomo:</b>). Можно задать ' +
              'резервную цепочку (fallback) и включить мониторинг + ' +
              'авто-переключение при деградации.',
        examples: [
            { label: 'YouTube через туннель, при сбое — nfqws2',
              code: 'Домены: youtube.com, googlevideo.com\nМетод: awg:awg0\nFallback: nfqws2, direct' },
            { label: 'Категория geosite через sing-box',
              code: 'geosite: google\nМетод: singbox:tun0' },
        ],
    });

    register('lists', {
        title: 'Списки (общие)',
        body: 'Именованные списки доменов и IP/CIDR. Один список можно ' +
              'переиспользовать в нескольких маршрутах и как hostlist для ' +
              'nfqws2. Записи распознаются автоматически: домен → в домены, ' +
              'IP/подсеть → в CIDR.',
        examples: [
            { label: 'Содержимое списка', code: 'youtube.com\ngooglevideo.com\n1.2.3.0/24\n2606:4700::/32' },
        ],
    });

    register('transparent', {
        title: 'Прозрачное проксирование',
        body: 'Заворачивает трафик клиентов (и опц. самого роутера) в ' +
              'sing-box без настройки на клиентах. <b>TProxy</b> — TCP+UDP ' +
              '(нужен модуль ядра), <b>Redirect</b> — только TCP (самый ' +
              'совместимый), <b>Hybrid</b> — TCP redirect + UDP tproxy. ' +
              'Не забудьте добавить соответствующий inbound в конфиг ' +
              '(кнопка «Добавить inbound\'ы»).',
        examples: [
            { label: 'Типичный выбор для роутера', code: 'Режим: tproxy\nTCP-порт: 1100\nIPv6: глушить (anti-leak)\nТрафик роутера: выкл' },
        ],
    });

    register('dscp', {
        title: 'DSCP / QoS маршрутизация',
        body: 'Маршрутизирует трафик с заданной DSCP-меткой в туннель. ' +
              'Метку ставит штатный QoS роутера (Keenetic IntelliQoS, ' +
              'OpenWrt SQM/qosify). Полезно, например, отправить весь ' +
              'realtime-трафик (EF) через отдельный канал.',
        examples: [
            { label: 'Realtime через WARP', code: 'DSCP: 46 (EF)\nТуннель: awg-warp-1' },
        ],
    });

    register('mihomo', {
        title: 'mihomo (Clash.Meta)',
        body: 'Альтернативный прокси-движок рядом с sing-box. Конфиги в ' +
              'формате clash-YAML. Установка тянет бинарь из апстрим-релизов ' +
              'MetaCubeX/mihomo (работает и через зеркало, если GitHub ' +
              'заблокирован — см. Настройки → Установка).',
        examples: [
            { label: 'Минимальный конфиг',
              code: 'mixed-port: 7890\nproxies:\n  - name: vpn\n    type: vless\n    server: example.com\n    port: 443\n    uuid: ...\nrules:\n  - MATCH,vpn' },
        ],
    });

    register('mirror', {
        title: 'Зеркало для загрузки',
        body: 'Если github.com заблокирован, укажите зеркало — GitHub-' +
              'прокси, которое проксирует ссылки (схема ghproxy). Применяется ' +
              'ко всем загрузкам бинарников (sing-box, mihomo, nfqws2, AWG). ' +
              'Можно задать и через переменную окружения ZAPRET_GUI_MIRROR.',
        examples: [
            { label: 'Значение поля', code: 'https://ghproxy.example' },
            { label: 'Оффлайн (локальный файл) — через ENV', code: 'ZAPRET_GUI_MIRROR не нужен;\nустановщик примет file:///opt/cache/sing-box.tar.gz' },
        ],
    });

    return { register, button, show, close, topics };
})();
