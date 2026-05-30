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
        body: 'Главная страница маршрутизации. Для каждого «назначения» ' +
              '(домены, IP/CIDR, общий список, geosite/geoip) выберите ' +
              '«метод» — через что пустить трафик: <b>direct</b> (напрямую), ' +
              '<b>nfqws2</b> (обход DPI на месте) или туннель ' +
              '(<b>awg:/singbox:/mihomo:</b>). Можно задать резервную ' +
              'цепочку (fallback) и включить мониторинг + авто-переключение ' +
              'при деградации.<br><br>' +
              '<b>Чем отличается от «AmneziaWG → AWG-правила»?</b> Та ' +
              'страница — низкоуровневые правила конкретно для AWG-туннелей ' +
              '(ip rule/ipset/dnsmasq/NDMS, CIDR/домены/устройства/DSCP). ' +
              'Здесь — единый высокоуровневый слой поверх всех движков. ' +
              'Начинайте отсюда; «AWG-правила» — для тонкой ручной настройки.',
        examples: [
            { label: 'YouTube через туннель, при сбое — nfqws2',
              code: 'Домены: youtube.com, googlevideo.com\nМетод: awg:awg0\nFallback: nfqws2, direct' },
            { label: 'Категория geosite через sing-box',
              code: 'geosite: google\nМетод: singbox:tun0' },
        ],
    });

    register('lists', {
        title: 'Списки маршрутизации',
        body: 'Именованные списки доменов и IP/CIDR <b>для страницы ' +
              '«Маршрутизация»</b> (единый слой). Один список можно ' +
              'переиспользовать в нескольких маршрутах. Записи ' +
              'распознаются автоматически: домен → в домены, IP/подсеть → ' +
              'в CIDR.<br><br>' +
              '<b>Чем отличается от «Домены» и «IP-списки»?</b><br>' +
              '• <b>Списки маршрутизации</b> (эта страница) — для единого ' +
              'слоя «назначение → метод», домены и IP вместе.<br>' +
              '• <b>Домены (nfqws2)</b> — hostlist-файлы именно для nfqws2 ' +
              '(какие хосты обходить на месте).<br>' +
              '• <b>IP-списки</b> — ipset\'ы (наборы IP в ядре) для ' +
              'firewall-правил nfqws2.',
        examples: [
            { label: 'Содержимое списка', code: 'youtube.com\ngooglevideo.com\n1.2.3.0/24\n2606:4700::/32' },
        ],
    });

    register('awgrules', {
        title: 'AWG-правила (расширенное)',
        body: 'Низкоуровневые правила маршрутизации <b>конкретно для ' +
              'AmneziaWG-туннелей</b>: CIDR, домены (через dnsmasq+ipset/' +
              'nftset), устройства (по MAC/IP), DSCP. На Keenetic — через ' +
              'NDMS-политики. Это «ручной» уровень.<br><br>' +
              'Для обычного выбора «куда → через что» используйте страницу ' +
              '<b>Маршрутизация</b> — она проще и охватывает все движки.',
    });

    register('domains', {
        title: 'Домены (nfqws2)',
        body: 'Hostlist-файлы для nfqws2 — списки доменов, к которым ' +
              'применяется обход DPI. Это не то же, что «Списки ' +
              'маршрутизации» (те — для туннелей/единого слоя).',
        examples: [
            { label: 'Формат hostlist', code: 'youtube.com\n*.googlevideo.com\ndiscord.com' },
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

    register('strategies', {
        title: 'Стратегии nfqws2',
        body: 'Стратегия — набор аргументов nfqws2 для обхода DPI. ' +
              'Встроенные (из каталогов) и пользовательские. Выберите и ' +
              'примените; «Превью» покажет итоговую команду. Кнопка ' +
              '«Обновить стратегии» тянет свежие каталоги из ' +
              'youtubediscord/zapret. Если не знаете, что выбрать — ' +
              'запустите «Подбор стратегий».',
    });

    register('scan', {
        title: 'Подбор стратегий',
        body: 'Автоматически перебирает стратегии против выбранного домена ' +
              'и находит рабочие. Укажите цель (напр. youtube.com), протокол ' +
              'и режим (quick/standard/full). Найденные рабочие стратегии ' +
              'можно применить в один клик.',
        examples: [
            { label: 'Типовая цель', code: 'youtube.com (TCP/TLS + QUIC)' },
        ],
    });

    register('blockcheck', {
        title: 'BlockCheck',
        body: 'Проверяет доступность сервисов и классифицирует тип ' +
              'блокировки: на уровне IP (нужен туннель), DPI/SNI (поможет ' +
              'nfqws2) или DNS. Поле <code>remediation</code> подсказывает, ' +
              'каким методом обходить.',
    });

    register('ipsets', {
        title: 'IP-списки (ipset)',
        body: 'Наборы IP-адресов/подсетей в ядре (ipset), на которые ' +
              'ссылаются firewall-правила nfqws2. Поддерживается загрузка ' +
              'по ASN. Не путать со «Списками маршрутизации» (те — для ' +
              'туннелей/единого слоя).',
    });

    register('awg', {
        title: 'AmneziaWG — туннели',
        body: 'Дашборд WireGuard/AmneziaWG-туннелей: статус интерфейсов и ' +
              'peer\'ов, up/down/restart, автозапуск, трафик. Конфиги — на ' +
              'вкладке «Конфиги», установка бинарников — «Установка», ' +
              'Cloudflare WARP — «WARP».',
    });

    register('control', {
        title: 'Управление nfqws2',
        body: 'Запуск/остановка/рестарт процесса nfqws2 и мониторинг его ' +
              'состояния. Аргументы задаются применённой стратегией ' +
              '(страница «Стратегии»).',
    });

    register('diagnostics', {
        title: 'Диагностика',
        body: 'Проверки сети: ping, HTTP/HTTPS, DNS, поиск конфликтов ' +
              '(другие процессы на NFQUEUE/портах), состояние системы. ' +
              'Помогает понять, почему обход не работает.',
    });

    register('autostart', {
        title: 'Автозапуск',
        body: 'Управление init-скриптом, который поднимает nfqws2 (и, при ' +
              'необходимости, туннели/правила) после перезагрузки роутера. ' +
              'Включите, чтобы настройки переживали ребут.',
    });

    register('zapret', {
        title: 'Zapret2 (установка nfqws2)',
        body: 'Установка/обновление бинарника nfqws2 (движок обхода DPI) из ' +
              'GitHub bol-van/zapret. При заблокированном GitHub поможет ' +
              'зеркало (Настройки → Установка).',
    });

    register('failover', {
        title: 'Автопереключение метода (failover)',
        body: 'Если включить галку <b>«Автопереключение метода при ' +
              'сбоях»</b> у маршрута, система периодически проверяет ' +
              'доступность назначения через текущий метод и, при ' +
              'устойчивой деградации, сама переключается на следующий ' +
              'метод из <b>резервной цепочки (fallback)</b> — например ' +
              '<code>awg:awg0 → singbox:tun0 → nfqws2 → direct</code>. ' +
              'Есть гистерезис и cooldown, чтобы не «дёргало».<br><br>' +
              'Галка <b>«только следить»</b> — мониторит и показывает ' +
              'успешность, но метод не меняет (вы переключаете вручную).' +
              '<br><br>Любая из галок сама поднимает фоновую проверку — ' +
              'отдельно включать мониторинг не требуется. По умолчанию обе ' +
              'выключены (никаких автодействий, пока вы их не включите).',
        examples: [
            { label: 'Маршрут с failover',
              code: 'Назначение: youtube.com\nМетод: awg:awg0\nFallback: nfqws2, direct\n☑ Автопереключение метода при сбоях' },
        ],
    });

    register('watchdog', {
        title: 'Авто-переподключение (watchdog)',
        body: 'Следит за качеством связи через AmneziaWG-туннель и сам ' +
              'перезапускает его при деградации. Два критерия: устаревший ' +
              'WireGuard-handshake и (если включена галка) <b>активная ' +
              'проба</b> — TCP-коннект к проверочному хосту прямо через ' +
              'туннель (SO_BINDTODEVICE). Несколько неудач подряд → ' +
              'тихий restart туннеля.<br><br>' +
              'Зачем: amneziawg-go иногда «зависает» — сайты тормозят, ' +
              'потом сеть отваливается, а ручной рестарт всё чинит. ' +
              'Watchdog делает это автоматически. Есть лимит рестартов/час; ' +
              'если он исчерпан — туннель помечается нездоровым (стоит ' +
              'сменить конфиг/прокси или включить failover на nfqws2 в ' +
              '«Маршрутизации»).',
        examples: [
            { label: 'Параметры по умолчанию',
              code: 'Хост проверки: 1.1.1.1:443\nНеудач подряд → рестарт: 2\nТаймаут handshake: 180 c' },
        ],
    });

    register('backup', {
        title: 'Бэкап / восстановление',
        body: 'Скачайте всю конфигурацию (настройки, стратегии, конфиги ' +
              'sing-box/mihomo, hostlist\'ы) в один JSON-файл и восстановите ' +
              'из него при переустановке/переносе. Параметры Web-GUI ' +
              '(адрес/порт/доступ) восстанавливаются только по отдельной ' +
              'галочке.',
    });

    return { register, button, show, close, topics };
})();
