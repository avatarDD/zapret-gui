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
              'запустите «Подбор стратегий».<br><br>' +
              '<b>Проверить (dry-run)</b> в окне превью валидирует стратегию ' +
              'через <code>nfqws2 --dry-run</code>: движок разбирает параметры ' +
              'и прогоняет lua-init, НЕ поднимая NFQUEUE и не трогая трафик. ' +
              'Ловит вызовы несуществующих lua-функций, битые ' +
              '<code>--blob</code>/<code>--lua-init</code> и кривой синтаксис ' +
              '<code>--lua-desync</code> ещё до применения.<br><br>' +
              '<b>Авто-оркестратор (circular).</b> Стратегии с ' +
              '<code>--lua-desync=circular</code> сами перебирают приёмы per-host ' +
              'и запоминают рабочий. При их применении автоматически ' +
              'подключаются companion-скрипты (детекторы, группировка доменов, ' +
              'учёт результатов) — их видно в «Превью» как дополнительные ' +
              '<code>--lua-init</code>. Отдельно включать ничего не нужно: ' +
              'достаточно выбрать circular-стратегию из каталога.<br><br>' +
              '<b>Порт и протокол.</b> Порт задаёт firewall (NFQUEUE по ' +
              '<code>nfqws.ports_tcp/udp</code>), а протокол ограничивает ' +
              '<code>--payload</code> (<code>tls_client_hello</code>/' +
              '<code>http_req</code>/<code>quic_initial</code>). В профиле ' +
              'желательно явно задавать <code>--filter-tcp/--filter-udp</code> + ' +
              '<code>--filter-l7</code> — они должны согласовываться с портами ' +
              'firewall. Кнопка <b>«+ фильтр…»</b> в редакторе вставляет готовый ' +
              'набор (TCP 443·TLS, TCP 80·HTTP, UDP 443·QUIC). Если вставить ' +
              '«голый» приём (<code>--lua-desync=…</code> без фильтра), он будет ' +
              'автоматически ограничен — итог видно в «Превью команды».',
    });

    register('blockcheck2', {
        title: 'BlockCheck2 (официальный)',
        body: 'Запускает ШТАТНЫЙ скрипт <code>blockcheck2.sh</code> из ' +
              'zapret2 (bol-van) как есть и стримит его вывод (телеметрию) ' +
              'в реальном времени. Подбирает рабочую стратегию средствами ' +
              'самого zapret2 (BATCH-режим, без интерактивных вопросов). Это ' +
              '«эталон» — в отличие от BlockCheck(mod), который перебирает наш ' +
              'каталог.<br><br>' +
              'Сверху телеметрии «примораживаются» <b>только найденные рабочие ' +
              'стратегии</b> (строки <code>working strategy found … : &lt;движок ' +
              'параметры&gt;</code>) и секции <code>* SUMMARY</code> / ' +
              '<code>* COMMON</code> (стратегии, рабочие сразу для всех целей). ' +
              'Попытки <code>UNAVAILABLE code=NN</code> и отдельные ' +
              '<code>AVAILABLE</code> в шапку не выносятся — только в общий лог.' +
              '<br><br>' +
              '<b>Качать полное тело (обход блока по ~20КБ)</b> — выставляет ' +
              '<code>CURL_HTTPS_GET=1</code>: HTTPS-проба тянет всё тело сайта ' +
              '(GET) вместо заголовков (HEAD/<code>-I</code>). Нужно, когда DPI ' +
              'пускает первые ~16-20 КБ и затем рвёт соединение (curl выдаёт ' +
              '<code>code=28</code> — таймаут): без полного тела такой блок не ' +
              'виден и стратегия ложно считается рабочей.<br><br>' +
              '<b>Параметры скрипта (env).</b> Передаются через расширенные ' +
              'поля «Доп. переменные окружения» (<code>KEY=VALUE</code>):' +
              '<br>• <code>DOMAINS</code> — домены (по умолч. rutracker.org); ' +
              '<code>IPVS</code> — версии IP (4 / 6 / 46);' +
              '<br>• <code>ENABLE_HTTP</code>, <code>ENABLE_HTTPS_TLS12</code>, ' +
              '<code>ENABLE_HTTPS_TLS13</code>, <code>ENABLE_HTTP3</code> — какие ' +
              'протоколы проверять (0/1);' +
              '<br>• <code>HTTP_PORT</code>=80, <code>HTTPS_PORT</code>=443, ' +
              '<code>QUIC_PORT</code>=443 — порты;' +
              '<br>• <code>SCANLEVEL</code> — quick / standard / force (глубина ' +
              'перебора); <code>REPEATS</code> — повторов на тест (фильтр ' +
              'нестабильных); <code>PARALLEL</code>=1 — параллельный прогон;' +
              '<br>• <code>CURL_MAX_TIME</code>=2, <code>CURL_MAX_TIME_QUIC</code>, ' +
              '<code>CURL_MAX_TIME_DOH</code>=2 — таймауты curl (сек); ' +
              '<code>CURL_HTTPS_GET</code>=1 — GET вместо HEAD (см. выше); ' +
              '<code>CURL_VERBOSE</code>=1 — подробный curl;' +
              '<br>• <code>SKIP_PKTWS</code> — не тестировать pkt-движок (nfqws2); ' +
              '<code>SKIP_IPBLOCK</code> — пропустить проверку блока по IP; ' +
              '<code>SKIP_DNSCHECK</code> — пропустить проверку подмены DNS;' +
              '<br>• <code>UNBLOCKED_DOM</code>=iana.org — эталонный незаблок. ' +
              'домен; <code>SECURE_DNS</code> — использовать DoH при спуфинге ' +
              'DNS; <code>DOH_SERVERS</code>, <code>DNSCHECK_DNS</code> — списки ' +
              'серверов.<br>' +
              'Полный перечень — в шапке самого <code>blockcheck2.sh</code>.<br><br>' +
              '<b>Создать стратегию из находки.</b> Над телеметрией найденные ' +
              'рабочие приёмы показываются кликабельными бейджами. Клик ' +
              'открывает редактор создания стратегии, предзаполненный этим ' +
              'приёмом: <code>--lua-desync</code> переносится дословно, а ' +
              '<code>--filter-*</code>/<code>--payload</code> выводятся из типа ' +
              'теста (HTTP/TLS/QUIC) — ровно тот протокол и порт, что проверял ' +
              'blockcheck2. Остаётся при желании добавить <code>--hostlist</code>.',
        examples: [
            { label: 'Типовая цель', code: 'rutracker.org, IP=4, SCANLEVEL=standard' },
            { label: 'Обход блока по 20КБ', code: 'CURL_HTTPS_GET=1 (галка «Качать полное тело»)' },
            { label: 'TTL-диапазон (доп. env)', code: 'MIN_TTL=1\nMAX_TTL=12' },
        ],
    });

    register('scan', {
        title: 'BlockCheck(mod) — подбор стратегий',
        body: 'Наш собственный (модифицированный) подбор: перебирает ' +
              'стратегии из каталога zapret-gui против выбранного домена и ' +
              'находит рабочие. Укажите цель (напр. youtube.com), протокол ' +
              'и режим (quick/standard/full). Найденные стратегии можно ' +
              'применить в один клик. Эталонный аналог — «BlockCheck2 ' +
              '(официальный)», который гоняет штатный blockcheck2.sh.',
        examples: [
            { label: 'Типовая цель', code: 'youtube.com (TCP/TLS + QUIC)' },
        ],
    });

    register('blockcheck', {
        title: 'Тестирование доступности',
        body: 'Проверяет доступность сервисов и классифицирует тип ' +
              'блокировки: на уровне IP (нужен туннель), DPI/SNI (поможет ' +
              'nfqws2) или DNS. Поле <code>remediation</code> подсказывает, ' +
              'каким методом обходить. Это НЕ подбор стратегий — для подбора ' +
              'см. «BlockCheck2 (официальный)» / «BlockCheck(mod)».',
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
