/**
 * test_geneva_auto_page.js — карточка «Авто» на странице geneva
 * (web/js/pages/geneva.js, секция auto).
 *
 * Страница поднимается так же, как в index.html: словари, i18n,
 * исходник страницы — в `node:vm` поверх мини-DOM и подменённого API.
 * Проверяется то, ради чего карточка есть:
 *   - выключенный режим так и показан, включённый — фаза, сводка и
 *     сервисы с цветным статусом, тексты из i18n (ru и en);
 *   - включение: ответ need_confirm → подтверждение человека → повтор
 *     с confirm:true; отказ в подтверждении — второго запроса нет;
 *   - кнопка «Сбросить» шлёт ключ сервиса;
 *   - «Сохранить»/«Авто» с пустым числовым полем не отправляет его
 *     вовсе (сервер не меняет пропущенную настройку), заполненные —
 *     уходят как есть; после перерисовки поля заново заполняются
 *     с сервера, а не остаются со значениями шаблона.
 */

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const WEB = path.join(__dirname, '..', 'web', 'js');

function makeElement(id) {
    const handlers = {};
    return {
        id, innerHTML: '', textContent: '', style: {}, dataset: {},
        checked: false, value: '',
        handlers,
        addEventListener(ev, fn) { (handlers[ev] = handlers[ev] || []).push(fn); },
        querySelectorAll() { return []; },
        closest() { return null; },
        focus() {}, setSelectionRange() {},
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    };
}

const AUTO_ON = {
    ok: true, enabled: true, running: true, phase: 'searching',
    counts: { applied: 1, searching: 1, ip_blocked: 1 }, total: 5,
    connections: 120,
    services: [
        { key: 'dns:93.184.216.53', name: 'DNS 93.184.216.53',
          status: 'applied', why: 'обход работает',
          strategy: '[UDP:dport:53]-tamper{DNS:qd:compress}-| \\/' },
        { key: 'web:blocked.example', name: 'blocked.example',
          status: 'searching', why: 'подбор', strategy: null },
    ],
    groups: [{ queue: 340, strategy: 'S', services: ['dns:x'],
               targets: ['93.184.216.53 tcp 53 udp 53'],
               stats: { pkts_out: 10, pkts_in: 5, triggered: 3 },
               rate: { pkts_out: 1, pkts_in: 0.5 } }],
    search: { running: true, key: 'web:blocked.example',
              name: 'blocked.example', strategy: '[TCP:flags:PA]-drop-| \\/' },
    problems: [], journal: [{ ts: 1, level: 'info', text: 'режим включён' }],
};

function makeSandbox({ auto, found, lists, suggest, lang = 'ru',
                       confirm = true, enableFails = true }) {
    const elements = new Map();
    const calls = { get: [], post: [], confirm: 0 };
    const document = {
        hidden: false,
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, makeElement(id));
            return elements.get(id);
        },
        addEventListener() {}, removeEventListener() {},
    };
    const sandbox = {
        console, document,
        window: { location: { origin: 'http://192.168.1.1:8080' } },
        localStorage: { getItem: () => lang, setItem() {} },
        setInterval: () => 1, clearInterval: () => {},
        setTimeout: () => 1, clearTimeout: () => {},
        API: {
            get(url) {
                calls.get.push(url);
                if (url === '/api/geneva/auto/lists') {
                    return Promise.resolve(lists || { ok: true });
                }
                if (url === '/api/geneva/auto/workers-suggest') {
                    return Promise.resolve(suggest ||
                        { ok: true, workers: 4, cpu: 4,
                          mem_available_mb: 205 });
                }
                if (url.startsWith('/api/geneva/auto')) return Promise.resolve(auto);
                if (url === '/api/geneva/found') return Promise.resolve(found || { ok: true, items: [] });
                if (url === '/api/geneva/status') {
                    return Promise.resolve({ ok: true, detect: {}, engine: {}, search: {} });
                }
                return Promise.resolve({ ok: true });
            },
            post(url, body) {
                calls.post.push([url, body]);
                if (url === '/api/geneva/auto/enable' && enableFails && !(body && body.confirm)) {
                    const e = new Error('need confirm');
                    e.data = { ok: false, error_code: 'need_confirm' };
                    return Promise.reject(e);
                }
                return Promise.resolve({ ok: true });
            },
        },
        Toast: { success() {}, error() {}, info() {}, warning() {} },
        Confirm: { show: () => { calls.confirm++; return Promise.resolve(confirm); } },
        // Выбор версии релиза (components/setup_ui.js) в песочницу не
        // грузим: страница зовёт его на верхнем уровне, а тестировать
        // здесь — поведение «Авто», не селектор версий.
        InstallExtras: {
            create() {
                return {
                    optionsHtml: () => '',
                    installBody: () => ({}),
                    selectedTag: () => '',
                    loadTransports: () => Promise.resolve(),
                    loadReleases: () => Promise.resolve(),
                    onTagChange() {}, onTransportChange() {},
                };
            },
        },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    for (const rel of ['i18n/ru.js', 'i18n/en.js', 'utils/i18n.js', 'pages/geneva.js']) {
        vm.runInContext(fs.readFileSync(path.join(WEB, rel), 'utf8'), sandbox, { filename: rel });
    }
    vm.runInContext('globalThis.__page = GenevaPage;', sandbox);
    return { sandbox, elements, calls, page: sandbox.__page };
}

async function renderAuto(env) {
    const container = makeElement('root');
    await env.page.render(container, { sections: ['auto'] });
    return container;
}

const tick = () => new Promise(r => setImmediate(r));

test('выключенный режим', async () => {
    const env = makeSandbox({ auto: { ok: true, enabled: false, problems: [] } });
    const root = await renderAuto(env);
    assert.match(root.innerHTML, /Авто: обход всего, что заблокировано/);
    assert.match(root.innerHTML, /Включите и больше ничего не настраивайте/);
    assert.match(env.elements.get('gv-auto').innerHTML, /Режим «Авто» выключен/);
    assert.strictEqual(env.elements.get('gv-auto-toggle').checked, false);
});

test('включённый: фаза, сводка, сервисы и группы', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    await renderAuto(env);
    const html = env.elements.get('gv-auto').innerHTML;
    assert.match(html, /подбирает стратегию/);
    assert.match(html, /Сервисов: 5 · обход работает: 1 · в работе: 1 · без обхода: 1 · соединений в последнем срезе: 120/);
    assert.match(html, /badge-success">обход работает/);
    assert.match(html, /пробую: \[TCP:flags:PA\]-drop-\| \\\//);
    assert.match(html, /data-auto-act="reset" data-key="dns:93.184.216.53"/);
    assert.match(html, /data-auto-act="check" data-key="dns:93.184.216.53"/);
    assert.match(html, /<th>Важность<\/th>/);
    assert.match(html, /очередь 340/);
    assert.match(html, /Работающие стратегии \(1\)/);
    assert.match(html, /режим включён/);
    assert.strictEqual(env.elements.get('gv-auto-toggle').checked, true);
});

test('английский', async () => {
    const env = makeSandbox({ auto: AUTO_ON, lang: 'en' });
    const root = await renderAuto(env);
    assert.match(root.innerHTML, /Auto: bypass everything that is blocked/);
    assert.match(env.elements.get('gv-auto').innerHTML, /bypassed/);
});

test('включение с подтверждением', async () => {
    const env = makeSandbox({ auto: { ok: true, enabled: false, problems: [] } });
    await renderAuto(env);
    const toggle = env.elements.get('gv-auto-toggle');
    toggle.checked = true;
    toggle.handlers.change[0]();
    for (let i = 0; i < 5; i++) await tick();
    const posts = env.calls.post.filter(p => p[0] === '/api/geneva/auto/enable');
    assert.strictEqual(env.calls.confirm, 1);
    assert.strictEqual(posts.length, 2);
    // объекты из другого контекста vm: сравниваем по JSON
    assert.strictEqual(JSON.stringify(posts[1][1]), '{"confirm":true}');
});

test('отказ от подтверждения — второго запроса нет', async () => {
    const env = makeSandbox({ auto: { ok: true, enabled: false, problems: [] }, confirm: false });
    await renderAuto(env);
    const toggle = env.elements.get('gv-auto-toggle');
    toggle.checked = true;
    toggle.handlers.change[0]();
    for (let i = 0; i < 5; i++) await tick();
    const posts = env.calls.post.filter(p => p[0] === '/api/geneva/auto/enable');
    assert.strictEqual(posts.length, 1);
});

test('сброс сервиса', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const btn = { dataset: { autoReset: 'web:blocked.example' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    assert.strictEqual(JSON.stringify(env.calls.post.at(-1)),
                       '["/api/geneva/auto/reset",{"key":"web:blocked.example"}]');
});

test('меню «⋯»: действия над сервисом', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const click = async (act) => {
        const btn = { dataset: { autoAct: act, key: 'dns:93.184.216.53' } };
        await root.handlers.click[0]({ target: { closest: () => btn } });
        for (let i = 0; i < 3; i++) await tick();
        return JSON.stringify(env.calls.post.at(-1));
    };
    assert.strictEqual(await click('check'),
        '["/api/geneva/auto/check-now",{"key":"dns:93.184.216.53"}]');
    assert.strictEqual(await click('important'),
        '["/api/geneva/auto/priority",{"key":"dns:93.184.216.53","value":"important"}]');
    assert.strictEqual(await click('pin'),
        '["/api/geneva/auto/pin",{"key":"dns:93.184.216.53","pinned":true}]');
    assert.strictEqual(await click('nosearch'),
        '["/api/geneva/auto/no-search",{"key":"dns:93.184.216.53"}]');
});

test('фильтр и стабильный порядок', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    await renderAuto(env);
    const box = env.elements.get('gv-auto');
    const order = () => [...box.innerHTML.matchAll(/<td title="([^"]+)"/g)].map(m => m[1]);
    assert.deepStrictEqual(order(), ['dns:93.184.216.53', 'web:blocked.example']);
    const filter = env.elements.get('gv-auto-filter');
    filter.value = 'blocked';
    filter.handlers.input[0]();
    assert.deepStrictEqual(order(), ['web:blocked.example']);
    filter.value = '';
    filter.handlers.input[0]();
    assert.deepStrictEqual(order(), ['dns:93.184.216.53', 'web:blocked.example']);
});

test('списки: сохранение', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    env.elements.get('gv-list-important').value = 'youtube.com\nAS12389';
    env.elements.get('gv-list-exclude').value = 'bank.example';
    env.elements.get('gv-list-byname').checked = true;
    const btn = { dataset: { action: 'auto-lists' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    for (let i = 0; i < 3; i++) await tick();
    const post = env.calls.post.find(p => p[0] === '/api/geneva/auto/lists');
    assert.ok(post);
    const body = JSON.parse(JSON.stringify(post[1]));
    assert.strictEqual(body.important, 'youtube.com\nAS12389');
    assert.strictEqual(body.exclude, 'bank.example');
    assert.strictEqual(body.by_name, true);
    assert.strictEqual(body.split_workers, false);
});

test('подборов меньше, чем задано: причина видна в карточке', async () => {
    // одна группа занята подбором, остальные — работающими стратегиями:
    // сводка обязана объяснить это рядом с фазой, а не только в
    // свёрнутом блоке списков
    const env = makeSandbox({
        auto: Object.assign({}, AUTO_ON, {
            split_workers: true, search_slots: 1, search_slots_wanted: 4,
        }),
    });
    await renderAuto(env);
    assert.match(env.elements.get('gv-auto').innerHTML,
        /Сейчас подборов идёт 1 из 4/);
});

test('отметки сервисов отдельно от списков', async () => {
    const env = makeSandbox({
        auto: AUTO_ON,
        lists: { ok: true, important: [], unimportant: [],
                 marked: { important: [{ service: 'web:a.example',
                                         name: 'a.example' }],
                           unimportant: [] } },
    });
    const root = await renderAuto(env);
    assert.ok(root.innerHTML.includes('gv-list-marked'));
    // раскрыли списки — данные с сервера
    env.sandbox.document.getElementById('gv-auto-lists');
    const marked = env.elements.get('gv-list-marked');
    assert.match(marked.textContent, /a\.example/);
    assert.match(marked.textContent, /Отмечены важными \(меню строки\): a\.example/);
    // в текстовом поле «Важно» отметки не появляются: это разные вещи
    assert.strictEqual(env.elements.get('gv-list-important').value, '');
});

test('отметка из меню обновляет и строку, и списки', async () => {
    // «Важно» в меню ⋯ — отметка сервиса в книге, а не строка списка:
    // форма списков не должна показывать устаревшее после нажатия
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const btn = { dataset: { autoAct: 'important', key: 'dns:93.184.216.53' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    for (let i = 0; i < 3; i++) await tick();
    const post = env.calls.post.find(p => p[0] === '/api/geneva/auto/priority');
    assert.ok(post, 'запрос важности ушёл');
    assert.ok(env.calls.get.filter(u => u === '/api/geneva/auto/lists').length >= 2,
        'списки перезапрошены после отметки');
});

const FOUND = {
    ok: true, auto_enabled: false, working: '',
    items: [
        { strategy: '[TCP:flags:PA]-fragment{tcp:34:True:17}-| \\/', auto: true,
          services: [{ name: 'youtube.com' }, { name: 'x.com' }], targets: [],
          degraded: 0, fitness: 396, last: 1700000000, working: false },
        { strategy: '[TCP:flags:PA]-fragment{tcp:-1:False}-| \\/', auto: false,
          services: [], targets: ['rutor.info'], degraded: 0, fitness: 398,
          last: 0, working: true },
    ],
};

test('вкладка «Стратегии»: только рабочие, библиотека — по раскрытию', async () => {
    const env = makeSandbox({ auto: { ok: true, enabled: false }, found: FOUND });
    const root = await (async () => {
        const c = makeElement('root');
        await env.page.render(c, { sections: ['found', 'library'] });
        return c;
    })();
    assert.match(root.innerHTML, /Рабочие стратегии/);
    assert.match(root.innerHTML, /Готовые стратегии geneva_c/);
    assert.ok(!env.calls.get.includes('/api/geneva/library'),
              'библиотека не грузится, пока блок свёрнут');
    const html = env.elements.get('gv-found').innerHTML;
    assert.match(html, /fragment\{tcp:34:True:17\}/);
    assert.match(html, /«Авто»: 2/);
    assert.match(html, /youtube\.com/);
    assert.match(html, /подбор: rutor\.info/);
    assert.match(html, /badge-accent">рабочая/);
    // «Сделать рабочей» — у нерабочей, у рабочей кнопки нет
    assert.strictEqual((html.match(/data-use=/g) || []).length, 1);
    assert.strictEqual((html.match(/data-copy=/g) || []).length, 2);
});

const NO_NFLOG = Object.assign({}, AUTO_ON, {
    detector: { running: false, supported: true, reason: 'no_nflog',
                problem: 'детектор geneva не работает' },
    problems: ['детектор geneva не работает: в ядре нет модуля NFLOG '
               + '(nfnetlink_log) — режим работает без подозрений по потокам'],
});

test('детектор без NFLOG: кнопка установки модуля (OpenWrt)', async () => {
    const env = makeSandbox({ auto: Object.assign({}, NO_NFLOG, {
        nflog_fix: { can_auto_install: true, platform: 'openwrt',
                     pkg_manager: 'apk',
                     command: 'apk update && apk add kmod-nfnetlink-log' } }) });
    const root = await renderAuto(env);
    const html = env.elements.get('gv-auto').innerHTML;
    assert.match(html, /нет модуля NFLOG/);
    assert.match(html, /data-auto-act="nflog"/);
    assert.match(html, /Установить модуль NFLOG/);
    // кнопка в общей ловушке кликов: POST на установку модуля.
    // Клик не ждём: опрос статуса крутится на setTimeout, который в этой
    // песочнице — заглушка, и промис установки не завершится никогда.
    const btn = { dataset: { autoAct: 'nflog' } };
    const before = env.calls.post.length;
    root.handlers.click[0]({ target: { closest: () => btn } });
    for (let i = 0; i < 3; i++) await tick();
    assert.ok(env.calls.post.slice(before).some(p => p[0] === '/api/diagnostics/nflog-deps/install'),
              JSON.stringify(env.calls.post));
});

test('детектор без NFLOG: на Keenetic вместо кнопки инструкция', async () => {
    const env = makeSandbox({ auto: Object.assign({}, NO_NFLOG, {
        nflog_fix: { can_auto_install: false, platform: 'keenetic',
                     instructions: 'Детектор geneva отключится сам — '
                                   + 'остальной режим «Авто» работает и без него.' } }) });
    await renderAuto(env);
    const html = env.elements.get('gv-auto').innerHTML;
    assert.match(html, /нет модуля NFLOG/);
    assert.ok(!/data-auto-act="nflog"/.test(html), 'кнопки на Keenetic нет');
    assert.match(html, /работает и без него/);
});

test('вкладка «Стратегии»: пусто', async () => {
    const env = makeSandbox({ auto: { ok: true, enabled: false } });
    const c = makeElement('root');
    await env.page.render(c, { sections: ['found'] });
    assert.match(env.elements.get('gv-found').innerHTML, /Рабочих стратегий пока нет/);
});
test('кнопка «Авто» у числа потоков: советует, но не сохраняет', async () => {
    const env = makeSandbox({
        auto: AUTO_ON,
        suggest: { ok: true, workers: 6, cpu: 2, mem_available_mb: 180 },
    });
    const root = await renderAuto(env);
    const before = env.calls.post.length;
    const btn = { dataset: { action: 'auto-workers-tune' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    for (let i = 0; i < 5; i++) await tick();
    assert.ok(env.calls.get.includes('/api/geneva/auto/workers-suggest'),
              JSON.stringify(env.calls.get));
    // поле заполнено советом…
    assert.strictEqual(+env.elements.get('gv-auto-workers').value, 6);
    // …но тихого сохранения нет: решение остаётся за «Сохранить»
    assert.strictEqual(env.calls.post.length, before,
        'авто-подбор не должен сам писать настройки, ' +
        JSON.stringify(env.calls.post));
});

test('галочки режима переехали в карточку из свёрнутых списков', async () => {
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const html = root.innerHTML;
    // все три — до блока списков, то есть видны без раскрытия
    const details = html.indexOf('<details');
    for (const id of ['gv-list-byname', 'gv-list-split', 'gv-list-final']) {
        const at = html.indexOf('id="' + id + '"');
        assert.ok(at > -1 && at < details, id + ' должен быть в карточке');
    }
    // карточная кнопка «Сохранить» уносит и их (песочница не читает
    // атрибут checked из HTML — ставим руками, как в тесте списков)
    env.elements.get('gv-list-byname').checked = true;
    env.elements.get('gv-list-final').checked = true;
    const btn = { dataset: { action: 'auto-settings' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    for (let i = 0; i < 3; i++) await tick();
    const post = env.calls.post.find(p => p[0] === '/api/geneva/auto/settings');
    assert.ok(post, JSON.stringify(env.calls.post));
    const body = JSON.parse(JSON.stringify(post[1]));
    assert.strictEqual(body.by_name, true);
    assert.strictEqual(body.split_workers, false);
    assert.strictEqual(body.final_check, true);
});

test('работающие стратегии: имена, адреса — в подсказке', async () => {
    const env = makeSandbox({
        auto: Object.assign({}, AUTO_ON, {
            groups: [{ queue: 340, profile: 'p1', strategy: 'S1',
                       services: ['web:a.example'],
                       names: ['a.example'], targets: ['1.2.3.4:443 tcp'],
                       stats: {}, rate: {} }],
        }),
    });
    await renderAuto(env);
    const html = env.elements.get('gv-auto').innerHTML;
    assert.match(html, /1 · a\.example/);
    assert.match(html, /title="1\.2\.3\.4:443 tcp"/);
});

test('профили geneva 2.0: в карточке имя профиля, а не общая очередь', async () => {
    const env = makeSandbox({
        auto: Object.assign({}, AUTO_ON, {
            groups: [
                { queue: 340, profile: 'p1-tcp-X1', strategy: 'S1',
                  services: ['web:a'], targets: ['1.1.1.1'],
                  stats: { flows: 2, pkts_out: 4, pkts_in: 2 } },
                { queue: 340, profile: 'p2-tcp-X2', strategy: 'S2',
                  services: ['web:b'], targets: ['2.2.2.2'],
                  stats: { flows: 1, pkts_out: 3, pkts_in: 1 } },
            ],
        }),
    });
    await renderAuto(env);
    const text = env.elements.get('gv-auto').innerHTML;
    assert.match(text, /p1-tcp-X1/);
    assert.match(text, /p2-tcp-X2/);
});

test('«Сохранить» с пустыми полями не отправляет числа', async () => {
    // Регрессия: пустое поле уходило как null, сервер тогда отвечал
    // «max_groups: целое от 1 до 8» (предел давно уже 64) и не
    // сохранял ничего.
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const btn = { dataset: { action: 'auto-settings' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    const posts = env.calls.post.filter(p => p[0] === '/api/geneva/auto/settings');
    assert.strictEqual(posts.length, 1);
    const body = posts[0][1];
    assert.strictEqual('workers' in body, false);
    assert.strictEqual('max_groups' in body, false);
});

test('«Авто» с пустым полем групп сохраняет только потоки', async () => {
    // Сценарий из баг-репорта: «Авто» подобрал потоки, поле групп
    // пустое — «Сохранить» должно сохранить потоки, не ругаясь на
    // группы (пустое поле не отправляется вовсе).
    const env = makeSandbox({ auto: AUTO_ON });
    const root = await renderAuto(env);
    const tune = { dataset: { action: 'auto-workers-tune' } };
    await root.handlers.click[0]({ target: { closest: () => tune } });
    for (let i = 0; i < 5; i++) await tick();
    assert.strictEqual(+env.elements.get('gv-auto-workers').value, 4);
    const btn = { dataset: { action: 'auto-settings' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    const posts = env.calls.post.filter(p => p[0] === '/api/geneva/auto/settings');
    assert.strictEqual(posts.length, 1);
    assert.strictEqual(posts[0][1].workers, 4);
    assert.strictEqual('max_groups' in posts[0][1], false);
});

test('заполненные поля сохраняются как есть', async () => {
    const auto = Object.assign({}, AUTO_ON,
        { workers: 5, max_groups: 3, help_tunnels: true });
    const env = makeSandbox({ auto });
    const root = await renderAuto(env);
    assert.strictEqual(String(env.elements.get('gv-auto-workers').value), '5');
    assert.strictEqual(String(env.elements.get('gv-auto-groups').value), '3');
    const btn = { dataset: { action: 'auto-settings' } };
    await root.handlers.click[0]({ target: { closest: () => btn } });
    const posts = env.calls.post.filter(p => p[0] === '/api/geneva/auto/settings');
    assert.strictEqual(posts.length, 1);
    assert.strictEqual(posts[0][1].workers, 5);
    assert.strictEqual(posts[0][1].max_groups, 3);
    assert.strictEqual(posts[0][1].help_tunnels, true);
});

test('повторная отрисовка заново заполняет поля с сервера', async () => {
    // До исправления отметка «поля уже заполнены» не сбрасывалась при
    // перерисовке: карточка показывала значения шаблона, и «Сохранить»
    // молча понижал настроенное раньше.
    const auto = Object.assign({}, AUTO_ON, { workers: 5, max_groups: 3 });
    const env = makeSandbox({ auto });
    await renderAuto(env);
    const w = env.elements.get('gv-auto-workers');
    const g = env.elements.get('gv-auto-groups');
    // перерисовка пересоздала поля со значениями шаблона
    w.value = '';
    g.value = '';
    await renderAuto(env);
    assert.strictEqual(String(w.value), '5');
    assert.strictEqual(String(g.value), '3');
});
