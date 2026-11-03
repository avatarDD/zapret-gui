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
 *   - кнопка «Сбросить» шлёт ключ сервиса.
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

function makeSandbox({ auto, lang = 'ru', confirm = true, enableFails = true }) {
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
                if (url.startsWith('/api/geneva/auto')) return Promise.resolve(auto);
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
    assert.match(html, /data-auto-reset="dns:93.184.216.53"/);
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
