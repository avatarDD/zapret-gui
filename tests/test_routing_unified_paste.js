/**
 * test_routing_unified_paste.js — разбор ввода в форме маршрута.
 *
 * «Вставить список» раскладывает смешанный текст по полям (как импорт
 * правил MagiTrickle с автоопределением типа), а поле «Домены» не режет
 * regexp:-шаблоны по запятым и пробелам — они часть выражения.
 */

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SRC = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'js', 'pages', 'routing_unified.js'),
    'utf8');

function loadPage() {
    const sandbox = { console, document: {}, window: {}, location: { hash: '' } };
    vm.createContext(sandbox);
    vm.runInContext(SRC + '\nthis.RoutingUnifiedPage = RoutingUnifiedPage;',
                    sandbox);
    return sandbox.RoutingUnifiedPage;
}

test('classify: домены, подсети, geosite/geoip — по своим полям', () => {
    const page = loadPage();
    const out = page._classifyEntries([
        'youtube.com, googlevideo.com',
        '1.2.3.0/24',
        '2001:db8::/32',
        '8.8.8.8',
        'geosite:Google',
        'geoip:ru  # комментарий',
        'https://www.example.org/path',
        'regexp:^r[0-9]{1,3}\\.cdn\\.net$',
        'cdn*.x.com',
    ].join('\n'));
    assert.deepStrictEqual(Array.from(out.domains), [
        'youtube.com', 'googlevideo.com', 'www.example.org',
        'regexp:^r[0-9]{1,3}\\.cdn\\.net$', 'cdn*.x.com']);
    assert.deepStrictEqual(Array.from(out.cidrs),
                           ['1.2.3.0/24', '2001:db8::/32', '8.8.8.8']);
    assert.deepStrictEqual(Array.from(out.geosite), ['google']);
    assert.deepStrictEqual(Array.from(out.geoip), ['ru']);
});

test('splitDomains: regexp-строка целиком, остальное — по разделителям', () => {
    const page = loadPage();
    assert.deepStrictEqual(
        Array.from(page._splitDomains('a.com b.com\nregexp:^x{1,2}, y$\nc.org;d.org')),
        ['a.com', 'b.com', 'regexp:^x{1,2}, y$', 'c.org', 'd.org']);
});
