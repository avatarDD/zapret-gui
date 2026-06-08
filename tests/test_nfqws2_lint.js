/**
 * test_nfqws2_lint.js — node-тесты для редактора стратегий nfqws2.
 *
 * Проверяют «мозги» IDE-редактора: справочник (nfqws2_spec) и
 * анализатор/линтер (nfqws2_lint) — токенизация, диагностика ошибок,
 * документация под курсором, анализ структуры.
 *
 * Запуск:  node tests/test_nfqws2_lint.js
 */
'use strict';

const assert = require('assert');
const path = require('path');

const Spec = require(path.join(__dirname, '..', 'web', 'js', 'utils', 'nfqws2_spec.js'));
const Lint = require(path.join(__dirname, '..', 'web', 'js', 'utils', 'nfqws2_lint.js'));
const Syntax = require(path.join(__dirname, '..', 'web', 'js', 'utils', 'syntax.js'));

// Снять html-теги и развернуть сущности — получить «видимый» текст слоя.
function stripHtml(html) {
    return html.replace(/<[^>]*>/g, '')
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>').replace(/&quot;/g, '"')
        .replace(/​/g, '');
}

let passed = 0;
function test(name, fn) {
    try { fn(); passed++; }
    catch (e) { console.error('FAIL: ' + name + '\n  ' + (e && e.message)); process.exitCode = 1; }
}
const errs = (r) => r.diagnostics.filter(d => d.severity === 'error');
const warns = (r) => r.diagnostics.filter(d => d.severity === 'warn');

// ──────────────── Spec ────────────────

test('spec: знает базовые флаги и функции nfqws2', () => {
    assert.ok(Spec.isKnownFlag('--filter-tcp'));
    assert.ok(Spec.isKnownFlag('--lua-desync'));
    assert.ok(Spec.isKnownFlag('--payload'));
    assert.ok(Spec.isKnownFunc('fake'));
    assert.ok(Spec.isKnownFunc('multisplit'));
    assert.ok(Spec.isKnownFunc('circular'));
});

test('spec: nfqws1 НЕ поддерживается', () => {
    assert.ok(!Spec.isKnownFlag('--dpi-desync'));
    assert.ok(!Spec.isKnownFlag('--dpi-desync-split-pos'));
});

test('spec: subargsFor(fake) включает blob + fooling-группу + orch-маркеры', () => {
    const sa = Spec.subargsFor('fake');
    assert.ok(sa.blob, 'есть blob');
    assert.ok(sa.tcp_md5, 'есть tcp_md5 (из fooling)');
    assert.ok(sa.ip_autottl, 'есть ip_autottl (из fooling)');
    assert.strictEqual(sa.strategy.kind, 'orch', 'strategy — оркестрационный маркер');
});

test('spec: circular знает detector/success/hostkey и их значения', () => {
    const sa = Spec.subargsFor('circular');
    assert.ok(sa.failure_detector);
    assert.ok(Spec.valuesForSubargType('lua-failure').indexOf('z2k_mid_stream_stall') >= 0);
    assert.ok(Spec.valuesForSubargType('lua-hostkey').indexOf('z2k_nohost_key') >= 0);
});

// ──────────────── Tokenize ────────────────

test('lint: токенизация сохраняет позиции', () => {
    const toks = Lint.tokenize('--filter-tcp=443 --lua-desync=fake');
    assert.strictEqual(toks.length, 2);
    assert.strictEqual(toks[0].start, 0);
    assert.strictEqual(toks[1].raw, '--lua-desync=fake');
});

// ──────────────── Diagnostics: ошибки ────────────────

test('lint: неизвестный флаг = ошибка', () => {
    const r = Lint.analyze('--filtr-tcp=443');
    assert.strictEqual(errs(r).length, 1);
    assert.ok(/неизвестный флаг/.test(errs(r)[0].message));
});

test('lint: legacy nfqws1 флаг = ошибка с подсказкой', () => {
    const r = Lint.analyze('--dpi-desync=fake');
    assert.ok(errs(r).length >= 1);
    assert.ok(/nfqws1/.test(errs(r)[0].message));
});

test('lint: неизвестная desync-функция = ошибка', () => {
    const r = Lint.analyze('--lua-desync=fakezzz');
    assert.ok(errs(r).some(d => /неизвестная desync-функция/.test(d.message)));
});

test('lint: --filter-tcp без значения = ошибка', () => {
    const r = Lint.analyze('--filter-tcp');
    assert.ok(errs(r).some(d => /требует значение/.test(d.message)));
});

test('lint: голый токен (незакавыченный пробел) = ошибка', () => {
    const r = Lint.analyze('--lua-desync=luaexec:code=a b');
    assert.ok(errs(r).some(d => /не похоже на параметр/.test(d.message)));
});

// ──────────────── Diagnostics: предупреждения ────────────────

test('lint: неверный порт = предупреждение', () => {
    const r = Lint.analyze('--filter-tcp=abc');
    assert.ok(warns(r).some(d => /порт/.test(d.message)));
});

test('lint: неизвестный sub-param функции = предупреждение', () => {
    const r = Lint.analyze('--lua-desync=fake:blobz=x');
    assert.ok(warns(r).some(d => /неизвестный параметр/.test(d.message)));
});

test('lint: неверный payload в csv = предупреждение', () => {
    const r = Lint.analyze('--payload=tls_client_hello,bogus');
    assert.ok(warns(r).some(d => /неизвестно/.test(d.message)));
});

// ──────────────── Глобальные/служебные флаги (--ipcache-hostname и пр.) ────────────────

test('spec: знает глобальные/служебные флаги nfqws2 1.0.1', () => {
    ['--ipcache-hostname', '--ipcache-lifetime', '--ctrack-timeouts',
     '--ctrack-disable', '--server', '--payload-disable', '--reasm-disable',
     '--fwmark', '--bind-fix4', '--bind-fix6', '--lua-init', '--lua-gc',
     '--writable', '--comment',
     '--hostlist-auto-incoming-maxseq', '--hostlist-auto-retrans-maxseq',
     '--hostlist-auto-retrans-reset', '--hostlist-auto-udp-out',
     '--hostlist-auto-udp-in',
    ].forEach((f) => {
        assert.ok(Spec.isKnownFlag(f), f + ' должен быть известен редактору');
    });
});

test('lint: --ipcache-hostname=1 НЕ ошибка (раньше «неизвестный флаг»)', () => {
    const r = Lint.analyze('--ipcache-hostname=1');
    assert.strictEqual(errs(r).length, 0,
        'не должно быть ошибок: ' + JSON.stringify(errs(r)));
});

test('lint: --ipcache-hostname без значения НЕ ошибка (arg optional)', () => {
    const r = Lint.analyze('--ipcache-hostname');
    assert.strictEqual(errs(r).length, 0);
});

test('lint: --ipcache-hostname=2 = предупреждение (enum 0|1)', () => {
    const r = Lint.analyze('--ipcache-hostname=2');
    assert.ok(warns(r).some(d => /недопустимое значение/.test(d.message)));
});

test('lint: строка builtin-пресета с ipcache без ложных ошибок', () => {
    const r = Lint.analyze(
        '--filter-tcp=80,443 --filter-l7=tls,http --ipcache-hostname=1 '
        + '--ipcache-lifetime=8400 --out-range=-s34228 --in-range=-s5556 '
        + '--lua-desync=circular');
    assert.strictEqual(errs(r).length, 0,
        'ложные ошибки на валидном пресете: ' + JSON.stringify(errs(r)));
});

test('lint: корректная стратегия — без ошибок', () => {
    const r = Lint.analyze(
        '--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello '
        + '--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,dupsid');
    assert.strictEqual(errs(r).length, 0, JSON.stringify(r.diagnostics));
    assert.strictEqual(warns(r).length, 0, JSON.stringify(r.diagnostics));
});

test('lint: реальная z2k circular-стратегия — без ошибок', () => {
    const r = Lint.analyze(
        '--filter-tcp=80,443 --filter-l7=tls,http --out-range=-s34228 --in-range=-s5556 '
        + '--lua-desync=circular:fails=3:retrans=3:failure_detector=z2k_mid_stream_stall'
        + ':success_detector=z2k_http_success_positive_only:hostkey=z2k_nohost_key');
    assert.strictEqual(errs(r).length, 0, JSON.stringify(r.diagnostics));
});

// ──────────────── Diagnostics: структура ────────────────

test('lint: приём без фильтра/payload = структурное предупреждение', () => {
    const r = Lint.analyze('--lua-desync=fake:blob=fake_default_tls');
    assert.ok(warns(r).some(d => d.structural && /трафику очереди/.test(d.message)));
    assert.ok(r.slots.has('desync'));
});

test('lint: анализ слотов скелета', () => {
    const r = Lint.analyze('--filter-tcp=443 --hostlist=yt.txt --payload=tls_client_hello --lua-desync=fake');
    assert.ok(r.slots.has('filter') && r.slots.has('list') && r.slots.has('range') && r.slots.has('desync'));
    assert.deepStrictEqual(r.order, ['filter', 'list', 'range', 'desync']);
    assert.deepStrictEqual(r.funcs, ['fake']);
});

// ──────────────── docAt ────────────────

test('docAt: на флаге даёт описание/тип/значения', () => {
    const text = '--filter-l7=tls';
    const doc = Lint.docAt(text, 5);
    assert.strictEqual(doc.kind, 'flag');
    assert.strictEqual(doc.title, '--filter-l7');
    assert.ok(doc.values.indexOf('tls') >= 0);
});

test('docAt: на имени desync-функции даёт сигнатуру и список args', () => {
    const text = '--lua-desync=fake:blob=fake_default_tls';
    const doc = Lint.docAt(text, 15); // внутри "fake"
    assert.strictEqual(doc.kind, 'func');
    assert.strictEqual(doc.title, 'fake');
    assert.strictEqual(doc.file, 'zapret-antidpi.lua');
    assert.ok(doc.argList.some(a => a.name === 'blob'));
});

test('docAt: на sub-arg даёт его тип и описание', () => {
    const text = '--lua-desync=fake:tcp_md5';
    const doc = Lint.docAt(text, 22); // внутри tcp_md5
    assert.strictEqual(doc.kind, 'subarg');
    assert.strictEqual(doc.title, 'tcp_md5');
    assert.strictEqual(doc.group, 'fooling');
});

// ──────────────── Подсветка overlay (выравнивание каретки) ────────────────

test('syntax: highlightWithDiagnostics посимвольно совпадает с исходником', () => {
    const samples = [
        '--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5',
        '--lua-desync=circular:fails=3 --in-range=-s5556',
        '--filtr-tcp=443 --lua-desync=bogus:x=1',  // с ошибками — текст всё равно должен совпадать
        'привет --hostlist=список.txt',             // юникод/HTML-символы
    ];
    for (const text of samples) {
        const r = Lint.analyze(text);
        const html = Syntax.highlightWithDiagnostics(text, r.diagnostics);
        assert.strictEqual(stripHtml(html), text,
            'видимый текст слоя != исходник для: ' + text);
    }
});

test('syntax: ошибочный токен обёрнут в .nfq-error', () => {
    const r = Lint.analyze('--filtr-tcp=443');
    const html = Syntax.highlightWithDiagnostics('--filtr-tcp=443', r.diagnostics);
    assert.ok(/nfq-error/.test(html), 'нет класса ошибки');
});

console.log('nfqws2 lint/spec: ' + passed + ' тест(ов) пройдено');
