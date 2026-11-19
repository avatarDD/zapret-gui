/**
 * test_i18n.js — английский интерфейс (web/js/utils/i18n.js,
 * web/js/i18n/en.text.js, tools/i18n_extract.js; docs/i18n.md).
 *
 * Интерфейс написан по-русски прямо в шаблонах, а в английском режиме
 * переводчик проходит DOM по словарю «русская фраза → English». Тест
 * держит три обещания:
 *
 *   - у каждой русской строки интерфейса есть перевод, и места
 *     подстановки {0}, {1} в ключе и переводе совпадают;
 *   - переводчик находит фразу и тогда, когда в неё вставлены числа,
 *     имена и куски других фраз, и не портит пробелы;
 *   - в русском режиме ничего не меняется и словарь не нужен.
 */

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const I18N = fs.readFileSync(path.join(ROOT, 'web/js/utils/i18n.js'), 'utf8');
const extractor = require(path.join(ROOT, 'tools/i18n_extract.js'));

function load(lang, dict) {
    const ctx = {
        console,
        localStorage: { getItem: () => lang, setItem() {} },
    };
    vm.createContext(ctx);
    vm.runInContext(I18N + '\nglobalThis.i18n = i18n;', ctx);
    if (dict) ctx.i18n._setTextDict(dict);
    return ctx.i18n;
}

// ─────────────────────────── словарь ───────────────────────────

test('у каждой русской строки интерфейса есть перевод', () => {
    const dict = extractor.loadDict();
    const missing = [...extractor.extractAll().keys()]
        .filter((k) => !dict[k]);
    assert.deepStrictEqual(missing.slice(0, 20), [],
        `${missing.length} строк без перевода: node tools/i18n_extract.js --missing`);
});

test('места подстановки в ключе и переводе совпадают', () => {
    const bad = Object.entries(extractor.loadDict())
        .filter(([k, v]) => extractor.placeholders(k) !== extractor.placeholders(v))
        .map(([k]) => k);
    assert.deepStrictEqual(bad, []);
});

test('в переводах не осталось кириллицы', () => {
    const bad = Object.entries(extractor.loadDict())
        .filter(([, v]) => /[А-Яа-яЁё]/.test(v))
        .map(([k]) => k);
    assert.deepStrictEqual(bad, []);
});

test('словарь — валидный JS и объявляет i18n_en_text', () => {
    const src = fs.readFileSync(extractor.DICT, 'utf8');
    const ctx = {};
    vm.createContext(ctx);
    vm.runInContext(src + '\nglobalThis.d = i18n_en_text;', ctx);
    assert.ok(Object.keys(ctx.d).length > 5000);
});

test('каждый ключ словаря переводится сам в себя, и с подстановками', () => {
    const dict = extractor.loadDict();
    const t = load('en', dict);
    const norm = (s) => s.replace(/\s+/g, ' ').trim();
    const fill = (s) => s.replace(/\{(\d+)\}/g, (m, d) => 'X0' + d + 'q');
    const bad = Object.entries(dict)
        .filter(([k, v]) => norm(t.translateText(fill(k))) !== norm(fill(v)))
        .map(([k]) => k);
    assert.deepStrictEqual(bad.slice(0, 10), [], `${bad.length} ключей`);
});

// ─────────────────────────── извлечение ───────────────────────────

function keysOf(src) {
    const out = new Set();
    extractor.extractFrom(src, out);
    return out;
}

test('извлечение: склейка строк превращается в шаблон', () => {
    const keys = keysOf(
        "x = 'Найдено ' + n + ' доменов';");
    assert.ok(keys.has('Найдено {0} доменов'), [...keys].join(' | '));
});

test('извлечение: шаблонная строка и текст между тегами', () => {
    const keys = keysOf(
        'h = `<div title="Подсказка">Всего: ${n} <b>шт.</b></div>`;');
    assert.ok(keys.has('Подсказка'), [...keys].join(' | '));
    assert.ok([...keys].some((k) => k.startsWith('Всего:')),
        [...keys].join(' | '));
});

test('извлечение: регулярка с кавычкой внутри ${} не сбивает разбор', () => {
    const keys = keysOf(
        "h = `<b>${v.replace(/'/g, '')}</b> Первый ${a / b} Третий`; y = 'Второй';");
    assert.ok(keys.has('Первый {0} Третий'), [...keys].join(' | '));
    assert.ok(keys.has('Второй'), [...keys].join(' | '));
});

test('извлечение: комментарии и строки без кириллицы не попадают', () => {
    const keys = keysOf(
        "// Комментарий\n/* Ещё */ x = 'plain'; y = /Регэксп/;");
    assert.deepStrictEqual([...keys.keys()], []);
});

// ─────────────────────────── переводчик ───────────────────────────

const DICT = {
    'Запустить': 'Start',
    'Не установлен': 'Not installed',
    'Конфиги': 'Configs',
    'Сайты по доменам': 'Sites by domain',
    'фейковый пакет': 'fake packet',
    'данные в SYN': 'data in SYN',
    'Что делает: {0}': 'What it does: {0}',
    'Найдено {0} доменов': 'Found {0} domains',
    'Автозапуск: {0} конф., скрипт: {1}{2}': 'Autostart: {0} conf., script: {1}{2}',
    'Перезапустить {0}?': 'Restart {0}?',
    '{1} из {0}': '{1} of {0}',
    'Снята {0}': 'Taken {0}',
    '(открывалось {0} из {1})': '({0} of {1} opened)',
    'Текущее состояние совпадает.': 'The current state matches.',
    'Профиль {0}': 'Profile {0}',
};

test('точное совпадение, пробелы по краям сохраняются', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('Запустить'), 'Start');
    assert.strictEqual(t.translateText('  Запустить\n '), '  Start\n ');
    assert.strictEqual(t.translateText('Запустить   '), 'Start   ');
});

test('регистр первой буквы: «не установлен» → «not installed»', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('не установлен'), 'not installed');
});

test('шаблон с подстановками и перестановкой', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('Найдено 12 доменов'), 'Found 12 domains');
    assert.strictEqual(t.translateText('3 из 7'), '3 of 7');
    // Значение подстановки переводится тем же словарём.
    assert.strictEqual(t.translateText('Перезапустить Конфиги?'),
        'Restart Configs?');
});

test('шаблон совпадает с обрезанным узлом DOM', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('Автозапуск: 0 конф., скрипт:'),
        'Autostart: 0 conf., script:');
});

test('склейка известных кусков через разделители', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('AmneziaWG · Конфиги'),
        'AmneziaWG · Configs');
    assert.strictEqual(t.translateText('Сайты по доменам:'), 'Sites by domain:');
    assert.strictEqual(
        t.translateText('Что делает: данные в SYN + фейковый пакет'),
        'What it does: data in SYN + fake packet');
    assert.strictEqual(
        t.translateText('Снята 01.02.2026 (открывалось 2 из 3). Текущее состояние совпадает.'),
        'Taken 01.02.2026 (2 of 3 opened). The current state matches.');
});

test('незнакомая фраза остаётся как есть и попадает в missing()', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('Совсем новая фраза'), 'Совсем новая фраза');
    assert.ok(t.missing().includes('Совсем новая фраза'));
    // Короткая метка не тянет за собой длинный русский хвост.
    assert.strictEqual(t.translateText('Профиль только для доменов YouTube'),
        'Профиль только для доменов YouTube');
});

test('длинный текст не тормозит: без шаблонов, только точное совпадение', () => {
    const t = load('en', extractor.loadDict());
    const long = 'Не удалось применить стратегию, проверьте настройки. '.repeat(700);
    const t0 = Date.now();
    assert.strictEqual(t.translateText(long), long);
    assert.ok(Date.now() - t0 < 500, `${Date.now() - t0} мс`);
});

test('многострочный текст переводится по строкам', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('Запустить\nКонфиги'), 'Start\nConfigs');
});

test('строки без кириллицы не трогаются', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.translateText('nfqws2 --qnum=200'), 'nfqws2 --qnum=200');
    assert.strictEqual(t.translateText(''), '');
});

test('ключевой API: неизвестный ключ в английском идёт через словарь фраз', () => {
    const t = load('en', DICT);
    assert.strictEqual(t.t('Запустить'), 'Start');
    assert.strictEqual(t.locale(), 'en-US');
});

test('русский режим: ничего не переводится', () => {
    const t = load('ru');
    assert.strictEqual(t.getLanguage(), 'ru');
    assert.strictEqual(t.locale(), 'ru-RU');
    assert.strictEqual(t.t('Запустить'), 'Запустить');
});

test('смену языка может запретить страница с несохранённым', () => {
    const t = load('ru');
    t.setSwitchGuard(() => false);
    assert.strictEqual(t.setLanguage('en'), false);
    assert.strictEqual(t.getLanguage(), 'ru');
    assert.strictEqual(t.setLanguage('ru'), false);  // уже выбран
});

test('неизвестный язык в хранилище — русский', () => {
    const t = load('de');
    assert.strictEqual(t.getLanguage(), 'ru');
});

// ──────────────────── сообщения сервера (en.server.js) ────────────────────

function loadDictFile(rel, name) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const box = {};
    new Function('globalThis', src + `\nglobalThis.d = ${name};`)(box);
    return box.d;
}

function loadWithGlobals(lang) {
    const ctx = {
        console,
        localStorage: { getItem: () => lang, setItem() {} },
        i18n_en_text: loadDictFile('web/js/i18n/en.text.js', 'i18n_en_text'),
        i18n_en_server: loadDictFile('web/js/i18n/en.server.js', 'i18n_en_server'),
    };
    vm.createContext(ctx);
    vm.runInContext(I18N + '\nglobalThis.i18n = i18n;', ctx);
    return ctx.i18n;
}

test('словарь сервера: подстановки совпадают, кириллицы нет', () => {
    const d = loadDictFile('web/js/i18n/en.server.js', 'i18n_en_server');
    assert.ok(Object.keys(d).length > 1000);
    const bad = Object.entries(d).filter(([k, v]) =>
        extractor.placeholders(k) !== extractor.placeholders(v)
        || /[А-Яа-яЁё]/.test(v)).map(([k]) => k);
    assert.deepStrictEqual(bad, []);
});

test('каждое сообщение сервера переводится с подставленными значениями', () => {
    const d = loadDictFile('web/js/i18n/en.server.js', 'i18n_en_server');
    const tr = loadWithGlobals('en');
    const bad = Object.keys(d)
        .map((k) => k.replace(/\{(\d+)\}/g, (m, n) => `v${n}x`))
        .filter((s) => /[А-Яа-яЁё]/.test(tr.translateText(s)));
    assert.deepStrictEqual(bad.slice(0, 20), [], `${bad.length} не переводятся`);
});

test('строки журнала и ошибки API переводятся', () => {
    const tr = loadWithGlobals('en');
    assert.strictEqual(tr.translateText('nfqws2 запущен (PID 1234)'),
        'nfqws2 started (PID 1234)');
    assert.strictEqual(tr.translateText('Конфиг не найден'), 'Config not found');
    // Крупные куски через « — » и хвост, который код дописывает с тире.
    assert.strictEqual(
        tr.translateText('Исключения (не обрабатываются) — netrogat.txt'),
        'Exclusions (not processed) — netrogat.txt');
    assert.strictEqual(
        tr.translateText('awg 1.2 установлен — вернул прежнюю версию'),
        'awg 1.2 installed — restored the previous version');
});

test('в русском режиме сообщения сервера не трогаются', () => {
    const tr = loadWithGlobals('ru');
    assert.strictEqual(tr.translateText('Конфиг не найден'), 'Конфиг не найден');
});

test('имя в кавычках из сообщения сервера не переводится', () => {
    const tr = loadWithGlobals('en');
    assert.strictEqual(tr.translateText("Конфиг 'Обход' не найден"),
        "Config 'Обход' not found");
});

test('при равных шаблонах побеждает словарь страниц', () => {
    const tr = loadWithGlobals('en');
    assert.match(tr.translateText('Удалено: 3 (2)'), /^Deleted: /);
});
