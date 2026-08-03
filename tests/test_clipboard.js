/**
 * test_clipboard.js — копирование в буфер работает по http (issue #272).
 *
 * Главный сценарий проекта: GUI открыт на роутере по адресу вроде
 * http://192.168.1.1:1080. Это НЕ secure context, поэтому весь объект
 * navigator.clipboard там отсутствует. Прямой вызов
 * `navigator.clipboard.writeText(x).then(ok, err)` в таком браузере падает
 * с TypeError СИНХРОННО — не срабатывает даже обработчик ошибки, и кнопка
 * молча не делает ничего. Ровно это и увидел пользователь на ссылке
 * tg://proxy.
 *
 * Тесты гоняют модуль в обеих средах: с Clipboard API и без него.
 */

const assert = require('node:assert');
const { test } = require('node:test');
const path = require('node:path');

const Clipboard = require(
    path.join(__dirname, '..', 'web', 'js', 'utils', 'clipboard.js'));

// ─────────────────────── мини-DOM ───────────────────────
// Полноценный jsdom тянуть некуда (в проекте нет npm-зависимостей), а нам
// нужны ровно createElement/appendChild/removeChild/execCommand.

function installDom({ execResult = true, throwOnExec = false } = {}) {
    const state = { appended: [], removed: [], copied: null, execCalls: 0 };
    const makeEl = () => ({
        style: {},
        value: '',
        setAttribute() {},
        select() {},
        setSelectionRange() {},
        focus() {},
    });
    global.document = {
        body: {
            appendChild(el) { state.appended.push(el); },
            removeChild(el) { state.removed.push(el); },
        },
        createElement: makeEl,
        createRange: () => ({ selectNodeContents() {} }),
        execCommand(cmd) {
            state.execCalls++;
            if (throwOnExec) throw new Error('нет доступа');
            if (cmd === 'copy') {
                const last = state.appended[state.appended.length - 1];
                state.copied = last ? last.value : null;
            }
            return execResult;
        },
    };
    global.window = {
        getSelection: () => ({ removeAllRanges() {}, addRange() {} }),
    };
    return state;
}

function withNavigator(nav) {
    if (nav === null) delete global.navigator;
    else global.navigator = nav;
}

function cleanup() {
    delete global.document;
    delete global.window;
    delete global.navigator;
    delete global.Toast;
}

// ─────────────────── http на роутере (нет Clipboard API) ───────────────────

test('без navigator.clipboard копирование не падает, а идёт через execCommand',
     async () => {
    const dom = installDom();
    withNavigator({});                      // navigator есть, clipboard нет
    try {
        const ok = await Clipboard.copy('tg://proxy?server=1.2.3.4');
        assert.strictEqual(ok, true, 'должно скопироваться фолбэком');
        assert.strictEqual(dom.copied, 'tg://proxy?server=1.2.3.4');
        assert.strictEqual(dom.execCalls, 1);
    } finally { cleanup(); }
});

test('navigator вообще отсутствует — тоже не падает', async () => {
    const dom = installDom();
    withNavigator(null);
    try {
        assert.strictEqual(await Clipboard.copy('x'), true);
        assert.strictEqual(dom.copied, 'x');
    } finally { cleanup(); }
});

test('временный textarea всегда убирается из DOM', async () => {
    const dom = installDom();
    withNavigator({});
    try {
        await Clipboard.copy('abc');
        assert.strictEqual(dom.appended.length, 1);
        assert.strictEqual(dom.removed.length, 1,
                           'элемент должен быть удалён, иначе они копятся');
    } finally { cleanup(); }
});

test('textarea убирается даже когда execCommand бросает', async () => {
    const dom = installDom({ throwOnExec: true });
    withNavigator({});
    try {
        assert.strictEqual(await Clipboard.copy('abc'), false);
        assert.strictEqual(dom.removed.length, 1);
    } finally { cleanup(); }
});

// ─────────────────── https / localhost (Clipboard API есть) ───────────────────

test('при доступном Clipboard API используется он', async () => {
    installDom();
    let written = null;
    withNavigator({ clipboard: { writeText: (t) => { written = t; return Promise.resolve(); } } });
    try {
        assert.strictEqual(await Clipboard.copy('secure'), true);
        assert.strictEqual(written, 'secure');
    } finally { cleanup(); }
});

test('отказ Clipboard API (политика разрешений) уводит на фолбэк', async () => {
    const dom = installDom();
    withNavigator({ clipboard: { writeText: () => Promise.reject(new Error('denied')) } });
    try {
        assert.strictEqual(await Clipboard.copy('x'), true);
        assert.strictEqual(dom.copied, 'x', 'должен сработать execCommand');
    } finally { cleanup(); }
});

// ─────────────────────── поведение и уведомления ───────────────────────

test('пустой текст не трогает DOM', async () => {
    const dom = installDom();
    withNavigator({});
    try {
        assert.strictEqual(await Clipboard.copy(''), false);
        assert.strictEqual(await Clipboard.copy(null), false);
        assert.strictEqual(dom.appended.length, 0);
    } finally { cleanup(); }
});

test('copyWithToast сообщает об успехе своим текстом', async () => {
    installDom();
    withNavigator({});
    const seen = [];
    global.Toast = { success: (m) => seen.push(['ok', m]),
                     error: (m) => seen.push(['err', m]) };
    try {
        await Clipboard.copyWithToast('link', { okText: 'Ссылка скопирована' });
        assert.deepStrictEqual(seen, [['ok', 'Ссылка скопирована']]);
    } finally { cleanup(); }
});

test('когда скопировать нельзя — текст выделяется и об этом говорят', async () => {
    installDom({ execResult: false });
    withNavigator({});
    const seen = [];
    global.Toast = { success: (m) => seen.push(['ok', m]),
                     error: (m) => seen.push(['err', m]) };
    let selected = false;
    const node = { nodeName: 'CODE' };
    global.window.getSelection = () => ({
        removeAllRanges() {}, addRange() { selected = true; },
    });
    try {
        const ok = await Clipboard.copyWithToast('link', { node });
        assert.strictEqual(ok, false);
        assert.strictEqual(selected, true, 'текст должен остаться выделенным');
        assert.strictEqual(seen.length, 1);
        assert.strictEqual(seen[0][0], 'err');
        assert.match(seen[0][1], /Ctrl\+C/,
                     'пользователю нужно сказать, что делать дальше');
    } finally { cleanup(); }
});

test('hasAsyncApi честно отражает окружение', () => {
    try {
        withNavigator({});
        assert.strictEqual(Clipboard.hasAsyncApi(), false);
        withNavigator({ clipboard: { writeText: () => Promise.resolve() } });
        assert.strictEqual(Clipboard.hasAsyncApi(), true);
        withNavigator({ clipboard: {} });
        assert.strictEqual(Clipboard.hasAsyncApi(), false,
                           'clipboard без writeText не годится');
    } finally { cleanup(); }
});
