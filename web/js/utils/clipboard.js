/**
 * clipboard.js — Копирование в буфер обмена, работающее по HTTP.
 *
 * Почему это отдельный модуль, а не одна строчка `navigator.clipboard`.
 *
 * `navigator.clipboard` существует ТОЛЬКО в secure context: https://,
 * либо http://localhost / 127.0.0.1. Наш GUI живёт на роутере и открывается
 * по обычному http на LAN-адресе (`http://192.168.1.1:1080`) — это НЕ
 * secure context, и весь объект `navigator.clipboard` там просто
 * `undefined`.
 *
 * Отсюда неочевидный симптом: `navigator.clipboard.writeText(x).then(ok, err)`
 * падает с TypeError СИНХРОННО, ещё до создания промиса. Значит не
 * срабатывает даже обработчик ошибки — кнопка не делает ровно ничего, без
 * единого сообщения. Пользователь видит «копирование сломано» (issue #272).
 *
 * Порядок попыток:
 *   1. `navigator.clipboard.writeText` — если доступен (https / localhost);
 *   2. `document.execCommand("copy")` через временный textarea — legacy-путь,
 *      он-то как раз и работает по http; формально deprecated, но во всех
 *      актуальных браузерах жив и является единственным вариантом вне
 *      secure context;
 *   3. если не вышло и это — выделяем текст в исходном элементе, чтобы
 *      пользователю осталось нажать Ctrl+C, и честно об этом сообщаем.
 *
 * Использование:
 *     Clipboard.copy(text)                 // → Promise<boolean>
 *     Clipboard.copyWithToast(text)        // + готовые уведомления
 *     Clipboard.copyWithToast(text, {node, okText})
 */

const Clipboard = (() => {

    /** Доступен ли современный API (secure context). */
    function hasAsyncApi() {
        return !!(typeof navigator !== "undefined"
                  && navigator.clipboard
                  && typeof navigator.clipboard.writeText === "function");
    }

    /**
     * Legacy-путь: скрытый textarea + execCommand.
     * Работает вне secure context, поэтому на роутере он основной.
     */
    function execCommandCopy(text) {
        if (typeof document === "undefined" || !document.body) return false;
        const ta = document.createElement("textarea");
        ta.value = text;
        // Не даём странице дёрнуться и не показываем поле пользователю.
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "0";
        ta.style.left = "0";
        ta.style.width = "1px";
        ta.style.height = "1px";
        ta.style.padding = "0";
        ta.style.border = "none";
        ta.style.outline = "none";
        ta.style.boxShadow = "none";
        ta.style.background = "transparent";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        let ok = false;
        try {
            ta.select();
            // iOS игнорирует select() у readonly-полей без явного диапазона.
            if (typeof ta.setSelectionRange === "function") {
                ta.setSelectionRange(0, text.length);
            }
            ok = document.execCommand("copy");
        } catch (e) {
            ok = false;
        }
        document.body.removeChild(ta);
        return ok;
    }

    /** Выделить текст внутри узла — последний шанс скопировать вручную. */
    function selectNode(node) {
        if (!node || typeof window === "undefined" || !window.getSelection) {
            return false;
        }
        try {
            const range = document.createRange();
            range.selectNodeContents(node);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Скопировать текст. Никогда не бросает исключение.
     * @param {string} text
     * @returns {Promise<boolean>} удалось ли положить в буфер
     */
    function copy(text) {
        const s = (text === null || text === undefined) ? "" : String(text);
        if (!s) return Promise.resolve(false);

        if (hasAsyncApi()) {
            // Даже в secure context запись может быть запрещена политикой
            // разрешений — тогда честно пробуем legacy-путь.
            return navigator.clipboard.writeText(s).then(
                () => true,
                () => execCommandCopy(s));
        }
        return Promise.resolve(execCommandCopy(s));
    }

    /**
     * Скопировать и показать уведомление.
     * @param {string} text
     * @param {object} [opts]
     * @param {HTMLElement} [opts.node] — что выделить, если скопировать нельзя
     * @param {string} [opts.okText]    — текст успеха
     * @returns {Promise<boolean>}
     */
    function copyWithToast(text, opts) {
        const o = opts || {};
        const okText = o.okText || "Скопировано";
        return copy(text).then((ok) => {
            const toast = (typeof Toast !== "undefined") ? Toast : null;
            if (ok) {
                if (toast) toast.success(okText);
                return true;
            }
            // Скопировать не вышло — оставим текст выделенным, чтобы
            // пользователю хватило Ctrl+C, и скажем об этом прямо.
            const selected = selectNode(o.node);
            if (toast) {
                toast.error(selected
                    ? "Браузер не дал доступ к буферу обмена — текст выделен, нажмите Ctrl+C"
                    : "Не удалось скопировать — выделите текст и нажмите Ctrl+C");
            }
            return false;
        });
    }

    return { copy, copyWithToast, hasAsyncApi, execCommandCopy, selectNode };
})();

if (typeof module !== "undefined" && module.exports) {
    module.exports = Clipboard;
}
