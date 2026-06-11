/**
 * transport_select.js — общий помощник «транспорт скачивания».
 *
 * Один кэшируемый запрос GET /api/install/transports (задача №8) и
 * генерация <option> для селектов «Качать через» в разных местах GUI:
 * установка бинарей (InstallExtras), автообновление списков (lists.js),
 * подписки и пул серверов (singbox_configs.js).
 *
 * Использование:
 *   const list = await TransportSelect.load();      // [{id,kind,label,detail}]
 *   sel.innerHTML = TransportSelect.optionsHtml(list, savedValue);
 *
 * Сохранённый, но сейчас недоступный транспорт (туннель не запущен)
 * остаётся в списке с пометкой — настройка не «сбрасывается» визуально.
 */
const TransportSelect = (() => {

    const DIRECT = { id: 'direct', kind: 'direct', label: 'Напрямую' };
    const CACHE_MS = 60 * 1000;

    let cache = null;
    let cacheAt = 0;
    let inflight = null;

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

    /** Список транспортов (кэш 60с; параллельные вызовы делят запрос). */
    async function load(force) {
        const now = Date.now();
        if (cache && !force && (now - cacheAt) < CACHE_MS) return cache;
        if (inflight) return inflight;
        inflight = (async () => {
            try {
                const r = await API.get('/api/install/transports');
                cache = (r && r.transports && r.transports.length)
                    ? r.transports : [DIRECT];
            } catch (_) {
                cache = [DIRECT];
            }
            cacheAt = Date.now();
            inflight = null;
            return cache;
        })();
        return inflight;
    }

    /**
     * <option>-разметка. list — из load() (null → только «Напрямую»),
     * selected — сохранённое значение ('' и 'direct' эквивалентны).
     */
    function optionsHtml(list, selected) {
        const items = (list && list.length) ? list.slice() : [DIRECT];
        const sel = (selected || 'direct');
        if (!items.some(t => t.id === sel)) {
            // Например awg:wg0, когда туннель сейчас опущен.
            items.push({ id: sel, label: sel + ' (сейчас недоступен)' });
        }
        return items.map(t =>
            `<option value="${escAttr(t.id)}" title="${escAttr(t.detail || '')}"
                     ${t.id === sel ? 'selected' : ''}>${esc(t.label)}</option>`
        ).join('');
    }

    /** Человекочитаемая подпись транспорта по id (для строк статуса). */
    function labelFor(list, id) {
        if (!id || id === 'direct') return 'напрямую';
        const t = (list || []).find(x => x.id === id);
        return t ? t.label : id;
    }

    return { load, optionsHtml, labelFor };
})();
