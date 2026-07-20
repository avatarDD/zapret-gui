/**
 * api.js — HTTP-клиент для взаимодействия с backend API.
 *
 * Использование:
 *   const status = await API.get('/api/status');
 *   await API.post('/api/start', { strategy_id: 'tcp_1' });
 */

const API = (() => {
    const BASE = '';  // Тот же origin

    async function request(method, path, body = null) {
        // MR-91: таймаут запроса 15с через AbortSignal.timeout / AbortController fallback
        let signal;
        let timeoutId;

        if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
            signal = AbortSignal.timeout(15000);
        } else {
            const controller = new AbortController();
            timeoutId = setTimeout(() => controller.abort(), 15000);
            signal = controller.signal;
        }

        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            signal,
        };

        if (body !== null && method !== 'GET') {
            opts.body = JSON.stringify(body);
        }

        try {
            const resp = await fetch(BASE + path, opts);
            clearTimeout(timeoutId);
            const data = await resp.json();

            if (!resp.ok) {
                // Бэкенд кладёт человекочитаемый текст то в `error`
                // (REST-ошибки), то в `message` (например awg up/down/
                // restart). Берём что есть, иначе — код статуса.
                const msg = data.error || data.message || `HTTP ${resp.status}`;
                throw new Error(msg);
            }

            return data;
        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                throw new Error('Превышено время ожидания запроса (таймаут 15с)');
            }
            if (err.name === 'TypeError') {
                // Сетевая ошибка (сервер недоступен)
                throw new Error('Сервер недоступен');
            }
            throw err;
        }
    }

    return {
        get:    (path) =>         request('GET', path),
        post:   (path, body) =>   request('POST', path, body),
        put:    (path, body) =>   request('PUT', path, body),
        delete: (path, body) =>   request('DELETE', path, body),
    };
})();
