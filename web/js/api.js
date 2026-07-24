/**
 * api.js — HTTP-клиент для взаимодействия с backend API.
 *
 * Использование:
 *   const status = await API.get('/api/status');
 *   await API.post('/api/start', { strategy_id: 'tcp_1' });
 */

const API = (() => {
    const BASE = '';  // Тот же origin

    const DEFAULT_TIMEOUT = 15000;

    async function request(method, path, body = null, opts = null) {
        // MR-91: таймаут запроса через AbortSignal.timeout / AbortController.
        // Дефолт 15с (защита от зависаний), но длинные СИНХРОННЫЕ эндпоинты
        // (traceroute до 45с, PMTU-проба) передают свой timeout, иначе фронт
        // оборвал бы легитимную операцию (регрессия: в main таймаута не было).
        const timeoutMs = (opts && opts.timeout) || DEFAULT_TIMEOUT;
        let signal;
        let timeoutId;

        if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
            signal = AbortSignal.timeout(timeoutMs);
        } else {
            const controller = new AbortController();
            timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            signal = controller.signal;
        }

        const fetchOpts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            signal,
        };

        if (body !== null && method !== 'GET') {
            fetchOpts.body = JSON.stringify(body);
        }

        try {
            const resp = await fetch(BASE + path, fetchOpts);
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
            if (err.name === 'AbortError' || err.name === 'TimeoutError') {
                throw new Error('Превышено время ожидания запроса (таймаут '
                                + Math.round(timeoutMs / 1000) + 'с)');
            }
            if (err.name === 'TypeError') {
                // Сетевая ошибка (сервер недоступен)
                throw new Error('Сервер недоступен');
            }
            throw err;
        }
    }

    return {
        // Необязательный последний аргумент opts = { timeout: <мс> } для
        // длинных синхронных эндпоинтов. По умолчанию — 15с.
        get:    (path, opts) =>         request('GET', path, null, opts),
        post:   (path, body, opts) =>   request('POST', path, body, opts),
        put:    (path, body, opts) =>   request('PUT', path, body, opts),
        delete: (path, body, opts) =>   request('DELETE', path, body, opts),
    };
})();
