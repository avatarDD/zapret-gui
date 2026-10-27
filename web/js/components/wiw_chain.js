/**
 * wiw_chain.js — как показать WARP-in-WARP человеку.
 *
 * В двойном туннеле два интерфейса, и в списках они выглядят одинаково
 * («Туннель AmneziaWG · warp1», «… · warp2»). Не видно, что трафик
 * надо слать во ВНУТРЕННИЙ (inner), а внешний (outer) только везёт
 * его UDP до Cloudflare. Маршрут в outer — это одиночный WARP, и
 * пользователь думает, что двойной туннель «не работает».
 *
 * Данные — `wiw_chains` из /api/routing/interfaces и /api/awg/interfaces
 * (core/wiw_chain.py): [{engine, mode, outer, outer_kind, inner,
 * inner_kind}]. Модуль только рисует, ничего не запрашивает.
 */

const WiwChain = (() => {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    const KIND = { awg: 'AmneziaWG', warp: 'MASQUE' };
    const MODE = {
        awg_awg:       'AmneziaWG + AmneziaWG',
        masque_masque: 'MASQUE + MASQUE',
        masque_awg:    'MASQUE снаружи, AmneziaWG внутри',
        awg_masque:    'AmneziaWG снаружи, MASQUE внутри',
    };

    /** Страница, где связкой управляют. */
    function manageHash(chain) {
        return chain && chain.engine === 'masque' ? '#warp-in-warp' : '#awg-warp?tab=wiw';
    }

    /**
     * Роль интерфейса или метод-токена (`awg:warp2`, `warp:usque1`, `warp2`):
     * {role: 'inner'|'outer', chain} или null. Сверяем по имени: у AWG
     * токен несёт имя конфига, и в связке хранится оно же.
     */
    function roleOf(chains, tokenOrName) {
        const t = String(tokenOrName || '');
        const i = t.indexOf(':');
        const name = i < 0 ? t : t.slice(i + 1);
        if (!name) return null;
        for (const ch of chains || []) {
            if (ch.inner === name) return { role: 'inner', chain: ch };
            if (ch.outer === name) return { role: 'outer', chain: ch };
        }
        return null;
    }

    /** Короткая подпись роли для <option> и списков (без HTML). */
    function roleText(chains, tokenOrName) {
        const r = roleOf(chains, tokenOrName);
        if (!r) return '';
        return r.role === 'inner'
            ? `WARP-in-WARP: внутренний, идёт через ${r.chain.outer}`
            : `WARP-in-WARP: внешний слой для ${r.chain.inner}`;
    }

    /** Значок роли рядом с именем туннеля. */
    function badgeHtml(chains, tokenOrName) {
        const r = roleOf(chains, tokenOrName);
        if (!r) return '';
        return r.role === 'inner'
            ? `<span class="badge badge-success wiw-badge"
                     title="Внутренний туннель WARP-in-WARP: его UDP идёт через ${esc(r.chain.outer)}. Маршруты для двойного туннеля ведите сюда.">
                   WARP-in-WARP · внутренний</span>`
            : `<span class="badge badge-info wiw-badge"
                     title="Внешний туннель WARP-in-WARP: везёт до Cloudflare только ${esc(r.chain.inner)}. Маршрут прямо в него — это одиночный WARP.">
                   WARP-in-WARP · внешний</span>`;
    }

    function node(name, kind, cls) {
        return `<span class="wiw-node ${cls || ''}">
                    <code>${esc(name)}</code>
                    <span class="wiw-kind">${esc(KIND[kind] || kind || '')}</span>
                </span>`;
    }

    /** Схема пути: Устройства → inner ⇢ внутри ⇢ outer → Интернет. */
    function diagramHtml(chain) {
        const arrow = '<span class="wiw-arrow">→</span>';
        return `<div class="wiw-flow">
            <span class="wiw-end">Устройства</span>${arrow}
            ${node(chain.inner, chain.inner_kind, 'wiw-inner')}
            <span class="wiw-arrow" title="UDP внутреннего туннеля идёт внутри внешнего">⇢ внутри ⇢</span>
            ${node(chain.outer, chain.outer_kind, 'wiw-outer')}${arrow}
            <span class="wiw-end">Интернет</span>
        </div>`;
    }

    /**
     * Карточка связки: схема, режим и что с маршрутами. `routes` — список
     * единого слоя (/api/unified/routes) или null, если его нет.
     * `opts.onRouting` — карточка уже на «Маршрутизации»: без ссылки туда.
     */
    function cardHtml(chain, routes, opts) {
        const onRouting = !!(opts && opts.onRouting);
        const routingRef = onRouting ? 'ниже'
            : 'на странице <a href="#routing">«Маршрутизация»</a>';
        const mode = MODE[chain.mode] || chain.mode || '';
        let routesNote = '';
        if (Array.isArray(routes)) {
            const on = routes.filter(r => r && r.enabled !== false);
            const hits = (name) => on.filter(r => ifaceOfMethod(r.method) === name).length;
            const nIn = hits(chain.inner);
            const nOut = hits(chain.outer);
            if (!nIn) {
                routesNote += `<div class="note-box warn">
                    Ни один включённый маршрут не ведёт в <code>${esc(chain.inner)}</code> —
                    в двойной туннель сейчас ничего не идёт. Заведите маршрут
                    ${routingRef} и выберите методом
                    <strong>${esc(chain.inner)}</strong> (внутренний).
                </div>`;
            } else {
                routesNote += `<div class="form-hint" style="margin-top:6px;">
                    Маршрутов через двойной туннель: <strong>${nIn}</strong>
                    (метод <code>${esc(chain.inner)}</code>).
                </div>`;
            }
            if (nOut) {
                routesNote += `<div class="note-box warn">
                    ${nOut} ${nOut === 1 ? 'маршрут ведёт' : 'маршрута(ов) ведут'} прямо во внешний
                    <code>${esc(chain.outer)}</code> — такой трафик идёт через один WARP,
                    а не через два. Для двойного смените метод на
                    <code>${esc(chain.inner)}</code>.
                </div>`;
            }
        }
        return `<div class="card wiw-card">
            <div class="card-title">WARP-in-WARP
                <span class="text-muted" style="font-weight:normal; font-size:12px;">${esc(mode)}</span>
            </div>
            ${diagramHtml(chain)}
            <div class="form-hint" style="margin-top:6px;">
                <strong>${esc(chain.inner)}</strong> — внутренний: в него ведут маршруты.
                <strong>${esc(chain.outer)}</strong> — внешний: везёт до Cloudflare только
                ${esc(chain.inner)}, свой трафик в него слать не нужно.
            </div>
            ${routesNote}
            <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">
                <a class="btn btn-ghost btn-sm" href="${manageHash(chain)}">Управление связкой</a>
                ${onRouting ? '' : '<a class="btn btn-ghost btn-sm" href="#routing">Маршрутизация</a>'}
            </div>
        </div>`;
    }

    /** Имя интерфейса из метод-токена: `awg:warp2` → `warp2`. */
    function ifaceOfMethod(method) {
        const t = String(method || '');
        const i = t.indexOf(':');
        return i < 0 ? '' : t.slice(i + 1);
    }

    /**
     * Пояснение под методом маршрута (таблица, редактор): для inner —
     * путь, для outer — предупреждение.
     */
    function methodNoteHtml(chains, token) {
        const r = roleOf(chains, token);
        if (!r || String(token || '').indexOf(':') < 0) return '';
        const ch = r.chain;
        if (r.role === 'inner') {
            return `<div class="text-muted" style="font-size:11px; margin-top:2px;">
                        WARP-in-WARP: ${esc(ch.inner)} → внутри ${esc(ch.outer)} → интернет</div>`;
        }
        return `<div class="text-error" style="font-size:11px; margin-top:2px;">
                    ⚠ ${esc(ch.outer)} — внешний слой WARP-in-WARP: так трафик пойдёт
                    через один WARP. Для двойного выберите ${esc(ch.inner)}.</div>`;
    }

    return { roleOf, roleText, badgeHtml, diagramHtml, cardHtml,
             methodNoteHtml, manageHash };
})();
