/**
 * foreign_note.js — предупреждение «этот движок работает и не из GUI».
 *
 * Страница движка показывает свои профили; туннель, поднятый init-скриптом
 * Entware (S99sing-box, S99mihomo, S99amneziawg…) или руками, в них не
 * значится — и страница выглядела как «всё остановлено», хотя движок
 * работает. ForeignNote.attach(container, engine) дописывает под
 * заголовок страницы строку со ссылкой на «Сторонние туннели», если
 * у движка есть чужие процессы или включённые чужие скрипты.
 */

const ForeignNote = (() => {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function attach(container, engine) {
        let data;
        try {
            data = await API.get('/api/foreign/status');
        } catch (_) {
            return;
        }
        if (!data || !container || !container.isConnected) return;
        const procs = (data.processes || []).filter(p => p.engine === engine);
        const scripts = (data.scripts || [])
            .filter(s => s.engine === engine && s.enabled);
        if (!procs.length && !scripts.length) return;
        const parts = [];
        if (procs.length) {
            parts.push('работает не из GUI: ' + procs.map(p =>
                `pid ${esc(p.pid)}${p.iface ? ` (<code>${esc(p.iface)}</code>)` : ''}`)
                .join(', '));
        }
        if (scripts.length) {
            parts.push('в автозапуске сторонний скрипт: ' + scripts.map(s =>
                `<code>${esc(s.name)}</code>`).join(', '));
        }
        const old = container.querySelector('.foreign-note');
        if (old) old.remove();
        const div = document.createElement('div');
        div.className = 'card foreign-note';
        div.innerHTML = `<div class="card-body form-hint">⚠ ${parts.join('; ')}.
            GUI таким экземпляром не управляет, а после перезагрузки его
            поднимет собственный скрипт. На странице
            <a href="#foreign-services">«Сторонние туннели»</a> его можно
            передать GUI или остановить и отключить.</div>`;
        const header = container.querySelector('.page-header');
        if (header && header.parentNode) {
            header.parentNode.insertBefore(div, header.nextSibling);
        } else {
            container.prepend(div);
        }
    }

    return { attach };
})();
