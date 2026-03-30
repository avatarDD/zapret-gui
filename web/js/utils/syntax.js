const NfqwsSyntax = (() => {
    const PARAMS = {
        '--filter-tcp':              { cat: 'filter', desc: 'Фильтр TCP-порта', values: ['80', '443', '80,443', '~22', '*'] },
        '--filter-udp':              { cat: 'filter', desc: 'Фильтр UDP-порта', values: ['443', '50000-50099', '50000-65535', '*'] },
        '--filter-l7':               { cat: 'filter', desc: 'Фильтр L7-протокола', values: ['http', 'tls', 'quic', 'wireguard', 'stun', 'discord'] },
        '--filter-l3':               { cat: 'filter', desc: 'Фильтр версии IP', values: ['ipv4', 'ipv6'] },
        '--payload':                 { cat: 'payload', desc: 'Тип payload', values: ['http_req', 'tls_client_hello', 'quic_initial', 'stun_binding_req'] },
        '--lua-desync':              { cat: 'desync', desc: 'Lua-цепочка desync', values: ['fake', 'multisplit', 'multidisorder', 'fakedsplit', 'hostfakesplit', 'syndata'] },
        '--dpi-desync':              { cat: 'desync', desc: 'Метод(ы) desync', values: ['fake', 'multisplit', 'multidisorder', 'fakedsplit', 'fakeddisorder', 'syndata', 'split', 'split2', 'disorder', 'disorder2', 'udplen', 'hopbyhop', 'destopt', 'ipfrag1', 'ipfrag2'] },
        '--dpi-desync-split-pos':    { cat: 'desync', desc: 'Позиция разбиения', values: ['1', 'midsld', 'midhost', 'sld+1', 'method+2', '1,midsld'] },
        '--dpi-desync-split-seqovl':         { cat: 'desync', desc: 'Sequence overlap', values: ['1', '681'] },
        '--dpi-desync-split-seqovl-pattern': { cat: 'desync', desc: 'Pattern seqovl', values: [] },
        '--dpi-desync-fooling':      { cat: 'desync', desc: 'Метод fooling', values: ['md5sig', 'badseq', 'badsum', 'datanoack', 'hopbyhop', 'hopbyhop2'] },
        '--dpi-desync-repeats':      { cat: 'desync', desc: 'Кол-во повторов', values: ['2', '3', '4', '6', '8', '11'] },
        '--dpi-desync-ttl':          { cat: 'desync', desc: 'TTL для fake', values: ['1', '3', '4', '8'] },
        '--dpi-desync-autottl':      { cat: 'desync', desc: 'Авто TTL', values: [] },
        '--dpi-desync-fake-tls':     { cat: 'desync', desc: 'Fake TLS файл', values: [] },
        '--dpi-desync-fake-http':    { cat: 'desync', desc: 'Fake HTTP файл', values: [] },
        '--dpi-desync-fake-quic':    { cat: 'desync', desc: 'Fake QUIC файл', values: [] },
        '--dpi-desync-fake-syndata': { cat: 'desync', desc: 'Fake SYN data', values: [] },
        '--dpi-desync-fake-unknown':     { cat: 'desync', desc: 'Fake unknown', values: [] },
        '--dpi-desync-fake-unknown-udp': { cat: 'desync', desc: 'Fake unknown UDP', values: [] },
        '--dpi-desync-fake-tls-mod':     { cat: 'desync', desc: 'Модиф. fake TLS', values: ['rnd', 'rndsni', 'dupsid', 'padencap', 'none'] },
        '--dpi-desync-fakedsplit-pattern': { cat: 'desync', desc: 'Pattern fakedsplit', values: [] },
        '--dpi-desync-any-protocol': { cat: 'desync', desc: 'Для любого протокола', values: ['1'] },
        '--dpi-desync-skip-nosni':   { cat: 'desync', desc: 'Пропуск без SNI', values: ['1'] },
        '--dpi-desync-cutoff':       { cat: 'desync', desc: 'Cutoff десинка', values: ['d2', 'n3', 'd4'] },
        '--dpi-desync-start':        { cat: 'desync', desc: 'Старт десинка', values: [] },
        '--dpi-desync-fwmark':       { cat: 'desync', desc: 'Метка пакетов', values: [] },
        '--dpi-desync-udplen-increment': { cat: 'desync', desc: 'Инкремент UDP', values: ['20'] },
        '--dpi-desync-udplen-pattern':   { cat: 'desync', desc: 'Pattern udplen', values: [] },
        '--dup':            { cat: 'dup', desc: 'Дубликация пакетов', values: ['2', '3'] },
        '--dup-fooling':    { cat: 'dup', desc: 'Fooling дубликатов', values: ['md5sig', 'badseq', 'badsum'] },
        '--dup-autottl':    { cat: 'dup', desc: 'Авто-TTL дубликатов', values: [] },
        '--dup-cutoff':     { cat: 'dup', desc: 'Cutoff дубликации', values: ['n3', 'd2'] },
        '--hostlist':                { cat: 'list', desc: 'Файл хостов', values: [] },
        '--hostlist-exclude':        { cat: 'list', desc: 'Исключения хостов', values: [] },
        '--hostlist-domains':        { cat: 'list', desc: 'Домены inline', values: [] },
        '--hostlist-exclude-domains': { cat: 'list', desc: 'Исключения inline', values: [] },
        '--hostlist-auto':           { cat: 'list', desc: 'Авто-хостлист', values: [] },
        '--hostlist-auto-fail-threshold': { cat: 'list', desc: 'Порог авто-детекции', values: [] },
        '--hostlist-auto-fail-time':     { cat: 'list', desc: 'Время авто-детекции', values: [] },
        '--hostlist-auto-retrans-threshold': { cat: 'list', desc: 'Порог ре-трансмиссий', values: [] },
        '--hostlist-auto-debug':     { cat: 'list', desc: 'Лог авто-хостлиста', values: [] },
        '--ipset':                   { cat: 'list', desc: 'IP-список', values: [] },
        '--ipset-exclude':           { cat: 'list', desc: 'Исключения IP', values: [] },
        '--ipset-ip':                { cat: 'list', desc: 'IP inline', values: [] },
        '--qnum':          { cat: 'global', desc: 'Номер NFQUEUE', values: ['300'] },
        '--daemon':        { cat: 'global', desc: 'Режим демона', values: [] },
        '--pidfile':       { cat: 'global', desc: 'Файл PID', values: [] },
        '--user':          { cat: 'global', desc: 'Пользователь', values: ['nobody'] },
        '--hostcase':      { cat: 'desync', desc: 'Рандомизация Host', values: [] },
        '--ipcache-hostname': { cat: 'global', desc: 'Кеш IP→hostname', values: [] },
        '--tcp-pkt-out':   { cat: 'limit', desc: 'TCP пакетов OUT', values: [] },
        '--tcp-pkt-in':    { cat: 'limit', desc: 'TCP пакетов IN', values: [] },
        '--udp-pkt-out':   { cat: 'limit', desc: 'UDP пакетов OUT', values: [] },
        '--udp-pkt-in':    { cat: 'limit', desc: 'UDP пакетов IN', values: [] },
        '--new':           { cat: 'special', desc: 'Разделитель профилей', values: [] },
    };
    const SUB_PARAMS = {
        'blob':       { desc: 'Файл блоба', values: ['fake_default_tls', 'fake_default_http', 'fake_default_quic'] },
        'pos':        { desc: 'Позиция разбиения', values: ['1', 'midsld', 'midhost', 'method+2', 'sld+1', '1,midsld'] },
        'repeats':    { desc: 'Кол-во повторов', values: ['2', '3', '6', '8', '11'] },
        'tcp_md5':    { desc: 'TCP MD5 опция', values: [] },
        'tcp_seq':    { desc: 'Смещение TCP seq', values: ['-10000', '-1'] },
        'ip_ttl':     { desc: 'IP TTL', values: ['1', '3', '4', '8'] },
        'ip6_ttl':    { desc: 'IPv6 Hop Limit', values: ['1', '3', '4', '8'] },
        'nofake1':    { desc: 'Без fake в 1-м пакете', values: [] },
        'midhost':    { desc: 'Позиция midhost', values: ['midsld'] },
        'fooling':    { desc: 'Метод fooling', values: ['md5sig', 'badseq', 'badsum'] },
        'badseq':     { desc: 'Bad sequence', values: [] },
        'md5sig':     { desc: 'TCP MD5 sig', values: [] },
    };
    const DESYNC_METHODS = [
        'fake', 'multisplit', 'multidisorder', 'fakedsplit', 'fakeddisorder',
        'hostfakesplit', 'syndata', 'disorder', 'disorder2', 'split', 'split2',
        'fakesplit', 'oob', 'disoob', 'hopbyhop', 'destopt', 'udplen', 'ipfrag1', 'ipfrag2',
    ];
    const FOOLING_METHODS = ['md5sig', 'badseq', 'badsum', 'datanoack', 'hopbyhop', 'hopbyhop2'];
    const L7_PROTOCOLS = ['http', 'tls', 'quic', 'wireguard', 'stun', 'discord'];
    function highlight(text, opts = {}) {
        if (!text || typeof text !== 'string') return text || '';
        const escapeFirst = opts.escapeFirst !== false;
        let src = escapeFirst ? escapeHtml(text) : text;
        // Разбиваем на токены, сохраняя пробелы
        return src.split(/(\s+)/).map(t => highlightToken(t)).join('');
    }
    function highlightToken(token) {
        if (/^\s+$/.test(token)) return token;
        if (token === '--new') return '<span class="nfq-new">--new</span>';
        if (/^\/[\w/.-]*nfqws2?\b/.test(token)) return '<span class="nfq-binary">' + token + '</span>';
        if (token === '^' || token === '\\') return '<span class="nfq-cont">' + token + '</span>';
        // --lua-desync=chain
        let m = token.match(/^(--lua-desync)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlLuaChain(m[3]);
        m = token.match(/^(--dpi-desync)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlList(m[3], 'nfq-method');
        m = token.match(/^(--(?:dpi-desync|dup)-fooling)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlList(m[3], 'nfq-fooling');
        m = token.match(/^(--dpi-desync-fake-tls-mod)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlTlsMod(m[3]);
        m = token.match(/^(--filter-l7)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlList(m[3], 'nfq-proto');
        m = token.match(/^(--dpi-desync-split-pos)(=)(.+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + s('nfq-pos', m[3]);
        m = token.match(/^(--[\w-]+)(=)(.+)$/);
        if (m) {
            let cls = 'nfq-value';
            if (/\.\w{2,4}(?:"|$)/.test(m[3]) || m[3].includes('/')) cls = 'nfq-file';
            else if (/^-?\d+$/.test(m[3]) || /^0x[0-9A-Fa-f]+$/.test(m[3])) cls = 'nfq-num';
            // Убираем кавычки в подсветке но сохраняем
            return s('nfq-flag', m[1]) + s('nfq-eq', '=') + s(cls, m[3]);
        }
        // --param (без значения)
        if (/^--[\w-]+$/.test(token)) return s('nfq-flag', token);
        return token;
    }
    function hlLuaChain(chain) {
        return chain.split(':').map((part, i) => {
            const sep = i > 0 ? s('nfq-sub-sep', ':') : '';
            if (i === 0) return sep + s('nfq-method', part);
            const eq = part.indexOf('=');
            if (eq > 0) {
                const k = part.substring(0, eq), v = part.substring(eq + 1);
                const vc = /^-?\d+$/.test(v) ? 'nfq-num' : 'nfq-subval';
                return sep + s('nfq-subkey', k) + s('nfq-eq', '=') + s(vc, v);
            }
            return sep + s('nfq-subflag', part);
        }).join('');
    }
    function hlList(val, cls) {
        return val.split(',').map((v, i) => {
            const sep = i > 0 ? s('nfq-comma', ',') : '';
            return sep + s(cls, v);
        }).join('');
    }
    function hlTlsMod(val) {
        return val.split(',').map((v, i) => {
            const sep = i > 0 ? s('nfq-comma', ',') : '';
            if (v.startsWith('sni=')) {
                return sep + s('nfq-subkey', 'sni') + s('nfq-eq', '=') + s('nfq-subval', v.substring(4));
            }
            return sep + s('nfq-subflag', v);
        }).join('');
    }
    function s(cls, text) { return '<span class="' + cls + '">' + text + '</span>'; }
    // ══════════════════ Полная команда ══════════════════
    function highlightCommand(text, opts) {
        if (!text) return text || '';
        return text.split('\n').map(l => highlight(l, opts)).join('\n');
    }
    function hasNfqwsArgs(text) {
        return text ? /--(?:filter-(?:tcp|udp|l[37])|lua-desync|dpi-desync|payload|qnum|hostlist|ipset|hostcase|dup)/.test(text) : false;
    }
    function highlightInLog(text, opts) {
        return (text && hasNfqwsArgs(text)) ? highlight(text, opts) : null;
    }
    function getSuggestions(prefix, context) {
        prefix = (prefix || '').toLowerCase();
        context = context || 'any';
        const results = [];
        if ((context === 'flag' || context === 'any') && prefix.startsWith('-')) {
            for (const [key, info] of Object.entries(PARAMS)) {
                if (key.toLowerCase().startsWith(prefix)) {
                    results.push({ text: key, desc: info.desc, type: 'flag', cat: info.cat, values: info.values });
                }
            }
        }
        if (context === 'sub' || (context === 'any' && !prefix.startsWith('-'))) {
            const search = prefix.replace(/^:/, '');
            for (const [key, info] of Object.entries(SUB_PARAMS)) {
                if (key.toLowerCase().startsWith(search))
                    results.push({ text: key, desc: info.desc, type: 'sub', values: info.values });
            }
        }
        if (context === 'method' || context === 'any') {
            DESYNC_METHODS.forEach(m => {
                if (m.startsWith(prefix)) results.push({ text: m, desc: 'Desync метод', type: 'method' });
            });
        }
        return results;
    }
    function getDesyncMethods(prefix) {
        return DESYNC_METHODS.filter(m => m.startsWith((prefix || '').toLowerCase()));
    }
    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }
    return {
        highlight, highlightCommand, highlightInLog, hasNfqwsArgs,
        getSuggestions, getDesyncMethods,
        PARAMS, SUB_PARAMS, DESYNC_METHODS, FOOLING_METHODS, L7_PROTOCOLS,
    };
})();
