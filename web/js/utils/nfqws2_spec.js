/**
 * nfqws2_spec.js — Единый справочник синтаксиса nfqws2 (ТОЛЬКО nfqws2/zapret2).
 *
 * Это «источник правды» для редактора стратегий: подсветка синтаксиса,
 * автодополнение, проверка ошибок, контекстные подсказки и схема-скелет.
 * Никакого legacy nfqws1 (`--dpi-desync*`) — движок другой (см. SKILL §1).
 *
 * Опирается на:
 *   - SKILL §3   — CLI-опции nfqws2 (v0.9.5.2)
 *   - SKILL §4   — диапазоны --in-range/--out-range
 *   - SKILL §5/6 — payload-типы и pos-маркеры
 *   - SKILL §8   — desync-функции zapret-antidpi.lua и блоки опций (fooling/…)
 *   - SKILL §9   — оркестраторы zapret-auto.lua + наш bundle
 *   - import/lua/*.lua — реальные экспортируемые функции расширений проекта
 *
 * Категории слотов (для скелета и проверки порядка внутри профиля):
 *   global  → декларации до первого --new (--blob)
 *   sep     → --new (разделитель профилей)
 *   filter  → --filter-*  (отбор профиля)
 *   list    → --hostlist… / --ipset… (ограничение по доменам/IP)
 *   range   → --out-range/--in-range/--payload (внутрипрофильные фильтры)
 *   desync  → --lua-desync (действие)
 *
 * Канонический порядок внутри профиля:
 *   filter → list → range → desync   (повторяется, разделяется --new)
 *
 * Экспортируется и для браузера (глобальный Nfqws2Spec), и для node (module.exports).
 */
const Nfqws2Spec = (() => {

    // ──────────────── Перечисления значений ────────────────

    // SKILL §3.6 / §5 — типы payload
    const PAYLOAD_TYPES = [
        'all', 'unknown', 'empty', 'known', 'ipv4', 'ipv6', 'icmp',
        'http_req', 'http_reply',
        'tls_client_hello', 'tls_server_hello',
        'dtls_client_hello', 'dtls_server_hello',
        'quic_initial',
        'wireguard_initiation', 'wireguard_response', 'wireguard_cookie',
        'wireguard_keepalive', 'wireguard_data',
        'dht', 'discord_ip_discovery', 'stun',
        'xmpp_stream', 'xmpp_starttls', 'xmpp_proceed', 'xmpp_features',
        'dns_query', 'dns_response',
        'mtproto_initial', 'bt_handshake', 'utp_bt_handshake',
    ];

    // SKILL §3.6 — L7-протоколы
    const L7_PROTOS = [
        'all', 'unknown', 'known', 'http', 'tls', 'dtls', 'quic',
        'wireguard', 'dht', 'discord', 'stun', 'xmpp', 'dns', 'mtproto',
        'bt', 'utp_bt',
    ];

    // SKILL §6 — относительные pos-маркеры (плюс арифметика +N/-N)
    const POS_MARKERS = [
        'method', 'host', 'endhost', 'sld', 'endsld', 'midsld',
        'sniext', 'extlen',
    ];

    // SKILL §4 — режимы диапазонов
    const RANGE_MODES = ['a', 'x', 'n', 'd', 'b', 's', 'p'];

    // tls_mod (SKILL §8.8): csv из этих токенов; sni= принимает домен
    const TLS_MODS = ['rnd', 'rndsni', 'dupsid', 'padencap', 'sni'];

    // ──────────────── Блоки опций (sub-arg groups, SKILL §8.8) ────────────────
    // Подключаются к desync-функциям. kind используется только для подсветки/группировки.
    // type: 'flag' (без значения) | 'int' | 'enum' | 'string' | 'hex'

    const SUBARG_GROUPS = {
        fooling: {
            label: 'fooling (обман DPI)',
            opts: {
                ip_ttl:          { type: 'int', desc: 'TTL IPv4-фейка', ex: ['1', '3', '8'] },
                ip6_ttl:         { type: 'int', desc: 'Hop limit IPv6-фейка', ex: ['1', '3', '8'] },
                ip_autottl:      { type: 'string', desc: 'Авто-TTL: <delta>,<min>-<max>', ex: ['-2,3-20'] },
                ip6_autottl:     { type: 'string', desc: 'Авто hop-limit IPv6', ex: ['-2,3-20'] },
                ip6_hopbyhop:    { type: 'flag', desc: 'IPv6 hop-by-hop заголовок (можно =hex)' },
                ip6_hopbyhop2:   { type: 'flag', desc: 'IPv6 hop-by-hop (вариант 2)' },
                ip6_destopt:     { type: 'flag', desc: 'IPv6 destination options' },
                ip6_destopt2:    { type: 'flag', desc: 'IPv6 destination options (вариант 2)' },
                ip6_routing:     { type: 'flag', desc: 'IPv6 routing header' },
                ip6_ah:          { type: 'flag', desc: 'IPv6 authentication header' },
                tcp_seq:         { type: 'int', desc: 'Смещение TCP seq (±)', ex: ['-10000', '1'] },
                tcp_ack:         { type: 'int', desc: 'Смещение TCP ack (±)', ex: ['-1'] },
                tcp_ts:          { type: 'int', desc: 'Смещение TCP timestamp (±)', ex: ['-5'] },
                tcp_md5:         { type: 'flag', desc: 'TCP MD5 signature (можно =16byte_hex)' },
                tcp_flags_set:   { type: 'string', desc: 'Установить флаги: FIN,SYN,…', ex: ['fin,syn'] },
                tcp_flags_unset: { type: 'string', desc: 'Снять флаги', ex: ['ack'] },
                tcp_ts_up:       { type: 'flag', desc: 'Увеличить TCP timestamp' },
                tcp_nop_del:     { type: 'flag', desc: 'Удалить NOP-опции TCP' },
                fool:            { type: 'lua-fool', desc: 'Кастомная Lua fool-функция', ex: ['z2k_dynamic_ttl'] },
                badsum:          { type: 'flag', desc: 'Неверная контрольная сумма' },
                badseq:          { type: 'flag', desc: 'Неверный TCP seq' },
            },
        },
        ipid: {
            label: 'ip_id',
            opts: {
                ip_id:      { type: 'enum', values: ['seq', 'rnd', 'zero', 'none'], desc: 'Стратегия IP ID' },
                ip_id_conn: { type: 'flag', desc: 'IP ID на соединение (=1)' },
            },
        },
        ipfrag: {
            label: 'ipfrag (IP-фрагментация)',
            opts: {
                ipfrag:          { type: 'flag', desc: 'Включить ipfrag2 (дефолт)' },
                ipfrag_disorder: { type: 'flag', desc: 'Фрагменты в обратном порядке' },
                ipfrag_pos_udp:  { type: 'int', desc: 'Позиция фрагмента UDP (кратно 8)', ex: ['8'] },
                ipfrag_pos_tcp:  { type: 'int', desc: 'Позиция фрагмента TCP (кратно 8)', ex: ['32'] },
                ipfrag_next:     { type: 'string', desc: 'Следующий протокол', ex: [] },
            },
        },
        reconstruct: {
            label: 'reconstruct',
            opts: {
                keepsum:           { type: 'flag', desc: 'Сохранить контрольную сумму' },
                ip6_preserve_next: { type: 'flag', desc: 'Сохранить IPv6 next-header' },
                ip6_last_proto:    { type: 'flag', desc: 'IPv6 последний протокол' },
            },
        },
        rawsend: {
            label: 'rawsend (отправка)',
            opts: {
                repeats: { type: 'int', desc: 'Повторов отправки', ex: ['2', '6', '11'] },
                fwmark:  { type: 'int', desc: 'fwmark для пакета', ex: [] },
                ifout:   { type: 'string', desc: 'Имя выходного интерфейса', ex: [] },
            },
        },
    };

    // Маркеры оркестрации — допустимы на ЛЮБОЙ desync-функции (без ошибки),
    // т.к. circular/condition помечают ими последующие инстансы (SKILL §9).
    const ORCH_MARKERS = {
        strategy: { type: 'int', desc: 'Номер подстратегии в circular (с 1)', ex: ['1', '2', '3'] },
        final:    { type: 'flag', desc: 'Финальная стратегия circular' },
        cond:     { type: 'lua-iff', desc: 'Условие для per_instance_condition' },
        cond_neg: { type: 'flag', desc: 'Инвертировать cond' },
    };

    // ──────────────── Lua iff / детекторы / хосткеи (значения для circular) ────────────────
    // Это НЕ desync-действия, а функции, на которые ссылаются circular/condition
    // через аргументы detector=/failure_detector=/success=/hostkey=/iff=/preload=.

    const IFF_FUNCS = [
        'cond_true', 'cond_false', 'cond_random', 'cond_payload_str',
        'cond_tcp_has_ts', 'cond_lua',
    ];
    const FAILURE_DETECTORS = [
        'standard_failure_detector', 'combined_failure_detector',
        'udp_aggressive_failure_detector', 'silent_drop_detector',
        'z2k_mid_stream_stall', 'z2k_http_mid_stream_stall',
        'z2k_tls_stalled', 'z2k_tls_alert_fatal', 'z2k_silent_drop_detector',
    ];
    const SUCCESS_DETECTORS = [
        'standard_success_detector', 'combined_success_detector',
        'udp_protocol_success_detector', 'z2k_http_success_positive_only',
        'z2k_success_no_reset', 'z2k_http_partial_response',
    ];
    const HOSTKEYS = [
        'standard_hostkey', 'get_grouped_hostname', 'udp_global_hostkey',
        'z2k_nohost_key',
    ];
    const PRELOADS = ['strategy_preload', 'strategy_preload_history'];
    const FOOL_FUNCS = ['z2k_dynamic_ttl'];

    // ──────────────── Desync-функции (--lua-desync=NAME) ────────────────
    // file — какой lua-скрипт её определяет (для подсказки и загрузки).
    // groups — какие блоки опций (fooling/ipid/…) принимает функция.
    // args — её собственные именованные аргументы.
    // payload — типичный payload-тип (для скелета/подсказки), необязательно.
    //
    // type аргумента: 'flag' | 'int' | 'enum' | 'string' | 'blob' | 'pos' |
    //                 'pattern' | 'payload' | 'tls_mod' | 'lua-detector' | …

    const G_FAKE = ['fooling', 'ipid', 'ipfrag', 'reconstruct', 'rawsend'];

    const LUA_FUNCS = {
        // ─── Базовые (zapret-antidpi.lua) ───
        fake: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'known',
            desc: 'Прямой фейк отдельным пакетом. Сегментация по MSS автоматическая.',
            groups: G_FAKE,
            args: {
                blob:     { type: 'blob', desc: 'Имя блоба фейка', required: false },
                payload:  { type: 'payload', desc: 'Тип payload (дефолт known)' },
                tls_mod:  { type: 'tls_mod', desc: 'Модификации TLS ClientHello' },
                dir:      { type: 'enum', values: ['in', 'out', 'any'], desc: 'Направление' },
                optional: { type: 'flag', desc: 'Не выносить вердикт при отсутствии payload' },
            },
        },
        multisplit: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Нарезать payload по списку маркеров (split).',
            groups: [],
            args: {
                pos:            { type: 'pos', desc: 'Маркеры разбиения (дефолт 2)' },
                seqovl:         { type: 'int', desc: 'Sequence overlap (байт)', ex: ['5', '681'] },
                seqovl_pattern: { type: 'pattern', desc: 'Паттерн/блоб для seqovl' },
                blob:           { type: 'blob', desc: 'Заменить payload' },
                optional:       { type: 'flag', desc: 'Необязательный' },
                nodrop:         { type: 'flag', desc: 'Не дропать оригинал' },
            },
        },
        multidisorder: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Как multisplit, но отправка в обратном порядке. Не работает с Windows-серверами.',
            groups: [],
            args: {
                pos:            { type: 'pos', desc: 'Маркеры (seqovl может быть маркером)' },
                seqovl:         { type: 'int', desc: 'Sequence overlap' },
                seqovl_pattern: { type: 'pattern', desc: 'Паттерн seqovl' },
                blob:           { type: 'blob', desc: 'Заменить payload' },
                optional:       { type: 'flag' }, nodrop: { type: 'flag' },
            },
        },
        multidisorder_legacy: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'multidisorder с поведением nfqws1 (backward-compat).',
            groups: [], args: { pos: { type: 'pos' }, seqovl: { type: 'int' } },
        },
        fakedsplit: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Split с замешиванием фейков. Требует fooling.',
            groups: G_FAKE,
            args: {
                pos:            { type: 'pos' },
                seqovl:         { type: 'int' },
                seqovl_pattern: { type: 'pattern' },
                pattern:        { type: 'pattern', desc: 'Паттерн фейка' },
                blob:           { type: 'blob' },
                optional:       { type: 'flag' }, nodrop: { type: 'flag' },
                nofake1:        { type: 'flag' }, nofake2: { type: 'flag' },
                nofake3:        { type: 'flag' }, nofake4: { type: 'flag' },
            },
        },
        fakeddisorder: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Disorder с замешиванием фейков. Требует fooling.',
            groups: G_FAKE,
            args: {
                pos: { type: 'pos' }, seqovl: { type: 'int' },
                seqovl_pattern: { type: 'pattern' }, pattern: { type: 'pattern' },
                blob: { type: 'blob' }, optional: { type: 'flag' }, nodrop: { type: 'flag' },
                nofake1: { type: 'flag' }, nofake2: { type: 'flag' },
                nofake3: { type: 'flag' }, nofake4: { type: 'flag' },
            },
        },
        hostfakesplit: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Резка http_req/tls_client_hello вокруг имени хоста.',
            groups: G_FAKE,
            args: {
                host:           { type: 'string', desc: 'random.template' },
                midhost:        { type: 'pos', desc: 'Маркер середины хоста' },
                disorder_after: { type: 'pos', desc: 'Маркер disorder' },
                nofake:         { type: 'flag' }, nofake2: { type: 'flag' },
                blob:           { type: 'blob' }, optional: { type: 'flag' }, nodrop: { type: 'flag' },
            },
        },
        tcpseg: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Отослать часть payload/reasm/blob между двумя маркерами. Вердикт не выносит.',
            groups: [],
            args: {
                pos:            { type: 'pos', desc: '2 маркера: m1,m2' },
                seqovl:         { type: 'int' },
                seqovl_pattern: { type: 'pattern' },
                blob:           { type: 'blob' },
                optional:       { type: 'flag' },
            },
        },
        oob: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Вставить 1 OOB-байт в TCP handshake. Требует --in-range=-s1.',
            groups: [],
            args: {
                char: { type: 'string', desc: 'OOB-символ' },
                byte: { type: 'int', desc: 'OOB-байт' },
                urp:  { type: 'enum', values: ['b', 'e'], desc: 'Позиция urgent pointer' },
            },
        },
        syndata: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'tls_client_hello',
            desc: 'Добавить payload в SYN (должен влезть в MTU). Стратегия нулевой фазы.',
            groups: ['fooling'],
            args: { blob: { type: 'blob' }, tls_mod: { type: 'tls_mod' } },
        },
        rst: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Отослать пустой RST (или RST+ACK при rstack).',
            groups: G_FAKE,
            args: {
                dir:     { type: 'enum', values: ['in', 'out', 'any'] },
                payload: { type: 'payload' },
                rstack:  { type: 'flag', desc: 'RST+ACK вместо RST' },
            },
        },
        wsize: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Менять tcp window и scale в SYN/ACK (только уменьшение).',
            groups: [],
            args: { wsize: { type: 'int' }, scale: { type: 'int' } },
        },
        wssize: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'window size по всем пакетам до cutoff. Снижает скорость!',
            groups: [],
            args: {
                dir: { type: 'enum', values: ['in', 'out', 'any'] },
                wsize: { type: 'int' }, scale: { type: 'int' },
                forced_cutoff: { type: 'int', desc: 'Cutoff в payload' },
            },
        },
        udplen: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Раздуть/обрезать UDP-payload.',
            groups: [],
            args: {
                dir: { type: 'enum', values: ['in', 'out', 'any'] },
                payload: { type: 'payload' },
                min: { type: 'int' }, max: { type: 'int' },
                increment: { type: 'int', ex: ['20'] },
                pattern: { type: 'pattern' },
                pattern_offset: { type: 'int' },
            },
        },
        dht_dn: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Заменить d1/d2 в DHT на dN.',
            groups: [], args: { dn: { type: 'string' } },
        },
        synack: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'SYN/ACK до SYN (TCB turnaround). Ломает NAT, требует nftables-POSTNAT.',
            groups: G_FAKE, args: {},
        },
        synack_split: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Вариация synack. Требует nftables-POSTNAT.',
            groups: G_FAKE, args: {},
        },
        tls_client_hello_clone: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Подготовить блоб с модифицированным TLS ClientHello.',
            groups: [],
            args: {
                blob: { type: 'blob' }, fallback: { type: 'string' },
                sni_del_ext: { type: 'flag' }, sni_del: { type: 'flag' },
                sni_snt: { type: 'string' }, sni_snt_new: { type: 'string' },
                sni_first: { type: 'flag' }, sni_last: { type: 'flag' },
            },
        },
        http_hostcase: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'http_req',
            desc: 'Менять регистр заголовка Host:.',
            groups: [], args: { spell: { type: 'string', ex: ['host'] } },
        },
        http_domcase: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'http_req',
            desc: 'Менять регистр имени домена в Host:.', groups: [], args: {},
        },
        http_methodeol: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'http_req',
            desc: '\\r\\n перед методом (nginx).', groups: [], args: {},
        },
        http_unixeol: {
            file: 'zapret-antidpi.lua', cat: 'core', payload: 'http_req',
            desc: '0D0A → 0A в HTTP.', groups: [], args: {},
        },
        drop: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'VERDICT_DROP (дроп пакета).',
            groups: [],
            args: { dir: { type: 'enum', values: ['in', 'out', 'any'] }, payload: { type: 'payload' } },
        },
        send: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Отправить текущий диссект (без дропа оригинала).',
            groups: G_FAKE,
            args: { dir: { type: 'enum', values: ['in', 'out', 'any'] }, delay: { type: 'int', desc: 'мс' } },
        },
        pktmod: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Применить fooling/ipid к диссекту (без отсылки и вердикта).',
            groups: ['fooling', 'ipid'], args: {},
        },
        pass: { file: 'zapret-antidpi.lua', cat: 'core', desc: 'No-op (для оркестраторов).', groups: [], args: {} },
        luaexec: {
            file: 'zapret-antidpi.lua', cat: 'core',
            desc: 'Выполнить Lua-выражение из code=.',
            groups: [], args: { code: { type: 'string', desc: 'Lua-код' } },
        },

        // ─── Оркестраторы (zapret-auto.lua + наш bundle) ───
        circular: {
            file: 'zapret-auto.lua', cat: 'orch',
            desc: 'Крутит подстратегии по кругу при неудачах. Требует входящих (--in-range=-s5556).',
            groups: [],
            args: {
                fails:            { type: 'int', desc: 'Фейлов до смены', ex: ['3'] },
                retrans:          { type: 'int', desc: 'Ретрансмиссий до смены', ex: ['3'] },
                nld:              { type: 'int', desc: 'Порог no-life-detect' },
                maxseq:           { type: 'int' },
                failure_detector: { type: 'lua-failure', desc: 'Детектор неудачи' },
                success_detector: { type: 'lua-success', desc: 'Детектор успеха' },
                detector:         { type: 'lua-failure', desc: 'Детектор (алиас)' },
                success:          { type: 'lua-success', desc: 'Детектор успеха (алиас)' },
                hostkey:          { type: 'lua-hostkey', desc: 'Группировка хостов' },
            },
        },
        circular_with_preload: {
            file: 'strategy-stats.lua', cat: 'orch',
            desc: 'circular + preload выученной стратегии (state.tsv).',
            groups: [],
            args: {
                fails: { type: 'int' }, retrans: { type: 'int' },
                failure_detector: { type: 'lua-failure' }, success_detector: { type: 'lua-success' },
                detector: { type: 'lua-failure' }, success: { type: 'lua-success' },
                hostkey: { type: 'lua-hostkey' }, preload: { type: 'lua-preload', desc: 'Функция preload' },
            },
        },
        repeater: {
            file: 'zapret-auto.lua', cat: 'orch',
            desc: 'Повторяет N последующих инстансов R раз.',
            groups: [],
            args: {
                instances: { type: 'int', desc: 'Сколько инстансов' },
                repeats:   { type: 'int', desc: 'Сколько раз' },
                stop:      { type: 'flag' }, clear: { type: 'flag' },
                iff:       { type: 'lua-iff', desc: 'Условие' }, neg: { type: 'flag' },
            },
        },
        condition: {
            file: 'zapret-auto.lua', cat: 'orch',
            desc: 'Выполнять следующие инстансы только если iff xor neg.',
            groups: [],
            args: {
                iff: { type: 'lua-iff' }, neg: { type: 'flag' },
                instances: { type: 'int' },
            },
        },
        per_instance_condition: {
            file: 'zapret-auto.lua', cat: 'orch',
            desc: 'Каждый следующий инстанс несёт свой cond=/cond_neg.',
            groups: [], args: {},
        },
        stopif: {
            file: 'zapret-auto.lua', cat: 'orch',
            desc: 'Очистить план при условии.',
            groups: [], args: { iff: { type: 'lua-iff' }, neg: { type: 'flag' } },
        },

        // ─── Расширения проекта (import/lua/*) ───
        hostfakesplit_stealth: { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (stealth).', groups: G_FAKE, args: {} },
        hostfakesplit_chaos:   { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (chaos).', groups: G_FAKE, args: {} },
        hostfakesplit_multi:   { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (multi).', groups: G_FAKE, args: {} },
        hostfakesplit_gradual: { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (gradual).', groups: G_FAKE, args: {} },
        hostfakesplit_decoy:   { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (decoy).', groups: G_FAKE, args: {} },
        hostfakesplit_blend:   { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (blend).', groups: G_FAKE, args: {} },
        hostfakesplit_soft:    { file: 'zapret-multishake.lua', cat: 'ext', desc: 'hostfakesplit (soft).', groups: G_FAKE, args: {} },
        snifakesplit:          { file: 'zapret-multishake.lua', cat: 'ext', desc: 'Резка вокруг SNI с фейком.', groups: G_FAKE, args: {} },
        fakemultisplit:    { file: 'fakemultisplit.lua', cat: 'ext', desc: 'fake + multisplit в одном инстансе.', groups: G_FAKE, args: { pos: { type: 'pos' }, blob: { type: 'blob' } } },
        fakemultidisorder: { file: 'fakemultidisorder.lua', cat: 'ext', desc: 'fake + multidisorder в одном инстансе.', groups: G_FAKE, args: { pos: { type: 'pos' }, blob: { type: 'blob' } } },
        wgobfs:   { file: 'zapret-obfs.lua', cat: 'ext', desc: 'WireGuard-обфускация.', groups: [], args: {} },
        ippxor:   { file: 'zapret-obfs.lua', cat: 'ext', desc: 'XOR IP-payload.', groups: [], args: {} },
        udp2icmp: { file: 'zapret-obfs.lua', cat: 'ext', desc: 'Туннель UDP в ICMP.', groups: [], args: {} },
        synhide:  { file: 'zapret-obfs.lua', cat: 'ext', desc: 'Скрыть SYN.', groups: [], args: {} },
        flood_white:    { file: 'zapret-16kb.lua', cat: 'ext', desc: 'Фейк-флуд белым SNI (16KB-обход).', groups: G_FAKE, args: { blob: { type: 'blob' }, repeats: { type: 'int' } } },
        ttl_ladder:     { file: 'zapret-16kb.lua', cat: 'ext', desc: 'TTL-лесенка фейков.', groups: G_FAKE, args: {} },
        white_sandwich: { file: 'zapret-16kb.lua', cat: 'ext', desc: 'Белый сэндвич (16KB-обход).', groups: G_FAKE, args: {} },
        seqovl_white:   { file: 'zapret-16kb.lua', cat: 'ext', desc: 'seqovl с белым паттерном.', groups: [], args: { seqovl: { type: 'int' } } },
        rst_flood:      { file: 'zapret-rst-flood.lua', cat: 'ext', desc: 'Флуд RST с подобранным TTL.', groups: ['fooling'], args: { repeats: { type: 'int' } } },
        z2k_ipfrag3:      { file: 'z2k-modern-core.lua', cat: 'ext', desc: '3-фрагментный IP-фрагментатор с overlap.', groups: [], args: {} },
        z2k_ipfrag3_tiny: { file: 'z2k-modern-core.lua', cat: 'ext', desc: '3-фрагментный (tiny).', groups: [], args: {} },
        z2k_timing_morph: { file: 'z2k-modern-core.lua', cat: 'ext', desc: 'Размытие сигнатур первых пакетов bad-checksum фейками.', groups: G_FAKE, args: {} },
        z2k_quic_morph_v2:{ file: 'z2k-modern-core.lua', cat: 'ext', payload: 'quic_initial', desc: 'QUIC Initial: фрагментация + морфинг version/CID/token + шум.', groups: [], args: {} },
        z2k_game_udp:     { file: 'z2k-modern-core.lua', cat: 'ext', desc: 'UDP fake-инъекция для игровых протоколов.', groups: [], args: { repeats: { type: 'int' } } },
        diag_once:   { file: 'custom_diag.lua', cat: 'ext', desc: 'Диагностический no-op (один раз).', groups: [], args: {} },
        diag_always: { file: 'custom_diag.lua', cat: 'ext', desc: 'Диагностический no-op (всегда).', groups: [], args: {} },
    };

    // custom_funcs.lua — расширенный каталог приёмов (http_*/tls_*/discord_*/…).
    // Регистрируем единообразно (groups=fake, без детальных args), чтобы они
    // распознавались автодополнением/линтером и не помечались ошибкой.
    const CUSTOM_FUNCS = [
        'decoy_hello', 'desync_combo', 'discord_ecn_exploit', 'discord_router_alert',
        'discord_timestamp_travel', 'discord_ultimate_combo', 'discord_urgent_sni',
        'discord_window_collapse', 'http_absolute_uri_v2', 'http_absolute_url',
        'http_aggressive', 'http_combo_bypass', 'http_fake_continuation', 'http_fake_xhost',
        'http_garbage_prefix', 'http_header_shuffle', 'http_host_bytesplit', 'http_hostmod',
        'http_inject_safe_header', 'http_ipfrag', 'http_lf_prefix', 'http_method_obfuscate',
        'http_methodeol_hostcase', 'http_methodeol_safe', 'http_methodeol_v2', 'http_mgts_combo',
        'http_mixed_prefix', 'http_multi_crlf', 'http_multidisorder', 'http_oob_prefix',
        'http_pipeline_fake', 'http_pipeline_fake_v2', 'http_seqovl_host', 'http_simple_bypass',
        'http_space_prefix', 'http_syndata', 'http_tab_prefix', 'http_triple_seqovl',
        'http_version_downgrade', 'http_xpadding', 'multisplit_tls', 'multisplitdisorder',
        'rst_desync', 'tls_aggressive', 'tls_disorder_gentle', 'tls_fake_disorder_gentle',
        'tls_fake_flood', 'tls_fake_simple', 'tls_fake_split', 'tls_multisplit_sni',
        'tls_split_gentle', 'tlsrec',
    ];
    CUSTOM_FUNCS.forEach((name) => {
        if (LUA_FUNCS[name]) return;
        const isHttp = name.indexOf('http') === 0;
        const isTls = name.indexOf('tls') === 0;
        LUA_FUNCS[name] = {
            file: 'custom_funcs.lua', cat: 'ext',
            desc: 'Приём проекта (custom_funcs).',
            payload: isHttp ? 'http_req' : (isTls ? 'tls_client_hello' : undefined),
            groups: G_FAKE,
            args: { blob: { type: 'blob' }, pos: { type: 'pos' }, repeats: { type: 'int' } },
        };
    });

    // ──────────────── CLI-флаги стратегии (--flag[=value]) ────────────────
    // slot — категория порядка/скелета. arg=null → флаг без значения.
    // arg.type: 'ports'|'enum'|'csv-enum'|'range'|'int'|'string'|'lua-chain'|
    //           'blob-decl'|'file:hostlist'|'file:ipset'|'csv-domains'|'csv-ip'

    const FLAGS = {
        '--new':         { slot: 'sep', cat: 'special', desc: 'Разделитель профилей (мультистратегия)', arg: { type: 'name', optional: true } },

        // фильтры профиля
        '--filter-l3':   { slot: 'filter', cat: 'filter', desc: 'Фильтр версии IP', arg: { type: 'enum', values: ['ipv4', 'ipv6'] } },
        '--filter-tcp':  { slot: 'filter', cat: 'filter', desc: 'Фильтр TCP-портов ([~]p1[-p2]|*)', arg: { type: 'ports', ex: ['80', '443', '80,443'] } },
        '--filter-udp':  { slot: 'filter', cat: 'filter', desc: 'Фильтр UDP-портов', arg: { type: 'ports', ex: ['443', '443,50000-50100'] } },
        '--filter-icmp': { slot: 'filter', cat: 'filter', desc: 'Фильтр ICMP type[:code]|*', arg: { type: 'string', ex: ['*'] } },
        '--filter-ipp':  { slot: 'filter', cat: 'filter', desc: 'Raw IP-протоколы', arg: { type: 'string' } },
        '--filter-l7':   { slot: 'filter', cat: 'filter', desc: 'Фильтр L7-протокола (csv)', arg: { type: 'csv-enum', values: L7_PROTOS } },
        '--filter-ssid': { slot: 'filter', cat: 'filter', desc: 'Wi-Fi SSID-фильтр (Linux)', arg: { type: 'string' } },

        // ipset / hostlist
        '--ipset':                 { slot: 'list', cat: 'list', desc: 'Include по IP/CIDR (файл)', arg: { type: 'file:ipset' } },
        '--ipset-ip':              { slot: 'list', cat: 'list', desc: 'Include по IP/CIDR (inline csv)', arg: { type: 'csv-ip' } },
        '--ipset-exclude':         { slot: 'list', cat: 'list', desc: 'Exclude по IP (файл)', arg: { type: 'file:ipset' } },
        '--ipset-exclude-ip':      { slot: 'list', cat: 'list', desc: 'Exclude по IP (inline csv)', arg: { type: 'csv-ip' } },
        '--hostlist':              { slot: 'list', cat: 'list', desc: 'Десинк только для хостов из файла', arg: { type: 'file:hostlist' } },
        '--hostlist-domains':      { slot: 'list', cat: 'list', desc: 'Хосты inline (csv)', arg: { type: 'csv-domains' } },
        '--hostlist-exclude':      { slot: 'list', cat: 'list', desc: 'Исключения хостов (файл)', arg: { type: 'file:hostlist' } },
        '--hostlist-exclude-domains': { slot: 'list', cat: 'list', desc: 'Исключения inline (csv)', arg: { type: 'csv-domains' } },
        '--hostlist-auto':         { slot: 'list', cat: 'list', desc: 'Автохостлист (файл)', arg: { type: 'file:hostlist' } },
        '--hostlist-auto-fail-threshold':    { slot: 'list', cat: 'list', desc: 'Фейлов для добавления (дефолт 3)', arg: { type: 'int' } },
        '--hostlist-auto-fail-time':         { slot: 'list', cat: 'list', desc: 'В пределах N сек (дефолт 60)', arg: { type: 'int' } },
        '--hostlist-auto-retrans-threshold': { slot: 'list', cat: 'list', desc: 'Ретрансмиссий = провал (дефолт 3)', arg: { type: 'int' } },
        '--hostlist-auto-debug':   { slot: 'list', cat: 'list', desc: 'Лог срабатываний автохостлиста', arg: { type: 'string' } },

        // внутрипрофильные фильтры (range/payload)
        '--out-range':   { slot: 'range', cat: 'range', desc: 'Диапазон по исходящему направлению', arg: { type: 'range', ex: ['-d10', '-s34228'] } },
        '--in-range':    { slot: 'range', cat: 'range', desc: 'Диапазон по входящему направлению', arg: { type: 'range', ex: ['-s5556', 'x'] } },
        '--payload':     { slot: 'range', cat: 'payload', desc: 'Какие payload-типы обрабатывают следующие функции', arg: { type: 'csv-enum', values: PAYLOAD_TYPES } },

        // действие
        '--lua-desync':  { slot: 'desync', cat: 'desync', desc: 'Вызов Lua-инстанса (desync-функция)', arg: { type: 'lua-chain' } },

        // глобальные декларации (до первого --new)
        '--blob':        { slot: 'global', cat: 'global', desc: 'Декларация именованного блоба (NAME:@file|0xHEX)', arg: { type: 'blob-decl' } },

        // профильные служебные
        '--name':        { slot: 'filter', cat: 'special', desc: 'Имя профиля', arg: { type: 'name' } },
        '--skip':        { slot: 'filter', cat: 'special', desc: 'Не использовать профиль', arg: null },
        '--template':    { slot: 'filter', cat: 'special', desc: 'Сделать профиль шаблоном', arg: { type: 'name', optional: true } },
        '--import':      { slot: 'filter', cat: 'special', desc: 'Импорт настроек из шаблона', arg: { type: 'name' } },
        '--cookie':      { slot: 'filter', cat: 'special', desc: 'desync.cookie для инстансов профиля', arg: { type: 'string', optional: true } },

        // ─── Глобальные / служебные (до первого --new) ───
        // Часть из них GUI ставит сам (--qnum/--debug/--user/--fwmark/
        // --lua-init), но ipcache-*/ctrack-*/server и т.п. легитимно
        // встречаются в стратегиях и наших пресетах. Редактор обязан их
        // знать — иначе ложная ошибка «неизвестный флаг» (напр. на
        // --ipcache-hostname=1, который есть в builtin-пресетах).
        // Список сверен с bol-van/zapret2 v1.0.1 (docs/manual.md, `-?`).
        '--ipcache-hostname':  { slot: 'global', cat: 'service', desc: 'Кэшировать ip→hostname (нужно стратегиям нулевой фазы: wssize/syndata с хостлистами)', arg: { type: 'enum', values: ['0', '1'], optional: true } },
        '--ipcache-lifetime':  { slot: 'global', cat: 'service', desc: 'TTL кэша ip→hostname, сек (дефолт 7200, 0 = без ограничений)', arg: { type: 'int', ex: ['7200', '8400'] } },
        '--ctrack-timeouts':   { slot: 'global', cat: 'service', desc: 'Таймауты внутр. conntrack: TCP SYN:ESTABLISHED:FIN[:UDP] (дефолт 60:300:60:60)', arg: { type: 'string', ex: ['60:300:60:60'] } },
        '--ctrack-disable':    { slot: 'global', cat: 'service', desc: 'Отключить внутренний conntrack', arg: { type: 'enum', values: ['0', '1'], optional: true } },
        '--server':            { slot: 'global', cat: 'service', desc: 'Серверный режим (инверсия направлений и фильтрации)', arg: { type: 'enum', values: ['0', '1'], optional: true } },
        '--payload-disable':   { slot: 'global', cat: 'service', desc: 'Не детектировать указанные payload-типы (без аргумента — все)', arg: { type: 'csv-enum', values: PAYLOAD_TYPES, optional: true } },
        '--reasm-disable':     { slot: 'global', cat: 'service', desc: 'Отключить reasm для типов (tls_client_hello, quic_initial)', arg: { type: 'csv-enum', values: ['tls_client_hello', 'quic_initial'], optional: true } },
        '--fwmark':            { slot: 'global', cat: 'service', desc: 'fwmark anti-loop (дефолт 0x40000000). Обычно ставит GUI', arg: { type: 'string', ex: ['0x40000000'] } },
        '--bind-fix4':         { slot: 'global', cat: 'service', desc: 'Фикс выбора исходящего интерфейса IPv4 (PBR/multi-WAN). Обычно ставит GUI', arg: null },
        '--bind-fix6':         { slot: 'global', cat: 'service', desc: 'Фикс выбора исходящего интерфейса IPv6. Обычно ставит GUI', arg: null },
        '--lua-init':          { slot: 'global', cat: 'service', desc: 'Загрузить Lua (@файл|текст). Обычно ставит GUI (core + extension)', arg: { type: 'string', ex: ['@/opt/zapret2/lua/zapret-lib.lua'] } },
        '--lua-gc':            { slot: 'global', cat: 'service', desc: 'Интервал GC Lua, сек (дефолт 60)', arg: { type: 'int' } },
        '--writable':          { slot: 'global', cat: 'service', desc: 'Каталог с правом записи для Lua (env WRITABLE). До zapret2 1.0 — --writeable', arg: { type: 'string', optional: true } },
        '--comment':           { slot: 'global', cat: 'service', desc: 'No-op, для читабельности конфига', arg: { type: 'string', optional: true } },

        // доп. параметры автохостлиста (slot list, как остальные --hostlist-auto-*)
        '--hostlist-auto-incoming-maxseq': { slot: 'list', cat: 'list', desc: 'Успех если входящий rel-seq > N (дефолт 4096)', arg: { type: 'int' } },
        '--hostlist-auto-retrans-maxseq':  { slot: 'list', cat: 'list', desc: 'Макс. rel-seq ретрансмиссии (дефолт 32768)', arg: { type: 'int' } },
        '--hostlist-auto-retrans-reset':   { slot: 'list', cat: 'list', desc: 'Слать RST ретрансмиттеру (дефолт 1)', arg: { type: 'enum', values: ['0', '1'], optional: true } },
        '--hostlist-auto-udp-out':         { slot: 'list', cat: 'list', desc: 'UDP-провал по исходящим (дефолт 4)', arg: { type: 'int' } },
        '--hostlist-auto-udp-in':          { slot: 'list', cat: 'list', desc: 'UDP-провал по входящим (дефолт 1)', arg: { type: 'int' } },
    };

    // Порядок слотов (для скелета и предупреждений о порядке)
    const SLOT_ORDER = ['global', 'sep', 'filter', 'list', 'range', 'desync'];
    const SLOT_LABELS = {
        global: 'Блобы/глоб.', sep: '--new', filter: 'Фильтр профиля',
        list: 'Домены/IP', range: 'Диапазон/payload', desync: 'Действие (desync)',
    };

    // ──────────────── Lookups ────────────────

    function flag(name) { return FLAGS[name] || null; }
    function func(name) { return LUA_FUNCS[name] || null; }
    function isKnownFlag(name) { return Object.prototype.hasOwnProperty.call(FLAGS, name); }
    function isKnownFunc(name) { return Object.prototype.hasOwnProperty.call(LUA_FUNCS, name); }

    function allFlagNames() { return Object.keys(FLAGS); }
    function allFuncNames() { return Object.keys(LUA_FUNCS); }

    // Полный набор допустимых sub-arg для функции: её args + опции групп +
    // оркестрационные маркеры. Возвращает map name → {type, values?, desc, kind}.
    function subargsFor(funcName) {
        const fn = LUA_FUNCS[funcName];
        const out = {};
        if (fn) {
            for (const [k, v] of Object.entries(fn.args || {})) {
                out[k] = Object.assign({ kind: 'arg' }, v);
            }
            for (const g of (fn.groups || [])) {
                const grp = SUBARG_GROUPS[g];
                if (!grp) continue;
                for (const [k, v] of Object.entries(grp.opts)) {
                    if (!out[k]) out[k] = Object.assign({ kind: g }, v);
                }
            }
        }
        // Оркестрационные маркеры — всегда допустимы (см. ORCH_MARKERS).
        for (const [k, v] of Object.entries(ORCH_MARKERS)) {
            if (!out[k]) out[k] = Object.assign({ kind: 'orch' }, v);
        }
        return out;
    }

    // Список значений для типа sub-arg (для подсказок detector=/hostkey=/…).
    function valuesForSubargType(type) {
        switch (type) {
            case 'lua-failure': return FAILURE_DETECTORS;
            case 'lua-success': return SUCCESS_DETECTORS;
            case 'lua-hostkey': return HOSTKEYS;
            case 'lua-preload': return PRELOADS;
            case 'lua-iff':     return IFF_FUNCS;
            case 'lua-fool':    return FOOL_FUNCS;
            default: return null;
        }
    }

    return {
        PAYLOAD_TYPES, L7_PROTOS, POS_MARKERS, RANGE_MODES, TLS_MODS,
        SUBARG_GROUPS, ORCH_MARKERS, LUA_FUNCS, FLAGS,
        IFF_FUNCS, FAILURE_DETECTORS, SUCCESS_DETECTORS, HOSTKEYS, PRELOADS, FOOL_FUNCS,
        SLOT_ORDER, SLOT_LABELS,
        flag, func, isKnownFlag, isKnownFunc, allFlagNames, allFuncNames,
        subargsFor, valuesForSubargType,
    };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = Nfqws2Spec;
