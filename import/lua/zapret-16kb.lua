--[[
ZAPRET 16KB BLOCK BYPASS

Специальные функции для обхода "16 КБ" блокировки на Cloudflare/Ростелеком.
Идея: засыпать ТСПУ фейками с белым SNI, чтобы он думал что соединение "белое".

Использование:
--lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua --lua-init=@zapret-16kb.lua
--lua-desync=flood_white:blob=bin_max:count=10:badsum:pos=1,midsld

]]

-- Отправить один фейк с указанными опциями
local function send_one_fake(desync, payload, opts)
    local dis = deepcopy(desync.dis)
    dis.payload = payload
    if opts.fooling then
        for k,v in pairs(opts.fooling) do
            dis[k] = v
        end
    end
    apply_fooling(desync, dis)
    return rawsend_dissect(dis, opts)
end

-- Создать payload с белым SNI
local function make_white_payload(desync)
    local white = blob(desync, desync.arg.blob or desync.arg.white_blob)
    if not white then
        error("flood_white: blob required")
    end
    if desync.arg.tls_mod then
        white = tls_mod_shim(desync, white, desync.arg.tls_mod, nil)
    end
    return white
end

--[[
flood_white - засыпать ТСПУ белыми фейками перед реальным пакетом

Аргументы:
- blob - TLS ClientHello с белым SNI (например bin_max с max.ru)
- tls_mod - модификация SNI (например sni=hp.com)
- count - количество фейков (по умолчанию 10)
- pos - позиции разреза для реального пакета (по умолчанию 1,midsld)
- badsum, ip_ttl, tcp_md5 и другие fooling параметры

Пример:
--lua-desync=flood_white:blob=bin_max:count=15:badsum:pos=1,midsld
]]
function flood_white(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end

    direction_cutoff_opposite(ctx, desync)

    if not direction_check(desync) or not payload_check(desync) then
        return
    end

    if not replay_first(desync) then
        if replay_drop(desync) then
            return VERDICT_DROP
        end
        return
    end

    -- Создаём белый payload
    local white = make_white_payload(desync)
    local count = tonumber(desync.arg.count) or 10

    DLOG("flood_white: sending "..count.." white fakes")

    -- Флудим белыми фейками
    for i = 1, count do
        local dis = deepcopy(desync.dis)
        dis.payload = white
        apply_fooling(desync, dis)
        if b_debug then
            DLOG("flood_white: fake #"..i)
        end
        rawsend_dissect(dis, {rawsend = {repeats = 1}})
    end

    -- Теперь отправляем реальный пакет через multisplit
    local data = desync.reasm_data or desync.dis.payload
    local spos = desync.arg.pos or "1,midsld"

    if b_debug then
        DLOG("flood_white: splitting real payload at "..spos)
    end

    local pos = resolve_multi_pos(data, desync.l7payload, spos)
    delete_pos_1(pos)

    if #pos > 0 then
        for i = 0, #pos do
            local pos_start = pos[i] or 1
            local pos_end = i < #pos and pos[i+1] - 1 or #data
            local part = string.sub(data, pos_start, pos_end)

            if b_debug then
                DLOG("flood_white: sending part "..(i+1))
            end

            if not rawsend_payload_segmented(desync, part, pos_start - 1) then
                return VERDICT_PASS
            end
        end
        replay_drop_set(desync)
        return VERDICT_DROP
    else
        DLOG("flood_white: no split positions, sending as-is")
        rawsend_payload_segmented(desync)
        return VERDICT_DROP
    end
end

--[[
ttl_ladder - отправить фейки с возрастающим TTL

Идея: ТСПУ может быть на разных хопах. Отправляем фейки с TTL от min до max,
чтобы хотя бы один дошёл до ТСПУ но не до сервера.

Аргументы:
- blob - TLS ClientHello с белым SNI
- ttl_min - минимальный TTL (по умолчанию 3)
- ttl_max - максимальный TTL (по умолчанию 12)
- pos - позиции разреза для реального пакета

Пример:
--lua-desync=ttl_ladder:blob=bin_max:ttl_min=4:ttl_max=10:pos=1,midsld
]]
function ttl_ladder(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end

    direction_cutoff_opposite(ctx, desync)

    if not direction_check(desync) or not payload_check(desync) then
        return
    end

    if not replay_first(desync) then
        if replay_drop(desync) then
            return VERDICT_DROP
        end
        return
    end

    local white = make_white_payload(desync)
    local ttl_min = tonumber(desync.arg.ttl_min) or 3
    local ttl_max = tonumber(desync.arg.ttl_max) or 12

    DLOG("ttl_ladder: sending fakes with TTL "..ttl_min.."-"..ttl_max)

    -- Отправляем фейки с разными TTL
    for ttl = ttl_min, ttl_max do
        local dis = deepcopy(desync.dis)
        dis.payload = white
        dis.ip_ttl = ttl
        if desync.dis.ipv6 then
            dis.ip6_ttl = ttl
        end
        if b_debug then
            DLOG("ttl_ladder: fake TTL="..ttl)
        end
        rawsend_dissect(dis, {rawsend = {repeats = 1}})
    end

    -- Отправляем реальный пакет
    local data = desync.reasm_data or desync.dis.payload
    local spos = desync.arg.pos or "1,midsld"
    local pos = resolve_multi_pos(data, desync.l7payload, spos)
    delete_pos_1(pos)

    if #pos > 0 then
        for i = 0, #pos do
            local pos_start = pos[i] or 1
            local pos_end = i < #pos and pos[i+1] - 1 or #data
            local part = string.sub(data, pos_start, pos_end)
            if not rawsend_payload_segmented(desync, part, pos_start - 1) then
                return VERDICT_PASS
            end
        end
        replay_drop_set(desync)
        return VERDICT_DROP
    else
        rawsend_payload_segmented(desync)
        return VERDICT_DROP
    end
end

--[[
white_sandwich - "сэндвич" из белых фейков вокруг реального пакета

Идея: отправить белые фейки ДО и ПОСЛЕ каждого сегмента реального пакета.
ТСПУ видит: белый-белый-реальный-белый-белый и может запутаться.

Аргументы:
- blob - TLS ClientHello с белым SNI
- before - фейков до сегмента (по умолчанию 3)
- after - фейков после сегмента (по умолчанию 3)
- pos - позиции разреза
- badsum, ip_ttl и другие fooling

Пример:
--lua-desync=white_sandwich:blob=bin_max:before=5:after=2:badsum:pos=1,midsld
]]
function white_sandwich(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end

    direction_cutoff_opposite(ctx, desync)

    if not direction_check(desync) or not payload_check(desync) then
        return
    end

    if not replay_first(desync) then
        if replay_drop(desync) then
            return VERDICT_DROP
        end
        return
    end

    local white = make_white_payload(desync)
    local before = tonumber(desync.arg.before) or 3
    local after = tonumber(desync.arg.after) or 3

    local data = desync.reasm_data or desync.dis.payload
    local spos = desync.arg.pos or "1,midsld"
    local pos = resolve_multi_pos(data, desync.l7payload, spos)
    delete_pos_1(pos)

    DLOG("white_sandwich: before="..before..", after="..after)

    -- Функция отправки фейков
    local function send_fakes(count, label)
        for i = 1, count do
            local dis = deepcopy(desync.dis)
            dis.payload = white
            apply_fooling(desync, dis)
            if b_debug then
                DLOG("white_sandwich: "..label.." fake #"..i)
            end
            rawsend_dissect(dis, {rawsend = {repeats = 1}})
        end
    end

    if #pos > 0 then
        for i = 0, #pos do
            local pos_start = pos[i] or 1
            local pos_end = i < #pos and pos[i+1] - 1 or #data
            local part = string.sub(data, pos_start, pos_end)

            -- Фейки ДО сегмента
            send_fakes(before, "before")

            -- Реальный сегмент
            if b_debug then
                DLOG("white_sandwich: real segment "..(i+1))
            end
            if not rawsend_payload_segmented(desync, part, pos_start - 1) then
                return VERDICT_PASS
            end

            -- Фейки ПОСЛЕ сегмента
            send_fakes(after, "after")
        end
        replay_drop_set(desync)
        return VERDICT_DROP
    else
        send_fakes(before, "before")
        rawsend_payload_segmented(desync)
        send_fakes(after, "after")
        return VERDICT_DROP
    end
end

--[[
seqovl_white - sequence overlap где overlap-часть содержит белый SNI

Идея: при seqovl первая часть пакета отправляется дважды - оригинал и с overlap.
Если overlap содержит белый SNI, ТСПУ может принять его за белое соединение.

Аргументы:
- blob - TLS ClientHello с белым SNI (берём первые N байт)
- ovl_size - размер overlap (по умолчанию 200)
- pos - позиции разреза
- badsum и другие fooling для overlap-пакета

Пример:
--lua-desync=seqovl_white:blob=bin_max:ovl_size=150:pos=1,midsld
]]
function seqovl_white(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end

    direction_cutoff_opposite(ctx, desync)

    if not direction_check(desync) or not payload_check(desync) then
        return
    end

    if not replay_first(desync) then
        if replay_drop(desync) then
            return VERDICT_DROP
        end
        return
    end

    local white = make_white_payload(desync)
    local ovl_size = tonumber(desync.arg.ovl_size) or 200
    local data = desync.reasm_data or desync.dis.payload

    -- Берём первые ovl_size байт белого payload
    local white_prefix = string.sub(white, 1, ovl_size)

    DLOG("seqovl_white: overlap size="..ovl_size)

    -- Отправляем overlap-пакет с белым содержимым
    local dis_ovl = deepcopy(desync.dis)
    dis_ovl.payload = white_prefix
    dis_ovl.tcp_seq = desync.dis.tcp_seq - ovl_size  -- Смещаем seq назад
    apply_fooling(desync, dis_ovl)

    if b_debug then
        DLOG("seqovl_white: sending white overlap")
    end
    rawsend_dissect(dis_ovl, {rawsend = {repeats = 1}})

    -- Теперь отправляем реальный пакет с разрезом
    local spos = desync.arg.pos or "1,midsld"
    local pos = resolve_multi_pos(data, desync.l7payload, spos)
    delete_pos_1(pos)

    if #pos > 0 then
        for i = 0, #pos do
            local pos_start = pos[i] or 1
            local pos_end = i < #pos and pos[i+1] - 1 or #data
            local part = string.sub(data, pos_start, pos_end)

            if b_debug then
                DLOG("seqovl_white: sending part "..(i+1))
            end

            if not rawsend_payload_segmented(desync, part, pos_start - 1) then
                return VERDICT_PASS
            end
        end
        replay_drop_set(desync)
        return VERDICT_DROP
    else
        rawsend_payload_segmented(desync)
        return VERDICT_DROP
    end
end

-- Регистрация функций для использования через --lua-desync
DLOG("zapret-16kb.lua loaded: flood_white, ttl_ladder, white_sandwich, seqovl_white")
