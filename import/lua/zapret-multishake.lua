--[[

NFQWS2 MULTISHAKE - Advanced Stealth Fakesplit Variants

Менее агрессивные и более скрытные варианты hostfakesplit.

Usage:
--lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua --lua-init=@zapret-multishake.lua

ВАЖНО: Используй те же fooling параметры что работают у тебя!
Если работает: hostfakesplit:host=vimeo.com:tcp_ts=-1000:tcp_md5:repeats=4
То используй:  hostfakesplit_stealth:host=vimeo.com:tcp_ts=-1000:tcp_md5:repeats=2:mode=soft

ФУНКЦИИ:

hostfakesplit_stealth - менее агрессивный hostfakesplit
  mode=soft     - только 1 фейк вместо 2
  mode=blend    - фейк похож на настоящий домен (меняем часть букв)
  mode=minimal  - фейк только для длинных SNI
  mode=random   - случайно 0-2 фейка

hostfakesplit_chaos - хаотичный порядок сегментов

hostfakesplit_multi - несколько разных фейковых доменов
  hosts=google.com,vimeo.com,amazon.com

hostfakesplit_gradual - фейк и реал разбиты на части и чередуются
  parts=3

hostfakesplit_decoy - дополнительные мусорные пакеты
  decoys=2
  decoy_size=50

]]


-- ============================================================================
-- HOSTFAKESPLIT_STEALTH - менее агрессивный hostfakesplit
-- ============================================================================

--[[
hostfakesplit_stealth - скрытная версия hostfakesplit

Отличия от обычного hostfakesplit:
- mode=soft: только 1 фейк вместо 2, меньше repeats
- mode=blend: фейк похож на настоящий домен (подменяем только часть букв)
- mode=minimal: фейк отправляется только если SNI длинный
- mode=random: случайно выбирает сколько фейков отправить (0-2)

standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
arg : host=<str> - шаблон фейкового хоста
arg : midhost=<posmarker> - разбить SNI
arg : mode=soft|blend|minimal|random - режим скрытности
arg : min_sni=N - для mode=minimal, минимальная длина SNI (по умолчанию 15)
arg : nodrop
]]
function hostfakesplit_stealth(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end
    direction_cutoff_opposite(ctx, desync)
    if desync.arg.optional and desync.arg.blob and not blob_exist(desync, desync.arg.blob) then
        DLOG("hostfakesplit_stealth: blob '"..desync.arg.blob.."' not found. skipped")
        return
    end
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                if b_debug then DLOG("hostfakesplit_stealth: resolved host range: "..table.concat(zero_based_pos(pos), " ")) end

                local mode = desync.arg.mode or "soft"
                local sni_len = pos[2] - pos[1] + 1
                local real_sni = string.sub(data, pos[1], pos[2])
                
                -- режим minimal - пропускаем короткие SNI
                if mode == "minimal" then
                    local min_sni = tonumber(desync.arg.min_sni) or 15
                    if sni_len < min_sni then
                        DLOG("hostfakesplit_stealth: SNI too short ("..sni_len.." < "..min_sni.."), passing through")
                        return
                    end
                end
                
                -- определяем сколько фейков отправлять
                local send_fake1, send_fake2 = true, true
                if mode == "soft" then
                    send_fake1 = true
                    send_fake2 = false  -- только 1 фейк
                elseif mode == "random" then
                    local rnd = math.random(100)
                    if rnd < 25 then
                        send_fake1, send_fake2 = false, false  -- 25% - без фейков
                    elseif rnd < 60 then
                        send_fake1, send_fake2 = true, false   -- 35% - 1 фейк
                    else
                        send_fake1, send_fake2 = true, true    -- 40% - 2 фейка
                    end
                    DLOG("hostfakesplit_stealth: random mode, fake1="..tostring(send_fake1).." fake2="..tostring(send_fake2))
                end
                
                -- ручное отключение фейков
                if desync.arg.nofake1 then send_fake1 = false end
                if desync.arg.nofake2 then send_fake2 = false end

                -- генерируем фейковый хост
                local fakehost
                if mode == "blend" then
                    -- подменяем только часть букв в настоящем SNI
                    fakehost = ""
                    for i = 1, sni_len do
                        local c = string.sub(real_sni, i, i)
                        if c ~= "." and math.random(100) < 40 then
                            -- 40% шанс заменить букву
                            fakehost = fakehost .. string.char(math.random(97, 122))
                        else
                            fakehost = fakehost .. c
                        end
                    end
                    DLOG("hostfakesplit_stealth: blend mode, fake="..fakehost)
                else
                    fakehost = genhost(sni_len, desync.arg.host)
                end

                local part
                local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
                local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

                -- часть до хоста
                part = string.sub(data, 1, pos[1] - 1)
                if b_debug then DLOG("hostfakesplit_stealth: sending before_host 0-"..(pos[1]-2).." len="..#part) end
                if not rawsend_payload_segmented(desync, part, 0, opts_orig) then return VERDICT_PASS end

                -- фейк 1
                if send_fake1 then
                    if b_debug then DLOG("hostfakesplit_stealth: sending fake1 "..(pos[1]-1).."-"..(pos[2]-1)) end
                    if not rawsend_payload_segmented(desync, fakehost, pos[1] - 1, opts_fake) then return VERDICT_PASS end
                end

                -- настоящий хост (с возможным разбиением)
                local midhost
                if desync.arg.midhost then
                    midhost = resolve_pos(data, desync.l7payload, desync.arg.midhost)
                    if midhost and (midhost <= pos[1] or midhost > pos[2]) then
                        midhost = nil
                    end
                end

                if midhost then
                    part = string.sub(data, pos[1], midhost - 1)
                    if b_debug then DLOG("hostfakesplit_stealth: sending real host part1 "..(pos[1]-1).."-"..(midhost-2)) end
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end

                    part = string.sub(data, midhost, pos[2])
                    if b_debug then DLOG("hostfakesplit_stealth: sending real host part2 "..(midhost-1).."-"..(pos[2]-1)) end
                    if not rawsend_payload_segmented(desync, part, midhost - 1, opts_orig) then return VERDICT_PASS end
                else
                    part = string.sub(data, pos[1], pos[2])
                    if b_debug then DLOG("hostfakesplit_stealth: sending real host "..(pos[1]-1).."-"..(pos[2]-1)) end
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end
                end

                -- фейк 2
                if send_fake2 then
                    if b_debug then DLOG("hostfakesplit_stealth: sending fake2 "..(pos[1]-1).."-"..(pos[2]-1)) end
                    if not rawsend_payload_segmented(desync, fakehost, pos[1] - 1, opts_fake) then return VERDICT_PASS end
                end

                -- остаток
                part = string.sub(data, pos[2] + 1)
                if b_debug then DLOG("hostfakesplit_stealth: sending after_host "..pos[2].."-"..(#data-1)) end
                if not rawsend_payload_segmented(desync, part, pos[2], opts_orig) then return VERDICT_PASS end

                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            else
                DLOG("hostfakesplit_stealth: host range cannot be resolved")
            end
        else
            DLOG("hostfakesplit_stealth: not acting on further replay pieces")
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
end


-- ============================================================================
-- HOSTFAKESPLIT_CHAOS - хаотичный порядок сегментов с фейками
-- ============================================================================

--[[
hostfakesplit_chaos - hostfakesplit с перемешанным порядком отправки

Вместо фиксированного порядка (before -> fake1 -> real -> fake2 -> after)
отправляет сегменты в хаотичном порядке, сохраняя правильные seq numbers.

standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
arg : host=<str> - шаблон фейкового хоста
arg : midhost=<posmarker> - разбить SNI
arg : order=<str> - порядок: числа 1,2,3,4,5 (1=before, 2=fake1, 3=real, 4=fake2, 5=after)
                    по умолчанию: случайный
arg : nofake1, nofake2
arg : nodrop
]]
function hostfakesplit_chaos(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end
    direction_cutoff_opposite(ctx, desync)
    if desync.arg.optional and desync.arg.blob and not blob_exist(desync, desync.arg.blob) then
        DLOG("hostfakesplit_chaos: blob '"..desync.arg.blob.."' not found. skipped")
        return
    end
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                if b_debug then DLOG("hostfakesplit_chaos: resolved host range: "..table.concat(zero_based_pos(pos), " ")) end

                local sni_len = pos[2] - pos[1] + 1
                local fakehost = genhost(sni_len, desync.arg.host)

                local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
                local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

                -- подготавливаем все сегменты
                local segments = {}
                
                -- 1: before_host
                segments[1] = {
                    name = "before",
                    data = string.sub(data, 1, pos[1] - 1),
                    offset = 0,
                    opts = opts_orig,
                    enabled = true
                }
                
                -- 2: fake1
                segments[2] = {
                    name = "fake1",
                    data = fakehost,
                    offset = pos[1] - 1,
                    opts = opts_fake,
                    enabled = not desync.arg.nofake1
                }
                
                -- 3: real host
                segments[3] = {
                    name = "real",
                    data = string.sub(data, pos[1], pos[2]),
                    offset = pos[1] - 1,
                    opts = opts_orig,
                    enabled = true
                }
                
                -- 4: fake2
                segments[4] = {
                    name = "fake2",
                    data = fakehost,
                    offset = pos[1] - 1,
                    opts = opts_fake,
                    enabled = not desync.arg.nofake2
                }
                
                -- 5: after_host
                segments[5] = {
                    name = "after",
                    data = string.sub(data, pos[2] + 1),
                    offset = pos[2],
                    opts = opts_orig,
                    enabled = true
                }

                -- определяем порядок отправки
                local order
                if desync.arg.order then
                    order = {}
                    for num in string.gmatch(desync.arg.order, "(%d+)") do
                        table.insert(order, tonumber(num))
                    end
                else
                    -- случайный порядок
                    order = {1, 2, 3, 4, 5}
                    for i = 5, 2, -1 do
                        local j = math.random(i)
                        order[i], order[j] = order[j], order[i]
                    end
                end

                if b_debug then DLOG("hostfakesplit_chaos: order="..table.concat(order, ",")) end

                -- отправляем в заданном порядке
                for _, idx in ipairs(order) do
                    local seg = segments[idx]
                    if seg and seg.enabled and #seg.data > 0 then
                        if b_debug then DLOG("hostfakesplit_chaos: sending "..seg.name.." offset="..seg.offset.." len="..#seg.data) end
                        if not rawsend_payload_segmented(desync, seg.data, seg.offset, seg.opts) then 
                            return VERDICT_PASS 
                        end
                    end
                end

                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            else
                DLOG("hostfakesplit_chaos: host range cannot be resolved")
            end
        else
            DLOG("hostfakesplit_chaos: not acting on further replay pieces")
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
end


-- ============================================================================
-- HOSTFAKESPLIT_MULTI - множественные фейки с разными доменами
-- ============================================================================

--[[
hostfakesplit_multi - отправка нескольких разных фейковых SNI

Вместо одного фейка отправляет несколько с разными доменами,
чтобы запутать DPI больше.

standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
arg : hosts=<str> - список доменов через запятую: google.com,vimeo.com,amazon.com
arg : midhost=<posmarker>
arg : nodrop
]]
function hostfakesplit_multi(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end
    direction_cutoff_opposite(ctx, desync)
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                if b_debug then DLOG("hostfakesplit_multi: resolved host range: "..table.concat(zero_based_pos(pos), " ")) end

                local sni_len = pos[2] - pos[1] + 1
                
                -- парсим список хостов
                local hosts = {}
                local hosts_str = desync.arg.hosts or "google.com,vimeo.com,amazon.com"
                for host in string.gmatch(hosts_str, "([^,]+)") do
                    table.insert(hosts, host)
                end

                local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
                local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

                local part

                -- before host
                part = string.sub(data, 1, pos[1] - 1)
                if b_debug then DLOG("hostfakesplit_multi: sending before_host") end
                if not rawsend_payload_segmented(desync, part, 0, opts_orig) then return VERDICT_PASS end

                -- фейки ДО настоящего SNI
                for i, host in ipairs(hosts) do
                    local fakehost = genhost(sni_len, host)
                    if b_debug then DLOG("hostfakesplit_multi: sending fake"..i.." ("..host..")") end
                    if not rawsend_payload_segmented(desync, fakehost, pos[1] - 1, opts_fake) then return VERDICT_PASS end
                end

                -- настоящий host
                local midhost
                if desync.arg.midhost then
                    midhost = resolve_pos(data, desync.l7payload, desync.arg.midhost)
                    if midhost and (midhost <= pos[1] or midhost > pos[2]) then
                        midhost = nil
                    end
                end

                if midhost then
                    part = string.sub(data, pos[1], midhost - 1)
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end
                    part = string.sub(data, midhost, pos[2])
                    if not rawsend_payload_segmented(desync, part, midhost - 1, opts_orig) then return VERDICT_PASS end
                else
                    part = string.sub(data, pos[1], pos[2])
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end
                end

                -- after host
                part = string.sub(data, pos[2] + 1)
                if not rawsend_payload_segmented(desync, part, pos[2], opts_orig) then return VERDICT_PASS end

                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            else
                DLOG("hostfakesplit_multi: host range cannot be resolved")
            end
        else
            DLOG("hostfakesplit_multi: not acting on further replay pieces")
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
end


-- ============================================================================
-- HOSTFAKESPLIT_GRADUAL - постепенная отправка с разбиением фейка
-- ============================================================================

--[[
hostfakesplit_gradual - фейк тоже разбивается на части

Вместо отправки целого фейка, разбиваем его на мелкие части
и перемешиваем с частями настоящего SNI.

Паттерн: fake_part1 -> real_part1 -> fake_part2 -> real_part2 -> ...

standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
arg : host=<str>
arg : parts=N - на сколько частей разбить (по умолчанию 3)
arg : nodrop
]]
function hostfakesplit_gradual(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end
    direction_cutoff_opposite(ctx, desync)
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                if b_debug then DLOG("hostfakesplit_gradual: resolved host range: "..table.concat(zero_based_pos(pos), " ")) end

                local sni_len = pos[2] - pos[1] + 1
                local real_sni = string.sub(data, pos[1], pos[2])
                local fakehost = genhost(sni_len, desync.arg.host)
                local num_parts = tonumber(desync.arg.parts) or 3

                local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
                local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

                -- before host
                local part = string.sub(data, 1, pos[1] - 1)
                if b_debug then DLOG("hostfakesplit_gradual: sending before_host") end
                if not rawsend_payload_segmented(desync, part, 0, opts_orig) then return VERDICT_PASS end

                -- разбиваем SNI на части и чередуем fake/real
                local part_size = math.ceil(sni_len / num_parts)
                for i = 1, num_parts do
                    local start_idx = (i - 1) * part_size + 1
                    local end_idx = math.min(i * part_size, sni_len)
                    if start_idx > sni_len then break end

                    local fake_part = string.sub(fakehost, start_idx, end_idx)
                    local real_part = string.sub(real_sni, start_idx, end_idx)
                    local offset = pos[1] - 1 + start_idx - 1

                    -- сначала фейк
                    if b_debug then DLOG("hostfakesplit_gradual: sending fake part "..i.." offset="..offset) end
                    if not rawsend_payload_segmented(desync, fake_part, offset, opts_fake) then return VERDICT_PASS end

                    -- потом настоящий
                    if b_debug then DLOG("hostfakesplit_gradual: sending real part "..i.." offset="..offset) end
                    if not rawsend_payload_segmented(desync, real_part, offset, opts_orig) then return VERDICT_PASS end
                end

                -- after host
                part = string.sub(data, pos[2] + 1)
                if b_debug then DLOG("hostfakesplit_gradual: sending after_host") end
                if not rawsend_payload_segmented(desync, part, pos[2], opts_orig) then return VERDICT_PASS end

                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            else
                DLOG("hostfakesplit_gradual: host range cannot be resolved")
            end
        else
            DLOG("hostfakesplit_gradual: not acting on further replay pieces")
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
end


-- ============================================================================
-- HOSTFAKESPLIT_DECOY - отправка decoy пакетов вокруг
-- ============================================================================

--[[
hostfakesplit_decoy - добавляет "мусорные" пакеты для отвлечения

Кроме фейкового SNI, отправляет дополнительные пакеты-приманки
с разными данными чтобы засорить буфер DPI.

standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
arg : host=<str>
arg : decoys=N - сколько decoy пакетов (по умолчанию 2)
arg : decoy_size=N - размер каждого decoy (по умолчанию 50)
arg : midhost=<posmarker>
arg : nodrop
]]
function hostfakesplit_decoy(ctx, desync)
    if not desync.dis.tcp then
        instance_cutoff_shim(ctx, desync)
        return
    end
    direction_cutoff_opposite(ctx, desync)
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                if b_debug then DLOG("hostfakesplit_decoy: resolved host range: "..table.concat(zero_based_pos(pos), " ")) end

                local sni_len = pos[2] - pos[1] + 1
                local fakehost = genhost(sni_len, desync.arg.host)
                local num_decoys = tonumber(desync.arg.decoys) or 2
                local decoy_size = tonumber(desync.arg.decoy_size) or 50

                local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
                local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

                -- генерируем decoy данные (случайные байты)
                local function gen_decoy(size)
                    local s = ""
                    for i = 1, size do
                        s = s .. string.char(math.random(0, 255))
                    end
                    return s
                end

                local part

                -- decoys ДО
                for i = 1, num_decoys do
                    local decoy = gen_decoy(decoy_size)
                    local offset = math.random(0, pos[1] - 2)
                    if b_debug then DLOG("hostfakesplit_decoy: sending decoy "..i.." offset="..offset) end
                    rawsend_payload_segmented(desync, decoy, offset, opts_fake)
                end

                -- before host
                part = string.sub(data, 1, pos[1] - 1)
                if not rawsend_payload_segmented(desync, part, 0, opts_orig) then return VERDICT_PASS end

                -- fake
                if not desync.arg.nofake1 then
                    if not rawsend_payload_segmented(desync, fakehost, pos[1] - 1, opts_fake) then return VERDICT_PASS end
                end

                -- real host
                local midhost
                if desync.arg.midhost then
                    midhost = resolve_pos(data, desync.l7payload, desync.arg.midhost)
                    if midhost and (midhost <= pos[1] or midhost > pos[2]) then
                        midhost = nil
                    end
                end

                if midhost then
                    part = string.sub(data, pos[1], midhost - 1)
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end
                    part = string.sub(data, midhost, pos[2])
                    if not rawsend_payload_segmented(desync, part, midhost - 1, opts_orig) then return VERDICT_PASS end
                else
                    part = string.sub(data, pos[1], pos[2])
                    if not rawsend_payload_segmented(desync, part, pos[1] - 1, opts_orig) then return VERDICT_PASS end
                end

                -- fake2
                if not desync.arg.nofake2 then
                    if not rawsend_payload_segmented(desync, fakehost, pos[1] - 1, opts_fake) then return VERDICT_PASS end
                end

                -- after host
                part = string.sub(data, pos[2] + 1)
                if not rawsend_payload_segmented(desync, part, pos[2], opts_orig) then return VERDICT_PASS end

                -- decoys ПОСЛЕ
                for i = 1, num_decoys do
                    local decoy = gen_decoy(decoy_size)
                    local offset = pos[2] + math.random(1, 50)
                    if b_debug then DLOG("hostfakesplit_decoy: sending trailing decoy "..i.." offset="..offset) end
                    rawsend_payload_segmented(desync, decoy, offset, opts_fake)
                end

                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            else
                DLOG("hostfakesplit_decoy: host range cannot be resolved")
            end
        else
            DLOG("hostfakesplit_decoy: not acting on further replay pieces")
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
end


-- ============================================================================
-- ALIASES / SHORTCUTS
-- ============================================================================

-- snifakesplit = hostfakesplit (они идентичны, host/endhost работают для TLS тоже)
function snifakesplit(ctx, desync)
    return hostfakesplit(ctx, desync)
end

-- hostfakesplit_soft - быстрый доступ к soft режиму
function hostfakesplit_soft(ctx, desync)
    desync.arg.mode = "soft"
    return hostfakesplit_stealth(ctx, desync)
end

-- hostfakesplit_blend - быстрый доступ к blend режиму
function hostfakesplit_blend(ctx, desync)
    desync.arg.mode = "blend"
    return hostfakesplit_stealth(ctx, desync)
end


DLOG("zapret-multishake.lua loaded")
