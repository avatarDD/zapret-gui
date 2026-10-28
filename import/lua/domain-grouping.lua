-- Domain grouping for circular orchestrator
-- Groups subdomains under base domain to share strategy state

-- Extract base domain (e.g., "rr5---sn-xxx.googlevideo.com" -> "googlevideo.com")
function get_grouped_hostname(hostname)
    if not hostname then return nil end

    -- Each service gets its own key to find optimal strategy independently
    if string.match(hostname, "%.googlevideo%.com$") then
        return "googlevideo.com"
    end

    if string.match(hostname, "%.youtube%.com$") or hostname == "youtube.com" then
        return "youtube.com"
    end

    if string.match(hostname, "%.ytimg%.com$") then
        return "ytimg.com"
    end

    if string.match(hostname, "%.ggpht%.com$") then
        return "ggpht.com"
    end

    -- Special handling for googleapis.com
    if string.match(hostname, "%.googleapis%.com$") then
        return "googleapis.com"
    end

    -- Special handling for google.com
    if string.match(hostname, "%.google%.com$") then
        return "google.com"
    end

        -- Special handling for rapidgator.net
    if string.match(hostname, "%.rapidgator%.net$") then
        return "rapidgator.net"
    end
    
    -- For other domains, return as-is
    return hostname
end

-- Hostkey for circular's per-host record: the upstream key (standard_hostkey,
-- which honours nld=, reqhost and falls back to the target ip), then narrowed by
-- get_grouped_hostname. The grouping rules only collapse deeper names into a
-- base domain, so they compose with nld=2.
--
-- This is the ONE place the default key is built. z2k-state-persist.lua keys
-- state.tsv through the same function (if this script is loaded), so rotation
-- and persistence always touch the same autostate[askey][hostkey] record.
-- Previously this override built its own key from host_or_ip(), ignoring nld=
-- and hostkey=: circular rotated "a.b.c" while persist wrote/seeded "b.c", so a
-- learned strategy for any subdomain outside the list below never reached disk.
function grouped_hostkey(desync)
    local hostkey = standard_hostkey(desync)
    if not hostkey then return nil end
    local grouped = get_grouped_hostname(hostkey)
    if grouped ~= hostkey then
        DLOG("domain-grouping: " .. hostkey .. " -> " .. grouped)
    end
    return grouped
end

-- Override automate_host_record to use grouped hostname
function automate_host_record(desync)
    local hostkey, askey

    -- Explicit hostkey= (e.g. z2k_nohost_key for hostless pools) wins, exactly
    -- as in upstream zapret-auto.lua; otherwise use the grouped key.
    if desync.arg.hostkey then
        if type(_G[desync.arg.hostkey])~="function" then
            error("automate: invalid hostkey function '"..desync.arg.hostkey.."'")
        end
        hostkey = _G[desync.arg.hostkey](desync)
    else
        hostkey = grouped_hostkey(desync)
    end

    if not hostkey then
        DLOG("automate: host record key unavailable")
        return nil
    end

    askey = (desync.arg.key and #desync.arg.key>0) and desync.arg.key or desync.func_instance
    DLOG("automate: host record key 'autostate."..askey.."."..hostkey.."'")

    if not autostate then
        autostate = {}
    end
    if not autostate[askey] then
        autostate[askey] = {}
    end
    if not autostate[askey][hostkey] then
        autostate[askey][hostkey] = {}
        -- Store hostname in record for logging in circular
        autostate[askey][hostkey]._hostname = hostkey
        autostate[askey][hostkey]._askey = askey

        -- NEW: При первом обращении к домену, начинаем с лучшей стратегии из истории
        -- Это быстрее чем начинать с 1 и перебирать все стратегии
        if get_best_strategy_from_history then
            local best = get_best_strategy_from_history(hostkey)
            if best then
                autostate[askey][hostkey].nstrategy = best
                DLOG("domain-grouping: starting " .. hostkey .. " from history strategy " .. best)
            end
        else
            -- Log new domain starting from strategy 1
            DLOG("domain-grouping: NEW " .. hostkey .. " starting from strategy 1")
        end
    end

    -- Log current strategy for this domain (for UI monitoring)
    local hrec = autostate[askey][hostkey]
    if hrec.nstrategy then
        -- Only log periodically to avoid spam (every 10th call)
        hrec._log_counter = (hrec._log_counter or 0) + 1
        if hrec._log_counter >= 10 then
            hrec._log_counter = 0
            local status = hrec.final and "LOCKED" or "LEARNING"
            -- Add [TLS]/[HTTP] tag based on askey (circular_1_1=TLS, circular_2_1=HTTP)
            local ptype_tag = (askey == "circular_2_1") and "[HTTP]" or "[TLS]"
            DLOG("domain-grouping: CURRENT " .. hostkey .. " strategy=" .. hrec.nstrategy .. " " .. ptype_tag .. " [" .. status .. "]")
        end
    end

    return autostate[askey][hostkey]
end
