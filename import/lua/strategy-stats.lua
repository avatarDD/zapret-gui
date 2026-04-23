-- Strategy statistics - preload strategies from registry and apply to circular
-- Python handles all SUCCESS/FAILURE detection and saves to registry
-- This file only handles loading preloaded strategies and applying them
-- МЕНЯТЬ ТОЛЬКО ФАЙЛ ПО ПУТИ H:\Privacy\zapret\lua\strategy-stats.lua

local working_strategies = {}  -- [hostname] = {strategy=N, locked=bool, applied=bool}

-- BLOCKED_STRATEGIES is managed by strategy-lock-manager.lua
-- Use slm_is_blocked() instead of is_strategy_blocked()

-- SKIP_PASS domains and IP ranges are managed by strategy-lock-manager.lua
-- Use slm_should_skip_pass() instead of should_skip_pass()

-- Helper: convert IP to /16 subnet (e.g., 103.142.5.10 -> 103.142.0.0)
-- Used for UDP to group similar IPs (usually same server cluster)
local function ip_to_subnet16(ip)
    if not ip then return nil end
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if a and b then
        return a .. "." .. b .. ".0.0"
    end
    return nil  -- Not an IP address
end

-- Helper: check if string is an IP address (not a hostname)
local function is_ip_address(str)
    if not str then return false end
    return str:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end

-- Track domains where we've already applied skip_pass
local skip_pass_applied = {}

-- Preload learned strategies from Python-generated Lua file
-- Called from learned-strategies.lua at startup
function strategy_preload(hostname, strategy)
    if not hostname or not strategy then return end

    working_strategies[hostname] = {
        strategy = strategy,
        locked = true,
        applied = false
    }

    -- Use slm_preload_locked() from strategy-lock-manager.lua
    -- This ensures preloaded strategies are recognized as LOCKED
    -- Note: uses "tls" as default askey for backward compatibility
    if slm_preload_locked then
        slm_preload_locked("tls", hostname, strategy)
    end

    DLOG("strategy-stats: PRELOADED " .. hostname .. " = strategy " .. strategy)
end

-- Preload history from Python-generated Lua file
-- Uses slm_preload_history() to populate SLM_QUALITY
function strategy_preload_history(hostname, strategy, successes, failures)
    if not hostname or not strategy then return end
    successes = successes or 0
    failures = failures or 0
    local total = successes + failures
    local rate = total > 0 and math.floor((successes / total) * 100) or 0

    -- Use slm_preload_history() from strategy-lock-manager.lua
    -- Note: uses "tls" as default askey for backward compatibility
    if slm_preload_history then
        slm_preload_history("tls", hostname, strategy, successes, failures)
    end

    DLOG("strategy-stats: HISTORY " .. hostname .. " s" .. strategy .. " successes=" .. successes .. " failures=" .. failures .. " rate=" .. rate .. "%")
end

-- Apply preload logic WITHOUT calling any orchestrator
-- This sets hrec.nstrategy based on working_strategies
local function apply_preload_logic(desync)
    -- Skip DHT traffic
    if desync and desync.l7proto == "dht" then
        return
    end

    -- Get hostname using standard_hostkey (same as circular uses - includes NLD cut)
    local hostname = standard_hostkey(desync)
    if not hostname then return end

    -- Get autostate key for this profile
    local askey = (desync.arg.key and #desync.arg.key>0) and desync.arg.key or desync.func_instance

    -- Check if we have preloaded strategy for this hostname
    local data = working_strategies[hostname]

    -- If not found with NLD-cut hostname, try original full hostname
    if not data and desync.track and desync.track.hostname then
        local full_hostname = desync.track.hostname
        if full_hostname ~= hostname then
            data = working_strategies[full_hostname]
            if data then
                hostname = full_hostname
            end
        end
    end

    -- For UDP (profiles 3 and 4): try /16 subnet lookup if exact IP not found
    if not data and is_ip_address(hostname) then
        if askey == "circular_3_1" or askey == "circular_4_1" or
           askey == "circular_quality_3_1" or askey == "circular_quality_4_1" then
            local subnet = ip_to_subnet16(hostname)
            if subnet then
                data = working_strategies[subnet]
                if data then
                    DLOG("strategy-stats: UDP /16 match: " .. hostname .. " -> " .. subnet)
                end
            end
        end
    end

    -- SKIP_PASS: Check FIRST before applying preload
    -- For certain domains, strategy 1 (pass) should NEVER be used
    -- slm_should_skip_pass() is defined in strategy-lock-manager.lua
    local skip_pass = slm_should_skip_pass and slm_should_skip_pass(hostname)

    if data and data.locked and data.strategy and not data.applied then
        -- SKIP_PASS: If preloaded strategy is 1 (pass) and domain needs bypass, skip to 2
        local apply_strategy = data.strategy
        if skip_pass and apply_strategy == 1 then
            apply_strategy = 2
            DLOG("strategy-stats: SKIP_PASS " .. hostname .. " preload strategy 1 -> 2 [" .. askey .. "]")
        end

        -- Get or create autostate record
        local hrec = automate_host_record(desync)
        if hrec then
            -- Only set nstrategy to START from this strategy
            -- Do NOT set hrec.final - that would disable rotation on failure
            -- circular will still rotate if failure_detector triggers
            hrec.nstrategy = apply_strategy
            data.applied = true
            DLOG("strategy-stats: APPLIED " .. hostname .. " = strategy " .. apply_strategy .. " [" .. askey .. "]")
        end
    end

    -- SKIP_PASS: Also check for NEW domains (no preload) - start from strategy 2
    -- This prevents pass from being locked for domains that NEED active DPI bypass
    if skip_pass and not skip_pass_applied[hostname] then
        local hrec = automate_host_record(desync)
        if hrec then
            -- If current strategy is 1 (pass) or not set, skip to 2
            if not hrec.nstrategy or hrec.nstrategy == 1 then
                hrec.nstrategy = 2
                skip_pass_applied[hostname] = true
                DLOG("strategy-stats: SKIP_PASS " .. hostname .. " -> start from strategy 2 [" .. askey .. "]")
            end
        end
    end
end

-- Wrap circular function to apply preloaded strategies before rotation starts
local original_circular = nil

function circular_with_preload(ctx, desync)
    -- Skip DHT traffic - pass through without processing
    if desync and desync.l7proto == "dht" then
        return VERDICT_PASS
    end

    -- Apply preload logic (sets hrec.nstrategy)
    apply_preload_logic(desync)

    -- Call original circular
    if original_circular then
        return original_circular(ctx, desync)
    else
        return circular(ctx, desync)
    end
end

-- Install wrapper after zapret-auto.lua is loaded
local original_circular_quality = nil

function install_circular_wrapper()
    -- Wrap circular (legacy)
    if circular and not original_circular then
        original_circular = circular
        circular = circular_with_preload
        DLOG("strategy-stats: circular wrapper installed")
    end
    -- Wrap circular_quality (current orchestrator)
    if circular_quality and not original_circular_quality then
        original_circular_quality = circular_quality
        circular_quality = function(ctx, desync)
            -- Skip DHT traffic - pass through without any processing
            if desync and desync.l7proto == "dht" then
                return VERDICT_PASS
            end
            -- Apply preload logic ONLY (do NOT call circular!)
            apply_preload_logic(desync)
            -- Then call original circular_quality which handles its own detection
            return original_circular_quality(ctx, desync)
        end
        DLOG("strategy-stats: circular_quality wrapper installed")
    end
end
