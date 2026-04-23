-- Combined failure detector - extends standard detector with default page detection
-- Uses standard_failure_detector for RST/retransmission/redirect detection
-- Adds: HTTP status code validation (only 2xx is success)
-- Adds: default page detection for HTTP (Apache/Nginx default pages)
-- Adds: DPI stub detection (fake 404 pages with wrong server names)
-- Adds: Block page detection in first 16KB

-- Lua 5.1 compatibility (winws2 uses Lua 5.1 without bit32 module)
if not bit32 then
    bit32 = {}
    function bit32.band(a, b)
        local result = 0
        local bitval = 1
        while a > 0 and b > 0 do
            if a % 2 == 1 and b % 2 == 1 then
                result = result + bitval
            end
            bitval = bitval * 2
            a = math.floor(a / 2)
            b = math.floor(b / 2)
        end
        return result
    end
    function bit32.rshift(a, n)
        return math.floor(a / (2 ^ n))
    end
end

-- Fix misclassified payload types (e.g. Roblox detected as WireGuard by size)
-- WireGuard initiation: 148 bytes, first byte = 0x01
-- WireGuard response: 92 bytes, first byte = 0x02
-- WireGuard cookie: 64 bytes, first byte = 0x03
function fix_payload_type(desync)
    if not desync.dis.udp or not desync.dis.payload then
        return desync.l7payload
    end

    local payload = desync.dis.payload
    local l7 = desync.l7payload

    -- Check if classified as WireGuard but first byte doesn't match
    if l7 == "wireguard_initiation" and #payload == 148 then
        local first_byte = payload:byte(1)
        if first_byte ~= 0x01 then
            -- Not real WireGuard - probably Roblox or other game
            return "game_udp"
        end
    elseif l7 == "wireguard_response" and #payload == 92 then
        local first_byte = payload:byte(1)
        if first_byte ~= 0x02 then
            return "game_udp"
        end
    elseif l7 == "wireguard_cookie" and #payload == 64 then
        local first_byte = payload:byte(1)
        if first_byte ~= 0x03 then
            return "game_udp"
        end
    end

    return l7
end

-- Known default page markers (check in HTTP response body)
local DEFAULT_PAGE_MARKERS = {
    "apache2 ubuntu default",
    "apache2 debian default",
    "it works!",
    "welcome to nginx",
    "iis windows server",
    "test page for the apache",
    "index of /",
    "default web page",
    "<title>apache2",
    "<title>welcome to nginx"
}

-- Known DPI stub markers - fake servers that indicate DPI interception
-- These appear in Server: header or error page footer
local DPI_STUB_MARKERS = {
    "ov.google.com",        -- Russian ISP DPI stub
    "blocked.mgts.ru",      -- MGTS block page
    "warning.rt.ru",        -- Rostelecom block page
    "block.mts.ru",         -- MTS block page
    "zapret.mts.ru"         -- MTS block page
}

-- Known block page markers in 16KB (Russian ISP block pages)
local BLOCK_PAGE_MARKERS = {
    -- Russian ISP block pages
    "eais.rkn.gov.ru",
    "vigruzki.rkn.gov.ru",
    "blocklist.rkn.gov.ru",
    "reestr.rublacklist.net",
    "nap.rkn.gov.ru",
    "zapret-info.gov.ru",
    "blacklist.rkn.gov.ru",
    -- ISP specific block pages
    "rkn.megafon.ru",
    "blocked.beeline.ru",
    "block.beeline.ru",
    "blocked.tele2.ru",
    "restriction.tele2.ru",
    "blocked.yota.ru",
    "blocking.ttk.ru",
    "block.ttk.ru",
    "blocked.domru.ru",
    "block.domru.ru",
    "blocked.2kom.ru",
    "blocked.ugmk-telecom.ru",
    -- Generic block page markers
    "access denied",
    "access blocked",
    "blocked by",
    "blocked for",
    "prohibited by law",
    "restricted content",
    "content blocked",
    "website blocked",
    "resource blocked",
    "site blocked"
}

-- Detect default page markers in HTTP response payload
local function check_default_page(payload)
    if not payload or #payload < 50 then return false end

    -- Check entire payload (up to 2KB) for markers
    local check_len = math.min(#payload, 2048)
    local lower_payload = string.lower(string.sub(payload, 1, check_len))

    for _, marker in ipairs(DEFAULT_PAGE_MARKERS) do
        if string.find(lower_payload, marker, 1, true) then
            return true, marker
        end
    end

    return false
end

-- Detect DPI stub markers in HTTP response
local function check_dpi_stub(payload)
    if not payload or #payload < 50 then return false end

    local check_len = math.min(#payload, 2048)
    local lower_payload = string.lower(string.sub(payload, 1, check_len))

    for _, marker in ipairs(DPI_STUB_MARKERS) do
        if string.find(lower_payload, marker, 1, true) then
            return true, marker
        end
    end

    return false
end

-- Detect block page markers in first 16KB of response
local function check_block_page(payload)
    if not payload or #payload < 50 then return false end

    -- Check first 16KB for block page markers
    local check_len = math.min(#payload, 16384)
    local lower_payload = string.lower(string.sub(payload, 1, check_len))

    for _, marker in ipairs(BLOCK_PAGE_MARKERS) do
        if string.find(lower_payload, marker, 1, true) then
            return true, marker
        end
    end

    return false
end

-- Check HTTP status code - only 2xx is success
local function check_http_status(payload)
    if not payload or #payload < 12 then return false, nil end

    -- Parse HTTP response: HTTP/1.x NNN
    local http_prefix = string.sub(payload, 1, 8)
    if http_prefix ~= "HTTP/1.1" and http_prefix ~= "HTTP/1.0" then
        return false, nil  -- Not HTTP response
    end

    -- Extract status code (position 10-12)
    local status_str = string.match(payload, "^HTTP/1%.[01] (%d%d%d)")
    if not status_str then
        return false, nil
    end

    local status_code = tonumber(status_str)
    if not status_code then
        return false, nil
    end

    -- Only 2xx is success
    if status_code >= 200 and status_code < 300 then
        return false, status_code  -- Not failure, success
    else
        return true, status_code  -- Failure: not 2xx
    end
end

-- ==================== UDP Protocol Validation ====================

-- Check STUN Binding Response
-- Valid STUN response: first 2 bytes = 0x0101 (Binding Success Response)
-- Magic cookie at bytes 5-8 = 0x2112A442
local function check_stun_response(payload)
    if not payload or #payload < 20 then return false, nil end

    local b1 = string.byte(payload, 1)
    local b2 = string.byte(payload, 2)

    -- STUN Binding Success Response = 0x0101
    if b1 == 0x01 and b2 == 0x01 then
        -- Verify magic cookie (bytes 5-8)
        if #payload >= 8 then
            local m1 = string.byte(payload, 5)
            local m2 = string.byte(payload, 6)
            local m3 = string.byte(payload, 7)
            local m4 = string.byte(payload, 8)
            if m1 == 0x21 and m2 == 0x12 and m3 == 0xA4 and m4 == 0x42 then
                return true, "STUN_SUCCESS"
            end
        end
        return true, "STUN_RESPONSE"
    end

    -- STUN Error Response = 0x0111
    if b1 == 0x01 and b2 == 0x11 then
        return false, "STUN_ERROR"
    end

    return false, nil
end

-- Check QUIC Initial Response
-- QUIC long header: first bit = 1 (0x80-0xFF), then form + version
-- Valid response usually has same version as request
local function check_quic_response(payload)
    if not payload or #payload < 5 then return false, nil end

    local first_byte = string.byte(payload, 1)

    -- Long header form (bit 7 = 1)
    if first_byte >= 0x80 then
        -- Get packet type (bits 4-5 for QUIC v1)
        local packet_type = bit32.band(bit32.rshift(first_byte, 4), 0x03)

        -- 0 = Initial, 1 = 0-RTT, 2 = Handshake, 3 = Retry
        if packet_type == 0 or packet_type == 2 then
            -- Check version (bytes 2-5)
            local v1 = string.byte(payload, 2)
            local v2 = string.byte(payload, 3)
            local v3 = string.byte(payload, 4)
            local v4 = string.byte(payload, 5)

            -- QUIC v1 = 0x00000001, QUIC v2 = 0x6b3343cf
            if (v1 == 0x00 and v2 == 0x00 and v3 == 0x00 and v4 == 0x01) or
               (v1 == 0x6b and v2 == 0x33 and v3 == 0x43 and v4 == 0xcf) then
                return true, "QUIC_VALID"
            end

            -- Version negotiation (version = 0)
            if v1 == 0x00 and v2 == 0x00 and v3 == 0x00 and v4 == 0x00 then
                return false, "QUIC_VERSION_NEG"  -- Not a success, need retry
            end
        end

        return true, "QUIC_LONG_HEADER"
    end

    -- Short header (bit 7 = 0) - means handshake completed
    if first_byte < 0x80 and first_byte >= 0x40 then
        return true, "QUIC_SHORT_HEADER"
    end

    return false, nil
end

-- Check Discord voice response
-- Discord IP Discovery response: starts with specific pattern
local function check_discord_response(payload)
    if not payload or #payload < 8 then return false, nil end

    -- Discord IP Discovery response format:
    -- 2 bytes type (0x0002 = response), 2 bytes length, 4 bytes SSRC
    local b1 = string.byte(payload, 1)
    local b2 = string.byte(payload, 2)

    -- Type 0x0002 = IP Discovery Response
    if b1 == 0x00 and b2 == 0x02 then
        return true, "DISCORD_IP_DISCOVERY"
    end

    -- Check if it's RTP (voice data) - indicates success
    -- RTP version 2: first byte & 0xC0 == 0x80
    if bit32.band(b1, 0xC0) == 0x80 then
        local payload_type = bit32.band(string.byte(payload, 2), 0x7F)
        -- Common audio payload types: 0 (PCMU), 8 (PCMA), 96-127 (dynamic)
        if payload_type == 0 or payload_type == 8 or payload_type >= 96 then
            return true, "RTP_AUDIO"
        end
    end

    return false, nil
end

-- Check for UDP "black hole" indicators
-- Some DPIs just drop UDP or send ICMP unreachable (which we can't see here)
-- But we can detect suspiciously small/malformed responses
local function check_udp_anomaly(payload)
    if not payload then return true, "NO_PAYLOAD" end

    -- Suspiciously small response (< 4 bytes usually invalid)
    if #payload < 4 then
        return true, "TOO_SMALL"
    end

    -- All zeros payload (some DPI sends this)
    local all_zeros = true
    for i = 1, math.min(#payload, 20) do
        if string.byte(payload, i) ~= 0 then
            all_zeros = false
            break
        end
    end
    if all_zeros and #payload > 4 then
        return true, "ALL_ZEROS"
    end

    return false, nil
end

-- ==================== TLS Checks ====================

-- Check TLS Alert - indicates TLS handshake failure
-- TLS Alert record: ContentType=0x15, Version, Length, AlertLevel, AlertDescription
local function check_tls_alert(payload)
    if not payload or #payload < 7 then return false, nil end

    local content_type = string.byte(payload, 1)

    -- 0x15 = TLS Alert record
    if content_type ~= 0x15 then
        return false, nil
    end

    -- Verify TLS version (bytes 2-3)
    local version_major = string.byte(payload, 2)
    local version_minor = string.byte(payload, 3)
    if version_major ~= 0x03 or version_minor < 0x00 or version_minor > 0x04 then
        return false, nil
    end

    -- Get alert level and description if available
    if #payload >= 7 then
        local alert_level = string.byte(payload, 6)  -- 1=warning, 2=fatal
        local alert_desc = string.byte(payload, 7)
        return true, alert_level, alert_desc
    end

    return true, nil, nil
end

-- Combined failure detector
-- Calls standard_failure_detector first, then adds HTTP/TLS status and content checks
-- Also detects connection stalls (no response after N outgoing packets)
function combined_failure_detector(desync, crec)
    if crec.nocheck then return false end

    -- First, call standard failure detector for RST/retrans/redirect
    if standard_failure_detector(desync, crec) then
        return true
    end

    -- ==================== Connection Stall Detection ====================
    -- For TCP: if we sent multiple packets but got no response, it's likely blocked
    -- This catches "silent drop" DPI that doesn't send RST
    if desync.dis.tcp and desync.outgoing and desync.track then
        -- Track outgoing packets with payload (actual data, not just ACKs)
        if desync.dis.payload and #desync.dis.payload > 0 then
            crec.tcp_out_with_payload = (crec.tcp_out_with_payload or 0) + 1
        end

        -- Stall threshold: 3 outgoing packets with payload, 0 incoming data
        local stall_out_threshold = tonumber(desync.arg.stall_out) or 3
        local tcp_in_count = crec.tcp_in_count or 0

        if crec.tcp_out_with_payload and crec.tcp_out_with_payload >= stall_out_threshold and tcp_in_count == 0 then
            if not crec.stall_detected then
                crec.stall_detected = true
                DLOG("combined_failure_detector: CONNECTION STALL out=" .. crec.tcp_out_with_payload .. " in=" .. tcp_in_count .. " (failure)")
                return true
            end
        end
    end

    -- Track incoming packets for stall detection
    if desync.dis.tcp and not desync.outgoing and desync.track then
        if desync.dis.payload and #desync.dis.payload > 0 then
            crec.tcp_in_count = (crec.tcp_in_count or 0) + 1
        end
    end

    -- ==================== Extended RST Detection ====================
    -- Detect RST even beyond standard inseq range (for TLS handshake failures)
    -- DPI often sends RST after Client Hello, which may have seq > inseq
    if desync.dis.tcp and not desync.outgoing and desync.track then
        if bitand(desync.dis.tcp.th_flags, TH_RST) ~= 0 then
            local seq = pos_get(desync, 's')
            -- Extended range: up to 16KB (covers most TLS handshakes)
            local extended_inseq = 0x4000
            if seq >= 1 and seq <= extended_inseq and not crec.rst_detected then
                crec.rst_detected = true
                DLOG("combined_failure_detector: RST detected at seq=" .. seq .. " (extended range)")
                return true
            end
        end
    end

    -- Additional checks for responses only (incoming packets)
    -- We only check incoming responses, NOT outgoing requests
    if not desync.dis.tcp or not desync.track then
        return false
    end

    -- Only check incoming (response) packets
    if desync.outgoing then
        return false
    end

    local payload = desync.dis.payload
    if not payload or #payload < 7 then
        return false
    end

    -- Check TLS Alert - indicates TLS handshake failure (DPI interference)
    -- Only check once per connection
    if not crec.tls_alert_checked then
        local is_alert, alert_level, alert_desc = check_tls_alert(payload)
        if is_alert then
            crec.tls_alert_checked = true
            local level_str = alert_level == 2 and "FATAL" or (alert_level == 1 and "WARNING" or "UNKNOWN")
            DLOG("combined_failure_detector: TLS ALERT " .. level_str .. " desc=" .. tostring(alert_desc) .. " (failure)")
            return true
        end
    end

    -- Need at least 12 bytes for HTTP status check
    if #payload < 12 then
        return false
    end

    -- Check HTTP status code - only 2xx is success
    -- Only check once per connection
    if not crec.http_status_checked then
        local is_failure, status_code = check_http_status(payload)
        if status_code then
            crec.http_status_checked = true
            if is_failure then
                DLOG("combined_failure_detector: HTTP STATUS " .. status_code .. " (not 2xx = failure)")
                return true
            else
                DLOG("combined_failure_detector: HTTP STATUS " .. status_code .. " (2xx = ok)")
            end
        end
    end

    -- Need at least 50 bytes for content checks
    if #payload < 50 then
        return false
    end

    -- Check for DPI stub markers (fake servers like ov.google.com)
    -- This catches 404/other responses from DPI that masquerade as legitimate servers
    if not crec.dpi_stub_found then
        local is_stub, marker = check_dpi_stub(payload)
        if is_stub then
            crec.dpi_stub_found = true
            DLOG("combined_failure_detector: DPI STUB detected (marker: " .. marker .. ")")
            return true
        end
    end

    -- Check for block page markers in first 16KB
    if not crec.block_page_found then
        local is_block, marker = check_block_page(payload)
        if is_block then
            crec.block_page_found = true
            DLOG("combined_failure_detector: BLOCK PAGE detected (marker: " .. marker .. ")")
            return true
        end
    end

    -- Check for default page content in HTTP response
    -- Only mark failure once per connection to avoid spam
    if not crec.default_page_found then
        local is_default, marker = check_default_page(payload)
        if is_default then
            crec.default_page_found = true
            DLOG("combined_failure_detector: DEFAULT PAGE detected (marker: " .. marker .. ")")
            return true
        end
    end

    return false
end

-- Combined success detector
-- FIRST checks for failures (TLS Alert, HTTP errors, block pages)
-- For UDP: validates protocol-specific responses (STUN, QUIC, Discord)
-- ONLY then delegates to standard_success_detector
-- This prevents marking connections as successful when TLS Alert or other errors occur
function combined_success_detector(desync, crec)
    if crec.nocheck then return false end

    -- ==================== TCP Checks ====================
    if not desync.outgoing and desync.dis.tcp and desync.track then
        local payload = desync.dis.payload

        -- Check TLS Alert FIRST - if we get TLS Alert, this is NOT a success
        if payload and #payload >= 7 then
            local is_alert, alert_level, alert_desc = check_tls_alert(payload)
            if is_alert then
                -- Mark as failure, not success
                crec.tls_alert_detected = true
                local level_str = alert_level == 2 and "FATAL" or (alert_level == 1 and "WARNING" or "UNKNOWN")
                DLOG("combined_success_detector: TLS ALERT " .. level_str .. " desc=" .. tostring(alert_desc) .. " - NOT SUCCESS")
                return false  -- Do not mark as success
            end
        end

        -- Check HTTP status - if non-2xx, this is NOT a success
        if payload and #payload >= 12 then
            local is_failure, status_code = check_http_status(payload)
            if status_code and is_failure then
                crec.http_failure_detected = true
                DLOG("combined_success_detector: HTTP STATUS " .. status_code .. " - NOT SUCCESS")
                return false
            end
        end

        -- Check for DPI stub markers - if found, NOT a success
        if payload and #payload >= 50 then
            local is_stub, marker = check_dpi_stub(payload)
            if is_stub then
                crec.dpi_stub_detected = true
                DLOG("combined_success_detector: DPI STUB (" .. marker .. ") - NOT SUCCESS")
                return false
            end

            local is_block, marker = check_block_page(payload)
            if is_block then
                crec.block_page_detected = true
                DLOG("combined_success_detector: BLOCK PAGE (" .. marker .. ") - NOT SUCCESS")
                return false
            end
        end
    end

    -- ==================== UDP Checks ====================
    if not desync.outgoing and desync.dis.udp then
        local payload = desync.dis.payload

        -- Check for UDP anomalies first
        if not crec.udp_anomaly_checked then
            local is_anomaly, anomaly_type = check_udp_anomaly(payload)
            if is_anomaly then
                crec.udp_anomaly_checked = true
                DLOG("combined_success_detector: UDP ANOMALY (" .. tostring(anomaly_type) .. ") - NOT SUCCESS")
                return false
            end
        end

        -- Try to validate protocol-specific response
        if payload and #payload >= 8 and not crec.udp_protocol_validated then
            -- Check STUN response
            local is_stun, stun_type = check_stun_response(payload)
            if is_stun then
                crec.udp_protocol_validated = true
                DLOG("combined_success_detector: STUN VALID (" .. tostring(stun_type) .. ") - SUCCESS")
                crec.nocheck = true
                return true  -- Immediate success
            elseif stun_type == "STUN_ERROR" then
                crec.udp_protocol_validated = true
                DLOG("combined_success_detector: STUN ERROR - NOT SUCCESS")
                return false
            end

            -- Check QUIC response
            local is_quic, quic_type = check_quic_response(payload)
            if is_quic then
                crec.udp_protocol_validated = true
                DLOG("combined_success_detector: QUIC VALID (" .. tostring(quic_type) .. ") - SUCCESS")
                crec.nocheck = true
                return true  -- Immediate success
            elseif quic_type == "QUIC_VERSION_NEG" then
                -- Version negotiation is not a success
                crec.udp_protocol_validated = true
                DLOG("combined_success_detector: QUIC VERSION_NEG - NOT SUCCESS")
                return false
            end

            -- Check Discord response
            local is_discord, discord_type = check_discord_response(payload)
            if is_discord then
                crec.udp_protocol_validated = true
                DLOG("combined_success_detector: DISCORD VALID (" .. tostring(discord_type) .. ") - SUCCESS")
                crec.nocheck = true
                return true  -- Immediate success
            end
        end
    end

    -- No failure indicators found - delegate to standard success detector
    return standard_success_detector(desync, crec)
end

-- ==================== UDP-Specific Detectors ====================
-- These solve the problem of:
-- 1. Standard detector only checks on outgoing packets
-- 2. Each IP = new key (Discord/Telegram use many servers)

-- Known service IP ranges (from ipset files)
-- Maps /16 subnet to service domain (for preload matching)
-- Format: ["o1.o2"] = "domain.tld"
local KNOWN_SERVICE_SUBNETS = {
    -- Roblox (from ipset-roblox.txt)
    ["18.165"] = "roblox.com",
    ["23.43"] = "roblox.com",
    ["23.173"] = "roblox.com",
    ["103.140"] = "roblox.com",
    ["103.142"] = "roblox.com",
    ["108.156"] = "roblox.com",
    ["128.116"] = "roblox.com",
    ["141.193"] = "roblox.com",
    ["185.105"] = "roblox.com",
    ["204.9"] = "roblox.com",
    ["204.13"] = "roblox.com",
    ["205.201"] = "roblox.com",
    ["212.188"] = "roblox.com",

    -- Discord (from ipset-discord.txt - main ranges)
    ["34.0"] = "discord.com",
    ["34.1"] = "discord.com",
    ["35.207"] = "discord.com",
    ["35.212"] = "discord.com",
    ["35.213"] = "discord.com",
    ["35.214"] = "discord.com",
    ["35.215"] = "discord.com",
    ["35.217"] = "discord.com",
    ["35.219"] = "discord.com",
    ["66.22"] = "discord.com",
    ["138.128"] = "discord.com",

    -- Telegram (from ipset-telegram.txt)
    ["91.105"] = "telegram.org",
    ["91.108"] = "telegram.org",
    ["149.154"] = "telegram.org",
    ["185.76"] = "telegram.org",

    -- League of Legends (from ipset-lol-*.txt)
    ["104.160"] = "leagueoflegends.com",

    -- WhatsApp (from ipset-whatsapp.txt - main ranges)
    ["157.240"] = "whatsapp.com",
    ["163.70"] = "whatsapp.com",
    ["179.60"] = "whatsapp.com",
    ["185.60"] = "whatsapp.com",
    ["31.13"] = "whatsapp.com",
    ["102.132"] = "whatsapp.com",

    -- Google STUN/TURN
    ["64.233"] = "google.com",
    ["74.125"] = "google.com",
    ["142.250"] = "google.com",
    ["142.251"] = "google.com",
    ["173.194"] = "google.com",
    ["209.85"] = "google.com",

    -- Cloudflare
    ["104.16"] = "cloudflare.com",
    ["104.17"] = "cloudflare.com",
    ["104.18"] = "cloudflare.com",
    ["104.21"] = "cloudflare.com",
    ["162.159"] = "cloudflare.com",
    ["172.64"] = "cloudflare.com",
    ["172.65"] = "cloudflare.com",
    ["172.66"] = "cloudflare.com",
    ["172.67"] = "cloudflare.com",
    ["188.114"] = "cloudflare.com",
}

-- Get service name by IP (returns nil if unknown)
local function get_service_by_ip(ip)
    if not ip then return nil end
    local o1, o2 = ip:match("^(%d+)%.(%d+)%.")
    if o1 and o2 then
        return KNOWN_SERVICE_SUBNETS[o1 .. "." .. o2]
    end
    return nil
end

-- Check if IP is local/private (should not be processed)
local function is_local_ip(ip)
    if not ip then return true end
    local o1 = tonumber(ip:match("^(%d+)%."))
    if not o1 then return true end
    -- 10.x.x.x, 127.x.x.x, 192.168.x.x, 172.16-31.x.x, 169.254.x.x
    if o1 == 10 or o1 == 127 then return true end
    if o1 == 192 then
        local o2 = tonumber(ip:match("^%d+%.(%d+)%."))
        if o2 == 168 then return true end
    end
    if o1 == 172 then
        local o2 = tonumber(ip:match("^%d+%.(%d+)%."))
        if o2 and o2 >= 16 and o2 <= 31 then return true end
    end
    if o1 == 169 then
        local o2 = tonumber(ip:match("^%d+%.(%d+)%."))
        if o2 == 254 then return true end
    end
    return false
end

-- UDP hostkey generator - groups by protocol and service
-- Uses desync.l7proto (set by C code via packet analysis) NOT ports
-- l7proto values: "quic", "stun", "discord", "wireguard", "dht", "unknown"
function udp_global_hostkey(desync)
    -- Skip local IPs - they don't need bypass
    local ip = host_ip(desync)
    if is_local_ip(ip) then
        return nil  -- Return nil to skip processing
    end

    -- Get protocol detected by C code (Magic Cookie for STUN, long header for QUIC, etc.)
    local l7proto = desync.l7proto or "unknown"
    DLOG("udp_global_hostkey: ip=" .. (ip or "nil") .. " l7proto=" .. l7proto)

    -- QUIC - detected by long header (byte[0] & 0xC0 == 0xC0)
    -- Use hostname if available (extracted from ClientHello)
    if l7proto == "quic" then
        local hostname = desync.track and desync.track.hostname
        if hostname and #hostname > 0 then
            -- Use NLD-cut hostname for QUIC
            local nld = desync.arg.nld and tonumber(desync.arg.nld) or 2
            local cut = dissect_nld(hostname, nld)
            if cut then
                return cut  -- Just hostname, no prefix needed
            end
            return hostname
        end
        -- QUIC without hostname - use service by IP or generic
        local service = get_service_by_ip(ip)
        if service then
            return slm_normalize_hostkey(service)
        end
        return "quic"  -- Generic QUIC (lowercase for consistency)
    end

    -- STUN - detected by Magic Cookie 0x2112A442 at bytes 4-7
    -- All STUN servers are interchangeable, use global key
    if l7proto == "stun" then
        -- Check if known service (Google STUN, Telegram, etc.)
        local service = get_service_by_ip(ip)
        if service then
            return slm_normalize_hostkey(service .. " stun")
        end
        return "stun"  -- Generic STUN (lowercase for consistency)
    end

    -- Discord - detected by IP Discovery packet format
    if l7proto == "discord" then
        return "discord voice"  -- Lowercase for consistency
    end

    -- WireGuard - detected by handshake format
    if l7proto == "wireguard" then
        return "wireguard"  -- Lowercase for consistency
    end

    -- DHT (BitTorrent) - detected by packet format
    if l7proto == "dht" then
        return "dht"  -- Lowercase for consistency
    end

    -- Unknown UDP protocol - use service by IP or /16 subnet
    if ip then
        -- Check if this is a known service
        local service = get_service_by_ip(ip)
        if service then
            return slm_normalize_hostkey(service)
        end

        -- Unknown service: use /16 subnet (already lowercase)
        local o1, o2 = ip:match("^(%d+)%.(%d+)%.")
        if o1 and o2 then
            return string.format("udp %s.%s.0.0", o1, o2)
        end
    end

    -- Fallback: use full IP (lowercase prefix)
    return ip or "udp unknown"
end

-- Aggressive UDP failure detector
-- Triggers failure much faster than standard detector
-- Key insight: if we sent packets and got nothing back, it's likely blocked
function udp_aggressive_failure_detector(desync, crec)
    if crec.nocheck then return false end

    -- First check standard failures (RST, etc)
    if standard_failure_detector(desync, crec) then
        return true
    end

    -- Only check on outgoing packets (when we're sending)
    if not desync.outgoing or not desync.dis.udp then
        return false
    end

    -- Get packet counts
    local out_count = pos_get(desync, 'n') or 0  -- outgoing packet number
    local in_count = crec.udp_in_count or 0

    -- Track incoming packets
    if not desync.outgoing then
        crec.udp_in_count = (crec.udp_in_count or 0) + 1
        return false
    end

    -- Aggressive threshold: 2 outgoing with 0 incoming = failure
    -- This is much faster than standard udp_out=5
    local threshold_out = tonumber(desync.arg.udp_fail_out) or 2
    local threshold_in = tonumber(desync.arg.udp_fail_in) or 0

    if out_count >= threshold_out and in_count <= threshold_in then
        DLOG("udp_aggressive_failure_detector: FAIL out=" .. out_count .. ">=" .. threshold_out .. " in=" .. in_count .. "<=" .. threshold_in)
        return true
    end

    return false
end

-- UDP success detector - immediate success on valid protocol response
function udp_protocol_success_detector(desync, crec)
    if crec.nocheck then return false end

    -- Only check incoming packets
    if desync.outgoing or not desync.dis.udp then
        return false
    end

    local payload = desync.dis.payload
    if not payload or #payload < 4 then
        return false
    end

    -- Check for UDP anomalies first
    local is_anomaly, anomaly_type = check_udp_anomaly(payload)
    if is_anomaly then
        DLOG("udp_protocol_success_detector: ANOMALY (" .. tostring(anomaly_type) .. ") - NOT SUCCESS")
        return false
    end

    -- Increment incoming counter
    crec.udp_in_count = (crec.udp_in_count or 0) + 1

    -- Any valid incoming packet = potential success
    -- But validate protocol if possible
    if #payload >= 8 then
        -- Check STUN
        local is_stun, stun_type = check_stun_response(payload)
        if is_stun then
            DLOG("udp_protocol_success_detector: STUN (" .. tostring(stun_type) .. ") - SUCCESS")
            crec.nocheck = true
            return true
        elseif stun_type == "STUN_ERROR" then
            DLOG("udp_protocol_success_detector: STUN_ERROR - NOT SUCCESS")
            return false
        end

        -- Check QUIC
        local is_quic, quic_type = check_quic_response(payload)
        if is_quic then
            DLOG("udp_protocol_success_detector: QUIC (" .. tostring(quic_type) .. ") - SUCCESS")
            crec.nocheck = true
            return true
        elseif quic_type == "QUIC_VERSION_NEG" then
            DLOG("udp_protocol_success_detector: QUIC_VERSION_NEG - NOT SUCCESS")
            return false
        end

        -- Check Discord
        local is_discord, discord_type = check_discord_response(payload)
        if is_discord then
            DLOG("udp_protocol_success_detector: DISCORD (" .. tostring(discord_type) .. ") - SUCCESS")
            crec.nocheck = true
            return true
        end
    end

    -- Unknown protocol but got valid response - count as success after threshold
    local in_threshold = tonumber(desync.arg.udp_in) or 1
    if crec.udp_in_count >= in_threshold then
        DLOG("udp_protocol_success_detector: GENERIC UDP in=" .. crec.udp_in_count .. " - SUCCESS")
        crec.nocheck = true
        return true
    end

    return false
end

-- ==================== Quality-Based Circular Orchestrator ====================
-- Uses strategy-lock-manager.lua for quality tracking and locking
-- slm_* functions handle: normalize, record, get_best, should_lock, get_locked, reset, get_stats
-- Alternative to standard circular that tracks success per strategy
-- and locks on the BEST one, not just the first working one
--
-- KEY DIFFERENCE: Failure takes priority over success!
-- If we see a failure (TLS Alert, RST, etc.) it overrides any previous "success"
-- This prevents locking on strategies that initially seem to work but then fail
--
-- arg: fails=N - failure count threshold to switch strategy (default 1)
-- arg: time=<sec> - failure counter reset timeout (default 60)
-- arg: lock_successes=N - minimum successes to lock on a strategy (default 3)
-- arg: lock_tests=N - minimum total tests before considering lock (default 5)
-- arg: lock_rate=N - minimum success rate to lock (default 0.6)
-- arg: skip_strategy=N - strategy to skip for locking (default 1 = pass)
-- arg: success_detector - success detector function name
-- arg: failure_detector - failure detector function name
-- arg: hostkey - hostkey generator function name
--
-- How it works:
-- 1. Rotates through strategies on failures (like standard circular)
-- 2. Records success/failure for each strategy
-- 3. FAILURE OVERRIDES SUCCESS - if failure detected, mark as fail even if success was seen
-- 4. After lock_tests tests, if a strategy has lock_successes successes
--    with lock_rate success rate, LOCK on that strategy (skip strategy 1/pass)
-- 5. Locked strategy is always used until reset

function circular_quality(ctx, desync)
    -- Skip if we're in replay mode (desync.plan is empty after orchestrate())
    -- During replay, C code re-invokes the profile but execution plan is already consumed
    if desync.replay_seq then
        DLOG("circular_quality: skip replay packet #" .. desync.replay_seq)
        return VERDICT_PASS
    end

    -- CRITICAL: Take over execution FIRST! This populates desync.plan from C code
    -- Without this call, desync.plan is nil and we can't orchestrate strategies
    orchestrate(ctx, desync)

    -- Now check if plan is empty (nested call or no strategies defined)
    if not desync.plan or #desync.plan == 0 then
        DLOG("circular_quality: no execution plan after orchestrate, passing through")
        return VERDICT_PASS
    end

    local function count_strategies(hrec)
        if not hrec.ctstrategy then
            local uniq={}
            local n=0
            for i,instance in pairs(desync.plan) do
                if instance.arg.strategy then
                    n = tonumber(instance.arg.strategy)
                    if not n or n<1 then
                        error("circular_quality: strategy number '"..tostring(instance.arg.strategy).."' is invalid")
                    end
                    uniq[tonumber(instance.arg.strategy)] = true
                end
            end
            n=0
            for i,v in pairs(uniq) do
                n=n+1
            end
            if n~=#uniq then
                error("circular_quality: strategies numbers must start from 1 and increment. gaps are not allowed.")
            end
            hrec.ctstrategy = n
        end
    end

    if not desync.track then
        DLOG_ERR("circular_quality: conntrack is missing but required")
        return
    end

    local hrec = automate_host_record(desync)
    if not hrec then
        DLOG("circular_quality: passing with no tampering")
        return
    end

    -- Get hostkey for quality tracking (normalized via slm_normalize_hostkey)
    local hostkey
    if desync.arg.hostkey then
        if type(_G[desync.arg.hostkey])~="function" then
            error("circular_quality: invalid hostkey function '"..desync.arg.hostkey.."'")
        end
        hostkey = _G[desync.arg.hostkey](desync)
    else
        -- Check if this hostname should be kept full (not NLD-cut)
        local full_hostname = desync.track and desync.track.hostname
        if full_hostname and slm_should_keep_full_hostname(full_hostname) then
            hostkey = slm_normalize_hostkey(full_hostname)
            DLOG("circular_quality: keeping full hostname (special): " .. (hostkey or "?"))
        else
            hostkey = standard_hostkey(desync)
        end
    end
    -- Normalize hostkey for slm_* functions
    hostkey = slm_normalize_hostkey(hostkey) or hostkey

    -- Count strategies from desync.plan (already populated by orchestrate() at function start)
    count_strategies(hrec)
    if hrec.ctstrategy==0 then
        error("circular_quality: add strategy=N tag argument to each following instance ! N must start from 1 and increment")
    end

    -- SKIP_PASS: Check if this domain should never use strategy 1 (pass)
    -- slm_should_skip_pass() is defined in strategy-lock-manager.lua
    local skip_pass = slm_should_skip_pass and slm_should_skip_pass(hostkey)

    if not hrec.nstrategy then
        -- Start from strategy 2 for domains that need active DPI bypass
        if skip_pass then
            DLOG("circular_quality: SKIP_PASS " .. (hostkey or "?") .. " -> start from strategy 2")
            hrec.nstrategy = 2
        else
            DLOG("circular_quality: start from strategy 1")
            hrec.nstrategy = 1
        end
    elseif skip_pass and hrec.nstrategy == 1 then
        -- If somehow stuck on strategy 1, force to 2
        DLOG("circular_quality: SKIP_PASS " .. (hostkey or "?") .. " -> force strategy 1 -> 2")
        hrec.nstrategy = 2
    end

    -- Initialize detectors ONCE (used for both locked and unlocked)
    local failure_detector, success_detector
    if desync.arg.failure_detector then
        if type(_G[desync.arg.failure_detector])~="function" then
            error("circular_quality: invalid failure detector function '"..desync.arg.failure_detector.."'")
        end
        failure_detector = _G[desync.arg.failure_detector]
    else
        failure_detector = standard_failure_detector
    end
    if desync.arg.success_detector then
        if type(_G[desync.arg.success_detector])~="function" then
            error("circular_quality: invalid success detector function '"..desync.arg.success_detector.."'")
        end
        success_detector = _G[desync.arg.success_detector]
    else
        success_detector = standard_success_detector
    end

    -- Get connection record and run detectors ALWAYS (even for locked strategies)
    local crec = automate_conn_record(desync)
    local is_failure = failure_detector(desync, crec)
    local is_success = not is_failure and success_detector(desync, crec)

    -- Check if we should use locked strategy
    local locked = slm_get_locked(desync.arg.key, hostkey)
    if locked then
        -- SKIP_PASS: Even if locked on strategy 1, force to 2 for domains that need bypass
        if skip_pass and locked == 1 then
            DLOG("circular_quality: SKIP_PASS " .. (hostkey or "?") .. " -> locked=1, forcing to 2 and resetting")
            hrec.nstrategy = 2
            -- Reset quality tracking so it can find a better strategy
            slm_reset(desync.arg.key, hostkey)
        -- BLOCKED: If locked strategy is marked as blocked by user, reset and re-learn
        elseif slm_is_blocked(desync.arg.key, hostkey, locked) then
            DLOG("circular_quality: BLOCKED " .. (hostkey or "?") .. " -> locked=" .. locked .. " is blocked, resetting")
            -- Find next non-blocked strategy
            local next_strat = locked
            for i = 1, hrec.ctstrategy do
                next_strat = (next_strat % hrec.ctstrategy) + 1
                if not slm_is_blocked(desync.arg.key, hostkey, next_strat) then
                    break
                end
            end
            hrec.nstrategy = next_strat
            -- Reset quality tracking so it can find a better strategy
            slm_reset(desync.arg.key, hostkey)
        else
            -- Use locked strategy
            hrec.nstrategy = locked

            -- === AUTO-UNLOCK: Track failures for locked strategies ===
            -- If locked strategy keeps failing, unlock and re-learn
            local unlock_fails = tonumber(desync.arg.unlock_fails) or 3

            if is_failure and not crec.locked_failure_recorded then
                crec.locked_failure_recorded = true
                hrec.locked_fail_count = (hrec.locked_fail_count or 0) + 1
                slm_record_result(desync.arg.key, hostkey, locked, false)
                DLOG("circular_quality: LOCKED strat " .. locked .. " FAIL #" .. hrec.locked_fail_count .. "/" .. unlock_fails .. " for " .. (hostkey or "?"))

                if hrec.locked_fail_count >= unlock_fails then
                    -- Check if this is a user lock (protected from auto-unlock)
                    if slm_is_user_lock(desync.arg.key, hostkey) then
                        -- User lock: do NOT reset, just log and clear fail counter
                        DLOG("circular_quality: USER LOCK protected for " .. (hostkey or "?") .. ", skipping auto-unlock (fails=" .. hrec.locked_fail_count .. ")")
                        hrec.locked_fail_count = 0
                    else
                        -- Auto lock: reset and re-learn as usual
                        DLOG("circular_quality: AUTO-UNLOCK [" .. tostring(desync.arg.key or "default") .. "] " .. (hostkey or "?") .. " after " .. hrec.locked_fail_count .. " consecutive fails")
                        slm_reset(desync.arg.key, hostkey)  -- This clears locked_strategy
                        hrec.locked_fail_count = 0
                        -- Start from next strategy (skip the failing one initially)
                        hrec.nstrategy = (locked % hrec.ctstrategy) + 1
                        -- Skip strategy 1 for SKIP_PASS domains
                        if skip_pass and hrec.nstrategy == 1 then
                            hrec.nstrategy = 2
                        end
                    end
                end

            elseif is_success and not crec.locked_success_recorded then
                crec.locked_success_recorded = true
                -- Success resets fail counter
                if hrec.locked_fail_count and hrec.locked_fail_count > 0 then
                    DLOG("circular_quality: LOCKED strat " .. locked .. " SUCCESS, reset fail counter (was " .. hrec.locked_fail_count .. ")")
                end
                hrec.locked_fail_count = 0
                slm_record_result(desync.arg.key, hostkey, locked, true)
            end

            DLOG("circular_quality: using LOCKED strategy " .. locked)
        end
    else
        -- Not locked yet - normal rotation with quality tracking

        -- If failure detected - override any previous success marking
        if is_failure then
            -- If we already recorded success for this connection, convert it to failure
            if crec.quality_success_recorded then
                DLOG("circular_quality: FAILURE overrides previous SUCCESS for strat " .. hrec.nstrategy)
                -- Decrement success via SLM_QUALITY global table (managed by strategy-lock-manager)
                -- Now uses two-level structure: SLM_QUALITY[askey][hostkey]
                local askey = desync.arg.key or "default"
                local as_table = SLM_QUALITY and SLM_QUALITY[askey]
                local qrec = as_table and as_table[hostkey]
                if qrec and qrec.strategy_successes and qrec.strategy_successes[hrec.nstrategy] then
                    qrec.strategy_successes[hrec.nstrategy] = math.max(0, qrec.strategy_successes[hrec.nstrategy] - 1)
                end
                crec.quality_success_recorded = nil
            end

            if not crec.quality_failure_recorded then
                crec.quality_failure_recorded = true
                slm_record_result(desync.arg.key, hostkey, hrec.nstrategy, false)

                local fails = tonumber(desync.arg.fails) or 1
                local maxtime = tonumber(desync.arg.time) or 60
                if automate_failure_counter(hrec, crec, fails, maxtime) then
                    -- Rotate to next strategy, skipping blocked ones
                    local start_strat = hrec.nstrategy
                    repeat
                        hrec.nstrategy = (hrec.nstrategy % hrec.ctstrategy) + 1
                        -- Skip blocked strategies
                        if slm_is_blocked(desync.arg.key, hostkey, hrec.nstrategy) then
                            DLOG("circular_quality: skipping BLOCKED strategy " .. hrec.nstrategy)
                        else
                            break
                        end
                    until hrec.nstrategy == start_strat  -- Prevent infinite loop
                    DLOG("circular_quality: rotate to strategy " .. hrec.nstrategy .. " [" .. slm_get_stats(desync.arg.key, hostkey) .. "]")
                end
            end

        -- Success detected and no failure
        elseif is_success and not crec.quality_success_recorded and not crec.quality_failure_recorded then
            crec.quality_success_recorded = true
            slm_record_result(desync.arg.key, hostkey, hrec.nstrategy, true)
            automate_failure_counter_reset(hrec)

            -- Check if we should lock now
            local should_lock_now, lock_strat = slm_should_lock(desync.arg.key, hostkey, desync.arg)
            if should_lock_now then
                DLOG("circular_quality: LOCKED on strategy " .. lock_strat .. " [" .. slm_get_stats(desync.arg.key, hostkey) .. "]")
                hrec.nstrategy = lock_strat
            end
        end
    end

    DLOG("circular_quality: current strategy " .. hrec.nstrategy)
    local verdict = VERDICT_PASS
    while true do
        local instance = plan_instance_pop(desync)
        if not instance then break end
        if instance.arg.strategy and tonumber(instance.arg.strategy)==hrec.nstrategy then
            verdict = plan_instance_execute(desync, verdict, instance)
        end
    end

    return verdict
end

DLOG("combined-detector v2 (strategy quality tracking) loaded")
