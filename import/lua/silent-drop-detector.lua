-- Custom failure detector for TCP silent drop (DPI drops packets without RST)
-- Works by counting outgoing vs incoming DATA packets (excluding SYN-ACK handshake)
-- If many outgoing data packets and few incoming data = failure

function silent_drop_detector(desync, crec, arg)
    if crec.nocheck then return false end

    local tcp_out = tonumber(arg.tcp_out) or 4  -- outgoing data packets threshold
    local tcp_in = tonumber(arg.tcp_in) or 1    -- incoming DATA packets threshold (1 = only SYN-ACK)

    if desync.dis.tcp and desync.outgoing and desync.track then
        -- Use dcounter (data packets) if available, otherwise pcounter
        local out_count = desync.track.pos.direct.dcounter or desync.track.pos.direct.pcounter or 0
        local in_count = desync.track.pos.reverse.dcounter or desync.track.pos.reverse.pcounter or 0

        -- Silent drop: many outgoing data packets but only handshake responses (SYN-ACK)
        -- Trigger FAILURE every tcp_out packets after threshold
        if out_count >= tcp_out and in_count <= tcp_in then
            local last_fail = crec.last_fail_out or 0
            if out_count >= last_fail + tcp_out then
                crec.last_fail_out = out_count
                -- Reset failure flag to allow multiple rotations in same connection
                crec.failure = nil
                DLOG("silent_drop_detector: FAILURE out="..out_count.." in="..in_count.." (last="..last_fail..")")
                return true
            end
        end

        if b_debug and out_count > 2 then
            DLOG("silent_drop_detector: out="..out_count.." in="..in_count)
        end
    end

    return false
end
