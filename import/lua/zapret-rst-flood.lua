--[[

NFQWS2 RST FLOOD - Anti-TSPU IP Throttling Strategy

Obkhod zamedleniya TSPU po IP-adresu. TSPU otslezhivaet TCP-sessii k opredelyonnym IP
i primenyaet throttling cherez N sekund. Eta strategiya:

1. State Table Pollution (faza SYN):
   Pered real'nym SYN otpravlyaet N fejkovyh SYN ot sluchajnyh IP s kalibrovannym TTL.
   Fejki dohodyat do TSPU no NE do servera. TSPU sozdayot zapisi dlya nesushchestvuyushchih sessij.

2. Periodic RST Reset (faza DATA):
   Vo vremya peredachi dannyh periodicheski otpravlyaet RST+ACK s kalibrovannym TTL.
   TSPU vidit RST i udalyaet sessiyu iz tablicy. Server RST ne poluchaet.
   Sleduyushchie pakety prohodyat kak "novaya" sessiya bez throttling.

Usage:
--lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua --lua-init=@zapret-rst-flood.lua

--lua-desync=rst_flood:flood_count=30:rst_interval=2:ip_autottl=-1,3-20:ttl_fallback=8
--lua-desync=rst_flood:flood_count=50:rst_interval=1.5:fin_mode:src_range=rfc1918
--lua-desync=rst_flood:no_pollution:rst_interval=1:ip_autottl=-2,3-20
--lua-desync=rst_flood:no_pollution:rst_bytes=12000:ip_autottl=-1,3-20:ttl_fallback=4

Parameters:
  flood_count=N       - number of fake SYNs for pollution (default: 30)
  rst_interval=N      - seconds between RST resets (default: 0, disabled)
  rst_bytes=N         - OUTGOING bytes between RST resets (default: 0, disabled)
                        tracks bytes SENT by client (direct.pbcounter)
                        client sends ~1KB per ~8KB received, so
                        rst_bytes=1500 ≈ RST every ~10-15KB from server
                        at least one of rst_interval/rst_bytes must be set
  ttl_fallback=N      - fixed TTL when autottl unavailable (default: 8)
  fin_mode            - alternate RST+ACK and FIN+ACK
  src_range=rfc1918   - 10.x.x.x for spoofed source IPs
  src_range=cgn       - 100.64.x.x CGN range (default)
  no_pollution        - disable phase 1 (RST only)
  no_rst              - disable phase 2 (pollution only)

Standard fooling args: ip_autottl, ip_ttl, ip6_ttl, ip6_autottl
Filtering: use --ipset as usual, Lua receives only matching packets

NOTE: Source IP spoofing requires that ISP does not implement BCP38/uRPF ingress filtering.
      If spoofed packets are dropped, try src_range=cgn (ISP's own CGN range looks more legitimate).
      Phase 2 (RST reset) works without spoofing and is the primary mechanism.

]]


-- ============================================================================
-- HELPERS
-- ============================================================================

-- Random source IPv4 in RFC1918 space (10.0.0.0/8)
local function random_src_rfc1918()
	return "\x0a" .. brandom(3)
end

-- Random source IPv4 in CGN space (100.64.0.0/10)
local function random_src_cgn()
	return "\x64" .. string.char(64 + math.random(0, 63)) .. brandom(2)
end

-- Get calibrated TTL/hop limit: reaches TSPU but dies before the server
local function get_calibrated_ttl(desync)
	-- Try autottl from incoming_ttl (SYN-ACK or ipcache)
	if desync.track and desync.track.incoming_ttl and desync.track.incoming_ttl > 0 then
		-- Use ip6_autottl for IPv6, ip_autottl for IPv4
		local attl_str = desync.dis.ip6 and desync.arg.ip6_autottl or desync.arg.ip_autottl
		if attl_str then
			local attl = parse_autottl(attl_str)
			if attl then
				local ttl = autottl(desync.track.incoming_ttl, attl)
				if ttl then
					return ttl, true
				end
			end
		end
	end
	-- Fallback to fixed TTL
	return tonumber(desync.arg.ttl_fallback) or 8, false
end


-- ============================================================================
-- RST_FLOOD: main strategy function
-- ============================================================================

--[[
rst_flood - anti-TSPU IP throttling via state table pollution + periodic RST

Phase 1 (SYN): flood TSPU state table with fake SYNs from spoofed IPs
Phase 2 (DATA): send calibrated RST by byte count or time to clear TSPU session state

standard args : direction, fooling (ip_autottl), rawsend, reconstruct
arg : flood_count=N (default 30)
arg : rst_interval=N seconds (default 2)
arg : ttl_fallback=N (default 8)
arg : fin_mode - alternate RST and FIN
arg : src_range=rfc1918|cgn (default cgn)
arg : no_pollution - skip phase 1
arg : no_rst - skip phase 2
]]
function rst_flood(ctx, desync)
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end

	-- Conntrack required for persistent state and autottl
	if not desync.track then return end

	-- Only process outgoing packets
	direction_cutoff_opposite(ctx, desync)
	if not desync.outgoing then return end

	-- Persistent state per TCP connection
	if not desync.track.lua_state.rst_flood then
		desync.track.lua_state.rst_flood = {
			last_rst_dt = 0,
			last_rst_bytes = 0,
			rst_count = 0,
			pollution_done = false,
			use_fin_next = false,
		}
	end
	local st = desync.track.lua_state.rst_flood

	local flags = desync.dis.tcp.th_flags

	-- =============================================
	-- PHASE 1: State Table Pollution (on outgoing SYN)
	-- =============================================
	if bitand(flags, TH_SYN + TH_ACK) == TH_SYN
	   and not desync.arg.no_pollution
	   and not st.pollution_done
	then
		local count = tonumber(desync.arg.flood_count) or 30
		local ttl, is_auto = get_calibrated_ttl(desync)
		local src_range = desync.arg.src_range or "cgn"
		local gen_src = (src_range == "rfc1918") and random_src_rfc1918 or random_src_cgn

		DLOG("rst_flood: POLLUTION "..count.." fake SYNs, TTL="..ttl
			..(is_auto and "(auto)" or "(fallback)")
			..", src="..src_range)

		for i = 1, count do
			local dis = deepcopy(desync.dis)

			-- Spoof source IP and set calibrated TTL
			if dis.ip then
				dis.ip.ip_src = gen_src()
				dis.ip.ip_ttl = ttl
			elseif dis.ip6 then
				-- IPv6: cannot spoof src easily, but set hop limit
				dis.ip6.ip6_hlim = ttl
			end

			-- Random source port and sequence number
			dis.tcp.th_sport = math.random(1024, 60000)
			dis.tcp.th_seq = math.random(1, 2000000000)
			dis.tcp.th_flags = TH_SYN
			dis.tcp.th_win = 64240
			dis.payload = ""

			rawsend_dissect(dis, rawsend_opts(desync))
		end

		st.pollution_done = true
		-- VERDICT_PASS: real SYN goes through unmodified
		return
	end

	-- =============================================
	-- PHASE 2: RST Reset (by server bytes or time)
	-- =============================================
	if not desync.arg.no_rst then
		local rst_interval = tonumber(desync.arg.rst_interval) or 0
		local rst_bytes = tonumber(desync.arg.rst_bytes) or 0
		local dt = desync.track.pos.dt or 0

		-- Track outgoing bytes as proxy for connection activity
		-- (reverse/server pbcounter stays 0 — range_in=x0 prevents counting)
		local dir = desync.track.pos.direct
		local out_bytes = dir and dir.pbcounter or 0

		-- Trigger RST by outgoing bytes OR by time (whichever fires first)
		local need_rst = false
		local trigger = ""

		-- Byte-based: use outgoing bytes as proxy
		-- Client sends ~1KB per ~5-8KB received from server
		-- So rst_bytes=1500 ≈ RST every ~10-15KB from server
		if rst_bytes > 0 and (out_bytes - st.last_rst_bytes) >= rst_bytes then
			need_rst = true
			trigger = "out="..out_bytes

		-- Time-based: fires on any outgoing packet
		elseif rst_interval > 0 and (dt - st.last_rst_dt) >= rst_interval then
			need_rst = true
			trigger = "t="..string.format("%.1f", dt)
		end

		if need_rst then
			local ttl, is_auto = get_calibrated_ttl(desync)

			local dis = deepcopy(desync.dis)
			dis.payload = ""

			-- Set calibrated TTL/hop limit (reaches TSPU, dies before server)
			if dis.ip then
				dis.ip.ip_ttl = ttl
			elseif dis.ip6 then
				dis.ip6.ip6_hlim = ttl
			end

			-- Choose RST+ACK or FIN+ACK (if fin_mode)
			if desync.arg.fin_mode and st.use_fin_next then
				dis.tcp.th_flags = TH_FIN + TH_ACK
				DLOG("rst_flood: FIN+ACK #"..st.rst_count
					.." TTL="..ttl..(is_auto and "(auto)" or "(fb)")
					.." ["..trigger.."]")
			else
				dis.tcp.th_flags = TH_RST + TH_ACK
				DLOG("rst_flood: RST+ACK #"..st.rst_count
					.." TTL="..ttl..(is_auto and "(auto)" or "(fb)")
					.." ["..trigger.."]")
			end

			rawsend_dissect(dis, rawsend_opts(desync))

			st.last_rst_dt = dt
			st.last_rst_bytes = out_bytes
			st.rst_count = st.rst_count + 1
			if desync.arg.fin_mode then
				st.use_fin_next = not st.use_fin_next
			end
		end
	end

	-- VERDICT_PASS: real packet always goes through unmodified
end
