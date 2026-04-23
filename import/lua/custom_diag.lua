-- custom_diag.lua
-- Safe diagnostics helpers: only logs, does not modify packets.
-- Load after zapret-lib.lua:
--   --lua-init=@lua/zapret-lib.lua --lua-init=@lua/custom_diag.lua
--
-- Usage example (temporarily add into the profile you want to observe):
--   --lua-desync=diag_once

local function diag_print(msg)
	if type(DLOG) == "function" then
		DLOG(msg)
	else
		print(msg)
	end
end

local TELEGRAM_CIDR_FALLBACK = {
	"91.108.56.0/22",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.16.0/22",
	"91.108.12.0/22",
	"149.154.160.0/20",
	"91.105.192.0/23",
	"91.108.20.0/22",
	"185.76.151.0/24",
	"2001:b28:f23d::/48",
	"2001:b28:f23f::/48",
	"2001:67c:4e8::/48",
	"2001:b28:f23c::/48",
	"2a0a:f280::/32",
}

local function diag_trim(s)
	return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function diag_load_cidrs_from_file(path)
	local ok, content = pcall(function()
		if type(readfile) == "function" then
			return readfile(path)
		end
		local f = io.open(path, "r")
		if not f then
			return nil
		end
		local s = f:read("*a")
		f:close()
		return s
	end)
	if not ok or not content or #content == 0 then
		return {}
	end

	local cidrs = {}
	for line in tostring(content):gmatch("[^\r\n]+") do
		line = diag_trim(line)
		if #line > 0 and not line:match("^#") then
			table.insert(cidrs, line)
		end
	end
	return cidrs
end

local function diag_parse_cidr(cidr)
	local ip_s, prefix_s = tostring(cidr):match("^([^/%s]+)/(%d+)$")
	if not ip_s or not prefix_s then
		return nil
	end
	local prefix = tonumber(prefix_s)
	if not prefix then
		return nil
	end
	local ipbin = (type(pton) == "function") and pton(ip_s) or nil
	if type(ipbin) ~= "string" then
		return nil
	end
	local bytes = #ipbin
	if bytes == 4 then
		if prefix < 0 or prefix > 32 then
			return nil
		end
	elseif bytes == 16 then
		if prefix < 0 or prefix > 128 then
			return nil
		end
	else
		return nil
	end
	return { net = ipbin, prefix = prefix, bytes = bytes, cidr = tostring(cidr) }
end

local function diag_compile_cidrs(cidrs)
	local out = {}
	for _, cidr in ipairs(cidrs or {}) do
		local e = diag_parse_cidr(cidr)
		if e then
			table.insert(out, e)
		end
	end
	return out
end

local TELEGRAM_NETS = (function()
	local cidrs = diag_load_cidrs_from_file("lists/ipset-telegram.txt")
	if #cidrs == 0 then
		cidrs = TELEGRAM_CIDR_FALLBACK
	end
	return diag_compile_cidrs(cidrs)
end)()

local function diag_ip_in_net(ipbin, netbin, prefix)
	local full = math.floor(prefix / 8)
	if full > 0 and ipbin:sub(1, full) ~= netbin:sub(1, full) then
		return false
	end
	local rem = prefix - full * 8
	if rem == 0 then
		return true
	end
	local ipb = string.byte(ipbin, full + 1)
	local netb = string.byte(netbin, full + 1)
	if not ipb or not netb then
		return false
	end
	local shift = 8 - rem
	return math.floor(ipb / (2 ^ shift)) == math.floor(netb / (2 ^ shift))
end

local function diag_match_telegram_ipbin(ipbin)
	if type(ipbin) ~= "string" then
		return nil
	end
	local bytes = #ipbin
	if bytes ~= 4 and bytes ~= 16 then
		return nil
	end
	for _, e in ipairs(TELEGRAM_NETS) do
		if e.bytes == bytes and diag_ip_in_net(ipbin, e.net, e.prefix) then
			return e.cidr
		end
	end
	return nil
end

local function diag_get_host(desync)
	if desync.hostname and #tostring(desync.hostname) > 0 then
		return tostring(desync.hostname)
	end
	if desync.track and desync.track.hostname and #tostring(desync.track.hostname) > 0 then
		return tostring(desync.track.hostname)
	end
	return "-"
end

local function diag_get_proto(desync)
	if desync.dis and desync.dis.tcp then
		return "tcp"
	end
	if desync.dis and desync.dis.udp then
		return "udp"
	end
	return "-"
end

local function diag_get_ports(desync)
	if not desync.dis then
		return "-", "-"
	end
	if desync.dis.tcp then
		return tostring(desync.dis.tcp.th_sport or "-"), tostring(desync.dis.tcp.th_dport or "-")
	end
	if desync.dis.udp then
		return tostring(desync.dis.udp.uh_sport or "-"), tostring(desync.dis.udp.uh_dport or "-")
	end
	return "-", "-"
end

local function diag_get_target_ip(desync)
	if type(host_ip) == "function" then
		return host_ip(desync) or "-"
	end
	-- Fallback when zapret-lib.lua is not loaded for some reason.
	if desync.target and desync.target.ip and type(ntop) == "function" then
		return ntop(desync.target.ip)
	end
	if desync.target and desync.target.ip6 and type(ntop) == "function" then
		return ntop(desync.target.ip6)
	end
	return "-"
end

local function diag_log(desync, prefix)
	local host = diag_get_host(desync)
	local proto = diag_get_proto(desync)
	local sport, dport = diag_get_ports(desync)
	local tip = diag_get_target_ip(desync)
	local dir = (desync.outgoing == true) and "out" or "in"
	local payload = tostring(desync.l7payload or "-")
	local inst = tostring(desync.func_instance or "-")
	local tg = diag_match_telegram_ipbin(desync.target and (desync.target.ip or desync.target.ip6) or nil)

	diag_print((prefix or "diag") .. ": inst=" .. inst ..
		" dir=" .. dir ..
		" proto=" .. proto ..
		" " .. tostring(sport) .. "->" .. tostring(dport) ..
		" dst=" .. tostring(tip) ..
		" host=" .. host ..
		" l7=" .. payload ..
		(tg and (" tg=" .. tg) or ""))
end

-- Log first packet per connection (best for debugging without spam).
function diag_once(ctx, desync)
	if not desync.track or not desync.track.lua_state then
		diag_log(desync, "diag_once(no_track)")
		return
	end
	if desync.track.lua_state.diag_once_done then
		return
	end
	desync.track.lua_state.diag_once_done = true
	diag_log(desync, "diag_once")
end

-- Log every packet that reaches this function (may be very noisy).
function diag_always(ctx, desync)
	diag_log(desync, "diag_always")
end

diag_print("custom_diag.lua: loaded (telegram_cidrs=" .. tostring(#TELEGRAM_NETS) .. ")")
