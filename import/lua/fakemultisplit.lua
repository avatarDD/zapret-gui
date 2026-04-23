-- custom helper for nfqws2
-- load after zapret-lib.lua and zapret-antidpi.lua:
--   --lua-init=@/mnt/g/Privacy/zapret2_custom/fakemultisplit.lua
--
-- usage example:
--   --lua-desync=fakemultisplit:fake_blob=fake_default_tls:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000
--
-- behavior:
--   real payload is split like multisplit
--   before each real segment a fake segment of the same sequence range is sent
--   fake data is taken from fake_blob at the same byte offsets; if it is shorter, the tail is padded with pattern or zero bytes

local function fakemultisplit_fake_part(fake_data, fake_pat, pos_start, part_len)
	local part = ""
	if fake_data and pos_start <= #fake_data then
		part = string.sub(fake_data, pos_start, pos_start + part_len - 1)
	end
	if #part < part_len then
		part = part .. pattern(fake_pat, 1, part_len - #part)
	end
	return part
end

-- nfqws2 custom : "multisplit" with interleaved "fake"
-- standard args : direction, payload, fooling, ip_id, rawsend, reconstruct
-- FOOLING AND REPEATS APPLIED ONLY TO FAKES. real parts keep only ip_id and tcp_ts_up, like fakedsplit
-- arg : pos=<posmarker list> . position marker list. for example : "1,host,midsld+1,-10"
-- arg : fake_blob=<blob> - fake payload source. slices are taken from matching offsets
-- arg : pattern=<blob> - padding pattern for fake slices when fake_blob is shorter. default - zero byte
-- arg : nofakeN - skip N-th fake segment, for example nofake1 or nofake3
-- arg : seqovl=N . decrease seq number of the first real segment by N and fill N bytes with pattern (default - all zero)
-- arg : seqovl_pattern=<blob> . override seqovl pattern
-- arg : blob=<blob> - use this data instead of desync.dis.payload/reasm_data as real payload
-- arg : optional - skip if blob/fake_blob is absent. use zero pattern if seqovl_pattern or pattern blob is absent
-- arg : tls_mod=<list> - optional TLS modifications for fake_blob, same format as in fake()
-- arg : nodrop - do not drop current dissect
function fakemultisplit(ctx, desync)
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end

	direction_cutoff_opposite(ctx, desync)

	if not desync.arg.fake_blob then
		error("fakemultisplit: 'fake_blob' arg required")
	end

	if desync.arg.optional and desync.arg.blob and not blob_exist(desync, desync.arg.blob) then
		DLOG("fakemultisplit: blob '"..desync.arg.blob.."' not found. skipped")
		return
	end
	if desync.arg.optional and not blob_exist(desync, desync.arg.fake_blob) then
		DLOG("fakemultisplit: fake_blob '"..desync.arg.fake_blob.."' not found. skipped")
		return
	end

	local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
	if #data>0 and direction_check(desync) and payload_check(desync) then
		if replay_first(desync) then
			local spos = desync.arg.pos or "2"
			if b_debug then DLOG("fakemultisplit: split pos: "..spos) end

			local pos = resolve_multi_pos(data, desync.l7payload, spos)
			if b_debug then DLOG("fakemultisplit: resolved split pos: "..table.concat(zero_based_pos(pos), " ")) end
			delete_pos_1(pos)

			if #pos>0 then
				local fake_data = blob(desync, desync.arg.fake_blob)
				if desync.reasm_data and desync.arg.tls_mod then
					local pl = tls_mod_shim(desync, fake_data, desync.arg.tls_mod, desync.reasm_data)
					if pl then fake_data = pl end
				end

				local fake_pat = "\x00"
				if desync.arg.pattern then
					if desync.arg.optional and not blob_exist(desync, desync.arg.pattern) then
						DLOG("fakemultisplit: blob '"..desync.arg.pattern.."' not found. using zero pattern")
					else
						fake_pat = blob(desync, desync.arg.pattern)
					end
				end

				local opts_orig = {
					rawsend = rawsend_opts_base(desync),
					reconstruct = {},
					ipfrag = {},
					ipid = desync.arg,
					fooling = {tcp_ts_up = desync.arg.tcp_ts_up}
				}
				local opts_fake = {
					rawsend = rawsend_opts(desync),
					reconstruct = reconstruct_opts(desync),
					ipfrag = {},
					ipid = desync.arg,
					fooling = desync.arg
				}

				for i=0,#pos do
					local pos_start = pos[i] or 1
					local pos_end = i<#pos and pos[i+1]-1 or #data
					local part_len = pos_end - pos_start + 1
					local fake_part = fakemultisplit_fake_part(fake_data, fake_pat, pos_start, part_len)

					if not desync.arg["nofake"..tostring(i+1)] then
						if b_debug then
							DLOG("fakemultisplit: sending fake part "..(i+1).." "..(pos_start-1).."-"..(pos_end-1).." len="..#fake_part.." : "..hexdump_dlog(fake_part))
						end
						if not rawsend_payload_segmented(desync, fake_part, pos_start-1, opts_fake) then
							return VERDICT_PASS
						end
					end

					local part = string.sub(data, pos_start, pos_end)
					local seqovl = 0
					if i==0 and desync.arg.seqovl and tonumber(desync.arg.seqovl)>0 then
						seqovl = tonumber(desync.arg.seqovl)
						local pat = "\x00"
						if desync.arg.seqovl_pattern then
							if desync.arg.optional and not blob_exist(desync, desync.arg.seqovl_pattern) then
								DLOG("fakemultisplit: blob '"..desync.arg.seqovl_pattern.."' not found. using zero pattern")
							else
								pat = blob(desync, desync.arg.seqovl_pattern)
							end
						end
						part = pattern(pat, 1, seqovl) .. part
					end

					if b_debug then
						DLOG("fakemultisplit: sending real part "..(i+1).." "..(pos_start-1).."-"..(pos_end-1).." len="..#part.." seqovl="..seqovl.." : "..hexdump_dlog(part))
					end
					if not rawsend_payload_segmented(desync, part, pos_start-1-seqovl, opts_orig) then
						return VERDICT_PASS
					end
				end

				replay_drop_set(desync)
				return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
			else
				DLOG("fakemultisplit: no valid split positions")
			end
		else
			DLOG("fakemultisplit: not acting on further replay pieces")
		end

		if replay_drop(desync) then
			return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
		end
	end
end
