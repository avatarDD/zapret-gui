-- init_vars.lua
-- Инициализация переменных для стратегий Zapret 2
-- Этот файл загружается через --lua-init ПОСЛЕ zapret-lib.lua и zapret-antidpi.lua

-- ============== TLS с модификацией SNI ==============
-- Используются в стратегиях как seqovl_pattern=tls_google и т.д.

-- Google SNI
tls_google = tls_mod(fake_default_tls, 'sni=www.google.com')

-- Max.ru SNI  
bin_max = tls_mod(fake_default_tls, 'sni=web.max.ru')
fake_max = tls_mod(fake_default_tls, 'rnd,sni=web.max.ru')

-- ============== Рандомизированные TLS ==============
-- Для обхода сигнатурного анализа

tls_rnd = tls_mod(fake_default_tls, 'rnd')
tls_rndsni = tls_mod(fake_default_tls, 'rnd,rndsni')
tls_rnd_google = tls_mod(fake_default_tls, 'rnd,sni=www.google.com')
tls_rnd_dupsid = tls_mod(fake_default_tls, 'rnd,dupsid')
tls_rnd_dupsid_google = tls_mod(fake_default_tls, 'rnd,dupsid,sni=www.google.com')
tls_padencap = tls_mod(fake_default_tls, 'rnd,padencap')
tls_padencap_google = tls_mod(fake_default_tls, 'rnd,padencap,sni=www.google.com')

-- ============== Специальные SNI для российских сервисов ==============
tls_vk = tls_mod(fake_default_tls, 'sni=vk.com')
tls_sber = tls_mod(fake_default_tls, 'sni=sberbank.ru')
tls_yandex = tls_mod(fake_default_tls, 'sni=yandex.ru')
tls_mail = tls_mod(fake_default_tls, 'sni=mail.ru')

-- ============== Cloudflare/CDN ==============
tls_cloudflare = tls_mod(fake_default_tls, 'sni=cloudflare.com')
tls_discord = tls_mod(fake_default_tls, 'sni=discord.com')
tls_youtube = tls_mod(fake_default_tls, 'sni=youtube.com')

-- init_vars.lua
function invert_bytes(s)
    local result = ""
    for i = 1, #s do
        result = result .. string.char(bit.bxor(string.byte(s, i), 0xFF))
    end
    return result
end

fake_inverted_tls = invert_bytes(fake_default_tls)
