# AGENTS.md — инструкции для AI-агентов

Файл читают Codex, Cursor, Jules, Aider, Zed, Continue и другие агенты,
поддерживающие стандарт `AGENTS.md`. Claude Code дополнительно сам подхватывает
скилы из `.claude/skills/`. Указатели для Gemini CLI, Copilot и Cursor лежат в
`GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/` и ведут сюда.

**Человеку читать не это, а:** [README.md](README.md) — пользовательская
документация, [CoderManual.md](CoderManual.md) — руководство разработчика
(архитектура, `core/` по доменам, REST, фронтенд, тесты, «куда добавить X»).

---

## Что это за проект

`zapret-gui` — веб-GUI и оркестратор средств обхода блокировок для роутеров
(Keenetic на Entware, OpenWrt, обычный Linux). Питон + Bottle на бэкенде,
vanilla-JS SPA на фронте, один `settings.json` как хранилище. Управляет
несколькими независимыми движками: nfqws2/zapret2, sing-box, mihomo,
AmneziaWG, MASQUE/usque, Opera Proxy, Telegram-туннель.

Ключевые принципы (подробно — CoderManual §1): минимум зависимостей (код едет
на роутер с `python3-light`, HTTP через `urllib`, не `requests`), логи в RAM,
singleton-менеджеры `get_xxx_manager()`, чистые функции отделены от I/O,
идемпотентный firewall, кроссплатформенность через детект платформы.

---

## Предметные справочники (скилы) — читать ПЕРЕД правкой

Каждый движок описан отдельным плотным справочником, выверенным по официальным
источникам (апстрим-репозиторий и его документация) и привязанным к нашему
коду. Это не обзорные тексты, а рабочие спецификации: точные CLI-флаги, форматы
конфигов, инварианты, типовые причины «не работает».

**Правило простое: собираешься трогать подсистему — сначала открой её скил
целиком.** Он экономит часы и предотвращает целый класс ошибок (устаревшие
флаги, несуществующие опции конфига, неверные пути на платформе).

<!-- BEGIN GENERATED SKILL INDEX -->

| Скил | Файл | О чём |
|---|---|---|
| **awg** | [`.claude/skills/awg/SKILL.md`](.claude/skills/awg/SKILL.md) | Полный справочник по AmneziaWG (AWG) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux) |
| **masque-usque** | [`.claude/skills/masque-usque/SKILL.md`](.claude/skills/masque-usque/SKILL.md) | Полный справочник по MASQUE / usque (Cloudflare WARP поверх HTTP/3) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux) |
| **mihomo** | [`.claude/skills/mihomo/SKILL.md`](.claude/skills/mihomo/SKILL.md) | Полный справочник по mihomo (MetaCubeX, ядро Clash.Meta) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux) |
| **nfqws2-strategies** | [`.claude/skills/nfqws2-strategies/SKILL.md`](.claude/skills/nfqws2-strategies/SKILL.md) | Полный справочник по nfqws2 / zapret2 в проекте zapret-gui (роутеры Keenetic на Entware) |
| **opera-proxy** | [`.claude/skills/opera-proxy/SKILL.md`](.claude/skills/opera-proxy/SKILL.md) | Полный справочник по Opera Proxy в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux): standalone-клиент Opera VPN (SurfEasy), который поднимает локальный HTTP- или SOCKS5-прокси |
| **singbox** | [`.claude/skills/singbox/SKILL.md`](.claude/skills/singbox/SKILL.md) | Полный справочник по sing-box в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt) |
| **telegram-tunnel** | [`.claude/skills/telegram-tunnel/SKILL.md`](.claude/skills/telegram-tunnel/SKILL.md) | Полный справочник по Telegram Tunnel в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt): локальный MTProto-прокси tg-ws-proxy-go (основной движок, пакет tg-ws-proxy + init.d S99tg-ws-prox… |

### Когда какой открывать

- **`awg`** — Полный справочник по AmneziaWG (AWG) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux). Использовать при любых задачах о: конфигах AWG (.conf — [Interface]/[Peer], wg-quick-расширения), параметрах обфускации (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5, J1-J3, Itime) и версиях протокола 1.0/1.5/2.0/3.0/3.1 (AWG 3+: HeaderProtectionKey, ContentPaddingAddition, Rekey*/RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts; AWG 3.1: RandomTrailers, DisableCookies), разборе и генерации конфигов (awg_config), жизненном цикле туннеля (amneziawg-go + awg setconf + ip link/addr/route, awg_manager), установке/детекте бинарей (amneziawg-go, awg/awg-quick), платформенных путях, Cloudflare WARP и WARP-in-WARP (warp_generator/warp_importer/awg_warp_in_warp), интеграции с нативным WireGuard Keenetic через NDMS (ndms/wg_discovery), watchdog/autostart, подписках, и диагностике «handshake есть, трафика нет / 92 B in, 20 KB out / туннель не поднимается». Источник истины — amnezia-vpn/amneziawg-go + amneziawg-tools + docs.amnezia.org, привязка — наш код core/awg_*.py, core/warp_*.py, core/ndms/wg_discovery.py, api/awg.py, web/js/pages/awg_*.js.
- **`masque-usque`** — Полный справочник по MASQUE / usque (Cloudflare WARP поверх HTTP/3) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux). Использовать при любых задачах о: протоколе MASQUE и CONNECT-IP (RFC 9484 / RFC 9298), CLI usque (register/enroll/nativetun/socks/http-proxy/l4-socks/l4-http-proxy/ portfw/account/version) и его флагах (-c/--config, -n/--interface-name, -s/--sni-address, -k/--keepalive-period, -m/--mtu, -I/--no-iproute2, -P/--connect-port, -6/--ipv6, -F/--no-tunnel-ipv4, -S/--no-tunnel-ipv6, --http2, --insecure, --persist, --always-reconnect, -r/--reconnect-delay, -i/--initial-packet-size, --on-connect/--on-disconnect), формате config.json (private_key ECDSA P-256, access_token, id, endpoint_v4/v6, endpoint_h2_v4/v6, endpoint_pub_key, license, ipv4, ipv6), регистрации устройства в Cloudflare и ZeroTrust (--jwt), «ленивом» подключении туннеля и том, почему «Tunnel established» не значит «подключено», настройке TUN-интерфейса (кто назначает адреса и поднимает link), профилях транспорта performance/restricted/auto (H3/QUIC против H2/TCP), SNI-маскировке, НАШЕЙ сборке бинарника (build-usque-binaries.yml, релизы usque-bin-v*, sha256 из manifest.json релиза, запасной источник usque-keenetic .ipk), регистрации через уже работающий обход (HTTPS_PROXY, транспорты awg/singbox/mihomo, мост SO_BINDTODEVICE), автозапуске, watchdog'е, WARP-in-WARP, API /api/usque/*, CLI `zapret-gui usque` и диагностике «туннель не поднимается / интерфейс есть, а трафика нет / версия показывается мусором / TLS handshake timeout при регистрации». Источники истины — Diniboy1123/usque и наша сборка, привязка — наш код core/usque_manager.py, core/usque_watchdog.py, core/iface_socks.py, api/usque.py, web/js/pages/usque.js, core/warp_in_warp.py, core/ext_binary_installer.py.
- **`mihomo`** — Полный справочник по mihomo (MetaCubeX, ядро Clash.Meta) в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux). Использовать при любых задачах о: clash-YAML конфигах (general-ключи, proxies, proxy-groups, rules, rule-providers, proxy-providers, dns/fake-ip, tun, sniffer, listeners), типах прокси (ss/vmess/vless/trojan/hysteria2/tuic/wireguard/…), CLI (mihomo -d/-f/-t/-v), external-controller (RESTful API + metacubexd), запуске/валидации/диагностике инстансов (mihomo_manager), установке/детекте бинаря и архитектурах (mihomo_installer/detector), платформенных путях, автозапуске, geo-базах, а также о НАШЕМ конвертере clash-YAML → sing-box outbounds (core/clash_yaml.py) для импорта clash-подписок. Источник истины — MetaCubeX/mihomo + wiki.metacubex.one, привязка — наш код core/mihomo_*.py, core/clash_yaml.py, api/mihomo.py, web/js/pages/mihomo.js.
- **`nfqws2-strategies`** — Полный справочник по nfqws2 / zapret2 в проекте zapret-gui (роутеры Keenetic на Entware). Использовать при любых запросах о: стратегиях nfqws2/zapret2, каталогах catalogs/*, сканере стратегий (strategy_scanner), сборке аргументов (nfqws_manager, strategy_builder, blob_registry, lua_manager), firewall / NFQUEUE-правилах (core/firewall.py), lua-desync функциях, blob'ах, hostlist'ах, оркестраторах (circular), blockcheck2-интеграции и диагностике «стратегия не работает / 0% успешности». Источник истины — bol-van/zapret2 (docs/manual.md, lua/zapret-antidpi.lua), привязка — наш код в core/.
- **`opera-proxy`** — Полный справочник по Opera Proxy в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt / Linux): standalone-клиент Opera VPN (SurfEasy), который поднимает локальный HTTP- или SOCKS5-прокси. Использовать при любых задачах о: CLI-флагах opera-proxy (-country/-bind-address/-socks-mode/-proxy-bypass/ -fake-SNI/-verbosity/-list-countries/-bootstrap-dns/-server-selection/ -api-proxy*/-timeout/-refresh/-proxy/-override-proxy-address/-config), цепочке подключения (bootstrap-DoH → api2.sec-tunnel.com → регистрация анонимного устройства → discover → CONNECT к eu0/as0/am0.sec-tunnel.com:443 по TLS с Basic-авторизацией), регионах EU/AS/AM и `-list-countries` как сетевой операции, нашем менеджере и его pid-файле, дренаже stdout, буфере «Лог», валидации настроек (parse_bind/validate_settings), watchdog'е и TCP-пробе, статусе running/listening, установке бинарника «последним релизом» с sha256-политикой pinned/unpinned, API /api/opera-proxy/*, CLI `zapret-gui opera`, мониторинге трафика и диагностике «процесс жив, а порт не отвечает / страны не загружаются / прокси не проксирует». Источник истины — Alexey71/opera-proxy (сам бинарник и его `-h`), привязка — наш код core/opera_proxy_manager.py, core/opera_proxy_watchdog.py, api/opera_proxy.py, web/js/pages/opera_proxy.js, core/ext_binary_installer.py.
- **`singbox`** — Полный справочник по sing-box в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt). Использовать при любых задачах о: конфигах sing-box (log/dns/inbounds/outbounds/endpoints/route/services/experimental), CLI (run/check/format/merge/tools/generate/rule-set), типах outbound (vless/vmess/trojan/shadowsocks/hysteria2/tuic/selector/urltest), TLS/Reality/ uTLS/ECH, transport (ws/grpc/httpupgrade/h2/quic), multiplex, прозрачном проксировании (tproxy/redirect/tun), подписках и пуле серверов (server_pool, subscription_*), парсинге vless:// vmess:// ss:// trojan:// hysteria2:// tuic://, миграциях версий 1.11/1.12/1.13/1.14 (geoip/geosite удалены в 1.12, block/dns outbounds + legacy inbound-поля + wireguard outbound удалены в 1.13, новый формат DNS с 1.12 и удаление legacy-DNS в 1.14), отладке и диагностике «sing-box не запускается / конфиг не валиден / прокси не работает». Источник истины — sing-box.sagernet.org + sagernet/sing-box, привязка — наш код core/singbox_*.py, api/singbox.py, web/js/pages/singbox*.js.
- **`telegram-tunnel`** — Полный справочник по Telegram Tunnel в проекте zapret-gui (роутеры Keenetic на Entware / OpenWrt): локальный MTProto-прокси tg-ws-proxy-go (основной движок, пакет tg-ws-proxy + init.d S99tg-ws-proxy) и резервный tg-mtproxy-client. Использовать при любых задачах о: config.conf/secret.conf и том, какие переменные реально читает init.d, CLI-флагах бинарника (--host/--port/--secret/ --cfproxy-domain/--cfproxy-worker-domain/--no-cfproxy/--cfproxy-priority/ --pool-size/--max-conns/--buf-kb/--dc-ip-default*/--fake-tls-domain/-v), режимах выхода на датацентр (direct / cfcommunity / cfdomain / hybrid / tunnel), ссылке tg://proxy и формате секрета (dd/ee + fake-TLS), ротации секрета, маршрутизации CIDR датацентров Telegram через AWG+WARP или MASQUE+WARP через единый слой, авто-регистрации CF-домена под nfqws2, установке пакета (GitHub-релиз, .ipk/.apk, sha256, opkg/apk), автозапуске и диагностике «прокси не поднимается / ссылка не работает / лога нет / обход работает через раз». Источник истины — spatiumstas/tg-ws-proxy-go (форк Flowseal/tg-ws-proxy), привязка — наш код core/tgproxy_manager.py, api/tgproxy.py, web/js/pages/tgproxy.js, core/ext_binary_installer.py.

<!-- END GENERATED SKILL INDEX -->

---

## Как проверять работу

```sh
python3 -m pytest tests/ -q      # Python-тесты (147+ файлов)
node --test tests/*.js           # JS-тесты (линтер стратегий и пр.)
make lint                        # синтаксис всех .py
```

Тесты-сторожа — заметная часть проекта: они фиксируют инварианты, которые
нельзя нарушить молча (соответствие карты lua-файлов их реальным функциям,
совместимость версий, синхронность этого индекса со скилами и т.п.). Если
такой тест упал — почти всегда сломан инвариант, а не тест.

## Рабочие соглашения

- **Язык.** Комментарии, docstring'и, сообщения коммитов, тексты в UI и
  документация — по-русски, как и весь существующий код.
- **Стиль.** Пиши так, как написан окружающий код: та же плотность
  комментариев, те же имена, те же идиомы. Новых зависимостей не добавлять.
- **Документация рядом с изменением.** Меняешь поведение — обнови
  `CHANGELOG.md`, при необходимости `README.md` / `CoderManual.md` и
  соответствующий скил.
- **Источник правды у скилов — апстрим.** Если апстрим-проект (bol-van/zapret2,
  sagernet/sing-box, MetaCubeX/mihomo, amnezia-vpn/amneziawg-go …) разошёлся со
  скилом — правь скил, а не подгоняй код под устаревший текст.

## Апстримы: чему мы соответствуем

`docs/upstream.json` — единственное место, где записана сверенная версия
каждого чужого проекта: репозиторий, `pinned`, дата сверки, скил,
vendored-файлы с sha256, отслеживаемые пути. Без него отставание не видно:
скил nfqws2 три месяца описывал zapret2 0.9.5.2, пока вышло пять релизов.

```sh
make upstream            # сверка с апстримами (нужна сеть)
make upstream-offline    # только локальные проверки, идёт в тестах
```

Еженедельный `.github/workflows/check-upstream.yml` заводит issue с меткой
`upstream-drift`, когда апстрим уходит вперёд. Работая по такой issue:
прочитай changelog между `pinned` и `latest` (важен не номер, а изменившаяся
семантика), синхронизируй vendored-файлы, **обнови скил**, потом `pinned` и
`verified_at`. Подробности — CoderManual §3.2.

Отдельно про lua: `import/lua/zapret-*.lua` — дословные копии релиза zapret2,
правятся только синхронизацией; наши расширения живут в отдельных файлах, и
каждый их вызов резолвится тестом `tests/test_lua_symbols_resolve.py`
(в Lua неизвестное имя — не ошибка загрузки, а тихо неработающая стратегия).

## Перегенерация этого индекса

Список скилов ниже автогенерируется из frontmatter самих `SKILL.md`:

```sh
python3 tools/gen_agent_index.py           # перегенерировать
python3 tools/gen_agent_index.py --check    # проверить синхронность
```

Правь текст **вне** маркеров `BEGIN/END GENERATED SKILL INDEX` — он переживает
перегенерацию. Добавил новый скил — прогони генератор.
