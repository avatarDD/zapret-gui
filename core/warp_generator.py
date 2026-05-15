# core/warp_generator.py
"""
Нативная генерация AmneziaWG-WARP конфигов.

Логика повторяет то, что делают сторонние WARP-генераторы
(warp-generator.github.io и т. п.):
  1) сгенерировать пару X25519 ключей;
  2) зарегистрировать аккаунт через неофициальный API
     Cloudflare (api.cloudflareclient.com /v0a2483/reg);
  3) опционально активировать WARP+ ключ;
  4) сгенерировать параметры AmneziaWG-обфускации;
  5) собрать .conf и (опционально) сохранить через AwgManager.

Использование:
    from core.warp_generator import generate_warp_config
    res = generate_warp_config(license_key=None, save=True)
    # res = {
    #   "ok": True,
    #   "name": "warp-gen-ab12cd",
    #   "text": "...",
    #   "parsed": {...},
    #   "account": {...},
    #   "saved": True,
    # }

Без новых зависимостей: только stdlib (urllib, ssl, json, secrets).
"""

import base64
import json
import random
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request

from core.awg_config import (
    derive_public_key,
    generate_keypair,
    parse_conf,
    render_conf,
)
from core.log_buffer import log


# ───────────────────────── Константы Cloudflare API ─────────────────
#
# Версии и заголовки выносим сюда, чтобы при изменении API не пришлось
# править логику. Значения подобраны под текущий v0a2483, который
# используется большинством WARP-клиентов.
#
CF_API_BASE        = "https://api.cloudflareclient.com"
CF_API_VERSION     = "v0a2483"
CF_CLIENT_VERSION  = "a-6.30-3596"        # Android-стиль, как в офиц. клиенте
CF_USER_AGENT      = "okhttp/3.12.1"

# Дефолтный endpoint и peer-ключ Cloudflare WARP (на случай, если
# регистрационный ответ почему-то не содержит полных данных).
DEFAULT_WARP_ENDPOINT_HOST = "engage.cloudflareclient.com"
DEFAULT_WARP_ENDPOINT_PORT = 2408
DEFAULT_WARP_PEER_PUBKEY   = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# Сколько ждём сетевых ответов. Cloudflare API из РФ часто отвечает
# медленно (DPI замедляет SNI=api.cloudflareclient.com), поэтому
# таймаут выбран с запасом.
HTTP_TIMEOUT = 30

# Сколько раз пытаемся повторить запрос при «прозрачных» сетевых
# ошибках (timeout, обрыв соединения, SSL handshake timeout).
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF = 2.0  # секунд между попытками (умножается на номер попытки)

# AmneziaWG обфускация — диапазоны параметров
JC_MIN, JC_MAX  = 4, 12
JMIN_VALUE      = 40
JMAX_VALUE      = 70
SX_MIN, SX_MAX  = 15, 100
HX_MIN, HX_MAX  = 5, 0x7FFFFFFF

# Источник: значения, которые нельзя ставить в S1/S2, чтобы суммарно
# не совпасть с фиксированными размерами WireGuard-пакетов. Берём
# значения, которые точно не пересекаются (handshake initiation = 148,
# handshake response = 92, cookie reply = 64, transport min = 32).
WG_FIXED_PACKET_SIZES = (32, 64, 92, 148)


# ───────────────────────── network helpers ──────────────────────────

class WarpApiError(RuntimeError):
    """Ошибка взаимодействия с Cloudflare WARP API."""
    pass


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _is_transient_error(exc: BaseException) -> bool:
    """
    Сетевая ошибка, которую имеет смысл повторить:
      - SSL handshake timeout (часто из-за DPI/нестабильной сети);
      - обычный socket.timeout;
      - ConnectionResetError / refused / aborted;
      - DNS-сбой (gaierror) — иногда восстанавливается со второй попытки.
    """
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    if isinstance(exc, ssl.SSLError):
        # "_ssl.c:...: The handshake operation timed out" и подобные
        return True
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (socket.timeout, TimeoutError, ssl.SSLError)):
            return True
        # Иногда reason — строка вроде "_ssl.c:989: The handshake operation
        # timed out"; ловим её эвристически.
        if isinstance(reason, str) and "timed out" in reason.lower():
            return True
        if isinstance(reason, (ConnectionResetError, ConnectionRefusedError,
                               ConnectionAbortedError, socket.gaierror)):
            return True
    if isinstance(exc, (ConnectionResetError, ConnectionRefusedError,
                        ConnectionAbortedError)):
        return True
    return False


def _format_network_error(exc: BaseException) -> str:
    """
    Сформировать сообщение, которое поможет пользователю понять, что
    делать. SSL handshake timeout до api.cloudflareclient.com в РФ —
    почти всегда блокировка/замедление DPI.
    """
    reason = exc
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", exc) or exc

    text = str(reason) or exc.__class__.__name__
    text_low = text.lower()
    looks_like_handshake_timeout = (
        isinstance(reason, ssl.SSLError)
        or ("handshake" in text_low and "timed out" in text_low)
    )
    if looks_like_handshake_timeout:
        return ("Не удалось установить TLS-соединение с "
                "api.cloudflareclient.com (handshake timeout). Скорее всего, "
                "доступ к Cloudflare API ограничен или замедлен провайдером. "
                "Запустите zapret/DPI-обход или попробуйте через VPN и "
                "сгенерируйте конфиг ещё раз.")
    return "Сеть до api.cloudflareclient.com недоступна: %s" % text


def _request_json(method: str, url: str, body: dict = None,
                  extra_headers: dict = None) -> dict:
    """
    Отправить HTTP-запрос с JSON-телом и распарсить JSON-ответ.
    Бросает WarpApiError с понятным сообщением. Делает несколько
    попыток при «прозрачных» сетевых ошибках.
    """
    headers = {
        "Content-Type":      "application/json; charset=UTF-8",
        "User-Agent":        CF_USER_AGENT,
        "CF-Client-Version": CF_CLIENT_VERSION,
        "Accept":            "*/*",
        "Accept-Encoding":   "identity",
    }
    if extra_headers:
        headers.update(extra_headers)

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    last_transient = None
    for attempt in range(1, HTTP_RETRIES + 1):
        req = urllib.request.Request(url=url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT,
                                        context=_ssl_context()) as resp:
                raw = resp.read()
            break
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            raise WarpApiError(
                "Cloudflare API ответил %d %s: %s"
                % (e.code, e.reason, body_text)
            )
        except Exception as e:
            if _is_transient_error(e) and attempt < HTTP_RETRIES:
                last_transient = e
                log.warning(
                    "WARP: попытка %d/%d не удалась (%s), повтор через %.1fс"
                    % (attempt, HTTP_RETRIES, e,
                       HTTP_RETRY_BACKOFF * attempt),
                    source="warp_generator")
                time.sleep(HTTP_RETRY_BACKOFF * attempt)
                continue
            if isinstance(e, (urllib.error.URLError, ssl.SSLError,
                              socket.timeout, TimeoutError, OSError)):
                raise WarpApiError(_format_network_error(e))
            raise
    else:
        # Все попытки исчерпаны транзиентной ошибкой
        raise WarpApiError(_format_network_error(last_transient))

    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise WarpApiError("Некорректный JSON от Cloudflare API: %s" % e)


# ───────────────────────── obfuscation params ───────────────────────

def generate_obfuscation_params() -> dict:
    """
    Сгенерировать набор AmneziaWG-обфускации (Jc, Jmin, Jmax, S1, S2,
    H1..H4). H1..H4 уникальны между собой.
    """
    rng = random.SystemRandom()

    s_pool = [v for v in range(SX_MIN, SX_MAX + 1)
              if v not in WG_FIXED_PACKET_SIZES]
    s1 = rng.choice(s_pool)
    s_pool2 = [v for v in s_pool if v != s1]
    s2 = rng.choice(s_pool2)

    # H1..H4 — четыре разных uint32 в [HX_MIN, HX_MAX]
    h_set = set()
    while len(h_set) < 4:
        h_set.add(rng.randint(HX_MIN, HX_MAX))
    h1, h2, h3, h4 = list(h_set)

    return {
        "Jc":   rng.randint(JC_MIN, JC_MAX),
        "Jmin": JMIN_VALUE,
        "Jmax": JMAX_VALUE,
        "S1":   s1,
        "S2":   s2,
        "H1":   h1,
        "H2":   h2,
        "H3":   h3,
        "H4":   h4,
    }


# ───────────────────────── account registration ─────────────────────

def _new_install_id() -> str:
    """22-символьный ID, как у официального клиента."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)) \
        .decode("ascii").rstrip("=")[:22]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def register_warp_account(public_key: str) -> dict:
    """
    Зарегистрировать новый WARP-аккаунт. Возвращает полный JSON-ответ
    Cloudflare, плюс стабильные поля под ключами account_id, token.
    """
    install_id = _new_install_id()

    body = {
        "key":        public_key,
        "install_id": install_id,
        "fcm_token":  "",
        "tos":        _now_iso(),
        "type":       "Android",
        "model":      "PC",
        "locale":     "en_US",
    }

    url = "%s/%s/reg" % (CF_API_BASE, CF_API_VERSION)
    resp = _request_json("POST", url, body=body)

    if not isinstance(resp, dict) or "id" not in resp:
        raise WarpApiError("Ответ регистрации не содержит id аккаунта")

    resp["_install_id"] = install_id
    return resp


def apply_warp_plus_license(account_id: str, token: str,
                            license_key: str) -> dict:
    """
    Активировать WARP+ ключ на свежем аккаунте. Бросает WarpApiError
    при неудаче.
    """
    url = "%s/%s/reg/%s/account" % (CF_API_BASE, CF_API_VERSION, account_id)
    headers = {"Authorization": "Bearer %s" % token}
    return _request_json("PUT", url, body={"license": license_key},
                         extra_headers=headers)


def fetch_warp_account(account_id: str, token: str) -> dict:
    """Получить актуальное состояние аккаунта (после применения ключа)."""
    url = "%s/%s/reg/%s/account" % (CF_API_BASE, CF_API_VERSION, account_id)
    headers = {"Authorization": "Bearer %s" % token}
    return _request_json("GET", url, body=None, extra_headers=headers)


# ───────────────────────── helpers: parse account ───────────────────

def _extract_endpoint(account: dict) -> tuple:
    """
    Извлечь (host, port) для peer.Endpoint из ответа регистрации.
    Возвращает значения по умолчанию, если ответ неполный.
    """
    cfg   = (account or {}).get("config") or {}
    peers = cfg.get("peers") or []
    if peers:
        ep = (peers[0] or {}).get("endpoint") or {}
        host_v4 = ep.get("v4") or ""
        host    = ep.get("host") or host_v4
        if host and ":" in host and not host.startswith("["):
            # endpoint в виде "host:port"
            h, _, p = host.rpartition(":")
            try:
                return h, int(p)
            except ValueError:
                pass
        if host:
            return host, DEFAULT_WARP_ENDPOINT_PORT
    return DEFAULT_WARP_ENDPOINT_HOST, DEFAULT_WARP_ENDPOINT_PORT


def _extract_peer_pubkey(account: dict) -> str:
    cfg   = (account or {}).get("config") or {}
    peers = cfg.get("peers") or []
    if peers:
        pk = (peers[0] or {}).get("public_key") or ""
        if pk:
            return pk
    return DEFAULT_WARP_PEER_PUBKEY


def _extract_addresses(account: dict) -> list:
    cfg   = (account or {}).get("config") or {}
    iface = cfg.get("interface") or {}
    addrs = iface.get("addresses") or {}
    out = []
    v4 = addrs.get("v4")
    v6 = addrs.get("v6")
    if v4:
        out.append("%s/32" % v4)
    if v6:
        out.append("%s/128" % v6)
    return out


def _extract_client_id_reserved(account: dict) -> list:
    """
    Cloudflare возвращает client_id (base64) — некоторые клиенты
    добавляют его в виде Reserved = a, b, c. Делать не обязательно,
    AmneziaWG-клиент отлично работает без него, поэтому вернём
    пустой список — оставляем место для будущего расширения.
    """
    return []


# ───────────────────────── building config ──────────────────────────

def build_config(account: dict, private_key: str,
                 obfuscation: dict = None,
                 dns: list = None,
                 mtu: int = 1280) -> dict:
    """
    Собрать parsed-структуру AWG-конфига из ответа регистрации и
    приватного ключа клиента.
    """
    obf = obfuscation or generate_obfuscation_params()
    dns_list = dns or ["1.1.1.1", "1.0.0.1"]

    addrs = _extract_addresses(account)
    if not addrs:
        # Хотя бы какой-то адрес — иначе awg-quick откажется
        addrs = ["172.16.0.2/32"]

    host, port = _extract_endpoint(account)
    peer_pub   = _extract_peer_pubkey(account)

    iface = {
        "PrivateKey": private_key,
        "Address":    addrs,
        "DNS":        dns_list,
        "MTU":        mtu,
        # AmneziaWG-обфускация
        "Jc":   obf["Jc"], "Jmin": obf["Jmin"], "Jmax": obf["Jmax"],
        "S1":   obf["S1"], "S2":   obf["S2"],
        "H1":   obf["H1"], "H2":   obf["H2"],
        "H3":   obf["H3"], "H4":   obf["H4"],
    }

    peer = {
        "PublicKey":  peer_pub,
        "AllowedIPs": ["0.0.0.0/0", "::/0"],
        "Endpoint":   "%s:%d" % (host, port),
    }

    return {"interface": iface, "peers": [peer]}


# ───────────────────────── naming ──────────────────────────────────

def _short_id(n: int = 6) -> str:
    """Короткий случайный hex-id."""
    return secrets.token_hex(max(1, n // 2))[:n]


def pick_generated_name(existing_names) -> str:
    """
    Вернуть свободное имя warp-gen-<id>, длиной ≤ 15 символов
    (ограничение awg_manager._valid_iface_name).
    """
    taken = set(existing_names or [])
    # warp-gen- = 9 символов, +6 случайных = 15
    for _ in range(50):
        name = "warp-gen-%s" % _short_id(6)
        if name not in taken:
            return name
    # Запасной вариант: warp-N
    for i in range(1, 1000):
        name = "warp-%d" % i
        if name not in taken:
            return name
    raise RuntimeError("Не удалось подобрать имя для warp-конфига")


# ───────────────────────── high-level API ───────────────────────────

def generate_warp_config(license_key: str = None,
                         save: bool = False,
                         name: str = None,
                         dns: list = None,
                         mtu: int = 1280,
                         awg_binary: str = None) -> dict:
    """
    Сгенерировать новый AWG-WARP конфиг.

    Параметры:
        license_key — опц. WARP+ ключ для апгрейда
        save        — если True, сохранить через AwgManager
        name        — желаемое имя (если None — авто)
        dns, mtu    — параметры [Interface]
        awg_binary  — путь к awg для генерации ключей

    Возвращает dict:
        {
          "ok":      True,
          "name":    "warp-gen-ab12cd",
          "text":    "...",                # render_conf(parsed)
          "parsed":  {...},
          "account": {                     # минимально нужное от CF
            "id":              "...",
            "type":            "free|warp_plus",
            "premium_data":    int,
            "quota":           int,
            "endpoint":        "host:port",
            "client_v4":       "172.16.x.x",
            "client_v6":       "2606:..."
          },
          "saved":   bool,
          "warnings": [...]
        }

    При ошибках бросает WarpApiError или RuntimeError с понятным
    сообщением.
    """
    warnings = []

    # 1) Ключи
    if awg_binary is None:
        try:
            from core.awg_installer import get_awg_installer
            info = get_awg_installer().get_installed_version() or {}
            awg_binary = info.get("awg") or None
        except Exception:
            awg_binary = None
    try:
        priv, pub = generate_keypair(awg_binary=awg_binary)
    except RuntimeError as e:
        raise RuntimeError("Не удалось сгенерировать пару ключей: %s" % e)

    # 2) Регистрация
    log.info("WARP: регистрация нового аккаунта", source="warp_generator")
    account = register_warp_account(pub)
    account_id = account.get("id") or ""
    token      = (account.get("token")
                  or (account.get("config") or {}).get("token")
                  or "")

    # 3) WARP+ ключ
    if license_key:
        license_key = license_key.strip()
    if license_key and account_id and token:
        try:
            log.info("WARP: применение WARP+ ключа", source="warp_generator")
            apply_warp_plus_license(account_id, token, license_key)
            # перезапросить актуальный конфиг
            updated = fetch_warp_account(account_id, token)
            # У некоторых ответов config переезжает на верхний уровень
            if isinstance(updated, dict) and updated.get("config"):
                account["config"] = updated["config"]
            if isinstance(updated, dict) and updated.get("account"):
                # на случай вложенности
                acc = updated["account"]
                for key in ("warp_plus", "premium_data", "quota",
                            "account_type"):
                    if key in acc:
                        account[key] = acc[key]
            for key in ("warp_plus", "premium_data", "quota",
                        "account_type"):
                if key in updated:
                    account[key] = updated[key]
        except WarpApiError as e:
            warnings.append("WARP+ ключ не применён: %s" % e)
            log.warning("WARP+ ключ не применён: %s" % e,
                        source="warp_generator")

    # 4) Обфускация + сборка конфига
    obfuscation = generate_obfuscation_params()
    parsed = build_config(account, priv, obfuscation=obfuscation,
                          dns=dns, mtu=mtu)
    text = render_conf(parsed)

    # 5) Имя
    chosen_name = (name or "").strip() or None
    if save or chosen_name:
        from core.awg_manager import get_awg_manager
        mgr = get_awg_manager()
        existing = [c["name"] for c in mgr.list_configs()]
        if not chosen_name:
            chosen_name = pick_generated_name(existing)

    saved = False
    if save:
        from core.awg_manager import get_awg_manager
        mgr = get_awg_manager()
        try:
            mgr.save_config(chosen_name, text=text, allow_overwrite=False)
            saved = True
            log.info("WARP: сохранён конфиг %s" % chosen_name,
                     source="warp_generator")
        except FileExistsError:
            warnings.append("Конфиг с именем '%s' уже существует, "
                            "сохранение пропущено" % chosen_name)

    # Что вернуть про аккаунт — краткая выжимка для UI
    addrs = _extract_addresses(account)
    host, port = _extract_endpoint(account)
    account_summary = {
        "id":           account_id,
        "type":         account.get("account_type")
                          or ("warp_plus"
                              if account.get("warp_plus") else "free"),
        "warp_plus":    bool(account.get("warp_plus")),
        "premium_data": account.get("premium_data") or 0,
        "quota":        account.get("quota") or 0,
        "endpoint":     "%s:%d" % (host, port),
        "client_v4":    addrs[0].split("/")[0] if addrs else "",
        "client_v6":    addrs[1].split("/")[0] if len(addrs) > 1 else "",
    }

    return {
        "ok":       True,
        "name":     chosen_name or "",
        "text":     text,
        "parsed":   parsed,
        "account":  account_summary,
        "saved":    saved,
        "warnings": warnings,
    }
