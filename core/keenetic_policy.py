# core/keenetic_policy.py
"""
Политика доступа Keenetic для перехвата nfqws2 (как POLICY_NAME /
POLICY_EXCLUDE в nfqws2-keenetic).

В веб-интерфейсе Keenetic («Приоритеты подключений → Политики доступа в
интернет») создаётся политика, например «nfqws», и в неё добавляются
устройства. NDMS метит пакеты устройств политики своим fwmark; по этой
метке правила перехвата решают, чей трафик уводить в NFQUEUE:

  • включение (exclude=False) — только устройства политики. Пакеты
    остальных помечаются connmark-исключением (тем же MARK_EXCLUDE, что
    и прочие исключения), и ответы их соединений тоже идут мимо очереди;
  • исключение (exclude=True) — все, кроме устройств политики.

Имя политики сравнивается с её описанием (description), как в
nfqws2-keenetic. Политики с таким именем нет — обрабатывается весь трафик
(и об этом пишем в журнал): молча выключать обход нельзя.

Метку читаем из `ndmc -c show ip policy`: строка с
«description = <имя>:», в следующей — «mark: <hex>». Маска 0x0fffffff —
как у nfqws2-keenetic: старшие биты заняты нашими метками
(0x40000000 — обработано nfqws2, 0x20000000 — исключение).
"""

import os
import re
import subprocess

from core.log_buffer import log


POLICY_MASK = "0x0fffffff"

_NDMC_PATHS = ("/bin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc")


def clean_name(name) -> str:
    """Имя политики без символов, опасных в grep-шаблоне shell-скриптов."""
    return re.sub(r"[^\w .-]", "", str(name or ""), flags=re.UNICODE).strip()


def parse_policy_mark(text: str, name: str) -> str:
    """Метка политики с описанием ``name`` из вывода ``show ip policy``.

    Чистая функция. Возвращает «0x<hex>/0x0fffffff» или "".
    """
    name = (name or "").strip()
    if not name or not text:
        return ""
    lines = str(text).splitlines()
    needle = ("description = %s:" % name).lower()
    for i, line in enumerate(lines):
        if needle not in line.lower():
            continue
        # Как `grep -A 1` у nfqws2-keenetic: сама строка и следующая.
        for nxt in lines[i:i + 2]:
            if "mark:" in nxt:
                val = nxt.strip().split()[-1].lower()
                if val.startswith("0x"):
                    val = val[2:]
                if re.fullmatch(r"[0-9a-f]{1,8}", val):
                    return "0x%s/%s" % (val, POLICY_MASK)
                return ""
    return ""


def _ndmc_show_policy() -> str:
    ndmc = next((p for p in _NDMC_PATHS if os.path.exists(p)), None)
    if not ndmc:
        return ""
    # ndmc — системный бинарь прошивки: с библиотеками Entware из
    # LD_LIBRARY_PATH он может не запуститься (так же делает nfqws2-keenetic).
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/lib:/usr/lib"
    try:
        r = subprocess.run([ndmc, "-c", "show ip policy"],
                           capture_output=True, text=True, timeout=5,
                           env=env)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (r.stdout or "") + "\n" + (r.stderr or "")


def resolve(cfg) -> dict:
    """Настройки политики → {name, exclude, mark}. mark "" — не применять."""
    name = clean_name(cfg.get("firewall", "keenetic_policy", default=""))
    exclude = bool(cfg.get("firewall", "keenetic_policy_exclude",
                           default=False))
    out = {"name": name, "exclude": exclude, "mark": ""}
    if not name:
        return out
    out["mark"] = parse_policy_mark(_ndmc_show_policy(), name)
    if out["mark"]:
        log.info("Найдена политика Keenetic «%s» (метка %s): %s"
                 % (name, out["mark"],
                    "её устройства исключены из обхода" if exclude
                    else "обход только для её устройств"),
                 source="firewall")
    else:
        log.warning("Политика Keenetic «%s» не найдена (ndmc show ip "
                    "policy) — обрабатывается трафик всех устройств"
                    % name, source="firewall")
    return out
