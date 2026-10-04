# core/blockcheck2_patch.py
"""
Клон штатного blockcheck2.sh с правками zapret-gui («мульти-доменный»
blockcheck2, вкладка «Подбор стратегий → Несколько доменов»).

Почему клон делается во время запуска, а не лежит готовым в репозитории:
blockcheck2.sh подключает соседние ``common/*.sh`` и тесты
``blockcheck2.d/*`` из установленного zapret2. Готовая копия от одной
версии с тестами другой — источник тихих расхождений. Поэтому берём
скрипт, который стоит на устройстве, и накладываем правки по якорям:
если якорь не найден (апстрим переписал функцию), правка не
применяется молча, а клон отказывается собираться — с названием
правки в ошибке.

Правки (все помечены в тексте ``# zapret-gui:``):

  stop_after  — ``GUI_STOP_AFTER=N``: набрав N рабочих стратегий на один
                тест (curl_test_https_tls12 ipv4 example.com и т.п.),
                остальные варианты этого теста не прогоняются — скрипт
                переходит к следующему тесту/домену. «Рабочая» — это
                ``code == 0`` в ``pktws_curl_test``, то есть успешны ВСЕ
                попытки ``REPEATS`` (при REPEATS=3 — 3/3; одна неудача
                даёт ненулевой код, см. ``curl_test``).
  found_mark  — каждая рабочая стратегия печатается сразу строкой
                «working strategy found» (в оригинале — только первая и
                только в конце теста), плюс строка-счётчик для GUI.
  ipt_wait    — ``iptables -w``: несколько копий blockcheck2 правят
                таблицы одновременно, и без ожидания xtables-лока часть
                правил молча не ставилась бы («Another app is currently
                holding the xtables lock»).

Параллельность доменов делает не скрипт, а ``core/blockcheck2_multi``:
несколько копий клона, по одной на группу доменов. Копии не мешают
друг другу — имена цепочек iptables, таблиц nft, очередей NFQUEUE и
временных файлов в blockcheck2.sh уже уникальны по ``$$``.

Модуль — чистые функции над текстом, тестируется без I/O.
"""

from __future__ import annotations

import re


MARK = "# zapret-gui:"

# Хелперы, которые вставляются перед pktws_curl_test(). Счётчик ведётся
# в переменной на (тест, ipv, домен): имя собирается из этих значений с
# заменой всего, что не [A-Za-z0-9_], на «_» — eval безопасен.
_HELPERS = r'''
# zapret-gui: ── правки GUI (core/blockcheck2_patch.py) ──
# zapret-gui: GUI_STOP_AFTER=N — хватит N рабочих стратегий на тест.
GUI_STOP_AFTER=${GUI_STOP_AFTER:-0}
gui_okvar()
{
	# $1 - test function, $2 - domain
	echo "GUI_OK_$(printf '%s' "${1}_${IPV}_${2}" | tr -c 'A-Za-z0-9_' '_')"
}
gui_enough()
{
	# $1 - test function, $2 - domain. 0 - лимит набран, тест пропускаем
	local v n
	[ "$GUI_STOP_AFTER" -gt 0 ] 2>/dev/null || return 1
	v=$(gui_okvar "$1" "$2")
	eval n=\${$v:-0}
	[ "$n" -ge "$GUI_STOP_AFTER" ] || return 1
	eval "[ -n \"\${${v}_SKIPMSG}\" ]" || {
		echo
		echo "* zapret-gui: $1 ipv$IPV $2 : набрано $n рабочих стратегий из $GUI_STOP_AFTER — остальные варианты этого теста пропущены"
		eval ${v}_SKIPMSG=1
	}
	return 0
}
gui_found()
{
	# $1 - test function, $2 - domain, $3 - strategy
	local v n
	v=$(gui_okvar "$1" "$2")
	eval n=\${$v:-0}
	n=$(($n+1))
	eval $v=\$n
	echo "!!!!! $1: working strategy found for ipv${IPV} $2 : $PKTWSD $3 !!!!!"
	echo "* zapret-gui: ok $n${GUI_STOP_AFTER:+/$GUI_STOP_AFTER} $1 ipv$IPV $2"
}
# zapret-gui: ── конец правок ──

'''

# (имя, regex-якорь, замена). Замена — функция от match.
_PATCHES = (
    (
        "helpers",
        re.compile(r"^pktws_curl_test\(\)\n", re.M),
        lambda m: _HELPERS + m.group(0),
    ),
    (
        "stop_after",
        re.compile(
            r"(pktws_curl_test\(\)\n\{\n(?:[ \t]*#[^\n]*\n)*"
            r"[ \t]*local testf=\$1 dom=\"\$2\" strategy code\n)"),
        lambda m: (m.group(1)
                   + "\t%s лимит рабочих стратегий на тест набран\n" % MARK
                   + '\tgui_enough "$testf" "$dom" && return 1\n'),
    ),
    (
        "found_mark",
        re.compile(
            r"(\[ \"\$code\" = 0 \] && \{\n"
            r"[ \t]*strategy=\"\$@\"\n"
            r"[ \t]*strategy_append_extra_pktws\n"
            r"[ \t]*report_append [^\n]*\n)"),
        lambda m: (m.group(1)
                   + "\t\t%s каждая рабочая стратегия — сразу\n" % MARK
                   + '\t\tgui_found "$testf" "$dom" "$strategy"\n'),
    ),
    (
        "ipt_wait",
        re.compile(r"^([ \t]*)IPTABLES=ip\$\{IPVV\}tables[ \t]*$", re.M),
        # Проверка — в момент настройки IP-версии: к этому времени
        # fix_sbin_path уже добавил /sbin в PATH.
        lambda m: (m.group(1) + "IPTABLES=ip${IPVV}tables\n"
                   + m.group(1) + "%s ждать xtables-лок, если iptables "
                   "умеет -w\n" % MARK
                   + m.group(1) + "$IPTABLES -w -L -n >/dev/null 2>&1 && "
                   "IPTABLES=\"$IPTABLES -w\""),
    ),
)

PATCH_NAMES = tuple(p[0] for p in _PATCHES)


class PatchError(RuntimeError):
    """Не нашёлся якорь правки — клон не собирается."""

    def __init__(self, missing):
        self.missing = list(missing)
        super().__init__(
            "blockcheck2.sh этой версии не удалось пропатчить: не найдено "
            "место для правок %s. Вероятно, апстрим изменил скрипт — "
            "запустите вкладку «Официальный (blockcheck2.sh)»."
            % ", ".join(self.missing))


def patch_script(text: str, source: str = "") -> str:
    """Применить все правки GUI к тексту blockcheck2.sh.

    Raises:
        PatchError: если хоть один якорь не найден (ровно один раз).
    """
    if MARK in text:
        # Уже пропатчен (повторно клонировать собственный клон незачем).
        return text
    missing = []
    out = text
    for name, rx, repl in _PATCHES:
        new, n = rx.subn(repl, out, count=1)
        if n != 1:
            missing.append(name)
            continue
        out = new
    if missing:
        raise PatchError(missing)
    header = (
        "%s клон %s с правками для мульти-доменного подбора.\n"
        "%s Сгенерирован автоматически, не редактировать: "
        "core/blockcheck2_patch.py\n" % (MARK, source or "blockcheck2.sh",
                                          MARK))
    # Шебанг оставляем первой строкой.
    if out.startswith("#!"):
        nl = out.find("\n") + 1
        return out[:nl] + header + out[nl:]
    return header + out
