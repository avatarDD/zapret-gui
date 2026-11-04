# core/nat_offload.py
"""
Ускорение NAT роутера: узнать, включено ли, и переключить по запросу.

Программная и аппаратная разгрузка потоков уводит установленное
соединение мимо netfilter: правила видят только его начало. geneva (и
«Авто») тогда не видит ClientHello устройств, и стратегия работает лишь
для самого роутера. Переключатель стоит на странице geneva; ничего не
меняется без явного действия пользователя (кнопка и подтверждение).

* **OpenWrt** — ``firewall.@defaults[0].flow_offloading`` (программная)
  и ``flow_offloading_hw`` (аппаратная) через ``uci``, затем
  ``uci commit firewall`` и ``/etc/init.d/firewall reload``.
  Выключение выключает обе, включение возвращает те, что были включены
  до выключения из GUI (``geneva.nat_offload_saved``; иначе — только
  программную).
* **Keenetic** — ``ppe software`` и ``ppe hardware`` в CLI (``ndmc``),
  затем ``system configuration save``. Выключено — строки
  ``no ppe software``/``no ppe hardware`` в ``show running-config``.

Прочие системы — ``supported: false``.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from core.log_buffer import log

OPENWRT_FIREWALL = "/etc/config/firewall"
UCI_SW = "firewall.@defaults[0].flow_offloading"
UCI_HW = "firewall.@defaults[0].flow_offloading_hw"


def _run(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def _truthy(v: str) -> bool:
    return str(v or "").strip().strip("'\"").lower() in ("1", "on", "true",
                                                         "yes")


def parse_keenetic_running(text: str) -> dict:
    """``show running-config`` → ``{software, hardware}``: включено ли.
    По умолчанию оба движка включены; выключенный — строка ``no ppe …``."""
    sw = hw = True
    for line in (text or "").splitlines():
        s = " ".join(line.split()).lower()
        if s == "no ppe software":
            sw = False
        elif s == "no ppe hardware":
            hw = False
    return {"software": sw, "hardware": hw}


class NatOffload:
    """Подменяемые ``run``/``platform``/``cfg`` — для тестов."""

    def __init__(self, *, run=_run, platform=None, cfg=None):
        self._run = run
        self._platform = platform
        self._cfg = cfg

    def platform(self) -> str:
        if self._platform is not None:
            return self._platform
        from core.system_info import platform_kind
        kind = platform_kind()
        if kind == "openwrt" and not (shutil.which("uci") and
                                      os.path.exists(OPENWRT_FIREWALL)):
            return "linux"
        if kind == "keenetic" and not shutil.which("ndmc"):
            return "linux"
        return kind

    def _config(self):
        if self._cfg is not None:
            return self._cfg
        from core.config_manager import get_config_manager
        return get_config_manager()

    # ── состояние ──

    def status(self) -> dict:
        """``{supported, platform, enabled, software, hardware, error}``."""
        kind = self.platform()
        out = {"supported": kind in ("openwrt", "keenetic"),
               "platform": kind, "enabled": False, "software": False,
               "hardware": False, "error": ""}
        if kind == "openwrt":
            for key, name in ((UCI_SW, "software"), (UCI_HW, "hardware")):
                ok, text = self._run(["uci", "-q", "get", key])
                out[name] = ok and _truthy(text)
        elif kind == "keenetic":
            ok, text = self._run(["ndmc", "-c", "show running-config"])
            if not ok:
                out["error"] = text.strip()[:300]
                return out
            out.update(parse_keenetic_running(text))
        out["enabled"] = bool(out["software"] or out["hardware"])
        return out

    # ── переключение ──

    def set(self, enabled: bool) -> dict:
        """Включить или выключить ускорение. Ответ — :meth:`status` плюс
        ``ok``; ``error`` — что не удалось."""
        st = self.status()
        if not st["supported"]:
            return dict(st, ok=False, error_code="unsupported",
                        error="переключение ускорения NAT есть только на "
                              "OpenWrt и Keenetic")
        cfg = self._config()
        if enabled:
            saved = cfg.get("geneva", "nat_offload_saved", default=None) or {}
            # без сохранённого: на Keenetic по умолчанию включены оба
            # движка, на OpenWrt — только программная разгрузка
            hw_default = st["platform"] == "keenetic"
            want = {"software": bool(saved.get("software", True)),
                    "hardware": bool(saved.get("hardware", hw_default))}
            if not want["software"] and not want["hardware"]:
                want["software"] = True
        else:
            if st["enabled"]:
                cfg.set("geneva", "nat_offload_saved",
                        {"software": st["software"],
                         "hardware": st["hardware"]})
                try:
                    cfg.save()
                except Exception:                   # noqa: BLE001
                    pass
            want = {"software": False, "hardware": False}
        steps = self._steps(st["platform"], want)
        for argv in steps:
            ok, text = self._run(argv)
            if not ok:
                log.warning("ускорение NAT: %s: %s" % (" ".join(argv), text),
                            source="geneva")
                out = self.status()
                return dict(out, ok=False, error_code="command_failed",
                            error="%s: %s" % (" ".join(argv),
                                              text.strip()[:300]))
        log.info("ускорение NAT %s (по запросу пользователя)"
                 % ("включено" if enabled else "выключено"), source="geneva")
        return dict(self.status(), ok=True)

    @staticmethod
    def _steps(kind: str, want: dict) -> list:
        if kind == "openwrt":
            return [["uci", "set", "%s=%d" % (UCI_SW, int(want["software"]))],
                    ["uci", "set", "%s=%d" % (UCI_HW, int(want["hardware"]))],
                    ["uci", "commit", "firewall"],
                    ["/etc/init.d/firewall", "reload"]]
        steps = []
        for name in ("software", "hardware"):
            steps.append(["ndmc", "-c", ("ppe %s" if want[name]
                                         else "no ppe %s") % name])
        steps.append(["ndmc", "-c", "system configuration save"])
        return steps


_inst = None


def get_nat_offload() -> NatOffload:
    global _inst
    if _inst is None:
        _inst = NatOffload()
    return _inst
