"""Профили по кабелю через pymobiledevice3: список и установка.

Зачем:
  • Установка. Раздача по Wi-Fi упирается в файрвол ПК и изоляцию клиентов
    роутера (проверено: SYN телефона доходил, ПК молча отбрасывал). По кабелю
    сеть не нужна. Важно: `profile store` iOS 27 отклоняет для DNS-профиля
    (MCInstallationErrorDomain 4022 «payload type … is not permitted»), а
    `profile install` показывает на телефоне запрос на установку — его и
    используем. Lockdown Mode на время установки нужно выключить.
  • Быстрый аудит. Список профилей читается за секунду, без бэкапа и пароля —
    поэтому чужие профили (MDM, сертификаты, VPN) видны в КАЖДОМ аудите, а не
    только в deep. Содержимое профиля так не видно — только имя и
    организация; типы payload проверяет deep-режим.

pymobiledevice3 ставится в отдельное окружение (системный pip в Debian/Ubuntu
запрещён, PEP 668):
    python3 -m venv ~/.local/share/ghost-lock/venv
    ~/.local/share/ghost-lock/venv/bin/pip install pymobiledevice3

Profiles over the cable via pymobiledevice3: listing and installing.

  • Installing. Serving over Wi-Fi hits the PC firewall and router client
    isolation (verified: the phone's SYN arrived, the PC silently dropped it).
    The cable needs no network. Note: iOS 27 rejects `profile store` for a DNS
    profile (MCInstallationErrorDomain 4022 "payload type … is not
    permitted"), while `profile install` shows an install prompt on the phone —
    that is what we use. Lockdown Mode must be off while installing.
  • Quick audit. The profile list is read in a second, no backup or password,
    so foreign profiles (MDM, certificates, VPN) show up in EVERY audit, not
    only deep. Contents are not visible this way — only name and organization;
    payload types are checked by deep mode.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding

VENV_BIN = Path.home() / ".local" / "share" / "ghost-lock" / "venv" / "bin" / "pymobiledevice3"
TIMEOUT = 60
OWN_PREFIX = "cc.ghostlock."
FOREIGN_WEIGHT = 5  # тип неизвестен без deep / type unknown without deep
INSTALL_HINT = ("python3 -m venv ~/.local/share/ghost-lock/venv && "
                "~/.local/share/ghost-lock/venv/bin/pip install pymobiledevice3")


class UsbProfileError(RuntimeError):
    pass


class LockdownModeError(UsbProfileError):
    """iOS отказывает в установке из-за Lockdown Mode — дальше пробовать бессмысленно.

    iOS refuses the install because of Lockdown Mode — no point trying further.
    """


def pmd3() -> str | None:
    env = os.environ.get("GHOST_LOCK_PMD3")
    if env and Path(env).exists():
        return env
    if VENV_BIN.exists():
        return str(VENV_BIN)
    return shutil.which("pymobiledevice3")


def _run(args: list[str], udid: str | None) -> subprocess.CompletedProcess:
    exe = pmd3()
    if not exe:
        raise UsbProfileError(f"pymobiledevice3 не установлен: {INSTALL_HINT}")
    cmd = [exe, *args]
    if udid:
        cmd += ["--udid", udid]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise UsbProfileError("телефон не ответил (разблокирован? кабель?)") from None
    except OSError as e:
        raise UsbProfileError(f"pymobiledevice3 не запускается: {e}") from None


def _device_error(proc: subprocess.CompletedProcess) -> str:
    text = f"{proc.stdout}\n{proc.stderr}"
    for marker in ("LocalizedDescription': '", 'LocalizedDescription": "'):
        if marker in text:
            return text.split(marker, 1)[1].split(marker[-1], 1)[0]
    lines = [l for l in text.strip().splitlines() if "ERROR" in l] or text.strip().splitlines()
    return lines[-1].strip() if lines else f"exit {proc.returncode}"


@dataclass
class UsbProfile:
    identifier: str
    name: str = ""
    organization: str = ""

    @property
    def own(self) -> bool:
        return self.identifier.startswith(OWN_PREFIX)


def parse_profile_list(stdout: str) -> list[UsbProfile]:
    """JSON-ответ `profile list` → профили. / `profile list` JSON → profiles."""
    try:
        data = json.loads(stdout[stdout.index("{"):])
    except ValueError:
        raise UsbProfileError("непонятный ответ pymobiledevice3") from None
    if data.get("Status") not in (None, "Acknowledged"):
        raise UsbProfileError(f"телефон ответил: {data.get('Status')}")
    meta: dict[str, Any] = data.get("ProfileMetadata") or {}
    idents = list(data.get("OrderedIdentifiers") or []) or list(meta)
    out = []
    for ident in dict.fromkeys(idents):
        m = meta.get(ident) or {}
        out.append(UsbProfile(identifier=str(ident),
                              name=str(m.get("PayloadDisplayName", "")),
                              organization=str(m.get("PayloadOrganization", ""))))
    return out


def list_profiles(udid: str | None = None) -> list[UsbProfile]:
    proc = _run(["profile", "list"], udid)
    if proc.returncode != 0:
        raise UsbProfileError(_device_error(proc))
    return parse_profile_list(proc.stdout)


def install_profile(path: Path, udid: str | None = None) -> None:
    """Показывает на телефоне запрос на установку профиля.

    Shows a profile install prompt on the phone.
    """
    proc = _run(["profile", "install", str(path)], udid)
    if proc.returncode != 0 or "rejected" in proc.stdout + proc.stderr:
        reason = _device_error(proc)
        if "lockdown mode" in reason.lower():
            raise LockdownModeError(reason)
        if "not permitted" in reason or "4022" in proc.stdout + proc.stderr:
            reason += " — выключен ли Lockdown Mode?"
        raise UsbProfileError(reason)


@dataclass
class QuickAudit:
    profiles: list[UsbProfile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    lines: list[tuple[bool | None, str]] = field(default_factory=list)


def quick_audit(profiles: list[UsbProfile], iocs: dict[str, Any]) -> QuickAudit:
    """Чужие профили по списку с телефона (без содержимого).

    Foreign profiles from the phone's list (without contents).
    """
    rep = QuickAudit(profiles=profiles)
    stalker = [str(x.get("value", "")).lower() for x in iocs.get("stalkerware_profiles", [])
               if isinstance(x, dict) and "." in str(x.get("value", ""))]
    foreign = [p for p in profiles if not p.own]
    for p in foreign:
        label = p.name or p.identifier
        org = f", «{p.organization}»" if p.organization else ""
        hit = next((s for s in stalker if p.identifier.lower().startswith(s)), None)
        rep.findings.append(Finding(
            ioc_type="stalkerware_profiles" if hit else "profile",
            value=p.identifier, weight=9 if hit else FOREIGN_WEIGHT,
            source=("префикс сталкерского ПО из базы IOC" if hit
                    else "чужой профиль: что внутри (MDM, сертификат, VPN), покажет audit --deep"),
            location=f"profile:{p.identifier}", context=f"«{label}»{org}",
        ))
    own = [p for p in profiles if p.own]
    if foreign:
        rep.lines.append((False, "Чужие профили: " + ", ".join(
            f"«{p.name or p.identifier}»" for p in foreign)))
    else:
        rep.lines.append((True, f"Чужих профилей нет (ghost-lock: {len(own)})"))
    return rep
