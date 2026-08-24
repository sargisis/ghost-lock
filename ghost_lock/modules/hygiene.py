"""Чек гигиены безопасности через кабель.

lockdownd отдаёт минимум, но самое важное: PasswordProtected.
Код-пароль — фундамент всей защиты: без него Face ID, USB Restricted
Mode и автостирание не работают, а телефон разблокируется касанием.
Биометрия по кабелю не читается (приватность iOS) — честно пишем это.

Security hygiene check over the cable.

lockdownd exposes little, but the most important thing: PasswordProtected.
The passcode is the foundation of all protection: without it Face ID, USB
Restricted Mode and auto-erase do not work, and the phone unlocks with a
touch. Biometrics cannot be read over cable (iOS privacy) — we say so honestly.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INFO_TIMEOUT = 20


@dataclass
class HygieneCheck:
    key: str          # машинное имя / machine name
    ok: bool | None   # True хорошо / False плохо / None неизвестно
                      # True good / False bad / None unknown
    title: str
    note: str = ""


def fetch_info(udid: str | None = None) -> dict[str, Any]:
    cmd = ["ideviceinfo"]
    if udid:
        cmd += ["-u", udid]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=INFO_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    info: dict[str, Any] = {}
    for line in proc.stdout.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    return info


def check_hygiene(info: dict[str, Any] | None = None,
                  udid: str | None = None) -> list[HygieneCheck]:
    if info is None:
        info = fetch_info(udid)

    checks: list[HygieneCheck] = []

    # Код-пароль: краеугольный камень. НО: ключ PasswordProtected —
    # легаси и на iOS 27 НЕНАДЁЖЕН (проверено на живом устройстве:
    # пароль+Face ID включены, ключ стабильно false при любом состоянии
    # экрана). Реальный статус без MDM-супервизии недоступен, поэтому
    # false трактуем как «неизвестно», никогда как «выключен».
    # Passcode: the cornerstone. BUT the PasswordProtected key is legacy and
    # UNRELIABLE on iOS 27 (verified on a live device: passcode + Face ID on,
    # yet the key stays false in every screen state). The real status is not
    # available without MDM supervision, so we treat false as "unknown",
    # never as "disabled".
    pp = info.get("PasswordProtected")
    pp_state = None if pp is None else str(pp).strip().lower() == "true"
    if pp_state is True:
        checks.append(HygieneCheck("passcode", True, "Код-пароль: устройство сообщает о защите",
                                   "Проверь вручную: Настройки → Face ID и код-пароль"))
    else:
        checks.append(HygieneCheck("passcode", None, "Код-пароль: не читается по кабелю",
                                   "Проверь вручную: Настройки → Face ID и код-пароль"))

    # Активация / Activation
    act = info.get("ActivationState")
    if act and act != "Activated":
        checks.append(HygieneCheck("activation", False, f"Устройство не активировано ({act})", ""))
    elif act:
        checks.append(HygieneCheck("activation", True, "Устройство активировано", ""))

    # Биометрия честно: не отдаётся без MDM-супервизии
    # Biometrics, honestly: not exposed without MDM supervision
    checks.append(HygieneCheck("biometry", None, "Биометрия: не читается по кабелю",
                               "Рекомендация: Face ID с Attention Detection включён"))

    return checks


def hygiene_score(checks: list[HygieneCheck]) -> int:
    """Штраф к общему score.

    Всегда 0: единственный доступный по кабелю сигнал (PasswordProtected)
    признан ненадёжным на современных iOS — штрафовать на его основе
    нельзя. Структура оставлена для будущей поддержки supervised-устройств,
    где читается настоящий SecurityInfo.

    Penalty added to the overall score.

    Always 0: the only cable-readable signal (PasswordProtected) proved
    unreliable on modern iOS, so penalizing based on it is impossible.
    The structure is kept for future supervised-device support, where the
    real SecurityInfo is readable.
    """
    return 0
