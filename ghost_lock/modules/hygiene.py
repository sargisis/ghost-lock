"""Чек гигиены безопасности через кабель.

lockdownd отдаёт минимум, но самое важное: PasswordProtected.
Код-пароль — фундамент всей защиты: без него Face ID, USB Restricted
Mode и автостирание не работают, а телефон разблокируется касанием.
Биометрия по кабелю не читается (приватность iOS) — честно пишем это.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INFO_TIMEOUT = 20


@dataclass
class HygieneCheck:
    key: str          # машинное имя
    ok: bool | None   # True хорошо / False плохо / None неизвестно
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
    pp = info.get("PasswordProtected")
    pp_state = None if pp is None else str(pp).strip().lower() == "true"
    if pp_state is True:
        checks.append(HygieneCheck("passcode", True, "Код-пароль: устройство сообщает о защите",
                                   "Проверь вручную: Настройки → Face ID и код-пароль"))
    else:
        checks.append(HygieneCheck("passcode", None, "Код-пароль: не читается по кабелю",
                                   "Проверь вручную: Настройки → Face ID и код-пароль"))

    # Активация
    act = info.get("ActivationState")
    if act and act != "Activated":
        checks.append(HygieneCheck("activation", False, f"Устройство не активировано ({act})", ""))
    elif act:
        checks.append(HygieneCheck("activation", True, "Устройство активировано", ""))

    # Биометрия честно: не отдаётся без MDM-супервизии
    checks.append(HygieneCheck("biometry", None, "Биометрия: не читается по кабелю",
                               "Рекомендация: Face ID с Attention Detection включён"))

    return checks


def hygiene_score(checks: list[HygieneCheck]) -> int:
    """Штраф к общему score.

    Всегда 0: единственный доступный по кабелю сигнал (PasswordProtected)
    признан ненадёжным на современных iOS — штрафовать на его основе
    нельзя. Структура оставлена для будущей поддержки supervised-устройств,
    где читается настоящий SecurityInfo.
    """
    return 0
