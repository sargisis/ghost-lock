"""Обнаружение iPhone по USB и сбор информации об устройстве.

Зависимости: libimobiledevice-utils (idevice_id, ideviceinfo).
"""

from __future__ import annotations

import json
import plistlib
import subprocess
from typing import Any


class DeviceError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError as e:
        raise DeviceError(
            f"Утилита {args[0]} не найдена. Установи: sudo apt install libimobiledevice-utils"
        ) from e
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        if "Unable to retrieve device list" in err:
            raise DeviceError(
                "Не удалось опросить USB (usbmuxd). Подключи айфон кабелем — демон стартует "
                "автоматически. Если телефон подключён и ошибка осталась: sudo systemctl start usbmuxd"
            )
        if "No device found" in err:
            raise DeviceError("Устройство не найдено. Подключи айфон кабелем и нажми «Доверять».")
        if "Could not connect" in err or "pair" in err.lower():
            raise DeviceError(
                "Устройство не спарено. Разблокируй айфон, подключи кабель и подтверди «Доверять этому компьютеру»."
            )
        raise DeviceError(f"{args[0]} завершился с ошибкой: {err}")
    return proc.stdout


def list_devices() -> list[str]:
    """Список UDID всех подключённых и спаренных устройств."""
    out = _run(["idevice_id", "-l"])
    return [u.strip() for u in out.splitlines() if u.strip()]


def device_info(udid: str) -> dict[str, Any]:
    """Полный plist ideviceinfo в виде словаря."""
    out = _run(["ideviceinfo", "-u", udid, "-x"])
    return dict(plistlib.loads(out.encode()))


def summary(info: dict[str, Any]) -> list[tuple[str, str]]:
    """Ключевые поля для отчёта."""
    keys = [
        ("DeviceName", "Имя устройства"),
        ("ProductType", "Модель"),
        ("ProductVersion", "Версия iOS"),
        ("BuildVersion", "Сборка iOS"),
        ("SerialNumber", "Серийный номер"),
        ("UniqueDeviceID", "UDID"),
        ("ActivationState", "Активация"),
        ("BasebandVersion", "Модем"),
        ("WiFiAddress", "Wi-Fi MAC"),
        ("BluetoothAddress", "BT MAC"),
        ("CPUArchitecture", "Архитектура"),
        ("ModelNumber", "Номер модели"),
        ("RegionInfo", "Регион"),
    ]
    return [(title, str(info.get(key, "n/a"))) for key, title in keys]


def to_json(info: dict[str, Any]) -> str:
    return json.dumps(info, ensure_ascii=False, indent=2, default=str)
