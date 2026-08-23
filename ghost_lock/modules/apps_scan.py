"""Скан установленных приложений: поиск шпионского/stalkerware-софта.

`ideviceinstaller list` отдаёт строки вида:
  cc.ghostlock.app - GhostLock 1.0
Парсер терпим к вариациям формата (разные версии утилиты).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from .models import Finding


@dataclass
class InstalledApp:
    bundle_id: str
    name: str
    version: str


def _run_installer(udid: str) -> str:
    try:
        proc = subprocess.run(
            ["ideviceinstaller", "-u", udid, "list"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "ideviceinstaller не найден: sudo apt install libimobiledevice-utils"
        ) from e
    if proc.returncode != 0:
        err = proc.stderr.strip()
        if "No device found" in err:
            raise RuntimeError("Устройство отключилось — подключи кабель и повтори аудит.")
        raise RuntimeError(f"ideviceinstaller: {err}")
    return proc.stdout


_APP_RE = re.compile(r"^\s*([A-Za-z0-9.\-]+)\s*[-–]\s*(.+?)\s*$")
# ideviceinstaller (новые версии) отдаёт CSV: bundle, "версия", "имя"
_CSV_RE = re.compile(r'^\s*([A-Za-z0-9.\-]+),\s*"([^"]*)",\s*"([^"]*)"\s*$')


def parse_app_list(output: str) -> list[InstalledApp]:
    """Понимает оба формата ideviceinstaller:
    старый:  cc.app - Name (1.2)
    CSV:     cc.app, "1.2", "Name"
    """
    apps: list[InstalledApp] = []
    for line in output.splitlines():
        csv_m = _CSV_RE.match(line)
        if csv_m and not csv_m.group(1).startswith("CFBundle"):
            apps.append(InstalledApp(
                bundle_id=csv_m.group(1),
                name=csv_m.group(3),
                version=csv_m.group(2),
            ))
            continue

        m = _APP_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ver_m = re.search(r"\(([0-9][0-9A-Za-z.\-]*)\)\s*$", rest)
        version = ver_m.group(1) if ver_m else ""
        name = rest[: ver_m.start()].strip() if ver_m else rest.strip()
        apps.append(InstalledApp(bundle_id=m.group(1), name=name, version=version))
    return apps


def list_installed_apps(udid: str) -> list[InstalledApp]:
    return parse_app_list(_run_installer(udid))


def scan_apps(iocs: dict, apps: list[InstalledApp]) -> list[Finding]:
    """Сверяет bundle-id и имена приложений с секцией spyware_bundles.

    Паттерны без точки в конце матчатся как подстрока в любом месте
    bundle-id ИЛИ имени приложения.
    """
    findings: list[Finding] = []
    for ioc in iocs.get("spyware_bundles", []):
        needle = str(ioc.get("value", "")).lower()
        if not needle:
            continue
        for app in apps:
            haystack = f"{app.bundle_id} {app.name}".lower()
            if needle in haystack:
                findings.append(Finding(
                    ioc_type="spyware_bundles",
                    value=ioc["value"],
                    weight=int(ioc.get("weight", 5)),
                    source=ioc.get("source", "unknown"),
                    location=f"installed_app:{app.bundle_id}",
                    context=f"{app.name} v{app.version or '?'}",
                ))
                break  # одно совпадение на IOC достаточно
    return findings
