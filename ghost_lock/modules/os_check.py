"""Проверка свежести iOS: сравниваем версию устройства с последней для модели.

Устаревшая iOS = известные, уже пропатченные эксплойты остаются рабочими.
Источник актуальных версий: публичный API api.ipsw.me (без ключей).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

IPSW_API = "https://api.ipsw.me/v4/device/{product_type}"
TIMEOUT = 15


@dataclass
class OSStatus:
    product_type: str
    installed: str
    latest: str | None
    outdated: bool | None  # None = не смогли проверить (нет сети)
    note: str = ""


def fetch_latest_ios(product_type: str) -> str | None:
    """Последняя подписанная версия iOS для модели, например 'iPhone15,2'."""
    url = IPSW_API.format(product_type=product_type)
    req = urllib.request.Request(url, headers={"User-Agent": "ghost-lock/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.load(resp)
    except (OSError, ValueError):
        return None

    firmwares = [
        f for f in data.get("firmwares", [])
        if f.get("signed") and str(f.get("version", "")).startswith(("16.", "17.", "18.", "19.", "20.", "21.", "22.", "23.", "24.", "25.", "26.", "27."))
    ]
    if not firmwares:
        return None

    def version_key(f):
        return [int(x) for x in str(f["version"]).split(".") if x.isdigit()]

    return max(firmwares, key=version_key)["version"]


def check_os(product_type: str, installed_version: str) -> OSStatus:
    latest = fetch_latest_ios(product_type)
    if latest is None:
        return OSStatus(
            product_type=product_type,
            installed=installed_version,
            latest=None,
            outdated=None,
            note="Не удалось получить данные Apple (нет сети?) — проверь обновления вручную.",
        )

    def vkey(v: str) -> list[int]:
        return [int(x) for x in v.split(".") if x.isdigit()]

    outdated = vkey(installed_version) < vkey(latest)
    note = (
        "Обнови iOS: в старых версиях известные эксплойты уже продаются как готовые."
        if outdated
        else "Версия актуальна."
    )
    return OSStatus(
        product_type=product_type,
        installed=installed_version,
        latest=latest,
        outdated=outdated,
        note=note,
    )
