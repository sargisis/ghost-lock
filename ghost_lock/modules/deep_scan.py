"""Глубокий форензик-режим: полный бэкап через idevicebackup2 + скан всего.

Обычный аудит смотрит только краш-логи (~сотни файлов). Полный бэкап —
это SMS-базы, история Safari, сетевая статистика, снапшоты приложений:
десятки тысяч файлов. Медленно (десятки минут первый раз, дальше
инкрементально быстро), но это уровень настоящего forensics.

Бэкап НЕ зашифрован (пользовательский пароль бэкапа мы не знаем) — зато
он лежит локально в ~/.local/share/ghost-lock/backups/.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

from .spyware_scan import ScanResult

BACKUP_TIMEOUT = 3600  # час на полный бэкап
BACKUPS_DIR = Path.home() / ".local" / "share" / "ghost-lock" / "backups"


def _run_backup(udid: str, dest_dir: Path) -> tuple[bool, str]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["idevicebackup2", "backup", "--full", str(dest_dir)]
    if udid:
        cmd.append(udid)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=BACKUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "бэкап не уложился в часовой таймаут"
    except OSError as e:
        return False, f"idevicebackup2 недоступен: {e}"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        reason = tail[-1] if tail else f"exit {proc.returncode}"
        return False, reason
    return True, ""


def run(udid: str, info: dict[str, Any]) -> ScanResult:
    """Полный бэкап + IOC-скан. Возвращает отдельный ScanResult."""
    from .spyware_scan import run_scan

    started = time.monotonic()
    dest = BACKUPS_DIR / udid
    print("  [~] Глубокий режим: полный бэкап. Первый раз может занять десятки минут…")
    ok, err = _run_backup(udid, dest)
    if not ok:
        res = ScanResult(findings=[], files_scanned=0)
        res.stats_note = f"deep: бэкап не удался ({err})"
        print(f"  [!] Бэкап не удался: {err}")
        return res

    n_files = sum(1 for _ in dest.rglob("*") if _.is_file())
    minutes = (time.monotonic() - started) / 60
    print(f"  [+] Бэкап готов за {minutes:.1f} мин ({n_files} файлов). Скан…")

    result = run_scan(info, str(dest))
    for f in result.findings:
        if not f.location.startswith("backup:"):
            f.location = f"backup:{f.location}"
    return result
