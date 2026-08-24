"""Выгрузка диагностических логов (краш-репортов) с устройства.

    Краш-логи - основной публичный источник артефактов шпионского ПО
    (методика Amnesty MVT): импланты иногда роняют процессы, оставляя следы.

    Export of diagnostic logs (crash reports) from the device.

    Crash logs are the main publicly available source of spyware artifacts
    (the Amnesty MVT methodology): implants occasionally crash processes,
    leaving traces behind.
    """

from __future__ import annotations

import subprocess
from pathlib import Path

from .. import config
from .connect import DeviceError, _run

CRASH_EXTENSIONS = {".ips", ".crash", ".panic", ".synced", ".plist"}


def export_crash_logs(udid: str, timeout: int = 90) -> tuple[Path, int]:
    """Экспортирует краш-логи в ~/.local/share/ghost-lock/crash_logs/<udid>.

    Возвращает (папка, число файлов). При зависании/ошибке экспорта не падаем:
    логи копятся инкрементально, работаем с тем, что уже скачано.

    Exports crash logs to ~/.local/share/ghost-lock/crash_logs/<udid>.

    Returns (folder, file count). Never hard-fails on export hangs/errors:
    logs accumulate incrementally, so we work with whatever is downloaded.
    """
    dest = config.CRASH_DIR / udid
    dest.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            ["idevicecrashreport", "-u", udid, "-e", "-k", str(dest)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0 and not any(dest.iterdir()):
            raise DeviceError(f"idevicecrashreport: {proc.stderr.strip()}")
    except subprocess.TimeoutExpired:
        pass  # используем ранее выгруженные логи

    count = sum(
        1 for f in dest.rglob("*") if f.is_file() and f.suffix in CRASH_EXTENSIONS
    )
    return dest, count


def collect_log_files(crash_dir: Path) -> list[Path]:
    """Все текстовые логи, пригодные для сканирования.

        All text logs suitable for scanning.
        """
    files: list[Path] = []
    for f in sorted(crash_dir.rglob("*")):
        if not f.is_file():
            continue
        try:
            if f.stat().st_size > config.MAX_SCAN_FILE_BYTES:
                continue  # слишком большой блоб — пропускаем / oversized blob, skip
        except OSError:
            continue
        if f.suffix in CRASH_EXTENSIONS or f.suffix == "":
            try:
                f.read_text(errors="strict")[:64]
                files.append(f)
            except (UnicodeDecodeError, PermissionError):
                continue
    return files


def log_stats(crash_dir: Path) -> dict[str, int]:
    """Статистика выгрузки для отчёта.

        Export statistics for the report.
        """
    stats = {"total": 0, "by_type": {}}
    for f in crash_dir.rglob("*"):
        if f.is_file():
            stats["total"] += 1
            ext = f.suffix or "(none)"
            stats["by_type"][ext] = stats["by_type"].get(ext, 0) + 1
    return stats
