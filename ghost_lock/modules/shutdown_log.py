"""Анализ shutdown.log из sysdiagnose (метод Kaspersky «iShutdown», 2024).

При каждой перезагрузке iOS пишет в shutdown.log процессы, которые мешали
выключению («remaining client pid: N (/путь)»). Импланты Pegasus, Reign и
Predator оставляли там процессы из нестандартных мест — /private/var/db/,
/private/var/tmp/. Ценность: журнал переживает удаление импланта и хранит
историю многих перезагрузок.

Откуда берётся: sysdiagnose (на телефоне — обе кнопки громкости + боковая
на 1–1,5 с, короткая вибрация). Архив sysdiagnose_*.tar.gz iOS кладёт в
DiagnosticLogs, который аудит и так выгружает; или ghost_lock.py sysdiagnose.
Архив читается в памяти: на диск не распаковывается ничего, кроме того, что
iOS уже отдала.

shutdown.log analysis from a sysdiagnose (Kaspersky "iShutdown" method, 2024).

On every reboot iOS logs the processes that delayed shutdown ("remaining
client pid: N (/path)"). Pegasus, Reign and Predator implants left processes
from unusual locations there — /private/var/db/, /private/var/tmp/. Value: the
log survives implant removal and keeps the history of many reboots.

Source: a sysdiagnose (on the phone: both volume buttons + side button for
1–1.5 s, a short vibration). iOS puts sysdiagnose_*.tar.gz into
DiagnosticLogs, which the audit already exports; or ghost_lock.py sysdiagnose.
The archive is read in memory; nothing is unpacked to disk.
"""

from __future__ import annotations

import datetime as dt
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding

LOG_SUFFIX = "logarchive/Extra/shutdown.log"
MAX_LOG_BYTES = 32 << 20

# Каталоги, откуда штатные процессы iOS при выключении не висят. Пути
# имплантов из отчётов Kaspersky/Amnesty: Pegasus — /private/var/db/…,
# Predator/Reign — /private/var/tmp/…
# Locations legitimate iOS processes do not linger from at shutdown. Implant
# paths per Kaspersky/Amnesty reports.
SUSPICIOUS_DIRS: list[tuple[str, int, str]] = [
    ("/private/var/db/", 8, "процесс из /private/var/db/ — так висел Pegasus (Kaspersky iShutdown)"),
    ("/private/var/tmp/", 7, "процесс из /private/var/tmp/ — так висели Predator/Reign"),
    ("/tmp/", 7, "процесс из /tmp/ — исполняемые файлы там не живут"),
    ("/private/var/mobile/Library/", 5, "процесс из пользовательской Library — нестандартное место"),
]

_SIGTERM = re.compile(r"SIGTERM:\s*\[(\d+)\]")
_CLIENT = re.compile(r"remaining client pid:\s*(\d+)\s*\((.*)\)\s*$")


@dataclass
class Reboot:
    timestamp: int | None
    clients: list[tuple[int, str]] = field(default_factory=list)


def find_archives(*dirs: Path) -> list[Path]:
    found: set[Path] = set()
    for d in dirs:
        if d and d.exists():
            found.update(p for p in d.rglob("sysdiagnose_*.tar.gz") if p.is_file())
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)


def read_shutdown_log(archive: Path) -> str | None:
    """Только shutdown.log из архива, в памяти. / Only shutdown.log, in memory."""
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if member.isfile() and member.name.endswith(LOG_SUFFIX):
                    if member.size > MAX_LOG_BYTES:
                        return None
                    fh = tar.extractfile(member)
                    return fh.read().decode("utf-8", errors="replace") if fh else None
    except (OSError, tarfile.TarError, EOFError):
        return None
    return None


def parse(text: str) -> list[Reboot]:
    reboots: list[Reboot] = []
    current: Reboot | None = None
    for line in text.splitlines():
        m = _SIGTERM.search(line)
        if m:
            current = Reboot(timestamp=int(m.group(1)))
            reboots.append(current)
            continue
        m = _CLIENT.search(line)
        if m:
            if current is None:
                current = Reboot(timestamp=None)
                reboots.append(current)
            current.clients.append((int(m.group(1)), m.group(2).strip()))
    return reboots


def _date(ts: int | None) -> str:
    if ts is None:
        return "?"
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "?"


@dataclass
class ShutdownAudit:
    archive: str = ""
    reboots: int = 0
    first: str = ""
    last: str = ""
    findings: list[Finding] = field(default_factory=list)
    lines: list[tuple[bool | None, str]] = field(default_factory=list)


def analyze(reboots: list[Reboot], iocs: dict[str, Any], archive: str = "") -> ShutdownAudit:
    from .netusage import APPLE_LOOKALIKES, LOOKALIKE_WEIGHT

    rep = ShutdownAudit(archive=archive, reboots=len(reboots))
    stamps = [r.timestamp for r in reboots if r.timestamp]
    rep.first, rep.last = (_date(min(stamps)), _date(max(stamps))) if stamps else ("?", "?")
    procs = {str(x["value"]).strip().lower(): x for x in iocs.get("processes", [])
             if isinstance(x, dict) and x.get("value")}
    paths = [x for x in iocs.get("file_paths", []) if isinstance(x, dict) and x.get("value")]

    # путь → даты перезагрузок, где он висел (один находкой на путь)
    # path → reboot dates it lingered in (one finding per path)
    seen: dict[str, list[str]] = {}
    for r in reboots:
        for _pid, path in r.clients:
            seen.setdefault(path, []).append(_date(r.timestamp))

    for path, dates in seen.items():
        low = path.lower()
        name = low.rsplit("/", 1)[-1]
        when = f"висел при выключении {len(dates)} раз(а), последний — {max(dates)}"
        for prefix, weight, why in SUSPICIOUS_DIRS:
            if low.startswith(prefix):
                rep.findings.append(Finding(ioc_type="shutdown_path", value=path, weight=weight,
                                            source=why, location=f"shutdown.log:{archive}", context=when))
                break
        if name in procs:
            ioc = procs[name]
            lookalike = name in APPLE_LOOKALIKES and low.startswith(("/system/", "/usr/"))
            rep.findings.append(Finding(
                ioc_type="process", value=path,
                weight=LOOKALIKE_WEIGHT if lookalike else int(ioc.get("weight", 8)),
                source=str(ioc.get("source", "")) + (" — системный путь Apple, проверь вручную" if lookalike else ""),
                location=f"shutdown.log:{archive}", context=when))
        for ioc in paths:
            if str(ioc["value"]).lower() in low:
                rep.findings.append(Finding(
                    ioc_type="file_paths", value=path, weight=int(ioc.get("weight", 6)),
                    source=str(ioc.get("source", "")), location=f"shutdown.log:{archive}", context=when))

    if not reboots:
        rep.lines.append((None, "shutdown.log пуст или в незнакомом формате"))
    elif rep.findings:
        rep.lines.append((False, f"shutdown.log: подозрительные процессы при выключении "
                                 f"({len({f.value for f in rep.findings})})"))
    else:
        rep.lines.append((True, f"shutdown.log: {rep.reboots} перезагрузок ({rep.first} … {rep.last}), "
                                f"{len(seen)} процессов — подозрительных нет"))
    return rep


def audit_dir(crash_dir: Path, iocs: dict[str, Any]) -> ShutdownAudit | None:
    """Самый свежий sysdiagnose в папке выгрузки → аудит; None, если архивов нет.

    The newest sysdiagnose in the export folder → audit; None if there is none.
    """
    archives = find_archives(crash_dir)
    for archive in archives:
        text = read_shutdown_log(archive)
        if text is not None:
            return analyze(parse(text), iocs, archive.name)
    if archives:
        rep = ShutdownAudit(archive=archives[0].name)
        rep.lines.append((None, f"sysdiagnose есть ({len(archives)}), но shutdown.log в нём не найден"))
        return rep
    return None
