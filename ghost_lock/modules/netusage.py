"""Сетевая статистика процессов (DataUsage.sqlite / netusage.sqlite).

iOS сама ведёт учёт: какой процесс когда выходил в сеть и сколько передал.
Имплант тоже процесс — его имя остаётся в ZPROCESS даже после того, как
бинарник удалён. Это один из главных источников в методике Amnesty MVT.

В отличие от краш-логов, здесь имя процесса — отдельное поле, поэтому
сравниваем ТОЧНО (а не подстрокой) с секцией processes базы IOC: ложных
срабатываний вроде «bh» внутри любого слова здесь нет.

Следы подчистки: Pegasus удалял свои строки из ZPROCESS, но записи трафика
в ZLIVEUSAGE ссылались на них и оставались. Такие «сироты» считаем и
выводим — пока как информацию: норма для чистого телефона ещё не набрана.

Per-process network statistics (DataUsage.sqlite / netusage.sqlite).

iOS itself records which process went online, when and how much it sent.
An implant is a process too — its name stays in ZPROCESS even after the
binary is gone. One of the key sources in the Amnesty MVT methodology.

Unlike crash logs, the process name here is a dedicated field, so we match
EXACTLY (not as a substring) against the IOC processes section: no false
positives such as "bh" inside any word.

Cleanup traces: Pegasus deleted its ZPROCESS rows while ZLIVEUSAGE traffic
rows kept pointing at them. We count such orphans and print them — for now
as information only, since the baseline for a clean phone is not known yet.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding

DB_NAMES = ("DataUsage.sqlite", "netusage.sqlite")

# Имена из отчётов, совпадающие с НАСТОЯЩИМИ демонами Apple (проверено на
# живых устройствах) — вес снижаем, но не прячем.
# Names from reports that coincide with REAL Apple daemons (verified on live
# devices) — the weight is lowered, not hidden.
APPLE_LOOKALIKES = {"roleaccountd", "updaterd"}
LOOKALIKE_WEIGHT = 3

# Core Data хранит время в секундах от 2001-01-01
# Core Data stores time as seconds since 2001-01-01
_COCOA_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)


@dataclass
class NetAudit:
    databases: int = 0
    processes: int = 0
    orphans: int = 0
    findings: list[Finding] = field(default_factory=list)
    lines: list[tuple[bool | None, str]] = field(default_factory=list)


def _ts(value: Any) -> str:
    try:
        return (_COCOA_EPOCH + dt.timedelta(seconds=float(value))).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError):
        return "?"


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}


def _candidates(*values: Any) -> set[str]:
    """Имя целиком и последняя часть пути: «/private/var/tmp/x» → {…, "x"}.

    The whole name and the last path segment.
    """
    out: set[str] = set()
    for v in values:
        if not v:
            continue
        v = str(v).strip().lower()
        out.add(v)
        out.add(v.rsplit("/", 1)[-1])
    out.discard("")
    return out


def _scan_db(db: Path, procs: dict[str, dict], paths: list[dict], rep: NetAudit) -> None:
    con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "ZPROCESS" not in tables:
            return
        rep.databases += 1
        cols = _columns(con, "ZPROCESS")
        wanted = [c for c in ("ZPROCNAME", "ZBUNDLENAME", "ZFIRSTTIMESTAMP", "ZTIMESTAMP") if c in cols]
        rows = con.execute(f"SELECT {', '.join(wanted)} FROM ZPROCESS").fetchall()
        rep.processes += len(rows)

        for row in rows:
            rec = dict(zip(wanted, row))
            name = rec.get("ZPROCNAME") or rec.get("ZBUNDLENAME") or ""
            seen = f"{_ts(rec.get('ZFIRSTTIMESTAMP'))} … {_ts(rec.get('ZTIMESTAMP'))}"
            cands = _candidates(rec.get("ZPROCNAME"), rec.get("ZBUNDLENAME"))

            for c in sorted(cands & procs.keys()):
                ioc = procs[c]
                lookalike = c in APPLE_LOOKALIKES
                rep.findings.append(Finding(
                    ioc_type="process", value=c,
                    weight=LOOKALIKE_WEIGHT if lookalike else int(ioc.get("weight", 8)),
                    source=str(ioc.get("source", "")) + (
                        " — имя совпадает с демоном Apple, проверь вручную" if lookalike else ""),
                    location=f"backup:{db.name}",
                    context=f"процесс «{name}» выходил в сеть: {seen}",
                ))

            raw = " ".join(str(v).lower() for v in (rec.get("ZPROCNAME"), rec.get("ZBUNDLENAME")) if v)
            for ioc in paths:
                needle = str(ioc.get("value", "")).lower()
                if needle and needle in raw:
                    rep.findings.append(Finding(
                        ioc_type="file_paths", value=ioc["value"],
                        weight=int(ioc.get("weight", 6)), source=str(ioc.get("source", "")),
                        location=f"backup:{db.name}",
                        context=f"процесс «{name}» выходил в сеть: {seen}",
                    ))

        # Сироты: трафик ссылается на удалённую строку ZPROCESS
        # Orphans: traffic rows point at a deleted ZPROCESS row
        if "ZLIVEUSAGE" in tables and "ZHASPROCESS" in _columns(con, "ZLIVEUSAGE"):
            rep.orphans += con.execute(
                "SELECT count(*) FROM ZLIVEUSAGE WHERE ZHASPROCESS IS NOT NULL "
                "AND ZHASPROCESS NOT IN (SELECT Z_PK FROM ZPROCESS)").fetchone()[0]
    finally:
        con.close()


def audit(root: Path, iocs: dict[str, Any]) -> NetAudit:
    rep = NetAudit()
    procs = {str(x["value"]).strip().lower(): x for x in iocs.get("processes", [])
             if isinstance(x, dict) and x.get("value")}
    paths = [x for x in iocs.get("file_paths", []) if isinstance(x, dict)]
    dbs = sorted(p for name in DB_NAMES for p in root.rglob(name) if p.is_file())
    for db in dbs:
        try:
            _scan_db(db, procs, paths, rep)
        except sqlite3.Error as e:
            rep.lines.append((None, f"{db.name}: не читается ({e})"))

    if not rep.databases:
        rep.lines.append((None, "Сетевая статистика: базы в бэкапе не найдены"))
        return rep
    if rep.findings:
        names = ", ".join(sorted({f.value for f in rep.findings}))
        rep.lines.append((False, f"Процессы из базы шпионов выходили в сеть: {names}"))
    else:
        rep.lines.append((True, f"Сетевая статистика: {rep.processes} процессов, "
                                f"совпадений с базой шпионов нет"))
    if rep.orphans:
        rep.lines.append((None, f"Записей трафика без процесса: {rep.orphans} "
                                "(возможна подчистка; норма пока не известна)"))
    return rep
